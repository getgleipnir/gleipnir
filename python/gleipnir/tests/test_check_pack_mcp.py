import asyncio
import csv
import io
import json
import zipfile
from types import SimpleNamespace

import pytest

import gleipnir
from gleipnir.adapters.mcp import instrument_session
from gleipnir.check import capabilities_from_records, evaluate, load_checklist, render_text


def test_pinned_checklist_loads():
    c = load_checklist()
    assert len(c["items"]) >= 30
    ids = {i["id"] for i in c["items"]}
    assert {"ACT-01", "TMP-01", "TMP-02", "OUT-01"} <= ids


def test_check_derives_capabilities_from_evidence(rec):
    @rec.tool(system="payments", redact=["card"], verify_outcome=lambda c, r: True)
    def refund(order, card):
        return {"refund_id": "R1"}

    caps0, _ = capabilities_from_records(rec.chain.store.read_all())
    assert "outcome_check" not in caps0 and "action_record" not in caps0
    with rec.context(identity={"principal": "svc", "scope": "refunds:write"}, model={"name": "m"},
                     versions={"prompt": "p1"}):
        a = refund("o1", "4111")
    rec.review(rec.chain.store.read_all()[-1]["id"], reviewer="ops-1", decision="approved", rule="amount>100",
               before_execution=False)
    caps, why = capabilities_from_records(rec.chain.store.read_all())
    for c in ["action_record", "identity_binding", "scope_record", "model_version", "config_version",
              "outcome_check", "redaction", "review_record", "signed_records", "hash_chain"]:
        assert c in caps, c
    assert "external_anchor" not in caps  # local anchor is not independent
    results = {r.id: r for r in evaluate(load_checklist(), caps)}
    assert results["ACT-01"].status == "covered"
    assert results["OUT-01"].status == "covered"
    assert results["TMP-02"].status == "partial"  # offline_verifier yes, external_anchor no
    assert results["ACC-03"].status == "process"
    assert results["ACT-03"].status == "missing"  # tool calls alone do not show model endpoints
    rec.record_action(tool="answer", system="kb", args={}, sources=[{"type": "kb", "id": "faq-1"}],
                      calls=[{"service": "provider-a", "endpoint": "chat"}])
    caps2, _ = capabilities_from_records(rec.chain.store.read_all())
    assert {"source_record", "endpoint_record"} <= caps2
    text = render_text(list(results.values()), why)
    assert "anchor='rekor'" in text
    assert a == {"refund_id": "R1"}


def test_pack_contents(rec, tmp_path, clock):
    @rec.tool(system="payments", verify_outcome=lambda c, r: gleipnir.Outcome.compare(
        {"amount": c.args["amount"]}, {"amount": r["amount"] - (0.01 if c.args["order"] == "o3" else 0)}))
    def refund(order, amount):
        if order == "o5":
            raise TimeoutError("gateway")
        return {"refund_id": f"R-{order}", "amount": amount}

    with rec.context(identity={"principal": "svc-agent", "scope": "refunds:write"}):
        for i in range(8):
            clock.advance(30)
            try:
                refund(f"o{i}", 10.0)
            except TimeoutError:
                pass
    path = rec.pack(tmp_path / "pack.zip")
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        assert {"summary.html", "actions.csv", "bundle.zip", "VERIFY.md", "verification.json"} <= names
        page = zf.read("summary.html").decode()
        rows = list(csv.DictReader(io.StringIO(zf.read("actions.csv").decode())))
        verification = json.loads(zf.read("verification.json"))
        inner = zf.read("bundle.zip")
    assert verification["result"] == "VALID"
    assert "Security Review Pack" in page and "svc-agent" in page and "TimeoutError" in page
    assert len(rows) == 8
    assert any(r["outcome"] == "mismatch" for r in rows)
    assert any("refund_id=R-o1" in r["external_ids"] for r in rows)
    bundle = tmp_path / "inner.zip"
    bundle.write_bytes(inner)
    from gleipnir_verify import verify_bundle
    assert verify_bundle(bundle).valid()


def test_cli_check_and_pack(tmp_path, clock, capsys):
    from gleipnir import cli

    home = tmp_path / "h"
    r = gleipnir.Recorder("a", "1", home=home, background=False, clock=clock, quiet=True, fsync=False)

    @r.tool(system="s")
    def f(i):
        return {"id": i}

    f(1)
    r.flush()
    assert cli.main(["--home", str(home), "check"]) == 0
    assert "checklist coverage" in capsys.readouterr().out
    assert cli.main(["--home", str(home), "check", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["items"]
    out = tmp_path / "p.zip"
    assert cli.main(["--home", str(home), "pack", "-o", str(out)]) == 0
    assert zipfile.is_zipfile(out)


class FakeSession:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments=None, read_timeout_seconds=None, **kw):
        self.calls.append((name, arguments, kw))
        if name == "explode":
            raise RuntimeError("transport closed")
        if name == "bad":
            return SimpleNamespace(isError=True, content=[SimpleNamespace(text="refund not allowed")],
                                   model_dump=lambda mode=None: {"isError": True})
        return SimpleNamespace(isError=False, content=[], structuredContent={"refund_id": "R7", "amount": 5},
                               model_dump=lambda mode=None: {"isError": False,
                                                             "structuredContent": {"refund_id": "R7", "amount": 5}})


async def test_mcp_adapter(rec):
    s = FakeSession()

    async def check(call, result):
        await asyncio.sleep(0)
        return gleipnir.Outcome.compare({"amount": call.args["amount"]}, result.structuredContent)

    instrument_session(s, rec, system="payments-mcp", redact=["card"], verify_outcome={"refund": check})
    instrument_session(s, rec, system="payments-mcp")  # idempotent
    res = await s.call_tool("refund", {"amount": 5, "card": "4111"}, read_timeout_seconds=3, meta={"x": 1})
    assert res.structuredContent["refund_id"] == "R7"
    assert s.calls[0][2] == {"meta": {"x": 1}}  # extra kwargs pass through
    await s.call_tool("bad", {"amount": 1})
    with pytest.raises(RuntimeError):
        await s.call_tool("explode")
    acts = [r for r in rec.chain.store.read_all() if r["kind"] == "action"]
    assert [a["tool"]["name"] for a in acts] == ["refund", "bad", "explode"]
    assert acts[0]["outcome"]["check"] == "match"
    assert acts[0]["args"]["card"]["redacted"].startswith("hmac")
    assert acts[0]["response"]["body"]["structuredContent"]["refund_id"] == "R7"
    assert acts[1]["response"]["status"] == "error" and "refund not allowed" in acts[1]["response"]["error"]
    assert acts[2]["response"]["error"].startswith("RuntimeError")
    assert all(a["tool"]["system"] == "payments-mcp" for a in acts)
