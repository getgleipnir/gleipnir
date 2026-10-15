import asyncio
import json

import pytest

import gleipnir
from gleipnir import Outcome
from gleipnir_verify import verify_bundle, verify_records


def actions(rec):
    return [r for r in rec.chain.store.read_all() if r["kind"] == "action"]


def test_decorator_records_and_returns_unchanged(rec):
    @rec.tool(system="payments")
    def refund(order_id: str, amount: float = 1.0):
        """docstring"""
        return {"refund_id": "R1", "amount": amount}

    assert refund("A1", amount=5) == {"refund_id": "R1", "amount": 5}
    assert refund.__doc__ == "docstring" and refund.__name__ == "refund"
    a = actions(rec)[0]
    assert a["tool"] == {"name": "refund", "system": "payments"}
    assert a["args"] == {"order_id": "A1", "amount": 5}
    assert a["response"] == {"status": "ok", "body": {"refund_id": "R1", "amount": 5}}
    assert a["agent"] == {"id": "support-agent", "version": "1.0.0"}
    assert "outcome" not in a


def test_defaults_are_recorded(rec):
    @rec.tool(system="s")
    def f(a, b=7):
        return None

    f(1)
    assert actions(rec)[0]["args"] == {"a": 1, "b": 7}


def test_exception_recorded_and_reraised(rec):
    @rec.tool(system="payments")
    def refund(order_id):
        raise ConnectionError("gateway down")

    with pytest.raises(ConnectionError):
        refund("A1")
    a = actions(rec)[0]
    assert a["response"] == {"status": "error", "error": "ConnectionError: gateway down"}


def test_outcome_match_mismatch_error(rec):
    ledger = {"R1": 10.0, "R2": 9.99}

    def check(call, resp):
        return Outcome.compare({"amount": call.args["amount"]}, {"amount": ledger[resp["id"]]})

    @rec.tool(system="payments", verify_outcome=check)
    def refund(rid, amount):
        return {"id": rid}

    refund("R1", 10.0)
    refund("R2", 10.0)
    refund("R3", 1.0)  # KeyError inside the check
    a = actions(rec)
    assert a[0]["outcome"]["check"] == "match"
    assert a[1]["outcome"] == {"check": "mismatch", "method": "verify_outcome", "observed": {"amount": 9.99},
                               "fields": ["amount"]}
    assert a[2]["outcome"]["check"] == "error" and "KeyError" in a[2]["outcome"]["detail"]


def test_outcome_bool_and_none(rec):
    @rec.tool(system="s", verify_outcome=lambda c, r: r)
    def f(x):
        return x

    f(True)
    f(False)
    f(None)
    assert [a["outcome"]["check"] for a in actions(rec)] == ["match", "mismatch", "not_checked"]


def test_redaction_never_stored(rec):
    @rec.tool(system="payments", redact={"card": "hmac", "cvv": "drop", "name": lambda v: v[0] + "***"})
    def charge(card, cvv, name, amount):
        return {"card": card, "ok": True}

    charge("4111111111111111", "123", "Alice", 5)
    raw = (rec.home / "chains" / "default" / "records.jsonl").read_text()
    assert "4111111111111111" not in raw and '"123"' not in raw and "Alice" not in raw
    a = actions(rec)[0]
    assert a["args"]["card"]["redacted"].startswith("hmac-sha256:")
    assert a["args"]["cvv"] == {"redacted": "dropped"}
    assert a["args"]["name"] == "A***"
    assert a["response"]["body"]["card"] == a["args"]["card"]  # same value -> same keyed hash
    assert a["redaction"]["fields"] == ["card", "cvv", "name"]


def test_redaction_list_without_key_drops(tmp_path, clock):
    r = gleipnir.Recorder("a", "1", home=tmp_path, background=False, clock=clock, quiet=True,
                          redaction_key=b"", fsync=False)

    @r.tool(system="s", redact=["secret"])
    def f(secret):
        return None

    f("x")
    assert actions(r)[0]["args"]["secret"] == {"redacted": "dropped"}


def test_context_and_claim(rec):
    @rec.tool(system="crm", claim=lambda args, res: f"updated {args['ticket']}")
    def update(ticket):
        return {"ok": True}

    with rec.context(trace_id="t-1", on_behalf_of="ticket:T-7", model={"provider": "p", "name": "m"},
                     versions={"prompt": "pr-3"}, identity={"principal": "svc-agent", "scope": "crm:write"}):
        update("T-7")
    a = actions(rec)[0]
    assert a["context"] == {"trace_id": "t-1", "on_behalf_of": "ticket:T-7"}
    assert a["model"]["name"] == "m" and a["versions"] == {"prompt": "pr-3"}
    assert a["identity"]["principal"] == "svc-agent"
    assert a["claim"] == {"text": "updated T-7"}
    c = rec.claim(a["id"], "I updated the ticket")
    assert c["kind"] == "claim" and c["claim"]["action"] == a["id"]
    with pytest.raises(ValueError):
        with rec.context(bogus=1):
            pass


def test_nested_context_merges(rec):
    @rec.tool(system="s")
    def f():
        return 1

    with rec.context(session="s1"):
        with rec.context(trace_id="t2"):
            f()
        f()
    a = actions(rec)
    assert a[0]["context"] == {"session": "s1", "trace_id": "t2"}
    assert a[1]["context"] == {"session": "s1"}


async def test_async_tool_and_async_outcome(rec):
    async def check(call, resp):
        await asyncio.sleep(0)
        return Outcome.match({"id": resp})

    @rec.tool(system="s", verify_outcome=check)
    async def f(x):
        await asyncio.sleep(0)
        return x * 2

    assert await f(21) == 42
    a = actions(rec)[0]
    assert a["response"]["body"] == 42 and a["outcome"]["check"] == "match"

    @rec.tool(system="s")
    async def g():
        raise ValueError("bad")

    with pytest.raises(ValueError):
        await g()
    assert actions(rec)[1]["response"]["status"] == "error"


def test_weird_values_are_jsonable(rec):
    import dataclasses
    from datetime import datetime, timezone

    @dataclasses.dataclass
    class D:
        x: int

    @rec.tool(system="s")
    def f(a, b, c, d, e):
        return object()

    f(D(1), {1, 2}, b"raw", float("nan"), datetime(2026, 1, 1, tzinfo=timezone.utc))
    a = actions(rec)[0]
    assert a["args"]["a"] == {"x": 1}
    assert a["args"]["b"] == [1, 2]
    assert a["args"]["c"] == {"bytes_len": 3}
    assert a["args"]["d"] == {"float": "nan"}
    assert "repr" in a["response"]["body"]


def test_segments_anchor_and_bundle_verify(rec, tmp_path, clock):
    @rec.tool(system="s")
    def f(i):
        return i

    for i in range(12):
        clock.advance(1)
        f(i)
    path = rec.export(tmp_path / "b.zip")
    r = verify_bundle(path, expect_key=rec.key_id, expect_until=clock.now)
    assert r.valid(strict=True), [x.as_dict() for x in r.findings]
    assert r.summary["segments"] == 3
    assert r.summary["segments_anchored"] == 3


def test_heartbeat_closes_empty_segments(rec, clock, tmp_path):
    clock.advance(61)
    seg = rec.chain.maybe_heartbeat()
    assert seg and seg["segment"]["count"] == 0 and seg["segment"]["heartbeat"]
    assert rec.chain.maybe_heartbeat() is None
    rec.chain.anchor_pending()
    path = rec.export(tmp_path / "b.zip")
    assert verify_bundle(path).valid(strict=True)


def test_restart_continues_chain(tmp_path, clock):
    def make():
        return gleipnir.Recorder("a", "1", home=tmp_path, background=False, clock=clock, quiet=True,
                                 segment_max_records=3, fsync=False)

    r1 = make()

    @r1.tool(system="s")
    def f(i):
        return i

    for i in range(4):
        f(i)
    chain = r1.chain.chain_id
    # crash without flush: one segment closed and anchored, one record open
    r2 = make()
    assert r2.chain.chain_id == chain

    @r2.tool(system="s")
    def g(i):
        return i

    for i in range(4):
        g(i)
    path = r2.export(tmp_path / "b.zip")
    r = verify_bundle(path)
    assert r.valid(strict=True), [x.as_dict() for x in r.findings]


def test_restart_with_wrong_key_refuses(tmp_path, clock):
    gleipnir.Recorder("a", "1", home=tmp_path, background=False, clock=clock, quiet=True, fsync=False)
    with pytest.raises(ValueError):
        gleipnir.Recorder("a", "1", home=tmp_path, background=False, clock=clock, quiet=True, fsync=False,
                          signer=gleipnir.Ed25519Signer.generate())


def test_key_rotation_verifies(rec, tmp_path):
    @rec.tool(system="s")
    def f(i):
        return i

    f(1)
    rec.chain.rotate_key(gleipnir.Ed25519Signer.generate())
    f(2)
    path = rec.export(tmp_path / "b.zip")
    r = verify_bundle(path)
    assert r.valid(), [x.as_dict() for x in r.findings]
    assert len(r.summary["keys"]) == 2


def test_anchor_failure_retries(tmp_path, clock):
    class Flaky:
        type = "local"

        def __init__(self):
            self.inner = gleipnir.LocalFileAnchor(tmp_path / "log.jsonl", clock=clock)
            self.fail = True

        def anchor(self, **kw):
            if self.fail:
                raise ConnectionError("log down")
            return self.inner.anchor(**kw)

    fl = Flaky()
    r = gleipnir.Recorder("a", "1", home=tmp_path, background=False, clock=clock, quiet=True, anchor=fl,
                          segment_max_records=2, fsync=False)

    @r.tool(system="s")
    def f(i):
        return i

    for i in range(4):
        f(i)
    assert len(r.chain.pending_anchor) == 2
    fl.fail = False
    assert r.chain.anchor_pending() == 2
    path = r.export(tmp_path / "b.zip")
    assert verify_bundle(path, anchor_options={"local_anchor_log": tmp_path / "log.jsonl"}).valid(strict=True)


def test_partial_export_by_time(rec, clock, tmp_path):
    @rec.tool(system="s")
    def f(i):
        return i

    marks = []
    for i in range(20):
        clock.advance(10)
        marks.append(clock.now)
        f(i)
    rec.flush()
    path = rec.export(tmp_path / "part.zip", since=marks[7], until=marks[12])
    r = verify_bundle(path)
    assert r.valid(), [x.as_dict() for x in r.findings]
    seqs = r.summary["first_seq"], r.summary["last_seq"]
    assert seqs[0] == 0
    import zipfile
    with zipfile.ZipFile(path) as zf:
        recs = [json.loads(x) for x in zf.read("records.jsonl").decode().splitlines()]
    acts = [x for x in recs if x["kind"] == "action"]
    assert 5 <= len(acts) < 20


def test_background_thread_heartbeat(tmp_path):
    import time

    r = gleipnir.Recorder("a", "1", home=tmp_path, heartbeat_seconds=1, quiet=True, fsync=False)
    time.sleep(2.5)
    r.close()
    recs = r.chain.store.read_all()
    assert any(x["kind"] == "segment" and x["segment"]["heartbeat"] for x in recs)
    assert verify_records(recs, anchor_options={"local_anchor_log": tmp_path / "anchors" /
                                                "local-anchor-log.jsonl"}).valid()


def test_bad_args(tmp_path):
    with pytest.raises(ValueError):
        gleipnir.Recorder("a", "1", home=tmp_path, anchor="rekor-typo", quiet=True, background=False)
    with pytest.raises(ValueError):
        gleipnir.ChainWriter(gleipnir.MemoryStore(), gleipnir.Ed25519Signer.generate(), segment_max_records=0)
    w = gleipnir.ChainWriter(gleipnir.MemoryStore(), gleipnir.Ed25519Signer.generate(), background=False)
    with pytest.raises(ValueError):
        w.append("segment", {})


def test_cli_init_status_export(tmp_path, capsys, clock):
    from gleipnir import cli
    from gleipnir_verify import verify_bundle

    home = str(tmp_path / "h")
    assert cli.main(["--home", home, "status"]) == 1
    assert cli.main(["--home", home, "init"]) == 0
    r = gleipnir.Recorder("a", "1", home=home, background=False, clock=clock, quiet=True, fsync=False,
                          segment_max_records=2)

    @r.tool(system="s")
    def f(i):
        return i

    for i in range(5):
        f(i)
    r.flush()
    assert cli.main(["--home", home, "status"]) == 0
    out = tmp_path / "x.zip"
    assert cli.main(["--home", home, "export", "-o", str(out)]) == 0
    assert verify_bundle(out).valid(strict=True)
    assert "verify with" in capsys.readouterr().out


def test_unicode_line_separators_survive_reload(rec, tmp_path):
    @rec.tool(system="s")
    def f(text):
        return text

    f("line sep par\u0085nel")
    rec.flush()
    records = rec.chain.store.read_all()
    assert actions(rec)[0]["args"]["text"] == "line sep par\u0085nel"
    path = rec.export(tmp_path / "u.zip")
    assert verify_bundle(path).valid(strict=True)
    raw_lines = rec.chain.store.path.read_text(encoding="utf-8").count("\n")
    assert raw_lines == len(rec.chain.store.read_all()) >= len(records)
    assert "\u2028" not in rec.chain.store.path.read_text(encoding="utf-8")


def test_huge_integers_are_recorded_not_raised(rec):
    @rec.tool(system="s")
    def f(n):
        return n * 2

    assert f(2**70) == 2**71
    a = actions(rec)[0]
    assert a["args"]["n"] == {"int": str(2**70)}
    assert a["response"]["body"] == {"int": str(2**71)}


def test_approval_bound_to_action(rec, tmp_path):
    from gleipnir_verify import verify_records

    @rec.tool(system="payments", redact=["card"])
    def refund(order, amount, card):
        return {"ok": True}

    approval = rec.approve(refund, {"order": "A1", "amount": 500, "card": "4111"}, approver="ops:anna",
                           rule="amount>100")
    with rec.context(approval=approval):
        refund("A1", 500, "4111")
    recs = rec.chain.store.read_all()
    assert verify_records(recs).valid()
    # executing something different from what was approved is caught
    with rec.context(approval=approval):
        refund("A1", 5000, "4111")
    codes = {f.code for f in verify_records(rec.chain.store.read_all()).errors}
    assert codes == {"approval_mismatch"}


def test_approval_must_precede_action(rec):
    from gleipnir_verify import verify_records
    from gleipnir_verify.verifier import action_digest

    @rec.tool(system="payments")
    def refund(order):
        return {"ok": True}

    with rec.context(approval="rev_later"):
        refund("A1")
    rec.chain.append("review", {"id": "rev_later", "review": {
        "action_digest": action_digest("refund", "payments", {"order": "A1"}), "decision": "approved",
        "reviewer": "x"}})
    codes = {f.code for f in verify_records(rec.chain.store.read_all()).errors}
    assert "approval_after_action" in codes


def test_approval_needs_tool_and_system(rec):
    import pytest

    with pytest.raises(ValueError):
        rec.approve("refund", {}, approver="x")


def test_single_action_proof(rec, tmp_path, clock):
    import json
    import zipfile

    from gleipnir_verify import cli as vcli

    @rec.tool(system="payments")
    def refund(order):
        return {"refund_id": "R-" + order}

    for i in range(7):
        clock.advance(1)
        refund(f"o{i}")
    target = actions(rec)[3]["id"]
    path = rec.prove(target, tmp_path / "proof.zip")
    rep = verify_bundle(path, expect_key=rec.key_id)
    assert rep.valid(), [f.as_dict() for f in rep.findings]
    assert rep.summary["action"] == target
    assert vcli.main([str(path)]) == 0
    # tamper with the action inside the proof
    with zipfile.ZipFile(path) as zf:
        files = {n: zf.read(n) for n in zf.namelist()}
    lines = files["records.jsonl"].decode().split("\n")
    a = json.loads(lines[1])
    a["args"]["order"] = "other"
    lines[1] = json.dumps(a)
    files["records.jsonl"] = "\n".join(lines).encode()
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        for n, d in files.items():
            zf.writestr(n, d)
    codes = {f.code for f in verify_bundle(bad).errors}
    assert "bad_signature" in codes and "proof_invalid" in codes
