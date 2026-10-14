"""End to end: bundles produced by the SDK, tampered on disk, must fail gleipnir-verify."""

import json
import zipfile

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import gleipnir
from gleipnir_verify import cli
from gleipnir_verify.canon import record_hash


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    from conftest import FakeClock

    d = tmp_path_factory.mktemp("e2e")
    clock = FakeClock()
    r = gleipnir.Recorder("support-agent", "1", home=d / "g", background=False, clock=clock, quiet=True,
                          segment_max_records=4, fsync=False)

    @r.tool(system="payments", verify_outcome=lambda c, resp: True)
    def refund(order, amount):
        return {"ok": True, "amount": amount}

    for i in range(13):
        clock.advance(5)
        refund(f"o{i}", i)
    path = r.export(d / "bundle.zip")
    with zipfile.ZipFile(path) as zf:
        manifest = zf.read("manifest.json")
        lines = zf.read("records.jsonl").decode().splitlines()
        log = zf.read("anchors/local-anchor-log.jsonl")
    head = json.loads(lines[-1])
    return {"dir": d, "manifest": manifest, "lines": lines, "log": log,
            "head": f"{head['seq']}:{record_hash(head)}", "until": clock.now.isoformat(), "key": r.key_id}


def write(b, lines, name):
    p = b["dir"] / name
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("manifest.json", b["manifest"])
        zf.writestr("records.jsonl", "\n".join(lines) + "\n")
        zf.writestr("anchors/local-anchor-log.jsonl", b["log"])
    return p


def verdict(b, p):
    return cli.main([str(p), "--expect-key", b["key"], "--known-head", b["head"], "--json"])


def test_untampered_valid(bundle, capsys):
    assert verdict(bundle, write(bundle, bundle["lines"], "ok.zip")) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "VALID"


@settings(max_examples=60, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_edit_on_disk_fails(bundle, data, capsys):
    lines = list(bundle["lines"])
    i = data.draw(st.integers(0, len(lines) - 1))
    rec = json.loads(lines[i])
    key = data.draw(st.sampled_from(sorted(k for k in rec if k != "sig")))
    rec[key] = "tampered"
    lines[i] = json.dumps(rec)
    assert verdict(bundle, write(bundle, lines, "edit.zip")) == 1
    capsys.readouterr()


@settings(max_examples=60, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_delete_reorder_truncate_on_disk_fails(bundle, data, capsys):
    lines = list(bundle["lines"])
    op = data.draw(st.sampled_from(["delete", "swap", "truncate"]))
    i = data.draw(st.integers(0, len(lines) - 2))
    if op == "delete":
        del lines[i]
    elif op == "swap":
        lines[i], lines[i + 1] = lines[i + 1], lines[i]
    else:
        lines = lines[: i + 1]
    assert verdict(bundle, write(bundle, lines, f"{op}.zip")) == 1
    capsys.readouterr()
