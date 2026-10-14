import copy
import json
import zipfile
from datetime import timedelta

import pytest
from chainbuilder import Builder, Key, resign
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gleipnir_verify import cli, verify_records
from gleipnir_verify.canon import record_hash
from gleipnir_verify.verifier import verify_bundle

OPTS = {"local_anchor_entries": None}


def run(b_or_records, builder=None, **kw):
    records = b_or_records if isinstance(b_or_records, list) else b_or_records.records
    log = (builder or (b_or_records if not isinstance(b_or_records, list) else None))
    opts = {"local_anchor_entries": log.anchor_log} if log is not None else {}
    return verify_records(records, anchor_options=opts, **kw)


def codes(report):
    return {f.code for f in report.errors}


def test_valid_chain():
    b = Builder().standard()
    r = run(b)
    assert r.valid(), [f.as_dict() for f in r.findings]
    assert r.valid(strict=True), [f.as_dict() for f in r.findings]
    assert r.summary["segments"] == 3 and r.summary["segments_anchored"] == 3


def test_empty_and_no_genesis():
    assert codes(verify_records([])) == {"empty"}
    b = Builder().standard()
    assert codes(verify_records(b.records[1:])) == {"no_genesis"}


def test_edit_detected():
    b = Builder().standard()
    recs = b.copy()
    recs[3]["args"]["amount"] = 9999
    assert "bad_signature" in codes(run(recs, b))


def test_edit_and_resign_with_other_key_detected():
    b = Builder().standard()
    recs = resign(b.copy(), Key(), start=3)
    recs[3]["args"]["amount"] = 999
    resign(recs, Key(), start=3)
    assert "unknown_key" in codes(run(recs, b))


def test_full_rewrite_with_attacker_key_caught_by_expect_key():
    b = Builder().standard()
    attacker = Key()
    recs = b.copy()
    recs[0]["public_key"] = {"id": attacker.id, "public": attacker.public}
    resign(recs, attacker, start=0)
    r = run(recs, b, expect_key=b.key.id)
    assert "unexpected_key" in codes(r)


def test_delete_detected():
    b = Builder().standard()
    recs = b.copy()
    del recs[2]
    assert {"gap", "broken_chain"} <= codes(run(recs, b))


def test_reorder_detected():
    b = Builder().standard()
    recs = b.copy()
    recs[2], recs[3] = recs[3], recs[2]
    assert "reordered" in codes(run(recs, b)) or "broken_chain" in codes(run(recs, b))


def test_truncate_detected_by_manifest_and_expect_until():
    b = Builder().standard()
    recs = b.copy()[:-6]
    manifest = {"chain": b.chain, "from_seq": 1, "to_seq": b.records[-1]["seq"], "format": 1}
    assert "truncated" in codes(run(recs, b, manifest=manifest))
    # Manifest rewritten too: a truncation older than one heartbeat is caught by expect_until.
    manifest2 = dict(manifest, to_seq=recs[-1]["seq"])
    later = b.now + timedelta(seconds=b.heartbeat + 120)
    assert "coverage" in codes(run(recs, b, manifest=manifest2, expect_until=later))
    # Within one heartbeat it is not; a known head from an earlier bundle catches it.
    assert run(recs, b, manifest=manifest2, expect_until=b.now).valid()
    head = (b.records[-1]["seq"], record_hash(b.records[-1]))
    assert "known_head_missing" in codes(run(recs, b, manifest=manifest2, known_head=head))
    rewritten = b.copy()
    rewritten[-2]["id"] = "x"
    resign(rewritten, b.key, start=len(rewritten) - 2)
    assert "known_head_changed" in codes(run(rewritten, b, known_head=head))


def test_merkle_mismatch_when_segment_rewritten():
    b = Builder().standard()
    recs = b.copy()
    seg = next(r for r in recs if r["kind"] == "segment")
    seg["segment"]["root"] = "sha256:" + "00" * 32
    resign(recs, b.key, start=seg["seq"])
    assert "merkle_mismatch" in codes(run(recs, b))


def test_anchor_mismatch_when_segment_rewritten_and_receipt_kept():
    b = Builder().standard()
    recs = b.copy()
    # Attacker edits an action, recomputes everything (same key), but cannot change the anchor log.
    recs[2]["args"]["amount"] = 999
    seg = next(r for r in recs if r["kind"] == "segment")
    from gleipnir_verify import merkle
    from gleipnir_verify.canon import hash_to_bytes
    resign(recs, b.key, start=2)
    members = [record_hash(recs[i]) for i in range(seg["segment"]["from"], seg["seq"])]
    seg["segment"]["root"] = "sha256:" + merkle.root([hash_to_bytes(h) for h in members]).hex()
    resign(recs, b.key, start=seg["seq"])
    # fix receipts to the new hash, as an attacker would
    for r in recs:
        if r["kind"] == "anchor" and r["anchor"]["segment_seq"] == seg["seq"]:
            r["anchor"]["segment_hash"] = record_hash(seg)
    resign(recs, b.key, start=seg["seq"] + 1)
    assert "anchor_invalid" in codes(run(recs, b))


def test_unanchored_and_tail_warnings():
    b = Builder()
    for i in range(3):
        b.action(i)
    seg = b.segment()
    b.action(99)
    r = run(b)
    assert r.valid()
    assert {"unanchored_segments", "unsegmented_tail"} <= {f.code for f in r.warnings}
    assert not r.valid(strict=True)
    b.anchor(seg)


def test_missed_heartbeat_warns():
    b = Builder(heartbeat=60)
    b.action()
    b.tick(3600)
    seg = b.segment()
    b.anchor(seg)
    r = run(b)
    assert "missed_heartbeat" in {f.code for f in r.warnings}


def test_key_rotation():
    b = Builder()
    b.action(1)
    new = Key()
    b._add({"kind": "key_rotation", "new_key": {"id": new.id, "public": new.public}})
    b.key = new
    b.action(2)
    seg = b.segment()
    b.anchor(seg)
    assert run(b).valid()
    # old key used after rotation
    old_key = Key()
    recs = b.copy()
    assert run(recs, b).valid()
    recs2 = resign(b.copy(), b.key, start=0)
    assert not run(recs2, b).valid()  # genesis now signed by the new key, which genesis does not declare
    del old_key


def test_wrong_chain_and_version():
    b = Builder().standard()
    recs = b.copy()
    recs[4]["chain"] = "other"
    resign(recs, b.key, start=4)
    assert "wrong_chain" in codes(run(recs, b))
    recs = b.copy()
    recs[0]["v"] = 2
    assert "format_version" in codes(run(recs, b))


def test_local_anchor_log_tampering():
    b = Builder().standard()
    log = copy.deepcopy(b.anchor_log)
    log[1]["segment_hash"] = "sha256:" + "11" * 32
    r = verify_records(b.records, anchor_options={"local_anchor_entries": log})
    assert "anchor_invalid" in codes(r)
    r = verify_records(b.records)
    assert r.valid() and any(f.code == "anchor_unchecked" for f in r.findings)


def test_partial_bundle_starting_at_segment():
    b = Builder().standard(segments=3, per=3)
    segs = [r for r in b.records if r["kind"] == "segment"]
    start = segs[0]["seq"] + 1  # second segment starts here
    recs = [b.records[0]] + b.records[start:]
    r = run(recs, b)
    assert r.valid(), [f.as_dict() for f in r.findings]
    assert any(f.code == "partial_bundle" for f in r.findings)


def test_partial_bundle_not_at_segment_boundary_fails():
    b = Builder().standard(segments=3, per=3)
    recs = [b.records[0]] + b.records[3:]
    assert not run(recs, b).valid()


def write_bundle(tmp_path, b, records=None, manifest=None):
    records = records if records is not None else b.records
    p = tmp_path / "bundle.zip"
    manifest = manifest or {"format": 1, "chain": b.chain, "from_seq": 1, "to_seq": records[-1]["seq"]}
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("records.jsonl", "".join(json.dumps(r) + "\n" for r in records))
        zf.writestr("anchors/local-anchor-log.jsonl", "".join(json.dumps(e) + "\n" for e in b.anchor_log))
    return p


def test_bundle_and_cli(tmp_path, capsys):
    b = Builder().standard()
    p = write_bundle(tmp_path, b)
    assert verify_bundle(p).valid(strict=True)
    assert cli.main([str(p)]) == 0
    assert "result: VALID" in capsys.readouterr().out
    assert cli.main([str(p), "--json", "--expect-key", b.key.id]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "VALID"
    assert cli.main([str(p), "--expect-key", "k_ed25519_0000000000000000"]) == 1
    late = (b.now + timedelta(days=1)).isoformat()
    assert cli.main([str(p), "--expect-until", late]) == 1
    capsys.readouterr()


def test_bad_bundles(tmp_path):
    p = tmp_path / "x.zip"
    p.write_bytes(b"not a zip")
    assert "bad_bundle" in codes(verify_bundle(p))
    b = Builder().standard()
    p2 = write_bundle(tmp_path, b, manifest={"format": 9})
    assert "format_version" in codes(verify_bundle(p2))


# ---- property tests: any edit, deletion, reorder or truncation must be caught -------------

def _chain():
    return Builder().standard(segments=3, per=4)


BASE = _chain()
N = len(BASE.records)
MANIFEST = {"chain": BASE.chain, "from_seq": 1, "to_seq": BASE.records[-1]["seq"], "format": 1}


def check_invalid(records):
    r = verify_records(records, manifest=MANIFEST, anchor_options={"local_anchor_entries": BASE.anchor_log},
                       expect_key=BASE.key.id, expect_until=BASE.now)
    return not r.valid()


def test_base_valid():
    r = verify_records(BASE.records, manifest=MANIFEST, anchor_options={"local_anchor_entries": BASE.anchor_log},
                       expect_key=BASE.key.id, expect_until=BASE.now)
    assert r.valid(strict=True), [f.as_dict() for f in r.findings]


def _paths(obj, prefix=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _paths(v, prefix + (i,))
    else:
        yield prefix


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(st.data())
def test_any_field_edit_fails(data):
    recs = copy.deepcopy(BASE.records)
    i = data.draw(st.integers(0, N - 1))
    paths = [p for p in _paths(recs[i])]
    path = data.draw(st.sampled_from(paths))
    target = recs[i]
    for k in path[:-1]:
        target = target[k]
    old = target[path[-1]]
    new = data.draw(st.one_of(st.integers(), st.text(max_size=5), st.booleans(), st.none()).filter(
        lambda v: v != old or type(v) is not type(old)))
    target[path[-1]] = new
    assert check_invalid(recs)


@settings(max_examples=200)
@given(st.data())
def test_any_deletion_fails(data):
    recs = copy.deepcopy(BASE.records)
    i = data.draw(st.integers(0, N - 1))
    del recs[i]
    assert check_invalid(recs)


@settings(max_examples=200)
@given(st.data())
def test_any_reorder_fails(data):
    recs = copy.deepcopy(BASE.records)
    i = data.draw(st.integers(0, N - 2))
    j = data.draw(st.integers(i + 1, N - 1))
    recs[i], recs[j] = recs[j], recs[i]
    assert check_invalid(recs)


@settings(max_examples=100)
@given(st.integers(1, N - 1))
def test_any_truncation_fails(k):
    assert check_invalid(copy.deepcopy(BASE.records[:k]))


@settings(max_examples=100)
@given(st.integers(1, N - 1))
def test_truncation_with_rewritten_manifest_fails_with_known_head(k):
    recs = copy.deepcopy(BASE.records[:k])
    manifest = dict(MANIFEST, to_seq=recs[-1]["seq"])
    head = (BASE.records[-1]["seq"], record_hash(BASE.records[-1]))
    r = verify_records(recs, manifest=manifest, anchor_options={"local_anchor_entries": BASE.anchor_log},
                       known_head=head)
    assert not r.valid()


@settings(max_examples=100)
@given(st.data())
def test_inserted_record_fails(data):
    recs = copy.deepcopy(BASE.records)
    i = data.draw(st.integers(1, N - 1))
    forged = copy.deepcopy(recs[i])
    forged["id"] = "forged"
    recs.insert(i, forged)
    assert check_invalid(recs)


def test_signed_insert_by_key_holder_breaks_segment_or_anchor():
    # Even the key holder cannot insert into an anchored segment without the anchor check failing.
    recs = copy.deepcopy(BASE.records)
    forged = copy.deepcopy(recs[2])
    forged["id"] = "forged"
    recs.insert(3, forged)
    for n, r in enumerate(recs):
        r["seq"] = n
    resign(recs, BASE.key, start=3)
    assert check_invalid(recs)


@pytest.mark.parametrize("seed", range(3))
def test_segment_drop_fails(seed):
    recs = copy.deepcopy(BASE.records)
    segs = [i for i, r in enumerate(recs) if r["kind"] == "segment"]
    del recs[segs[seed % len(segs)]]
    assert check_invalid(recs)


@pytest.mark.parametrize("bad", [
    [{"seq": 0}],
    [None],
    ["string"],
    [{"kind": "genesis", "seq": 0, "v": 1, "public_key": "x"}],
])
def test_malformed_input_never_crashes(bad):
    r = verify_records(bad)
    assert not r.valid()


def test_unencodable_values_are_reported_not_raised():
    recs = copy.deepcopy(BASE.records)
    recs[3]["args"]["amount"] = 2 ** 60
    recs[4]["args"]["amount"] = float("nan")
    r = verify_records(recs)
    assert not r.valid()


# ---- regressions from the independent review (2026-10-14) ------------------------------

def test_stripping_anchor_receipts_fails_when_anchor_required():
    b = Builder().standard()
    # The key holder rebuilds the whole chain, consistently, without any anchor receipts.
    forged = Builder(key=b.key)
    for s in range(3):
        for i in range(4):
            forged.action(s * 100 + i)
        forged.segment()
    assert verify_records(forged.records).valid()  # without a requirement: warnings only
    r = verify_records(forged.records, require_anchor="rekor")
    assert "anchor_required" in codes(r)


def test_require_anchor_rejects_non_independent_anchors():
    b = Builder().standard()
    r = verify_records(b.records, anchor_options={"local_anchor_entries": b.anchor_log}, require_anchor="rekor")
    assert "anchor_required" in codes(r)


def test_dropping_records_at_the_start_is_flagged():
    b = Builder().standard(segments=3, per=3)
    segs = [r for r in b.records if r["kind"] == "segment"]
    recs = [b.records[0]] + b.records[segs[0]["seq"] + 1:]
    r = run(recs, b)
    assert r.valid() and not r.valid(strict=True)
    assert r.summary["partial"] is True
    assert "partial_bundle" in codes(run(recs, b, require_full=True))


def test_unchecked_receipts_are_not_counted_as_anchored():
    b = Builder().standard()
    r = verify_records(b.records)
    assert r.summary["segments_anchored"] == 0
    assert "anchors_unchecked" in {f.code for f in r.warnings}


def test_manifest_key_must_match():
    b = Builder().standard()
    m = {"chain": b.chain, "from_seq": 1, "to_seq": b.records[-1]["seq"], "format": 1, "key": "k_ed25519_00"}
    assert "manifest_key" in codes(run(b.records, b, manifest=m))


@pytest.mark.parametrize("records_bytes,manifest_bytes", [
    (b"\xff\xfe\x00garbage", b'{"format": 1}'),
    (b"{}\n", b"[]"),
    (b"[" * 100000 + b"\n", b'{"format": 1}'),
    (b'{"seq": ' + b"9" * 5000 + b"}\n", b'{"format": 1}'),
    (b"[1, 2]\n", b'{"format": 1}'),
])
def test_hostile_bundles_never_crash(tmp_path, records_bytes, manifest_bytes, capsys):
    p = tmp_path / "hostile.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("records.jsonl", records_bytes)
    assert not verify_bundle(p).valid()
    assert cli.main([str(p)]) == 1
    capsys.readouterr()


@pytest.mark.parametrize("args", [["--known-head", "foo"], ["--expect-until", "yesterday"],
                                  ["--expect-until", "2026-10-14T10:00:00"]])
def test_bad_cli_arguments_exit_cleanly(tmp_path, args, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([str(tmp_path / "x.zip"), *args])
    assert exc.value.code == 2
    capsys.readouterr()
