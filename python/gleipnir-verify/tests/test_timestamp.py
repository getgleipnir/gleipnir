import base64
import copy
import json
from datetime import timedelta
from pathlib import Path

from chainbuilder import Builder

from gleipnir_verify import verify_records
from gleipnir_verify.anchors import AnchorResult
from gleipnir_verify.canon import record_hash
from gleipnir_verify.timestamp import verify_timestamp_receipt

FIX = json.loads((Path(__file__).parent / "fixtures" / "rfc3161_receipt.json").read_text())
SEG = FIX["segment_hash"]


def test_real_token_verifies_offline():
    res = verify_timestamp_receipt(FIX["anchor"], segment_hash=SEG, options={})
    assert res.ok is True and res.independent and res.time.startswith("2026-10-14T")


def test_wrong_segment_and_corrupt_token_rejected():
    assert verify_timestamp_receipt(FIX["anchor"], segment_hash="sha256:" + "00" * 32, options={}).ok is False
    a = copy.deepcopy(FIX["anchor"])
    raw = bytearray(base64.b64decode(a["receipt"]["response"]))
    raw[-10] ^= 0xFF
    a["receipt"]["response"] = base64.b64encode(bytes(raw)).decode()
    assert verify_timestamp_receipt(a, segment_hash=SEG, options={}).ok is False
    a["receipt"]["response"] = "not base64!!"
    assert verify_timestamp_receipt(a, segment_hash=SEG, options={}).ok is False


def test_untrusted_tsa_rejected(tmp_path):
    p = tmp_path / "root.json"
    p.write_text(json.dumps({"tlogs": [], "timestampAuthorities": []}))
    assert verify_timestamp_receipt(FIX["anchor"], segment_hash=SEG, options={"trusted_root": str(p)}).ok is False


def _chain_with_fake_timestamps(delay_s):
    """A chain whose segments carry 'rfc3161' receipts checked by a stub returning a chosen time."""
    b = Builder()
    segs = []
    for i in range(3):
        b.action(i)
        segs.append(b.segment())
    for s in segs:
        b._add({"kind": "anchor", "anchor": {"segment_seq": s["seq"], "segment_hash": record_hash(s),
                                             "type": "rfc3161", "receipt": {}}})
    closes = {s["seq"]: s["segment"]["closed_at"] for s in segs}

    def stub(receipt, *, segment_hash, chain, options):
        from gleipnir_verify.verifier import parse_time
        t = parse_time(closes[receipt["segment_seq"]]) + timedelta(seconds=delay_s)
        return AnchorResult(True, "stub", independent=True, time=t.strftime("%Y-%m-%dT%H:%M:%SZ"))

    return b, {"rfc3161": stub}


def test_timely_timestamps_pass_requirements():
    b, verifiers = _chain_with_fake_timestamps(5)
    r = verify_records(b.records, anchor_verifiers=verifiers, require_anchor=["rfc3161"], max_anchor_delay=600)
    assert r.valid(), [f.as_dict() for f in r.findings]
    assert r.summary["segments_timestamped"] == 3


def test_rebuilt_history_timestamped_late_is_caught():
    b, verifiers = _chain_with_fake_timestamps(3 * 86400)
    r = verify_records(b.records, anchor_verifiers=verifiers, max_anchor_delay=3600)
    assert "late_timestamp" in {f.code for f in r.errors}
    r2 = verify_records(b.records, anchor_verifiers=verifiers)
    assert r2.valid() and "late_timestamp" in {f.code for f in r2.warnings}


def test_missing_timestamp_fails_when_required():
    b = Builder().standard()
    r = verify_records(b.records, require_anchor=["rfc3161"])
    assert "anchor_required" in {f.code for f in r.errors}
