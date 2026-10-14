import base64
import copy
import json
from pathlib import Path

import pytest

from gleipnir_verify.rekor import parse_checkpoint, verify_rekor_receipt

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "rekor_v2_receipt.json").read_text())
SEG = FIXTURE["segment_hash"]


def anchor():
    return copy.deepcopy(FIXTURE["anchor"])


def flip(b64text):
    raw = bytearray(base64.b64decode(b64text))
    raw[-1] ^= 1
    return base64.b64encode(bytes(raw)).decode()


def test_real_receipt_verifies_offline():
    res = verify_rekor_receipt(anchor(), segment_hash=SEG, options={})
    assert res.ok is True and res.independent


def test_other_segment_rejected():
    assert verify_rekor_receipt(anchor(), segment_hash="sha256:" + "00" * 32, options={}).ok is False


@pytest.mark.parametrize("mutate", [
    lambda a: a["receipt"]["entry"]["inclusionProof"]["hashes"].__setitem__(
        0, flip(a["receipt"]["entry"]["inclusionProof"]["hashes"][0])),
    lambda a: a["receipt"]["entry"]["inclusionProof"].__setitem__(
        "rootHash", flip(a["receipt"]["entry"]["inclusionProof"]["rootHash"])),
    lambda a: a["receipt"]["entry"]["inclusionProof"].__setitem__(
        "logIndex", str(int(a["receipt"]["entry"]["inclusionProof"]["logIndex"]) + 1)),
    lambda a: a["receipt"]["entry"].__setitem__("canonicalizedBody", flip(a["receipt"]["entry"]["canonicalizedBody"])),
    lambda a: a["receipt"]["anchor_key"].__setitem__("public", flip(a["receipt"]["anchor_key"]["public"])),
    lambda a: a["receipt"]["entry"]["logId"].__setitem__("keyId", base64.b64encode(b"\0" * 32).decode()),
])
def test_tampered_receipts_rejected(mutate):
    a = anchor()
    mutate(a)
    assert verify_rekor_receipt(a, segment_hash=SEG, options={}).ok is False


def test_forged_checkpoint_signature_rejected():
    a = anchor()
    cp = a["receipt"]["entry"]["inclusionProof"]["checkpoint"]
    lines = cp["envelope"].split("\n")
    for i, line in enumerate(lines):
        if line.startswith("— log2025-1"):
            name, sig = line.rsplit(" ", 1)
            lines[i] = f"{name} {flip(sig)}"
    cp["envelope"] = "\n".join(lines)
    assert verify_rekor_receipt(a, segment_hash=SEG, options={}).ok is False


def test_checkpoint_origin_must_match_log():
    a = anchor()
    cp = a["receipt"]["entry"]["inclusionProof"]["checkpoint"]
    cp["envelope"] = cp["envelope"].replace("log2025-1.rekor.sigstore.dev\n", "evil.example\n", 1)
    assert verify_rekor_receipt(a, segment_hash=SEG, options={}).ok is False


def test_untrusted_root_file(tmp_path):
    p = tmp_path / "root.json"
    p.write_text(json.dumps({"tlogs": []}))
    res = verify_rekor_receipt(anchor(), segment_hash=SEG, options={"trusted_root": str(p)})
    assert res.ok is False and "trusted root" in res.detail


def test_malformed_receipt():
    assert verify_rekor_receipt({"receipt": {}}, segment_hash=SEG, options={}).ok is False


def test_parse_checkpoint_errors():
    with pytest.raises(ValueError):
        parse_checkpoint("no blank line")
    with pytest.raises(ValueError):
        parse_checkpoint("a\n\n— x AAAA\n")
