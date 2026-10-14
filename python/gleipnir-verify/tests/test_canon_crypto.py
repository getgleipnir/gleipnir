import json
from pathlib import Path

import pytest

from gleipnir_verify.canon import canonicalize, hash_to_bytes, record_hash
from gleipnir_verify.crypto import decode_public_key, encode_public_key, verify_signature

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "test-vectors"


def test_jcs_rfc8785_examples():
    # Examples from RFC 8785 section 3.2.3 (key ordering) and number formatting.
    assert canonicalize({"b": 1, "a": [3, 2], "c": {"z": True, "y": None}}) == \
        b'{"a":[3,2],"b":1,"c":{"y":null,"z":true}}'
    assert canonicalize(1e21) == b"1e+21"
    assert canonicalize(0.000001) == b"0.000001"
    assert canonicalize(1e-7) == b"1e-7"
    assert canonicalize("\u000f\n\u20ac") == b'"\\u000f\\n\xe2\x82\xac"'


def test_record_hash_ignores_sig_only():
    r = {"a": 1, "sig": "x"}
    assert record_hash(r) == record_hash({"a": 1})
    assert record_hash(r) != record_hash({"a": 2, "sig": "x"})


def test_hash_parsing():
    with pytest.raises(ValueError):
        hash_to_bytes("md5:00")
    with pytest.raises(ValueError):
        hash_to_bytes("sha256:00")


def test_public_key_roundtrip_and_bad_sig():
    raw = bytes(range(32))
    assert decode_public_key(encode_public_key(raw)) == raw
    with pytest.raises(ValueError):
        decode_public_key("rsa:abc")
    assert not verify_signature(raw, b"m", "ed25519:AAAA")
    assert not verify_signature(raw, b"m", "nope")


@pytest.mark.parametrize("path", sorted(VECTORS.glob("*.json")), ids=lambda p: p.name)
def test_vectors(path):
    v = json.loads(path.read_text())
    if "record" in v:
        assert canonicalize({k: x for k, x in v["record"].items() if k != "sig"}).decode() == v["canonical"]
        assert record_hash(v["record"]) == v["hash"]
        assert verify_signature(decode_public_key(v["public_key"]), ("gleipnir/record/v1\n" + v["hash"]).encode(),
                                v["record"]["sig"])


def test_merkle_vectors():
    from gleipnir_verify import merkle

    v = json.loads((VECTORS / "merkle.json").read_text())
    for case in v["cases"]:
        leaves = [bytes.fromhex(x) for x in case["leaves"]]
        assert merkle.root(leaves).hex() == case["root"]
        for i, proof in enumerate(case.get("proofs", [])):
            assert merkle.verify_inclusion(i, len(leaves), merkle.leaf_hash(leaves[i]),
                                           [bytes.fromhex(p) for p in proof], bytes.fromhex(case["root"]))
