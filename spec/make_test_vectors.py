"""Regenerate spec/test-vectors/*.json. Deterministic: fixed key seed, fixed records.

Run: uv run python spec/make_test_vectors.py
Every implementation (Python, TypeScript, ...) must reproduce canonical bytes, hashes,
signatures and Merkle roots exactly.
"""

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gleipnir_verify import merkle
from gleipnir_verify.canon import canonicalize, hash_to_bytes, record_hash
from gleipnir_verify.crypto import encode_public_key, encode_signature, key_id, record_message

OUT = Path(__file__).parent / "test-vectors"
SEED = bytes(range(32))
sk = Ed25519PrivateKey.from_private_bytes(SEED)
raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
KID, PUB = key_id(raw), encode_public_key(raw)

RECORDS = {
    "01-genesis": {"v": 1, "kind": "genesis", "chain": "ch_vector", "seq": 0, "id": "gen_1",
                   "time": "2026-10-14T09:00:00.000Z", "key": KID,
                   "public_key": {"id": KID, "public": PUB},
                   "config": {"heartbeat_seconds": 600, "segment_max_records": 1000}},
    "02-action-unicode-numbers": {
        "v": 1, "kind": "action", "chain": "ch_vector", "seq": 1, "id": "act_1",
        "time": "2026-10-14T09:00:01.250Z", "key": KID, "prev": "sha256:" + "ab" * 32,
        "agent": {"id": "support-agent", "version": "3.2.4"},
        "tool": {"name": "issue_refund", "system": "payments-api"},
        "args": {"order_id": "A-1001", "amount": 42.1, "note": "Grüße €", "big": 9007199254740991,
                 "small": 1e-7, "neg": -0.0, "card": {"redacted": "hmac-sha256:" + "0" * 64}},
        "response": {"status": "ok", "body": {"refund_id": "R-9", "amount": 42.1, "ok": True, "x": None}},
        "outcome": {"check": "match", "method": "verify_outcome"},
        "t": {"start": "2026-10-14T09:00:01.000Z", "end": "2026-10-14T09:00:01.250Z"},
    },
}

for name, rec in RECORDS.items():
    rec = dict(rec)
    h = record_hash(rec)
    rec["sig"] = encode_signature(sk.sign(record_message(h)))
    vector = {"description": f"record {name}", "private_key_seed_hex": SEED.hex(), "public_key": PUB,
              "key_id": KID, "record": rec, "canonical": canonicalize({k: v for k, v in rec.items() if k != "sig"})
              .decode("utf-8"), "hash": h}
    (OUT / f"{name}.json").write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

# ECDSA P-256 key type (RFC 6979 deterministic signatures, so the vector is reproducible).
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from gleipnir_verify.crypto import encode_p256_public_key, encode_p256_signature  # noqa: E402

p256 = ec.derive_private_key(int.from_bytes(bytes(range(1, 33)), "big"), ec.SECP256R1())
spki = p256.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
P256_KID, P256_PUB = key_id(("ecdsa-p256", spki)), encode_p256_public_key(spki)
prec = {"v": 1, "kind": "genesis", "chain": "ch_vector_p256", "seq": 0, "id": "gen_p256",
        "time": "2026-10-14T09:00:00.000Z", "key": P256_KID, "public_key": {"id": P256_KID, "public": P256_PUB},
        "config": {"heartbeat_seconds": 600, "segment_max_records": 1000}}
ph = record_hash(prec)
prec["sig"] = encode_p256_signature(
    p256.sign(record_message(ph), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
(OUT / "03-genesis-ecdsa-p256.json").write_text(json.dumps({
    "description": "genesis signed with an ECDSA P-256 key (deterministic RFC 6979 signature)",
    "private_key_scalar_hex": bytes(range(1, 33)).hex(), "public_key": P256_PUB, "key_id": P256_KID,
    "record": prec, "canonical": canonicalize({k: v for k, v in prec.items() if k != "sig"}).decode("utf-8"),
    "hash": ph}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

leaves = [hash_to_bytes(record_hash(r)) for r in RECORDS.values()]
merkle_vectors = {"description": "RFC 6962 Merkle roots over raw 32-byte record hashes",
                  "cases": []}
for n in [0, 1, 2, 3, 5, 8]:
    entries = [hash_to_bytes("sha256:" + bytes([i]) .hex() * 32) for i in range(n)]
    case = {"leaves": [e.hex() for e in entries], "root": merkle.root(entries).hex()}
    if n:
        case["proofs"] = [[p.hex() for p in merkle.inclusion_proof(i, entries)] for i in range(n)]
    merkle_vectors["cases"].append(case)
(OUT / "merkle.json").write_text(json.dumps(merkle_vectors, indent=2) + "\n")
print("wrote", sorted(p.name for p in OUT.iterdir()))
