"""Regenerate spec/test-vectors/*.json. Deterministic: fixed key seed, fixed records.

Run: uv run python spec/make_test_vectors.py
Every implementation (Python, TypeScript, ...) must reproduce canonical bytes, hashes,
signatures and Merkle roots exactly.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

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

# ---- signed approvals (spec/format.md, "Signed approvals") ---------------------------------------------------
from gleipnir_verify.approvals import approval_challenge, approval_message, check_signature, load_approvers  # noqa: E402
from gleipnir_verify.crypto import b64u, unb64u  # noqa: E402
from gleipnir_verify.verifier import action_digest, verify_records  # noqa: E402

TOOL, SYSTEM = "issue_refund", "payments-api"
ARGS = {"order_id": "A-1001", "amount": "500.00", "currency": "EUR"}
DIGEST = action_digest(TOOL, SYSTEM, ARGS)
MSG = approval_message(DIGEST)


def _raw_pub(key: Ed25519PrivateKey) -> str:
    return encode_public_key(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _spki_pub(key: ec.EllipticCurvePrivateKey) -> str:
    return encode_p256_public_key(key.public_key().public_bytes(serialization.Encoding.DER,
                                                                serialization.PublicFormat.SubjectPublicKeyInfo))


ED_SEED, P256_SCALAR, WA_SCALAR = bytes(range(64, 96)), bytes(range(96, 128)), bytes(range(128, 160))
ed_approver = Ed25519PrivateKey.from_private_bytes(ED_SEED)
p256_approver = ec.derive_private_key(int.from_bytes(P256_SCALAR, "big"), ec.SECP256R1())
wa_key = ec.derive_private_key(int.from_bytes(WA_SCALAR, "big"), ec.SECP256R1())
other = Ed25519PrivateKey.from_private_bytes(bytes(range(160, 192)))
ED_PUB, P256_APPROVER_PUB, WA_PUB, OTHER_PUB = (_raw_pub(ed_approver), _spki_pub(p256_approver), _spki_pub(wa_key),
                                                _raw_pub(other))
RP_ID, ORIGIN = "approve.example.com", "https://approve.example.com"
CRED_ID = b64u(bytes(range(16)))


def _p256_det(key: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    return key.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))


def key_sig(approver_id: str, key: Any, pub: str, msg: bytes = MSG) -> dict:
    if isinstance(key, Ed25519PrivateKey):
        sig = encode_signature(key.sign(msg))
    else:
        sig = encode_p256_signature(_p256_det(key, msg))
    return {"type": "key", "approver_id": approver_id, "public_key": pub, "sig": sig}


def client_data(**over: Any) -> bytes:
    cd: dict[str, Any] = {"type": "webauthn.get", "challenge": b64u(approval_challenge(DIGEST)), "origin": ORIGIN,
                          "crossOrigin": False}
    cd.update(over)
    return json.dumps(cd, separators=(",", ":")).encode("utf-8")


def auth_data(rp_id: str = RP_ID, flags: int = 0x05, counter: int = 7) -> bytes:
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big")


def wa_sig(auth: bytes | None = None, cdj: bytes | None = None, cred: str = CRED_ID) -> dict:
    auth = auth_data() if auth is None else auth
    cdj = client_data() if cdj is None else cdj
    sig = _p256_det(wa_key, auth + hashlib.sha256(cdj).digest())
    return {"type": "webauthn", "approver_id": "ops:li", "public_key": WA_PUB, "rp_id": RP_ID,
            "credential_id": cred, "authenticator_data": b64u(auth), "client_data_json": b64u(cdj),
            "signature": b64u(sig)}


REGISTRY = [
    {"id": "ops:anna", "name": "Anna Berger", "public_key": ED_PUB, "roles": ["refunds"]},
    {"id": "ops:jonas", "name": "Jonas Weber", "public_key": P256_APPROVER_PUB},
    {"id": "ops:li", "name": "Li Wei", "webauthn": {"public_key": WA_PUB, "rp_id": RP_ID, "credential_id": CRED_ID}},
]
good_ed = key_sig("ops:anna", ed_approver, ED_PUB)
good_wa = wa_sig()
flipped_raw = bytearray(unb64u(good_ed["sig"][len("ed25519:"):]))
flipped_raw[0] ^= 1
CASES: list[tuple[str, Any]] = [
    ("key signature, Ed25519", good_ed),
    ("key signature, ECDSA P-256 (RFC 6979)", key_sig("ops:jonas", p256_approver, P256_APPROVER_PUB)),
    ("WebAuthn assertion (ES256), UP and UV set", good_wa),
    ("WebAuthn assertion with backup flags BE and BS", wa_sig(auth=auth_data(flags=0x1D))),
    ("unsigned approval", None),
    ("Ed25519 signature with one bit flipped", {**good_ed, "sig": "ed25519:" + b64u(bytes(flipped_raw))}),
    ("signature over the record domain instead of the approval domain",
     key_sig("ops:anna", ed_approver, ED_PUB, b"gleipnir/record/v1\n" + DIGEST.encode())),
    ("signed by a key that is not registered for this approver", key_sig("ops:anna", other, OTHER_PUB)),
    ("approver not in the registry", key_sig("ops:eve", other, OTHER_PUB)),
    ("unknown signature type", {**good_ed, "type": "pgp"}),
    ("WebAuthn: origin not allowed", wa_sig(cdj=client_data(origin="https://evil.example"))),
    ("WebAuthn: challenge is another digest",
     wa_sig(cdj=client_data(challenge=b64u(hashlib.sha256(b"other").digest())))),
    ("WebAuthn: type webauthn.create", wa_sig(cdj=client_data(type="webauthn.create"))),
    ("WebAuthn: cross-origin frame", wa_sig(cdj=client_data(crossOrigin=True))),
    ("WebAuthn: rpIdHash of another relying party", wa_sig(auth=auth_data(rp_id="evil.example"))),
    ("WebAuthn: user verification (UV) not set", wa_sig(auth=auth_data(flags=0x01))),
    ("WebAuthn: user presence (UP) not set", wa_sig(auth=auth_data(flags=0x04))),
    ("WebAuthn: attested credential data (AT) set", wa_sig(auth=auth_data(flags=0x45))),
    ("WebAuthn: another credential id", wa_sig(cred=b64u(bytes(16)))),
    ("WebAuthn: client data changed after signing",
     {**good_wa, "client_data_json": b64u(client_data(origin=ORIGIN + "/"))}),
    ("WebAuthn assertion presented as type key", {**good_wa, "type": "key"}),
]
REG = load_approvers(REGISTRY)
case_list = []
for name, sig in CASES:
    body = {"action_digest": DIGEST, "tool": TOOL, "system": SYSTEM,
            "reviewer": sig["approver_id"] if sig else "ops:anna", "decision": "approved", "before_execution": True}
    if sig is not None:
        body["signature"] = sig
    expected = {mode: [[lv, code] for lv, code, _ in check_signature(body, reg, [ORIGIN], req)]
                for mode, reg, req in (("no_registry", None, False), ("registry", REG, False), ("require", REG, True))}
    case_list.append({"description": name, "review": body, "expected": expected})

# One whole chain: genesis, the passkey-signed approval, the approved action, a segment.
chain_recs: list[dict] = []


def _add(fields: dict) -> dict:
    n = len(chain_recs)
    rec = {"v": 1, "chain": "ch_vector_approval", "seq": n, "id": f"r{n}", "time": f"2026-10-14T09:00:0{n}.000Z",
           "key": KID, **fields}
    if chain_recs:
        rec["prev"] = record_hash(chain_recs[-1])
    rec["sig"] = encode_signature(sk.sign(record_message(record_hash(rec))))
    chain_recs.append(rec)
    return rec


_add({"kind": "genesis", "public_key": {"id": KID, "public": PUB},
      "config": {"heartbeat_seconds": 600, "segment_max_records": 1000}})
approval_rec = _add({"kind": "review", "review": case_list[2]["review"]})
_add({"kind": "action", "agent": {"id": "support-agent", "version": "3.2.4"},
      "tool": {"name": TOOL, "system": SYSTEM}, "args": ARGS, "approval": approval_rec["id"],
      "response": {"status": "ok", "body": {"refund_id": "R-9"}},
      "t": {"start": "2026-10-14T09:00:02.000Z", "end": "2026-10-14T09:00:02.000Z"}})
_members = [hash_to_bytes(record_hash(r)) for r in chain_recs[1:]]
_add({"kind": "segment", "segment": {"from": 1, "count": 2, "root": "sha256:" + merkle.root(_members).hex(),
                                     "opened_at": "2026-10-14T09:00:00.000Z",
                                     "closed_at": "2026-10-14T09:00:03.000Z", "heartbeat": False}})
chain_expected = {}
for mode, kw in (("no_registry", {}), ("registry", {"approvers": REGISTRY}),
                 ("registry_other_origin", {"approvers": REGISTRY, "webauthn_origins": ["https://other.example"]}),
                 ("require", {"approvers": REGISTRY, "require_signed_approvals": True})):
    chain_report = verify_records(chain_recs, **kw)
    chain_expected[mode] = {"valid": chain_report.valid(),
                            "findings": [[f.level, f.code] for f in chain_report.findings]}

(OUT / "approvals.json").write_text(json.dumps({
    "description": "signed approvals: approval message, WebAuthn challenge, key and passkey signatures, and the "
                   "findings (level, code) each case produces without a registry, with the registry, and with "
                   "--require-signed-approvals; allowed origin " + ORIGIN,
    "tool": TOOL, "system": SYSTEM, "args": ARGS, "action_digest": DIGEST, "approval_message": MSG.decode("ascii"),
    "webauthn_challenge": b64u(approval_challenge(DIGEST)),
    "approver_keys": {"ops:anna": {"ed25519_seed_hex": ED_SEED.hex()},
                      "ops:jonas": {"p256_scalar_hex": P256_SCALAR.hex()},
                      "ops:li": {"p256_scalar_hex": WA_SCALAR.hex(), "rp_id": RP_ID, "origin": ORIGIN,
                                 "credential_id": CRED_ID, "authenticator_data_hex": auth_data().hex(),
                                 "client_data_json": client_data().decode("utf-8")}},
    "registry": REGISTRY, "allowed_origins": [ORIGIN], "cases": case_list,
    "chain": {"records": chain_recs, "expected": chain_expected},
}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", sorted(p.name for p in OUT.iterdir()))
