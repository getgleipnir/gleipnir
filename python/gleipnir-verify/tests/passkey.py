"""Test helper: a software passkey (ES256) that makes real WebAuthn assertions, as a phone would."""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from gleipnir_verify.crypto import b64u, encode_p256_public_key

RP_ID = "bank.example"
ORIGIN = "https://bank.example"
WEBAUTHN = {"rp_id": RP_ID, "origins": [ORIGIN]}


class Passkey:
    def __init__(self, secret: int | None = None) -> None:
        self.sk = ec.derive_private_key(secret, ec.SECP256R1()) if secret else ec.generate_private_key(ec.SECP256R1())
        der = self.sk.public_key().public_bytes(serialization.Encoding.DER,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_key = encode_p256_public_key(der)

    def assert_(self, challenge: bytes, *, origin: str = ORIGIN, rp_id: str = RP_ID, flags: int = 0x05) -> dict:
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (1).to_bytes(4, "big")
        cdj = json.dumps({"type": "webauthn.get", "challenge": b64u(challenge), "origin": origin},
                         separators=(",", ":")).encode()
        # Deterministic (RFC 6979) so the shared vectors stay byte-stable.
        der = self.sk.sign(auth + hashlib.sha256(cdj).digest(),
                           ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        return {"type": "webauthn", "authenticator_data": b64u(auth), "client_data_json": b64u(cdj),
                "signature": b64u(der)}
