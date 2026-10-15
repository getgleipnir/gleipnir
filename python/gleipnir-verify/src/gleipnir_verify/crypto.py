"""Record signing keys and signatures.

Two key types are supported:

- ``ed25519`` (default): public key ``"ed25519:" || b64url(raw 32 bytes)``, signature
  ``"ed25519:" || b64url(64-byte signature)``, key id ``k_ed25519_<16 hex of SHA-256(raw)>``.
- ``ecdsa-p256`` (for HSM/KMS setups without Ed25519, e.g. Azure Key Vault, Cloud KMS HSM):
  public key ``"ecdsa-p256:" || b64url(DER SubjectPublicKeyInfo)``, signature
  ``"ecdsa-p256:" || b64url(DER ECDSA signature)`` over SHA-256 of the message, key id
  ``k_p256_<16 hex of SHA-256(DER SPKI)>``.

In both cases the signed message is ``"gleipnir/record/v1\\n" || record_hash``.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RECORD_DOMAIN = b"gleipnir/record/v1\n"
PUBKEY_PREFIX = "ed25519:"
SIG_PREFIX = "ed25519:"
P256_PREFIX = "ecdsa-p256:"

# A decoded public key: raw Ed25519 bytes, or ("ecdsa-p256", DER SPKI).
PublicKey = Union[bytes, tuple]


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def record_message(record_hash: str) -> bytes:
    """The exact bytes a record signature covers."""
    return RECORD_DOMAIN + record_hash.encode("ascii")


def encode_public_key(raw: bytes) -> str:
    return PUBKEY_PREFIX + b64u(raw)


def encode_p256_public_key(spki_der: bytes) -> str:
    return P256_PREFIX + b64u(spki_der)


def decode_public_key(text: str) -> PublicKey:
    if not isinstance(text, str):
        raise ValueError("public key must be a string")
    if text.startswith(PUBKEY_PREFIX):
        raw = unb64u(text[len(PUBKEY_PREFIX):])
        if len(raw) != 32:
            raise ValueError("bad ed25519 public key length")
        return raw
    if text.startswith(P256_PREFIX):
        der = unb64u(text[len(P256_PREFIX):])
        key = serialization.load_der_public_key(der)
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
            raise ValueError("not an ECDSA P-256 public key")
        return ("ecdsa-p256", der)
    raise ValueError("unsupported public key type")


def key_id(public: PublicKey) -> str:
    """Short, stable identifier of a public key (also its fingerprint)."""
    if isinstance(public, (bytes, bytearray)):
        return "k_ed25519_" + hashlib.sha256(public).hexdigest()[:16]
    return "k_p256_" + hashlib.sha256(public[1]).hexdigest()[:16]


def encode_signature(sig: bytes) -> str:
    return SIG_PREFIX + b64u(sig)


def encode_p256_signature(der_sig: bytes) -> str:
    return P256_PREFIX + b64u(der_sig)


def verify_signature(public: PublicKey, message: bytes, sig_text: str) -> bool:
    if not isinstance(sig_text, str):
        return False
    try:
        if isinstance(public, (bytes, bytearray)):
            if not sig_text.startswith(SIG_PREFIX):
                return False
            Ed25519PublicKey.from_public_bytes(bytes(public)).verify(unb64u(sig_text[len(SIG_PREFIX):]), message)
            return True
        if not sig_text.startswith(P256_PREFIX):
            return False
        key = serialization.load_der_public_key(public[1])
        assert isinstance(key, ec.EllipticCurvePublicKey)
        key.verify(unb64u(sig_text[len(P256_PREFIX):]), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
