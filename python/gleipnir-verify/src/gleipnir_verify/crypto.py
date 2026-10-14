"""Ed25519 keys and record signatures."""

from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RECORD_DOMAIN = b"gleipnir/record/v1\n"
PUBKEY_PREFIX = "ed25519:"
SIG_PREFIX = "ed25519:"


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


def decode_public_key(text: str) -> bytes:
    if not text.startswith(PUBKEY_PREFIX):
        raise ValueError("unsupported public key type")
    raw = unb64u(text[len(PUBKEY_PREFIX) :])
    if len(raw) != 32:
        raise ValueError("bad ed25519 public key length")
    return raw


def key_id(raw_public: bytes) -> str:
    """Short, stable identifier of a public key (also its fingerprint)."""
    return "k_ed25519_" + hashlib.sha256(raw_public).hexdigest()[:16]


def encode_signature(sig: bytes) -> str:
    return SIG_PREFIX + b64u(sig)


def verify_signature(raw_public: bytes, message: bytes, sig_text: str) -> bool:
    if not isinstance(sig_text, str) or not sig_text.startswith(SIG_PREFIX):
        return False
    try:
        sig = unb64u(sig_text[len(SIG_PREFIX) :])
        Ed25519PublicKey.from_public_bytes(raw_public).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False
