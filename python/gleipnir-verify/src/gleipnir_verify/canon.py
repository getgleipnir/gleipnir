"""Canonical JSON (RFC 8785 / JCS) and record hashing."""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

HASH_PREFIX = "sha256:"


def canonicalize(obj: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of a JSON value."""
    return rfc8785.dumps(obj)


def sha256_tagged(data: bytes) -> str:
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def record_hash(record: dict[str, Any]) -> str:
    """Hash of a record: sha256 over the JCS encoding of the record without its ``sig`` field."""
    body = {k: v for k, v in record.items() if k != "sig"}
    return sha256_tagged(canonicalize(body))


def hash_to_bytes(tagged: str) -> bytes:
    if not isinstance(tagged, str) or not tagged.startswith(HASH_PREFIX):
        raise ValueError(f"not a sha256 hash: {tagged!r}")
    raw = bytes.fromhex(tagged[len(HASH_PREFIX) :])
    if len(raw) != 32:
        raise ValueError(f"wrong hash length: {tagged!r}")
    return raw


def bytes_to_hash(raw: bytes) -> str:
    return HASH_PREFIX + raw.hex()
