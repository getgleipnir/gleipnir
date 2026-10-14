"""Signing keys.

Records are signed with Ed25519. The default signer keeps a private key in a local
file, which is fine for development and pilots. Production deployments should plug
in a signer backed by a KMS or HSM (implement the ``Signer`` protocol).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gleipnir_verify.crypto import encode_public_key, encode_signature, key_id


class Signer(Protocol):
    @property
    def key_id(self) -> str: ...

    @property
    def public_key(self) -> str: ...

    def sign(self, message: bytes) -> str: ...


class Ed25519Signer:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._key = private_key
        raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._raw_public = raw
        self._key_id = key_id(raw)

    @classmethod
    def generate(cls) -> Ed25519Signer:
        return cls(Ed25519PrivateKey.generate())

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key(self) -> str:
        return encode_public_key(self._raw_public)

    def sign(self, message: bytes) -> str:
        return encode_signature(self._key.sign(message))

    def private_pem(self) -> bytes:
        return self._key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )


DEV_KEY_WARNING = """\
gleipnir: generated a new LOCAL signing key at {path}
  key id: {key_id}
  This key is fine for development and pilots. Anyone who can read this file can sign
  records as you, so for production keep the key in a KMS/HSM and pass a custom Signer.
  Publish the key id where buyers can see it (for example your trust center).
"""


def write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def load_or_create_signer(home: Path, quiet: bool = False) -> Ed25519Signer:
    path = home / "keys" / "signing-ed25519.pem"
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} is not an Ed25519 private key")
        return Ed25519Signer(key)
    signer = Ed25519Signer.generate()
    write_private_file(path, signer.private_pem())
    if not quiet:
        sys.stderr.write(DEV_KEY_WARNING.format(path=path, key_id=signer.key_id))
    return signer


def load_or_create_secret(home: Path, name: str) -> bytes:
    path = home / "keys" / name
    if path.exists():
        return path.read_bytes()
    secret = os.urandom(32)
    write_private_file(path, secret)
    return secret
