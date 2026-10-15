"""Approver keys and signed approvals.

An approval is worth what its signature is worth. The agent's process should never hold an
approver's key: the approver signs the action digest elsewhere (``gleipnir approve sign`` on their
machine, or a passkey on the static page site/approve/index.html) and the vendor records the
signature it is handed with ``rec.approve(..., signature=...)``.

Flow::

    digest = rec.approval_digest(refund, {"order": "A1", "amount": 500})   # vendor, shows it to the approver
    sig = ApproverKey.load("anna.pem", approver_id="ops:anna").sign(digest)  # approver, on their own device
    approval = rec.approve(refund, {"order": "A1", "amount": 500}, signature=sig)

The buyer lists who may approve in an approver registry (``ApproverKey.registry_entry``, or the
passkey page's registration output) and verifies with ``gleipnir-verify --approvers FILE``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gleipnir_verify.approvals import approval_challenge, check_signature
from gleipnir_verify.approvals import approval_message as _message_for_digest
from gleipnir_verify.crypto import (
    b64u,
    encode_p256_public_key,
    encode_p256_signature,
    encode_public_key,
    encode_signature,
)
from gleipnir_verify.verifier import action_digest

from .keys import write_private_file
from .util import to_jsonable

__all__ = ["ApproverKey", "approval_challenge", "approval_digest", "approval_message", "parse_signature",
           "check_approval_signature"]


def approval_digest(tool: str, args: Mapping[str, Any], system: str) -> str:
    """The action digest an approval of ``tool(args)`` on ``system`` commits to.

    ``args`` must be exactly as the action will record them, so after redaction. For a tool with
    redacted fields use ``Recorder.approval_digest``, which applies the recorder's redaction.
    """
    return action_digest(tool, system, to_jsonable(dict(args)))


def approval_message(tool: str, args: Mapping[str, Any], system: str) -> bytes:
    """The exact bytes an approver signs: ``"gleipnir/approval/v1\\n" || action_digest``."""
    return _message_for_digest(approval_digest(tool, args, system))


class ApproverKey:
    """An approver's own signing key (Ed25519 or ECDSA P-256). Keep it on the approver's device."""

    def __init__(self, private_key: Ed25519PrivateKey | ec.EllipticCurvePrivateKey, approver_id: str):
        if not isinstance(approver_id, str) or not approver_id:
            raise ValueError("approver_id must be a non-empty string")
        if isinstance(private_key, ec.EllipticCurvePrivateKey) and private_key.curve.name != "secp256r1":
            raise ValueError("ECDSA approver keys must be P-256")
        if not isinstance(private_key, (Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
            raise ValueError("approver keys are Ed25519 or ECDSA P-256")
        self._key = private_key
        self.approver_id = approver_id

    @classmethod
    def generate(cls, approver_id: str, kind: str = "ed25519") -> ApproverKey:
        if kind == "ed25519":
            return cls(Ed25519PrivateKey.generate(), approver_id)
        if kind in ("ecdsa-p256", "p256"):
            return cls(ec.generate_private_key(ec.SECP256R1()), approver_id)
        raise ValueError("kind must be 'ed25519' or 'ecdsa-p256'")

    @classmethod
    def load(cls, path: str | Path, approver_id: str) -> ApproverKey:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        return cls(key, approver_id)  # type: ignore[arg-type]

    def save(self, path: str | Path) -> Path:
        """Write the private key (PKCS#8 PEM, mode 0600). Fails if the file exists."""
        path = Path(path)
        write_private_file(path, self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
        return path

    @property
    def public_key(self) -> str:
        if isinstance(self._key, Ed25519PrivateKey):
            raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return encode_public_key(raw)
        spki = self._key.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        return encode_p256_public_key(spki)

    def sign(self, action_digest: str) -> dict[str, Any]:
        """Sign an approval of the action with this digest; returns ``review.signature``."""
        approval_challenge(action_digest)  # validates the digest's form
        msg = _message_for_digest(action_digest)
        if isinstance(self._key, Ed25519PrivateKey):
            sig = encode_signature(self._key.sign(msg))
        else:
            sig = encode_p256_signature(self._key.sign(msg, ec.ECDSA(hashes.SHA256())))
        return {"type": "key", "approver_id": self.approver_id, "public_key": self.public_key, "sig": sig}

    def registry_entry(self, name: str, roles: list[str] | None = None) -> dict[str, Any]:
        """This approver's entry for the buyer's approver registry (``gleipnir-verify --approvers``)."""
        entry: dict[str, Any] = {"id": self.approver_id, "name": name, "public_key": self.public_key}
        if roles:
            entry["roles"] = list(roles)
        return entry


def parse_signature(signature: Mapping[str, Any] | str) -> dict[str, Any]:
    """A signature as handed over: a dict, or the JSON text printed by the CLI or the passkey page."""
    if isinstance(signature, str):
        try:
            signature = json.loads(signature)
        except ValueError:
            raise ValueError("the approval signature is not valid JSON") from None
    if not isinstance(signature, Mapping):
        raise ValueError("the approval signature must be a JSON object")
    return dict(signature)


def check_approval_signature(action_digest: str, signature: Mapping[str, Any],
                             webauthn_origins: list[str] | None = None) -> None:
    """Raise ValueError unless ``signature`` is a valid approver signature over ``action_digest``.

    This checks the signature, not who the key belongs to: that is the buyer's registry's job.
    """
    body = {"action_digest": action_digest, "signature": dict(signature)}
    for level, code, message in check_signature(body, None, webauthn_origins, False):
        if level == "error":
            raise ValueError(f"{code}: {message}")


def challenge_b64u(action_digest: str) -> str:
    """The WebAuthn challenge for a digest, base64url (what the passkey page signs)."""
    return b64u(approval_challenge(action_digest))
