"""Signed approvals: an approval bound to the approver's own key, made outside the agent's process.

An approval review may carry ``review.signature`` over the approval message
``"gleipnir/approval/v1\\n" || action_digest``:

- ``{"type": "key", "approver_id", "public_key", "sig"}``: an Ed25519 or ECDSA P-256 key in the
  record key format, ``sig`` in the record signature format.
- ``{"type": "webauthn", "approver_id", "public_key", "rp_id", "credential_id", "authenticator_data",
  "client_data_json", "signature"}``: a passkey assertion (ES256) whose challenge is the 32 raw bytes
  of the action digest, checked as WebAuthn Level 3 section 7.2 describes.

Who may approve is the buyer's decision: the buyer gives the verifier a registry of approvers
(:func:`load_approvers`). See spec/format.md, "Signed approvals".
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .crypto import P256_PREFIX, PublicKey, b64u, decode_public_key, key_id, unb64u, verify_signature

APPROVAL_DOMAIN = b"gleipnir/approval/v1\n"
SIGNATURE_TYPES = ("key", "webauthn")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_B64U = re.compile(r"[A-Za-z0-9_-]*", re.ASCII)

# authenticatorData flags (WebAuthn L3 section 6.1)
UP, UV, BE, BS, AT, ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80

ERROR, WARN, INFO = "error", "warn", "info"


def approval_message(action_digest: str) -> bytes:
    """The exact bytes an approver signs for an approval of the action with this digest."""
    return APPROVAL_DOMAIN + action_digest.encode("ascii")


def approval_challenge(action_digest: str) -> bytes:
    """The WebAuthn challenge for an approval: the 32 raw bytes of the action digest."""
    if not isinstance(action_digest, str) or not _DIGEST.fullmatch(action_digest):
        raise ValueError("action digest must be sha256: followed by 64 lowercase hex characters")
    return bytes.fromhex(action_digest[len("sha256:"):])


@dataclass
class Approver:
    """One entry of the buyer's approver registry."""

    id: str
    name: str
    type: str  # "key" or "webauthn"
    public: PublicKey
    public_key: str
    rp_id: str | None = None
    credential_id: str | None = None
    roles: list[str] = field(default_factory=list)


def _is_text(value: Any) -> bool:
    """A non-empty string that is valid Unicode (no lone surrogates from JSON escapes)."""
    if not isinstance(value, str) or not value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _is_b64u(value: Any) -> bool:
    return isinstance(value, str) and _B64U.fullmatch(value) is not None and len(value) % 4 != 1


class Registry(dict):  # type: ignore[type-arg]
    """A parsed approver registry: approver id -> :class:`Approver`."""


def load_approvers(data: Any) -> Registry:
    """Parse an approver registry (a JSON list). Raises ValueError with a message for the person."""
    if not isinstance(data, list):
        raise ValueError("the approvers file must be a JSON list")
    out = Registry()
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise ValueError(f"approver #{i} must be a JSON object")
        aid = entry.get("id")
        if not isinstance(aid, str) or not aid:
            raise ValueError(f"approver #{i} needs a non-empty string id")
        if aid in out:
            raise ValueError(f"approver id {aid!r} appears twice")
        name = entry.get("name")
        if not isinstance(name, str):
            raise ValueError(f"approver {aid!r} needs a string name")
        roles = entry.get("roles", [])
        if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
            raise ValueError(f"approver {aid!r}: roles must be a list of strings")
        if ("public_key" in entry) == ("webauthn" in entry):
            raise ValueError(f"approver {aid!r} needs exactly one of public_key or webauthn")
        if "public_key" in entry:
            try:
                pub = decode_public_key(entry["public_key"])
            except Exception:  # noqa: BLE001 - ValueError, UnsupportedAlgorithm, ...
                raise ValueError(f"approver {aid!r}: cannot read public_key") from None
            out[aid] = Approver(aid, name, "key", pub, entry["public_key"], roles=list(roles))
            continue
        wa = entry["webauthn"]
        if not isinstance(wa, dict):
            raise ValueError(f"approver {aid!r}: webauthn must be a JSON object")
        try:
            pub = decode_public_key(wa.get("public_key"))
        except Exception:  # noqa: BLE001
            pub = None
        if not isinstance(pub, tuple):
            raise ValueError(f"approver {aid!r}: webauthn.public_key must be an ECDSA P-256 key")
        rp_id = wa.get("rp_id")
        if not _is_text(rp_id):
            raise ValueError(f"approver {aid!r}: webauthn.rp_id must be a non-empty string")
        cred = wa.get("credential_id")
        if cred is not None and (not _is_b64u(cred) or not cred):
            raise ValueError(f"approver {aid!r}: webauthn.credential_id must be base64url")
        out[aid] = Approver(aid, name, "webauthn", pub, wa["public_key"], rp_id=rp_id, credential_id=cred,
                            roles=list(roles))
    return out


def check_signature(body: dict[str, Any], approvers: dict[str, Approver] | None, origins: list[str] | None,
                    require: bool) -> list[tuple[str, str, str]]:
    """Findings (level, code, message) for the signature of one approval review body.

    Unsigned approvals are errors when the buyer gave a registry or requires signed approvals; a valid
    signature by a key nobody vouched for (no registry) is a warning, or an error when required.
    """
    strict = ERROR if require else WARN
    if "signature" not in body:
        level = ERROR if require or approvers is not None else WARN
        return [(level, "approval_unsigned", "the approval is not signed by the approver, so who approved is only "
                 "the vendor's word")]
    sig = body["signature"]
    if not isinstance(sig, dict):
        return [(ERROR, "approval_bad_signature", "the approval signature is not a JSON object")]
    typ = sig.get("type")
    if not isinstance(typ, str) or typ not in SIGNATURE_TYPES:
        return [(ERROR, "approval_bad_signature", "the approval signature has an unknown type")]
    aid = sig.get("approver_id")
    if not isinstance(aid, str) or not aid:
        return [(ERROR, "approval_bad_signature", "the approval signature names no approver_id")]
    if "reviewer" in body and body["reviewer"] != aid:
        return [(ERROR, "approval_bad_signature", f"the approval names reviewer {body['reviewer']!r} but is signed "
                 f"by {aid!r}")]
    bad = "approval_bad_signature" if typ == "key" else "approval_webauthn_invalid"
    try:
        pub = decode_public_key(sig.get("public_key"))
    except Exception:  # noqa: BLE001 - ValueError, UnsupportedAlgorithm, ...
        return [(ERROR, bad, f"cannot read the public key of approver {aid!r}")]
    if typ == "webauthn" and not isinstance(pub, tuple):
        return [(ERROR, bad, f"the passkey of approver {aid!r} is not an ECDSA P-256 key")]
    entry: Approver | None = None
    if approvers is not None:
        entry = approvers.get(aid)
        if entry is None:
            return [(ERROR, "approval_unknown_approver", f"approver {aid!r} is not in the approver registry")]
        if entry.type != typ:
            return [(ERROR, "approval_unknown_approver", f"approver {aid!r} is registered for {entry.type} "
                     f"signatures, not {typ}")]
        if key_id(entry.public) != key_id(pub):
            return [(ERROR, "approval_unknown_approver", f"approver {aid!r} signed with a key that is not the one "
                     "in the approver registry")]
        pub = entry.public
    digest = body.get("action_digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        return [(ERROR, bad, "the approved action digest is malformed, so no signature can cover it")]
    if typ == "key":
        if not verify_signature(pub, approval_message(digest), sig.get("sig")):
            return [(ERROR, bad, f"the signature of approver {aid!r} does not match the approved action")]
    else:
        rp_id = entry.rp_id if entry is not None else sig.get("rp_id")
        if not _is_text(rp_id):
            return [(ERROR, bad, "WebAuthn assertion invalid: no valid rp_id")]
        allowed = list(origins) if origins else [f"https://{rp_id}"]
        detail = webauthn_problem(sig, pub, digest, rp_id, allowed,
                                  entry.credential_id if entry is not None else None)
        if detail is not None:
            return [(ERROR, bad, f"WebAuthn assertion invalid: {detail}")]
    if entry is not None:
        return [(INFO, "approval_verified", f"approved by {entry.name} ({aid}), signature verified")]
    return [(strict, "approval_unknown_approver", f"the signature by {aid!r} is valid, but no approver registry "
             "was given, so nothing shows whose key it is (pass --approvers)")]


def webauthn_problem(sig: dict[str, Any], pub: PublicKey, digest: str, rp_id: str, origins: list[str],
                     credential_id: str | None) -> str | None:
    """Why a WebAuthn assertion does not approve this digest, or None when it does."""
    fields = (sig.get("authenticator_data"), sig.get("client_data_json"), sig.get("signature"))
    if not all(_is_b64u(f) for f in fields):
        return "authenticator_data, client_data_json and signature must be base64url strings"
    auth, cdj, der = (unb64u(f) for f in fields)  # type: ignore[arg-type]
    if len(auth) < 37:
        return "authenticator data is too short"
    try:
        cd = json.loads(cdj.decode("utf-8"))
    except Exception:  # noqa: BLE001 - any decode/parse failure
        cd = None
    if not isinstance(cd, dict):
        return "client data is not a JSON object"
    if cd.get("type") != "webauthn.get":
        return "client data type is not webauthn.get"
    if cd.get("challenge") != b64u(approval_challenge(digest)):
        return "the challenge is not the approved action digest"
    origin = cd.get("origin")
    if not isinstance(origin, str):
        return "client data has no origin"
    if origin not in origins:
        return f"origin {origin!r} is not allowed"
    if cd.get("crossOrigin") is True or "topOrigin" in cd:
        return "the assertion was made in a cross-origin frame"
    if auth[:32] != hashlib.sha256(rp_id.encode("utf-8")).digest():
        return "rpIdHash does not match the relying party id"
    flags = auth[32]
    if not flags & UP:
        return "user presence (UP) flag not set"
    if not flags & UV:
        return "user verification (UV) flag not set"
    if flags & AT:
        return "attested credential data (AT) flag set in an assertion"
    if flags & BS and not flags & BE:
        return "backup state (BS) set without backup eligibility (BE)"
    if (len(auth) > 37) != bool(flags & ED):
        return "authenticator data length does not match its flags"
    if credential_id is not None and sig.get("credential_id") != credential_id:
        return "the credential id is not the registered one"
    if not verify_signature(pub, auth + hashlib.sha256(cdj).digest(), P256_PREFIX + fields[2]):  # type: ignore[operator]
        return "the signature does not verify"
    return None
