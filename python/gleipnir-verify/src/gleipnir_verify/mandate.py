"""Mandates for AI agents that pay: issue, sign, revoke, attach to a payment, check. See spec/mandate.md.

A company signatory signs a mandate for one agent. The bank checks every payment the agent starts
against it and signs a decision: allow, block or escalate.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .approvals import webauthn_problem
from .canon import canonicalize, hash_to_bytes, sha256_tagged
from .crypto import b64u, decode_public_key, encode_public_key, verify_signature

V = "0.1"
KINDS = ("mandate", "revocation", "payment", "decision")
RAILS = {"sepa", "sepa_instant", "ach", "wire", "faster_payments", "fednow", "rtp"}
_ESCALATE = {"signer_unknown", "status_unavailable", "over_payment_limit", "over_period_limit"}


# ---------- hashing and signing ----------

def obj_hash(obj: dict[str, Any], sig_field: str = "sig") -> str:
    """sha256 over the JCS encoding of the object without its signature field."""
    return sha256_tagged(canonicalize({k: v for k, v in obj.items() if k != sig_field}))


def message(kind: str, h: str) -> bytes:
    return f"gleipnir/{kind}/v{V}\n".encode() + h.encode("ascii")


def new_key() -> tuple[Ed25519PrivateKey, str]:
    """A fresh Ed25519 key and its public key text."""
    sk = Ed25519PrivateKey.generate()
    return sk, public_key_of(sk)


def public_key_of(sk: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization as s
    return encode_public_key(sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw))


def _sign(sk: Ed25519PrivateKey, kind: str, obj: dict[str, Any], sig_field: str = "sig") -> dict[str, Any]:
    out = {k: v for k, v in obj.items() if k != sig_field}
    out[sig_field] = "ed25519:" + b64u(sk.sign(message(kind, obj_hash(out, sig_field))))
    return out


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ts(text: Any) -> datetime:
    if not isinstance(text, str) or not text.endswith("Z"):
        raise ValueError(f"bad timestamp: {text!r}")
    return datetime.fromisoformat(text[:-1] + "+00:00")


def _amount(text: Any) -> Decimal:
    if not isinstance(text, str):
        raise ValueError("amounts are decimal strings")
    try:
        d = Decimal(text)
    except InvalidOperation as e:
        raise ValueError(f"bad amount: {text!r}") from e
    if d < 0 or not d.is_finite():
        raise ValueError(f"bad amount: {text!r}")
    return d


def norm_account(acc: dict[str, Any]) -> dict[str, Any]:
    if "iban" in acc:
        return {"iban": str(acc["iban"]).replace(" ", "").upper()}
    return {k: str(v).replace(" ", "") for k, v in sorted(acc.items())}


# ---------- issuing ----------

def issue(*, company: dict, agent: dict, signer: dict, scope: dict, valid_until: str, id: str,
          valid_from: str | None = None, status_url: str | None = None) -> dict[str, Any]:
    """An unsigned mandate. Sign it with sign_mandate() or a passkey."""
    m: dict[str, Any] = {"v": f"gleipnir/mandate/{V}", "id": id, "company": company, "agent": agent,
                         "signer": signer, "scope": scope, "valid_until": valid_until, "issued_at": now()}
    if valid_from:
        m["valid_from"] = valid_from
    if status_url:
        m["status_url"] = status_url
    problem = mandate_problem(m)
    if problem:
        raise ValueError(problem)
    return m


def sign_mandate(mandate: dict, sk: Ed25519PrivateKey) -> dict[str, Any]:
    return _sign(sk, "mandate", mandate)


def passkey_challenge(mandate: dict) -> bytes:
    """The WebAuthn challenge a signatory's passkey signs: the 32 raw bytes of the mandate hash."""
    return hash_to_bytes(obj_hash(mandate))


def revoke(mandate: dict, *, signer: dict, sk: Ed25519PrivateKey, id: str, reason: str = "",
           revoked_at: str | None = None) -> dict[str, Any]:
    r = {"v": f"gleipnir/revocation/{V}", "id": id, "mandate": mandate["id"], "mandate_hash": obj_hash(mandate),
         "revoked_at": revoked_at or now(), "signer": signer}
    if reason:
        r["reason"] = reason
    return _sign(sk, "revocation", r)


def attach(mandate: dict, *, id: str, rail: str, amount: str, currency: str, payee: dict, reference: str = "",
           agent_sk: Ed25519PrivateKey | None = None, requested_at: str | None = None) -> dict[str, Any]:
    """A payment that relies on this mandate, signed by the agent when the mandate names an agent key."""
    p: dict[str, Any] = {"v": f"gleipnir/payment/{V}", "id": id,
                         "mandate": {"id": mandate["id"], "hash": obj_hash(mandate)},
                         "rail": rail, "amount": amount, "currency": currency, "payee": payee,
                         "requested_at": requested_at or now()}
    if reference:
        p["reference"] = reference
    if agent_sk is not None:
        p = _sign(agent_sk, "payment", p, "agent_sig")
    return p


# ---------- checking ----------

def mandate_problem(m: Any) -> str | None:
    if not isinstance(m, dict) or m.get("v") != f"gleipnir/mandate/{V}":
        return "unknown mandate version"
    for path in ("id", "company.name", "company.country", "agent.id", "signer.id", "signer.public_key",
                 "scope.currency", "scope.max_per_payment", "valid_until"):
        cur: Any = m
        for part in path.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if not isinstance(cur, str) or not cur:
            return f"missing {path}"
    try:
        _amount(m["scope"]["max_per_payment"])
        if "max_per_period" in m["scope"]:
            _amount(m["scope"]["max_per_period"]["amount"])
        _ts(m["valid_until"])
        if "valid_from" in m:
            _ts(m["valid_from"])
    except (ValueError, KeyError, TypeError) as e:
        return str(e)
    bad = set(m["scope"].get("rails", [])) - RAILS
    return f"unknown rails: {sorted(bad)}" if bad else None


# authority(company, signer) -> name of the source that authorizes the signer ("bank_kyb", "register",
# "vlei"), False if a source says this person may not sign, None if no source knows the person.
Authority = Callable[[dict, dict], "str | bool | None"]


@dataclass
class Checker:
    id: str
    sk: Ed25519PrivateKey
    authority: Authority
    revocations: list[dict] = field(default_factory=list)
    # status(url) -> "active" | "revoked"; raises when unreachable.
    status: Callable[[str], str] | None = None
    # spent(mandate_id, period, at) -> Decimal already paid in the current period.
    spent: Callable[[str, str, datetime], Decimal] = lambda _id, _p, _at: Decimal(0)
    webauthn: dict = field(default_factory=dict)  # {"rp_id": ..., "origins": [...]}

    def _sig_ok(self, kind: str, obj: dict, pub_text: str, sig_field: str = "sig") -> bool:
        try:
            pub = decode_public_key(pub_text)
        except ValueError:
            return False
        sig = obj.get(sig_field)
        h = obj_hash(obj, sig_field)
        if isinstance(sig, dict) and sig.get("type") == "webauthn" and kind == "mandate":
            return webauthn_problem(sig, pub, h, self.webauthn.get("rp_id", ""), self.webauthn.get("origins", []),
                                    None) is None
        return verify_signature(pub, message(kind, h), sig)

    def check(self, mandate: dict, payment: dict) -> dict[str, Any]:
        checks: list[str] = []
        reason = self._run(mandate, payment, checks)
        outcome = "allow" if reason is None else "escalate" if reason in _ESCALATE else "block"
        d = {"v": f"gleipnir/decision/{V}", "id": "d_" + obj_hash(payment)[7:23],
             "payment": {"id": payment.get("id"), "hash": obj_hash(payment, "agent_sig")},
             "mandate": {"id": mandate.get("id") if isinstance(mandate, dict) else None,
                         "hash": obj_hash(mandate) if isinstance(mandate, dict) else None},
             "outcome": outcome, "reasons": [reason] if reason else [], "checks": checks,
             "checked_at": now(), "checker": {"id": self.id, "public_key": public_key_of(self.sk)}}
        return _sign(self.sk, "decision", d)

    def _run(self, m: dict, p: dict, checks: list[str]) -> str | None:
        if mandate_problem(m):
            return "mandate_malformed"
        if not isinstance(p, dict) or p.get("mandate", {}).get("hash") != obj_hash(m):
            return "mandate_mismatch"
        if not self._sig_ok("mandate", m, m["signer"]["public_key"]):
            return "mandate_bad_signature"
        checks.append("mandate_valid")
        src = self.authority(m["company"], m["signer"])
        if src is False:
            return "signer_not_authorized"
        if not src:
            return "signer_unknown"
        checks.append(f"signer_authorized:{src}")
        try:
            at = _ts(p.get("requested_at"))
        except ValueError:
            return "mandate_malformed"
        if "valid_from" in m and at < _ts(m["valid_from"]):
            return "mandate_not_yet_valid"
        if at > _ts(m["valid_until"]):
            return "mandate_expired"
        mh = obj_hash(m)
        for r in self.revocations:
            if (r.get("mandate_hash") == mh and _ts(r["revoked_at"]) <= at
                    and self._sig_ok("revocation", r, r["signer"]["public_key"])
                    and self.authority(m["company"], r["signer"])):
                return "mandate_revoked"
        if "status_url" in m:
            if self.status is None:
                return "status_unavailable"
            try:
                st = self.status(m["status_url"])
            except Exception:
                return "status_unavailable"
            if st == "revoked":
                return "mandate_revoked"
            if st != "active":
                return "status_unavailable"
        checks.append("not_revoked")
        if "public_key" in m["agent"]:
            if not self._sig_ok("payment", p, m["agent"]["public_key"], "agent_sig"):
                return "agent_bad_signature"
            checks.append("agent_signed")
        sc = m["scope"]
        if "rails" in sc and p.get("rail") not in sc["rails"]:
            return "rail_not_allowed"
        if p.get("currency") != sc["currency"]:
            return "currency_mismatch"
        if "payees" in sc:
            acc = p.get("payee", {}).get("account")
            if not isinstance(acc, dict) or norm_account(acc) not in [norm_account(x["account"]) for x in sc["payees"]]:
                return "payee_not_on_mandate"
            checks.append("payee_on_mandate")
        try:
            amt = _amount(p.get("amount"))
        except ValueError:
            return "mandate_malformed"
        if amt > _amount(sc["max_per_payment"]):
            return "over_payment_limit"
        checks.append("within_payment_limit")
        if "max_per_period" in sc:
            per = sc["max_per_period"]
            if self.spent(m["id"], per["period"], at) + amt > _amount(per["amount"]):
                return "over_period_limit"
            checks.append("within_period_limit")
        return None


def verify_decision(decision: dict) -> bool:
    """Anyone can check a decision was signed by the checker it names and not changed since."""
    try:
        pub = decode_public_key(decision["checker"]["public_key"])
    except (KeyError, TypeError, ValueError):
        return False
    return verify_signature(pub, message("decision", obj_hash(decision)), decision.get("sig"))
