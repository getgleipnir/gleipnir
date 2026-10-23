"""Mandates for AI agents that pay: issue, sign, revoke, attach to a payment, check. See spec/mandate.md.

A company signatory signs a mandate for one agent. The bank checks every payment the agent starts
against it and signs a decision: allow, block or escalate.

Wiring a Checker (all three are the bank's own systems):

- ``authority(company, signer_id) -> AuthorityResult | None``: who may sign for the company and with which
  keys, from the bank's KYB records, a company register or vLEI. Never from the mandate.
- ``payments``: payment log for idempotency (``InMemoryPaymentLog`` for tests; persistent in production).
- ``ledger``: atomic period ledger (``InMemoryLedger`` for tests). Required for mandates with a period limit.
"""

from __future__ import annotations

import re
import secrets
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .approvals import webauthn_problem
from .canon import canonicalize, hash_to_bytes, sha256_tagged
from .crypto import b64u, decode_public_key, encode_public_key, verify_signature
from .verifier import parse_time

V = "0.1"
RAILS = {"sepa", "sepa_instant", "ach", "wire", "faster_payments", "fednow", "rtp"}
PERIODS = {"P1D", "P7D", "P1M"}
# ISO 4217 minor units of the currencies supported in 0.1.
MINOR_UNITS = {"EUR": 2, "USD": 2, "GBP": 2, "CHF": 2, "SEK": 2, "NOK": 2, "DKK": 2, "PLN": 2, "CZK": 2,
               "HUF": 2, "JPY": 0}
_AMOUNT_RE = {0: re.compile(r"(0|[1-9][0-9]*)"), 2: re.compile(r"(0|[1-9][0-9]*)\.[0-9]{2}")}
ESCALATE = {"signer_unknown", "status_unavailable", "over_payment_limit", "over_period_limit", "ledger_missing",
            "checker_unavailable"}


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


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def fmt_ts(t: datetime) -> str:
    return t.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now() -> str:
    return fmt_ts(utcnow())


def _ts(text: Any) -> datetime:
    """Strict RFC 3339 in UTC (``YYYY-MM-DDTHH:MM:SS[.ffffff]Z``), same grammar as the TypeScript port."""
    if not isinstance(text, str) or not text.endswith("Z"):
        raise ValueError(f"bad timestamp: {text!r}")
    return parse_time(text)


def parse_amount(text: Any, currency: Any) -> Decimal:
    """A strictly formatted, positive amount in the currency's minor units, else ValueError."""
    if not isinstance(currency, str) or currency not in MINOR_UNITS:
        raise ValueError(f"unsupported currency: {currency!r}")
    if not isinstance(text, str) or not _AMOUNT_RE[MINOR_UNITS[currency]].fullmatch(text):
        raise ValueError(f"bad amount for {currency}: {text!r}")
    d = Decimal(text)
    if d <= 0:
        raise ValueError(f"amount must be positive: {text!r}")
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


# ---------- validation ----------

def _get(obj: Any, path: str) -> Any:
    for part in path.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def _str_fields(obj: Any, paths: Iterable[str]) -> str | None:
    for path in paths:
        v = _get(obj, path)
        if not isinstance(v, str) or not v:
            return f"missing {path}"
    return None


def _jcs_ok(obj: Any) -> bool:
    try:
        canonicalize(obj)
        return True
    except Exception:  # noqa: BLE001 - any value JCS cannot encode
        return False


def mandate_problem(m: Any) -> str | None:
    """Why this is not a well-formed mandate, or None."""
    if not isinstance(m, dict) or m.get("v") != f"gleipnir/mandate/{V}":
        return "unknown mandate version"
    bad = _str_fields(m, ("id", "company.name", "company.country", "agent.id", "signer.id", "signer.public_key",
                          "scope.currency", "scope.max_per_payment", "valid_until"))
    if bad:
        return bad
    if not _jcs_ok(m):
        return "mandate is not valid I-JSON"
    sc = m["scope"]
    try:
        parse_amount(sc["max_per_payment"], sc["currency"])
        if "max_per_period" in sc:
            per = sc["max_per_period"]
            if not isinstance(per, dict) or per.get("period") not in PERIODS:
                return "max_per_period needs a period of P1D, P7D or P1M"
            parse_amount(per.get("amount"), sc["currency"])
        until = _ts(m["valid_until"])
        if "valid_from" in m and _ts(m["valid_from"]) > until:
            return "valid_from is after valid_until"
    except ValueError as e:
        return str(e)
    rails = sc.get("rails", [])
    if not isinstance(rails, list) or not all(isinstance(r, str) for r in rails):
        return "rails must be a list of strings"
    if set(rails) - RAILS:
        return f"unknown rails: {sorted(set(rails) - RAILS)}"
    payees = sc.get("payees", [])
    if not isinstance(payees, list) or not all(isinstance(x, dict) and isinstance(x.get("account"), dict)
                                               and x["account"] for x in payees):
        return "every payee needs an account object"
    if "status_url" in m and not isinstance(m["status_url"], str):
        return "status_url must be a string"
    return None


def payment_problem(p: Any) -> str | None:
    """Why this is not a well-formed payment, or None."""
    if not isinstance(p, dict) or p.get("v") != f"gleipnir/payment/{V}":
        return "unknown payment version"
    bad = _str_fields(p, ("id", "mandate.id", "mandate.hash", "rail", "currency", "requested_at"))
    if bad:
        return bad
    if not isinstance(_get(p, "payee.account"), dict) or not p["payee"]["account"]:
        return "missing payee.account"
    if not _jcs_ok(p):
        return "payment is not valid I-JSON"
    try:
        parse_amount(p.get("amount"), p["currency"])
        _ts(p["requested_at"])
    except ValueError as e:
        return str(e)
    return None


def revocation_problem(r: Any) -> str | None:
    if not isinstance(r, dict) or r.get("v") != f"gleipnir/revocation/{V}":
        return "unknown revocation version"
    bad = _str_fields(r, ("id", "mandate", "mandate_hash", "revoked_at", "signer.id", "signer.public_key"))
    if bad or not _jcs_ok(r):
        return bad or "revocation is not valid I-JSON"
    try:
        _ts(r["revoked_at"])
    except ValueError as e:
        return str(e)
    return None


# ---------- the bank's systems ----------

@dataclass(frozen=True)
class AuthorityResult:
    """What an authority source (bank KYB, register, vLEI) says about one person at one company."""
    source: str                  # "bank_kyb", "register", "vlei"
    keys: tuple[str, ...]        # public keys the source binds to this person
    may_sign: bool = True


# authority(company, signer_id) -> AuthorityResult, or None if no source knows the person.
Authority = Callable[[dict, str], "AuthorityResult | None"]


class PaymentLog(Protocol):
    def seen(self, payment_id: str, payment_hash: str) -> dict | str | None:
        """Atomically register a payment id. None: new (now registered). A decision dict: this id and hash
        were decided before. "duplicate": the id is known with another hash, or is still being checked."""

    def remember(self, payment_id: str, decision: dict) -> None:
        """Store the decision for a registered payment id."""


class Ledger(Protocol):
    def reserve(self, mandate_id: str, period: str, amount: Decimal, limit: Decimal, at: datetime) -> bool:
        """Atomically add amount to the period total if the total stays within limit."""


class InMemoryPaymentLog:
    """Payment log for tests and demos. Production needs a persistent, shared store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, tuple[str, dict | None]] = {}

    def seen(self, payment_id: str, payment_hash: str) -> dict | str | None:
        with self._lock:
            if payment_id not in self._items:
                self._items[payment_id] = (payment_hash, None)
                return None
            h, decision = self._items[payment_id]
            return decision if h == payment_hash and decision is not None else "duplicate"

    def remember(self, payment_id: str, decision: dict) -> None:
        with self._lock:
            self._items[payment_id] = (self._items[payment_id][0], decision)


def period_key(period: str, at: datetime) -> str:
    at = at.astimezone(timezone.utc)
    if period == "P1D":
        return at.strftime("%Y-%m-%d")
    if period == "P7D":
        y, w, _ = at.isocalendar()
        return f"{y}-W{w:02d}"
    if period == "P1M":
        return at.strftime("%Y-%m")
    raise ValueError(f"unknown period {period!r}")


class InMemoryLedger:
    """Period ledger for tests and demos: calendar periods in UTC, guarded by a lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.totals: dict[tuple[str, str], Decimal] = {}

    def reserve(self, mandate_id: str, period: str, amount: Decimal, limit: Decimal, at: datetime) -> bool:
        key = (mandate_id, period_key(period, at))
        with self._lock:
            total = self.totals.get(key, Decimal(0)) + amount
            if total > limit:
                return False
            self.totals[key] = total
            return True

    def release(self, mandate_id: str, period: str, amount: Decimal, at: datetime) -> None:
        key = (mandate_id, period_key(period, at))
        with self._lock:
            self.totals[key] = max(Decimal(0), self.totals.get(key, Decimal(0)) - amount)


class _Stop(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


# ---------- checking ----------

@dataclass
class Checker:
    id: str
    sk: Ed25519PrivateKey
    authority: Authority
    ledger: Ledger | None = None
    payments: PaymentLog = field(default_factory=InMemoryPaymentLog)
    revocations: list[dict] = field(default_factory=list)
    # status(url) -> "active" | "revoked"; raises when unreachable.
    status: Callable[[str], str] | None = None
    clock: Callable[[], datetime] = utcnow
    max_skew: timedelta = timedelta(seconds=60)
    webauthn: dict = field(default_factory=dict)  # {"rp_id": ..., "origins": [...]}

    def _sig_ok(self, kind: str, obj: dict, pub_text: str, sig_field: str = "sig") -> bool:
        try:
            pub = decode_public_key(pub_text)
            sig = obj.get(sig_field)
            h = obj_hash(obj, sig_field)
            if isinstance(sig, dict) and sig.get("type") == "webauthn" and kind == "mandate":
                return webauthn_problem(sig, pub, h, self.webauthn.get("rp_id", ""),
                                        self.webauthn.get("origins", []), None) is None
            return verify_signature(pub, message(kind, h), sig)
        except Exception:  # noqa: BLE001 - any malformed key or signature fails closed
            return False

    def _authorized(self, company: dict, signer: dict) -> AuthorityResult:
        """The source's answer for this signer, checked against the key the signer used. Raises _Stop."""
        try:
            res = self.authority(company, signer["id"])
        except Exception as e:  # noqa: BLE001
            raise _Stop("checker_unavailable") from e
        if res is None:
            raise _Stop("signer_unknown")
        if not isinstance(res, AuthorityResult):
            raise _Stop("checker_unavailable")
        if not res.may_sign or signer.get("public_key") not in res.keys:
            raise _Stop("signer_not_authorized")
        return res

    def check(self, mandate: Any, payment: Any) -> dict[str, Any]:
        """Check one payment against one mandate. Never raises on input; always returns a signed decision."""
        at = self.clock()
        checks: list[str] = []
        state: dict[str, bool] = {}
        p_hash = None
        if isinstance(payment, dict) and _jcs_ok(payment):
            p_hash = obj_hash(payment, "agent_sig")
        try:
            reason = self._run(mandate, payment, p_hash, at, checks, state)
        except _Stop as s:
            reason = s.reason
        except Exception:  # noqa: BLE001 - last line of defence: unexpected input never allows
            reason = "payment_malformed"
        if isinstance(reason, dict):  # idempotent retry: the earlier decision, unchanged
            return reason
        d = self._decision(mandate, payment, p_hash, reason, checks, at)
        if state.get("registered"):
            try:
                self.payments.remember(payment["id"], d)
            except Exception:  # noqa: BLE001 - the decision still stands; the log is the bank's to fix
                pass
        return d

    def _decision(self, m: Any, p: Any, p_hash: str | None, reason: str | None, checks: list[str],
                  at: datetime) -> dict[str, Any]:
        outcome = "allow" if reason is None else "escalate" if reason in ESCALATE else "block"
        pid = p.get("id") if isinstance(p, dict) and isinstance(p.get("id"), str) else None
        mid = m.get("id") if isinstance(m, dict) and isinstance(m.get("id"), str) else None
        mh = obj_hash(m) if isinstance(m, dict) and _jcs_ok(m) else None
        d = {"v": f"gleipnir/decision/{V}", "id": "d_" + secrets.token_hex(12),
             "payment": {"id": pid, "hash": p_hash}, "mandate": {"id": mid, "hash": mh},
             "outcome": outcome, "reasons": [reason] if reason else [], "checks": checks,
             "checked_at": fmt_ts(at), "checker": {"id": self.id, "public_key": public_key_of(self.sk)}}
        return _sign(self.sk, "decision", d)

    def _run(self, m: Any, p: Any, p_hash: str | None, at: datetime, checks: list[str],
             state: dict[str, bool]) -> str | dict | None:
        if mandate_problem(m):
            return "mandate_malformed"
        if p_hash is None or payment_problem(p):
            return "payment_malformed"
        try:
            prior = self.payments.seen(p["id"], p_hash)
        except Exception:  # noqa: BLE001
            return "checker_unavailable"
        if isinstance(prior, dict):
            return prior
        if prior is not None:
            return "duplicate_payment"
        state["registered"] = True
        mh = obj_hash(m)
        if p["mandate"]["hash"] != mh:
            return "mandate_mismatch"
        if abs(_ts(p["requested_at"]) - at) > self.max_skew:
            return "clock_skew"
        if not self._sig_ok("mandate", m, m["signer"]["public_key"]):
            return "mandate_bad_signature"
        checks.append("mandate_valid")
        src = self._authorized(m["company"], m["signer"])
        checks.append(f"signer_authorized:{src.source}")
        if "valid_from" in m and at < _ts(m["valid_from"]):
            return "mandate_not_yet_valid"
        if at > _ts(m["valid_until"]):
            return "mandate_expired"
        if self._revoked(m, mh, at):
            return "mandate_revoked"
        if "status_url" in m:
            if self.status is None:
                return "status_unavailable"
            try:
                st = self.status(m["status_url"])
            except Exception:  # noqa: BLE001
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
        if "rails" in sc and p["rail"] not in sc["rails"]:
            return "rail_not_allowed"
        if p["currency"] != sc["currency"]:
            return "currency_mismatch"
        if "payees" in sc:
            if norm_account(p["payee"]["account"]) not in [norm_account(x["account"]) for x in sc["payees"]]:
                return "payee_not_on_mandate"
            checks.append("payee_on_mandate")
        amt = parse_amount(p["amount"], p["currency"])
        if amt > parse_amount(sc["max_per_payment"], sc["currency"]):
            return "over_payment_limit"
        checks.append("within_payment_limit")
        if "max_per_period" in sc:
            per = sc["max_per_period"]
            if self.ledger is None:
                return "ledger_missing"
            try:
                ok = self.ledger.reserve(m["id"], per["period"], amt, parse_amount(per["amount"], sc["currency"]), at)
            except Exception:  # noqa: BLE001
                return "checker_unavailable"
            if not ok:
                return "over_period_limit"
            checks.append("within_period_limit")
        return None

    def _revoked(self, m: dict, mh: str, at: datetime) -> bool:
        for r in self.revocations:
            if revocation_problem(r) or r["mandate_hash"] != mh or _ts(r["revoked_at"]) > at:
                continue
            if not self._sig_ok("revocation", r, r["signer"]["public_key"]):
                continue
            try:
                self._authorized(m["company"], r["signer"])
            except _Stop as s:
                if s.reason == "checker_unavailable":
                    raise
                continue
            return True
        return False


def verify_decision(decision: Any, checker_keys: Iterable[str]) -> bool:
    """True if the decision was signed by one of the bank's known checker keys and not changed since.

    checker_keys come from the bank (its published key list), never from the decision itself.
    """
    keys = set(checker_keys)
    try:
        pub_text = decision["checker"]["public_key"]
        if pub_text not in keys:
            return False
        return verify_signature(decode_public_key(pub_text), message("decision", obj_hash(decision)),
                                decision.get("sig"))
    except Exception:  # noqa: BLE001
        return False
