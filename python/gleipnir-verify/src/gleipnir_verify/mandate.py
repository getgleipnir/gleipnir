"""Mandates for AI agents that pay: issue, sign, delegate, revoke, attach to a payment, check. See spec/mandate.md.

A company signatory (or a threshold of signatories) signs a mandate for one agent, possibly on the strength of
a signed delegation chain (CEO -> CFO). The bank checks every payment the agent starts against it and signs
a decision: allow, block or escalate.

Wiring a Checker (all three are the bank's own systems):

- ``authority(company, person_id) -> AuthorityResult | None``: who may sign for the company, how (alone or
  jointly) and with which keys, from the bank's KYB records, a company register or vLEI. Never from the
  mandate. ``combine(kyb, vlei)`` asks several sources in order.
- ``payments``: payment log for idempotency (``InMemoryPaymentLog`` for tests; persistent in production).
- ``ledger``: atomic period ledger (``InMemoryLedger`` for tests). Required for mandates with a period limit.

Gleipnir does not verify identities: the bank or a vLEI issuer binds keys to people (spec section 3).
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

V = "0.2"
RAILS = {"sepa", "sepa_instant", "ach", "wire", "faster_payments", "fednow", "rtp"}
PERIODS = {"P1D", "P7D", "P1M"}
# ISO 4217 minor units of the currencies supported in 0.2.
MINOR_UNITS = {"EUR": 2, "USD": 2, "GBP": 2, "CHF": 2, "SEK": 2, "NOK": 2, "DKK": 2, "PLN": 2, "CZK": 2,
               "HUF": 2, "JPY": 0}
_AMOUNT_RE = {0: re.compile(r"(0|[1-9][0-9]*)"), 2: re.compile(r"(0|[1-9][0-9]*)\.[0-9]{2}")}
ESCALATE = {"signer_unknown", "status_unavailable", "over_payment_limit", "over_period_limit", "ledger_missing",
            "checker_unavailable"}
MANDATE_SIG_FIELDS = ("sig", "sigs")
# Outcomes the payment log never caches: a retry is checked afresh once the dependency is back, the mandate
# becomes valid, or a new period starts.
TRANSIENT = {"checker_unavailable", "status_unavailable", "ledger_missing", "mandate_not_yet_valid",
             "over_period_limit"}
_COUNTRY_RE = re.compile(r"[A-Z]{2}")
_IBAN_RE = re.compile(r"[A-Za-z0-9 ]+")
_MAX_INT = 2 ** 53 - 1
MAX_DELEGATION_DEPTH = 5


# ---------- hashing and signing ----------

def obj_hash(obj: dict[str, Any], sig_field: str | tuple[str, ...] = "sig") -> str:
    """sha256 over the JCS encoding of the object without its signature field(s)."""
    skip = (sig_field,) if isinstance(sig_field, str) else sig_field
    return sha256_tagged(canonicalize({k: v for k, v in obj.items() if k not in skip}))


def mandate_hash(mandate: dict[str, Any]) -> str:
    """The hash every mandate signature covers: the mandate minus ``sig`` and ``sigs``."""
    return obj_hash(mandate, MANDATE_SIG_FIELDS)


def delegation_hash(delegation: dict[str, Any]) -> str:
    return obj_hash(delegation)


def message(kind: str, h: str) -> bytes:
    return f"gleipnir/{kind}/v{V}\n".encode() + h.encode("ascii")


def new_key() -> tuple[Ed25519PrivateKey, str]:
    """A fresh Ed25519 key and its public key text."""
    sk = Ed25519PrivateKey.generate()
    return sk, public_key_of(sk)


def public_key_of(sk: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization as s
    return encode_public_key(sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw))


def _sig_text(sk: Ed25519PrivateKey, kind: str, h: str) -> str:
    return "ed25519:" + b64u(sk.sign(message(kind, h)))


def _sign(sk: Ed25519PrivateKey, kind: str, obj: dict[str, Any], sig_field: str = "sig") -> dict[str, Any]:
    out = {k: v for k, v in obj.items() if k != sig_field}
    out[sig_field] = _sig_text(sk, kind, obj_hash(out, sig_field))
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
    """Account fields are strings (checked by _account_problem); IBANs ASCII, uppercased without spaces."""
    if "iban" in acc:
        return {"iban": acc["iban"].replace(" ", "").upper()}
    return {k: v.replace(" ", "") for k, v in sorted(acc.items())}


def _account_problem(acc: Any) -> str | None:
    if not isinstance(acc, dict) or not acc:
        return "every payee needs an account object"
    if not all(isinstance(v, str) and v for v in acc.values()):
        return "account fields must be non-empty strings"
    if "iban" in acc and not _IBAN_RE.fullmatch(acc["iban"]):
        return "IBAN must be ASCII letters, digits and spaces"
    return None


# ---------- issuing ----------

def issue(*, company: dict, agent: dict, scope: dict, valid_until: str, id: str, signer: dict | None = None,
          signers: dict | None = None, delegation: list[dict] | None = None, valid_from: str | None = None,
          status_url: str | None = None) -> dict[str, Any]:
    """An unsigned mandate: one ``signer`` (sign with sign_mandate) or ``signers`` {threshold, of} (cosign)."""
    m: dict[str, Any] = {"v": f"gleipnir/mandate/{V}", "id": id, "company": company, "agent": agent,
                         "scope": scope, "valid_until": valid_until, "issued_at": now()}
    if signer is not None:
        m["signer"] = signer
    if signers is not None:
        m["signers"] = signers
    if delegation:
        m["delegation"] = delegation
    if valid_from:
        m["valid_from"] = valid_from
    if status_url:
        m["status_url"] = status_url
    problem = mandate_problem(m)
    if problem:
        raise ValueError(problem)
    return m


def sign_mandate(mandate: dict, sk: Ed25519PrivateKey) -> dict[str, Any]:
    """Sign a single-signer mandate."""
    out = {k: v for k, v in mandate.items() if k != "sig"}
    out["sig"] = _sig_text(sk, "mandate", mandate_hash(out))
    return out


def cosign(mandate: dict, sk: Ed25519PrivateKey, signer_id: str) -> dict[str, Any]:
    """Add (or replace) one co-signature on a multi-signature mandate. Co-signers sign the same hash."""
    entry = {"signer": signer_id, "sig": _sig_text(sk, "mandate", mandate_hash(mandate))}
    sigs = [s for s in mandate.get("sigs", []) if s.get("signer") != signer_id] + [entry]
    return {**mandate, "sigs": sigs}


def passkey_digest(mandate: dict) -> str:
    """What a signatory's passkey signs: SHA-256 of the domain-separated mandate message (spec 4.3).

    Domain separation keeps a mandate passkey signature from ever being valid as an approval of an agent
    action (format.md "Signed approvals"), which signs the bare action digest.
    """
    return sha256_tagged(message("mandate", mandate_hash(mandate)))


def passkey_challenge(mandate: dict) -> bytes:
    """The WebAuthn challenge: the 32 raw bytes of passkey_digest(mandate)."""
    return hash_to_bytes(passkey_digest(mandate))


def delegate(*, id: str, company: dict, from_: dict, to: dict, scope: dict, valid_until: str,
             sk: Ed25519PrivateKey, parent: dict | None = None, valid_from: str | None = None,
             issued_at: str | None = None) -> dict[str, Any]:
    """A signed delegation from ``from_`` (who signs with ``sk``) to ``to``. ``parent``: the link above."""
    d: dict[str, Any] = {"v": f"gleipnir/delegation/{V}", "id": id, "company": company, "from": from_, "to": to,
                         "scope": scope, "valid_until": valid_until, "issued_at": issued_at or now()}
    if parent is not None:
        d["parent"] = {"id": parent["id"], "hash": delegation_hash(parent)}
    if valid_from:
        d["valid_from"] = valid_from
    problem = delegation_problem(d)
    if problem:
        raise ValueError(problem)
    return _sign(sk, "delegation", d)


def revoke(target: dict, *, signer: dict, sk: Ed25519PrivateKey, id: str, reason: str = "",
           revoked_at: str | None = None) -> dict[str, Any]:
    """A signed revocation of a mandate or of a delegation link."""
    r: dict[str, Any] = {"v": f"gleipnir/revocation/{V}", "id": id}
    if str(target.get("v", "")).startswith("gleipnir/delegation/"):
        r.update({"delegation": target["id"], "delegation_hash": delegation_hash(target)})
    else:
        r.update({"mandate": target["id"], "mandate_hash": mandate_hash(target)})
    r.update({"revoked_at": revoked_at or now(), "signer": signer})
    if reason:
        r["reason"] = reason
    return _sign(sk, "revocation", r)


def attach(mandate: dict, *, id: str, rail: str, amount: str, currency: str, payee: dict, reference: str = "",
           agent_sk: Ed25519PrivateKey | None = None, requested_at: str | None = None) -> dict[str, Any]:
    """A payment that relies on this mandate, signed by the agent when the mandate names an agent key."""
    p: dict[str, Any] = {"v": f"gleipnir/payment/{V}", "id": id,
                         "mandate": {"id": mandate["id"], "hash": mandate_hash(mandate)},
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


def _numbers_ok(obj: Any) -> bool:
    """I-JSON as spec 13 profiles it: no floats, integers within +-(2^53 - 1)."""
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return True
    if isinstance(obj, int):
        return -_MAX_INT <= obj <= _MAX_INT
    if isinstance(obj, float):
        return False
    if isinstance(obj, list):
        return all(_numbers_ok(x) for x in obj)
    if isinstance(obj, dict):
        return all(_numbers_ok(x) for x in obj.values())
    return False


def _jcs_ok(obj: Any) -> bool:
    try:
        canonicalize(obj)
    except Exception:  # noqa: BLE001 - any value JCS cannot encode
        return False
    try:
        return _numbers_ok(obj)
    except RecursionError:
        return False


def _person_problem(p: Any, what: str) -> str | None:
    if not isinstance(p, dict) or _str_fields(p, ("id", "public_key")):
        return f"missing {what}.id or {what}.public_key"
    return None


def _scope_problem(sc: dict) -> str | None:
    """Scope rules shared by mandates and delegations."""
    try:
        parse_amount(sc["max_per_payment"], sc["currency"])
        if "max_per_period" in sc:
            per = sc["max_per_period"]
            if not isinstance(per, dict) or per.get("period") not in PERIODS:
                return "max_per_period needs a period of P1D, P7D or P1M"
            parse_amount(per.get("amount"), sc["currency"])
    except ValueError as e:
        return str(e)
    rails = sc.get("rails", [])
    if not isinstance(rails, list) or not all(isinstance(r, str) for r in rails):
        return "rails must be a list of strings"
    if set(rails) - RAILS:
        return f"unknown rails: {sorted(set(rails) - RAILS)}"
    payees = sc.get("payees", [])
    if not isinstance(payees, list) or not all(isinstance(x, dict) for x in payees):
        return "every payee needs an account object"
    for x in payees:
        bad = _account_problem(x.get("account"))
        if bad:
            return bad
    return None


def _validity_problem(obj: dict) -> str | None:
    try:
        until = _ts(obj["valid_until"])
        if "valid_from" in obj and _ts(obj["valid_from"]) > until:
            return "valid_from is after valid_until"
    except ValueError as e:
        return str(e)
    return None


def _signers_problem(m: dict) -> str | None:
    if ("signer" in m) == ("signers" in m):
        return "exactly one of signer or signers"
    if "signer" in m:
        if "sigs" in m:
            return "a single signer signs in sig, not sigs"
        return _person_problem(m["signer"], "signer")
    ss = m["signers"]
    if "sig" in m or "delegation" in m:
        return "multi-signature mandates sign in sigs and take no delegation"
    if not isinstance(ss, dict) or not isinstance(ss.get("of"), list) or not ss["of"]:
        return "signers needs a non-empty list 'of'"
    th = ss.get("threshold")
    if type(th) is not int or not 1 <= th <= len(ss["of"]):
        return "signers.threshold must be an integer between 1 and the number of signers"
    ids = []
    for p in ss["of"]:
        bad = _person_problem(p, "signers.of[]")
        if bad:
            return bad
        ids.append(p["id"])
    if len(set(ids)) != len(ids):
        return "duplicate signer id"
    if len({p["public_key"] for p in ss["of"]}) != len(ss["of"]):
        return "duplicate signer key: one person cannot count twice"
    sigs = m.get("sigs", [])
    if not isinstance(sigs, list) or not all(isinstance(s, dict) and s.get("signer") in ids
                                             and isinstance(s.get("sig"), (str, dict)) for s in sigs):
        return "every sigs entry needs a signer from signers.of and a sig"
    if len({s["signer"] for s in sigs}) != len(sigs):
        return "one signature per signer"
    return None


def mandate_problem(m: Any) -> str | None:
    """Why this is not a well-formed mandate, or None."""
    if not isinstance(m, dict) or m.get("v") != f"gleipnir/mandate/{V}":
        return "unknown mandate version"
    bad = _str_fields(m, ("id", "company.name", "company.country", "agent.id", "scope.currency",
                          "scope.max_per_payment", "valid_until"))
    if bad:
        return bad
    if not _jcs_ok(m):
        return "mandate is not valid I-JSON"
    if not _COUNTRY_RE.fullmatch(m["company"]["country"]):
        return "company.country must be an ISO 3166-1 alpha-2 code"
    bad = _signers_problem(m) or _scope_problem(m["scope"]) or _validity_problem(m)
    if bad:
        return bad
    if "status_url" in m and not isinstance(m["status_url"], str):
        return "status_url must be a string"
    if "delegation" in m:
        chain = m["delegation"]
        if not isinstance(chain, list) or not 1 <= len(chain) <= MAX_DELEGATION_DEPTH:
            return f"delegation must be a list of 1 to {MAX_DELEGATION_DEPTH} links"
        for d in chain:
            bad = delegation_problem(d)
            if bad:
                return f"delegation: {bad}"
    return None


def delegation_problem(d: Any) -> str | None:
    """Why this is not a well-formed delegation, or None."""
    if not isinstance(d, dict) or d.get("v") != f"gleipnir/delegation/{V}":
        return "unknown delegation version"
    bad = _str_fields(d, ("id", "company.name", "from.id", "from.public_key", "to.id", "to.public_key",
                          "scope.currency", "scope.max_per_payment", "valid_until"))
    if bad:
        return bad
    if not _jcs_ok(d):
        return "delegation is not valid I-JSON"
    if "parent" in d and _str_fields(d["parent"], ("id", "hash")):
        return "parent needs id and hash"
    return _scope_problem(d["scope"]) or _validity_problem(d)


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
    if p["rail"] not in RAILS:
        return f"unknown rail: {p['rail']!r}"
    bad = _account_problem(p["payee"]["account"])
    if bad:
        return bad
    try:
        parse_amount(p.get("amount"), p["currency"])
        _ts(p["requested_at"])
    except ValueError as e:
        return str(e)
    return None


def revocation_problem(r: Any) -> str | None:
    if not isinstance(r, dict) or r.get("v") != f"gleipnir/revocation/{V}":
        return "unknown revocation version"
    if ("mandate_hash" in r) == ("delegation_hash" in r):
        return "a revocation targets exactly one mandate or delegation"
    target = ("mandate", "mandate_hash") if "mandate_hash" in r else ("delegation", "delegation_hash")
    bad = _str_fields(r, (*target, "id", "revoked_at", "signer.id", "signer.public_key"))
    if bad or not _jcs_ok(r):
        return bad or "revocation is not valid I-JSON"
    try:
        _ts(r["revoked_at"])
    except ValueError as e:
        return str(e)
    return None


def _signatures(m: dict) -> tuple[list[tuple[dict, Any]], int]:
    """(signer, signature) pairs present on a well-formed mandate, and the mandate's threshold."""
    if "signer" in m:
        return ([(m["signer"], m["sig"])] if "sig" in m else []), 1
    by_id = {p["id"]: p for p in m["signers"]["of"]}
    return [(by_id[s["signer"]], s["sig"]) for s in m.get("sigs", [])], m["signers"]["threshold"]


def _verify(kind: str, h: str, sig: Any, pub_text: Any, webauthn: dict) -> bool:
    try:
        pub = decode_public_key(pub_text)
        if isinstance(sig, dict) and sig.get("type") == "webauthn" and kind == "mandate":
            return webauthn_problem(sig, pub, sha256_tagged(message(kind, h)), webauthn.get("rp_id", ""),
                                    webauthn.get("origins", []), None) is None
        return verify_signature(pub, message(kind, h), sig)
    except Exception:  # noqa: BLE001 - any malformed key or signature fails closed
        return False


def _same_person(a: dict, b: dict) -> bool:
    return (a["id"], a["public_key"]) == (b["id"], b["public_key"])


def _same_company(link: dict, mandate: dict) -> bool:
    """A link names the mandate's company: same name, and the same country and ids where the link gives them."""
    return link.get("name") == mandate["name"] and all(
        link[k] == mandate.get(k) for k in ("country", "ids") if k in link)


def _chain_problem(m: dict, chain: list[dict], webauthn: dict) -> str | None:
    """Linkage and signatures of a delegation chain (spec section 5, steps 1-2), or None."""
    for i, d in enumerate(chain):
        if not _same_company(d["company"], m["company"]):
            return "delegation_broken"
        if i == 0:
            if "parent" in d:
                return "delegation_broken"
        elif not _same_person(d["from"], chain[i - 1]["to"]) \
                or d.get("parent", {}).get("hash") != delegation_hash(chain[i - 1]) \
                or d.get("parent", {}).get("id") != chain[i - 1]["id"]:
            return "delegation_broken"
    if not _same_person(m["signer"], chain[-1]["to"]):
        return "delegation_broken"
    for d in chain:
        if not _verify("delegation", delegation_hash(d), d.get("sig"), d["from"]["public_key"], webauthn):
            return "delegation_bad_signature"
    return None


def _within(child: dict, parent: dict) -> bool:
    """True if the child's scope and validity are no wider than the parent's (spec section 5, step 4)."""
    cs, ps = child["scope"], parent["scope"]
    if cs["currency"] != ps["currency"]:
        return False
    cur = ps["currency"]
    if parse_amount(cs["max_per_payment"], cur) > parse_amount(ps["max_per_payment"], cur):
        return False
    if "rails" in ps and ("rails" not in cs or not set(cs["rails"]) <= set(ps["rails"])):
        return False
    if "payees" in ps:
        allowed = [norm_account(x["account"]) for x in ps["payees"]]
        if "payees" not in cs or any(norm_account(x["account"]) not in allowed for x in cs["payees"]):
            return False
    if "max_per_period" in ps:
        pp, cp = ps["max_per_period"], cs.get("max_per_period")
        if not isinstance(cp, dict) or cp["period"] != pp["period"] \
                or parse_amount(cp["amount"], cur) > parse_amount(pp["amount"], cur):
            return False
    if _ts(child["valid_until"]) > _ts(parent["valid_until"]):
        return False
    if "valid_from" in parent and ("valid_from" not in child or _ts(child["valid_from"]) < _ts(parent["valid_from"])):
        return False
    return True


# ---------- the bank's systems ----------

@dataclass(frozen=True)
class AuthorityResult:
    """What an authority source (bank KYB, register, vLEI) says about one person at one company."""
    source: str                  # "bank_kyb", "register", "vlei"
    keys: tuple[str, ...]        # public keys the source binds to this person (enrollment, spec section 3)
    may_sign: bool = True        # signing power of their own; False for a person known only as a delegate
    joint: int = 1               # signatures their power requires, including their own (joint with one other: 2)


# authority(company, person_id) -> AuthorityResult, or None if no source knows the person.
Authority = Callable[[dict, str], "AuthorityResult | None"]


def combine(*sources: Authority) -> Authority:
    """Ask several authority sources in order (bank KYB first, then vLEI); the first that knows the person wins."""
    def authority(company: dict, person_id: str) -> AuthorityResult | None:
        for src in sources:
            res = src(company, person_id)
            if res is not None:
                return res
        return None
    return authority


class PaymentLog(Protocol):
    """Idempotency per payer (spec 7). ``key`` is payment_key(company, payment id)."""

    def lookup(self, key: str, payment_hash: str) -> dict | None:
        """The earlier final decision for this key and this exact payment, or None."""

    def register(self, key: str, payment_hash: str) -> bool:
        """Atomically claim the key. False if it is already claimed (by any payment)."""

    def remember(self, key: str, decision: dict) -> None:
        """Store the final decision for a claimed key."""

    def forget(self, key: str) -> None:
        """Release a claim without a decision (a transient failure), so a retry is checked afresh."""


class Ledger(Protocol):
    """Period totals (spec 7). ``key`` is "mandate:<hash>" or "delegation:<hash>"; ``at`` picks the period."""

    def reserve(self, key: str, period: str, amount: Decimal, limit: Decimal, at: datetime) -> bool:
        """Atomically add amount to the period total if the total stays within limit."""

    def release(self, key: str, period: str, amount: Decimal, at: datetime) -> None:
        """Give back a reservation (a later step failed, or the bank did not execute)."""


def payment_key(company: dict, payment_id: str) -> str:
    """The payment log key: payment ids are unique per payer, so the payer is part of the key.

    JCS of [country, name, ids, id]: unambiguous, so no company name or id can be crafted to collide.
    """
    return canonicalize([company.get("country"), company.get("name"), company.get("ids"), payment_id]).decode()


class InMemoryPaymentLog:
    """Payment log for tests and demos. Production needs a persistent, shared store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, tuple[str, dict | None]] = {}

    def lookup(self, key: str, payment_hash: str) -> dict | None:
        with self._lock:
            entry = self._items.get(key)
            return entry[1] if entry and entry[0] == payment_hash else None

    def register(self, key: str, payment_hash: str) -> bool:
        with self._lock:
            if key in self._items:
                return False
            self._items[key] = (payment_hash, None)
            return True

    def remember(self, key: str, decision: dict) -> None:
        with self._lock:
            self._items[key] = (self._items[key][0], decision)

    def forget(self, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)


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

    def reserve(self, key: str, period: str, amount: Decimal, limit: Decimal, at: datetime) -> bool:
        k = (key, period_key(period, at))
        with self._lock:
            total = self.totals.get(k, Decimal(0)) + amount
            if total > limit:
                return False
            self.totals[k] = total
            return True

    def release(self, key: str, period: str, amount: Decimal, at: datetime) -> None:
        k = (key, period_key(period, at))
        with self._lock:
            self.totals[k] = max(Decimal(0), self.totals.get(k, Decimal(0)) - amount)


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

    def _authorized(self, company: dict, person: dict, need_power: bool = True) -> AuthorityResult:
        """The source's answer for this person, checked against the key they used. Raises _Stop."""
        try:
            res = self.authority(company, person["id"])
        except Exception as e:  # noqa: BLE001
            raise _Stop("checker_unavailable") from e
        if res is None:
            raise _Stop("signer_unknown")
        if not isinstance(res, AuthorityResult) or type(res.joint) is not int or res.joint < 1 \
                or type(res.may_sign) is not bool or not isinstance(res.keys, (tuple, list)):
            raise _Stop("checker_unavailable")
        if person.get("public_key") not in res.keys or (need_power and not res.may_sign):
            raise _Stop("signer_not_authorized")
        return res

    def check(self, mandate: Any, payment: Any) -> dict[str, Any]:
        """Check one payment against one mandate. Never raises on input; always returns a signed decision."""
        at = self.clock()
        checks: list[str] = []
        state: dict[str, Any] = {}
        p_hash = None
        try:
            if isinstance(payment, dict) and _jcs_ok(payment):
                p_hash = obj_hash(payment, "agent_sig")
        except Exception:  # noqa: BLE001
            p_hash = None
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
                if reason in TRANSIENT:
                    self.payments.forget(state["key"])
                else:
                    self.payments.remember(state["key"], d)
            except Exception:  # noqa: BLE001 - the decision still stands; the log is the bank's to fix
                pass
        return d

    def _decision(self, m: Any, p: Any, p_hash: str | None, reason: str | None, checks: list[str],
                  at: datetime) -> dict[str, Any]:
        outcome = "allow" if reason is None else "escalate" if reason in ESCALATE else "block"
        pid = p.get("id") if isinstance(p, dict) and isinstance(p.get("id"), str) else None
        mid = m.get("id") if isinstance(m, dict) and isinstance(m.get("id"), str) else None
        mh = mandate_hash(m) if isinstance(m, dict) and _jcs_ok(m) else None
        d = {"v": f"gleipnir/decision/{V}", "id": "d_" + secrets.token_hex(12),
             "payment": {"id": pid, "hash": p_hash}, "mandate": {"id": mid, "hash": mh},
             "outcome": outcome, "reasons": [reason] if reason else [], "checks": checks,
             "checked_at": fmt_ts(at), "checker": {"id": self.id, "public_key": public_key_of(self.sk)}}
        return _sign(self.sk, "decision", d)

    def _signers_ok(self, m: dict, sigs: list[tuple[dict, Any]], threshold: int, checks: list[str]) -> None:
        """Steps 8-10: every signer through authority separately, then threshold and joint. Raises _Stop."""
        counted: list[AuthorityResult] = []
        unknown = False
        seen_keys: set[str] = set()
        for signer, _ in sigs:
            if signer["public_key"] in seen_keys:  # one person counts once (also blocked by mandate_problem)
                continue
            seen_keys.add(signer["public_key"])
            try:
                counted.append(self._authorized(m["company"], signer))
            except _Stop as s:
                if s.reason != "signer_unknown":
                    raise
                unknown = True
        needed = max([threshold] + [r.joint for r in counted])
        if len(counted) < needed:
            if unknown:
                raise _Stop("signer_unknown")
            raise _Stop("joint_signature_required" if len(counted) >= threshold else "signature_threshold_not_met")
        checks.extend(f"signer_authorized:{r.source}" for r in counted)
        if "signers" in m:
            checks.append(f"signatures:{len(counted)}/{needed}")

    def _chain_ok(self, m: dict, chain: list[dict], checks: list[str]) -> str | None:
        """Section 5, steps 3-4: authority per link and narrowing. Raises _Stop; returns a reason or None."""
        root = self._authorized(m["company"], chain[0]["from"])
        if root.joint > 1:
            raise _Stop("joint_signature_required")
        for d in chain:
            self._authorized(m["company"], d["to"], need_power=False)
        checks.extend([f"delegation:{len(chain)}", f"signer_authorized:{root.source}"])
        for parent, child in zip(chain, [*chain[1:], m], strict=True):
            if not _within(child, parent):
                return "scope_exceeds_delegation"
        return None

    def _run(self, m: Any, p: Any, p_hash: str | None, at: datetime, checks: list[str],
             state: dict[str, Any]) -> str | dict | None:
        if mandate_problem(m):
            return "mandate_malformed"
        if p_hash is None or payment_problem(p):
            return "payment_malformed"
        key = payment_key(m["company"], p["id"])
        try:
            prior = self.payments.lookup(key, p_hash)
        except Exception:  # noqa: BLE001
            return "checker_unavailable"
        if isinstance(prior, dict):
            return prior  # idempotent retry, read-only: unknown payers cannot write to the log
        mh = mandate_hash(m)
        if p["mandate"]["hash"] != mh:
            return "mandate_mismatch"
        if abs(_ts(p["requested_at"]) - at) > self.max_skew:
            return "clock_skew"
        sigs, threshold = _signatures(m)
        if not sigs or not all(_verify("mandate", mh, sig, s["public_key"], self.webauthn) for s, sig in sigs):
            return "mandate_bad_signature"
        chain = m.get("delegation", [])
        if chain:
            bad = _chain_problem(m, chain, self.webauthn)
            if bad:
                return bad
        checks.append("mandate_valid")
        if chain:
            bad = self._chain_ok(m, chain, checks)
            if bad:
                return bad
        else:
            self._signers_ok(m, sigs, threshold, checks)
        if "public_key" in m["agent"]:
            if not _verify("payment", p_hash, p.get("agent_sig"), m["agent"]["public_key"], self.webauthn):
                return "agent_bad_signature"
            checks.append("agent_signed")
        # Authentic from here on: only now may the payment id be claimed (spec 7, step 13).
        try:
            claimed = self.payments.register(key, p_hash)
        except Exception:  # noqa: BLE001
            return "checker_unavailable"
        if not claimed:
            return "duplicate_payment"
        state["registered"], state["key"] = True, key
        if "valid_from" in m and at < _ts(m["valid_from"]):
            return "mandate_not_yet_valid"
        if at > _ts(m["valid_until"]):
            return "mandate_expired"
        revoked = self._revoked(m, mh, chain, sigs, at)
        if revoked:
            return revoked
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
        return self._reserve(m, mh, chain, amt, at, checks)

    def _reserve(self, m: dict, mh: str, chain: list[dict], amt: Decimal, at: datetime,
                 checks: list[str]) -> str | None:
        """Step 21: reserve the amount against the mandate's period limit and against every delegation link's
        own period limit (a link's limit is shared by all mandates under it), all or nothing."""
        wanted = [(f"mandate:{mh}", m["scope"])] if "max_per_period" in m["scope"] else []
        wanted += [(f"delegation:{delegation_hash(d)}", d["scope"]) for d in chain if "max_per_period" in d["scope"]]
        if not wanted:
            return None
        if self.ledger is None:
            return "ledger_missing"
        done: list[tuple[str, str]] = []
        try:
            for key, sc in wanted:
                per = sc["max_per_period"]
                if not self.ledger.reserve(key, per["period"], amt, parse_amount(per["amount"], sc["currency"]), at):
                    self._release(done, amt, at)
                    return "over_period_limit"
                done.append((key, per["period"]))
        except Exception:  # noqa: BLE001
            self._release(done, amt, at)
            return "checker_unavailable"
        checks.append("within_period_limit")
        return None

    def _release(self, done: list[tuple[str, str]], amt: Decimal, at: datetime) -> None:
        for key, period in done:
            try:
                self.ledger.release(key, period, amt, at)  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001, S110 - best effort; the bank reconciles its ledger
                pass

    def _revoked(self, m: dict, mh: str, chain: list[dict], sigs: list[tuple[dict, Any]], at: datetime) -> str | None:
        """Section 9: a valid revocation of the mandate or of any delegation link, by an allowed person."""
        def people(links: list[dict]) -> set[tuple[str, str]]:
            out: set[tuple[str, str]] = set()
            for d in links:
                out |= {(d["from"]["id"], d["from"]["public_key"]), (d["to"]["id"], d["to"]["public_key"])}
            return out

        # The line of authority of each target: the mandate's own signers and its whole chain; for a link,
        # that link and the links above it (a delegate below cannot cut their delegator's authority).
        mandate_parties = {(s["id"], s["public_key"]) for s, _ in sigs} | people(chain)
        link_parties = {delegation_hash(d): people(chain[: i + 1]) for i, d in enumerate(chain)}
        for r in self.revocations:
            if revocation_problem(r) or _ts(r["revoked_at"]) > at:
                continue
            if "mandate_hash" in r:
                if r["mandate_hash"] != mh:
                    continue
                reason, parties = "mandate_revoked", mandate_parties
            elif r["delegation_hash"] in link_parties:
                reason, parties = "delegation_revoked", link_parties[r["delegation_hash"]]
            else:
                continue
            if not _verify("revocation", obj_hash(r), r.get("sig"), r["signer"]["public_key"], self.webauthn):
                continue
            try:
                res = self._authorized(m["company"], r["signer"], need_power=False)
            except _Stop as s:
                if s.reason == "checker_unavailable":
                    raise
                continue
            if res.may_sign or (r["signer"]["id"], r["signer"]["public_key"]) in parties:
                return reason
        return None


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


def verify_receipt(mandate: Any, payment: Any, decision: Any, checker_keys: Iterable[str], *,
                   webauthn: dict | None = None) -> dict[str, Any]:
    """Check a receipt offline, months later, without the bank: who authorized this payment, what was decided.

    Verifies the decision against the bank's known keys, that it names exactly this mandate and payment, and
    every signature in the mandate, its delegation chain and the payment. It cannot re-run the bank's authority
    check; the decision's ``signer_authorized:<source>`` checks record which source the bank relied on.

    For mandates signed with a passkey, pass the bank's passkey settings (``{"rp_id": ..., "origins": [...]}``);
    without them a passkey signature cannot be checked and the receipt reports ``mandate_bad_signature``.
    """
    wa = webauthn or {}
    problems: list[str] = []
    signed_by: list[str] = []
    chain_view: list[str] = []
    if not verify_decision(decision, checker_keys):
        problems.append("decision_bad_signature")
    m_ok = mandate_problem(mandate) is None
    if not m_ok:
        problems.append("mandate_malformed")
    else:
        mh = mandate_hash(mandate)
        if _get(decision, "mandate.hash") != mh:
            problems.append("decision_mandate_mismatch")
        sigs, _ = _signatures(mandate)
        signed_by = [s["id"] for s, sig in sigs if _verify("mandate", mh, sig, s["public_key"], wa)]
        if not sigs or len(signed_by) != len(sigs):
            problems.append("mandate_bad_signature")
        chain = mandate.get("delegation", [])
        chain_view = [f"{d['from']['id']} -> {d['to']['id']}" for d in chain]
        bad = _chain_problem(mandate, chain, wa) if chain else None
        if bad:
            problems.append(bad)
    if payment_problem(payment):
        problems.append("payment_malformed")
    else:
        ph = obj_hash(payment, "agent_sig")
        if _get(decision, "payment.hash") != ph:
            problems.append("decision_payment_mismatch")
        if m_ok:
            if payment["mandate"]["hash"] != mandate_hash(mandate):
                problems.append("payment_mandate_mismatch")
            agent_key = mandate["agent"].get("public_key")
            if agent_key is not None and not _verify("payment", ph, payment.get("agent_sig"), agent_key, wa):
                problems.append("agent_bad_signature")
    checks = _get(decision, "checks")
    authority = [c for c in checks if isinstance(c, str) and c.startswith("signer_authorized:")] \
        if isinstance(checks, list) else []
    return {
        "valid": not problems,
        "problems": problems,
        "outcome": _get(decision, "outcome"),
        "reasons": _get(decision, "reasons"),
        "checked_at": _get(decision, "checked_at"),
        "checker": _get(decision, "checker.id"),
        "company": _get(mandate, "company.name"),
        "agent": _get(mandate, "agent.id"),
        "signed_by": signed_by,
        "delegation": chain_view,
        "authority": authority,
        "payment": {"id": _get(payment, "id"), "amount": _get(payment, "amount"),
                    "currency": _get(payment, "currency"), "payee": _get(payment, "payee.account")},
    }
