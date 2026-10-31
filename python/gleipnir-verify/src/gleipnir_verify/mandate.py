"""Mandates for AI agents that pay: issue, sign, delegate, revoke, attach to a payment, check, override.

See spec/mandate.md. A company signatory (or a threshold of signatories) signs a mandate for one agent, possibly
on the strength of a signed delegation chain (CEO -> CFO). The bank checks every payment the agent starts against
it and signs a decision: allow, block or escalate. An escalation is resolved by a signed override.

Wiring a Checker (all are the bank's own systems):

- ``authority(company, person_id) -> AuthorityResult | None``: who may sign for the company, how (alone or
  jointly) and with which keys, from the bank's KYB records, a company register or vLEI. Never from the
  mandate. ``combine(kyb, vlei)`` asks several sources in order.
- ``holds(company, account) -> bool``: does this company hold this account at this bank (the debtor side).
- ``payments``: payment log for idempotency (``InMemoryPaymentLog`` for tests; persistent in production).
- ``ledger``: atomic period ledger (``InMemoryLedger`` for tests). Required for mandates with a period limit.
- ``status(url) -> dict``: fetches a signed status response, for mandates with a ``status_url``.
- ``officers``: public keys of bank staff who may sign overrides.

Gleipnir does not verify identities: the bank or a vLEI issuer binds keys to people (spec section 3).
"""

from __future__ import annotations

import re
import secrets
import threading
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .approvals import webauthn_problem
from .canon import canonicalize, hash_to_bytes, sha256_tagged
from .crypto import b64u, decode_public_key, encode_public_key, verify_signature
from .verifier import parse_time

V = "0.4"   # objects 0.5 left unchanged: payments, overrides, delegations, statuses, revocation lists, key sets
V5 = "0.5"  # mandates that use unlisted_payees, payee approvals, revocations of them, decisions about 0.5 mandates

# ---------- accounts and rails (spec section 6) ----------

_D = re.compile
# Each scheme: its fields and their canonical grammar. Accounts are compared exactly, so producers normalize
# (``account()``, ``iban()``) and checkers refuse anything not in canonical form.
SCHEMES: dict[str, dict[str, re.Pattern[str]]] = {
    "iban": {"iban": _D(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}")},
    "us_aba": {"routing": _D(r"[0-9]{9}"), "account": _D(r"[0-9]{1,17}")},
    "uk_sort_code": {"sort_code": _D(r"[0-9]{6}"), "account": _D(r"[0-9]{8}")},
    "ca_eft": {"institution": _D(r"[0-9]{3}"), "transit": _D(r"[0-9]{5}"), "account": _D(r"[0-9]{7,12}")},
    "au_bsb": {"bsb": _D(r"[0-9]{6}"), "account": _D(r"[0-9]{5,10}")},
    "in_ifsc": {"ifsc": _D(r"[A-Z]{4}0[A-Z0-9]{6}"), "account": _D(r"[0-9]{9,18}")},
    "mx_clabe": {"clabe": _D(r"[0-9]{18}")},
    "swift": {"bic": _D(r"[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?"), "account": _D(r"[A-Z0-9]{1,34}")},
}
_ALL = frozenset(SCHEMES)
# rail -> (account schemes it can carry, the only currency it can carry or None for any)
RAIL_RULES: dict[str, tuple[frozenset[str], str | None]] = {
    "sepa": (frozenset({"iban"}), "EUR"),
    "sepa_instant": (frozenset({"iban"}), "EUR"),
    "ach": (frozenset({"us_aba"}), "USD"),
    "fednow": (frozenset({"us_aba"}), "USD"),
    "rtp": (frozenset({"us_aba"}), "USD"),
    "faster_payments": (frozenset({"uk_sort_code"}), "GBP"),
    "bacs": (frozenset({"uk_sort_code"}), "GBP"),
    "chaps": (frozenset({"uk_sort_code"}), "GBP"),
    "ca_eft": (frozenset({"ca_eft"}), "CAD"),
    "npp": (frozenset({"au_bsb"}), "AUD"),
    "becs": (frozenset({"au_bsb"}), "AUD"),
    "neft": (frozenset({"in_ifsc"}), "INR"),
    "rtgs": (frozenset({"in_ifsc"}), "INR"),
    "imps": (frozenset({"in_ifsc"}), "INR"),
    "spei": (frozenset({"mx_clabe"}), "MXN"),
    "wire": (_ALL, None),
}
RAILS = set(RAIL_RULES)
PERIODS = {"P1D", "P7D", "P1M"}
# ISO 4217 minor units of the currencies supported in 0.3.
MINOR_UNITS = {"EUR": 2, "USD": 2, "GBP": 2, "CHF": 2, "SEK": 2, "NOK": 2, "DKK": 2, "PLN": 2, "CZK": 2,
               "HUF": 2, "RON": 2, "CAD": 2, "AUD": 2, "NZD": 2, "SGD": 2, "HKD": 2, "INR": 2, "MXN": 2, "JPY": 0}
_AMOUNT_RE = {0: _D(r"(0|[1-9][0-9]*)"), 2: _D(r"(0|[1-9][0-9]*)\.[0-9]{2}")}

ESCALATE = {"signer_unknown", "status_unavailable", "over_payment_limit", "over_period_limit", "ledger_missing",
            "checker_unavailable", "override_invalid", "override_not_authorized", "new_payee"}
# Escalations that keep the payment id while a person decides (spec 7, "Idempotency"). Every other non-allow
# outcome of a check releases the id, so a corrected payment may use it again.
HOLDS = {"over_payment_limit", "new_payee"}
# Escalations a company signatory may resolve; every escalation may be resolved by a bank officer.
COMPANY_OVERRIDABLE = {"over_payment_limit", "over_period_limit", "new_payee"}
# Escalations no override can resolve: the bank fixes the dependency and the agent retries.
NOT_OVERRIDABLE = {"ledger_missing", "checker_unavailable", "override_invalid", "override_not_authorized"}
# A re-check after an override that stops on one of these keeps the escalation, so the override can be retried.
RETRYABLE = {"checker_unavailable", "status_unavailable", "ledger_missing"}
MAX_DEPTH = 32       # nesting of objects and arrays (spec 13)
MAX_SIGNERS = 16     # entries in signers.of, and signatures on an override
MANDATE_SIG_FIELDS = ("sig", "sigs")
_COUNTRY_RE = _D(r"[A-Z]{2}")
_MAX_INT = 2 ** 53 - 1
MAX_DELEGATION_DEPTH = 5
MAX_URL = 2048
MAX_APPROVALS = 16   # payee approvals presented with one payment (spec 7.2)
UNLISTED = ("block", "escalate")


def _iban_checksum_ok(text: str) -> bool:
    digits = "".join(str(int(c, 36)) for c in text[4:] + text[:4])
    return int(digits) % 97 == 1


def _aba_checksum_ok(r: str) -> bool:
    d = [int(c) for c in r]
    return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 == 0


def _clabe_checksum_ok(c: str) -> bool:
    w = [3, 7, 1] * 6
    s = sum((int(c[i]) * w[i]) % 10 for i in range(17))
    return (10 - s % 10) % 10 == int(c[17])


def account_problem(acc: Any) -> str | None:
    """Why this is not a canonical account object of a known scheme, or None."""
    if not isinstance(acc, dict):
        return "an account must be an object"
    scheme = acc.get("scheme")
    if not isinstance(scheme, str) or scheme not in SCHEMES:
        return f"unknown account scheme: {scheme!r}"
    want = SCHEMES[scheme]
    if set(acc) != {"scheme", *want}:
        return f"a {scheme} account has exactly the fields {sorted(want)}"
    for name, grammar in want.items():
        v = acc[name]
        if not isinstance(v, str) or not v.isascii() or not grammar.fullmatch(v):
            return f"{scheme}.{name} is not in canonical form"
    if scheme == "iban" and not _iban_checksum_ok(acc["iban"]):
        return "IBAN check digits are wrong"
    if scheme == "us_aba" and not _aba_checksum_ok(acc["routing"]):
        return "ABA routing number check digit is wrong"
    if scheme == "mx_clabe" and not _clabe_checksum_ok(acc["clabe"]):
        return "CLABE check digit is wrong"
    return None


def account(scheme: str, **fields: str) -> dict[str, str]:
    """A canonical account from human input: spaces and hyphens removed, letters uppercased. ValueError if bad."""
    acc = {"scheme": scheme, **{k: re.sub(r"[\s-]", "", v).upper() for k, v in fields.items()}}
    problem = account_problem(acc)
    if problem:
        raise ValueError(problem)
    return acc


def iban(text: str) -> dict[str, str]:
    """``account("iban", iban=text)``: accepts "AT61 1904 3002 3457 3201"."""
    return account("iban", iban=text)


def rail_fits(rail: str, currency: str, accounts: Iterable[dict]) -> bool:
    """True if the rail can carry this currency between accounts of these schemes."""
    schemes, cur = RAIL_RULES[rail]
    return (cur is None or cur == currency) and all(a["scheme"] in schemes for a in accounts)


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


def override_hash(override: dict[str, Any]) -> str:
    """The hash every override signature covers: the override minus ``sigs``."""
    return obj_hash(override, "sigs")


def message(kind: str, h: str, v: str = V) -> bytes:
    return f"gleipnir/{kind}/v{v}\n".encode() + h.encode("ascii")


def version_of(obj: Any, kind: str) -> str:
    """The draft an object is in: "0.5" if its ``v`` says so, else "0.4" (the version every other check uses)."""
    return V5 if isinstance(obj, dict) and obj.get("v") == f"gleipnir/{kind}/{V5}" else V


def payee_approval_hash(approval: dict[str, Any]) -> str:
    """The hash every payee approval signature covers: the approval minus ``sigs``."""
    return obj_hash(approval, "sigs")


def new_key() -> tuple[Ed25519PrivateKey, str]:
    """A fresh Ed25519 key and its public key text."""
    sk = Ed25519PrivateKey.generate()
    return sk, public_key_of(sk)


def public_key_of(sk: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization as s
    return encode_public_key(sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw))


def _sig_text(sk: Ed25519PrivateKey, kind: str, h: str, v: str = V) -> str:
    return "ed25519:" + b64u(sk.sign(message(kind, h, v)))


def _sign(sk: Ed25519PrivateKey, kind: str, obj: dict[str, Any], sig_field: str = "sig",
          v: str = V) -> dict[str, Any]:
    out = {k: x for k, x in obj.items() if k != sig_field}
    out[sig_field] = _sig_text(sk, kind, obj_hash(out, sig_field), v)
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


# ---------- issuing ----------

def issue(*, company: dict, agent: dict, scope: dict, valid_until: str, id: str, signer: dict | None = None,
          signers: dict | None = None, delegation: list[dict] | None = None, valid_from: str | None = None,
          status_url: str | None = None, issued_at: str | None = None, version: str | None = None) -> dict[str, Any]:
    """An unsigned mandate: one ``signer`` (sign with sign_mandate) or ``signers`` {threshold, of} (cosign).

    ``version``: "0.4" or "0.5"; by default 0.5 if the scope uses ``unlisted_payees`` or
    ``max_per_unlisted_payee`` (spec 4.1), else 0.4, so a mandate a 0.4 checker can read stays 0.4.
    """
    if version is None:
        version = V5 if {"unlisted_payees", "max_per_unlisted_payee"} & set(scope) else V
    m: dict[str, Any] = {"v": f"gleipnir/mandate/{version}", "id": id, "company": company, "agent": agent,
                         "scope": scope, "valid_until": valid_until, "issued_at": issued_at or now()}
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
    out["sig"] = _sig_text(sk, "mandate", mandate_hash(out), version_of(mandate, "mandate"))
    return out


def cosign(mandate: dict, sk: Ed25519PrivateKey, signer_id: str) -> dict[str, Any]:
    """Add (or replace) one co-signature on a multi-signature mandate. Co-signers sign the same hash."""
    sig = _sig_text(sk, "mandate", mandate_hash(mandate), version_of(mandate, "mandate"))
    entry = {"signer": signer_id, "sig": sig}
    sigs = [s for s in mandate.get("sigs", []) if s.get("signer") != signer_id] + [entry]
    return {**mandate, "sigs": sigs}


def passkey_digest(mandate: dict) -> str:
    """What a signatory's passkey signs: SHA-256 of the domain-separated mandate message (spec 4.3).

    Domain separation keeps a mandate passkey signature from ever being valid as an approval of an agent
    action (format.md "Signed approvals"), which signs the bare action digest.
    """
    return sha256_tagged(message("mandate", mandate_hash(mandate), version_of(mandate, "mandate")))


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
    """A signed revocation of a mandate, a delegation link or a payee approval.

    A revocation is in the draft of what it revokes: 0.5 for a 0.5 mandate and for a payee approval (which only
    0.5 has), else 0.4. Checkers accept revocations of both drafts (spec 13.1).
    """
    kind = str(target.get("v", ""))
    ver = V5 if kind.startswith("gleipnir/payee_approval/") or kind == f"gleipnir/mandate/{V5}" else V
    r: dict[str, Any] = {"v": f"gleipnir/revocation/{ver}", "id": id}
    if kind.startswith("gleipnir/delegation/"):
        r.update({"delegation": target["id"], "delegation_hash": delegation_hash(target)})
    elif kind.startswith("gleipnir/payee_approval/"):
        r.update({"payee_approval": target["id"], "payee_approval_hash": payee_approval_hash(target)})
    else:
        r.update({"mandate": target["id"], "mandate_hash": mandate_hash(target)})
    r.update({"revoked_at": revoked_at or now(), "signer": signer})
    if reason:
        r["reason"] = reason
    return _sign(sk, "revocation", r, v=ver)


def approve_payee(mandate: dict, *, payee: dict, id: str, approved_at: str | None = None,
                  valid_until: str | None = None, reason: str = "") -> dict[str, Any]:
    """An unsigned payee approval (spec 7.2): this payee account counts as listed on this 0.5 mandate. The
    company's signatories add their signatures with sign_payee_approval, as many as the mandate itself needed."""
    if version_of(mandate, "mandate") != V5:
        raise ValueError("payee approvals need a 0.5 mandate")
    a: dict[str, Any] = {"v": f"gleipnir/payee_approval/{V5}", "id": id,
                         "mandate": {"id": mandate["id"], "hash": mandate_hash(mandate)},
                         "payee": {"name": payee.get("name", ""), "account": payee.get("account")},
                         "approved_at": approved_at or now(), "sigs": []}
    if valid_until:
        a["valid_until"] = valid_until
    if reason:
        a["reason"] = reason
    problem = payee_approval_problem({**a, "sigs": [{"signer": {"id": "x", "public_key": "x"}, "sig": "x"}]})
    if problem:
        raise ValueError(problem)
    return a


def sign_payee_approval(approval: dict, sk: Ed25519PrivateKey, signer: dict) -> dict[str, Any]:
    """Add (or replace) one signature on a payee approval. ``signer``: {id, public_key} of the person signing."""
    entry = {"signer": signer, "sig": _sig_text(sk, "payee_approval", payee_approval_hash(approval), V5)}
    sigs = [s for s in approval.get("sigs", []) if _get(s, "signer.id") != signer["id"]] + [entry]
    return {**approval, "sigs": sigs}


def payee_approval_digest(approval: dict) -> str:
    """What a signatory's passkey signs for a payee approval (the WebAuthn challenge is its 32 raw bytes)."""
    return sha256_tagged(message("payee_approval", payee_approval_hash(approval), V5))


def attach(mandate: dict, *, id: str, rail: str, amount: str, currency: str, payee: dict, reference: str = "",
           from_account: dict | None = None, agent_sk: Ed25519PrivateKey | None = None,
           requested_at: str | None = None) -> dict[str, Any]:
    """A payment that relies on this mandate, signed by the agent when the mandate names an agent key.

    ``from_account`` defaults to the mandate's only debtor account; it is required when the mandate lists several.
    """
    if from_account is None:
        accounts = mandate.get("scope", {}).get("from_accounts", [])
        if len(accounts) != 1:
            raise ValueError("the mandate lists several from_accounts: pass from_account")
        from_account = accounts[0]
    p: dict[str, Any] = {"v": f"gleipnir/payment/{V}", "id": id,
                         "mandate": {"id": mandate["id"], "hash": mandate_hash(mandate)},
                         "rail": rail, "amount": amount, "currency": currency, "from_account": from_account,
                         "payee": payee, "requested_at": requested_at or now()}
    if reference:
        p["reference"] = reference
    if agent_sk is not None:
        p = _sign(agent_sk, "payment", p, "agent_sig")
    return p


def status_response(mandate: dict, *, status: str, signer: dict, sk: Ed25519PrivateKey,
                    at: str | None = None) -> dict[str, Any]:
    """What a ``status_url`` answers: a signed, timed statement about exactly this mandate (spec 9.1)."""
    s = {"v": f"gleipnir/status/{V}", "mandate": {"id": mandate["id"], "hash": mandate_hash(mandate)},
         "status": status, "at": at or now(), "signer": signer}
    return _sign(sk, "status", s)


def make_override(decision: dict, *, outcome: str, id: str, reason: str = "",
                  decided_at: str | None = None) -> dict[str, Any]:
    """An unsigned override of an escalate decision; add signatures with sign_override (spec 7.1)."""
    o: dict[str, Any] = {"v": f"gleipnir/override/{V}", "id": id,
                         "decision": {"id": decision.get("id"), "hash": obj_hash(decision)},
                         "outcome": outcome, "decided_at": decided_at or now(), "sigs": []}
    if reason:
        o["reason"] = reason
    return o


def sign_override(override: dict, sk: Ed25519PrivateKey, signer: dict) -> dict[str, Any]:
    """Add (or replace) one signature on an override. ``signer``: {id, public_key} of the person signing."""
    entry = {"signer": signer, "sig": _sig_text(sk, "override", override_hash(override))}
    sigs = [s for s in override.get("sigs", []) if _get(s, "signer.id") != signer["id"]] + [entry]
    return {**override, "sigs": sigs}


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


def _depth_ok(obj: Any) -> bool:
    """At most MAX_DEPTH nested objects and arrays, counted without recursion (spec 13)."""
    stack = [(obj, 1)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, (dict, list)):
            if d > MAX_DEPTH:
                return False
            stack.extend((x, d + 1) for x in (v.values() if isinstance(v, dict) else v))
    return True


def _jcs_ok(obj: Any) -> bool:
    if not _depth_ok(obj):
        return False
    try:
        canonicalize(obj)
    except Exception:  # noqa: BLE001 - any value JCS cannot encode
        return False
    try:
        return _numbers_ok(obj)
    except RecursionError:
        return False


# ---------- shapes: every object has a closed set of fields (spec 13, "Versioning") ----------
# A field the checker does not know could narrow what a signer meant, so it is never ignored: an unknown field
# makes the object malformed. Producers put anything a checker must not act on under "x".
_ANY = "any"
_X = "x"


def _s(n: int) -> tuple[str, int]:
    return ("s", n)


def _o(name: str) -> tuple[str, str]:
    return ("o", name)


def _l(name: str) -> tuple[str, str]:
    return ("l", name)


SHAPES: dict[str, dict[str, Any]] = {
    "person": {"id": _ANY, "public_key": _ANY, "name": _s(140), "role": _s(140)},
    "company": {"name": _s(140), "country": _ANY, "ids": "ids"},
    "agent": {"id": _ANY, "name": _s(140), "public_key": _ANY},
    "payee": {"name": _s(140), "account": _ANY},
    "period": {"amount": _ANY, "period": _ANY},
    "scope": {"from_accounts": _ANY, "rails": _ANY, "currency": _ANY, "max_per_payment": _ANY,
              "max_per_period": _o("period"), "payees": _l("payee"), "purpose": _s(500)},
    "signers": {"threshold": _ANY, "of": _l("person")},
    "sigentry": {"signer": _ANY, "sig": _ANY},
    "ref": {"id": _ANY, "hash": _ANY},
    "mandate": {"v": _ANY, "id": _s(128), "company": _o("company"), "agent": _o("agent"), "signer": _o("person"),
                "signers": _o("signers"), "sigs": _l("sigentry"), "sig": _ANY, "scope": _o("scope"),
                "valid_from": _ANY, "valid_until": _ANY, "issued_at": _ANY, "status_url": _ANY, "delegation": _ANY,
                "x": _X},
    "delegation": {"v": _ANY, "id": _s(128), "company": _o("company"), "from": _o("person"), "to": _o("person"),
                   "scope": _o("scope"), "valid_from": _ANY, "valid_until": _ANY, "issued_at": _ANY,
                   "parent": _o("ref"), "sig": _ANY, "x": _X},
    "payment": {"v": _ANY, "id": _s(35), "mandate": _o("ref"), "rail": _ANY, "amount": _ANY, "currency": _ANY,
                "from_account": _ANY, "payee": _o("payee"), "reference": _s(140), "requested_at": _ANY,
                "agent_sig": _ANY, "x": _X},
    "revocation": {"v": _ANY, "id": _s(128), "mandate": _ANY, "mandate_hash": _ANY, "delegation": _ANY,
                   "delegation_hash": _ANY, "revoked_at": _ANY, "signer": _o("person"), "reason": _s(500),
                   "sig": _ANY, "x": _X},
    "status": {"v": _ANY, "mandate": _o("ref"), "status": _ANY, "at": _ANY, "signer": _o("person"), "sig": _ANY},
    "osig": {"signer": _o("person"), "sig": _ANY},
    "override": {"v": _ANY, "id": _s(128), "decision": _o("ref"), "outcome": _ANY, "decided_at": _ANY,
                 "reason": _s(500), "sigs": _l("osig"), "x": _X},
    "payee_approval": {"v": _ANY, "id": _s(128), "mandate": _o("ref"), "payee": _o("approved_payee"),
                       "approved_at": _ANY, "valid_until": _ANY, "reason": _s(500), "sigs": _l("osig"), "x": _X},
    "approved_payee": {"name": _s(140), "account": _ANY},
}
# 0.5 adds fields to a mandate's scope and a third revocation target; 0.4 objects keep exactly their 0.4 shape.
SHAPES["scope@0.5"] = {**SHAPES["scope"], "unlisted_payees": _ANY, "max_per_unlisted_payee": _ANY}
SHAPES["mandate@0.5"] = {**SHAPES["mandate"], "scope": _o("scope@0.5")}
SHAPES["revocation@0.5"] = {**SHAPES["revocation"], "payee_approval": _ANY, "payee_approval_hash": _ANY}


def _shape_problem(obj: Any, shape: str, path: str) -> str | None:
    """The first field outside the object's shape (keys in sorted order), or a wrongly typed informational
    field, or None. Values the shape marks as ``any`` are validated elsewhere."""
    if not isinstance(obj, dict):
        return None
    spec = SHAPES[shape]
    for k in sorted(obj):
        where = f"{path}.{k}" if path else k
        if k not in spec:
            return f"unknown field {where}"
        kind, v = spec[k], obj[k]
        if kind == _X or kind == "ids":
            if not isinstance(v, dict):
                return f"{where} must be an object"
        elif isinstance(kind, tuple) and kind[0] == "s":
            if not isinstance(v, str):
                return f"{where} must be a string"
            if len(v) > kind[1]:
                return f"{where} is longer than {kind[1]} characters"
        elif isinstance(kind, tuple) and kind[0] == "o":
            bad = _shape_problem(v, kind[1], where)
            if bad:
                return bad
        elif isinstance(kind, tuple) and kind[0] == "l" and isinstance(v, list):
            for item in v:
                bad = _shape_problem(item, kind[1], f"{where}[]")
                if bad:
                    return bad
    return None


def _person_problem(p: Any, what: str) -> str | None:
    if not isinstance(p, dict) or _str_fields(p, ("id", "public_key")):
        return f"missing {what}.id or {what}.public_key"
    return None


def _accounts_problem(accs: Any, what: str) -> str | None:
    if not isinstance(accs, list) or not accs:
        return f"{what} must be a non-empty list of accounts"
    for a in accs:
        bad = account_problem(a)
        if bad:
            return f"{what}: {bad}"
    if len({canonicalize(a) for a in accs}) != len(accs):
        return f"{what} lists an account twice"
    return None


def _scope_problem(sc: dict, *, debtor_required: bool) -> str | None:
    """Scope rules shared by mandates and delegations."""
    try:
        parse_amount(sc["max_per_payment"], sc["currency"])
        if "max_per_period" in sc:
            per = sc["max_per_period"]
            if not isinstance(per, dict) or not isinstance(per.get("period"), str) or per["period"] not in PERIODS:
                return "max_per_period needs a period of P1D, P7D or P1M"
            parse_amount(per.get("amount"), sc["currency"])
    except ValueError as e:
        return str(e)
    rails = sc.get("rails", [])
    if not isinstance(rails, list) or not all(isinstance(r, str) for r in rails):
        return "rails must be a list of strings"
    if set(rails) - RAILS:
        return f"unknown rails: {sorted(set(rails) - RAILS)}"
    if "payees" in sc:
        payees = sc["payees"]
        if not isinstance(payees, list) or not payees or not all(isinstance(x, dict) for x in payees):
            return "payees must be a non-empty list of {name, account}"
        bad = _accounts_problem([x.get("account") for x in payees], "payees")
        if bad:
            return bad
    if "from_accounts" in sc or debtor_required or "max_per_period" in sc:
        if "from_accounts" not in sc:
            return "from_accounts is required" + ("" if debtor_required else " with a period limit")
        bad = _accounts_problem(sc["from_accounts"], "from_accounts")
        if bad:
            return bad
    return None


def _validity_problem(obj: dict) -> str | None:
    try:
        until = _ts(obj["valid_until"])
        _ts(obj["issued_at"])
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
    if len(ss["of"]) > MAX_SIGNERS:
        return f"at most {MAX_SIGNERS} signers"
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


def _unlisted_problem(sc: dict) -> str | None:
    """0.5 scope rules for payees that are not on the list (spec 4.1)."""
    if "unlisted_payees" in sc and sc["unlisted_payees"] not in UNLISTED:
        return "unlisted_payees must be block or escalate"
    if "max_per_unlisted_payee" in sc:
        if sc.get("unlisted_payees") != "escalate":
            return "max_per_unlisted_payee needs unlisted_payees: escalate"
        try:
            parse_amount(sc["max_per_unlisted_payee"], sc["currency"])
        except ValueError as e:
            return str(e)
    return None


def mandate_problem(m: Any) -> str | None:
    """Why this is not a well-formed mandate (0.4 or 0.5), or None."""
    if not isinstance(m, dict) or m.get("v") not in (f"gleipnir/mandate/{V}", f"gleipnir/mandate/{V5}"):
        return "unknown mandate version"
    bad = _str_fields(m, ("id", "company.name", "company.country", "agent.id", "scope.currency",
                          "scope.max_per_payment", "valid_until", "issued_at"))
    if bad:
        return bad
    if not _jcs_ok(m):
        return "mandate is not valid I-JSON"
    v5 = version_of(m, "mandate") == V5
    bad = _shape_problem(m, "mandate@0.5" if v5 else "mandate", "")
    if bad:
        return bad
    if not _COUNTRY_RE.fullmatch(m["company"]["country"]):
        return "company.country must be an ISO 3166-1 alpha-2 code"
    bad = _signers_problem(m) or _scope_problem(m["scope"], debtor_required=True) or _validity_problem(m)
    if bad:
        return bad
    if v5:
        bad = _unlisted_problem(m["scope"])
        if bad:
            return bad
    if "status_url" in m:
        url = m["status_url"]
        if not isinstance(url, str) or not url.startswith("https://") or len(url) > MAX_URL or not url.isascii():
            return "status_url must be an https URL"
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
                          "scope.currency", "scope.max_per_payment", "valid_until", "issued_at"))
    if bad:
        return bad
    if not _jcs_ok(d):
        return "delegation is not valid I-JSON"
    bad = _shape_problem(d, "delegation", "")
    if bad:
        return bad
    if "parent" in d and _str_fields(d["parent"], ("id", "hash")):
        return "parent needs id and hash"
    return _scope_problem(d["scope"], debtor_required=False) or _validity_problem(d)


def payment_problem(p: Any) -> str | None:
    """Why this is not a well-formed payment, or None."""
    if not isinstance(p, dict) or p.get("v") != f"gleipnir/payment/{V}":
        return "unknown payment version"
    bad = _str_fields(p, ("id", "mandate.id", "mandate.hash", "rail", "currency", "requested_at"))
    if bad:
        return bad
    if not isinstance(p.get("payee"), dict):
        return "missing payee"
    if not _jcs_ok(p):
        return "payment is not valid I-JSON"
    bad = _shape_problem(p, "payment", "")
    if bad:
        return bad
    if p["rail"] not in RAILS:
        return f"unknown rail: {p['rail']!r}"
    bad = account_problem(p["payee"].get("account"))
    if bad:
        return f"payee.account: {bad}"
    bad = account_problem(p.get("from_account"))
    if bad:
        return f"from_account: {bad}"
    try:
        parse_amount(p.get("amount"), p["currency"])
        _ts(p["requested_at"])
    except ValueError as e:
        return str(e)
    return None


_TARGETS = (("mandate", "mandate_hash"), ("delegation", "delegation_hash"), ("payee_approval", "payee_approval_hash"))


def revocation_problem(r: Any) -> str | None:
    """Why this is not a well-formed revocation (0.4: of a mandate or delegation; 0.5: also of a payee
    approval), or None."""
    if not isinstance(r, dict) or r.get("v") not in (f"gleipnir/revocation/{V}", f"gleipnir/revocation/{V5}"):
        return "unknown revocation version"
    v5 = version_of(r, "revocation") == V5
    targets = [t for t in (_TARGETS if v5 else _TARGETS[:2]) if t[1] in r]
    if len(targets) != 1:
        return ("a revocation targets exactly one mandate, delegation or payee approval" if v5
                else "a revocation targets exactly one mandate or delegation")
    target = targets[0]
    bad = _str_fields(r, (*target, "id", "revoked_at", "signer.id", "signer.public_key"))
    if bad or not _jcs_ok(r):
        return bad or "revocation is not valid I-JSON"
    bad = _shape_problem(r, "revocation@0.5" if v5 else "revocation", "")
    if bad:
        return bad
    try:
        _ts(r["revoked_at"])
    except ValueError as e:
        return str(e)
    return None


def status_problem(s: Any) -> str | None:
    if not isinstance(s, dict) or s.get("v") != f"gleipnir/status/{V}":
        return "unknown status version"
    bad = _str_fields(s, ("mandate.id", "mandate.hash", "status", "at", "signer.id", "signer.public_key"))
    if bad or not _jcs_ok(s):
        return bad or "status is not valid I-JSON"
    bad = _shape_problem(s, "status", "")
    if bad:
        return bad
    if s["status"] not in ("active", "revoked"):
        return "status must be active or revoked"
    try:
        _ts(s["at"])
    except ValueError as e:
        return str(e)
    return None


def override_problem(o: Any) -> str | None:
    if not isinstance(o, dict) or o.get("v") != f"gleipnir/override/{V}":
        return "unknown override version"
    bad = _str_fields(o, ("id", "decision.id", "decision.hash", "outcome", "decided_at"))
    if bad or not _jcs_ok(o):
        return bad or "override is not valid I-JSON"
    bad = _shape_problem(o, "override", "")
    if bad:
        return bad
    if o["outcome"] not in ("allow", "block"):
        return "outcome must be allow or block"
    if "reason" in o and not isinstance(o["reason"], str):
        return "reason must be a string"
    bad = _osigs_problem(o.get("sigs"), "an override")
    if bad:
        return bad
    try:
        _ts(o["decided_at"])
    except ValueError as e:
        return str(e)
    return None


def _osigs_problem(sigs: Any, what: str) -> str | None:
    """Signatures of people named in the entry ({signer: {id, public_key}, sig}): overrides, payee approvals."""
    if not isinstance(sigs, list) or not sigs:
        return f"{what} needs at least one signature"
    if len(sigs) > MAX_SIGNERS:
        return f"at most {MAX_SIGNERS} signatures"
    for s in sigs:
        if not isinstance(s, dict) or _person_problem(s.get("signer"), "sigs[].signer") \
                or not isinstance(s.get("sig"), (str, dict)):
            return "every sigs entry needs a signer {id, public_key} and a sig"
    if len({s["signer"]["id"] for s in sigs}) != len(sigs) \
            or len({s["signer"]["public_key"] for s in sigs}) != len(sigs):
        return "one signature per person and per key"
    return None


def payee_approval_problem(a: Any) -> str | None:
    """Why this is not a well-formed payee approval (0.5 only, spec 7.2), or None."""
    if not isinstance(a, dict) or a.get("v") != f"gleipnir/payee_approval/{V5}":
        return "unknown payee approval version"
    bad = _str_fields(a, ("id", "mandate.id", "mandate.hash", "payee.name", "approved_at"))
    if bad or not _jcs_ok(a):
        return bad or "payee approval is not valid I-JSON"
    bad = _shape_problem(a, "payee_approval", "")
    if bad:
        return bad
    bad = account_problem(a["payee"].get("account"))
    if bad:
        return f"payee.account: {bad}"
    bad = _osigs_problem(a.get("sigs"), "a payee approval")
    if bad:
        return bad
    try:
        at = _ts(a["approved_at"])
        if "valid_until" in a and _ts(a["valid_until"]) < at:
            return "valid_until is before approved_at"
    except ValueError as e:
        return str(e)
    return None


def _approvals_problem(approvals: Any) -> str | None:
    if not isinstance(approvals, list):
        return "payee approvals must be a list"
    if len(approvals) > MAX_APPROVALS:
        return f"at most {MAX_APPROVALS} payee approvals"
    for a in approvals:
        bad = payee_approval_problem(a)
        if bad:
            return bad
    return None


# ---------- payee names (spec 7, step 21) ----------
# Look-alike letters from other scripts (lowercase, or the lowercase of a capital look-alike such as Cyrillic
# В -> в -> b), and digits that pass for letters, mapped to the Latin letter they imitate. Applied to both
# sides after lowercasing; the comparison can only block, never allow, so a wider match is the safe side.
# The same table is in spec/mandate.md (step 21) and the TypeScript port.
_CONFUSABLE = str.maketrans({
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t",
    "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l",
    "α": "a", "β": "b", "ε": "e", "ζ": "z", "η": "h", "ι": "i", "κ": "k", "μ": "m", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "ı": "i", "ȷ": "j", "ɑ": "a", "ɡ": "g", "0": "o", "1": "l",
})


def payee_name_key(name: Any) -> str:
    """The comparison key of a payee name (spec 7, step 21): compatibility-decomposed (NFKD), lowercased, every
    character that is not a letter or a digit removed (spaces, punctuation, symbols, accents, invisible
    characters), and look-alike characters folded. "Brenner-Stahl A.G." and "BRENNER STAHL AG" share a key.
    Empty for a missing name or one without letters or digits; an empty key matches nothing."""
    if not isinstance(name, str):
        return ""
    t = unicodedata.normalize("NFKD", unicodedata.normalize("NFKD", name).lower())
    t = t.replace("ß", "ss").replace("ς", "σ")
    return "".join(c for c in t if unicodedata.category(c)[0] in "LN").translate(_CONFUSABLE)


def _signatures(m: dict) -> tuple[list[tuple[dict, Any]], int]:
    """(signer, signature) pairs present on a well-formed mandate, and the mandate's threshold."""
    if "signer" in m:
        return ([(m["signer"], m["sig"])] if "sig" in m else []), 1
    by_id = {p["id"]: p for p in m["signers"]["of"]}
    return [(by_id[s["signer"]], s["sig"]) for s in m.get("sigs", [])], m["signers"]["threshold"]


def _verify(kind: str, h: str, sig: Any, pub_text: Any, webauthn: dict, v: str = V) -> bool:
    """A signature over message(kind, h, v). Passkey (WebAuthn) signatures are accepted for what people sign in
    the bank's app: mandates, overrides and payee approvals."""
    try:
        pub = decode_public_key(pub_text)
        if isinstance(sig, dict) and sig.get("type") == "webauthn" and kind in ("mandate", "override",
                                                                                  "payee_approval"):
            return webauthn_problem(sig, pub, sha256_tagged(message(kind, h, v)), webauthn.get("rp_id", ""),
                                    webauthn.get("origins", []), None) is None
        return verify_signature(pub, message(kind, h, v), sig)
    except Exception:  # noqa: BLE001 - any malformed key or signature fails closed
        return False


def _same_person(a: dict, b: dict) -> bool:
    return (a["id"], a["public_key"]) == (b["id"], b["public_key"])


def _same_company(link: dict, mandate: dict) -> bool:
    """A link names the mandate's company: same name, and the same country and ids where the link gives them."""
    def same(k: str) -> bool:  # exact JSON equality; absent is not null, true is not 1
        return k in mandate and canonicalize(link[k]) == canonicalize(mandate[k])
    return link.get("name") == mandate["name"] and all(same(k) for k in ("country", "ids") if k in link)


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


def _key(acc: dict) -> bytes:
    return canonicalize(acc)


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
        allowed = {_key(x["account"]) for x in ps["payees"]}
        if "payees" not in cs or any(_key(x["account"]) not in allowed for x in cs["payees"]):
            return False
        if cs.get("unlisted_payees") == "escalate":  # a person could add payees the delegator never allowed
            return False
    if "from_accounts" in ps:
        allowed = {_key(a) for a in ps["from_accounts"]}
        if "from_accounts" not in cs or any(_key(a) not in allowed for a in cs["from_accounts"]):
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
    keys: tuple[str, ...]        # current public keys the source binds to this person (enrollment, spec section 3)
    may_sign: bool = True        # signing power of their own; False for a person known only as a delegate
    joint: int = 1               # signatures their power requires, including their own (joint with one other: 2)
    # Rotated-out keys -> retirement time: still accepted for objects issued before that time (spec 8).
    retired: Mapping[str, str] = field(default_factory=dict)
    # The source's own id for this person; several ids or keys of one person count once (spec 8).
    person: str | None = None


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
        """The decision this key holds for this exact payment, or None."""

    def register(self, key: str, payment_hash: str) -> bool:
        """Atomically claim the key. False if it is already claimed (by any payment)."""

    def remember(self, key: str, decision: dict) -> None:
        """Store the decision a claimed key holds (an allow, or an escalation waiting for a person)."""

    def forget(self, key: str) -> None:
        """Release a claim, so the payment id may be used again."""

    def take(self, key: str, payment_hash: str, decision_id: str) -> bool:
        """Atomically take over a held escalation for resolving: if the key holds the decision ``decision_id``
        for this payment, clear it (claimed, being checked) and return True; otherwise False. Two concurrent
        overrides of one escalation must not both re-check it."""


class Ledger(Protocol):
    """Period totals (spec 7). ``key`` is "mandate:<hash>" or "delegation:<hash>"; ``at`` picks the period."""

    def reserve(self, key: str, period: str, amount: Decimal, limit: Decimal | None, at: datetime) -> bool:
        """Atomically add amount to the period total if the total stays within limit (None: an override, add)."""

    def release(self, key: str, period: str, amount: Decimal, at: datetime) -> None:
        """Give back a reservation (a later step failed, or the bank did not execute)."""


def payment_key(customer: str, payment_id: str) -> str:
    """The payment log key: payment ids are unique per payer, so the payer is part of the key.

    ``customer`` is the bank's own id for the account holder (what ``holds`` returns), never text from the
    mandate, so two mandates of one customer share one id space. JCS of [customer, id]: unambiguous.
    """
    return canonicalize([customer, payment_id]).decode()


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

    def take(self, key: str, payment_hash: str, decision_id: str) -> bool:
        with self._lock:
            entry = self._items.get(key)
            if not entry or entry[0] != payment_hash or not isinstance(entry[1], dict) \
                    or entry[1].get("id") != decision_id:
                return False
            self._items[key] = (payment_hash, None)
            return True


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

    def reserve(self, key: str, period: str, amount: Decimal, limit: Decimal | None, at: datetime) -> bool:
        k = (key, period_key(period, at))
        with self._lock:
            total = self.totals.get(k, Decimal(0)) + amount
            if limit is not None and total > limit:
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


def _holds_id(decision: dict) -> bool:
    """Whether the payment log keeps this decision (and so the payment id): spec 7, "Idempotency"."""
    r = decision["reasons"]
    return decision["outcome"] == "allow" or (len(r) == 1 and (r[0] in HOLDS or r[0] == "blocked_by_override"))


def _pkey(p: dict) -> tuple[str, str]:
    return (p["id"], p["public_key"])


def _persons(v: Any) -> list[tuple[str, str]] | None:
    """A list of {id, public_key} as tuples, or None if it is not one."""
    if not isinstance(v, list) or not all(isinstance(x, dict) and set(x) == {"id", "public_key"}
                                          and all(isinstance(y, str) for y in x.values()) for x in v):
        return None
    return [_pkey(x) for x in v]


# ---------- checking ----------

@dataclass
class Checker:
    id: str
    sk: Ed25519PrivateKey
    authority: Authority
    # holds(company, account) -> the bank's customer id of the holder if this company holds this account at
    # this bank, else None. Required. The customer id keys the payment log.
    holds: Callable[[dict, dict], str | None] | None = None
    ledger: Ledger | None = None
    payments: PaymentLog = field(default_factory=InMemoryPaymentLog)
    revocations: list[dict] = field(default_factory=list)
    # revocation_feed() -> revocations from a signed, current revocation list (revocations_from_list); raises
    # when no current list is available. For checkers that learn revocations from someone else (spec 9.2).
    revocation_feed: Callable[[], list[dict]] | None = None
    # status(url) -> the signed status response (a dict); raises when unreachable.
    status: Callable[[str], Any] | None = None
    clock: Callable[[], datetime] = utcnow
    max_skew: timedelta = timedelta(seconds=60)
    status_max_age: timedelta = timedelta(minutes=5)
    override_window: timedelta = timedelta(hours=72)
    officers: Iterable[str] = ()  # public keys of bank staff who may sign overrides
    require_payees: bool = False  # policy: block mandates without a payee list (payees_required)
    webauthn: dict = field(default_factory=dict)  # {"rp_id": ..., "origins": [...]}

    @property
    def public_key(self) -> str:
        return public_key_of(self.sk)

    def _authorized(self, company: dict, person: dict, need_power: bool = True,
                    issued: str | None = None) -> AuthorityResult:
        """The source's answer for this person, checked against the key they used. Raises _Stop.

        ``issued``: when the object this key signed was issued; a retired key counts only for objects issued
        before its retirement. None: current keys only.
        """
        try:
            res = self.authority(company, person["id"])
        except Exception as e:  # noqa: BLE001
            raise _Stop("checker_unavailable") from e
        if res is None:
            raise _Stop("signer_unknown")
        if not isinstance(res, AuthorityResult) or type(res.joint) is not int or res.joint < 1 \
                or type(res.may_sign) is not bool or not isinstance(res.keys, (tuple, list)) \
                or not isinstance(res.retired, Mapping) or not (res.person is None or isinstance(res.person, str)):
            raise _Stop("checker_unavailable")
        key = person.get("public_key")
        ok = key in res.keys
        if not ok and issued is not None and key in res.retired:
            try:
                ok = _ts(issued) < _ts(res.retired[key])
            except ValueError as e:
                raise _Stop("checker_unavailable") from e
        if not ok or (need_power and not res.may_sign):
            raise _Stop("signer_not_authorized")
        return res

    def check(self, mandate: Any, payment: Any, payee_approvals: Any = None) -> dict[str, Any]:
        """Check one payment against one mandate. Never raises on input; always returns a signed decision.

        ``payee_approvals``: signed payee approvals that travel with the payment (spec 7.2), used for 0.5
        mandates only; a 0.4 mandate is checked exactly as in 0.4.
        """
        return self._checked(mandate, payment, lambda p_hash, at, checks, state: self._run(
            mandate, payment, p_hash, at, checks, state, approvals=payee_approvals))

    def resolve(self, mandate: Any, payment: Any, decision: Any, override: Any,
                payee_approvals: Any = None) -> dict[str, Any]:
        """Apply a signed override to one of this checker's escalate decisions (spec 7.1). Never raises on input.

        Returns the final decision (allow or block, signed, naming the escalation and the override), a later
        escalation if re-checking hit another one, or an escalate ``override_invalid`` / ``override_not_authorized``
        when the override does not count.
        """
        return self._checked(mandate, payment, lambda p_hash, at, checks, state: self._resolve(
            mandate, payment, decision, override, p_hash, at, checks, state, payee_approvals),
            resolving=(decision, override))

    def _checked(self, mandate: Any, payment: Any, run: Callable, resolving: tuple | None = None) -> dict[str, Any]:
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
            reason = run(p_hash, at, checks, state)
        except _Stop as s:
            reason = s.reason
        except Exception:  # noqa: BLE001 - last line of defence: unexpected input never allows
            reason = "payment_malformed"
        if isinstance(reason, dict):  # idempotent retry: the decision the log holds, unchanged
            return reason
        extra = dict(state.get("refs", {}))
        if "signers" in state:
            extra["signers"] = state["signers"]
        if reason == "signer_unknown" and state.get("unknown"):
            extra["unknown"] = [{"id": i, "public_key": k} for i, k in state["unknown"]]
        if "payee_approval" in state:
            extra["payee_approval"] = state["payee_approval"]
        d = self._decision(mandate, payment, p_hash, reason, checks, at, extra)
        if state.get("registered"):
            try:
                if _holds_id(d):
                    self.payments.remember(state["key"], d)
                elif "restore" in state and reason in RETRYABLE:
                    self.payments.remember(state["key"], state["restore"])  # the escalation still waits
                else:
                    self.payments.forget(state["key"])
            except Exception:  # noqa: BLE001 - the decision still stands; the log is the bank's to fix
                pass
        return d

    def _decision(self, m: Any, p: Any, p_hash: str | None, reason: str | None, checks: list[str],
                  at: datetime, extra: dict) -> dict[str, Any]:
        outcome = "allow" if reason is None else "escalate" if reason in ESCALATE else "block"
        pid = p.get("id") if isinstance(p, dict) and isinstance(p.get("id"), str) else None
        mid = m.get("id") if isinstance(m, dict) and isinstance(m.get("id"), str) else None
        mh = mandate_hash(m) if isinstance(m, dict) and _jcs_ok(m) else None
        ver = version_of(m, "mandate")  # a decision is in the draft of the mandate it is about
        d = {"v": f"gleipnir/decision/{ver}", "id": "d_" + secrets.token_hex(12),
             "payment": {"id": pid, "hash": p_hash}, "mandate": {"id": mid, "hash": mh},
             "outcome": outcome, "reasons": [reason] if reason else [], "checks": checks,
             "checked_at": fmt_ts(at), "checker": {"id": self.id, "public_key": self.public_key}, **extra}
        return _sign(self.sk, "decision", d, v=ver)

    def _person(self, company: dict, person: dict, need_power: bool, issued: str | None,
                vouched: frozenset, unknown: list) -> AuthorityResult | None:
        """_authorized, except for unknown people: None if a bank override vouched for exactly this person,
        else recorded in ``unknown`` and re-raised."""
        try:
            return self._authorized(company, person, need_power, issued)
        except _Stop as s:
            if s.reason == "signer_unknown":
                if _pkey(person) in vouched:
                    return None
                if _pkey(person) not in unknown:
                    unknown.append(_pkey(person))
            raise

    def _signers_ok(self, m: dict, sigs: list[tuple[dict, Any]], threshold: int, checks: list[str],
                    vouched: frozenset, state: dict) -> None:
        """Steps 10-12: every signer through authority separately, then threshold and joint. Raises _Stop."""
        counted: list[AuthorityResult] = []
        signers: list[dict] = []
        persons: set[str] = set()
        n_vouched = 0
        unknown: list = state.setdefault("unknown", [])
        for signer, _ in sigs:
            try:
                res = self._person(m["company"], signer, True, m["issued_at"], vouched, unknown)
            except _Stop as s:
                if s.reason != "signer_unknown":
                    raise
                continue
            who = "id:" + signer["id"] if res is None or res.person is None else "person:" + res.person
            if who in persons:  # one person counts once, whatever ids or keys they appear under
                continue
            persons.add(who)
            signers.append({"id": signer["id"], "public_key": signer["public_key"]})
            if res is None:
                n_vouched += 1  # unknown to every source, vouched for by a bank officer's override
            else:
                counted.append(res)
        needed = max([threshold] + [r.joint for r in counted])
        have = len(counted) + n_vouched
        if have < needed:
            if unknown:
                raise _Stop("signer_unknown")
            raise _Stop("joint_signature_required" if have >= threshold else "signature_threshold_not_met")
        checks.extend(f"signer_authorized:{r.source}" for r in counted)
        checks.extend(["signer_authorized:override"] * n_vouched)
        if "signers" in m:
            checks.append(f"signatures:{have}/{needed}")
        state["signers"] = signers

    def _chain_ok(self, m: dict, chain: list[dict], checks: list[str], vouched: frozenset,
                  state: dict) -> str | None:
        """Section 5, steps 3-4: authority per link and narrowing. Raises _Stop; returns a reason or None."""
        unknown: list = state.setdefault("unknown", [])
        people = [(chain[0]["from"], True, chain[0]["issued_at"])]
        # Each delegate's key is checked as of the object it signed next: the next link, or the mandate.
        people += [(d["to"], False, signed["issued_at"]) for d, signed in zip(chain, [*chain[1:], m], strict=True)]
        answers = []
        for person, power, issued in people:  # everyone, so an escalation names every unknown person
            try:
                answers.append(self._person(m["company"], person, power, issued, vouched, unknown))
            except _Stop as s:
                if s.reason != "signer_unknown":
                    raise
        if unknown:
            raise _Stop("signer_unknown")
        root = answers[0]
        if root is not None and root.joint > 1:
            raise _Stop("joint_signature_required")
        checks.extend([f"delegation:{len(chain)}", f"signer_authorized:{root.source if root else 'override'}"])
        for parent, child in zip(chain, [*chain[1:], m], strict=True):
            if not _within(child, parent):
                return "scope_exceeds_delegation"
        state["signers"] = [{"id": m["signer"]["id"], "public_key": m["signer"]["public_key"]}]
        return None

    def _authentic(self, m: Any, p: Any, p_hash: str | None, approvals: Any = None) -> str | None:
        """Steps 1-6: parse, then every signature on the objects themselves. No external system is asked."""
        if mandate_problem(m):
            return "mandate_malformed"
        if p_hash is None or payment_problem(p):
            return "payment_malformed"
        mv = version_of(m, "mandate")
        if mv == V5 and approvals is not None and _approvals_problem(approvals):
            return "payee_approval_invalid"  # step 2: every payee approval presented is well formed
        mh = mandate_hash(m)
        if p["mandate"]["hash"] != mh:
            return "mandate_mismatch"
        sigs, _ = _signatures(m)
        if not sigs or not all(_verify("mandate", mh, sig, s["public_key"], self.webauthn, mv) for s, sig in sigs):
            return "mandate_bad_signature"
        chain = m.get("delegation", [])
        if chain:
            bad = _chain_problem(m, chain, self.webauthn)
            if bad:
                return bad
        if "public_key" in m["agent"] and \
                not _verify("payment", p_hash, p.get("agent_sig"), m["agent"]["public_key"], self.webauthn):
            return "agent_bad_signature"
        return None

    def _run(self, m: Any, p: Any, p_hash: str | None, at: datetime, checks: list[str],
             state: dict[str, Any], waive: frozenset[str] = frozenset(), claimed: bool | None = None,
             vouched: frozenset = frozenset(), approvals: Any = None) -> str | dict | None:
        """The check (spec 7). ``claimed`` is set when resolving an override: True if this payment already holds
        its id, False if it must claim it; then the lookup and the clock-skew step are skipped."""
        bad = self._authentic(m, p, p_hash, approvals)
        if bad:
            return bad
        mh = mandate_hash(m)
        chain = m.get("delegation", [])
        bad, customer = self._held(m, chain, p["from_account"])
        if bad:
            return bad
        key = payment_key(customer, p["id"])
        state["key"] = key
        if claimed:  # the held escalation was taken over: whatever happens next must settle the claim
            state["registered"] = True
        if claimed is None:
            try:
                prior = self.payments.lookup(key, p_hash)
            except Exception:  # noqa: BLE001
                return "checker_unavailable"
            if isinstance(prior, dict):
                return prior  # idempotent retry, read-only, and only for an authentic payment
            if abs(_ts(p["requested_at"]) - at) > self.max_skew:
                return "clock_skew"
        checks.append("mandate_valid")
        if "public_key" in m["agent"]:
            checks.append("agent_signed")
        checks.append("account_held")
        sigs, threshold = _signatures(m)
        if chain:
            bad = self._chain_ok(m, chain, checks, vouched, state)
            if bad:
                return bad
        else:
            self._signers_ok(m, sigs, threshold, checks, vouched, state)
        # Authentic and authorized from here on: only now may the payment id be claimed (step 14).
        if not claimed:
            try:
                ok = self.payments.register(key, p_hash)
            except Exception:  # noqa: BLE001
                return "checker_unavailable"
            if ok is False:
                return "duplicate_payment"
            if ok is not True:  # a store that answers anything but True/False is broken: fail closed
                return "checker_unavailable"
            state["registered"] = True
        if "valid_from" in m and at < _ts(m["valid_from"]):
            return "mandate_not_yet_valid"
        if at > _ts(m["valid_until"]):
            return "mandate_expired"
        revoked = self._revoked(m, mh, chain, sigs, at, self.revocations)
        if revoked:
            return revoked
        known = list(self.revocations)  # the revocations this check relies on, for payee approvals too
        if self.revocation_feed is not None:
            try:
                fed = self.revocation_feed()
            except Exception:  # noqa: BLE001
                fed = None
            if isinstance(fed, list):
                known += fed
                revoked = self._revoked(m, mh, chain, sigs, at, fed)
                if revoked:
                    return revoked
                checks.append("revocation_list_current")
            elif "status_unavailable" in waive:
                checks.append("revocation_list_unavailable_approved")
            else:
                return "status_unavailable"
        if "status_url" in m:
            st = self._status(m, mh, chain, sigs, at)
            if st == "revoked":
                return "mandate_revoked"
            if st == "active":
                checks.append("status_active")
            elif "status_unavailable" in waive:
                checks.append("status_unavailable_approved")  # a bank officer confirmed it another way
            else:
                return "status_unavailable"
        checks.append("not_revoked")
        sc = m["scope"]
        fa = p["from_account"]
        if "rails" in sc and p["rail"] not in sc["rails"]:
            return "rail_not_allowed"
        if not rail_fits(p["rail"], p["currency"], [fa, p["payee"]["account"]]):
            return "rail_mismatch"
        if p["currency"] != sc["currency"]:
            return "currency_mismatch"
        amt = parse_amount(p["amount"], p["currency"])
        if version_of(m, "mandate") == V5:
            bad = self._payee(m, mh, chain, sigs, p, amt, at, checks, state, waive, approvals or [], known)
            if bad:
                return bad
        elif "payees" in sc:
            if _key(p["payee"]["account"]) not in {_key(x["account"]) for x in sc["payees"]}:
                return "payee_not_on_mandate"
            checks.append("payee_on_mandate")
        elif self.require_payees:
            return "payees_required"
        if amt > parse_amount(sc["max_per_payment"], sc["currency"]):
            if "over_payment_limit" not in waive:
                return "over_payment_limit"
            checks.append("over_payment_limit_approved")
        else:
            checks.append("within_payment_limit")
        # A bank officer's waiver lifts every period limit; the company's own signatories lift only the
        # mandate's: a delegated aggregate (a CEO's cap on a CFO) still binds them.
        force = "links" if "over_period_limit" in waive else "mandate" if "over_period_limit:mandate" in waive else ""
        return self._reserve(m, mh, chain, amt, at, checks, force=force)

    def _payee(self, m: dict, mh: str, chain: list[dict], sigs: list[tuple[dict, Any]], p: dict, amt: Decimal,
               at: datetime, checks: list[str], state: dict, waive: frozenset[str], approvals: list[dict],
               revocations: list[dict]) -> str | None:
        """Step 21 for a 0.5 mandate (spec 7): a listed or approved payee account passes; a listed payee's name
        with another account blocks; any other payee follows the mandate's unlisted_payees."""
        sc = m["scope"]
        acc = p["payee"]["account"]
        listed = sc.get("payees", [])
        if _key(acc) in {_key(x["account"]) for x in listed}:
            checks.append("payee_on_mandate")
            return None
        policy = sc.get("unlisted_payees")
        if "payees" not in sc and policy is None:  # no payee control at all: as in 0.4
            return "payees_required" if self.require_payees else None
        if self._approved(m, mh, chain, sigs, acc, at, checks, state, approvals, revocations):
            return None
        name = payee_name_key(p["payee"].get("name"))
        if name and any(payee_name_key(x.get("name")) == name for x in listed):
            return "payee_account_changed"  # "we changed our bank details": never escalated, never waived
        if policy != "escalate":
            return "payee_not_on_mandate"
        if "max_per_unlisted_payee" in sc:
            if amt > parse_amount(sc["max_per_unlisted_payee"], sc["currency"]):
                return "over_unlisted_payee_limit"
            checks.append("within_unlisted_payee_limit")
        if "new_payee" not in waive:
            return "new_payee"
        checks.append("new_payee_approved")
        return None

    def _approved(self, m: dict, mh: str, chain: list[dict], sigs: list[tuple[dict, Any]], acc: dict,
                  at: datetime, checks: list[str], state: dict, approvals: list[dict],
                  revocations: list[dict]) -> bool:
        """Spec 7.2: whether a payee approval presented with the payment makes this payee account count as listed.
        Only approvals of this mandate (id and hash) for exactly this account are looked at, in the order given.
        One that is badly signed, dated ahead or before the mandate's ``issued_at``, outside a delegation link's
        payee list, or not signed by enough people who may sign blocks (``payee_approval_invalid``); a revoked or
        expired one does not count."""
        for a in approvals:
            if a["mandate"] != {"id": m["id"], "hash": mh} or _key(a["payee"]["account"]) != _key(acc):
                continue
            ah = payee_approval_hash(a)
            if not all(_verify("payee_approval", ah, s["sig"], s["signer"]["public_key"], self.webauthn, V5)
                       for s in a["sigs"]):
                raise _Stop("payee_approval_invalid")
            if _ts(a["approved_at"]) > at + self.max_skew:
                raise _Stop("payee_approval_invalid")
            if _ts(a["approved_at"]) < _ts(m["issued_at"]):  # cannot predate the mandate whose hash it names
                raise _Stop("payee_approval_invalid")
            for d in chain:  # an approval cannot add a payee a delegator's payee list excludes
                if "payees" in d["scope"] and _key(acc) not in {_key(x["account"]) for x in d["scope"]["payees"]}:
                    raise _Stop("payee_approval_invalid")
            if self._approval_revoked(m, mh, chain, sigs, a, ah, at, revocations):
                checks.append("payee_approval_revoked")
                continue
            if "valid_until" in a and at > _ts(a["valid_until"]):
                checks.append("payee_approval_expired")
                continue
            approvers, needed = self._company_signers(m, a["sigs"], a["approved_at"], "payee_approval_invalid")
            checks.append(f"payee_approved:{len(approvers)}/{needed}")
            state["payee_approval"] = {"id": a["id"], "hash": ah,
                                       "approvers": [{"id": x["id"], "public_key": x["public_key"]}
                                                     for x in approvers]}
            return True
        return False

    def _approval_revoked(self, m: dict, mh: str, chain: list[dict], sigs: list[tuple[dict, Any]], a: dict,
                          ah: str, at: datetime, revocations: list[dict]) -> bool:
        """A valid revocation of this payee approval (by its hash), effective now, by someone who may revoke the
        mandate or who signed the approval."""
        parties = self._parties(chain, sigs)[0] | {_pkey(s["signer"]) for s in a["sigs"]}
        for r in revocations:
            if revocation_problem(r) or r.get("payee_approval_hash") != ah or _ts(r["revoked_at"]) > at:
                continue
            if not _verify("revocation", obj_hash(r), r.get("sig"), r["signer"]["public_key"], self.webauthn,
                           version_of(r, "revocation")):
                continue
            if self._may_revoke(m, r["signer"], parties, r["revoked_at"]):
                return True
        return False

    def _held(self, m: dict, chain: list[dict], fa: dict) -> tuple[str, str]:
        """Step 7: the debtor account is on the mandate and the bank holds it for this company; with a period
        limit (a period limit is one bank's ledger, so it cannot span banks), the bank holds every account the
        limited object lists, for the same customer. Returns ("", customer id) or (reason, "")."""
        if _key(fa) not in {_key(a) for a in m["scope"]["from_accounts"]}:
            return "account_not_on_mandate", ""
        if self.holds is None:
            return "checker_unavailable", ""
        wanted = [fa]
        for obj in [m, *chain]:
            if "max_per_period" in obj["scope"]:
                wanted += obj["scope"]["from_accounts"]
        customers: set[str] = set()
        seen: set[bytes] = set()
        for acc in wanted:
            if _key(acc) in seen:
                continue
            seen.add(_key(acc))
            try:
                c = self.holds(m["company"], acc)
            except Exception:  # noqa: BLE001
                return "checker_unavailable", ""
            if c is None or c is False:
                return "account_not_held", ""
            if not isinstance(c, str) or not c:
                return "checker_unavailable", ""
            customers.add(c)
        if len(customers) != 1:
            return "account_not_held", ""
        return "", customers.pop()

    def _reserve(self, m: dict, mh: str, chain: list[dict], amt: Decimal, at: datetime,
                 checks: list[str], force: str = "") -> str | None:
        """Step 23: reserve the amount against the mandate's period limit and against every delegation link's
        own period limit (a link's limit is shared by all mandates under it), all or nothing. ``force``: an
        override approved going over ("mandate": the mandate's own limit; "links": every limit), so the amount
        is added without that limit and the totals stay true."""
        wanted = [(f"mandate:{mh}", m["scope"], bool(force))] if "max_per_period" in m["scope"] else []
        wanted += [(f"delegation:{delegation_hash(d)}", d["scope"], force == "links")
                   for d in chain if "max_per_period" in d["scope"]]
        if not wanted:
            return None
        if self.ledger is None:
            return "ledger_missing"
        done: list[tuple[str, str]] = []
        try:
            for key, sc, forced in wanted:
                per = sc["max_per_period"]
                limit = None if forced else parse_amount(per["amount"], sc["currency"])
                ok = self.ledger.reserve(key, per["period"], amt, limit, at)
                if ok is not True:  # False: over the limit; anything else: a broken ledger, fail closed
                    self._release(done, amt, at)
                    return "over_period_limit" if ok is False else "checker_unavailable"
                done.append((key, per["period"]))
        except Exception:  # noqa: BLE001
            self._release(done, amt, at)
            return "checker_unavailable"
        checks.append("over_period_limit_approved" if force else "within_period_limit")
        return None

    def _release(self, done: list[tuple[str, str]], amt: Decimal, at: datetime) -> None:
        for key, period in done:
            try:
                self.ledger.release(key, period, amt, at)  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001, S110 - best effort; the bank reconciles its ledger
                pass

    @staticmethod
    def _parties(chain: list[dict], sigs: list[tuple[dict, Any]]) -> tuple[set, dict]:
        def people(links: list[dict]) -> set[tuple[str, str]]:
            out: set[tuple[str, str]] = set()
            for d in links:
                out |= {(d["from"]["id"], d["from"]["public_key"]), (d["to"]["id"], d["to"]["public_key"])}
            return out
        # The line of authority of each target: the mandate's own signers and its whole chain; for a link,
        # that link and the links above it (a delegate below cannot cut their delegator's authority).
        mandate_parties = {(s["id"], s["public_key"]) for s, _ in sigs} | people(chain)
        link_parties = {delegation_hash(d): people(chain[: i + 1]) for i, d in enumerate(chain)}
        return mandate_parties, link_parties

    def _may_revoke(self, m: dict, signer: dict, parties: set, issued: str | None) -> bool:
        """Known with that key, and either may sign for the company or is in the line of authority. Raises
        _Stop("checker_unavailable") if the source is down; any other refusal is False."""
        try:
            res = self._authorized(m["company"], signer, need_power=False, issued=issued)
        except _Stop as s:
            if s.reason == "checker_unavailable":
                raise
            return False
        return res.may_sign or (signer["id"], signer["public_key"]) in parties

    def revocation_counts(self, mandate: Any, revocation: Any, payee_approval: Any = None) -> bool:
        """Whether this revocation would switch off this mandate (or a link of its chain, or, given the approval,
        one of its payee approvals) now: well formed, validly signed, aimed at it, by someone who may revoke it
        (section 9). For a store that accepts revocations from outside: keep only those that count, so nobody can
        fill it with junk. Raises nothing; a source that is down gives False."""
        try:
            if mandate_problem(mandate) or revocation_problem(revocation):
                return False
            sigs, _ = _signatures(mandate)
            chain = mandate.get("delegation", [])
            mandate_parties, link_parties = self._parties(chain, sigs)
            r = revocation
            if "mandate_hash" in r:
                if r["mandate_hash"] != mandate_hash(mandate):
                    return False
                parties = mandate_parties
            elif r.get("delegation_hash") in link_parties:
                parties = link_parties[r["delegation_hash"]]
            elif "payee_approval_hash" in r:
                a = payee_approval
                if version_of(mandate, "mandate") != V5 or payee_approval_problem(a) \
                        or a["mandate"] != {"id": mandate["id"], "hash": mandate_hash(mandate)} \
                        or r["payee_approval_hash"] != payee_approval_hash(a):
                    return False
                parties = mandate_parties | {_pkey(s["signer"]) for s in a["sigs"]}
            else:
                return False
            if not _verify("revocation", obj_hash(r), r.get("sig"), r["signer"]["public_key"], self.webauthn,
                           version_of(r, "revocation")):
                return False
            return self._may_revoke(mandate, r["signer"], parties, r["revoked_at"])
        except Exception:  # noqa: BLE001
            return False

    def _revoked(self, m: dict, mh: str, chain: list[dict], sigs: list[tuple[dict, Any]], at: datetime,
                 revocations: list[dict]) -> str | None:
        """Section 9: a valid revocation of the mandate or of any delegation link, by an allowed person.

        One signatory of a jointly signed mandate may revoke it alone: switching off needs no co-signer.
        """
        mandate_parties, link_parties = self._parties(chain, sigs)
        for r in revocations:
            if revocation_problem(r) or _ts(r["revoked_at"]) > at:
                continue
            if "mandate_hash" in r:
                if r["mandate_hash"] != mh:
                    continue
                reason, parties = "mandate_revoked", mandate_parties
            elif r.get("delegation_hash") in link_parties:
                reason, parties = "delegation_revoked", link_parties[r["delegation_hash"]]
            else:  # another mandate's link, or a payee approval (step 21)
                continue
            if not _verify("revocation", obj_hash(r), r.get("sig"), r["signer"]["public_key"], self.webauthn,
                           version_of(r, "revocation")):
                continue
            if self._may_revoke(m, r["signer"], parties, r["revoked_at"]):
                return reason
        return None

    def _status(self, m: dict, mh: str, chain: list[dict], sigs: list[tuple[dict, Any]], at: datetime) -> str | None:
        """Step 17: "active" or "revoked" from a valid, fresh status response signed by someone who could revoke
        the mandate; None if there is no such answer."""
        if self.status is None:
            return None
        try:
            s = self.status(m["status_url"])
        except Exception:  # noqa: BLE001
            return None
        if status_problem(s) or s["mandate"] != {"id": m["id"], "hash": mh}:
            return None
        t = _ts(s["at"])
        if t > at + self.max_skew or at - t > self.status_max_age:
            return None
        if not _verify("status", obj_hash(s), s.get("sig"), s["signer"]["public_key"], self.webauthn):
            return None
        mandate_parties, _ = self._parties(chain, sigs)
        if not self._may_revoke(m, s["signer"], mandate_parties, None):
            return None
        return s["status"]

    def _resolve(self, m: Any, p: Any, d: Any, o: Any, p_hash: str | None, at: datetime, checks: list[str],
                 state: dict[str, Any], approvals: Any = None) -> str | dict | None:
        bad = self._authentic(m, p, p_hash, approvals)
        if bad:
            return bad
        mh = mandate_hash(m)
        if override_problem(o) or not verify_decision(d, [self.public_key]) or d.get("outcome") != "escalate" \
                or not isinstance(d.get("reasons"), list) or len(d["reasons"]) != 1 \
                or d.get("payment") != {"id": p["id"], "hash": p_hash} or _get(d, "mandate.hash") != mh \
                or o["decision"] != {"id": d.get("id"), "hash": obj_hash(d)}:
            return "override_invalid"
        # The window runs from the first escalation of this payment, however many overrides follow.
        first = d.get("escalated_at", d["checked_at"])
        earlier, vouched_before = d.get("waived", []), _persons(d.get("vouched", []))
        unknown = _persons(d.get("unknown", []))
        if not isinstance(earlier, list) or not all(isinstance(x, str) for x in earlier) \
                or vouched_before is None or unknown is None:
            return "override_invalid"
        try:
            escalated, decided = _ts(first), _ts(o["decided_at"])
        except ValueError:
            return "override_invalid"
        if at - escalated > self.override_window or decided < _ts(d["checked_at"]) or decided > at + self.max_skew:
            return "override_invalid"
        oh = override_hash(o)
        if not all(_verify("override", oh, s["sig"], s["signer"]["public_key"], self.webauthn) for s in o["sigs"]):
            return "override_invalid"
        reason = d["reasons"][0]
        if reason in NOT_OVERRIDABLE:
            return "override_not_authorized"
        officers = set(self.officers)
        bank_sigs = [s for s in o["sigs"] if s["signer"]["public_key"] in officers]
        if bank_sigs:
            who, waiver = "override:bank", reason
            approvers = [{**s["signer"], "role": "bank"} for s in bank_sigs]
        elif reason in COMPANY_OVERRIDABLE:
            who, approvers = self._company_override(m, o)
            waiver = "over_period_limit:mandate" if reason == "over_period_limit" else reason
        else:
            return "override_not_authorized"
        # Overrides add up: a re-check after one override can escalate again, and the next override keeps the
        # earlier waivers (recorded in the escalation this checker signed). A signer_unknown waiver vouches
        # only for the people that escalation named.
        waive = frozenset({*earlier, waiver})
        vouched = frozenset({*vouched_before, *(unknown if reason == "signer_unknown" else [])})
        state["refs"] = {"escalation": {"id": d["id"], "hash": obj_hash(d)}, "override": {"id": o["id"], "hash": oh},
                         "approvers": [{k: a[k] for k in ("id", "public_key", "role")} for a in approvers],
                         "waived": sorted(waive), "escalated_at": first}
        if vouched:
            state["refs"]["vouched"] = [{"id": i, "public_key": k} for i, k in sorted(vouched)]
        checks.append(who)
        bad, customer = self._held(m, m.get("delegation", []), p["from_account"])
        if bad:
            return bad
        key = payment_key(customer, p["id"])
        try:
            prior = self.payments.lookup(key, p_hash)
        except Exception:  # noqa: BLE001
            return "checker_unavailable"
        held = isinstance(prior, dict) and prior.get("id") == d["id"]
        if isinstance(prior, dict) and not held:
            return prior  # already resolved: the same answer again, never a second reservation
        if held:
            try:
                took = self.payments.take(key, p_hash, d["id"])
            except Exception:  # noqa: BLE001
                return "checker_unavailable"
            if took is not True and took is not False:
                return "checker_unavailable"
            if not took:  # another override of this escalation got there first
                try:
                    again = self.payments.lookup(key, p_hash)
                except Exception:  # noqa: BLE001
                    return "checker_unavailable"
                return again if isinstance(again, dict) else "duplicate_payment"
            state["restore"] = d
        if o["outcome"] == "block":
            if not held:
                try:
                    ok = self.payments.register(key, p_hash)
                except Exception:  # noqa: BLE001
                    return "checker_unavailable"
                if ok is not True:
                    return "duplicate_payment" if ok is False else "checker_unavailable"
            state["registered"], state["key"] = True, key
            return "blocked_by_override"
        return self._run(m, p, p_hash, at, checks, state, waive=waive, claimed=held, vouched=vouched,
                         approvals=approvals)

    def _company_override(self, m: dict, o: dict) -> tuple[str, list[dict]]:
        """Company signatories resolving an over-limit or new-payee escalation (spec 7.1). Raises _Stop."""
        approvers, needed = self._company_signers(m, o["sigs"], None, "override_not_authorized")
        return f"override:company:{len(approvers)}/{needed}", [{**a, "role": "company"} for a in approvers]

    def _company_signers(self, m: dict, osigs: list[dict], issued: str | None, refused: str) -> tuple[list[dict], int]:
        """The company's own people signing an override or a payee approval: as many authorized people as the
        mandate itself needed (its threshold and the joint rule of everyone who signed it or this object), each
        counted once. ``issued``: when they signed, for retired keys (None: current keys only). Raises
        _Stop(refused), or _Stop("checker_unavailable") if the source is down."""
        sigs, threshold = _signatures(m)
        joints = [threshold]
        for signer, _ in sigs:  # what the mandate needed: its signers' joint rules, as the bank knows them now
            try:
                joints.append(self._authorized(m["company"], signer, True, m["issued_at"]).joint)
            except _Stop as e:
                if e.reason == "checker_unavailable":
                    raise
        persons: set[str] = set()
        approvers: list[dict] = []
        for s in osigs:
            try:
                res = self._authorized(m["company"], s["signer"], need_power=True, issued=issued)
            except _Stop as e:
                if e.reason == "checker_unavailable":
                    raise
                raise _Stop(refused) from e
            who = "person:" + res.person if res.person is not None else "id:" + s["signer"]["id"]
            if who in persons:
                continue
            persons.add(who)
            joints.append(res.joint)
            approvers.append(dict(s["signer"]))
        needed = max(joints)
        if len(approvers) < needed:
            raise _Stop(refused)
        return approvers, needed


def keyset(checker_id: str, keys: Iterable[dict], issued_at: str | None = None) -> dict[str, Any]:
    """The bank's published checker keys (spec 10.1), served at /.well-known/gleipnir-checker.json. Each key:
    {"public_key", "from"?, "until"?, "compromised"?}. Keys are never removed, only given an ``until``."""
    ks = {"v": f"gleipnir/keys/{V}", "checker": checker_id, "issued_at": issued_at or now(), "keys": list(keys)}
    problem = keyset_problem(ks)
    if problem:
        raise ValueError(problem)
    return ks


def keyset_problem(ks: Any) -> str | None:
    if not isinstance(ks, dict) or ks.get("v") != f"gleipnir/keys/{V}":
        return "unknown key set version"
    bad = _str_fields(ks, ("checker", "issued_at"))
    if bad or not _jcs_ok(ks):
        return bad or "key set is not valid I-JSON"
    if set(ks) - {"v", "checker", "issued_at", "keys"}:
        return f"unknown field {sorted(set(ks) - {'v', 'checker', 'issued_at', 'keys'})[0]}"
    keys = ks.get("keys")
    if not isinstance(keys, list) or not keys:
        return "keys must be a non-empty list"
    for k in keys:
        if not isinstance(k, dict) or not isinstance(k.get("public_key"), str) or set(k) - {
                "public_key", "from", "until", "compromised"}:
            return "every key needs public_key, and only from, until, compromised besides"
        if "compromised" in k and type(k["compromised"]) is not bool:
            return "compromised must be true or false"
        try:
            for f in ("from", "until"):
                if f in k:
                    _ts(k[f])
            if "from" in k and "until" in k and _ts(k["from"]) >= _ts(k["until"]):
                return "a key's from must be before its until"
        except ValueError as e:
            return str(e)
    if len({k["public_key"] for k in keys}) != len(keys):
        return "a key is listed twice"
    try:
        _ts(ks["issued_at"])
    except ValueError as e:
        return str(e)
    return None


def _key_valid(ks: dict, pub: str, at: str | datetime) -> bool:
    """The key set lists this key, not compromised, and ``at`` falls in its [from, until) window."""
    for k in ks["keys"]:
        if k["public_key"] == pub:
            if k.get("compromised"):
                return False
            t = at if isinstance(at, datetime) else _ts(at)
            return ("from" not in k or _ts(k["from"]) <= t) and ("until" not in k or t < _ts(k["until"]))
    return False


def verify_decision(decision: Any, checker_keys: Iterable[str] | dict) -> bool:
    """True if the decision was signed by one of the bank's known checker keys and not changed since.

    ``checker_keys`` come from the bank, never from the decision itself: a list of public keys, or the bank's
    key set (spec 10.1), in which case the decision must name that checker and fall in the key's window.
    """
    try:
        pub_text = decision["checker"]["public_key"]
        if isinstance(checker_keys, dict):
            if keyset_problem(checker_keys) or decision["checker"].get("id") != checker_keys["checker"] \
                    or not _key_valid(checker_keys, pub_text, decision["checked_at"]):
                return False
        elif pub_text not in set(checker_keys):
            return False
        return verify_signature(decode_public_key(pub_text),
                                message("decision", obj_hash(decision), version_of(decision, "decision")),
                                decision.get("sig"))
    except Exception:  # noqa: BLE001
        return False


def revocation_list(revocations: Iterable[dict], *, issuer: str, sk: Ed25519PrivateKey, next_update: str,
                    issued_at: str | None = None) -> dict[str, Any]:
    """A signed list of the revocations a checker knows (spec 9.2), for checkers that are not told directly.
    Signed with the issuer's checker key; consumers still verify every revocation in it on every payment."""
    doc = {"v": f"gleipnir/revocations/{V}", "issuer": {"id": issuer, "public_key": public_key_of(sk)},
           "issued_at": issued_at or now(), "next_update": next_update, "revocations": list(revocations)}
    return _sign(sk, "revocations", doc)


def revocation_list_problem(doc: Any) -> str | None:
    if not isinstance(doc, dict) or doc.get("v") != f"gleipnir/revocations/{V}":
        return "unknown revocation list version"
    bad = _str_fields(doc, ("issuer.id", "issuer.public_key", "issued_at", "next_update"))
    if bad or not _jcs_ok(doc):
        return bad or "revocation list is not valid I-JSON"
    if set(doc) - {"v", "issuer", "issued_at", "next_update", "revocations", "sig"} or set(doc["issuer"]) - {
            "id", "public_key"}:
        return "unknown field in revocation list"
    if not isinstance(doc.get("revocations"), list):
        return "revocations must be a list"
    try:
        if _ts(doc["next_update"]) <= _ts(doc["issued_at"]):
            return "next_update must be after issued_at"
    except ValueError as e:
        return str(e)
    return None


MAX_REVOCATION_LIST_AGE = timedelta(hours=24)


def revocations_from_list(doc: Any, issuer_keys: Iterable[str] | dict, at: datetime) -> list[dict]:
    """The revocations of a current, validly signed list from a trusted issuer, else ValueError (spec 9.2).

    ``issuer_keys``: the issuer's checker keys or key set, obtained out of band. Current means issued no later
    than ``at`` (plus a minute) and ``at`` before ``next_update``: a stale list does not count, so an attacker
    cannot keep a checker on an old list that predates a revocation. A list is current for at most
    ``MAX_REVOCATION_LIST_AGE``, and with a key set the issuer's key must be valid both when the list was issued
    and now, so a retired or leaked key cannot sign a list that stays current for years.
    """
    problem = revocation_list_problem(doc)
    if problem:
        raise ValueError(problem)
    pub = doc["issuer"]["public_key"]
    if isinstance(issuer_keys, dict):
        if keyset_problem(issuer_keys) or issuer_keys["checker"] != doc["issuer"]["id"] \
                or not _key_valid(issuer_keys, pub, doc["issued_at"]) \
                or not _key_valid(issuer_keys, pub, at):
            raise ValueError("revocation list issuer key not trusted")
    elif pub not in set(issuer_keys):
        raise ValueError("revocation list issuer key not trusted")
    if not _verify("revocations", obj_hash(doc), doc.get("sig"), pub, {}):
        raise ValueError("revocation list signature is invalid")
    if _ts(doc["issued_at"]) > at + timedelta(seconds=60) or at >= _ts(doc["next_update"]):
        raise ValueError("revocation list is not current")
    if _ts(doc["next_update"]) - _ts(doc["issued_at"]) > MAX_REVOCATION_LIST_AGE:
        raise ValueError("revocation list is current for longer than 24 hours")
    return [r for r in doc["revocations"] if isinstance(r, dict)]


def verify_receipt(mandate: Any, payment: Any, decision: Any, checker_keys: Iterable[str] | dict, *,
                   override: Any = None, webauthn: dict | None = None,
                   payee_approvals: Iterable[Any] = ()) -> dict[str, Any]:
    """Check a receipt offline, months later, without the bank: who authorized this payment, what was decided.

    Verifies the decision against the bank's known keys, that it names exactly this mandate and payment, and
    every signature in the mandate, its delegation chain and the payment. A decision made on an override also
    needs that override: its hash must match and its signatures must be valid. It cannot re-run the bank's
    authority check; the decision's ``signer_authorized:<source>`` and ``override:<who>`` checks record what the
    bank relied on.

    For mandates signed with a passkey, pass the bank's passkey settings (``{"rp_id": ..., "origins": [...]}``);
    without them a passkey signature cannot be checked and the receipt reports ``mandate_bad_signature``.

    A 0.5 decision that relied on a payee approval names it (``payee_approval``); pass the approvals that
    travelled with the payment, and the receipt checks that one: same hash, this mandate, this payee account,
    and a valid signature by everyone the bank recorded as approving it (``payee_approved_by``).
    """
    wa = webauthn or {}
    problems: list[str] = []
    signed_by: list[str] = []
    chain_view: list[str] = []
    approved_by: list[str] = []
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
        valid = [s for s, sig in sigs if _verify("mandate", mh, sig, s["public_key"], wa,
                                                 version_of(mandate, "mandate"))]
        signed_by = [s["id"] for s in valid]
        if not sigs or len(valid) != len(sigs):
            problems.append("mandate_bad_signature")
        counted = _persons(_get(decision, "signers")) if _get(decision, "signers") is not None else None
        if _get(decision, "signers") is not None:
            # The bank recorded whom it counted; the receipt shows exactly those, each with a valid signature here.
            if counted is None or not set(counted) <= {_pkey(s) for s in valid}:
                problems.append("mandate_signers_mismatch")
            else:
                signed_by = [i for i, _ in counted]
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
    ref = _get(decision, "override")
    if ref is not None or override is not None:
        if override is None:
            problems.append("override_missing")
        elif override_problem(override) or not isinstance(ref, dict) \
                or ref != {"id": override["id"], "hash": override_hash(override)} \
                or override["decision"] != _get(decision, "escalation"):
            problems.append("override_mismatch")
        else:
            oh = override_hash(override)
            valid = {_pkey(s["signer"]) for s in override["sigs"]
                     if _verify("override", oh, s["sig"], s["signer"]["public_key"], wa)}
            approvers = _get(decision, "approvers")
            listed = _persons([{"id": a.get("id"), "public_key": a.get("public_key")} for a in approvers]) \
                if isinstance(approvers, list) and all(isinstance(a, dict) for a in approvers) else None
            # Who approved is what the bank recorded, each with a valid signature on this override.
            if listed is None or not listed or not set(listed) <= valid:
                problems.append("override_bad_signature")
            else:
                approved_by = [a["id"] for a in approvers]
    approved_payee_by: list[str] = []
    ref = _get(decision, "payee_approval")
    if ref is not None:
        found = [a for a in payee_approvals if isinstance(a, dict) and payee_approval_problem(a) is None
                 and isinstance(ref, dict) and ref.get("id") == a["id"] and ref.get("hash") == payee_approval_hash(a)]
        if not found:
            problems.append("payee_approval_missing")
        else:
            a = found[0]
            if a["mandate"] != _get(decision, "mandate") or payment_problem(payment) \
                    or _key(a["payee"]["account"]) != _key(payment["payee"]["account"]):
                problems.append("payee_approval_mismatch")
            ah = payee_approval_hash(a)
            valid = {_pkey(s["signer"]) for s in a["sigs"]
                     if _verify("payee_approval", ah, s["sig"], s["signer"]["public_key"], wa, V5)}
            listed = _persons(ref.get("approvers"))
            if not listed or not set(listed) <= valid:
                problems.append("payee_approval_bad_signature")
            else:
                approved_payee_by = [i for i, _ in listed]
    checks = _get(decision, "checks")
    authority = [c for c in checks if isinstance(c, str) and c.startswith(("signer_authorized:", "override:"))] \
        if isinstance(checks, list) else []
    extra = {"payee_approved_by": approved_payee_by} if version_of(decision, "decision") == V5 else {}
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
        "approved_by": approved_by,
        "payment": {"id": _get(payment, "id"), "amount": _get(payment, "amount"),
                    "currency": _get(payment, "currency"), "from": _get(payment, "from_account"),
                    "payee": _get(payment, "payee.account")},
        **extra,
    }
