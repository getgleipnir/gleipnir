"""Conformance vectors for mandate checking, shared by the Python reference and the TypeScript port.

    uv run python python/gleipnir-verify/tests/mandate_vectors.py   # rewrites the fixture

Keys come from fixed seeds (test keys only), clocks are fixed, so the file is stable. Decision ids are
random, so a vector pins everything in a decision except ``id`` and ``sig``; ``signed`` holds complete
decisions signed by the Python reference for verify_decision() checks.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gleipnir_verify import mandate as M

OUT = Path(__file__).resolve().parents[3] / "typescript/packages/verify/test/fixtures/mandate-vectors.json"


def key(n: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)


SIGNER, AGENT, BANK, OTHER = key(1), key(2), key(3), key(4)
NOW = "2026-10-23T09:14:02.000Z"
COMPANY = {"name": "Nordhafen Logistik GmbH", "country": "AT"}
SIGNER_ID = "kberger@nordhafen.at"
BRENNER = {"name": "Brenner Stahl AG", "account": {"iban": "AT611904300234573201"}}
KYB = [{"company": COMPANY["name"], "signer": SIGNER_ID, "source": "bank_kyb",
        "keys": [M.public_key_of(SIGNER)], "may_sign": True}]


def signer(sk: Ed25519PrivateKey = SIGNER, sid: str = SIGNER_ID) -> dict[str, Any]:
    return {"id": sid, "name": "K. Berger", "role": "Prokurist", "public_key": M.public_key_of(sk)}


def scope(**kw: Any) -> dict[str, Any]:
    s = {"rails": ["sepa", "sepa_instant"], "currency": "EUR", "max_per_payment": "25000.00",
         "max_per_period": {"amount": "40000.00", "period": "P1M"}, "payees": [BRENNER]}
    s.update(kw)
    return {k: v for k, v in s.items() if v is not None}


def mandate(sk: Ed25519PrivateKey = SIGNER, sign: bool = True, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"v": "gleipnir/mandate/0.1", "id": "m_vec", "company": COMPANY,
                            "agent": {"id": "ap-agent", "public_key": M.public_key_of(AGENT)},
                            "signer": signer(sk), "scope": scope(), "valid_until": "2026-12-31T23:59:59.000Z",
                            "issued_at": "2026-10-01T08:00:00.000Z"}
    base.update(kw)
    base = {k: v for k, v in base.items() if v is not None}
    return M.sign_mandate(base, sk) if sign else base


def pay(m: dict, pid: str, amount: str = "100.00", *, payee: dict = BRENNER, rail: str = "sepa",
        currency: str = "EUR", agent: Ed25519PrivateKey | None = AGENT, at: str = NOW) -> dict[str, Any]:
    return M.attach(m, id=pid, rail=rail, amount=amount, currency=currency, payee=payee,
                    reference="INV-1", agent_sk=agent, requested_at=at)


def case(name: str, m: Any, payments: list[Any], *, now: str | list[str] = NOW, authority: list | None = None,
         revocations: list | None = None, status: str | None = None, ledger: bool = True) -> dict[str, Any]:
    return {"name": name, "mandate": m, "payments": payments,
            "now": now if isinstance(now, list) else [now] * len(payments),
            "authority": KYB if authority is None else authority, "revocations": revocations or [],
            "status": status, "ledger": ledger}


def cases() -> list[dict[str, Any]]:
    m = mandate()
    tampered = {**m, "scope": scope(max_per_payment="99999.00")}
    rev = M.revoke(m, signer=signer(), sk=SIGNER, id="r_1", revoked_at="2026-10-22T00:00:00.000Z")
    rev_other = M.revoke(m, signer=signer(OTHER, "intern@nordhafen.at"), sk=OTHER, id="r_2",
                         revoked_at="2026-10-22T00:00:00.000Z")
    rev_later = M.revoke(m, signer=signer(), sk=SIGNER, id="r_3", revoked_at="2026-10-24T00:00:00.000Z")
    weekly = mandate(scope=scope(max_per_period={"amount": "150.00", "period": "P7D"}))
    jpy = mandate(scope=scope(currency="JPY", max_per_payment="500000", max_per_period=None))
    no_agent_key = mandate(agent={"id": "ap-agent"})
    status_m = mandate(status_url="https://bank.example/mandates/m_vec")
    other_payee = {"name": "Brenner Stahl AG", "account": {"iban": "LT121000011101001000"}}
    bad_sig_payment = {**pay(m, "p_1"), "amount": "200.00"}
    us = mandate(scope=scope(rails=["ach"], currency="USD", max_per_period=None,
                             payees=[{"name": "Acme", "account": {"routing": "021000021", "account": "123456789"}}]))
    return [
        case("allow", m, [pay(m, "p_1", "18400.00")]),
        case("payee_not_on_mandate", m, [pay(m, "p_1", payee=other_payee)]),
        case("iban_spaces_and_case_allowed", m,
             [pay(m, "p_1", payee={"name": "x", "account": {"iban": "at61 1904 3002 3457 3201"}})]),
        case("over_payment_limit", m, [pay(m, "p_1", "25000.01")]),
        case("period_limit_and_retry", m, [pay(m, "p_1", "20000.00"), pay(m, "p_2", "20000.00"),
                                            pay(m, "p_3", "0.01"), pay(m, "p_1", "20000.00")]),
        case("duplicate_id_changed_payment", m, [pay(m, "p_1"), pay(m, "p_1", "1.00")]),
        case("weekly_period_resets_on_monday", weekly,
             [pay(weekly, "p_1", "100.00", at="2026-10-25T23:59:30.000Z"),
              pay(weekly, "p_2", "100.00", at="2026-10-25T23:59:40.000Z"),
              pay(weekly, "p_3", "100.00", at="2026-10-26T00:00:10.000Z")],
             now=["2026-10-25T23:59:30.000Z", "2026-10-25T23:59:40.000Z", "2026-10-26T00:00:10.000Z"]),
        case("ledger_missing", m, [pay(m, "p_1")], ledger=False),
        case("jpy_integer_amounts", jpy, [pay(jpy, "p_1", "120000", currency="JPY"),
                                          pay(jpy, "p_2", "1200.50", currency="JPY")]),
        case("us_account_fields", us, [pay(us, "p_1", "10.00", rail="ach", currency="USD",
                                           payee={"name": "Acme", "account": {"account": "123456789",
                                                                              "routing": "021000021"}}),
                                       pay(us, "p_2", "10.00", rail="ach", currency="USD",
                                           payee={"name": "Acme", "account": {"account": "123456789",
                                                                              "routing": "021000021",
                                                                              "extra": "1"}})]),
        case("rail_not_allowed", m, [pay(m, "p_1", rail="wire")]),
        case("currency_mismatch", m, [pay(m, "p_1", currency="USD")]),
        case("agent_bad_signature", m, [bad_sig_payment, pay(m, "p_2", agent=OTHER), pay(m, "p_3", agent=None)]),
        case("no_agent_key_unsigned_ok", no_agent_key, [pay(no_agent_key, "p_1", agent=None)]),
        case("mandate_bad_signature", tampered, [pay(tampered, "p_1")]),
        case("mandate_mismatch", m, [pay(tampered, "p_1")]),
        case("signer_unknown", m, [pay(m, "p_1")], authority=[]),
        case("signer_not_authorized_wrong_key", m, [pay(m, "p_1")],
             authority=[{**KYB[0], "keys": [M.public_key_of(OTHER)]}]),
        case("signer_not_authorized_may_not_sign", m, [pay(m, "p_1")], authority=[{**KYB[0], "may_sign": False}]),
        case("mandate_expired", m, [pay(m, "p_1", at="2027-01-01T00:00:00.000Z")], now="2027-01-01T00:00:00.000Z"),
        case("mandate_not_yet_valid", mandate(valid_from="2026-11-01T00:00:00.000Z"),
             [pay(mandate(valid_from="2026-11-01T00:00:00.000Z"), "p_1")]),
        case("revoked", m, [pay(m, "p_1")], revocations=[rev]),
        case("revocation_by_unauthorized_signer_ignored", m, [pay(m, "p_1")], revocations=[rev_other]),
        case("revocation_in_future_ignored", m, [pay(m, "p_1")], revocations=[rev_later]),
        case("status_active", status_m, [pay(status_m, "p_1")], status="active"),
        case("status_revoked", status_m, [pay(status_m, "p_1")], status="revoked"),
        case("status_unreachable", status_m, [pay(status_m, "p_1")], status="error"),
        case("status_not_wired", status_m, [pay(status_m, "p_1")]),
        case("clock_skew", m, [pay(m, "p_1", at="2026-10-23T09:16:00.000Z"),
                               pay(m, "p_2", at="2026-10-23T09:15:02.000Z")]),
        case("payment_malformed", m, [{**pay(m, "p_1"), "amount": "1.5"}, {**pay(m, "p_2"), "amount": 100},
                                      {**pay(m, "p_3"), "requested_at": "2026-10-23T09:14Z"}, "not a payment",
                                      {**pay(m, "p_4"), "payee": {"name": "x", "account": {}}}]),
        case("mandate_malformed", {**m, "v": "gleipnir/mandate/0.2"}, [pay(m, "p_1")]),
        case("mandate_malformed_amount", mandate(sign=False, scope=scope(max_per_payment="25000")),
             [pay(m, "p_1")]),
    ]


def authority_fn(table: list[dict]) -> M.Authority:
    def authority(company: dict, signer_id: str) -> M.AuthorityResult | None:
        for row in table:
            if row["company"] == company.get("name") and row["signer"] == signer_id:
                return M.AuthorityResult(row["source"], tuple(row["keys"]), row["may_sign"])
        return None
    return authority


def status_fn(value: str | None):
    if value is None:
        return None

    def status(url: str) -> str:
        if value == "error":
            raise ConnectionError(url)
        return value
    return status


def run(c: dict[str, Any]) -> list[dict[str, Any]]:
    """Run a vector through the Python reference; returns the decisions."""
    clock = {"now": c["now"][0]}
    checker = M.Checker(id="bank:VECTORS", sk=BANK, authority=authority_fn(c["authority"]),
                        ledger=M.InMemoryLedger() if c["ledger"] else None, revocations=c["revocations"],
                        status=status_fn(c["status"]), clock=lambda: datetime.fromisoformat(
                            clock["now"].replace("Z", "+00:00")))
    out = []
    for p, at in zip(c["payments"], c["now"], strict=True):
        clock["now"] = at
        out.append(checker.check(c["mandate"], p))
    return out


def expected(decisions: list[dict]) -> list[dict[str, Any]]:
    first: dict[str, int] = {}
    rows = []
    for i, d in enumerate(decisions):
        row = {k: v for k, v in d.items() if k not in ("id", "sig")}
        if d["id"] in first:
            row = {"same_as": first[d["id"]]}
        first.setdefault(d["id"], i)
        rows.append(row)
    return rows


def build() -> dict[str, Any]:
    out_cases = []
    signed = []
    for c in cases():
        decisions = run(c)
        out_cases.append({**c, "expect": expected(decisions)})
        signed.append(decisions[0])
    return {
        "note": "Generated by python/gleipnir-verify/tests/mandate_vectors.py. Test keys from fixed seeds.",
        "bank": {"id": "bank:VECTORS", "seed_hex": (bytes([3]) * 32).hex(), "public_key": M.public_key_of(BANK)},
        "other_public_key": M.public_key_of(OTHER),
        "cases": out_cases,
        "signed": signed,
    }


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
