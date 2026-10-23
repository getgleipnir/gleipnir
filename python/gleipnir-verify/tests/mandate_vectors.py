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
from gleipnir_verify.approvals import approval_challenge

try:
    from passkey import WEBAUTHN, Passkey
except ImportError:  # run as a script from the repo root
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from passkey import WEBAUTHN, Passkey

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


HOFER, CEO, CFO, CTRL = key(5), key(6), key(7), key(8)


def person(sk: Ed25519PrivateKey, pid: str, role: str = "") -> dict[str, Any]:
    p = {"id": pid, "public_key": M.public_key_of(sk)}
    return {**p, "role": role} if role else p


def row(pid: str, sk: Ed25519PrivateKey, *, source: str = "bank_kyb", may_sign: bool = True, joint: int = 1,
        keys: list[str] | None = None) -> dict[str, Any]:
    return {"company": COMPANY["name"], "signer": pid, "source": source,
            "keys": keys if keys is not None else [M.public_key_of(sk)], "may_sign": may_sign, "joint": joint}


BERGER_P, HOFER_P = person(SIGNER, SIGNER_ID, "Prokurist"), person(HOFER, "mhofer@nordhafen.at", "Geschäftsführerin")
CEO_P, CFO_P, CTRL_P = (person(CEO, "ceo@nordhafen.at", "CEO"), person(CFO, "cfo@nordhafen.at", "CFO"),
                        person(CTRL, "controller@nordhafen.at", "Controller"))
JOINT_KYB = [row(SIGNER_ID, SIGNER), row(HOFER_P["id"], HOFER)]
CHAIN_KYB = [row(CEO_P["id"], CEO), row(CFO_P["id"], CFO, may_sign=False), row(CTRL_P["id"], CTRL, may_sign=False),
             row(SIGNER_ID, SIGNER)]
WIDE = {"rails": ["sepa", "sepa_instant"], "currency": "EUR", "max_per_payment": "50000.00",
        "max_per_period": {"amount": "200000.00", "period": "P1M"}}


def multi(threshold: int = 2, signed: tuple = ((SIGNER, SIGNER_ID), (HOFER, "mhofer@nordhafen.at")),
          **kw: Any) -> dict[str, Any]:
    m = mandate(sign=False, signer=None, signers={"threshold": threshold, "of": [BERGER_P, HOFER_P]}, **kw)
    for sk, sid in signed:
        m = M.cosign(m, sk, sid)
    return m


def link(gid: str, frm: tuple, to: dict, *, parent: dict | None = None, sc: dict | None = None,
         until: str = "2027-03-31T23:59:59.000Z") -> dict[str, Any]:
    sk, fp = frm
    return M.delegate(id=gid, company=COMPANY, from_=fp, to=to, scope=sc or WIDE, valid_until=until, sk=sk,
                      parent=parent, issued_at="2026-10-01T08:00:00.000Z")


def delegated(chain: list[dict], sk: Ed25519PrivateKey = CFO, who: dict | None = None, **kw: Any) -> dict[str, Any]:
    base = mandate(sign=False, signer=who or CFO_P, delegation=chain, **kw)
    return M.sign_mandate(base, sk)


def v02_cases() -> list[dict[str, Any]]:
    both = multi()
    one = multi(signed=((SIGNER, SIGNER_ID),))
    forged = {**both, "sigs": [both["sigs"][0], {"signer": "mhofer@nordhafen.at",
                                                 "sig": M.cosign(both, OTHER, "x")["sigs"][-1]["sig"]}]}
    any1 = multi(threshold=1, signed=((SIGNER, SIGNER_ID),))
    any1_both = multi(threshold=1)
    g1 = link("g_ceo_cfo", (CEO, CEO_P), CFO_P)
    d1 = delegated([g1])
    g2 = link("g_cfo_ctrl", (CFO, CFO_P), CTRL_P, parent=g1,
              sc={**WIDE, "max_per_payment": "30000.00"}, until="2027-01-31T23:59:59.000Z")
    d2 = delegated([g1, g2], CTRL, CTRL_P)
    d2_wide = delegated([g1, link("g_cfo_ctrl_w", (CFO, CFO_P), CTRL_P, parent=g1,
                                  sc={**WIDE, "max_per_payment": "60000.00"})], CTRL, CTRL_P)
    over = delegated([g1], scope=scope(max_per_payment="60000.00"))
    longer = delegated([g1], valid_until="2027-06-30T23:59:59.000Z")
    payees_link = link("g_payees", (CEO, CEO_P), CFO_P, sc={**WIDE, "payees": [
        {"name": "Other", "account": {"iban": "DE89370400440532013000"}}]})
    off_list = delegated([payees_link])
    wrong_signer = delegated([g1], SIGNER, BERGER_P)
    bad_parent = {**g2, "parent": {"id": "g_ceo_cfo", "hash": "sha256:" + "0" * 64}}
    broken_chain = delegated([g1, M._sign(CFO, "delegation", bad_parent)], CTRL, CTRL_P)
    tampered_link = delegated([{**g1, "scope": {**WIDE, "max_per_payment": "90000.00"}}])
    rev_link = M.revoke(g1, signer=CEO_P, sk=CEO, id="r_g1", revoked_at="2026-10-22T00:00:00.000Z")
    rev_own = M.revoke(d1, signer=CFO_P, sk=CFO, id="r_own", revoked_at="2026-10-22T00:00:00.000Z")
    rev_ctrl = M.revoke(d1, signer=CTRL_P, sk=CTRL, id="r_ctrl", revoked_at="2026-10-22T00:00:00.000Z")
    vlei = [row(SIGNER_ID, SIGNER, source="vlei")]
    m = mandate()
    return [
        case("multisig_2_of_2_allow", both, [pay(both, "p_1")], authority=JOINT_KYB),
        case("multisig_one_of_two_signed", one, [pay(one, "p_1")], authority=JOINT_KYB),
        case("multisig_forged_cosignature", forged, [pay(forged, "p_1")], authority=JOINT_KYB),
        case("multisig_cosigner_unknown", both, [pay(both, "p_1")], authority=JOINT_KYB[:1]),
        case("multisig_cosigner_wrong_key", both, [pay(both, "p_1")],
             authority=[JOINT_KYB[0], row(HOFER_P["id"], OTHER)]),
        case("gesamtprokura_alone_blocked", any1, [pay(any1, "p_1")],
             authority=[row(SIGNER_ID, SIGNER, joint=2), JOINT_KYB[1]]),
        case("gesamtprokura_with_cosigner_allow", any1_both, [pay(any1_both, "p_1")],
             authority=[row(SIGNER_ID, SIGNER, joint=2), JOINT_KYB[1]]),
        case("single_signer_joint_required", m, [pay(m, "p_1")], authority=[row(SIGNER_ID, SIGNER, joint=2)]),
        case("multisig_threshold_too_high", mandate(sign=False, signer=None,
                                                    signers={"threshold": 3, "of": [BERGER_P, HOFER_P]}),
             [pay(m, "p_1")]),
        case("delegation_ceo_cfo_allow", d1, [pay(d1, "p_1")], authority=CHAIN_KYB),
        case("delegation_two_links_allow", d2, [pay(d2, "p_1")], authority=CHAIN_KYB),
        case("delegation_child_link_wider", d2_wide, [pay(d2_wide, "p_1")], authority=CHAIN_KYB),
        case("delegation_mandate_over_limit", over, [pay(over, "p_1")], authority=CHAIN_KYB),
        case("delegation_mandate_outlives_link", longer, [pay(longer, "p_1")], authority=CHAIN_KYB),
        case("delegation_payee_not_in_link", off_list, [pay(off_list, "p_1")], authority=CHAIN_KYB),
        case("delegation_signer_not_last_link", wrong_signer, [pay(wrong_signer, "p_1")], authority=CHAIN_KYB),
        case("delegation_parent_hash_wrong", broken_chain, [pay(broken_chain, "p_1")], authority=CHAIN_KYB),
        case("delegation_link_tampered", tampered_link, [pay(tampered_link, "p_1")], authority=CHAIN_KYB),
        case("delegation_delegate_unknown", d1, [pay(d1, "p_1")], authority=[CHAIN_KYB[0]]),
        case("delegation_root_without_power", d1, [pay(d1, "p_1")],
             authority=[row(CEO_P["id"], CEO, may_sign=False), *CHAIN_KYB[1:]]),
        case("delegation_root_needs_cosigner", d1, [pay(d1, "p_1")],
             authority=[row(CEO_P["id"], CEO, joint=2), *CHAIN_KYB[1:]]),
        case("delegation_revoked_by_ceo", d1, [pay(d1, "p_1")], authority=CHAIN_KYB, revocations=[rev_link]),
        case("delegate_withdraws_own_mandate", d1, [pay(d1, "p_1")], authority=CHAIN_KYB, revocations=[rev_own]),
        case("revocation_by_outsider_without_power_ignored", d1, [pay(d1, "p_1")], authority=CHAIN_KYB,
             revocations=[rev_ctrl]),
        case("cfo_removed_from_signatories", m, [pay(m, "p_1")], authority=[row(SIGNER_ID, SIGNER, may_sign=False)]),
        case("second_bank_without_vlei", m, [pay(m, "p_1")], authority=[]),
        case("second_bank_with_vlei", m, [pay(m, "p_1")], authority=vlei),
        *passkey_cases(),
    ]


def passkey_cases() -> list[dict[str, Any]]:
    """Passkey-signed mandates (fixed P-256 keys; ECDSA signatures are random but only ever verified)."""
    pk_b, pk_h = Passkey(0xB16B00B5), Passkey(0xC0FFEE)
    who_b = {"id": SIGNER_ID, "public_key": pk_b.public_key}
    who_h = {"id": "mhofer@nordhafen.at", "public_key": pk_h.public_key}
    kyb = [row(SIGNER_ID, SIGNER, keys=[pk_b.public_key]), row(who_h["id"], HOFER, keys=[pk_h.public_key])]
    one = mandate(sign=False, signer=who_b)
    signed = {**one, "sig": pk_b.assert_(M.passkey_challenge(one))}
    bare = {**one, "sig": pk_b.assert_(approval_challenge(M.mandate_hash(one)))}
    wrong_origin = {**one, "sig": pk_b.assert_(M.passkey_challenge(one), origin="https://evil.example")}
    joint = mandate(sign=False, signer=None, signers={"threshold": 2, "of": [who_b, who_h]})
    ch = M.passkey_challenge(joint)
    joint = {**joint, "sigs": [{"signer": who_b["id"], "sig": pk_b.assert_(ch)},
                               {"signer": who_h["id"], "sig": pk_h.assert_(ch)}]}
    return [
        case("passkey_signed_allow", signed, [pay(signed, "p_1")], authority=kyb, webauthn=WEBAUTHN),
        case("passkey_without_checker_config", signed, [pay(signed, "p_1")], authority=kyb),
        case("passkey_bare_hash_m1", bare, [pay(bare, "p_1")], authority=kyb, webauthn=WEBAUTHN),
        case("passkey_wrong_origin", wrong_origin, [pay(wrong_origin, "p_1")], authority=kyb, webauthn=WEBAUTHN),
        case("passkey_gesamtprokura_allow", joint, [pay(joint, "p_1")], authority=kyb, webauthn=WEBAUTHN),
    ]


def signer(sk: Ed25519PrivateKey = SIGNER, sid: str = SIGNER_ID) -> dict[str, Any]:
    return {"id": sid, "name": "K. Berger", "role": "Prokurist", "public_key": M.public_key_of(sk)}


def scope(**kw: Any) -> dict[str, Any]:
    s = {"rails": ["sepa", "sepa_instant"], "currency": "EUR", "max_per_payment": "25000.00",
         "max_per_period": {"amount": "40000.00", "period": "P1M"}, "payees": [BRENNER]}
    s.update(kw)
    return {k: v for k, v in s.items() if v is not None}


def mandate(sk: Ed25519PrivateKey = SIGNER, sign: bool = True, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"v": "gleipnir/mandate/0.2", "id": "m_vec", "company": COMPANY,
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
         revocations: list | None = None, status: str | None = None, ledger: bool = True,
         webauthn: dict | None = None) -> dict[str, Any]:
    return {"name": name, "mandate": m, "payments": payments, "webauthn": webauthn or {},
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
        *v02_cases(),
    ]


def authority_fn(table: list[dict]) -> M.Authority:
    def authority(company: dict, signer_id: str) -> M.AuthorityResult | None:
        for row in table:
            if row["company"] == company.get("name") and row["signer"] == signer_id:
                return M.AuthorityResult(row["source"], tuple(row["keys"]), row["may_sign"], row.get("joint", 1))
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
                        status=status_fn(c["status"]), webauthn=c.get("webauthn") or {},
                        clock=lambda: datetime.fromisoformat(
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
        receipt = M.verify_receipt(c["mandate"], c["payments"][0], decisions[0], [M.public_key_of(BANK)],
                                   webauthn=c.get("webauthn") or {})
        out_cases.append({**c, "expect": expected(decisions), "receipt": {k: v for k, v in receipt.items()
                                                                          if k != "checked_at"}})
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
