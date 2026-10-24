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

from gleipnir_verify import iso20022 as ISO
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
BRENNER = {"name": "Brenner Stahl AG", "account": {"scheme": "iban", "iban": "AT611904300234573201"}}
KYB = [{"company": COMPANY["name"], "signer": SIGNER_ID, "source": "bank_kyb",
        "keys": [M.public_key_of(SIGNER)], "may_sign": True}]
# The company's own accounts: DEBTOR at this bank, ELSEWHERE at another bank.
DEBTOR = {"scheme": "iban", "iban": "AT483200000012345864"}
ELSEWHERE = {"scheme": "iban", "iban": "DE44500105175407324931"}
HOLDS = [{"company": COMPANY["name"], "account": DEBTOR}]


HOFER, CEO, CFO, CTRL = key(5), key(6), key(7), key(8)


def person(sk: Ed25519PrivateKey, pid: str, role: str = "") -> dict[str, Any]:
    p = {"id": pid, "public_key": M.public_key_of(sk)}
    return {**p, "role": role} if role else p


def row(pid: str, sk: Ed25519PrivateKey, *, source: str = "bank_kyb", may_sign: bool = True, joint: int = 1,
        keys: list[str] | None = None) -> dict[str, Any]:
    return {"company": COMPANY["name"], "signer": pid, "source": source,
            "keys": keys if keys is not None else [M.public_key_of(sk)], "may_sign": may_sign, "joint": joint}


BERGER_P, HOFER_P = person(SIGNER, SIGNER_ID, "Authorised signatory"), person(HOFER, "mhofer@nordhafen.at",
                                                                             "Managing director")
CEO_P, CFO_P, CTRL_P = (person(CEO, "ceo@nordhafen.at", "CEO"), person(CFO, "cfo@nordhafen.at", "CFO"),
                        person(CTRL, "controller@nordhafen.at", "Controller"))
JOINT_KYB = [row(SIGNER_ID, SIGNER), row(HOFER_P["id"], HOFER)]
CHAIN_KYB = [row(CEO_P["id"], CEO), row(CFO_P["id"], CFO, may_sign=False), row(CTRL_P["id"], CTRL, may_sign=False),
             row(SIGNER_ID, SIGNER)]
WIDE = {"rails": ["sepa", "sepa_instant"], "currency": "EUR", "max_per_payment": "50000.00",
        "max_per_period": {"amount": "200000.00", "period": "P1M"}, "from_accounts": [DEBTOR]}


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


def delegated(chain: list[dict], sk: Ed25519PrivateKey = CFO, who: dict | None = None, mid: str = "m_vec",
              **kw: Any) -> dict[str, Any]:
    base = mandate(sign=False, signer=who or CFO_P, delegation=chain, id=mid, **kw)
    return M.sign_mandate(base, sk)


def v02_cases() -> list[dict[str, Any]]:  # noqa: PLR0915
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
        {"name": "Other", "account": {"scheme": "iban", "iban": "DE89370400440532013000"}}]})
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
        case("joint_signatory_alone_blocked", any1, [pay(any1, "p_1")],
             authority=[row(SIGNER_ID, SIGNER, joint=2), JOINT_KYB[1]]),
        case("joint_signatory_with_cosigner_allow", any1_both, [pay(any1_both, "p_1")],
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
        *audit2_cases(),
        *v03_cases(),
        *audit3_cases(),
        *v04_cases(),
    ]


def audit2_cases() -> list[dict[str, Any]]:
    """Inputs from the second external audit (F1-F16), pinned for both implementations."""
    m = mandate()
    shared = link("g_shared", (CEO, CEO_P), CFO_P, sc={**WIDE, "max_per_payment": "200000.00",
                                                     "max_per_period": {"amount": "200000.00", "period": "P1M"}})
    big = scope(max_per_payment="150000.00", max_per_period={"amount": "200000.00", "period": "P1M"})
    ma = delegated([shared], mid="m_a", scope=big)
    mb = delegated([shared], mid="m_b", scope=big)
    proto_added = {**m, "__proto__": "x"}
    proto_payment = {**pay(m, "p_1"), "__proto__": {"a": "b"}}
    other_co = {"name": "Andere Spedition GmbH", "country": "AT"}
    other_signer = person(OTHER, "boss@andere.at")
    other_acc = {"scheme": "iban", "iban": "AT291200000123456789"}
    other = M.sign_mandate({**mandate(sign=False, signer=other_signer, scope=scope(from_accounts=[other_acc])),
                            "company": other_co}, OTHER)
    other_kyb = [*KYB, {**row("boss@andere.at", OTHER), "company": other_co["name"]}]
    same_key = mandate(sign=False, signer=None, signers={"threshold": 2, "of": [
        BERGER_P, {**HOFER_P, "public_key": BERGER_P["public_key"]}]})
    no_rails = mandate(scope=scope(rails=None))
    de_link = M.delegate(id="g_de", company={"name": COMPANY["name"], "country": "DE"}, from_=CEO_P, to=CFO_P,
                         scope=WIDE, valid_until="2027-03-31T23:59:59.000Z", sk=CEO,
                         issued_at="2026-10-01T08:00:00.000Z")
    de = delegated([de_link])
    g1 = link("g_ceo_cfo", (CEO, CEO_P), CFO_P)
    g2 = link("g_cfo_ctrl", (CFO, CFO_P), CTRL_P, parent=g1, sc={**WIDE, "max_per_payment": "30000.00"},
              until="2027-01-31T23:59:59.000Z")
    d2 = delegated([g1, g2], CTRL, CTRL_P)
    leaf_cuts_root = M.revoke(g1, signer=CTRL_P, sk=CTRL, id="r_leaf", revoked_at="2026-10-22T00:00:00.000Z")
    junk = mandate(sign=False, signer=person(OTHER, "intruder@x"))
    p_signed = pay(m, "INV-1")
    p_unsigned = {k: v for k, v in p_signed.items() if k != "agent_sig"}
    bad_account = mandate(sign=False, scope=scope(payees=[{"name": "Acme", "account": {"scheme": "us_aba",
                                                                                      "routing": 21000021}}]))
    non_ascii = mandate(sign=False, scope=scope(payees=[{"name": "X", "account": {"scheme": "iban",
                                                                                 "iban": "AT61\u01951904"}}]))
    return [
        case("F1_delegated_period_limit_is_shared", ma, [pay(ma, "p_1", "150000.00"), pay(mb, "p_2", "150000.00"),
                                                         pay(ma, "p_3", "40000.00")],
             authority=CHAIN_KYB, mandates=[ma, mb], which=[0, 1, 0]),
        case("F2_proto_key_added_after_signing", proto_added, [pay(m, "p_1")]),
        case("F2_proto_object_in_payment", m, [proto_payment]),
        case("F4_unsigned_junk_cannot_burn_payment_id", junk, [pay(junk, "INV-1", agent=None), pay(m, "INV-1")],
             mandates=[junk, m], which=[0, 1]),
        case("F5_unsigned_copy_first", m, [p_unsigned, p_signed]),
        case("F6_same_mandate_id_other_company", other,
             [pay(other, "o_1", "25000.00"), pay(other, "o_2", "15000.00"), pay(m, "p_1", "25000.00")],
             authority=other_kyb, mandates=[other, m], which=[0, 0, 1],
             holds=[*HOLDS, {"company": other_co["name"], "account": other_acc}]),
        case("F7_one_key_two_signer_ids", same_key, [pay(same_key, "p_1")], authority=JOINT_KYB),
        case("F11_unknown_rail_in_payment", no_rails, [pay(no_rails, "p_1", rail="bitcoin")]),
        case("F13_link_names_other_country", de, [pay(de, "p_1")], authority=CHAIN_KYB),
        case("F14_leaf_delegate_cannot_cut_root", d2, [pay(d2, "p_1")], authority=CHAIN_KYB,
             revocations=[leaf_cuts_root]),
        case("F3_account_value_not_a_string", bad_account, [pay(m, "p_1")]),
        case("F16_non_ascii_iban", non_ascii, [pay(m, "p_1")]),
    ]


def seed(sk: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization as ser
    return sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption()).hex()


def resolve(of: int, outcome: str = "allow", signers: tuple = ((SIGNER, SIGNER_ID),), at: str = NOW,
            oid: str = "o_1", **kw: Any) -> dict[str, Any]:
    return {"resolve": {"of": of, "id": oid, "outcome": outcome, "decided_at": at,
                        "signers": [{"seed": seed(sk), "id": pid} for sk, pid in signers], **kw}}


def local(currency: str, rail: str, debtor: dict, payee: dict, mid: str = "m_vec") -> tuple[dict, dict, list]:
    """A mandate for one country's own rail: (mandate, payment, holds)."""
    m = mandate(id=mid, scope=scope(rails=[rail], currency=currency, max_per_period=None,
                                    max_per_payment="500000" if currency == "JPY" else "25000.00",
                                    from_accounts=[debtor], payees=[{"name": "Supplier", "account": payee}]))
    amount = "120000" if currency == "JPY" else "100.00"
    return m, pay(m, "p_1", amount, rail=rail, currency=currency, payee={"name": "Supplier", "account": payee}), \
        [{"company": COMPANY["name"], "account": debtor}]


def v03_cases() -> list[dict[str, Any]]:  # noqa: PLR0915
    """0.3: debtor accounts, account schemes and rails worldwide, signed status, overrides, key rotation,
    corrected payments, the payee policy, cached decisions only for authentic payments."""
    m = mandate()
    officer_sk = key(9)
    officer = M.public_key_of(officer_sk)
    out = []

    # Debtor accounts.
    other_from = pay(m, "p_1", frm=ELSEWHERE)
    two_banks = mandate(scope=scope(from_accounts=[DEBTOR, ELSEWHERE]))
    two_banks_no_period = mandate(scope=scope(from_accounts=[DEBTOR, ELSEWHERE], max_per_period=None))
    out += [
        case("account_not_on_mandate", m, [other_from]),
        case("account_not_held_here", m, [pay(m, "p_1")], holds=[]),
        case("period_limit_cannot_span_banks", two_banks, [pay(two_banks, "p_1")]),
        case("several_banks_without_period_limit", two_banks_no_period, [pay(two_banks_no_period, "p_1")]),
        case("second_bank_cannot_replay", m, [pay(m, "p_1")],
             holds=[{"company": COMPANY["name"], "account": ELSEWHERE}]),
    ]

    # Account schemes and rails around the world.
    world = {
        "uk_faster_payments": ("GBP", "faster_payments", {"scheme": "uk_sort_code", "sort_code": "200000",
                                                          "account": "55779911"},
                               {"scheme": "uk_sort_code", "sort_code": "601613", "account": "31926819"}),
        "ca_eft": ("CAD", "ca_eft", {"scheme": "ca_eft", "institution": "003", "transit": "12345",
                                     "account": "1234567"},
                   {"scheme": "ca_eft", "institution": "004", "transit": "54321", "account": "7654321"}),
        "au_npp": ("AUD", "npp", {"scheme": "au_bsb", "bsb": "062000", "account": "12345678"},
                   {"scheme": "au_bsb", "bsb": "033000", "account": "87654321"}),
        "in_neft": ("INR", "neft", {"scheme": "in_ifsc", "ifsc": "HDFC0000001", "account": "50100012345678"},
                    {"scheme": "in_ifsc", "ifsc": "SBIN0000300", "account": "00000012345678"}),
        "mx_spei": ("MXN", "spei", {"scheme": "mx_clabe", "clabe": "012180000118359713"},
                    {"scheme": "mx_clabe", "clabe": "002010077777777771"}),
        "swift_wire_jpy": ("JPY", "wire", {"scheme": "us_aba", "routing": "011000015", "account": "000123456789"},
                           {"scheme": "swift", "bic": "MHCBJPJT", "account": "1234567"}),
    }
    for name, (cur, rail, debtor, payee) in world.items():
        wm, wp, wh = local(cur, rail, debtor, payee)
        out.append(case(name, wm, [wp], holds=wh))
    gb = world["uk_faster_payments"][3]
    out += [
        case("rail_mismatch_scheme", m, [pay(m, "p_1", payee={"name": "x", "account": gb})]),
        case("currency_mismatch", mandate(scope=scope(rails=None)),
             [pay(mandate(scope=scope(rails=None)), "p_1", rail="wire", currency="USD")]),
        case("account_checksums_malformed", m, [
            pay(m, "p_1", payee={"name": "x", "account": {"scheme": "iban", "iban": "AT621904300234573201"}}),
            pay(m, "p_2", payee={"name": "x", "account": {"scheme": "us_aba", "routing": "021000022",
                                                          "account": "1"}}),
            pay(m, "p_3", payee={"name": "x", "account": {"scheme": "mx_clabe", "clabe": "002010077777777772"}}),
            pay(m, "p_4", payee={"name": "x", "account": {"scheme": "telex", "number": "1"}}),
            {**pay(m, "p_5"), "from_account": {"scheme": "iban", "iban": "AT48 3200 0000 1234 5864"}}]),
    ]

    # Signed status responses.
    st_m = mandate(status_url="https://bank.example/mandates/m_vec")
    me = signer()
    ok = M.status_response(st_m, status="active", signer=me, sk=SIGNER, at=NOW)
    stranger = person(OTHER, "intern@nordhafen.at")
    out += [
        case("status_forged_signature", st_m, [pay(st_m, "p_1")],
             status={**ok, "sig": M.status_response(st_m, status="active", signer=me, sk=OTHER, at=NOW)["sig"]}),
        case("status_stale", st_m, [pay(st_m, "p_1")],
             status=M.status_response(st_m, status="active", signer=me, sk=SIGNER, at="2026-10-23T09:08:00.000Z")),
        case("status_for_other_mandate", st_m, [pay(st_m, "p_1")],
             status=M.status_response(m, status="active", signer=me, sk=SIGNER, at=NOW)),
        case("status_from_outsider", st_m, [pay(st_m, "p_1")],
             authority=[*KYB, row(stranger["id"], OTHER, may_sign=False)],
             status=M.status_response(st_m, status="active", signer=stranger, sk=OTHER, at=NOW)),
    ]

    # Corrected payments, cached decisions.
    wrong = {"name": "Brenner Stahl AG", "account": {"scheme": "iban", "iban": "LT121000011101001000"}}
    p_ok = pay(m, "INV-7")
    out += [
        case("corrected_payment_after_block", m, [pay(m, "INV-7", payee=wrong), pay(m, "INV-7"), pay(m, "INV-7")]),
        case("cached_decision_only_for_authentic_payment", m, [
            p_ok, {k: v for k, v in p_ok.items() if k != "agent_sig"},
            {**p_ok, "agent_sig": pay(m, "INV-7", agent=OTHER)["agent_sig"]}, p_ok]),
        case("payees_required_policy", mandate(scope=scope(payees=None)),
             [pay(mandate(scope=scope(payees=None)), "p_1")], policy={"require_payees": True}),
        case("payees_optional_by_default", mandate(scope=scope(payees=None)),
             [pay(mandate(scope=scope(payees=None)), "p_1")]),
    ]

    # Key rotation.
    new_k = key(10)
    rotated = [row(SIGNER_ID, new_k, keys=[M.public_key_of(new_k)]) | {"retired": {
        M.public_key_of(SIGNER): "2026-10-15T00:00:00.000Z"}}]
    after = mandate(issued_at="2026-10-20T00:00:00.000Z")
    out += [
        case("rotated_key_old_mandate_still_valid", m, [pay(m, "p_1")], authority=rotated),
        case("rotated_key_new_mandate_refused", after, [pay(after, "p_1")], authority=rotated),
        case("rotated_key_dropped_after_compromise", m, [pay(m, "p_1")],
             authority=[row(SIGNER_ID, new_k, keys=[M.public_key_of(new_k)])]),
    ]

    # One joint signatory may revoke alone.
    both = multi()
    rev_one = M.revoke(both, signer=HOFER_P, sk=HOFER, id="r_hofer", revoked_at="2026-10-22T00:00:00.000Z")
    out.append(case("one_joint_signer_revokes", both, [pay(both, "p_1")], authority=JOINT_KYB, revocations=[rev_one]))

    # Overrides.
    big = pay(m, "p_big", "30000.00")
    out += [
        case("override_company_allows_over_limit", m, [big, big, big],
             ops=["check", resolve(0), "check"]),
        case("override_block_holds_id", m, [big, big, big, pay(m, "p_big", "1.00")],
             ops=["check", resolve(0, "block", reason="Not this invoice"), "check", "check"]),
        case("override_replayed_same_answer", m, [big, big, big], ops=["check", resolve(0), resolve(0)]),
        case("override_by_outsider", m, [big, big], ops=["check", resolve(0, signers=((OTHER, "intern@x"),))],
             authority=[*KYB, row("intern@x", OTHER, may_sign=False)]),
        case("override_tampered_decision_hash", m, [big, big],
             ops=["check", resolve(0, decision_hash="sha256:" + "0" * 64)]),
        case("override_too_late", m, [big, big], now=[NOW, "2026-10-26T09:14:03.000Z"],
             ops=["check", resolve(0, at="2026-10-26T09:14:02.000Z")]),
        case("override_signed_before_escalation", m, [big, big],
             ops=["check", resolve(0, at="2026-10-23T09:14:01.000Z")]),
        case("override_on_allow_refused", m, [pay(m, "p_1"), pay(m, "p_1")], ops=["check", resolve(0)]),
        case("override_unknown_signer_company_refused", m, [pay(m, "p_1"), pay(m, "p_1")], authority=[],
             ops=["check", resolve(0)]),
        case("override_unknown_signer_bank_officer", m, [pay(m, "p_1"), pay(m, "p_1")], authority=[],
             ops=["check", resolve(0, signers=((officer_sk, "ops@bank"),))], officers=[officer]),
        case("override_joint_signer_alone_refused", both, [pay(both, "p_big", "30000.00")] * 3,
             authority=[row(SIGNER_ID, SIGNER, joint=2), row(HOFER_P["id"], HOFER, joint=2)],
             ops=["check", resolve(0), resolve(0, signers=((SIGNER, SIGNER_ID), (HOFER, HOFER_P["id"])),
                                               oid="o_2")]),
        case("override_period_limit_by_officer", m,
             [pay(m, "p_1", "20000.00"), pay(m, "p_2", "20000.01"), pay(m, "p_2", "20000.01"), pay(m, "p_3", "1.00")],
             ops=["check", "check", resolve(1, signers=((officer_sk, "ops@bank"),)), "check"], officers=[officer]),
        case("override_status_unavailable_by_officer", st_m, [pay(st_m, "p_1"), pay(st_m, "p_1")], status="error",
             ops=["check", resolve(0, signers=((officer_sk, "ops@bank"),))], officers=[officer]),
        case("override_status_company_refused", st_m, [pay(st_m, "p_1"), pay(st_m, "p_1")], status="error",
             ops=["check", resolve(0)]),
        case("override_then_second_escalation", m, [pay(m, "p_1", "30000.00"), pay(m, "p_1", "30000.00"),
                                                     pay(m, "p_1", "30000.00"), pay(m, "p_1", "30000.00")],
             authority=[], officers=[officer],
             ops=["check", resolve(0, signers=((officer_sk, "ops@bank"),)),
                  resolve(1, signers=((officer_sk, "ops@bank"),), oid="o_2"), "check"]),
    ]
    return out


def audit3_cases() -> list[dict[str, Any]]:
    """Inputs from the third audit (24.10.2026), pinned for both implementations."""
    officer_sk = key(9)
    officer = M.public_key_of(officer_sk)
    ops = ((officer_sk, "ops@bank"),)
    m = mandate()
    both = multi()
    lei = mandate(id="m_lei", company={**COMPANY, "ids": {"lei": "529900T8BM49AURSDO55"}})
    lei_holds = [*HOLDS, {"company": COMPANY["name"], "account": DEBTOR}]
    deep: Any = "x"
    for _ in range(M.MAX_DEPTH):
        deep = [deep]
    deep_m = mandate(scope=scope(purpose=deep))
    alias = {**HOFER_P, "id": "KBerger@nordhafen.at"}
    aliased = mandate(sign=False, signer=None, signers={"threshold": 2, "of": [BERGER_P, alias]})
    aliased = M.cosign(M.cosign(aliased, SIGNER, SIGNER_ID), HOFER, alias["id"])
    alias_kyb = [row(SIGNER_ID, SIGNER, keys=[M.public_key_of(SIGNER), M.public_key_of(HOFER)]) | {"person": "p1"},
                 row(alias["id"], HOFER, keys=[M.public_key_of(SIGNER), M.public_key_of(HOFER)]) | {"person": "p1"}]
    null_ids = M._sign(CEO, "delegation", {"v": f"gleipnir/delegation/{M.V}", "id": "g_null",
                                           "company": {**COMPANY, "ids": None}, "from": CEO_P, "to": CFO_P,
                                           "scope": WIDE, "valid_until": "2027-03-31T23:59:59.000Z",
                                           "issued_at": "2026-10-01T08:00:00.000Z"})
    d_null = delegated([null_ids])
    big = pay(m, "p_big", "30000.00")
    shared = link("g_cap", (CEO, CEO_P), CFO_P, sc={**WIDE, "max_per_period": {"amount": "30000.00", "period": "P1M"}})
    capped = delegated([shared], scope=scope(max_per_period={"amount": "30000.00", "period": "P1M"}))
    capped_kyb = [*CHAIN_KYB]
    return [
        case("A3_unknown_signer_named_in_escalation", both, [pay(both, "p_1"), pay(both, "p_1")],
             authority=JOINT_KYB[:1], officers=[officer], ops=["check", resolve(0, signers=ops)]),
        case("A3_one_customer_one_id_space", m, [pay(m, "INV-9"), pay(lei, "INV-9")], mandates=[m, lei], which=[0, 1],
             holds=lei_holds),
        case("A3_one_person_counts_once", aliased, [pay(aliased, "p_1")], authority=alias_kyb),
        case("A3_nesting_limit", deep_m, [pay(deep_m, "p_1")]),
        case("A3_link_ids_null_is_not_absent", d_null, [pay(d_null, "p_1")], authority=CHAIN_KYB),
        case("A3_ledger_missing_not_overridable", m, [pay(m, "p_1"), pay(m, "p_1")], ledger=False, officers=[officer],
             ops=["check", resolve(0, signers=ops)]),
        case("A3_company_override_needs_mandate_joint", both, [pay(both, "p_big", "30000.00")] * 3,
             authority=[row(SIGNER_ID, SIGNER, joint=2), row(HOFER_P["id"], HOFER, joint=2), row("c@x", OTHER)],
             ops=["check", resolve(0, signers=((OTHER, "c@x"),)),
                  resolve(0, signers=((OTHER, "c@x"), (SIGNER, SIGNER_ID)), oid="o_2")]),
        case("A3_company_cannot_lift_delegated_cap", capped,
             [pay(capped, "p_1", "20000.00"), pay(capped, "p_2", "20000.00"), pay(capped, "p_2", "20000.00"),
              pay(capped, "p_2", "20000.00")],
             authority=[*capped_kyb, row("boss@x", OTHER)], officers=[officer],
             ops=["check", "check", resolve(1, signers=((OTHER, "boss@x"),)), resolve(2, signers=ops, oid="o_2")]),
        case("A3_override_approvers_recorded", m, [big, big], ops=["check", resolve(0)]),
    ]


def v04_cases() -> list[dict[str, Any]]:
    """0.4: revocation lists from another checker (spec 9.2)."""
    m = mandate()
    home = key(11)
    home_pk = M.public_key_of(home)
    rev = M.revoke(m, signer=signer(), sk=SIGNER, id="r_feed", revoked_at="2026-10-22T00:00:00.000Z")
    ok = M.revocation_list([rev], issuer="bank:HOME", sk=home, issued_at="2026-10-23T09:00:00.000Z",
                           next_update="2026-10-23T10:00:00.000Z")
    empty = M.revocation_list([], issuer="bank:HOME", sk=home, issued_at="2026-10-23T09:00:00.000Z",
                              next_update="2026-10-23T10:00:00.000Z")
    stale = M.revocation_list([], issuer="bank:HOME", sk=home, issued_at="2026-10-23T08:00:00.000Z",
                              next_update="2026-10-23T09:00:00.000Z")
    long = M.revocation_list([], issuer="bank:HOME", sk=home, issued_at="2026-10-23T09:00:00.000Z",
                             next_update="2026-10-25T09:00:00.000Z")
    ks = lambda k: {"v": f"gleipnir/keys/{M.V}", "checker": "bank:HOME",  # noqa: E731
                    "issued_at": "2026-10-23T00:00:00.000Z", "keys": [{"public_key": home_pk, **k}]}
    officer_sk = key(9)
    return [
        case("feed_keyset_revokes", m, [pay(m, "p_1")], feed={"doc": ok, "keys": ks({})}),
        case("feed_issuer_key_retired_since", m, [pay(m, "p_1")],
             feed={"doc": empty, "keys": ks({"until": "2026-10-23T09:10:00.000Z"})}),
        case("feed_current_for_too_long", m, [pay(m, "p_1")], feed={"doc": long, "keys": [home_pk]}),
        case("feed_revokes", m, [pay(m, "p_1")], feed={"doc": ok, "keys": [home_pk]}),
        case("feed_current_empty", m, [pay(m, "p_1")], feed={"doc": empty, "keys": [home_pk]}),
        case("feed_stale", m, [pay(m, "p_1")], feed={"doc": stale, "keys": [home_pk]}),
        case("feed_untrusted_issuer", m, [pay(m, "p_1")], feed={"doc": ok, "keys": [M.public_key_of(OTHER)]}),
        case("feed_tampered", m, [pay(m, "p_1")], feed={"doc": {**ok, "revocations": []}, "keys": [home_pk]}),
        case("feed_unreachable_officer_override", m, [pay(m, "p_1"), pay(m, "p_1")], feed="error",
             officers=[M.public_key_of(officer_sk)], ops=["check", resolve(0, signers=((officer_sk, "ops@bank"),))]),
    ]


def keyset_cases(signed: list[dict]) -> list[list[Any]]:
    """[key set, decision, valid]: decisions checked against the bank's published key set (spec 10.1)."""
    d = signed[0]
    bank = M.public_key_of(BANK)
    at = d["checked_at"]
    mk = lambda keys, checker="bank:VECTORS": {"v": f"gleipnir/keys/{M.V}", "checker": checker,  # noqa: E731
                                               "issued_at": "2026-10-24T00:00:00.000Z", "keys": keys}
    return [
        [mk([{"public_key": bank}]), d, True],
        [mk([{"public_key": bank, "from": "2026-01-01T00:00:00.000Z", "until": "2027-01-01T00:00:00.000Z"}]), d, True],
        [mk([{"public_key": bank, "until": at}]), d, False],
        [mk([{"public_key": bank, "from": "2026-10-24T00:00:00.000Z"}]), d, False],
        [mk([{"public_key": bank, "compromised": True}]), d, False],
        [mk([{"public_key": bank}], "bank:OTHER"), d, False],
        [mk([{"public_key": M.public_key_of(OTHER)}]), d, False],
        [mk([{"public_key": bank, "extra": 1}]), d, False],
    ]


def pain001_cases() -> list[dict[str, Any]]:
    """ISO 20022 pain.001 for each account scheme, and altered messages (spec 6.2). Both implementations must
    produce the identical XML and the identical problems."""
    out: list[dict[str, Any]] = []
    m = mandate()
    p = pay(m, "INV-2026-0912", "18400.00", payee={"name": "Brenner & Söhne <AG>", "account": BRENNER["account"]})
    d = run(case("x", m, [p]))[0]
    good = ISO.pain001(m, p, d)
    out.append({"name": "sepa_with_decision", "mandate": m, "payment": p, "decision": d, "xml": good,
                "problems": ISO.pain001_problems(good, m, p, d)})
    worlds = {
        "uk": ("GBP", "faster_payments", {"scheme": "uk_sort_code", "sort_code": "200000", "account": "55779911"},
               {"scheme": "uk_sort_code", "sort_code": "601613", "account": "31926819"}),
        "ca": ("CAD", "ca_eft", {"scheme": "ca_eft", "institution": "003", "transit": "12345", "account": "1234567"},
               {"scheme": "ca_eft", "institution": "004", "transit": "54321", "account": "7654321"}),
        "au": ("AUD", "npp", {"scheme": "au_bsb", "bsb": "062000", "account": "12345678"},
               {"scheme": "au_bsb", "bsb": "033000", "account": "87654321"}),
        "in": ("INR", "neft", {"scheme": "in_ifsc", "ifsc": "HDFC0000001", "account": "50100012345678"},
               {"scheme": "in_ifsc", "ifsc": "SBIN0000300", "account": "00000012345678"}),
        "mx": ("MXN", "spei", {"scheme": "mx_clabe", "clabe": "012180000118359713"},
               {"scheme": "mx_clabe", "clabe": "002010077777777771"}),
        "us_swift": ("JPY", "wire", {"scheme": "us_aba", "routing": "011000015", "account": "000123456789"},
                     {"scheme": "swift", "bic": "MHCBJPJT", "account": "1234567"}),
        "sepa_instant": ("EUR", "sepa_instant", DEBTOR, BRENNER["account"]),
    }
    for name, (cur, rail, debtor, payee) in worlds.items():
        wm, wp, _ = local(cur, rail, debtor, payee)
        x = ISO.pain001(wm, wp)
        out.append({"name": name, "mandate": wm, "payment": wp, "decision": None, "xml": x,
                    "problems": ISO.pain001_problems(x, wm, wp)})
    tx = good[good.index("<CdtTrfTxInf>"):good.index("</CdtTrfTxInf>") + len("</CdtTrfTxInf>")]
    altered = {
        "amount_changed": good.replace(">18400.00</InstdAmt>", ">18400.01</InstdAmt>"),
        "currency_changed": good.replace('Ccy="EUR"', 'Ccy="USD"'),
        "creditor_changed": good.replace("AT611904300234573201", "LT121000011101001000"),
        "debtor_changed": good.replace("AT483200000012345864", "DE44500105175407324931"),
        "envelope_removed": good[:good.index("<SplmtryData>")] + good[good.index("</SplmtryData>") + 14:],
        "other_decision": good,
        "end_to_end_id_changed": good.replace("<EndToEndId>INV-2026-0912<", "<EndToEndId>INV-2026-0913<"),
        "duplicate_transaction": good.replace(tx, tx + tx),
        "doctype": good.replace("<Document", '<!DOCTYPE Document [<!ENTITY x "y">]><Document', 1),
        "cdata": good.replace("<Ustrd>", "<Ustrd><![CDATA[x]]>"),
        "processing_instruction": good.replace("<Document", "<?evil x?><Document", 1),
        "foreign_namespace_element": good.replace("<Cdtr>", '<Cdtr><e:IBAN xmlns:e="urn:evil">x</e:IBAN>'),
        "other_pain001_version": good.replace("pain.001.001.09", "pain.001.001.03"),
        "comment_inside_amount": good.replace(">18400.00</InstdAmt>", "><!-- c -->18400.00</InstdAmt>"),
        "numeric_entity": good.replace("<IBAN>AT61", "<IBAN>&#65;&#x54;61"),
        "unknown_entity": good.replace("Brenner", "&nbsp;Brenner"),
        "bare_ampersand": good.replace("&amp;", "&"),
        "truncated": good[:-20],
        "not_a_string": 42,
        "deep": good.replace("<Ustrd>", "<Ustrd>" + "<a>" * 70 + "</a>" * 70).replace("&lt;AG&gt;", ""),
        # Everything else must be what pain001 writes (third-party review of 0.4).
        "extra_transaction_to_attacker": good.replace(tx, tx + tx.replace(">INV-2026-0912<", ">INV-EVIL<")
                                                      .replace(">18400.00<", ">99999.00<")
                                                      .replace("AT611904300234573201", "LT121000011101001000")),
        "second_payment_block": good.replace("</PmtInf>", "</PmtInf>" + good[good.index("<PmtInf>"):
                                             good.index("</PmtInf>") + 9].replace(">INV-2026-0912<", ">X-2<")),
        "cheque_instead_of_transfer": good.replace("<PmtMtd>TRF<", "<PmtMtd>CHK<"),
        "intermediary_agent_added": good.replace("<CdtrAgt>", "<IntrmyAgt1><FinInstnId><BICFI>EVILXXXX</BICFI>"
                                                 "</FinInstnId></IntrmyAgt1><CdtrAgt>"),
        "control_sum_changed": good.replace("<CtrlSum>18400.00<", "<CtrlSum>99999.00<"),
        "service_level_changed": good.replace("<Cd>SEPA</Cd>", "<Cd>URGP</Cd>"),
        "attribute_added": good.replace("<Cdtr>", '<Cdtr a="1">'),
        "structured_remittance": good.replace("<RmtInf><Ustrd>", "<RmtInf><Strd/><Ustrd>"),
        "names_and_ids_changed": good.replace(">Acme Robotics GmbH<", ">ACME<").replace(
            "<MsgId>INV-2026-0912<", "<MsgId>ERP-77<").replace("<PmtInfId>INV-2026-0912<", "<PmtInfId>B-1<"),
        "remittance_removed": good[:good.index("<RmtInf>")] + good[good.index("</RmtInf>") + 9:],
        "pretty_printed": good.replace("><", ">\n  <"),
        "byte_order_mark_reference": good.replace(">18400.00</InstdAmt>", ">18400.00&#xFEFF;</InstdAmt>"),
        "next_line_reference": good.replace(">18400.00</InstdAmt>", ">18400.00&#x85;</InstdAmt>"),
        "bad_declaration": good.replace('<?xml version="1.0" encoding="UTF-8"?>', "<?xml garbage?>"),
        "double_dash_comment": good.replace("<Cdtr>", "<Cdtr><!-- a -- b -->"),
        "cdata_end_in_text": good.replace("<Ustrd>", "<Ustrd>]]>"),
        "empty_prefix_namespace": good.replace("<Cdtr>", '<Cdtr xmlns:p="">'),
    }
    other_d = {**d, "id": "d_other"}
    for name, x in altered.items():
        dd = other_d if name == "other_decision" else d
        out.append({"name": name, "mandate": m, "payment": p, "decision": dd, "xml": x,
                    "problems": ISO.pain001_problems(x, m, p, dd)})
    return out


def problem_cases() -> list[list[Any]]:
    """[kind, input, problem]: the exact messages both implementations give (third audit, F16)."""
    m = mandate(sign=False)
    p = pay(mandate(), "p_1")
    out: list[list[Any]] = []
    for sc in (scope(max_per_payment="1.0"), scope(currency="XAU"), scope(max_per_payment="it's"),
               scope(rails=["sepa", "it's", 'say "x"']),
               scope(from_accounts=[{"scheme": "it's"}]), scope(from_accounts=[{"scheme": "iban", "iban": "x"}]),
               scope(payees=[{"account": {"scheme": "us_aba", "routing": "021000021"}}])):
        mm = {**m, "scope": sc}
        out.append(["mandate", mm, M.mandate_problem(mm)])
    for extra in ({"valid_until": "2026-12-31T23:59:59+00:00"}, {"issued_at": "x\ny"}, {"status_url": "http://x"}):
        mm = {**m, **extra}
        out.append(["mandate", mm, M.mandate_problem(mm)])
    for extra in ({"rail": "telex"}, {"rail": "it's"}, {"amount": "1,00"}, {"currency": "€"},
                  {"from_account": {"scheme": "iban", "iban": "AT621904300234573201"}}):
        pp = {**p, **extra}
        out.append(["payment", pp, M.payment_problem(pp)])
    return out


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
        case("passkey_joint_signing_allow", joint, [pay(joint, "p_1")], authority=kyb, webauthn=WEBAUTHN),
    ]


def signer(sk: Ed25519PrivateKey = SIGNER, sid: str = SIGNER_ID) -> dict[str, Any]:
    return {"id": sid, "name": "K. Berger", "role": "Authorised signatory", "public_key": M.public_key_of(sk)}


def scope(**kw: Any) -> dict[str, Any]:
    s = {"rails": ["sepa", "sepa_instant"], "currency": "EUR", "max_per_payment": "25000.00",
         "max_per_period": {"amount": "40000.00", "period": "P1M"}, "payees": [BRENNER], "from_accounts": [DEBTOR]}
    s.update(kw)
    return {k: v for k, v in s.items() if v is not None}


def mandate(sk: Ed25519PrivateKey = SIGNER, sign: bool = True, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"v": "gleipnir/mandate/0.4", "id": "m_vec", "company": COMPANY,
                            "agent": {"id": "ap-agent", "public_key": M.public_key_of(AGENT)},
                            "signer": signer(sk), "scope": scope(), "valid_until": "2026-12-31T23:59:59.000Z",
                            "issued_at": "2026-10-01T08:00:00.000Z"}
    base.update(kw)
    base = {k: v for k, v in base.items() if v is not None}
    return M.sign_mandate(base, sk) if sign else base


def pay(m: dict, pid: str, amount: str = "100.00", *, payee: dict = BRENNER, rail: str = "sepa",
        currency: str = "EUR", agent: Ed25519PrivateKey | None = AGENT, at: str = NOW,
        frm: dict | None = None) -> dict[str, Any]:
    accounts = m.get("scope", {}).get("from_accounts") or [DEBTOR]
    return M.attach(m, id=pid, rail=rail, amount=amount, currency=currency, payee=payee,
                    from_account=frm or accounts[0], reference="INV-1", agent_sk=agent, requested_at=at)


def case(name: str, m: Any, payments: list[Any], *, now: str | list[str] = NOW, authority: list | None = None,
         revocations: list | None = None, status: Any = None, ledger: bool = True,
         webauthn: dict | None = None, mandates: list | None = None, which: list[int] | None = None,
         holds: list | None = None, ops: list | None = None, policy: dict | None = None,
         officers: list[str] | None = None, feed: Any = None) -> dict[str, Any]:
    """One checker, several steps. Step i checks payments[i] against mandates[which[i]] (default: the mandate),
    or, when ops[i] is a resolve op, applies an override to the decision of step ops[i]["of"].

    ``status``: None (no status client), "error" (unreachable), or the signed response the status client returns.
    ``holds``: the bank's accounts as {company, account}. ``policy``: {"require_payees": bool}.
    """
    extra: dict[str, Any] = {"mandates": mandates, "which": which} if mandates else {}
    if ops:
        extra["ops"] = ops
    if feed is not None:
        extra["feed"] = feed
    return {"name": name, "mandate": m, "payments": payments, "webauthn": webauthn or {}, **extra,
            "now": now if isinstance(now, list) else [now] * len(payments),
            "authority": KYB if authority is None else authority, "revocations": revocations or [],
            "status": status, "ledger": ledger, "holds": HOLDS if holds is None else holds,
            "policy": policy or {}, "officers": officers or []}


def cases() -> list[dict[str, Any]]:
    m = mandate()
    tampered = {**m, "scope": scope(max_per_payment="99999.00")}
    rev = M.revoke(m, signer=signer(), sk=SIGNER, id="r_1", revoked_at="2026-10-22T00:00:00.000Z")
    rev_other = M.revoke(m, signer=signer(OTHER, "intern@nordhafen.at"), sk=OTHER, id="r_2",
                         revoked_at="2026-10-22T00:00:00.000Z")
    rev_later = M.revoke(m, signer=signer(), sk=SIGNER, id="r_3", revoked_at="2026-10-24T00:00:00.000Z")
    weekly = mandate(scope=scope(max_per_period={"amount": "150.00", "period": "P7D"}))
    jpy = mandate(scope=scope(currency="JPY", max_per_payment="500000", max_per_period=None, rails=["wire"]))
    no_agent_key = mandate(agent={"id": "ap-agent"})
    status_m = mandate(status_url="https://bank.example/mandates/m_vec")
    active = M.status_response(status_m, status="active", signer=signer(), sk=SIGNER, at=NOW)
    revoked_st = M.status_response(status_m, status="revoked", signer=signer(), sk=SIGNER, at=NOW)
    other_payee = {"name": "Brenner Stahl AG", "account": {"scheme": "iban", "iban": "LT121000011101001000"}}
    bad_sig_payment = {**pay(m, "p_1"), "amount": "200.00"}
    acme = {"scheme": "us_aba", "routing": "021000021", "account": "123456789"}
    us_debtor = {"scheme": "us_aba", "routing": "011000015", "account": "000123456789"}
    us = mandate(scope=scope(rails=["ach"], currency="USD", max_per_period=None, from_accounts=[us_debtor],
                             payees=[{"name": "Acme", "account": acme}]))
    return [
        case("allow", m, [pay(m, "p_1", "18400.00")]),
        case("payee_not_on_mandate", m, [pay(m, "p_1", payee=other_payee)]),
        case("iban_not_canonical_malformed", m,
             [pay(m, "p_1", payee={"name": "x", "account": {"scheme": "iban", "iban": "at61 1904 3002 3457 3201"}})]),
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
        case("jpy_integer_amounts", jpy, [pay(jpy, "p_1", "120000", currency="JPY", rail="wire"),
                                          pay(jpy, "p_2", "1200.50", currency="JPY", rail="wire")]),
        case("us_account_fields", us, [pay(us, "p_1", "10.00", rail="ach", currency="USD",
                                           payee={"name": "Acme", "account": {"account": "123456789",
                                                                              "routing": "021000021",
                                                                              "scheme": "us_aba"}}),
                                       pay(us, "p_2", "10.00", rail="ach", currency="USD",
                                           payee={"name": "Acme", "account": {**acme, "extra": "1"}})],
             holds=[{"company": COMPANY["name"], "account": us_debtor}]),
        case("rail_not_allowed", m, [pay(m, "p_1", rail="wire")]),
        case("rail_mismatch_currency", m, [pay(m, "p_1", currency="USD")]),
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
        case("status_active", status_m, [pay(status_m, "p_1")], status=active),
        case("status_revoked", status_m, [pay(status_m, "p_1")], status=revoked_st),
        case("status_plain_text_not_accepted", status_m, [pay(status_m, "p_1")], status="active"),
        case("status_unreachable", status_m, [pay(status_m, "p_1")], status="error"),
        case("status_not_wired", status_m, [pay(status_m, "p_1")]),
        case("clock_skew", m, [pay(m, "p_1", at="2026-10-23T09:16:00.000Z"),
                               pay(m, "p_2", at="2026-10-23T09:15:02.000Z")]),
        case("payment_malformed", m, [{**pay(m, "p_1"), "amount": "1.5"}, {**pay(m, "p_2"), "amount": 100},
                                      {**pay(m, "p_3"), "requested_at": "2026-10-23T09:14Z"}, "not a payment",
                                      {**pay(m, "p_4"), "payee": {"name": "x", "account": {}}}]),
        case("mandate_malformed", {**m, "v": "gleipnir/mandate/0.2"}, [pay(m, "p_1")]),
        case("mandate_without_from_accounts", mandate(scope=scope(from_accounts=None, max_per_period=None)),
             [pay(m, "p_1")]),
        case("mandate_malformed_amount", mandate(sign=False, scope=scope(max_per_payment="25000")),
             [pay(m, "p_1")]),
        *v02_cases(),
    ]


def authority_fn(table: list[dict]) -> M.Authority:
    def authority(company: dict, signer_id: str) -> M.AuthorityResult | None:
        for row in table:
            if row["company"] == company.get("name") and row["signer"] == signer_id:
                return M.AuthorityResult(row["source"], tuple(row["keys"]), row["may_sign"], row.get("joint", 1),
                                         row.get("retired", {}), row.get("person"))
        return None
    return authority


def status_fn(value: Any):
    if value is None:
        return None

    def status(url: str) -> Any:
        if value == "error":
            raise ConnectionError(url)
        return value
    return status


def feed_fn(feed: Any, clock: dict):
    if feed is None:
        return None

    def revocations() -> list[dict]:
        if feed == "error":
            raise ConnectionError("revocation list unreachable")
        at = datetime.fromisoformat(clock["now"].replace("Z", "+00:00"))
        return M.revocations_from_list(feed["doc"], feed["keys"], at)
    return revocations


def holds_fn(rows: list[dict]):
    def holds(company: dict, account: dict) -> str | None:
        for r in rows:
            if r["company"] == company.get("name") and r["account"] == account:
                return r.get("customer", "cust:" + r["company"])
        return None
    return holds


def seed_key(seed_hex: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def build_override(spec: dict, decision: dict) -> dict:
    """An override as a resolve op describes it, signed with Ed25519 seeds (deterministic in both languages)."""
    o = M.make_override(decision, outcome=spec["outcome"], id=spec["id"], reason=spec.get("reason", ""),
                        decided_at=spec["decided_at"])
    if "decision_hash" in spec:
        o["decision"]["hash"] = spec["decision_hash"]
    for s in spec["signers"]:
        sk = seed_key(s["seed"])
        o = M.sign_override(o, sk, {"id": s["id"], "public_key": M.public_key_of(sk)})
    return o


def run(c: dict[str, Any]) -> list[dict[str, Any]]:
    """Run a vector through the Python reference; returns the decisions."""
    clock = {"now": c["now"][0]}
    checker = M.Checker(id="bank:VECTORS", sk=BANK, authority=authority_fn(c["authority"]),
                        holds=holds_fn(c["holds"]),
                        ledger=M.InMemoryLedger() if c["ledger"] else None, revocations=c["revocations"],
                        status=status_fn(c["status"]), webauthn=c.get("webauthn") or {},
                        require_payees=c["policy"].get("require_payees", False), officers=c["officers"],
                        revocation_feed=feed_fn(c.get("feed"), clock),
                        clock=lambda: datetime.fromisoformat(
                            clock["now"].replace("Z", "+00:00")))
    out: list[dict] = []
    mandates = c.get("mandates") or [c["mandate"]]
    which = c.get("which") or [0] * len(c["payments"])
    ops = c.get("ops") or ["check"] * len(c["payments"])
    for p, at, i, op in zip(c["payments"], c["now"], which, ops, strict=True):
        clock["now"] = at
        if op == "check":
            out.append(checker.check(mandates[i], p))
        else:
            d = out[op["resolve"]["of"]]
            out.append(checker.resolve(mandates[i], p, d, build_override(op["resolve"], d)))
    return out


def expected(decisions: list[dict]) -> list[dict[str, Any]]:
    """What a vector pins: everything but random parts. Decision ids are random, so an ``escalation`` reference
    becomes the step whose decision it names, and an ``override`` reference keeps its id (its hash covers the
    escalation's random id)."""
    first: dict[str, int] = {}
    rows = []
    for i, d in enumerate(decisions):
        row = {k: v for k, v in d.items() if k not in ("id", "sig")}
        if "escalation" in row:
            row["escalation"] = {"step": first.get(row["escalation"]["id"])}
        if "override" in row:
            row["override"] = {"id": row["override"]["id"]}
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
        first = (c.get("mandates") or [c["mandate"]])[(c.get("which") or [0])[0]]
        receipt = M.verify_receipt(first, c["payments"][0], decisions[0], [M.public_key_of(BANK)],
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
        "problems": problem_cases(),
        "keysets": keyset_cases(signed),
        "pain001": pain001_cases(),
        "payment_keys": [[cu, pid, M.payment_key(cu, pid)] for cu, pid in [
            ("cust:Alpha", "Beta|INV-1"), ("cust:Alpha|Beta", "INV-1"),
            ("Müller \"&\" Söhne", "INV-\u00e9"), ("X", "1")]],
    }


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
