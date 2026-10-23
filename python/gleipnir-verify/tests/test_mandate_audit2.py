"""Regression tests for the second external audit (23.10.2026 evening), findings F1-F16.

Each test runs the attack the auditor demonstrated and asserts it is now closed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from kit import DEBTOR, holds

from gleipnir_verify import mandate as M

NOW = datetime(2026, 10, 23, 9, 14, 2, tzinfo=timezone.utc)
CO = {"name": "Nordhafen Logistik GmbH", "country": "AT"}
BRENNER = {"name": "Brenner Stahl AG", "account": {"scheme": "iban", "iban": "AT611904300234573201"}}
UNTIL = "2026-12-31T23:59:59.000Z"


class K:
    def __init__(self) -> None:
        self.sk, self.pk = M.new_key()


@pytest.fixture()
def w():
    keys = {n: K() for n in ("ceo", "cfo", "berger", "agent", "bank", "evil")}
    people = {n: {"id": f"{n}@nordhafen.at", "public_key": keys[n].pk} for n in keys}
    kyb = {people["ceo"]["id"]: M.AuthorityResult("bank_kyb", (keys["ceo"].pk,)),
           people["cfo"]["id"]: M.AuthorityResult("bank_kyb", (keys["cfo"].pk,), may_sign=False),
           people["berger"]["id"]: M.AuthorityResult("bank_kyb", (keys["berger"].pk,))}
    return {"k": keys, "p": people, "kyb": kyb}


def bank(w, **kw):
    return M.Checker(id="bank:t", sk=w["k"]["bank"].sk, authority=lambda c, pid: w["kyb"].get(pid)
                     if c.get("name") == CO["name"] else None, ledger=kw.pop("ledger", M.InMemoryLedger()),
                     clock=lambda: NOW, holds=kw.pop("holds", holds), **kw)


def scope(**kw):
    s = {"rails": ["sepa"], "currency": "EUR", "max_per_payment": "200000.00",
         "max_per_period": {"amount": "200000.00", "period": "P1M"}, "payees": [BRENNER],
         "from_accounts": [DEBTOR], **kw}
    return {k: v for k, v in s.items() if v is not None}


def mandate(w, signer="berger", mid="m_1", company=CO, **kw):
    m = M.issue(id=mid, company=company, agent={"id": "agent", "public_key": w["k"]["agent"].pk},
                signer=w["p"][signer], scope=kw.pop("scope", None) or scope(), valid_until=UNTIL, **kw)
    return M.sign_mandate(m, w["k"][signer].sk)


def pay(w, m, pid, amount="100.00", agent="agent", **kw):
    return M.attach(m, id=pid, rail=kw.pop("rail", "sepa"), amount=amount, currency="EUR",
                    payee=kw.pop("payee", BRENNER), agent_sk=w["k"][agent].sk if agent else None,
                    requested_at=M.fmt_ts(NOW))


def link(w, **kw):
    return M.delegate(id="g1", company=CO, from_=w["p"]["ceo"], to=w["p"]["cfo"], sk=w["k"]["ceo"].sk,
                      scope=kw.pop("scope", None) or scope(payees=None), valid_until="2027-03-31T23:59:59.000Z", **kw)


def test_F1_delegated_period_limit_is_shared_by_all_mandates_under_the_link(w):
    g = link(w)
    b = bank(w)
    allowed = 0
    for i in range(5):
        m = mandate(w, "cfo", mid=f"m_{i}", delegation=[g], scope=scope(max_per_payment="150000.00"))
        allowed += b.check(m, pay(w, m, f"p_{i}", "150000.00"))["outcome"] == "allow"
    assert allowed == 1  # 150k of the 200k monthly delegation; the second 150k would exceed it
    # A failed link reservation gives back the mandate's own reservation (all or nothing).
    by_kind: dict[str, object] = {}
    for (key, _), v in b.ledger.totals.items():
        kind = key.split(":")[0]
        by_kind[kind] = by_kind.get(kind, 0) + v
    assert by_kind == {"mandate": M.parse_amount("150000.00", "EUR"), "delegation": M.parse_amount("150000.00", "EUR")}


def test_F4_unsigned_junk_cannot_burn_a_payment_id(w):
    b = bank(w)
    real = mandate(w)
    junk = M.issue(id="m_junk", company=CO, agent={"id": "x"}, signer={"id": "x", "public_key": w["k"]["evil"].pk},
                   scope=scope(), valid_until=UNTIL)  # never signed
    assert b.check(junk, pay(w, junk, "INV-7", agent=None))["outcome"] == "block"
    assert b.check(real, pay(w, real, "INV-7"))["outcome"] == "allow"


def test_F5_unsigned_copy_does_not_poison_the_signed_payment(w):
    b = bank(w)
    m = mandate(w)
    p = pay(w, m, "INV-8")
    unsigned = {k: v for k, v in p.items() if k != "agent_sig"}
    assert b.check(m, unsigned)["reasons"] == ["agent_bad_signature"]
    assert b.check(m, p)["outcome"] == "allow"


def test_F5_transient_failure_is_not_cached(w):
    up = {"ok": False}

    def kyb(company, pid):
        if not up["ok"]:
            raise TimeoutError
        return w["kyb"].get(pid)
    b = M.Checker(id="b", sk=w["k"]["bank"].sk, authority=kyb, ledger=M.InMemoryLedger(), clock=lambda: NOW,
                  holds=holds)
    m = mandate(w)
    p = pay(w, m, "INV-9")
    assert b.check(m, p)["reasons"] == ["checker_unavailable"]
    up["ok"] = True
    assert b.check(m, p)["outcome"] == "allow"
    s = mandate(w, mid="m_s", status_url="https://s.example")
    b.status = lambda url: (_ for _ in ()).throw(ConnectionError())
    ps = pay(w, s, "INV-10")
    assert b.check(s, ps)["reasons"] == ["status_unavailable"]
    b.status = lambda url: M.status_response(s, status="active", signer=w["p"]["berger"], sk=w["k"]["berger"].sk,
                                             at=M.fmt_ts(NOW))
    assert b.check(s, ps)["outcome"] == "allow"


def test_F5_final_decisions_are_still_idempotent(w):
    b = bank(w)
    m = mandate(w)
    p = pay(w, m, "INV-11")
    first = b.check(m, p)
    assert b.check(m, p) == first
    assert b.check(m, {**p, "amount": "1.00"})["reasons"] in (["duplicate_payment"], ["agent_bad_signature"])


def test_F6_same_mandate_id_at_another_company_does_not_share_the_ledger(w):
    b = bank(w)
    w["kyb"]["evil@nordhafen.at"] = M.AuthorityResult("bank_kyb", (w["k"]["evil"].pk,))
    other_co = {"name": "Nordhafen Logistik GmbH", "country": "AT"}  # same name is the worst case
    other = mandate(w, "evil", mid="m_1", company=other_co, scope=scope(max_per_payment="200000.00"))
    assert b.check(other, pay(w, other, "OTHER-1", "200000.00"))["outcome"] == "allow"
    mine = mandate(w, mid="m_1")
    assert b.check(mine, pay(w, mine, "MINE-1", "200000.00"))["outcome"] == "allow"


def test_F7_one_key_cannot_count_twice(w):
    k = w["k"]["berger"]
    with pytest.raises(ValueError, match="duplicate signer key"):
        M.issue(id="m_j", company=CO, agent={"id": "agent"}, valid_until=UNTIL, scope=scope(),
                signers={"threshold": 2, "of": [{"id": "a@x", "public_key": k.pk}, {"id": "b@x", "public_key": k.pk}]})


@pytest.mark.parametrize("bad", [{"may_sign": None}, {"may_sign": "yes"}, {"joint": "2"}, {"joint": True},
                                 {"keys": "ed25519:x"}])
def test_F10_odd_authority_answers_fail_closed(w, bad):
    base = {"source": "bank_kyb", "keys": (w["k"]["berger"].pk,), "may_sign": True, "joint": 1}
    res = M.AuthorityResult(**{**base, **bad})
    b = M.Checker(id="b", sk=w["k"]["bank"].sk, authority=lambda c, pid: res, ledger=M.InMemoryLedger(),
                  clock=lambda: NOW)
    m = mandate(w)
    assert b.check(m, pay(w, m, "p"))["reasons"] == ["checker_unavailable"]


def test_F11_unknown_rail_is_malformed(w):
    m = mandate(w, scope=scope(rails=None))
    assert bank(w).check(m, pay(w, m, "p", rail="bitcoin"))["reasons"] == ["payment_malformed"]


@pytest.mark.parametrize("value", [2.0, 1.5, 2 ** 60, -(2 ** 60)])
def test_F3_numbers_outside_i_json_are_malformed(w, value):
    m = M.issue(id="m", company=CO, agent={"id": "a"}, signer=w["p"]["berger"], scope=scope(), valid_until=UNTIL)
    assert M.mandate_problem({**m, "x": value}) == "mandate is not valid I-JSON"
    assert M.mandate_problem({**m, "x": {"deep": [value]}}) == "mandate is not valid I-JSON"
    js = {**m, "signers": {"threshold": value, "of": [w["p"]["berger"]]}}
    del js["signer"]
    assert M.mandate_problem(js) is not None


@pytest.mark.parametrize("account", [{"routing": 21000021}, {"routing": "021000021", "nested": {"a": "b"}},
                                     {"scheme": "iban", "iban": "AT61ƕ1904"}, {"scheme": "iban", "iban": ""}])
def test_F3_F16_account_fields_are_ascii_strings(w, account):
    assert M.mandate_problem({**mandate(w), "scope": scope(payees=[{"name": "x", "account": account}])}) is not None
    m = mandate(w, scope=scope(payees=None))
    p = M.attach(m, id="p", rail="sepa", amount="1.00", currency="EUR", payee={"account": account})
    assert M.payment_problem(p) is not None


def test_F13_country_and_link_company_and_parent_id(w):
    with pytest.raises(ValueError, match="alpha-2"):
        mandate(w, company={"name": CO["name"], "country": "Austria"})
    g = M.delegate(id="g1", company={"name": CO["name"], "country": "DE"}, from_=w["p"]["ceo"], to=w["p"]["cfo"],
                   sk=w["k"]["ceo"].sk, scope=scope(payees=None), valid_until="2027-03-31T23:59:59.000Z")
    m = mandate(w, "cfo", delegation=[g])
    assert bank(w).check(m, pay(w, m, "p"))["reasons"] == ["delegation_broken"]
    g1 = link(w)
    w["kyb"]["berger@nordhafen.at"] = M.AuthorityResult("bank_kyb", (w["k"]["berger"].pk,), may_sign=False)
    g2 = M.delegate(id="g2", company=CO, from_=w["p"]["cfo"], to=w["p"]["berger"], sk=w["k"]["cfo"].sk,
                    scope=scope(payees=None), valid_until="2027-01-31T23:59:59.000Z", parent=g1)
    wrong_id = M._sign(w["k"]["cfo"].sk, "delegation", {**g2, "parent": {**g2["parent"], "id": "g_other"}})
    m2 = mandate(w, "berger", mid="m_2", delegation=[g1, wrong_id])
    assert bank(w).check(m2, pay(w, m2, "p2"))["reasons"] == ["delegation_broken"]
    ok = mandate(w, "berger", mid="m_3", delegation=[g1, g2])
    assert bank(w).check(ok, pay(w, ok, "p3"))["outcome"] == "allow"


def test_F14_a_delegate_below_cannot_cut_the_link_above(w):
    g1 = link(w)
    w["kyb"]["berger@nordhafen.at"] = M.AuthorityResult("bank_kyb", (w["k"]["berger"].pk,), may_sign=False)
    g2 = M.delegate(id="g2", company=CO, from_=w["p"]["cfo"], to=w["p"]["berger"], sk=w["k"]["cfo"].sk,
                    scope=scope(payees=None), valid_until="2027-01-31T23:59:59.000Z", parent=g1)
    m = mandate(w, "berger", delegation=[g1, g2])
    b = bank(w, revocations=[M.revoke(g1, signer=w["p"]["berger"], sk=w["k"]["berger"].sk, id="r",
                                      revoked_at="2026-10-01T00:00:00.000Z")])
    assert b.check(m, pay(w, m, "p"))["outcome"] == "allow"  # ignored: Berger is below g1
    b.revocations = [M.revoke(g2, signer=w["p"]["berger"], sk=w["k"]["berger"].sk, id="r2",
                              revoked_at="2026-10-01T00:00:00.000Z")]
    assert b.check(m, pay(w, m, "p2"))["reasons"] == ["delegation_revoked"]  # his own link: honoured


def test_N1_payment_keys_cannot_be_crafted_to_collide():
    a = M.payment_key({"name": "Alpha", "country": "AT"}, "Beta|INV-1")
    b = M.payment_key({"name": "Alpha|Beta", "country": "AT"}, "INV-1")
    assert a != b


def test_R2_time_dependent_blocks_are_not_cached(w):
    clock = {"t": datetime(2026, 10, 31, 23, 59, 40, tzinfo=timezone.utc)}
    b = M.Checker(id="b", sk=w["k"]["bank"].sk, authority=lambda c, pid: w["kyb"].get(pid),
                  ledger=M.InMemoryLedger(), clock=lambda: clock["t"], max_skew=timedelta(days=2), holds=holds)
    m = mandate(w, valid_from="2026-11-01T00:00:00.000Z")
    p = M.attach(m, id="p", rail="sepa", amount="100.00", currency="EUR", payee=BRENNER, agent_sk=w["k"]["agent"].sk,
                 requested_at="2026-10-31T23:59:40.000Z")
    assert b.check(m, p)["reasons"] == ["mandate_not_yet_valid"]
    clock["t"] = datetime(2026, 11, 1, 0, 0, 20, tzinfo=timezone.utc)
    assert b.check(m, p)["outcome"] == "allow"
