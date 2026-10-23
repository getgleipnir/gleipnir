from decimal import Decimal

import pytest

from gleipnir_verify import mandate as M

IBAN = "AT611904300234573201"


@pytest.fixture
def world():
    signer_sk, signer_pk = M.new_key()
    agent_sk, agent_pk = M.new_key()
    bank_sk, _ = M.new_key()
    m = M.issue(
        id="m_1",
        company={"name": "Nordhafen Logistik GmbH", "country": "AT"},
        agent={"id": "ap-agent", "public_key": agent_pk},
        signer={"id": "kberger@nordhafen.at", "name": "K. Berger", "public_key": signer_pk},
        scope={"rails": ["sepa"], "currency": "EUR", "max_per_payment": "25000.00",
               "max_per_period": {"amount": "30000.00", "period": "P1M"},
               "payees": [{"name": "Brenner Stahl AG", "account": {"iban": IBAN}}]},
        valid_from="2026-01-01T00:00:00.000Z", valid_until="2099-01-01T00:00:00.000Z",
    )
    m = M.sign_mandate(m, signer_sk)
    kyb = {"kberger@nordhafen.at": signer_pk}
    checker = M.Checker(id="bank:TEST", sk=bank_sk,
                        authority=lambda c, s: "bank_kyb" if kyb.get(s["id"]) == s["public_key"] else None)

    def pay(amount="18400.00", iban=IBAN, sk=agent_sk, **kw):
        return M.attach(m, id="p_1", rail=kw.get("rail", "sepa"), amount=amount, currency="EUR",
                        payee={"name": "Brenner", "account": {"iban": iban}}, agent_sk=sk)

    return m, checker, pay, signer_sk, signer_pk


def test_allow_and_decision_verifies(world):
    m, checker, pay, *_ = world
    d = checker.check(m, pay())
    assert d["outcome"] == "allow", d
    assert "signer_authorized:bank_kyb" in d["checks"]
    assert M.verify_decision(d)
    d["outcome"] = "block"
    assert not M.verify_decision(d)


def test_new_iban_blocked(world):
    m, checker, pay, *_ = world
    d = checker.check(m, pay(iban="DE89370400440532013000"))
    assert (d["outcome"], d["reasons"]) == ("block", ["payee_not_on_mandate"])


def test_iban_spacing_normalized(world):
    m, checker, pay, *_ = world
    assert checker.check(m, pay(iban="at61 1904 3002 3457 3201"))["outcome"] == "allow"


def test_over_limit_escalates(world):
    m, checker, pay, *_ = world
    assert checker.check(m, pay(amount="25000.01"))["reasons"] == ["over_payment_limit"]
    checker.spent = lambda *_: Decimal("20000")
    d = checker.check(m, pay())
    assert (d["outcome"], d["reasons"]) == ("escalate", ["over_period_limit"])


def test_tampered_mandate(world):
    m, checker, pay, *_ = world
    p = pay()
    m2 = {**m, "scope": {**m["scope"], "max_per_payment": "999999.00"}}
    assert checker.check(m2, p)["reasons"] == ["mandate_mismatch"]
    p2 = M.attach(m2, id="p_2", rail="sepa", amount="1.00", currency="EUR",
                  payee={"account": {"iban": IBAN}}, agent_sk=None)
    assert checker.check(m2, p2)["reasons"] == ["mandate_bad_signature"]


def test_unknown_signer_escalates(world):
    m, checker, pay, *_ = world
    checker.authority = lambda c, s: None
    assert checker.check(m, pay())["outcome"] == "escalate"
    checker.authority = lambda c, s: False
    assert checker.check(m, pay())["reasons"] == ["signer_not_authorized"]


def test_agent_signature_required(world):
    m, checker, pay, *_ = world
    other, _ = M.new_key()
    assert checker.check(m, pay(sk=other))["reasons"] == ["agent_bad_signature"]
    assert checker.check(m, pay(sk=None))["reasons"] == ["agent_bad_signature"]


def test_revocation(world):
    m, checker, pay, signer_sk, signer_pk = world
    r = M.revoke(m, signer={"id": "kberger@nordhafen.at", "public_key": signer_pk}, sk=signer_sk, id="r_1",
                 revoked_at="2026-01-02T00:00:00.000Z")
    checker.revocations.append(r)
    assert checker.check(m, pay())["reasons"] == ["mandate_revoked"]


def test_forged_revocation_ignored(world):
    m, checker, pay, _, signer_pk = world
    evil, _ = M.new_key()
    r = M.revoke(m, signer={"id": "kberger@nordhafen.at", "public_key": signer_pk}, sk=evil, id="r_x")
    checker.revocations.append(r)
    assert checker.check(m, pay())["outcome"] == "allow"


def test_status_url_unreachable_escalates(world):
    _, checker, _, signer_sk, signer_pk = world
    m = M.sign_mandate(M.issue(id="m_2", company={"name": "X", "country": "AT"}, agent={"id": "a"},
                               signer={"id": "kberger@nordhafen.at", "public_key": signer_pk},
                               scope={"currency": "EUR", "max_per_payment": "10.00"},
                               valid_until="2099-01-01T00:00:00.000Z", status_url="https://x/status"), signer_sk)
    p = M.attach(m, id="p", rail="ach", amount="5.00", currency="EUR", payee={"account": {"iban": IBAN}})

    def down(_):
        raise OSError

    checker.status = down
    assert checker.check(m, p)["reasons"] == ["status_unavailable"]
    checker.status = lambda _: "active"
    assert checker.check(m, p)["outcome"] == "allow"


def test_issue_rejects_float_amounts():
    with pytest.raises(ValueError):
        M.issue(id="m", company={"name": "X", "country": "AT"}, agent={"id": "a"},
                signer={"id": "s", "public_key": "ed25519:x"}, scope={"currency": "EUR", "max_per_payment": 10.0},
                valid_until="2099-01-01T00:00:00.000Z")
