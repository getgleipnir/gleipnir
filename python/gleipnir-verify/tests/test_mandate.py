import itertools
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from kit import DEBTOR, holds

from gleipnir_verify import mandate as M

IBAN = "AT611904300234573201"
NOW = datetime(2026, 10, 23, 9, 14, 2, tzinfo=timezone.utc)
REQ = "2026-10-23T09:14:02.000Z"
_ids = itertools.count()


@pytest.fixture
def world():
    signer_sk, signer_pk = M.new_key()
    agent_sk, agent_pk = M.new_key()
    bank_sk, bank_pk = M.new_key()
    m = M.issue(
        id="m_1",
        company={"name": "Nordhafen Logistik GmbH", "country": "AT"},
        agent={"id": "ap-agent", "public_key": agent_pk},
        signer={"id": "kberger@nordhafen.at", "name": "K. Berger", "public_key": signer_pk},
        scope={"rails": ["sepa"], "currency": "EUR", "max_per_payment": "25000.00",
               "max_per_period": {"amount": "30000.00", "period": "P1M"},
               "payees": [{"name": "Brenner Stahl AG", "account": {"scheme": "iban", "iban": IBAN}}],
               "from_accounts": [DEBTOR]},
        valid_from="2026-01-01T00:00:00.000Z", valid_until="2099-01-01T00:00:00.000Z",
    )
    m = M.sign_mandate(m, signer_sk)
    kyb = {"kberger@nordhafen.at": (signer_pk,)}
    checker = M.Checker(id="bank:TEST", sk=bank_sk, ledger=M.InMemoryLedger(), clock=lambda: NOW, holds=holds,
                        authority=lambda c, sid: M.AuthorityResult("bank_kyb", kyb[sid]) if sid in kyb else None)

    def pay(amount="18400.00", iban=IBAN, sk=agent_sk, mandate=None, **kw):
        return M.attach(mandate or m, id=kw.get("id") or f"p_{next(_ids)}", rail=kw.get("rail", "sepa"),
                        amount=amount, currency=kw.get("currency", "EUR"),
                        payee={"name": "Brenner", "account": kw.get("account") or {"scheme": "iban", "iban": iban}},
                        agent_sk=sk,
                        requested_at=kw.get("requested_at", REQ))

    return m, checker, pay, signer_sk, signer_pk, bank_pk


def test_allow_and_decision_verifies(world):
    m, checker, pay, *_, bank_pk = world
    d = checker.check(m, pay())
    assert d["outcome"] == "allow", d
    assert "signer_authorized:bank_kyb" in d["checks"]
    assert d["checked_at"] == REQ
    assert M.verify_decision(d, [bank_pk])
    d["outcome"] = "block"
    assert not M.verify_decision(d, [bank_pk])


def test_new_iban_blocked(world):
    m, checker, pay, *_ = world
    d = checker.check(m, pay(iban="DE89370400440532013000"))
    assert (d["outcome"], d["reasons"]) == ("block", ["payee_not_on_mandate"])


def test_iban_must_be_canonical(world):
    m, checker, pay, *_ = world
    # Accounts are compared exactly, so only the canonical form is accepted on the wire; producers normalize.
    assert checker.check(m, pay(iban="at61 1904 3002 3457 3201"))["reasons"] == ["payment_malformed"]
    assert M.iban("at61 1904 3002 3457 3201") == {"scheme": "iban", "iban": IBAN}
    assert checker.check(m, pay(account=M.iban("at61 1904 3002 3457 3201")))["outcome"] == "allow"


def test_over_limit_escalates(world):
    m, checker, pay, *_ = world
    assert checker.check(m, pay(amount="25000.01"))["reasons"] == ["over_payment_limit"]
    assert checker.check(m, pay(amount="20000.00"))["outcome"] == "allow"
    d = checker.check(m, pay(amount="10000.01"))
    assert (d["outcome"], d["reasons"]) == ("escalate", ["over_period_limit"])
    assert checker.check(m, pay(amount="10000.00"))["outcome"] == "allow"


def test_tampered_mandate(world):
    m, checker, pay, *_ = world
    p = pay()
    m2 = {**m, "scope": {**m["scope"], "max_per_payment": "999999.00"}}
    assert checker.check(m2, p)["reasons"] == ["mandate_mismatch"]
    p2 = M.attach(m2, id="p_t2", rail="sepa", amount="1.00", currency="EUR",
                  payee={"account": {"scheme": "iban", "iban": IBAN}}, agent_sk=None, requested_at=REQ)
    assert checker.check(m2, p2)["reasons"] == ["mandate_bad_signature"]


def test_unknown_signer_escalates(world):
    m, checker, pay, *_ = world
    checker.authority = lambda c, sid: None
    assert checker.check(m, pay())["outcome"] == "escalate"
    checker.authority = lambda c, sid: M.AuthorityResult("register", ("ed25519:other",), may_sign=False)
    assert checker.check(m, pay())["reasons"] == ["signer_not_authorized"]


def test_signer_key_must_come_from_the_source(world):
    m, checker, pay, *_ = world
    checker.authority = lambda c, sid: M.AuthorityResult("bank_kyb", (M.new_key()[1],))
    assert checker.check(m, pay())["reasons"] == ["signer_not_authorized"]


def test_authority_failures_never_allow(world):
    m, checker, pay, *_ = world

    def down(*_):
        raise OSError

    checker.authority = down
    assert checker.check(m, pay())["reasons"] == ["checker_unavailable"]
    checker.authority = lambda c, sid: "bank_kyb"  # old contract: rejected
    assert checker.check(m, pay())["reasons"] == ["checker_unavailable"]


def test_agent_signature_required(world):
    m, checker, pay, *_ = world
    other, _ = M.new_key()
    assert checker.check(m, pay(sk=other))["reasons"] == ["agent_bad_signature"]
    assert checker.check(m, pay(sk=None))["reasons"] == ["agent_bad_signature"]


def test_revocation(world):
    m, checker, pay, signer_sk, signer_pk, _ = world
    r = M.revoke(m, signer={"id": "kberger@nordhafen.at", "public_key": signer_pk}, sk=signer_sk, id="r_1",
                 revoked_at="2026-01-02T00:00:00.000Z", reason="Agent replaced")
    checker.revocations.append(r)
    assert checker.check(m, pay())["reasons"] == ["mandate_revoked"]


def test_future_revocation_applies_from_bank_time(world):
    m, checker, pay, signer_sk, signer_pk, _ = world
    r = M.revoke(m, signer={"id": "kberger@nordhafen.at", "public_key": signer_pk}, sk=signer_sk, id="r_1",
                 revoked_at="2026-10-24T00:00:00.000Z")
    checker.revocations.append(r)
    assert checker.check(m, pay())["outcome"] == "allow"
    checker.clock = lambda: datetime(2026, 10, 24, 0, 0, 1, tzinfo=timezone.utc)
    assert checker.check(m, pay(requested_at="2026-10-24T00:00:01.000Z"))["reasons"] == ["mandate_revoked"]


def test_revocation_with_unreachable_authority_escalates(world):
    m, checker, pay, signer_sk, signer_pk, _ = world
    r = M.revoke(m, signer={"id": "x@nordhafen.at", "public_key": signer_pk}, sk=signer_sk, id="r_1",
                 revoked_at="2026-01-02T00:00:00.000Z")
    checker.revocations.append(r)
    base = checker.authority

    def flaky(c, sid):
        if sid == "x@nordhafen.at":
            raise OSError
        return base(c, sid)

    checker.authority = flaky
    assert checker.check(m, pay())["reasons"] == ["checker_unavailable"]


def test_forged_revocation_ignored(world):
    m, checker, pay, _, signer_pk, _ = world
    evil, _ = M.new_key()
    r = M.revoke(m, signer={"id": "kberger@nordhafen.at", "public_key": signer_pk}, sk=evil, id="r_x")
    checker.revocations.append(r)
    assert checker.check(m, pay())["outcome"] == "allow"


def _status_mandate(signer_sk, signer_pk):
    return M.sign_mandate(M.issue(id="m_2", company={"name": "X", "country": "AT"}, agent={"id": "a"},
                                  signer={"id": "kberger@nordhafen.at", "public_key": signer_pk},
                                  scope={"currency": "EUR", "max_per_payment": "10.00", "from_accounts": [DEBTOR]},
                                  valid_until="2099-01-01T00:00:00.000Z", status_url="https://x.example/status"),
                          signer_sk)


def test_status_url(world):
    _, checker, _, signer_sk, signer_pk, _ = world
    m = _status_mandate(signer_sk, signer_pk)
    me = {"id": "kberger@nordhafen.at", "public_key": signer_pk}

    def p():
        return M.attach(m, id=f"p_{next(_ids)}", rail="sepa", amount="5.00", currency="EUR",
                        payee={"account": {"scheme": "iban", "iban": IBAN}}, requested_at=REQ)

    def answer(status, **kw):
        return M.status_response(m, status=status, signer=kw.get("signer", me), sk=kw.get("sk", signer_sk),
                                 at=kw.get("at", REQ))

    assert checker.check(m, p())["reasons"] == ["status_unavailable"]  # no status client

    def down(_):
        raise OSError

    checker.status = down
    assert checker.check(m, p())["reasons"] == ["status_unavailable"]
    checker.status = lambda _: answer("revoked")
    assert checker.check(m, p())["reasons"] == ["mandate_revoked"]
    checker.status = lambda _: "active"  # 0.2 plain text: no longer an answer
    assert checker.check(m, p())["reasons"] == ["status_unavailable"]
    checker.status = lambda _: answer("active")
    d = checker.check(m, p())
    assert d["outcome"] == "allow" and "status_active" in d["checks"]


def test_status_response_must_be_signed_fresh_and_about_this_mandate(world):
    _, checker, _, signer_sk, signer_pk, _ = world
    m = _status_mandate(signer_sk, signer_pk)
    me = {"id": "kberger@nordhafen.at", "public_key": signer_pk}
    evil_sk, evil_pk = M.new_key()

    def p():
        return M.attach(m, id=f"p_{next(_ids)}", rail="sepa", amount="5.00", currency="EUR",
                        payee={"account": {"scheme": "iban", "iban": IBAN}}, requested_at=REQ)

    good = M.status_response(m, status="active", signer=me, sk=signer_sk, at=REQ)
    bad = {
        "forged": M.status_response(m, status="active", signer=me, sk=evil_sk, at=REQ),
        "stranger": M.status_response(m, status="active", signer={"id": "evil", "public_key": evil_pk},
                                      sk=evil_sk, at=REQ),
        "stale": M.status_response(m, status="active", signer=me, sk=signer_sk, at="2026-10-23T09:00:00.000Z"),
        "future": M.status_response(m, status="active", signer=me, sk=signer_sk, at="2026-10-23T09:20:00.000Z"),
        "other_mandate": {**good, "mandate": {"id": "m_2", "hash": "sha256:" + "0" * 64}},
        "edited": {**good, "status": "revoked"},
        "garbage": {"status": "active"},
    }
    for name, answer in bad.items():
        checker.status = lambda _, a=answer: a
        assert checker.check(m, p())["reasons"] == ["status_unavailable"], name
    checker.status = lambda _: good
    assert checker.check(m, p())["outcome"] == "allow"
    # A delegate known to the bank but outside this mandate's line of authority cannot vouch for it.
    base = checker.authority
    checker.authority = lambda c, sid: (M.AuthorityResult("bank_kyb", (evil_pk,), may_sign=False)
                                        if sid == "evil" else base(c, sid))
    checker.status = lambda _: bad["stranger"]
    assert checker.check(m, p())["reasons"] == ["status_unavailable"]


def test_status_url_must_be_https(world):
    _, _, _, signer_sk, signer_pk, _ = world
    with pytest.raises(ValueError, match="https"):
        M.issue(id="m_2", company={"name": "X", "country": "AT"}, agent={"id": "a"},
                signer={"id": "k", "public_key": signer_pk},
                scope={"currency": "EUR", "max_per_payment": "10.00", "from_accounts": [DEBTOR]},
                valid_until="2099-01-01T00:00:00.000Z", status_url="http://x.example/status")


def test_validity_window_uses_bank_clock(world):
    m, checker, pay, *_ = world
    checker.clock = lambda: datetime(2025, 12, 31, 12, 0, tzinfo=timezone.utc)
    assert checker.check(m, pay(requested_at="2025-12-31T12:00:00.000Z"))["reasons"] == ["mandate_not_yet_valid"]
    checker.clock = lambda: datetime(2099, 1, 2, tzinfo=timezone.utc)
    assert checker.check(m, pay(requested_at="2099-01-02T00:00:00.000Z"))["reasons"] == ["mandate_expired"]


def test_clock_skew(world):
    m, checker, pay, *_ = world
    ok = pay(amount="100.00", requested_at="2026-10-23T09:15:02.000Z")  # exactly 60 s
    assert checker.check(m, ok)["outcome"] == "allow"
    assert checker.check(m, pay(requested_at="2026-10-23T09:15:03.000Z"))["reasons"] == ["clock_skew"]
    checker.max_skew = timedelta(minutes=5)
    assert checker.check(m, pay(amount="100.00", requested_at="2026-10-23T09:19:00.000Z"))["outcome"] == "allow"


def test_rail_and_currency(world):
    m, checker, pay, *_ = world
    assert checker.check(m, pay(rail="wire"))["reasons"] == ["rail_not_allowed"]
    # SEPA carries EUR between IBANs only: anything else cannot be executed on that rail at all.
    assert checker.check(m, pay(currency="USD"))["reasons"] == ["rail_mismatch"]
    assert checker.check(m, pay(account={"scheme": "uk_sort_code", "sort_code": "601613", "account": "31926819"}))[
        "reasons"] == ["rail_mismatch"]


def test_idempotent_retry_and_duplicate(world):
    m, checker, pay, *_ = world
    p = pay(id="p_same")
    d1 = checker.check(m, p)
    assert checker.check(m, p) == d1
    assert checker.check(m, pay(id="p_same", amount="1.00"))["reasons"] == ["duplicate_payment"]


def test_payment_log_and_ledger_failures(world):
    m, checker, pay, *_ = world

    class Down:
        def seen(self, *_):
            raise OSError

        def reserve(self, *_):
            raise OSError

        def remember(self, *_):
            raise OSError

    checker.payments = Down()
    assert checker.check(m, pay())["reasons"] == ["checker_unavailable"]
    checker.payments = M.InMemoryPaymentLog()
    checker.ledger = Down()
    assert checker.check(m, pay())["reasons"] == ["checker_unavailable"]
    checker.ledger = None
    assert checker.check(m, pay())["reasons"] == ["ledger_missing"]


def test_remember_failure_keeps_decision(world):
    m, checker, pay, *_ = world

    class Log(M.InMemoryPaymentLog):
        def remember(self, *_):
            raise OSError

    checker.payments = Log()
    assert checker.check(m, pay())["outcome"] == "allow"


def test_us_account_and_jpy():
    signer_sk, signer_pk = M.new_key()
    acme = M.account("us_aba", routing="011000015", account="000123456789")
    supplier = M.account("us_aba", routing="021000021", account="1234 5678")
    m = M.sign_mandate(M.issue(id="m_us", company={"name": "Acme Inc", "country": "US"}, agent={"id": "a"},
                               signer={"id": "cfo@acme", "public_key": signer_pk},
                               scope={"rails": ["ach", "wire"], "currency": "USD", "max_per_payment": "500.00",
                                      "payees": [{"account": supplier}], "from_accounts": [acme]},
                               valid_until="2099-01-01T00:00:00.000Z"), signer_sk)
    checker = M.Checker(id="bank:US", sk=M.new_key()[0], clock=lambda: NOW, holds=lambda c, a: a == acme,
                        authority=lambda c, sid: M.AuthorityResult("bank_kyb", (signer_pk,)))
    p = M.attach(m, id="p_us", rail="ach", amount="10.00", currency="USD",
                 payee={"account": {"scheme": "us_aba", "account": "12345678", "routing": "021000021"}},
                 requested_at=REQ)
    assert checker.check(m, p)["outcome"] == "allow"
    eur = M.attach(m, id="p_us2", rail="wire", amount="10.00", currency="EUR", payee={"account": supplier},
                   requested_at=REQ)
    assert checker.check(m, eur)["reasons"] == ["currency_mismatch"]  # wire carries any currency, not this mandate
    assert M.parse_amount("1500", "JPY") == Decimal(1500)
    with pytest.raises(ValueError):
        M.parse_amount("1500.00", "JPY")


def test_ledger_periods():
    led = M.InMemoryLedger()
    at = datetime(2026, 10, 23, tzinfo=timezone.utc)
    for period in ("P1D", "P7D", "P1M"):
        assert led.reserve("m", period, Decimal("60"), Decimal("100"), at)
        assert not led.reserve("m", period, Decimal("60"), Decimal("100"), at)
        led.release("m", period, Decimal("60"), at)
        assert led.reserve("m", period, Decimal("60"), Decimal("100"), at)
    assert M.period_key("P7D", at) == "2026-W43"
    with pytest.raises(ValueError):
        M.period_key("P1Y", at)


def test_passkey_challenge(world):
    m = world[0]
    assert len(M.passkey_challenge(m)) == 32


@pytest.mark.parametrize("bad, problem", [
    ({"scope": {"currency": "EUR", "max_per_payment": "10.00", "max_per_period": "x"}}, "max_per_period"),
    ({"scope": {"currency": "EUR", "max_per_payment": "10.00", "rails": "sepa"}}, "rails must be"),
    ({"scope": {"currency": "EUR", "max_per_payment": "10.00", "rails": ["telex"]}}, "unknown rails"),
    ({"scope": {"currency": "EUR", "max_per_payment": "10.00", "payees": [{}]}}, "payees"),
    ({"scope": {"currency": "XXX", "max_per_payment": "10.00"}}, "unsupported currency"),
    ({"valid_from": "2099-02-01T00:00:00.000Z"}, "valid_from is after"),
    ({"valid_until": "tomorrow"}, "bad timestamp"),
    ({"status_url": 5}, "status_url"),
    ({"status_url": "http://x.example/s"}, "https"),
    ({"scope": {"currency": "EUR", "max_per_payment": "10.00", "from_accounts": []}}, "from_accounts"),
    ({"issued_at": "yesterday"}, "bad timestamp"),
    ({"company": {"name": "X", "country": "AT", "n": float("nan")}}, "I-JSON"),
    ({"v": "gleipnir/mandate/9"}, "unknown mandate version"),
])
def test_mandate_problems(bad, problem):
    m = {"v": "gleipnir/mandate/0.3", "id": "m", "company": {"name": "X", "country": "AT"}, "agent": {"id": "a"},
         "signer": {"id": "s", "public_key": "ed25519:x"},
         "valid_until": "2099-01-01T00:00:00.000Z", "issued_at": "2026-01-01T00:00:00.000Z", **bad}
    m["scope"] = {"from_accounts": [DEBTOR], **m.get("scope", {"currency": "EUR", "max_per_payment": "10.00"})}
    assert problem in M.mandate_problem(m)


def test_payment_problems(world):
    m, checker, pay, *_ = world
    good = pay()
    assert M.payment_problem(good) is None
    assert "payee.account" in M.payment_problem({**good, "payee": {"account": {}}})
    assert "bad timestamp" in M.payment_problem({**good, "requested_at": "now"})
    assert "unknown payment version" in M.payment_problem({**good, "v": "x"})
    assert M.revocation_problem({"v": "x"}) == "unknown revocation version"
    r = {"v": "gleipnir/revocation/0.3", "id": "r", "mandate": "m", "mandate_hash": "h", "revoked_at": "x",
         "signer": {"id": "s", "public_key": "k"}}
    assert "bad timestamp" in M.revocation_problem(r)
    assert "I-JSON" in M.revocation_problem({**r, "revoked_at": "2026-01-01T00:00:00.000Z", "x": float("inf")})


def test_unexpected_error_blocks(world):
    m, checker, pay, *_ = world

    class Weird(dict):
        def __getitem__(self, k):
            if k == "amount":
                raise RuntimeError("boom")
            return super().__getitem__(k)

    p = Weird(pay())
    d = checker.check(m, p)
    assert d["outcome"] == "block"


def test_verify_decision_rejects_garbage():
    assert not M.verify_decision(None, ["ed25519:x"])
    assert not M.verify_decision({"checker": {"public_key": "ed25519:x"}}, ["ed25519:x"])


def test_issue_rejects_float_amounts():
    with pytest.raises(ValueError):
        M.issue(id="m", company={"name": "X", "country": "AT"}, agent={"id": "a"},
                signer={"id": "s", "public_key": "ed25519:x"},
                scope={"currency": "EUR", "max_per_payment": 10.0, "from_accounts": [DEBTOR]},
                valid_until="2099-01-01T00:00:00.000Z")
