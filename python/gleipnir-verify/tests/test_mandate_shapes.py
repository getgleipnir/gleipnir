"""Malformed multi-signature, delegation, revocation, account, status and override shapes are rejected, never crash."""

from __future__ import annotations

import pytest
from kit import DEBTOR, holds

from gleipnir_verify import mandate as M

SK, PK = M.new_key()
P = {"id": "a@x", "public_key": PK}
Q = {"id": "b@x", "public_key": M.new_key()[1]}
SCOPE = {"currency": "EUR", "max_per_payment": "10.00", "from_accounts": [DEBTOR]}
T = "2026-01-01T00:00:00.000Z"
BASE = {"v": "gleipnir/mandate/0.4", "id": "m", "company": {"name": "X", "country": "AT"}, "agent": {"id": "a"},
        "scope": SCOPE, "valid_until": "2099-01-01T00:00:00.000Z", "issued_at": T}
LINK = {"v": "gleipnir/delegation/0.4", "id": "g", "company": {"name": "X"}, "from": P, "to": P, "scope": SCOPE,
        "valid_until": "2099-01-01T00:00:00.000Z", "issued_at": T}


@pytest.mark.parametrize("extra, problem", [
    ({}, "exactly one of signer or signers"),
    ({"signer": P, "signers": {"threshold": 1, "of": [P]}}, "exactly one"),
    ({"signer": P, "sigs": []}, "signs in sig, not sigs"),
    ({"signer": {"id": "a"}}, "signer.public_key"),
    ({"signers": {"threshold": 1, "of": [P]}, "sig": "x"}, "sign in sigs"),
    ({"signers": {"threshold": 1, "of": [P]}, "delegation": [LINK]}, "take no delegation"),
    ({"signers": {"threshold": 1, "of": []}}, "non-empty list"),
    ({"signers": "two"}, "non-empty list"),
    ({"signers": {"threshold": 2, "of": [P]}}, "threshold"),
    ({"signers": {"threshold": True, "of": [P]}}, "threshold"),
    ({"signers": {"threshold": 1, "of": [{"id": "a"}]}}, "public_key"),
    ({"signers": {"threshold": 1, "of": [P, P]}}, "duplicate signer id"),
    ({"signers": {"threshold": 1, "of": [P, Q]}, "sigs": [{"signer": "z@x", "sig": "x"}]}, "signer from signers.of"),
    ({"signers": {"threshold": 1, "of": [P, Q]}, "sigs": [{"signer": "a@x", "sig": 5}]}, "signer from signers.of"),
    ({"signers": {"threshold": 1, "of": [P, Q]}, "sigs": "x"}, "signer from signers.of"),
    ({"signers": {"threshold": 1, "of": [P, Q]}, "sigs": [{"signer": "a@x", "sig": "x"}] * 2}, "one signature per"),
    ({"signer": P, "delegation": []}, "delegation must be a list of 1 to 5"),
    ({"signer": P, "delegation": [LINK] * 6}, "delegation must be a list of 1 to 5"),
    ({"signer": P, "delegation": [{**LINK, "v": "gleipnir/delegation/0.1"}]}, "unknown delegation version"),
    ({"signer": P, "delegation": [{**LINK, "to": {"id": "b"}}]}, "missing to.public_key"),
    ({"signer": P, "delegation": [{**LINK, "parent": {"id": "g"}}]}, "parent needs id and hash"),
    ({"signer": P, "delegation": [{**LINK, "scope": {**SCOPE, "rails": ["telex"]}}]}, "unknown rails"),
    ({"signer": P, "delegation": [{**LINK, "valid_from": "2100-01-01T00:00:00.000Z"}]}, "valid_from is after"),
    ({"signer": P, "delegation": [{**LINK, "n": float("inf")}]}, "I-JSON"),
])
def test_mandate_shape_problems(extra, problem):
    assert problem in (M.mandate_problem({**BASE, **extra}) or "")


@pytest.mark.parametrize("r, problem", [
    ({"v": "gleipnir/revocation/0.4", "id": "r"}, "exactly one mandate or delegation"),
    ({"v": "gleipnir/revocation/0.4", "id": "r", "mandate_hash": "h", "delegation_hash": "h"}, "exactly one"),
    ({"v": "gleipnir/revocation/0.4", "id": "r", "delegation_hash": "h", "revoked_at": "x", "signer": P},
     "missing delegation"),
    ({"v": "gleipnir/revocation/0.4", "id": "r", "delegation": "g", "delegation_hash": "h", "revoked_at": "x",
      "signer": P}, "bad timestamp"),
])
def test_revocation_shape_problems(r, problem):
    assert problem in M.revocation_problem(r)


def test_delegate_rejects_bad_link():
    with pytest.raises(ValueError, match="bad amount"):
        M.delegate(id="g", company={"name": "X"}, from_=P, to=P, scope={"currency": "EUR", "max_per_payment": "1"},
                   valid_until="2099-01-01T00:00:00.000Z", sk=SK)


def test_combine_propagates_source_failure():
    def down(company, pid):
        raise TimeoutError
    with pytest.raises(TimeoutError):
        M.combine(lambda c, p: None, down)({}, "x")


def test_bad_authority_answer_is_checker_unavailable():
    sk, pk = M.new_key()
    m = M.sign_mandate(M.issue(id="m", company={"name": "X", "country": "AT"}, agent={"id": "a"},
                               signer={"id": "s", "public_key": pk}, scope=SCOPE,
                               valid_until="2099-01-01T00:00:00.000Z"), sk)
    p = M.attach(m, id="p", rail="sepa", amount="1.00", currency="EUR",
                 payee={"account": {"scheme": "iban", "iban": "AT611904300234573201"}})
    for bad in ["yes", M.AuthorityResult("kyb", (pk,), joint=0), M.AuthorityResult("kyb", (pk,), joint=1.5)]:
        c = M.Checker(id="b", sk=sk, authority=lambda co, pid, bad=bad: bad, holds=holds)
        assert c.check(m, {**p, "id": f"p_{bad!r}"[:20]})["reasons"] == ["checker_unavailable"]


@pytest.mark.parametrize("acc, problem", [
    (None, "must be an object"),
    ({"iban": "AT611904300234573201"}, "unknown account scheme"),
    ({"scheme": "telex", "number": "1"}, "unknown account scheme"),
    ({"scheme": "iban", "iban": "AT611904300234573201", "bic": "RZBAATWW"}, "exactly the fields"),
    ({"scheme": "iban", "iban": "AT61 1904 3002 3457 3201"}, "canonical"),
    ({"scheme": "iban", "iban": "at611904300234573201"}, "canonical"),
    ({"scheme": "iban", "iban": "AT621904300234573201"}, "check digits"),
    ({"scheme": "iban", "iban": 5}, "canonical"),
    ({"scheme": "us_aba", "routing": "021000022", "account": "1"}, "check digit"),
    ({"scheme": "us_aba", "routing": "02100002", "account": "1"}, "canonical"),
    ({"scheme": "us_aba", "routing": "021000021", "account": "12-34"}, "canonical"),
    ({"scheme": "uk_sort_code", "sort_code": "60-16-13", "account": "31926819"}, "canonical"),
    ({"scheme": "uk_sort_code", "sort_code": "601613", "account": "3192681"}, "canonical"),
    ({"scheme": "in_ifsc", "ifsc": "SBIN1000300", "account": "000000123456"}, "canonical"),
    ({"scheme": "mx_clabe", "clabe": "002010077777777772"}, "check digit"),
    ({"scheme": "swift", "bic": "MHCB", "account": "1"}, "canonical"),
    ({"scheme": "swift", "bic": "MHCBJPJT", "account": "١٢٣"}, "canonical"),
])
def test_account_problems(acc, problem):
    assert problem in (M.account_problem(acc) or "")


def test_account_normalizes_human_input():
    assert M.account("uk_sort_code", sort_code="60-16-13", account="3192 6819") == \
        {"scheme": "uk_sort_code", "sort_code": "601613", "account": "31926819"}
    assert M.account("swift", bic="mhcbjpjt", account="ab 12") == {"scheme": "swift", "bic": "MHCBJPJT",
                                                                  "account": "AB12"}
    with pytest.raises(ValueError, match="check digits"):
        M.iban("AT62 1904 3002 3457 3201")


@pytest.mark.parametrize("rail, currency, schemes, fits", [
    ("sepa", "EUR", ["iban", "iban"], True),
    ("sepa", "USD", ["iban", "iban"], False),
    ("sepa", "EUR", ["iban", "uk_sort_code"], False),
    ("ach", "USD", ["us_aba", "us_aba"], True),
    ("faster_payments", "GBP", ["uk_sort_code", "uk_sort_code"], True),
    ("faster_payments", "GBP", ["iban", "uk_sort_code"], False),
    ("wire", "JPY", ["us_aba", "swift"], True),
    ("spei", "MXN", ["mx_clabe", "mx_clabe"], True),
])
def test_rail_fits(rail, currency, schemes, fits):
    assert M.rail_fits(rail, currency, [{"scheme": s} for s in schemes]) is fits


@pytest.mark.parametrize("extra, problem", [
    ({"scope": {**SCOPE, "from_accounts": "AT48"}}, "from_accounts"),
    ({"scope": {**SCOPE, "from_accounts": [DEBTOR, DEBTOR]}}, "twice"),
    ({"scope": {k: v for k, v in SCOPE.items() if k != "from_accounts"}}, "from_accounts is required"),
    ({"scope": {**SCOPE, "payees": []}}, "payees must be a non-empty"),
    ({"scope": {**SCOPE, "payees": [{"name": "x"}]}}, "must be an object"),
])
def test_mandate_account_lists(extra, problem):
    assert problem in (M.mandate_problem({**BASE, "signer": P, **extra}) or "")


def test_link_period_limit_needs_from_accounts():
    sc = {"currency": "EUR", "max_per_payment": "1.00", "max_per_period": {"amount": "5.00", "period": "P1M"}}
    assert "with a period limit" in M.delegation_problem({**LINK, "scope": sc})
    assert M.delegation_problem({**LINK, "scope": {"currency": "EUR", "max_per_payment": "1.00"}}) is None


@pytest.mark.parametrize("s, problem", [
    ({}, "unknown status version"),
    ({"v": "gleipnir/status/0.4"}, "missing mandate.id"),
    ({"v": "gleipnir/status/0.4", "mandate": {"id": "m", "hash": "h"}, "status": "paused", "at": T, "signer": P},
     "active or revoked"),
    ({"v": "gleipnir/status/0.4", "mandate": {"id": "m", "hash": "h"}, "status": "active", "at": "now", "signer": P},
     "bad timestamp"),
])
def test_status_shape_problems(s, problem):
    assert problem in (M.status_problem(s) or "")


GOOD_OVERRIDE = {"v": "gleipnir/override/0.4", "id": "o", "decision": {"id": "d", "hash": "h"}, "outcome": "allow",
                 "decided_at": T, "sigs": [{"signer": P, "sig": "x"}]}


@pytest.mark.parametrize("extra, problem", [
    ({"v": "x"}, "unknown override version"),
    ({"outcome": "escalate"}, "allow or block"),
    ({"reason": 5}, "reason must be a string"),
    ({"sigs": []}, "at least one signature"),
    ({"sigs": [{"signer": {"id": "a"}, "sig": "x"}]}, "every sigs entry"),
    ({"sigs": [{"signer": P, "sig": 5}]}, "every sigs entry"),
    ({"sigs": [{"signer": P, "sig": "x"}, {"signer": {**Q, "public_key": PK}, "sig": "y"}]}, "one signature per"),
    ({"decided_at": "soon"}, "bad timestamp"),
    ({"x": 1.5}, "I-JSON"),
])
def test_override_shape_problems(extra, problem):
    assert M.override_problem(GOOD_OVERRIDE) is None
    assert problem in (M.override_problem({**GOOD_OVERRIDE, **extra}) or "")


@pytest.mark.parametrize("extra, problem", [
    ({"max_per_week": "1.00"}, "unknown field max_per_week"),
    ({"scope": {**SCOPE, "max_per_day": "1.00"}}, "unknown field scope.max_per_day"),
    ({"scope": {**SCOPE, "payees": [{"account": DEBTOR, "iban_hint": "x"}]}}, "unknown field scope.payees[].iban_hint"),
    ({"company": {"name": "X", "country": "AT", "lei": "5299"}}, "unknown field company.lei"),
    ({"company": {"name": "X", "country": "AT", "ids": "5299"}}, "company.ids must be an object"),
    ({"agent": {"id": "a", "name": 5}}, "agent.name must be a string"),
    ({"signer": {**P, "role": "x" * 141}}, "signer.role is longer than 140 characters"),
    ({"x": "note"}, "x must be an object"),
    ({"id": "m" * 129}, "id is longer than 128 characters"),
])
def test_unknown_fields_are_malformed(extra, problem):
    """0.4: a checker never ignores a field it does not know; anything informational goes under "x"."""
    assert problem == M.mandate_problem({**BASE, "signer": P, **extra})


def test_x_extensions_are_carried_and_signed():
    m = {**BASE, "signer": P, "x": {"erp": {"po": "4500012345"}, "any": [1, 2]}}
    assert M.mandate_problem(m) is None
    assert M.mandate_hash(m) != M.mandate_hash({**m, "x": {}})


def test_payment_id_fits_iso20022_end_to_end_id():
    m = M.sign_mandate(M.issue(id="m", company={"name": "X", "country": "AT"}, agent={"id": "a"}, signer=P,
                               scope=SCOPE, valid_until="2099-01-01T00:00:00.000Z"), SK)
    payee = {"account": M.iban("AT611904300234573201")}
    ok = M.attach(m, id="p" * 35, rail="sepa", amount="1.00", currency="EUR", payee=payee)
    assert M.payment_problem(ok) is None
    long = M.attach(m, id="p" * 36, rail="sepa", amount="1.00", currency="EUR", payee=payee)
    assert M.payment_problem(long) == "id is longer than 35 characters"
    ref = M.attach(m, id="p", rail="sepa", amount="1.00", currency="EUR", payee=payee, reference="r" * 141)
    assert M.payment_problem(ref) == "reference is longer than 140 characters"
