"""Malformed multi-signature, delegation and revocation shapes (spec 0.2) are rejected, never crash."""

from __future__ import annotations

import pytest

from gleipnir_verify import mandate as M

SK, PK = M.new_key()
P = {"id": "a@x", "public_key": PK}
Q = {"id": "b@x", "public_key": PK}
SCOPE = {"currency": "EUR", "max_per_payment": "10.00"}
BASE = {"v": "gleipnir/mandate/0.2", "id": "m", "company": {"name": "X", "country": "AT"}, "agent": {"id": "a"},
        "scope": SCOPE, "valid_until": "2099-01-01T00:00:00.000Z"}
LINK = {"v": "gleipnir/delegation/0.2", "id": "g", "company": {"name": "X"}, "from": P, "to": P, "scope": SCOPE,
        "valid_until": "2099-01-01T00:00:00.000Z"}


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
    ({"v": "gleipnir/revocation/0.2", "id": "r"}, "exactly one mandate or delegation"),
    ({"v": "gleipnir/revocation/0.2", "id": "r", "mandate_hash": "h", "delegation_hash": "h"}, "exactly one"),
    ({"v": "gleipnir/revocation/0.2", "id": "r", "delegation_hash": "h", "revoked_at": "x", "signer": P},
     "missing delegation"),
    ({"v": "gleipnir/revocation/0.2", "id": "r", "delegation": "g", "delegation_hash": "h", "revoked_at": "x",
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
    p = M.attach(m, id="p", rail="sepa", amount="1.00", currency="EUR", payee={"account": {"iban": "AT1"}})
    for bad in ["yes", M.AuthorityResult("kyb", (pk,), joint=0), M.AuthorityResult("kyb", (pk,), joint=1.5)]:
        c = M.Checker(id="b", sk=sk, authority=lambda co, pid, bad=bad: bad)
        assert c.check(m, {**p, "id": f"p_{bad!r}"[:20]})["reasons"] == ["checker_unavailable"]
