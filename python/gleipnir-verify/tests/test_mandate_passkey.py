"""Mandates signed with a passkey in the bank's app (spec 3a and 4.3), with real WebAuthn assertions."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from passkey import WEBAUTHN, Passkey

from gleipnir_verify import mandate as M
from gleipnir_verify.approvals import approval_challenge

NOW = datetime(2026, 10, 23, 9, 14, 2, tzinfo=timezone.utc)
COMPANY = {"name": "Nordhafen Logistik GmbH", "country": "AT"}
BRENNER = {"name": "Brenner Stahl AG", "account": {"iban": "AT611904300234573201"}}
SCOPE = {"rails": ["sepa"], "currency": "EUR", "max_per_payment": "25000.00", "payees": [BRENNER]}


@pytest.fixture()
def keys():
    return {"berger": Passkey(), "hofer": Passkey(), "bank": M.new_key()[0]}


def checker(keys, kyb, **kw):
    return M.Checker(id="bank:test", sk=keys["bank"], authority=lambda c, pid: kyb.get(pid), clock=lambda: NOW,
                     webauthn=WEBAUTHN, **kw)


def pay(m, pid="p_1"):
    return M.attach(m, id=pid, rail="sepa", amount="100.00", currency="EUR", payee=BRENNER,
                    requested_at=M.fmt_ts(NOW))


def single(keys):
    return M.issue(id="m_pk", company=COMPANY, agent={"id": "agent"},
                   signer={"id": "kberger", "public_key": keys["berger"].public_key}, scope=SCOPE,
                   valid_until="2026-12-31T23:59:59.000Z")


def kyb_for(keys, *names):
    return {n if n != "berger" else "kberger": M.AuthorityResult("bank_kyb", (keys[n].public_key,)) for n in names}


def test_passkey_signed_mandate_allows(keys):
    m = single(keys)
    m = {**m, "sig": keys["berger"].assert_(M.passkey_challenge(m))}
    d = checker(keys, kyb_for(keys, "berger")).check(m, pay(m))
    assert d["outcome"] == "allow"
    assert M.verify_receipt(m, pay(m), d, [M.public_key_of(keys["bank"])], webauthn=WEBAUTHN)["signed_by"] == \
        ["kberger"]


def test_m1_approval_challenge_is_not_a_mandate_signature(keys):
    """A passkey assertion over the bare mandate hash (what the approval page signs) is not a mandate signature."""
    m = single(keys)
    bare = approval_challenge(M.mandate_hash(m))
    assert bare != M.passkey_challenge(m)
    m = {**m, "sig": keys["berger"].assert_(bare)}
    assert checker(keys, kyb_for(keys, "berger")).check(m, pay(m))["reasons"] == ["mandate_bad_signature"]


@pytest.mark.parametrize("kw", [{"origin": "https://evil.example"}, {"rp_id": "evil.example"}, {"flags": 0x01}])
def test_passkey_from_wrong_site_or_without_user_verification(keys, kw):
    m = single(keys)
    m = {**m, "sig": keys["berger"].assert_(M.passkey_challenge(m), **kw)}
    assert checker(keys, kyb_for(keys, "berger")).check(m, pay(m))["reasons"] == ["mandate_bad_signature"]


def test_passkey_needs_checker_webauthn_config(keys):
    m = single(keys)
    m = {**m, "sig": keys["berger"].assert_(M.passkey_challenge(m))}
    plain = M.Checker(id="b", sk=keys["bank"], authority=lambda c, p: kyb_for(keys, "berger").get(p), clock=lambda: NOW)
    assert plain.check(m, pay(m))["reasons"] == ["mandate_bad_signature"]


def test_joint_signing_with_two_passkeys(keys):
    m = M.issue(id="m_joint", company=COMPANY, agent={"id": "agent"},
                signers={"threshold": 2, "of": [{"id": "kberger", "public_key": keys["berger"].public_key},
                                                {"id": "hofer", "public_key": keys["hofer"].public_key}]},
                scope=SCOPE, valid_until="2026-12-31T23:59:59.000Z")
    ch = M.passkey_challenge(m)
    m = {**m, "sigs": [{"signer": "kberger", "sig": keys["berger"].assert_(ch)},
                       {"signer": "hofer", "sig": keys["hofer"].assert_(ch)}]}
    d = checker(keys, kyb_for(keys, "berger", "hofer")).check(m, pay(m))
    assert d["outcome"] == "allow" and "signatures:2/2" in d["checks"]
    swapped = {**m, "sigs": [{"signer": "kberger", "sig": m["sigs"][1]["sig"]}, m["sigs"][1]]}
    assert checker(keys, kyb_for(keys, "berger", "hofer")).check(swapped, pay(swapped, "p_2"))["reasons"] == \
        ["mandate_bad_signature"]

