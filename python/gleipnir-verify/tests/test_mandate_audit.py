"""Audit 2026-10-23: attacks on the mandate check (spec/mandate.md, gleipnir_verify.mandate).

Every test asserts the SAFE behaviour. A failing test is an open finding; the id in the test name
(C1, H2, ...) matches the findings table in docs/audit-2026-10-23.md. Tests that pass document
attacks that were tried and are already handled.
"""

from __future__ import annotations

import itertools
import json
import threading
from datetime import datetime, timezone

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from kit import DEBTOR, holds

from gleipnir_verify import mandate as M

IBAN = "AT611904300234573201"
SIGNER_ID = "kberger@nordhafen.at"
COMPANY = {"name": "Nordhafen Logistik GmbH", "country": "AT"}
NOW = datetime(2026, 10, 23, 9, 14, 2, tzinfo=timezone.utc)
_ids = itertools.count()


def kyb_authority(keys_by_id):
    """The bank's KYB records: signer id -> keys. The new contract never sees the mandate's key."""
    def authority(company, signer_id):
        keys = keys_by_id.get(signer_id)
        return M.AuthorityResult("bank_kyb", tuple(keys)) if keys else None
    return authority


# ---------------------------------------------------------------- fixtures


def make_world(*, scope_extra=None, agent_key=True, **issue_kw):
    signer_sk, signer_pk = M.new_key()
    agent_sk, agent_pk = M.new_key()
    bank_sk, bank_pk = M.new_key()
    scope = {"rails": ["sepa"], "currency": "EUR", "max_per_payment": "25000.00",
             "max_per_period": {"amount": "30000.00", "period": "P1M"},
             "payees": [{"name": "Brenner Stahl AG", "account": {"scheme": "iban", "iban": IBAN}}],
             "from_accounts": [DEBTOR]}
    scope.update(scope_extra or {})
    agent = {"id": "ap-agent", "public_key": agent_pk} if agent_key else {"id": "ap-agent"}
    kw = {"valid_from": "2026-01-01T00:00:00.000Z", "valid_until": "2026-12-31T23:59:59.000Z"}
    kw.update(issue_kw)
    m = M.sign_mandate(M.issue(id="m_1", company=dict(COMPANY), agent=agent,
                               signer={"id": SIGNER_ID, "name": "K. Berger", "public_key": signer_pk},
                               scope=scope, **kw), signer_sk)
    checker = M.Checker(id="bank:TEST", sk=bank_sk, authority=kyb_authority({SIGNER_ID: [signer_pk]}),
                        ledger=M.InMemoryLedger(), clock=lambda: NOW, holds=holds)
    return dict(m=m, checker=checker, signer_sk=signer_sk, signer_pk=signer_pk, agent_sk=agent_sk,
                bank_sk=bank_sk, bank_pk=bank_pk)


def pay(w, *, amount="18400.00", iban=IBAN, pid=None, requested_at="2026-10-23T09:14:02.000Z", account=None,
        mandate=None, **kw):
    mandate = mandate or w["m"]
    pid = pid or f"p_{next(_ids)}"
    return M.attach(mandate, id=pid, rail=kw.get("rail", "sepa"), amount=amount, currency=kw.get("currency", "EUR"),
                    payee={"name": "Brenner Stahl AG", "account": account or {"scheme": "iban", "iban": iban}},
                    agent_sk=kw.get("agent_sk", w["agent_sk"]), requested_at=requested_at)


@pytest.fixture
def w():
    return make_world()


def outcome(d):
    return d["outcome"], d["reasons"]


# ---------------------------------------------------------------- 1. signatures and authority


def test_C1_authority_by_signer_id_alone_lets_anyone_forge_a_mandate():
    """The Checker passes the signer dict (id + public_key from the mandate itself) to authority().
    A bank that looks the signer up by id, the natural reading of the API and of spec section 6, accepts a
    mandate signed with the attacker's own key. The check must bind the signing key to the authority source."""
    w = make_world()
    evil_sk, evil_pk = M.new_key()
    agent_sk, agent_pk = M.new_key()
    forged = M.sign_mandate(M.issue(id="m_evil", company=dict(COMPANY), agent={"id": "x", "public_key": agent_pk},
                                    signer={"id": SIGNER_ID, "public_key": evil_pk},
                                    scope={"currency": "EUR", "max_per_payment": "999999.00",
                                           "from_accounts": [DEBTOR]},
                                    valid_until="2026-12-31T23:59:59.000Z"), evil_sk)
    # The bank looks the signer up by id only; the key comes from its own KYB records.
    w["checker"].authority = kyb_authority({SIGNER_ID: [w["signer_pk"]]})
    p = M.attach(forged, id="p", rail="sepa", amount="999999.00", currency="EUR",
                 payee={"account": {"scheme": "iban", "iban": "LT121000011101001000"}}, agent_sk=agent_sk,
                 requested_at="2026-10-23T09:14:02.000Z")
    d = w["checker"].check(forged, p)
    assert d["outcome"] != "allow"
    assert d["reasons"] == ["signer_not_authorized"]


def test_ok_signature_domain_separation(w):
    """A revocation or decision signature pasted in as the mandate signature does not verify."""
    r = M.revoke(w["m"], signer={"id": SIGNER_ID, "public_key": w["signer_pk"]}, sk=w["signer_sk"], id="r")
    m2 = {**w["m"], "sig": r["sig"]}
    assert w["checker"].check(m2, pay(w, mandate=m2))["reasons"] == ["mandate_bad_signature"]
    d = w["checker"].check(w["m"], pay(w))
    m3 = {**w["m"], "sig": d["sig"]}
    assert w["checker"].check(m3, pay(w, mandate=m3))["reasons"] == ["mandate_bad_signature"]


def test_ok_key_type_confusion(w):
    """A P-256 key declared for an Ed25519 signature (or garbage key text) fails closed."""
    for bad in ("ecdsa-p256:" + w["signer_pk"].split(":", 1)[1], "rsa:abc", "", "ed25519:"):
        m2 = {**w["m"], "signer": {**w["m"]["signer"], "public_key": bad}}
        if not bad:
            assert w["checker"].check(m2, pay(w, mandate=m2))["reasons"] == ["mandate_malformed"]
        else:
            assert w["checker"].check(m2, pay(w, mandate=m2))["outcome"] == "block"


def test_ok_webauthn_unconfigured_fails_closed(w):
    """With no rp_id / origins configured a passkey-signed mandate is rejected, not accepted."""
    fake = {"type": "webauthn", "authenticator_data": "AAAA" * 10, "client_data_json": "e30", "signature": "AAAA"}
    m2 = {**w["m"], "sig": fake}
    assert w["checker"].check(m2, pay(w, mandate=m2))["reasons"] == ["mandate_bad_signature"]


def test_ok_webauthn_not_accepted_for_payment_or_revocation(w):
    fake = {"type": "webauthn", "authenticator_data": "AAAA", "client_data_json": "e30", "signature": "AAAA"}
    p = {**pay(w), "agent_sig": fake}
    assert w["checker"].check(w["m"], p)["reasons"] == ["agent_bad_signature"]
    r = M.revoke(w["m"], signer={"id": SIGNER_ID, "public_key": w["signer_pk"]}, sk=w["signer_sk"], id="r",
                 revoked_at="2026-01-02T00:00:00.000Z")
    w["checker"].revocations.append({**r, "sig": fake})
    assert w["checker"].check(w["m"], pay(w))["outcome"] == "allow"


def test_M1_passkey_challenge_is_domain_separated(w):
    """The mandate passkey challenge is the bare mandate hash, the same shape as an approval challenge
    (approvals.approval_challenge). One signing page could be used to make a signatory approve 'an action'
    that is really a mandate. The challenge should be bound to 'gleipnir/mandate/v0.1'."""
    from gleipnir_verify.approvals import approval_challenge
    h = M.mandate_hash(w["m"])
    assert M.passkey_challenge(w["m"]) != approval_challenge(h)  # fixed: challenge = SHA-256(domain || hash)


# ---------------------------------------------------------------- 2. replay and time


def test_H1_same_payment_twice_is_allowed_twice(w):
    """No idempotency: the exact same payment document gets a second 'allow'. The checker (or the spec)
    must reject a payment id it has already decided, or the decision must say it is a duplicate."""
    p = pay(w)
    first = w["checker"].check(w["m"], p)
    assert first["outcome"] == "allow"
    again = w["checker"].check(w["m"], p)
    # Idempotent: the bank gets the SAME decision back (same id), not a second allow, and nothing is reserved twice.
    assert again == first
    assert sum(w["checker"].ledger.totals.values()) == 18400


def test_H1b_same_payment_id_different_amount(w):
    w["checker"].check(w["m"], pay(w, pid="p_same", amount="100.00"))
    assert w["checker"].check(w["m"], pay(w, pid="p_same", amount="20000.00"))["outcome"] != "allow"


def test_C2_agent_backdates_requested_at_to_dodge_revocation(w):
    """requested_at is chosen by the agent. A revoked mandate still pays if the agent dates the payment
    one second before the revocation. The checker must use its own clock."""
    r = M.revoke(w["m"], signer={"id": SIGNER_ID, "public_key": w["signer_pk"]}, sk=w["signer_sk"], id="r",
                 revoked_at="2026-11-01T10:00:00.000Z")
    w["checker"].revocations.append(r)
    w["checker"].clock = lambda: datetime(2026, 11, 1, 10, 0, 30, tzinfo=timezone.utc)  # bank's clock
    backdated = pay(w, requested_at="2026-11-01T09:59:59.000Z")  # actually sent after the revocation
    assert w["checker"].check(w["m"], backdated)["outcome"] != "allow"


def test_C2b_agent_backdates_requested_at_to_dodge_expiry():
    w = make_world(valid_until="2026-01-31T23:59:59.000Z")
    old = pay(w, requested_at="2026-01-31T23:59:58.000Z")  # the real date is 2026-10-23
    assert w["checker"].check(w["m"], old)["outcome"] != "allow"


def test_M2_requested_at_far_in_future_accepted(w):
    """A payment dated months ahead is checked as if it were then (period counters, revocations)."""
    assert w["checker"].check(w["m"], pay(w, requested_at="2026-12-30T00:00:00.000Z"))["outcome"] != "allow"


@pytest.mark.parametrize("ts", ["2026-10-23T09:14:02+00:00", "2026-10-23T11:14:02.000+02:00"])
def test_ok_non_utc_timestamps_rejected(w, ts):
    assert w["checker"].check(w["m"], pay(w, requested_at=ts))["outcome"] == "block"


@pytest.mark.parametrize("ts", ["2026-10-23T09Z", "2026-10-23T09:14Z", "2026-10-23T09:14:02.1234567Z",
                                "2026-10-23 09:14:02Z", "2026-10-23T09:14:02,000Z"])
def test_L1_non_rfc3339_timestamps_rejected(w, ts):
    """Fixed: strict RFC 3339 (shared grammar with the TypeScript port)."""
    assert w["checker"].check(w["m"], pay(w, requested_at=ts))["reasons"] == ["payment_malformed"]


def test_L2_valid_until_before_valid_from_is_issued():
    with pytest.raises(ValueError):
        make_world(valid_from="2026-12-01T00:00:00.000Z", valid_until="2026-01-01T00:00:00.000Z")


# ---------------------------------------------------------------- 3. period limit


def test_H2_period_limit_fail_open_without_counter():
    """Checker.spent defaults to 'nothing spent'. A bank that forgets to wire the counter enforces no
    monthly limit at all. Without a counter the check must not allow when max_per_period is set."""
    w = make_world()
    w["checker"].ledger = None  # the bank forgot to wire the ledger
    allowed = sum(w["checker"].check(w["m"], pay(w, pid=f"p{i}", amount="20000.00"))["outcome"] == "allow"
                  for i in range(5))
    assert allowed * 20000 <= 30000
    assert w["checker"].check(w["m"], pay(w))["reasons"] == ["ledger_missing"]


def test_H3_period_limit_race_between_parallel_checks():
    """check() reads 'spent' but never reserves the amount. Two payments checked in parallel each see the
    old total and both pass, together breaking the limit."""
    w = make_world()
    results = []
    start = threading.Barrier(8)

    def run():
        p = pay(w, amount="20000.00")
        start.wait(timeout=5)
        results.append(w["checker"].check(w["m"], p)["outcome"])

    ts = [threading.Thread(target=run) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count("allow") == 1  # 30 000 limit, 20 000 each


def test_L3_period_value_not_validated():
    with pytest.raises(ValueError):
        make_world(scope_extra={"max_per_period": {"amount": "30000.00", "period": "whenever"}})


# ---------------------------------------------------------------- 4. amounts


@pytest.mark.parametrize("amount", ["NaN", "sNaN", "-NaN"])
def test_H4_nan_amount_crashes_check(w, amount):
    """Decimal('NaN') < 0 raises InvalidOperation, which is not a ValueError: check() raises instead of
    returning a signed 'block'. A malformed field from the agent becomes an unhandled exception at the bank."""
    d = w["checker"].check(w["m"], pay(w, amount=amount))
    assert d["outcome"] == "block"


@pytest.mark.parametrize("amount", ["25000.001", "1e3", "1E+4", "0025000.00", "25000", " 100.00", "100.00\n"])
def test_M3_amount_format_not_enforced(w, amount):
    """spec: decimal strings with the currency's minor units ("25000.00"). Exponents, leading zeros,
    whitespace, missing or extra decimals all pass, so two systems can read one amount differently."""
    assert w["checker"].check(w["m"], pay(w, amount=amount))["outcome"] == "block"


@pytest.mark.parametrize("amount", ["0.00", "-0", "-0.00"])
def test_M4_zero_and_negative_zero_allowed(w, amount):
    assert w["checker"].check(w["m"], pay(w, amount=amount))["outcome"] == "block"


def test_ok_negative_and_infinite_amounts(w):
    for a in ("-1.00", "Infinity", "-Infinity", "abc", ""):
        assert w["checker"].check(w["m"], pay(w, amount=a))["outcome"] == "block"


def test_ok_float_amount_in_payment(w):
    assert w["checker"].check(w["m"], pay(w, amount=18400.0))["outcome"] == "block"


def test_ok_huge_amount(w):
    assert w["checker"].check(w["m"], pay(w, amount="1" + "0" * 400))["outcome"] in ("block", "escalate")


# ---------------------------------------------------------------- 5. payee


def test_ok_iban_case_and_spaces(w):
    """0.3: the wire carries canonical accounts only; producers normalize with M.iban()."""
    assert w["checker"].check(w["m"], pay(w, iban="at61 1904 3002 3457 3201"))["reasons"] == ["payment_malformed"]
    assert w["checker"].check(w["m"], pay(w, account=M.iban("at61 1904 3002 3457 3201")))["outcome"] == "allow"


def test_ok_same_name_other_account(w):
    assert w["checker"].check(w["m"], pay(w, iban="DE89370400440532013000"))["reasons"] == ["payee_not_on_mandate"]


def test_L4_iban_checksum_not_validated():
    """A mandate can list an IBAN with a wrong check digit; it should be refused at issue time."""
    with pytest.raises(ValueError):
        make_world(scope_extra={"payees": [{"account": {"scheme": "iban", "iban": "AT001904300234573201"}}]})


def test_M5_iban_with_tabs_or_dashes(w):
    """Fixed in 0.3: producers normalize (whitespace and dashes, ISO 13616 print format); the wire is canonical."""
    assert M.iban("AT61\t1904-3002 3457\t3201") == {"scheme": "iban", "iban": IBAN}
    assert w["checker"].check(w["m"], pay(w, account=M.iban("AT61\t1904-3002 3457\t3201")))["outcome"] == "allow"
    assert w["checker"].check(w["m"], pay(w, iban="AT61\t1904\t3002\t3457\t3201"))["reasons"] == \
        ["payment_malformed"]


def test_ok_us_account_extra_fields_fail_closed():
    w = make_world(scope_extra={"rails": ["ach"], "currency": "USD", "max_per_payment": "25000.00",
                                "max_per_period": {"amount": "30000.00", "period": "P1M"},
                                "payees": [{"account": M.account("us_aba", routing="021000021",
                                                                 account="123456789")}]})
    p = pay(w, rail="ach", currency="USD", amount="10.00",
            account={"scheme": "us_aba", "routing": "021000021", "account": "123456789", "type": "checking"})
    assert w["checker"].check(w["m"], p)["outcome"] == "block"


def test_H5_malformed_payee_entry_crashes_check():
    """A payee without 'account' in a signed mandate raises KeyError inside check()."""
    w = make_world()
    bad = {k: v for k, v in w["m"].items() if k != "sig"}
    bad["scope"] = {**bad["scope"], "payees": [{"name": "Brenner Stahl AG"}]}
    bad = M.sign_mandate(bad, w["signer_sk"])  # signed, but never went through issue()
    assert w["checker"].check(bad, pay(w, mandate=bad))["outcome"] == "block"


# ---------------------------------------------------------------- 6. revocation and status


def test_ok_revocation_by_outsider_ignored(w):
    evil_sk, evil_pk = M.new_key()
    r = M.revoke(w["m"], signer={"id": "evil@x", "public_key": evil_pk}, sk=evil_sk, id="r",
                 revoked_at="2026-01-02T00:00:00.000Z")
    w["checker"].revocations.append(r)
    assert w["checker"].check(w["m"], pay(w))["outcome"] == "allow"


@pytest.mark.parametrize("answer", ["unknown", "may_not_sign", "other_key", "no_keys", "not_a_result"])
def test_ok_revocation_authority_falsy(w, answer):
    """A revocation counts only if the source binds the revoker's key to someone who may sign."""
    hofer_sk, hofer_pk = M.new_key()
    other_pk = M.new_key()[1]
    r = M.revoke(w["m"], signer={"id": "mhofer@nordhafen.at", "public_key": hofer_pk}, sk=hofer_sk, id="r",
                 revoked_at="2026-01-02T00:00:00.000Z")
    w["checker"].revocations.append(r)
    answers = {"unknown": None, "may_not_sign": M.AuthorityResult("bank_kyb", (hofer_pk,), may_sign=False),
               "other_key": M.AuthorityResult("bank_kyb", (other_pk,)), "no_keys": M.AuthorityResult("bank_kyb", ()),
               "not_a_result": "bank_kyb"}
    base = w["checker"].authority
    w["checker"].authority = lambda c, sid: answers[answer] if sid == "mhofer@nordhafen.at" else base(c, sid)
    d = w["checker"].check(w["m"], pay(w))
    assert d["outcome"] == ("escalate" if answer == "not_a_result" else "allow"), d["reasons"]


def test_H6_malformed_revocation_in_list_crashes_every_check(w):
    """One bad entry in Checker.revocations (missing revoked_at) raises KeyError for every payment."""
    w["checker"].revocations.append({"mandate_hash": M.obj_hash(w["m"])})
    assert w["checker"].check(w["m"], pay(w))["outcome"] in ("allow", "block", "escalate")


def test_M6_no_status_url_and_no_revocation_list_means_irrevocable():
    """Was: a revocation held by the home bank did not reach another bank. Fixed in 0.3 by from_accounts: the
    mandate only works at the bank that holds its debtor accounts, which is where the revocation goes (spec 9).
    A mandate listing accounts at several banks must be revoked at each, or carry a status_url."""
    w = make_world()
    r = M.revoke(w["m"], signer={"id": SIGNER_ID, "public_key": w["signer_pk"]}, sk=w["signer_sk"], id="r",
                 revoked_at="2026-01-02T00:00:00.000Z")
    other_bank = M.Checker(id="bank:OTHER", sk=M.new_key()[0], authority=w["checker"].authority,
                           ledger=M.InMemoryLedger(), clock=lambda: NOW, holds=lambda c, a: False)
    assert r  # revoked at the company's home bank only
    assert other_bank.check(w["m"], pay(w))["reasons"] == ["account_not_held"]


@pytest.mark.parametrize("answer", ["Active", "", None, "ACTIVE ", 1, "revoked ", "active", {"status": "active"}])
def test_ok_status_answers_fail_closed(answer):
    w = make_world(status_url="https://x/status")
    w["checker"].status = lambda _: answer
    assert w["checker"].check(w["m"], pay(w))["outcome"] != "allow"


def test_ok_status_raises_any_exception():
    w = make_world(status_url="https://x/status")

    def boom(_):
        raise TimeoutError

    w["checker"].status = boom
    assert w["checker"].check(w["m"], pay(w))["reasons"] == ["status_unavailable"]


# ---------------------------------------------------------------- 7. decisions


def test_C3_verify_decision_trusts_the_key_inside_the_decision(w):
    """Anyone can mint an 'allow' decision under their own key and verify_decision() says True. A verifier
    must check against the bank's pinned key: verify_decision(d, expected_key=bank_pk)."""
    evil_sk, evil_pk = M.new_key()
    d = w["checker"].check(w["m"], pay(w, amount="26000.00"))
    assert d["outcome"] == "escalate"
    forged = {k: v for k, v in d.items() if k != "sig"}
    forged.update(outcome="allow", reasons=[], checker={"id": "bank:TEST", "public_key": evil_pk})
    forged = M._sign(evil_sk, "decision", forged)
    assert not M.verify_decision(forged, checker_keys=[w["bank_pk"]])
    assert M.verify_decision(d, checker_keys=[w["bank_pk"]])
    assert not M.verify_decision(d, checker_keys=[])
    with pytest.raises(TypeError):
        M.verify_decision(forged)  # no keyless variant


def test_L5_decision_id_is_deterministic_and_reveals_payment_hash(w):
    """id = 'd_' + 64 bits of the payment hash: two checks of one payment get the same decision id, and the
    id lets anyone confirm a guess of the payment's contents (amount, IBAN). Use a random id."""
    d = w["checker"].check(w["m"], pay(w))
    assert d["id"][2:] not in d["payment"]["hash"]


# ---------------------------------------------------------------- 8. encoding


@pytest.mark.parametrize("payment", [None, "x", [], 42, {"v": "x"}])
def test_H7_non_dict_payment_crashes_check(w, payment):
    """check() builds the decision with obj_hash(payment) after _run; a non-dict payment raises."""
    assert w["checker"].check(w["m"], payment)["outcome"] == "block"


@pytest.mark.parametrize("mandate", [None, "x", [], 42])
def test_ok_non_dict_mandate(w, mandate):
    assert w["checker"].check(mandate, pay(w))["outcome"] == "block"


def test_H8_non_jcs_value_in_payment_crashes_check(w):
    """A float NaN or an integer beyond 2^53 anywhere in the payment makes JCS raise inside check()."""
    for bad in (float("nan"), 10**20):
        p = {**pay(w), "reference": bad}
        assert w["checker"].check(w["m"], p)["outcome"] == "block"


def test_ok_field_order_does_not_change_hash(w):
    m2 = json.loads(json.dumps(w["m"], sort_keys=True))
    assert M.obj_hash(m2) == M.obj_hash(w["m"])


@pytest.mark.xfail(strict=True, reason="L6 open: NFC normalization")
def test_L6_unicode_normalization_changes_hash():
    """'Café' as NFC and NFD hash differently; the authority lookup by company name is then a string
    compare. Fail-closed, but spec should say NFC or compare on ids, not names."""
    a = {"name": "Café"}
    b = {"name": "Café"}
    assert M.obj_hash(a) == M.obj_hash(b)


def test_M7_duplicate_json_keys_parse_differently():
    """The library takes dicts; the bank's JSON parser decides duplicates. Python keeps the last value, other
    parsers the first. Spec must say: reject duplicate keys before hashing."""
    raw = '{"amount": "1.00", "amount": "99999.00"}'
    assert json.loads(raw)["amount"] == "99999.00"  # what a Python bank sees
    with pytest.raises(ValueError):
        json.loads(raw, object_pairs_hook=_no_dupes_reference)
    from pathlib import Path
    spec = (Path(__file__).parents[3] / "spec" / "mandate.md").read_text()
    assert "duplicate" in spec.lower(), "spec does not require rejecting duplicate JSON keys"


def _no_dupes_reference(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


# ---------------------------------------------------------------- 9. fuzzing


json_scalar = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=True),
                        st.text(max_size=12))
json_val = st.recursive(json_scalar, lambda c: st.one_of(st.lists(c, max_size=3),
                                                         st.dictionaries(st.text(max_size=8), c, max_size=4)),
                        max_leaves=12)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(junk=json_val)
def test_H9_fuzz_check_never_raises_and_never_allows_junk(w, junk):
    """check() must return a decision for any input and never 'allow' a payment that is not a valid one."""
    for m, p in ((w["m"], junk), (junk, pay(w))):
        try:
            d = w["checker"].check(m, p)
        except Exception as e:  # noqa: BLE001
            pytest.fail(f"check() raised {type(e).__name__}: {e} on {junk!r}")
        assert d["outcome"] != "allow"


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(field=st.sampled_from(["amount", "currency", "rail", "payee", "requested_at", "mandate", "id"]), junk=json_val)
def test_H9b_fuzz_payment_fields(w, field, junk):
    p = {**pay(w), field: junk}
    try:
        p = M._sign(w["agent_sk"], "payment", p, "agent_sig")
    except Exception:  # noqa: BLE001 - junk JCS cannot hash; send it unsigned
        pass
    try:
        d = w["checker"].check(w["m"], p)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"check() raised {type(e).__name__} for {field}={junk!r}")
    if d["outcome"] == "allow":
        assert field in ("id",) or (field == "payee" and isinstance(junk, dict))
