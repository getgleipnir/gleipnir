"""Regression tests for the third independent audit (24.10.2026, spec 0.3), findings F1-F19.

Each test runs the attack the auditor demonstrated and asserts it is closed (or, where the spec now says so,
the documented behaviour).
"""

from __future__ import annotations

from akit3 import CO, KEYS, P, bank, kyb_default, mandate, multi, override, pay, scope

from gleipnir_verify import mandate as M


def test_F2_failed_recheck_after_override_keeps_the_escalation():
    kyb = kyb_default()
    down = {"on": False}

    def authority(c, pid):
        if down["on"]:
            raise RuntimeError("KYB timeout")
        return kyb.get(pid)

    b = bank(kyb, authority=authority, officers=[KEYS["officer"].pk])
    m = mandate("a")
    p = pay(m, "p_1", "2000.00")
    e = b.check(m, p)
    o = override(e, ["officer"])
    down["on"] = True
    assert b.resolve(m, p, e, o)["reasons"] == ["checker_unavailable"]
    assert b.check(m, p) == e  # the escalation is still there
    down["on"] = False
    assert b.resolve(m, p, e, o)["outcome"] == "allow"  # the same override works once KYB is back


def test_F2_recheck_that_blocks_releases_the_id():
    kyb = kyb_default()
    b = bank(kyb, officers=[KEYS["officer"].pk])
    m = mandate("a")
    p = pay(m, "p_1", "2000.00")
    e = b.check(m, p)
    kyb[P["a"]["id"]] = M.AuthorityResult("bank_kyb", (KEYS["a"].pk,), may_sign=False)
    assert b.resolve(m, p, e, override(e, ["officer"]))["reasons"] == ["signer_not_authorized"]
    kyb[P["a"]["id"]] = M.AuthorityResult("bank_kyb", (KEYS["a"].pk,))
    assert b.check(m, pay(m, "p_1", "900.00"))["outcome"] == "allow"  # not wedged


def test_F3_signer_unknown_waiver_vouches_only_for_the_people_named():
    kyb = kyb_default()
    del kyb[P["b"]["id"]]
    b = bank(kyb, officers=[KEYS["officer"].pk])
    m = multi(["a", "b"], 2)
    p = pay(m, "p_1")
    e = b.check(m, p)
    assert e["reasons"] == ["signer_unknown"] and e["unknown"] == [P["b"]]
    del kyb[P["a"]["id"]]  # a leaves after the escalation
    r = b.resolve(m, p, e, override(e, ["officer"]))
    assert r["reasons"] == ["signer_unknown"] and r["unknown"] == [P["a"]]  # a is not vouched for
    assert r["vouched"] == [P["b"]]


def test_F4_one_customer_shares_one_payment_id_space_across_mandates():
    b = bank(kyb_default())
    m1 = mandate("a", mid="m_old")
    m2 = mandate("a", mid="m_new", company={**CO, "ids": {"lei": "529900T8BM49AURSDO55"}})
    assert b.check(m1, pay(m1, "INV-2026-0912", "900.00"))["outcome"] == "allow"
    assert b.check(m2, pay(m2, "INV-2026-0912", "900.00"))["reasons"] == ["duplicate_payment"]


def test_F5_one_person_counts_once_when_the_source_names_them():
    k2 = M.new_key()
    alice = M.AuthorityResult("bank_kyb", (KEYS["a"].pk, k2[1]), person="kyb:4711")
    b = bank({}, authority=lambda c, pid: alice if pid.lower() == "a@nordhafen.at" else None)
    m = M.issue(id="m_2of2", company=CO, agent={"id": "agent", "public_key": KEYS["agent"].pk},
                signers={"threshold": 2, "of": [P["a"], {"id": "A@nordhafen.at", "public_key": k2[1]}]},
                scope=scope(), valid_until="2026-12-31T23:59:59.000Z", issued_at="2026-10-01T00:00:00.000Z")
    m = M.cosign(M.cosign(m, KEYS["a"].sk, "a@nordhafen.at"), k2[0], "A@nordhafen.at")
    assert b.check(m, pay(m, "p_1"))["reasons"] == ["signature_threshold_not_met"]
    bad = M.AuthorityResult("bank_kyb", (KEYS["a"].pk,), person=5)  # type: ignore[arg-type]
    assert bank({}, authority=lambda c, pid: bad).check(m, pay(m, "p_2"))["reasons"] == ["checker_unavailable"]


def test_F6_receipt_shows_whom_the_bank_counted():
    b = bank(kyb_default())
    m = multi(["a", "b"], 1)
    p = pay(m, "p_1")
    d = b.check(m, p)
    assert d["signers"] == [P["a"], P["b"]]
    assert M.verify_receipt(m, p, d, [b.public_key])["signed_by"] == ["a@nordhafen.at", "b@nordhafen.at"]
    only_b = {**m, "sigs": [s for s in m["sigs"] if s["signer"] == P["b"]["id"]]}
    assert M.verify_receipt(only_b, p, d, [b.public_key])["problems"] == ["mandate_signers_mismatch"]


def test_F6_override_approvers_cannot_be_relabeled_or_dropped():
    b = bank(kyb_default(), officers=[KEYS["officer"].pk])
    m = mandate("a")
    p = pay(m, "p_1", "2000.00")
    e = b.check(m, p)
    o = override(e, ["officer"])
    d = b.resolve(m, p, e, o)
    assert d["approvers"] == [{**P["officer"], "role": "bank"}]
    forged = {**o, "sigs": [{**o["sigs"][0], "signer": {"id": "ceo@nordhafen.at",
                                                         "public_key": o["sigs"][0]["signer"]["public_key"]}}]}
    assert M.verify_receipt(m, p, d, [b.public_key], override=forged)["problems"] == ["override_bad_signature"]
    b2 = bank(kyb_default())
    m2 = multi(["a", "b"], 2, mid="m_j")
    p2 = pay(m2, "p_2", "2000.00")
    e2 = b2.check(m2, p2)
    o2 = override(e2, ["a", "b"])
    d2 = b2.resolve(m2, p2, e2, o2)
    assert M.verify_receipt(m2, p2, d2, [b2.public_key], override=o2)["approved_by"] == ["a@nordhafen.at",
                                                                                          "b@nordhafen.at"]
    only_a = {**o2, "sigs": o2["sigs"][:1]}
    assert M.verify_receipt(m2, p2, d2, [b2.public_key], override=only_a)["problems"] == ["override_bad_signature"]


def test_F9_nesting_is_limited_explicitly():
    m = mandate("a")
    deep: object = "x"
    for _ in range(M.MAX_DEPTH):
        deep = [deep]
    assert M.mandate_problem({**m, "x": {"d": deep}}) == "mandate is not valid I-JSON"
    ok: object = "x"
    for _ in range(M.MAX_DEPTH - 2):
        ok = [ok]
    assert M.mandate_problem({**m, "x": {"d": ok}}) is None


def test_F11_signer_unknown_does_not_hold_the_id():
    kyb = kyb_default()
    del kyb[P["b"]["id"]]
    b = bank(kyb)
    m = multi(["a", "b"], 2)
    assert b.check(m, pay(m, "INV-7"))["reasons"] == ["signer_unknown"]
    assert b.payments._items == {}


def test_F12_dependency_escalations_are_not_overridable():
    b = bank(kyb_default(), ledger=None, officers=[KEYS["officer"].pk])
    m = mandate("a")
    p = pay(m, "p_1")
    e = b.check(m, p)
    assert e["reasons"] == ["ledger_missing"]
    assert b.resolve(m, p, e, override(e, ["officer"]))["reasons"] == ["override_not_authorized"]


def test_F13_company_override_needs_what_the_mandate_needed():
    kyb = kyb_default()
    for n in ("a", "b"):
        kyb[P[n]["id"]] = M.AuthorityResult("bank_kyb", (KEYS[n].pk,), joint=2)
    b = bank(kyb)
    m = multi(["a", "b"], 1)
    p = pay(m, "p_1", "2000.00")
    e = b.check(m, p)
    assert b.resolve(m, p, e, override(e, ["c"]))["reasons"] == ["override_not_authorized"]
    assert b.resolve(m, p, e, override(e, ["c", "a"], oid="o_2"))["checks"][0] == "override:company:2/2"


def test_F14_signer_lists_are_capped():
    m = M.issue(id="m", company=CO, agent={"id": "a"}, scope=scope(), valid_until="2026-12-31T23:59:59.000Z",
                signers={"threshold": 1, "of": [P["a"]]})
    many = {"threshold": 1, "of": [{"id": f"p{i}", "public_key": M.new_key()[1]} for i in range(M.MAX_SIGNERS + 1)]}
    assert M.mandate_problem({**m, "signers": many}) == f"at most {M.MAX_SIGNERS} signers"


def test_F15_link_company_compares_exact_json():
    link_co = {**CO, "ids": None}
    assert not M._same_company(link_co, CO)
    assert not M._same_company({**CO, "ids": {"x": True}}, {**CO, "ids": {"x": 1}})
    assert M._same_company({**CO, "ids": {"x": 1}}, {**CO, "ids": {"x": 1}})


def test_F19_override_window_runs_from_the_first_escalation():
    from datetime import timedelta

    from akit3 import NOW

    clock = {"t": NOW}
    kyb = kyb_default()
    del kyb[P["b"]["id"]]
    b = bank(kyb, officers=[KEYS["officer"].pk], clock=lambda: clock["t"])
    m = multi(["a", "b"], 2, scope=scope(max_per_payment="10.00"))
    p = pay(m, "p_1")
    e1 = b.check(m, p)
    clock["t"] = NOW + timedelta(hours=71)
    e2 = b.resolve(m, p, e1, override(e1, ["officer"], decided_at=M.fmt_ts(clock["t"])))
    assert e2["reasons"] == ["over_payment_limit"] and e2["escalated_at"] == e1["checked_at"]
    clock["t"] = NOW + timedelta(hours=73)
    assert b.resolve(m, p, e2, override(e2, ["officer"], oid="o_2",
                                         decided_at=M.fmt_ts(clock["t"])))["reasons"] == ["override_invalid"]


def test_F19_company_cannot_lift_a_delegated_aggregate():
    kyb = kyb_default()
    b = bank(kyb, officers=[KEYS["officer"].pk])
    link = M.delegate(id="g", company=CO, from_=P["ceo"], to=P["cfo"], sk=KEYS["ceo"].sk,
                      scope=scope(max_per_payment="5000.00", payees=None,
                                  max_per_period={"amount": "1000.00", "period": "P1M"}),
                      valid_until="2027-01-31T23:59:59.000Z", issued_at="2026-10-01T00:00:00.000Z")
    m = M.sign_mandate(M.issue(id="m_cfo", company=CO, agent={"id": "agent", "public_key": KEYS["agent"].pk},
                               signer=P["cfo"], delegation=[link], valid_until="2026-12-31T23:59:59.000Z",
                               issued_at="2026-10-01T00:00:00.000Z",
                               scope=scope(max_per_period={"amount": "1000.00", "period": "P1M"})), KEYS["cfo"].sk)
    assert b.check(m, pay(m, "p_1", "900.00"))["outcome"] == "allow"
    p = pay(m, "p_2", "900.00")
    e = b.check(m, p)
    assert e["reasons"] == ["over_period_limit"]
    r = b.resolve(m, p, e, override(e, ["a"]))  # a company signatory, not the CEO's delegation
    assert r["reasons"] == ["over_period_limit"]  # the link's own 1000 still binds
    r2 = b.resolve(m, p, r, override(r, ["officer"], oid="o_2"))
    assert r2["outcome"] == "allow"
