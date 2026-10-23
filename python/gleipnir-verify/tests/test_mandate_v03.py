"""0.3 behaviour beyond the shared vectors: overrides end to end, receipts with overrides, key rotation edges."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from kit import DEBTOR, holds

from gleipnir_verify import mandate as M

NOW = datetime(2026, 10, 23, 9, 14, 2, tzinfo=timezone.utc)
CO = {"name": "Nordhafen Logistik GmbH", "country": "AT"}
BRENNER = {"name": "Brenner Stahl AG", "account": M.iban("AT611904300234573201")}


@pytest.fixture()
def w():
    keys = {n: M.new_key() for n in ("berger", "hofer", "agent", "bank", "ops", "evil")}
    people = {n: {"id": f"{n}@nordhafen.at", "public_key": keys[n][1]} for n in keys}
    kyb = {people[n]["id"]: M.AuthorityResult("bank_kyb", (keys[n][1],)) for n in ("berger", "hofer")}
    clock = {"t": NOW}
    bank = M.Checker(id="bank:t", sk=keys["bank"][0], authority=lambda c, pid: kyb.get(pid), holds=holds,
                     ledger=M.InMemoryLedger(), clock=lambda: clock["t"], officers=[keys["ops"][1]])
    m = M.sign_mandate(M.issue(id="m_1", company=CO, agent={"id": "a", "public_key": keys["agent"][1]},
                               signer=people["berger"], valid_until="2026-12-31T23:59:59.000Z",
                               issued_at="2026-10-01T08:00:00.000Z",
                               scope={"rails": ["sepa"], "currency": "EUR", "max_per_payment": "25000.00",
                                      "max_per_period": {"amount": "40000.00", "period": "P1M"},
                                      "payees": [BRENNER], "from_accounts": [DEBTOR]}), keys["berger"][0])
    return {"k": keys, "p": people, "kyb": kyb, "bank": bank, "m": m, "clock": clock}


def pay(w, pid, amount):
    return M.attach(w["m"], id=pid, rail="sepa", amount=amount, currency="EUR", payee=BRENNER,
                    agent_sk=w["k"]["agent"][0], requested_at=M.fmt_ts(w["clock"]["t"]))


def override(w, d, who="berger", outcome="allow", oid="o_1"):
    o = M.make_override(d, outcome=outcome, id=oid, decided_at=M.fmt_ts(w["clock"]["t"]))
    for name in [who] if isinstance(who, str) else who:
        o = M.sign_override(o, w["k"][name][0], w["p"][name])
    return o


def test_override_receipt_binds_the_override(w):
    p = pay(w, "p_1", "30000.00")
    d = w["bank"].check(w["m"], p)
    o = override(w, d)
    final = w["bank"].resolve(w["m"], p, d, o)
    keys = [w["k"]["bank"][1]]
    assert M.verify_receipt(w["m"], p, final, keys, override=o)["valid"]
    other = override(w, d, oid="o_2")
    assert M.verify_receipt(w["m"], p, final, keys, override=other)["problems"] == ["override_mismatch"]
    forged = {**o, "sigs": [{**o["sigs"][0], "sig": override(w, d, "evil")["sigs"][0]["sig"]}]}
    assert M.verify_receipt(w["m"], p, final, keys, override=forged)["problems"] == ["override_bad_signature"]
    plain = w["bank"].check(w["m"], pay(w, "p_2", "100.00"))
    assert M.verify_receipt(w["m"], pay(w, "p_2", "100.00"), plain, keys, override=o)["problems"] == \
        ["override_mismatch"]


def test_forced_period_override_keeps_ledger_totals_true(w):
    assert w["bank"].check(w["m"], pay(w, "p_1", "25000.00"))["outcome"] == "allow"
    p = pay(w, "p_2", "20000.00")
    d = w["bank"].check(w["m"], p)
    assert d["reasons"] == ["over_period_limit"]
    final = w["bank"].resolve(w["m"], p, d, override(w, d, "ops"))
    assert final["outcome"] == "allow" and "over_period_limit_approved" in final["checks"]
    (total,) = w["bank"].ledger.totals.values()
    assert total == Decimal("45000.00")


def test_override_cannot_be_used_for_another_payment_or_mandate(w):
    p = pay(w, "p_1", "30000.00")
    d = w["bank"].check(w["m"], p)
    o = override(w, d)
    p2 = pay(w, "p_9", "30000.00")
    assert w["bank"].resolve(w["m"], p2, d, o)["reasons"] == ["override_invalid"]
    # A decision from another bank (or edited) is not this checker's escalation.
    other = M.Checker(id="bank:x", sk=w["k"]["evil"][0], authority=w["bank"].authority, holds=holds,
                      ledger=M.InMemoryLedger(), clock=lambda: NOW)
    d_other = other.check(w["m"], p)
    assert w["bank"].resolve(w["m"], p, d_other, override(w, d_other))["reasons"] == ["override_invalid"]
    edited = {**d, "reasons": ["signer_unknown"]}
    assert w["bank"].resolve(w["m"], p, edited, override(w, edited, "ops"))["reasons"] == ["override_invalid"]


def test_override_after_mandate_revoked_blocks(w):
    p = pay(w, "p_1", "30000.00")
    d = w["bank"].check(w["m"], p)
    w["bank"].revocations.append(M.revoke(w["m"], signer=w["p"]["berger"], sk=w["k"]["berger"][0], id="r",
                                          revoked_at=M.fmt_ts(NOW)))
    final = w["bank"].resolve(w["m"], p, d, override(w, d))
    assert final["reasons"] == ["mandate_revoked"]
    # The block released the id: a corrected payment under a new mandate may use it.
    assert w["bank"].payments.lookup(M.payment_key(CO, "p_1"), M.obj_hash(p, "agent_sig")) is None


def test_concurrent_resolves_reserve_once(w):
    """Eight overrides of one held escalation at once: one re-check, one reservation (PaymentLog.take)."""
    import time

    class SlowLog(M.InMemoryPaymentLog):
        def lookup(self, key, payment_hash):
            time.sleep(0.01)  # every thread sees the held escalation before any takes it over
            return super().lookup(key, payment_hash)

    w["bank"].payments = SlowLog()
    p = pay(w, "p_1", "30000.00")
    d = w["bank"].check(w["m"], p)
    o = override(w, d)
    out = []
    threads = [threading.Thread(target=lambda: out.append(w["bank"].resolve(w["m"], p, d, o))) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert {x["outcome"] for x in out} <= {"allow", "block"}
    allows = {x["id"] for x in out if x["outcome"] == "allow"}
    assert len(allows) == 1
    (total,) = w["bank"].ledger.totals.values()
    assert total == Decimal("30000.00")


def test_key_rotation_applies_to_delegation_and_revocation(w):
    """A retired key still counts for what it signed before retirement: mandates, and revocations."""
    new_sk, new_pk = M.new_key()
    w["kyb"][w["p"]["berger"]["id"]] = M.AuthorityResult("bank_kyb", (new_pk,),
                                                         retired={w["p"]["berger"]["public_key"]:
                                                                  "2026-10-23T00:00:00.000Z"})
    assert w["bank"].check(w["m"], pay(w, "p_1", "100.00"))["outcome"] == "allow"  # issued before retirement
    late = M.revoke(w["m"], signer=w["p"]["berger"], sk=w["k"]["berger"][0], id="r_late",
                    revoked_at="2026-10-23T08:00:00.000Z")
    w["bank"].revocations = [late]  # signed with the retired key after retirement: not counted
    assert w["bank"].check(w["m"], pay(w, "p_2", "100.00"))["outcome"] == "allow"
    early = M.revoke(w["m"], signer=w["p"]["berger"], sk=w["k"]["berger"][0], id="r_early",
                     revoked_at="2026-10-22T08:00:00.000Z")
    w["bank"].revocations = [early]
    assert w["bank"].check(w["m"], pay(w, "p_3", "100.00"))["reasons"] == ["mandate_revoked"]
    old_pk = w["p"]["berger"]["public_key"]
    w["kyb"][w["p"]["berger"]["id"]] = M.AuthorityResult("bank_kyb", (new_pk,), retired={old_pk: "soon"})
    assert w["bank"].check(w["m"], pay(w, "p_4", "100.00"))["reasons"] == ["checker_unavailable"]


def test_holds_hook_failures_never_allow(w):
    for bad in (None, lambda c, a: "yes", lambda c, a: (_ for _ in ()).throw(TimeoutError())):
        w["bank"].holds = bad
        assert w["bank"].check(w["m"], pay(w, f"p_{id(bad)}", "100.00"))["reasons"] == ["checker_unavailable"]


def test_override_window_is_configurable(w):
    p = pay(w, "p_1", "30000.00")
    d = w["bank"].check(w["m"], p)
    w["clock"]["t"] = NOW + timedelta(days=5)
    o = override(w, d)
    assert w["bank"].resolve(w["m"], p, d, o)["reasons"] == ["override_invalid"]
    w["bank"].override_window = timedelta(days=7)
    assert w["bank"].resolve(w["m"], p, d, o)["outcome"] == "allow"


def test_attach_needs_from_account_when_several():
    m = {"id": "m", "scope": {"from_accounts": [DEBTOR, M.iban("DE44500105175407324931")]}}
    with pytest.raises(ValueError, match="several from_accounts"):
        M.attach(m, id="p", rail="sepa", amount="1.00", currency="EUR", payee=BRENNER)
