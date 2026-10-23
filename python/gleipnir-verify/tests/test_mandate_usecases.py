"""The 21 use cases from the chain-of-trust write-up (23.10.2026), one named test each.

Setup 1-4, each payment 5-13, lifecycle 14-18, cross-bank 19, after the fact 20-21.
Nordhafen Logistik GmbH: K. Berger (authorised signatory) and M. Hofer (managing director) sign; the CEO delegates to
the CFO; the accounts payable agent pays Brenner Stahl AG.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
from kit import DEBTOR, holds

from gleipnir_verify import mandate as M

T0 = datetime(2026, 10, 23, 9, 14, 2, tzinfo=timezone.utc)
COMPANY = {"name": "Nordhafen Logistik GmbH", "country": "AT"}
BRENNER = {"name": "Brenner Stahl AG", "account": {"scheme": "iban", "iban": "AT611904300234573201"}}
MUELLER = {"name": "Müller Transporte", "account": {"scheme": "iban", "iban": "DE89370400440532013000"}}
UNTIL = "2026-12-31T23:59:59.000Z"


def ts(t: datetime) -> str:
    return M.fmt_ts(t)


class World:
    """One company, its people and agent, and a bank whose KYB the tests can change."""

    def __init__(self) -> None:
        self.now = T0
        names = ("berger", "hofer", "ceo", "cfo", "agent", "agent2", "bank", "bank2")
        self.keys = {name: M.new_key() for name in names}
        self.people = {
            "berger": {"id": "kberger@nordhafen.at", "name": "K. Berger", "role": "Authorised signatory"},
            "hofer": {"id": "mhofer@nordhafen.at", "name": "M. Hofer", "role": "Managing director"},
            "ceo": {"id": "ceo@nordhafen.at", "role": "CEO"},
            "cfo": {"id": "cfo@nordhafen.at", "role": "CFO"},
        }
        # The bank's KYB: person id -> AuthorityResult. Tests edit it (a CFO leaves, a signer is added).
        self.kyb = {
            self.p("berger")["id"]: M.AuthorityResult("bank_kyb", (self.pk("berger"),)),
            self.p("hofer")["id"]: M.AuthorityResult("bank_kyb", (self.pk("hofer"),)),
            self.p("ceo")["id"]: M.AuthorityResult("bank_kyb", (self.pk("ceo"),)),
            self.p("cfo")["id"]: M.AuthorityResult("bank_kyb", (self.pk("cfo"),), may_sign=False),
        }
        self.bank = self.checker("bank:NORDATWW", "bank", self.kyb_authority)
        self.n = 0

    def sk(self, name: str):
        return self.keys[name][0]

    def pk(self, name: str) -> str:
        return self.keys[name][1]

    def p(self, name: str) -> dict:
        return {**self.people[name], "public_key": self.pk(name)}

    def kyb_authority(self, company: dict, person_id: str) -> M.AuthorityResult | None:
        return self.kyb.get(person_id) if company.get("name") == COMPANY["name"] else None

    def checker(self, bank_id: str, key: str, authority: M.Authority, **kw) -> M.Checker:
        return M.Checker(id=bank_id, sk=self.sk(key), authority=authority, ledger=M.InMemoryLedger(),
                         clock=lambda: self.now, holds=kw.pop("holds", holds), **kw)

    def scope(self, **kw) -> dict:
        s = {"rails": ["sepa", "sepa_instant"], "currency": "EUR", "max_per_payment": "25000.00",
             "max_per_period": {"amount": "40000.00", "period": "P1M"}, "payees": [BRENNER],
             "from_accounts": [DEBTOR], **kw}
        return {k: v for k, v in s.items() if v is not None}

    def mandate(self, signer: str = "berger", agent: str = "agent", mid: str = "m_ap", **kw) -> dict:
        m = M.issue(id=mid, company=COMPANY, agent={"id": f"{agent}-id", "public_key": self.pk(agent)},
                    signer=self.p(signer), scope=kw.pop("scope", None) or self.scope(),
                    valid_until=kw.pop("valid_until", UNTIL), **kw)
        return M.sign_mandate(m, self.sk(signer))

    def pay(self, m: dict, amount: str = "18400.00", *, payee: dict = BRENNER, agent: str | None = "agent",
            rail: str = "sepa", pid: str | None = None, at: datetime | None = None) -> dict:
        self.n += 1
        return M.attach(m, id=pid or f"p_{self.n}", rail=rail, amount=amount, currency="EUR", payee=payee,
                        reference=f"INV-{self.n}", agent_sk=self.sk(agent) if agent else None,
                        requested_at=ts(at or self.now))

    def revoke(self, target: dict, by: str, rid: str = "r_1", at: datetime | None = None) -> dict:
        return M.revoke(target, signer=self.p(by), sk=self.sk(by), id=rid, revoked_at=ts(at or self.now))


@pytest.fixture()
def w() -> World:
    return World()


def outcome(d: dict) -> tuple[str, list[str]]:
    return d["outcome"], d["reasons"]


# ---------- setup ----------

def test_uc01_issue(w):
    """CFO-level signatory issues a mandate in the bank app: payees, limits, validity. It is active."""
    m = w.mandate()
    assert M.mandate_problem(m) is None
    assert len(M.passkey_challenge(m)) == 32  # what a passkey in the bank's app signs
    d = w.bank.check(m, w.pay(m))
    assert outcome(d) == ("allow", [])
    assert "signer_authorized:bank_kyb" in d["checks"]
    with pytest.raises(ValueError, match="bad amount"):
        w.mandate(scope=w.scope(max_per_payment="25000"))
    with pytest.raises(ValueError, match="exactly one of signer or signers"):
        M.issue(id="m", company=COMPANY, agent={"id": "a"}, scope=w.scope(), valid_until=UNTIL)


def test_uc02_two_signers(w):
    """Joint signing: Berger and Hofer must both sign. One signature, or a joint signatory alone, is not enough."""
    unsigned = M.issue(id="m_joint", company=COMPANY, agent={"id": "agent-id", "public_key": w.pk("agent")},
                       signers={"threshold": 2, "of": [w.p("berger"), w.p("hofer")]}, scope=w.scope(),
                       valid_until=UNTIL)
    one = M.cosign(unsigned, w.sk("berger"), w.p("berger")["id"])
    both = M.cosign(one, w.sk("hofer"), w.p("hofer")["id"])
    assert outcome(w.bank.check(one, w.pay(one))) == ("block", ["signature_threshold_not_met"])
    d = w.bank.check(both, w.pay(both))
    assert outcome(d) == ("allow", []) and "signatures:2/2" in d["checks"]
    # Co-signer the bank does not know: maybe legitimate elsewhere -> escalate.
    del w.kyb[w.p("hofer")["id"]]
    assert outcome(w.bank.check(both, w.pay(both))) == ("escalate", ["signer_unknown"])
    # The register says Berger may only sign jointly (joint 2): alone he cannot issue even a 1-of-2 mandate.
    w.kyb[w.p("hofer")["id"]] = M.AuthorityResult("bank_kyb", (w.pk("hofer"),))
    w.kyb[w.p("berger")["id"]] = M.AuthorityResult("register", (w.pk("berger"),), joint=2)
    any1 = M.cosign({**unsigned, "signers": {**unsigned["signers"], "threshold": 1}}, w.sk("berger"),
                    w.p("berger")["id"])
    assert outcome(w.bank.check(any1, w.pay(any1))) == ("block", ["joint_signature_required"])
    single = w.mandate()
    assert outcome(w.bank.check(single, w.pay(single))) == ("block", ["joint_signature_required"])


def test_uc03_delegation(w):
    """CEO -> CFO -> agent: a signed chain. Each link through authority, no widening, a revoked link kills all below."""
    link = M.delegate(id="g_ceo_cfo", company=COMPANY, from_=w.p("ceo"), to=w.p("cfo"), sk=w.sk("ceo"),
                      scope=w.scope(max_per_payment="50000.00",
                                    max_per_period={"amount": "200000.00", "period": "P1M"}, payees=None),
                      valid_until="2027-03-31T23:59:59.000Z")
    m = w.mandate("cfo", delegation=[link])
    d = w.bank.check(m, w.pay(m))
    assert outcome(d) == ("allow", []) and "delegation:1" in d["checks"]
    wider = w.mandate("cfo", mid="m_wide", delegation=[link], scope=w.scope(max_per_payment="60000.00"))
    assert outcome(w.bank.check(wider, w.pay(wider))) == ("block", ["scope_exceeds_delegation"])
    # Without the chain, the CFO has no signing power of their own.
    alone = w.mandate("cfo", mid="m_alone")
    assert outcome(w.bank.check(alone, w.pay(alone))) == ("block", ["signer_not_authorized"])
    w.bank.revocations.append(w.revoke(link, "ceo", "r_link"))
    assert outcome(w.bank.check(m, w.pay(m))) == ("block", ["delegation_revoked"])


def test_uc04_change_limit_or_add_payee(w):
    """A change is a new mandate plus a revocation of the old one; editing in place breaks the signature."""
    old = w.mandate()
    new = w.mandate(mid="m_ap_v2", scope=w.scope(max_per_payment="30000.00", payees=[BRENNER, MUELLER]))
    w.bank.revocations.append(w.revoke(old, "berger", "r_old"))
    assert outcome(w.bank.check(old, w.pay(old))) == ("block", ["mandate_revoked"])
    assert outcome(w.bank.check(new, w.pay(new, "28000.00", payee=MUELLER))) == ("allow", [])
    edited = {**new, "scope": w.scope(max_per_payment="99000.00", payees=[BRENNER, MUELLER])}
    assert outcome(w.bank.check(edited, w.pay(edited, "90000.00"))) == ("block", ["mandate_bad_signature"])


# ---------- each payment ----------

def test_uc05_normal_invoice(w):
    m = w.mandate()
    d = w.bank.check(m, w.pay(m))
    assert outcome(d) == ("allow", [])
    assert d["checks"] == ["mandate_valid", "agent_signed", "signer_authorized:bank_kyb", "not_revoked",
                           "account_held", "payee_on_mandate", "within_payment_limit", "within_period_limit"]


def test_uc06_new_iban(w):
    """'We changed our bank details': a different account is a different payee."""
    m = w.mandate()
    swapped = {"name": "Brenner Stahl AG", "account": {"scheme": "iban", "iban": "LT121000011101001000"}}
    assert outcome(w.bank.check(m, w.pay(m, payee=swapped))) == ("block", ["payee_not_on_mandate"])
    same = {"name": "Brenner Stahl", "account": M.iban("at61 1904 3002 3457 3201")}  # as typed from the invoice
    assert outcome(w.bank.check(m, w.pay(m, payee=same))) == ("allow", [])
    # After the block the agent may correct the payment and use the same invoice id again.
    assert outcome(w.bank.check(m, w.pay(m, payee=swapped, pid="INV-77")))[0] == "block"
    assert outcome(w.bank.check(m, w.pay(m, pid="INV-77"))) == ("allow", [])


def test_uc07_over_payment_limit(w):
    """Above the limit a person decides: a signatory signs an override in the bank app, the bank re-checks."""
    m = w.mandate()
    p = w.pay(m, "25000.01")
    d = w.bank.check(m, p)
    assert outcome(d) == ("escalate", ["over_payment_limit"])
    assert w.bank.check(m, p) == d  # still waiting: the id stays held
    o = M.sign_override(M.make_override(d, outcome="allow", id="o_1", reason="Annual contract",
                                        decided_at=ts(w.now)), w.sk("berger"), w.p("berger"))
    final = w.bank.resolve(m, p, d, o)
    assert outcome(final) == ("allow", []) and "override:company:1/1" in final["checks"]
    assert final["escalation"] == {"id": d["id"], "hash": M.obj_hash(d)}
    assert w.bank.check(m, p) == final  # the agent's retry gets the final answer
    r = M.verify_receipt(m, p, final, [w.pk("bank")], override=o)
    assert r["valid"] and r["approved_by"] == ["kberger@nordhafen.at"]
    assert M.verify_receipt(m, p, final, [w.pk("bank")])["problems"] == ["override_missing"]
    assert outcome(w.bank.check(m, w.pay(m, "25000.00"))) == ("escalate", ["over_period_limit"])  # 40k a month
    assert outcome(w.bank.check(m, w.pay(m, "14999.99"))) == ("allow", [])


def test_uc08_monthly_limit_used_up(w):
    m = w.mandate()
    assert outcome(w.bank.check(m, w.pay(m, "20000.00")))[0] == "allow"
    assert outcome(w.bank.check(m, w.pay(m, "20000.00")))[0] == "allow"
    assert outcome(w.bank.check(m, w.pay(m, "0.01"))) == ("escalate", ["over_period_limit"])
    w.now = datetime(2026, 11, 2, 8, 0, tzinfo=timezone.utc)  # next calendar month (UTC)
    assert outcome(w.bank.check(m, w.pay(m, "20000.00")))[0] == "allow"


def test_uc09_same_payment_twice(w):
    m = w.mandate()
    p = w.pay(m, pid="p_twice")
    first = w.bank.check(m, p)
    assert w.bank.check(m, p) == first  # idempotent retry: same signed decision, booked once
    assert w.bank.ledger.totals[(f"mandate:{M.mandate_hash(m)}", "2026-10")] == M.parse_amount("18400.00", "EUR")
    changed = M.attach(m, id="p_twice", rail="sepa", amount="18500.00", currency="EUR", payee=BRENNER,
                       agent_sk=w.sk("agent"), requested_at=ts(w.now))
    assert outcome(w.bank.check(m, changed)) == ("block", ["duplicate_payment"])


def test_uc10_wrong_rail(w):
    m = w.mandate()
    assert outcome(w.bank.check(m, w.pay(m, rail="wire"))) == ("block", ["rail_not_allowed"])


def test_uc11_signed_by_another_agent(w):
    m = w.mandate()
    assert outcome(w.bank.check(m, w.pay(m, agent="agent2"))) == ("block", ["agent_bad_signature"])
    assert outcome(w.bank.check(m, w.pay(m, agent=None))) == ("block", ["agent_bad_signature"])


def test_uc12_mandate_tampered(w):
    m = w.mandate()
    raised = {**m, "scope": w.scope(max_per_payment="99999.00")}
    p = w.pay(m, "90000.00")  # payment still names the hash of the signed mandate
    assert outcome(w.bank.check(raised, p)) == ("block", ["mandate_mismatch"])
    assert outcome(w.bank.check(raised, w.pay(raised, "90000.00"))) == ("block", ["mandate_bad_signature"])
    forged = M.sign_mandate(raised, w.sk("agent"))  # re-signed with a key the bank never enrolled
    forged = {**forged, "signer": {**forged["signer"], "public_key": w.pk("agent")}}
    forged = M.sign_mandate(forged, w.sk("agent"))
    assert outcome(w.bank.check(forged, w.pay(forged, "90000.00"))) == ("block", ["signer_not_authorized"])


def test_uc13_time_manipulated(w):
    """The agent's clock does not count: an expired mandate stays expired, a past period stays past."""
    m = w.mandate(valid_until="2026-10-31T23:59:59.000Z")
    w.now = datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
    backdated = w.pay(m, at=datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc))
    assert outcome(w.bank.check(m, backdated)) == ("block", ["clock_skew"])
    honest = w.pay(m)
    assert outcome(w.bank.check(m, honest)) == ("block", ["mandate_expired"])
    assert outcome(w.bank.check(m, w.pay(m, at=w.now + timedelta(seconds=59)))) == ("block", ["mandate_expired"])


# ---------- lifecycle ----------

def test_uc14_cfo_fired(w):
    """From the moment the bank knows: KYB updated, or a revocation, or the delegation cut."""
    m = w.mandate()
    assert outcome(w.bank.check(m, w.pay(m)))[0] == "allow"
    w.kyb[w.p("berger")["id"]] = M.AuthorityResult("bank_kyb", (w.pk("berger"),), may_sign=False)
    assert outcome(w.bank.check(m, w.pay(m))) == ("block", ["signer_not_authorized"])
    del w.kyb[w.p("berger")["id"]]
    assert outcome(w.bank.check(m, w.pay(m))) == ("escalate", ["signer_unknown"])
    # Delegated CFO: the CEO cuts the delegation, or revokes the CFO's mandate directly.
    link = M.delegate(id="g_ceo_cfo", company=COMPANY, from_=w.p("ceo"), to=w.p("cfo"), sk=w.sk("ceo"),
                      scope=w.scope(max_per_payment="50000.00", payees=None,
                                    max_per_period={"amount": "200000.00", "period": "P1M"}),
                      valid_until="2027-03-31T23:59:59.000Z")
    cm = w.mandate("cfo", mid="m_cfo", delegation=[link])
    assert outcome(w.bank.check(cm, w.pay(cm)))[0] == "allow"
    w.bank.revocations.append(w.revoke(cm, "ceo", "r_cfo_m"))
    assert outcome(w.bank.check(cm, w.pay(cm))) == ("block", ["mandate_revoked"])
    w.bank.revocations = [w.revoke(link, "ceo", "r_link")]
    assert outcome(w.bank.check(cm, w.pay(cm))) == ("block", ["delegation_revoked"])
    # A revocation that only takes effect tomorrow does not block today.
    w.bank.revocations = [w.revoke(cm, "ceo", "r_later", at=w.now + timedelta(days=1))]
    assert outcome(w.bank.check(cm, w.pay(cm)))[0] == "allow"


def test_uc15_agent_replaced(w):
    old = w.mandate()
    w.bank.revocations.append(w.revoke(old, "berger", "r_agent"))
    new = w.mandate(agent="agent2", mid="m_ap_agent2")
    assert outcome(w.bank.check(old, w.pay(old))) == ("block", ["mandate_revoked"])
    assert outcome(w.bank.check(new, w.pay(new, agent="agent2"))) == ("allow", [])
    assert outcome(w.bank.check(new, w.pay(new, agent="agent"))) == ("block", ["agent_bad_signature"])


def test_uc16_mandate_expired(w):
    m = w.mandate(valid_until="2026-10-23T09:00:00.000Z")
    assert outcome(w.bank.check(m, w.pay(m))) == ("block", ["mandate_expired"])
    later = w.mandate(mid="m_later", valid_from="2026-11-01T00:00:00.000Z")
    assert outcome(w.bank.check(later, w.pay(later))) == ("block", ["mandate_not_yet_valid"])


@pytest.mark.parametrize("status", [None, "down", "garbage", "unsigned", "revoked"])
def test_uc17_revocation_status_unreachable(w, status):
    """status_url that cannot be read, or answers without a valid signature, escalates; never allows."""
    m = w.mandate(status_url="https://bank.example/mandates/m_ap/status")

    def answer(st):
        return M.status_response(m, status=st, signer=w.p("berger"), sk=w.sk("berger"), at=ts(w.now))

    def fetch(url: str):
        if status == "down":
            raise ConnectionError(url)
        if status == "revoked":
            return answer("revoked")
        if status == "unsigned":
            return {k: v for k, v in answer("active").items() if k != "sig"}
        return status
    w.bank.status = None if status is None else fetch
    expected = ("block", ["mandate_revoked"]) if status == "revoked" else ("escalate", ["status_unavailable"])
    assert outcome(w.bank.check(m, w.pay(m))) == expected
    w.bank.status = lambda url: answer("active")
    assert outcome(w.bank.check(m, w.pay(m)))[0] == "allow"


def test_uc18_signer_unknown_to_bank(w):
    w.people["stranger"] = {"id": "ext@consultant.example"}
    w.keys["stranger"] = M.new_key()
    m = w.mandate("stranger")
    assert outcome(w.bank.check(m, w.pay(m))) == ("escalate", ["signer_unknown"])
    w.bank.authority = lambda company, pid: (_ for _ in ()).throw(TimeoutError("kyb down"))
    assert outcome(w.bank.check(m, w.pay(m))) == ("escalate", ["checker_unavailable"])


# ---------- cross-bank ----------

def test_uc19_second_bank(w):
    """The agent pays through a bank that never onboarded the company: no KYB there, vLEI closes the gap."""
    m = w.mandate()
    no_kyb = w.checker("bank:OTHERDEFF", "bank2", lambda company, pid: None)
    assert outcome(no_kyb.check(m, w.pay(m))) == ("escalate", ["signer_unknown"])

    vlei_creds = {w.p("berger")["id"]: M.AuthorityResult("vlei", (w.pk("berger"),))}  # OOR credential via a QVI

    def vlei(company: dict, pid: str) -> M.AuthorityResult | None:
        return vlei_creds.get(pid) if company.get("name") == COMPANY["name"] else None

    second = w.checker("bank:OTHERDEFF", "bank2", M.combine(lambda company, pid: None, vlei))
    # The mandate names the debtor account; it works at the bank that holds it (here: both do).
    d = second.check(m, w.pay(m))
    assert outcome(d) == ("allow", [])
    assert "signer_authorized:vlei" in d["checks"]
    # A vLEI credential bound to another key does not help.
    vlei_creds[w.p("berger")["id"]] = M.AuthorityResult("vlei", (w.pk("hofer"),))
    assert outcome(second.check(m, w.pay(m))) == ("block", ["signer_not_authorized"])
    # A bank that does not hold the debtor account cannot be used to replay the mandate.
    elsewhere = w.checker("bank:THIRDFRPP", "bank2", w.kyb_authority, holds=lambda company, account: False)
    assert outcome(elsewhere.check(m, w.pay(m))) == ("block", ["account_not_held"])


# ---------- after the fact ----------

def test_uc20_dispute_three_months_later(w):
    """A lawyer asks who authorized this payment. The receipt answers offline, without the bank or Gleipnir."""
    link = M.delegate(id="g_ceo_cfo", company=COMPANY, from_=w.p("ceo"), to=w.p("cfo"), sk=w.sk("ceo"),
                      scope=w.scope(max_per_payment="50000.00", payees=None,
                                    max_per_period={"amount": "200000.00", "period": "P1M"}),
                      valid_until="2027-03-31T23:59:59.000Z")
    m = w.mandate("cfo", delegation=[link])
    p = w.pay(m)
    d = w.bank.check(m, p)
    bank_keys = [w.pk("bank")]  # from the bank's published key list
    r = M.verify_receipt(m, p, d, bank_keys)
    assert r["valid"] and r["outcome"] == "allow"
    assert r["signed_by"] == ["cfo@nordhafen.at"]
    assert r["delegation"] == ["ceo@nordhafen.at -> cfo@nordhafen.at"]
    assert r["authority"] == ["signer_authorized:bank_kyb"]
    assert r["payment"] == {"id": p["id"], "amount": "18400.00", "currency": "EUR", "from": DEBTOR,
                            "payee": BRENNER["account"]}
    assert r["company"] == COMPANY["name"] and r["checker"] == "bank:NORDATWW"
    # Every way to rewrite history fails.
    assert M.verify_receipt(m, p, {**d, "outcome": "block"}, bank_keys)["problems"] == ["decision_bad_signature"]
    other = w.pay(m, "1.00")
    assert M.verify_receipt(m, other, d, bank_keys)["problems"] == ["decision_payment_mismatch"]
    swapped = w.mandate(mid="m_other")
    assert "decision_mandate_mismatch" in M.verify_receipt(swapped, p, d, bank_keys)["problems"]
    assert M.verify_receipt(m, p, d, [w.pk("bank2")])["problems"] == ["decision_bad_signature"]
    assert not M.verify_receipt("junk", None, None, bank_keys)["valid"]


def test_uc21_audit_log(w):
    """An auditor reviews all agent payments from the decision log, with nothing but the bank's public key."""
    m = w.mandate()
    log = []
    for amount, payee in [("18400.00", BRENNER), ("26000.00", BRENNER), ("100.00", MUELLER), ("22000.00", BRENNER),
                          ("1.00", BRENNER)]:
        p = w.pay(m, amount, payee=payee)
        log.append((p, w.bank.check(m, p)))
    bank_keys = [w.pk("bank")]
    receipts = [M.verify_receipt(m, p, d, bank_keys) for p, d in log]
    assert all(r["valid"] for r in receipts)
    assert Counter(r["outcome"] for r in receipts) == {"allow": 2, "escalate": 2, "block": 1}
    assert sum(M.parse_amount(r["payment"]["amount"], "EUR") for r in receipts if r["outcome"] == "allow") \
        == M.parse_amount("18401.00", "EUR")
    # An edited entry, or an entry signed by someone else, stands out.
    p, d = log[1]
    tampered = {**d, "outcome": "allow", "reasons": []}
    fake = M._sign(w.sk("bank2"), "decision", {**d, "checker": {"id": "bank:NORDATWW", "public_key": w.pk("bank2")}})
    assert not M.verify_receipt(m, p, tampered, bank_keys)["valid"]
    assert not M.verify_receipt(m, p, fake, bank_keys)["valid"]
