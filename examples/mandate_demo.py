"""Smoke test of the mandate flow: issue, sign, attach, check, override, verify the decision.

    uv run python examples/mandate_demo.py

A signatory of Nordhafen Logistik GmbH gives the accounts payable agent a mandate. The bank checks
the payments the agent starts and signs a decision for each.
"""

from __future__ import annotations

from gleipnir_verify import mandate as m

# Keys: the company signatory, the agent and the bank (checker).
berger_sk, berger_pk = m.new_key()
agent_sk, agent_pk = m.new_key()
bank_sk, bank_pk = m.new_key()

BRENNER = {"name": "Brenner Stahl AG", "account": m.iban("AT61 1904 3002 3457 3201")}
NORDHAFEN = m.iban("AT48 3200 0000 1234 5864")  # the company's own account the agent pays from

mandate = m.sign_mandate(m.issue(
    id="m_demo_nordhafen_ap",
    company={"name": "Nordhafen Logistik GmbH", "country": "AT"},
    agent={"id": "ap-agent", "name": "Accounts payable agent", "public_key": agent_pk},
    signer={"id": "kberger@nordhafen.at", "name": "K. Berger", "role": "Authorised signatory", "public_key": berger_pk},
    scope={
        "rails": ["sepa", "sepa_instant"],
        "currency": "EUR",
        "max_per_payment": "25000.00",
        "max_per_period": {"amount": "100000.00", "period": "P1M"},
        "payees": [BRENNER],
        "from_accounts": [NORDHAFEN],
        "purpose": "Supplier invoices",
    },
    valid_until="2026-12-31T23:59:59.000Z",
), berger_sk)

# The bank's own KYB records: who may sign for which company, and with which keys.
KYB = {("Nordhafen Logistik GmbH", "kberger@nordhafen.at"): (berger_pk,)}


def authority(company: dict, signer_id: str) -> m.AuthorityResult | None:
    keys = KYB.get((company["name"], signer_id))
    return m.AuthorityResult("bank_kyb", keys) if keys else None


def holds(company: dict, account: dict) -> str | None:
    """The bank's books: its customer Nordhafen holds this account here (returns the customer id)."""
    return "cust:nordhafen" if company["name"] == "Nordhafen Logistik GmbH" and account == NORDHAFEN else None


bank = m.Checker(id="bank:DEMOATWW", sk=bank_sk, authority=authority, holds=holds, ledger=m.InMemoryLedger())
BANK_KEYS = [bank_pk]  # what a company or auditor gets from the bank, out of band

cases = [
    ("18 400 EUR to Brenner Stahl, IBAN on mandate", "18400.00", BRENNER, "allow"),
    ("UC6 new IBAN for Brenner Stahl", "18400.00",
     {"name": "Brenner Stahl AG", "account": {"scheme": "iban", "iban": "LT121000011101001000"}}, "block"),
    ("26 000 EUR to Brenner Stahl", "26000.00", BRENNER, "escalate"),
]

ok = True
payments, decisions = [], []
for i, (label, amount, payee, expected) in enumerate(cases, 1):
    payment = m.attach(mandate, id=f"p_demo_{i}", rail="sepa", amount=amount, currency="EUR",
                       payee=payee, reference=f"INV-2026-09{i:02d}", agent_sk=agent_sk)
    payments.append(payment)
    decision = bank.check(mandate, payment)
    decisions.append(decision)
    valid = m.verify_decision(decision, BANK_KEYS)
    reason = ",".join(decision["reasons"]) or "-"
    passed = decision["outcome"] == expected and valid
    ok &= passed
    print(f"{i}. {label:<48} {decision['outcome']:<9} reason={reason:<22} "
          f"decision_sig={'VALID' if valid else 'INVALID'}  {'ok' if passed else 'UNEXPECTED'}")

# 2b. After the block the agent corrects payment 2 (the IBAN on the mandate) and reuses the invoice id.
fixed = bank.check(mandate, m.attach(mandate, id="p_demo_2", rail="sepa", amount="18400.00", currency="EUR",
                                     payee=BRENNER, reference="INV-2026-0902", agent_sk=agent_sk))
ok &= fixed["outcome"] == "allow"
print(f"   {'payment 2 corrected, same invoice id':<48} {fixed['outcome']}")

# 3b. Payment 3 waits for a person: K. Berger approves it in the bank app (a signed override).
override = m.sign_override(m.make_override(decisions[2], outcome="allow", id="o_demo_3",
                                           reason="Annual maintenance contract"),
                           berger_sk, {"id": "kberger@nordhafen.at", "public_key": berger_pk})
final = bank.resolve(mandate, payments[2], decisions[2], override)
receipt = m.verify_receipt(mandate, payments[2], final, BANK_KEYS, override=override)
ok &= final["outcome"] == "allow" and receipt["valid"] and bank.check(mandate, payments[2]) == final
print(f"   {'payment 3 approved by K. Berger (override)':<48} {final['outcome']:<9} "
      f"approved_by={receipt['approved_by']}")

# 4. The agent sends payment 1 again: the bank gets the same decision back, nothing is booked twice.
again = bank.check(mandate, payments[0])
same = again == decisions[0]
dup = bank.check(mandate, m.attach(mandate, id="p_demo_1", rail="sepa", amount="1.00", currency="EUR",
                                   payee=BRENNER, agent_sk=agent_sk))  # same id, new amount, signed by the agent
ok &= same and dup["reasons"] == ["duplicate_payment"]
print(f"4. {'payment 1 resent':<48} {'same decision ' + again['id'] if same else 'NEW DECISION (BUG)'}")
print(f"   {'same payment id, new amount 1.00, re-signed':<48} {dup['outcome']:<9} reason={dup['reasons'][0]}")

# 5. A decision edited after the fact, or re-signed with someone else's key, does not verify.
tampered = dict(bank.check(mandate, m.attach(mandate, id="p_demo_t", rail="sepa", amount="26000.00",
                                             currency="EUR", payee=BRENNER, agent_sk=agent_sk)))
tampered["outcome"] = "allow"
evil_sk, evil_pk = m.new_key()
forged = m._sign(evil_sk, "decision", {**{k: v for k, v in tampered.items() if k != "sig"},
                                       "checker": {"id": "bank:DEMOATWW", "public_key": evil_pk}})
rejected = not m.verify_decision(tampered, BANK_KEYS) and not m.verify_decision(forged, BANK_KEYS)
ok &= rejected
print(f"5. {'edited decision / decision forged with own key':<48} verify_decision -> "
      f"{'INVALID, INVALID (as expected)' if rejected else 'VALID (BUG)'}")

# UC14. The CFO leaves. Their power came from the CEO through a signed delegation; the CEO cuts it.
ceo_sk, ceo_pk = m.new_key()
cfo_sk, cfo_pk = m.new_key()
CEO = {"id": "ceo@nordhafen.at", "role": "CEO", "public_key": ceo_pk}
CFO = {"id": "cfo@nordhafen.at", "role": "CFO", "public_key": cfo_pk}
KYB[("Nordhafen Logistik GmbH", CEO["id"])] = (ceo_pk,)
DELEGATES = {("Nordhafen Logistik GmbH", CFO["id"]): (cfo_pk,)}  # enrolled at the bank, no own signing power


def kyb_with_delegates(company: dict, person_id: str) -> m.AuthorityResult | None:
    key = (company["name"], person_id)
    if key in DELEGATES:
        return m.AuthorityResult("bank_kyb", DELEGATES[key], may_sign=False)
    return authority(company, person_id)


link = m.delegate(id="g_ceo_cfo", company={"name": "Nordhafen Logistik GmbH", "country": "AT"}, from_=CEO, to=CFO,
                  scope={"rails": ["sepa"], "currency": "EUR", "max_per_payment": "50000.00",
                         "from_accounts": [NORDHAFEN]},
                  valid_until="2027-03-31T23:59:59.000Z", sk=ceo_sk)
cfo_mandate = m.sign_mandate(m.issue(
    id="m_demo_cfo", company={"name": "Nordhafen Logistik GmbH", "country": "AT"},
    agent={"id": "ap-agent", "public_key": agent_pk}, signer=CFO, delegation=[link],
    scope={"rails": ["sepa"], "currency": "EUR", "max_per_payment": "25000.00", "payees": [BRENNER],
           "from_accounts": [NORDHAFEN]},
    valid_until="2026-12-31T23:59:59.000Z"), cfo_sk)
bank2 = m.Checker(id="bank:DEMOATWW", sk=bank_sk, authority=kyb_with_delegates, holds=holds,
                  ledger=m.InMemoryLedger())


def cfo_pay(n: int) -> dict:
    return m.attach(cfo_mandate, id=f"p_demo_cfo_{n}", rail="sepa", amount="9800.00", currency="EUR",
                    payee=BRENNER, agent_sk=agent_sk)


cfo_p1 = cfo_pay(1)
before = bank2.check(cfo_mandate, cfo_p1)
bank2.revocations.append(m.revoke(link, signer=CEO, sk=ceo_sk, id="r_cfo_left", reason="CFO left the company"))
after = bank2.check(cfo_mandate, cfo_pay(2))
passed = before["outcome"] == "allow" and after["reasons"] == ["delegation_revoked"]
ok &= passed
print(f"6. {'UC14 CFO (via CEO delegation) pays, then leaves':<48} {before['outcome']} -> {after['outcome']:<9} "
      f"reason={after['reasons'][0]:<22} {'ok' if passed else 'UNEXPECTED'}")

# UC19. The agent pays through a second bank that holds the account but has no KYB on Nordhafen's signatories.
second_sk, second_pk = m.new_key()
VLEI = {("Nordhafen Logistik GmbH", "kberger@nordhafen.at"): (berger_pk,)}  # OOR credential, issued by a QVI


def no_kyb(company: dict, person_id: str) -> m.AuthorityResult | None:
    return None


def vlei(company: dict, person_id: str) -> m.AuthorityResult | None:
    keys = VLEI.get((company["name"], person_id))
    return m.AuthorityResult("vlei", keys) if keys else None


results = []
for label, auth in (("without vLEI", no_kyb), ("with vLEI", m.combine(no_kyb, vlei))):
    other = m.Checker(id="bank:OTHERDEFF", sk=second_sk, authority=auth, holds=holds, ledger=m.InMemoryLedger())
    d = other.check(mandate, m.attach(mandate, id=f"p_demo_2nd_{len(results)}", rail="sepa", amount="5000.00",
                                      currency="EUR", payee=BRENNER, agent_sk=agent_sk))
    results.append(d)
    src = next((c for c in d["checks"] if c.startswith("signer_authorized:")), "-")
    print(f"{7 + len(results) - 1}. {'UC19 second bank, ' + label:<48} {d['outcome']:<9} "
          f"reason={','.join(d['reasons']) or '-':<22} {src}")
passed = results[0]["reasons"] == ["signer_unknown"] and results[1]["outcome"] == "allow"
ok &= passed
print(f"   {'UC19':<48} {'ok' if passed else 'UNEXPECTED'}")

# UC20 in one line: the receipt names who authorized the CFO payment, checkable offline with the bank's key.
r = m.verify_receipt(cfo_mandate, cfo_p1, before, BANK_KEYS)
ok &= r["valid"]
print(f"9. {'UC20 receipt for the CFO payment':<48} valid={r['valid']}  signed_by={r['signed_by']}  "
      f"chain={r['delegation']}")

# 0.5: an accounts payable mandate where new suppliers wait for a person instead of being blocked.
ap5 = m.sign_mandate(m.issue(
    id="m_demo_nordhafen_ap5",
    company={"name": "Nordhafen Logistik GmbH", "country": "AT"},
    agent={"id": "ap-agent", "name": "Accounts payable agent", "public_key": agent_pk},
    signer={"id": "kberger@nordhafen.at", "name": "K. Berger", "role": "Authorised signatory", "public_key": berger_pk},
    scope={"rails": ["sepa"], "currency": "EUR", "max_per_payment": "25000.00", "payees": [BRENNER],
           "from_accounts": [NORDHAFEN], "unlisted_payees": "escalate", "max_per_unlisted_payee": "5000.00"},
    valid_until="2026-12-31T23:59:59.000Z",
), berger_sk)
KRANBAU = {"name": "Kranbau Wels GmbH", "account": m.iban("AT13 1100 0006 2230 0000")}
SWAPPED = {"name": "BRENNER-STAHL A.G.", "account": m.iban("LT12 1000 0111 0100 1000")}
approval = m.sign_payee_approval(m.approve_payee(ap5, payee=KRANBAU, id="pa_kranbau", reason="Contract 2026-118"),
                                 berger_sk, {"id": "kberger@nordhafen.at", "public_key": berger_pk})


def pay5(pid: str, payee: dict, amount: str = "1200.00") -> dict:
    return m.attach(ap5, id=pid, rail="sepa", amount=amount, currency="EUR", payee=payee, agent_sk=agent_sk)


steps = [
    ("0.5 new supplier, not on the mandate", bank.check(ap5, pay5("p5_1", KRANBAU)), "new_payee"),
    ("0.5 'we changed our bank details', look-alike", bank.check(ap5, pay5("p5_2", SWAPPED)), "payee_account_changed"),
    ("0.5 new supplier, 6 000 EUR first payment", bank.check(ap5, pay5("p5_3", KRANBAU, "6000.00")),
     "over_unlisted_payee_limit"),
    ("0.5 supplier approved once by K. Berger", bank.check(ap5, pay5("p5_4", KRANBAU), [approval]), "-"),
]
for n, (label, d, want) in enumerate(steps, 10):
    passed = (",".join(d["reasons"]) or "-") == want and m.verify_decision(d, BANK_KEYS)
    ok &= passed
    print(f"{n}. {label:<48} {d['outcome']:<9} reason={','.join(d['reasons']) or '-':<22} "
          f"{'ok' if passed else 'UNEXPECTED'}")

raise SystemExit(0 if ok else 1)
