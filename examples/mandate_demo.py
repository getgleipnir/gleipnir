"""Smoke test of the mandate flow: issue, sign, attach, check, verify the decision.

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

BRENNER = {"name": "Brenner Stahl AG", "account": {"iban": "AT611904300234573201"}}

mandate = m.sign_mandate(m.issue(
    id="m_demo_nordhafen_ap",
    company={"name": "Nordhafen Logistik GmbH", "country": "AT"},
    agent={"id": "ap-agent", "name": "Accounts payable agent", "public_key": agent_pk},
    signer={"id": "kberger@nordhafen.at", "name": "K. Berger", "role": "Prokurist", "public_key": berger_pk},
    scope={
        "rails": ["sepa", "sepa_instant"],
        "currency": "EUR",
        "max_per_payment": "25000.00",
        "max_per_period": {"amount": "100000.00", "period": "P1M"},
        "payees": [BRENNER],
        "purpose": "Supplier invoices",
    },
    valid_until="2026-12-31T23:59:59.000Z",
), berger_sk)

# The bank's own KYB records: who may sign for which company, and with which keys.
KYB = {("Nordhafen Logistik GmbH", "kberger@nordhafen.at"): (berger_pk,)}


def authority(company: dict, signer_id: str) -> m.AuthorityResult | None:
    keys = KYB.get((company["name"], signer_id))
    return m.AuthorityResult("bank_kyb", keys) if keys else None


bank = m.Checker(id="bank:DEMOATWW", sk=bank_sk, authority=authority, ledger=m.InMemoryLedger())
BANK_KEYS = [bank_pk]  # what a company or auditor gets from the bank, out of band

cases = [
    ("18 400 EUR to Brenner Stahl, IBAN on mandate", "18400.00", BRENNER, "allow"),
    ("18 400 EUR to Brenner Stahl, changed IBAN", "18400.00",
     {"name": "Brenner Stahl AG", "account": {"iban": "LT121000011101001000"}}, "block"),
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

# 4. The agent sends payment 1 again: the bank gets the same decision back, nothing is booked twice.
again = bank.check(mandate, payments[0])
same = again == decisions[0]
dup = bank.check(mandate, {**payments[0], "amount": "1.00"})
ok &= same and dup["reasons"] == ["duplicate_payment"]
print(f"4. {'payment 1 resent':<48} {'same decision ' + again['id'] if same else 'NEW DECISION (BUG)'}")
print(f"   {'same payment id, amount changed to 1.00':<48} {dup['outcome']:<9} reason={dup['reasons'][0]}")

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

raise SystemExit(0 if ok else 1)
