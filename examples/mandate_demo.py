"""Smoke test of the mandate flow: issue, sign, attach, check, verify the decision.

    uv run python examples/mandate_demo.py

A signatory of Nordhafen Logistik GmbH gives the accounts payable agent a mandate. The bank checks
three payments the agent starts and signs a decision for each.
"""

from __future__ import annotations

from decimal import Decimal

from gleipnir_verify import mandate as m

# Keys: the company signatory, the agent and the bank (checker).
berger_sk, berger_pk = m.new_key()
agent_sk, agent_pk = m.new_key()
bank_sk, _ = m.new_key()

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

# The bank's own KYB records: who may sign for which company.
KYB = {("Nordhafen Logistik GmbH", "kberger@nordhafen.at"): berger_pk}


def authority(company: dict, signer: dict) -> str | None:
    key = KYB.get((company["name"], signer["id"]))
    return "bank_kyb" if key == signer.get("public_key") else None


paid: dict[str, Decimal] = {}  # running monthly total per mandate (the bank keeps this)
bank = m.Checker(id="bank:DEMOATWW", sk=bank_sk, authority=authority,
                 spent=lambda mid, _period, _at: paid.get(mid, Decimal(0)))

cases = [
    ("18 400 EUR to Brenner Stahl, IBAN on mandate", "18400.00", BRENNER, "allow"),
    ("18 400 EUR to Brenner Stahl, changed IBAN", "18400.00",
     {"name": "Brenner Stahl AG", "account": {"iban": "LT121000011101001000"}}, "block"),
    ("26 000 EUR to Brenner Stahl", "26000.00", BRENNER, "escalate"),
]

ok = True
for i, (label, amount, payee, expected) in enumerate(cases, 1):
    payment = m.attach(mandate, id=f"p_demo_{i}", rail="sepa", amount=amount, currency="EUR",
                       payee=payee, reference=f"INV-2026-09{i:02d}", agent_sk=agent_sk)
    decision = bank.check(mandate, payment)
    if decision["outcome"] == "allow":
        paid[mandate["id"]] = paid.get(mandate["id"], Decimal(0)) + Decimal(amount)
    valid = m.verify_decision(decision)
    reason = ",".join(decision["reasons"]) or "-"
    passed = decision["outcome"] == expected and valid
    ok &= passed
    print(f"{i}. {label:<48} {decision['outcome']:<9} reason={reason:<22} "
          f"decision_sig={'VALID' if valid else 'INVALID'}  {'ok' if passed else 'UNEXPECTED'}")

# A decision edited after the fact no longer verifies.
tampered = dict(bank.check(mandate, m.attach(mandate, id="p_demo_t", rail="sepa", amount="26000.00",
                                             currency="EUR", payee=BRENNER, agent_sk=agent_sk)))
tampered["outcome"] = "allow"
tampered_ok = not m.verify_decision(tampered)
ok &= tampered_ok
print(f"4. {'escalate edited to allow after signing':<48} verify_decision -> "
      f"{'INVALID (as expected)' if tampered_ok else 'VALID (BUG)'}")

raise SystemExit(0 if ok else 1)
