"""An accounts payable agent pays suppliers by ACH through Increase, under a Gleipnir mandate.

    uv run python examples/increase-ach/agent.py            # live Increase sandbox (no account needed)
    uv run python examples/increase-ach/agent.py --dry-run  # same flow against an in-memory fake, offline

What happens:

1. Increase sandbox: a fresh sandbox group (one unauthenticated POST /groups), an account, an account
   number, and $50,000 of simulated incoming wire to pay from. Set INCREASE_API_KEY to reuse a key.
2. The company's signatory signs a mandate for the agent: ACH only, one supplier, at most $5,000 per payment
   and $20,000 per month, from this one account, until the end of the year.
3. The agent asks the platform's checker before every payment. Only an "allow" reaches POST /ach_transfers.
     a. $1,250 to Acme Supplies, account on the mandate      -> allow    -> ACH transfer created
     b. $1,250 to "Acme Supplies" at a new account number    -> block    -> nothing sent (the agent was tricked)
     c. $7,500 to Acme Supplies                              -> escalate -> the signatory approves -> sent
4. Every decision is signed by the checker and written to decisions.jsonl; anyone with the checker's public
   key can verify it later, and a changed byte breaks it.

Gleipnir never touches the money: Increase moves it, the checker only says whether this agent may.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from gleipnir_verify import mandate as m

SANDBOX = "https://sandbox.increase.com"
ACME = {"name": "Acme Supplies Inc", "account": m.account("us_aba", routing="101050001", account="987654321")}
TRICKED = {"name": "Acme Supplies Inc", "account": m.account("us_aba", routing="101050001", account="555000111")}

# The example request body of "Create an Entity" in Increase's API reference (increase.com/documentation/api/entities).
_ADDR = {"city": "New York", "line1": "33 Liberty Street", "state": "NY", "zip": "10045"}
INCREASE_SAMPLE_ENTITY = {"structure": "corporation", "corporation": {
    "name": "National Phonograph Company", "website": "https://example.com", "incorporation_state": "NY",
    "address": _ADDR, "legal_identifier": {"category": "us_employer_identification_number", "value": "602214076"},
    "beneficial_owners": [{"company_title": "CEO", "prongs": ["control"], "individual": {
        "name": "Ian Crease", "date_of_birth": "1970-01-31", "address": _ADDR,
        "identification": {"method": "social_security_number", "number": "078051120"}}}]}}


# ---------- a tiny Increase client (stdlib only) ----------

class Increase:
    def __init__(self, key: str, base: str = SANDBOX) -> None:
        self.key, self.base = key, base

    def post(self, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(self.base + path, data=json.dumps(body or {}).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {self.key}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            sys.exit(f"Increase {path}: HTTP {e.code} {e.read().decode(errors='replace')[:400]}")

    @staticmethod
    def new_sandbox_key(base: str = SANDBOX) -> str:
        req = urllib.request.Request(base + "/groups", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["sandbox_api_key"]


class FakeIncrease:
    """Offline stand-in with the same calls and response fields the example uses."""

    def __init__(self) -> None:
        self.n, self.transfers = 0, []

    def _id(self, prefix: str) -> str:
        self.n += 1
        return f"{prefix}_fake{self.n:04d}"

    def post(self, path: str, body: dict | None = None) -> dict:
        body = body or {}
        if path == "/entities":
            return {"id": self._id("entity")}
        if path == "/accounts":
            return {"id": self._id("account"), "name": body["name"]}
        if path == "/account_numbers":
            return {"id": self._id("account_number"), "account_id": body["account_id"],
                    "routing_number": "101050001", "account_number": "123456789012"}
        if path == "/simulations/inbound_wire_transfers":
            return {"id": self._id("inbound_wire_transfer"), "amount": body["amount"]}
        if path == "/ach_transfers":
            t = {"id": self._id("ach_transfer"), "status": "pending_submission", **body}
            self.transfers.append(t)
            return t
        raise ValueError(path)


# ---------- the run ----------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true", help="use an in-memory fake instead of the Increase sandbox")
    ap.add_argument("--out", default="decisions.jsonl", help="where to write the signed decisions")
    args = ap.parse_args()

    if args.dry_run:
        inc = FakeIncrease()
        print("Increase: in-memory fake (--dry-run)")
    else:
        key = os.environ.get("INCREASE_API_KEY") or Increase.new_sandbox_key()
        inc = Increase(key)
        print("Increase: sandbox group ready")

    # Accounts belong to an entity. A fresh sandbox group has none, so create one from the sample body in
    # Increase's API reference (POST /entities); these are Increase's documented test values, not real data.
    entity_id = os.environ.get("INCREASE_ENTITY_ID") or inc.post("/entities", INCREASE_SAMPLE_ENTITY)["id"]
    account = inc.post("/accounts", {"name": "Nordwind Trading operating account", "entity_id": entity_id})
    number = inc.post("/account_numbers", {"account_id": account["id"], "name": "AP payouts"})
    inc.post("/simulations/inbound_wire_transfers", {"account_number_id": number["id"], "amount": 5_000_000})
    own = m.account("us_aba", routing=number["routing_number"], account=number["account_number"])
    print(f"Increase: account {account['id']} funded with $50,000 (simulated wire)\n")

    # Keys: the company's signatory, the AP agent, and the platform's checker.
    signer_sk, signer_pk = m.new_key()
    agent_sk, agent_pk = m.new_key()
    checker_sk, checker_pk = m.new_key()
    company = {"name": "Nordwind Trading LLC", "country": "US"}
    signer = {"id": "dana@nordwind.example", "name": "Dana Ruiz", "role": "CFO", "public_key": signer_pk}

    mandate = m.sign_mandate(m.issue(
        id="m_nordwind_ap_ach", company=company,
        agent={"id": "ap-agent", "name": "Accounts payable agent", "public_key": agent_pk}, signer=signer,
        scope={"rails": ["ach"], "currency": "USD", "max_per_payment": "5000.00",
               "max_per_period": {"amount": "20000.00", "period": "P1M"},
               "payees": [ACME], "from_accounts": [own], "purpose": "Supplier invoices"},
        valid_until="2026-12-31T23:59:59.000Z"), signer_sk)
    print(f"Mandate {mandate['id']} signed by {signer['name']} ({signer['role']}): ACH to Acme Supplies, "
          "max $5,000 per payment, $20,000 per month\n")

    # The platform already knows from onboarding (KYB) who may sign for this business, and which account it holds.
    def authority(c: dict, person_id: str) -> m.AuthorityResult | None:
        ok = c["name"] == company["name"] and person_id == signer["id"]
        return m.AuthorityResult("bank_kyb", (signer_pk,)) if ok else None

    def holds(c: dict, acc: dict) -> str | None:
        return "cust:nordwind" if c["name"] == company["name"] and acc == own else None

    checker = m.Checker(id="platform:increase-demo", sk=checker_sk, authority=authority, holds=holds,
                        ledger=m.InMemoryLedger())
    out = Path(args.out)
    out.write_text("")
    ok = True

    def send(payment: dict, label: str, expected: str) -> dict:
        nonlocal ok
        decision = checker.check(mandate, payment)
        with out.open("a") as f:
            f.write(json.dumps(decision) + "\n")
        reasons = ",".join(decision["reasons"]) or "-"
        line = f"{label:<46} {decision['outcome']:<9} reason={reasons:<22}"
        if decision["outcome"] == "allow":
            t = inc.post("/ach_transfers", {
                "account_id": account["id"], "amount": int(m.parse_amount(payment["amount"], "USD") * 100),
                "routing_number": payment["payee"]["account"]["routing"],
                "account_number": payment["payee"]["account"]["account"],
                "statement_descriptor": payment.get("reference", "Supplier invoice")[:200],
                "company_name": company["name"][:16], "individual_name": payment["payee"]["name"][:22]})
            line += f" -> ACH {t['id']} ({t.get('status', 'created')})"
        else:
            line += " -> not sent"
        ok &= decision["outcome"] == expected and m.verify_decision(decision, [checker_pk])
        print(line)
        return decision

    def pay(pid: str, amount: str, payee: dict, ref: str) -> dict:
        return m.attach(mandate, id=pid, rail="ach", amount=amount, currency="USD", payee=payee, reference=ref,
                        agent_sk=agent_sk)

    send(pay("p_inv_1001", "1250.00", ACME, "INV-1001"), "a. $1,250 to Acme, account on the mandate", "allow")
    send(pay("p_inv_1002", "1250.00", TRICKED, "INV-1002"), "b. $1,250 to 'Acme', new account number", "block")
    p3 = pay("p_inv_1003", "7500.00", ACME, "INV-1003")
    d3 = send(p3, "c. $7,500 to Acme (over $5,000 limit)", "escalate")

    # The CFO looks at invoice 1003 and approves it: a signed override, not a click in someone else's tool.
    override = m.sign_override(m.make_override(d3, outcome="allow", id="o_inv_1003", reason="Annual contract"),
                               signer_sk, {"id": signer["id"], "public_key": signer_pk})
    final = checker.resolve(mandate, p3, d3, override)
    with out.open("a") as f:
        f.write(json.dumps(final) + "\n")
    if final["outcome"] == "allow":
        t = inc.post("/ach_transfers", {
            "account_id": account["id"], "amount": 750_000, "routing_number": ACME["account"]["routing"],
            "account_number": ACME["account"]["account"], "statement_descriptor": "INV-1003",
            "company_name": company["name"][:16], "individual_name": ACME["name"][:22]})
        print(f"{'   approved by Dana Ruiz (signed override)':<46} {final['outcome']:<9} {'':<29} -> ACH {t['id']}")
    ok &= final["outcome"] == "allow"

    print(f"\nSigned decisions: {out} (verify with the checker key {checker_pk[:24]}...)")
    print("All outcomes as expected." if ok else "UNEXPECTED OUTCOME")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
