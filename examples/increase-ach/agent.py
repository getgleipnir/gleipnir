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
from datetime import timedelta
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

    def post(self, path: str, body: dict | None = None, idempotency_key: str | None = None) -> dict:
        headers = {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"}
        if idempotency_key:
            # Increase de-duplicates retried POSTs with the same key, so one allowed payment pays at most once.
            headers["Idempotency-Key"] = idempotency_key
        req = urllib.request.Request(self.base + path, data=json.dumps(body or {}).encode(), method="POST",
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            sys.exit(f"Increase {path}: HTTP {e.code} {e.read().decode(errors='replace')[:400]}")
        except (urllib.error.URLError, TimeoutError) as e:
            # The request may or may not have reached Increase. Don't retry blindly: look the transfer up first.
            sys.exit(f"Increase {path}: no answer ({e}); outcome unknown, check the dashboard before retrying")

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
        self.allowed: list[dict] = []  # transfer bodies the example is allowed to send, filled from allow decisions

    def _id(self, prefix: str) -> str:
        self.n += 1
        return f"{prefix}_fake{self.n:04d}"

    def post(self, path: str, body: dict | None = None, idempotency_key: str | None = None) -> dict:
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
            # Fail loudly if the example ever sends something other than exactly what a decision allowed.
            if body not in self.allowed or not idempotency_key:
                raise AssertionError(f"transfer not covered by an allow decision: {body}")
            t = {"id": self._id("ach_transfer"), "status": "pending_submission", **body}
            self.transfers.append(t)
            return t
        raise ValueError(path)


# ---------- the run ----------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true", help="use an in-memory fake instead of the Increase sandbox")
    ap.add_argument("--out", default="decisions.jsonl", help="where to write the signed decisions")
    ap.add_argument("--force", action="store_true", help="overwrite --out if it exists")
    args = ap.parse_args()

    out = Path(args.out)
    if out.exists() and not args.force:
        sys.exit(f"{out} exists; pass --force to overwrite it")

    if args.dry_run:
        inc = FakeIncrease()
        print("Increase: in-memory fake (--dry-run)")
    else:
        key = os.environ.get("INCREASE_API_KEY") or Increase.new_sandbox_key()
        inc = Increase(key)
        print("Increase: sandbox group ready")

    # Accounts belong to an entity. A fresh sandbox group has none, so create one from the sample body in
    # Increase's API reference (POST /entities); these are Increase's documented test values, not real data.
    entity_id = os.environ.get("INCREASE_ENTITY_ID")
    if not entity_id:
        if os.environ.get("INCREASE_API_KEY"):
            print("Increase: creating Increase's documented sample entity in your sandbox (set INCREASE_ENTITY_ID "
                  "to use your own)")
        entity_id = inc.post("/entities", INCREASE_SAMPLE_ENTITY)["id"]
    account = inc.post("/accounts", {"name": "Nordwind Trading operating account", "entity_id": entity_id})
    number = inc.post("/account_numbers", {"account_id": account["id"], "name": "AP payouts"})
    inc.post("/simulations/inbound_wire_transfers", {"account_number_id": number["id"], "amount": 5_000_000})
    own = m.account("us_aba", routing=number["routing_number"], account=number["account_number"])
    print(f"Increase: account {account['id']} funded with $50,000 (simulated wire)\n")

    # Keys. ALL FOUR LIVE IN THIS ONE PROCESS ONLY SO THE DEMO RUNS ON ITS OWN. In production the CFO signs with
    # their own passkey, the checker runs at the platform (or in a gateway that alone holds the Increase API key),
    # and the agent holds neither the API key nor any other signing key.
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
        valid_until=m.fmt_ts(m.utcnow() + timedelta(days=90))), signer_sk)
    print(f"Mandate {mandate['id']} signed by {signer['name']} ({signer['role']}): ACH to Acme Supplies, "
          "max $5,000 per payment, $20,000 per month, for 90 days\n")

    # The platform already knows from onboarding (KYB) who may sign for this business, and which account it holds.
    def authority(c: dict, person_id: str) -> m.AuthorityResult | None:
        ok = c["name"] == company["name"] and person_id == signer["id"]
        return m.AuthorityResult("bank_kyb", (signer_pk,)) if ok else None

    def holds(c: dict, acc: dict) -> str | None:
        return "cust:nordwind" if c["name"] == company["name"] and acc == own else None

    checker = m.Checker(id="platform:increase-demo", sk=checker_sk, authority=authority, holds=holds,
                        ledger=m.InMemoryLedger())
    out.write_text("")
    ok = True

    def record(decision: dict) -> None:
        with out.open("a") as f:
            f.write(json.dumps(decision) + "\n")

    def ach_body(payment: dict) -> dict:
        """The Increase transfer for exactly this payment. Only ever called for a verified allow decision."""
        acc = payment["payee"]["account"]
        # The payee name sent on the ACH entry comes from the mandate (the payee matched by account), not from
        # whatever name the agent wrote into the payment.
        name = next(p["name"] for p in mandate["scope"]["payees"] if p["account"] == acc)
        # account["id"] is the Increase account behind `own`, the from_account the checker verified.
        return {"account_id": account["id"], "amount": int(m.parse_amount(payment["amount"], "USD") * 100),
                "routing_number": acc["routing"], "account_number": acc["account"],
                "statement_descriptor": payment.get("reference", "Supplier invoice")[:200],
                "company_name": company["name"][:16], "individual_name": name[:22]}

    def pay_out(decision: dict, payment: dict) -> dict:
        """Send money only for a verified allow decision about this very payment."""
        if not (decision["outcome"] == "allow" and m.verify_decision(decision, [checker_pk])
                and decision["payment"] == {"id": payment["id"], "hash": m.obj_hash(payment, "agent_sig")}):
            raise RuntimeError(f"refusing to send {payment['id']}: no verified allow for this payment")
        body = ach_body(payment)
        if isinstance(inc, FakeIncrease):
            inc.allowed.append(body)
        return inc.post("/ach_transfers", body, idempotency_key=payment["id"])

    def send(payment: dict, label: str, expected: str) -> dict:
        nonlocal ok
        decision = checker.check(mandate, payment)
        record(decision)
        reasons = ",".join(decision["reasons"]) or "-"
        line = f"{label:<46} {decision['outcome']:<9} reason={reasons:<22}"
        if decision["outcome"] == "allow":
            t = pay_out(decision, payment)
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
    record(final)
    if final["outcome"] == "allow" and final.get("escalation", {}).get("id") == d3["id"]:
        t = pay_out(final, p3)  # the very payment that was escalated, nothing hard-coded
        print(f"{'   approved by Dana Ruiz (signed override)':<46} {final['outcome']:<9} {'':<29} -> ACH {t['id']}")
    ok &= final["outcome"] == "allow" and final.get("escalation", {}).get("id") == d3["id"]

    print(f"\nSigned decisions: {out} (verify with the checker key {checker_pk[:24]}...)")
    print("All outcomes as expected." if ok else "UNEXPECTED OUTCOME")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
