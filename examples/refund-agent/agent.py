"""A toy support agent that issues refunds, recorded with Gleipnir.

No LLM or API key needed: the "agent" applies fixed rules so the demo is reproducible.
Run:  uv run python agent.py          (local test anchor)
      uv run python agent.py --rekor  (publishes segment hashes to the public Sigstore log)
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from fake_payments import FakePayments

import gleipnir

HERE = Path(__file__).parent
TICKETS = [
    {"ticket": "T-101", "order_id": "A-1001", "issue": "damaged item", "paid_cents": 4_210},
    {"ticket": "T-102", "order_id": "A-1002", "issue": "late delivery", "paid_cents": 18_000},
    {"ticket": "T-103", "order_id": "A-1003", "issue": "wrong size", "paid_cents": 2_999},
    {"ticket": "T-104", "order_id": "A-1004", "issue": "never arrived", "paid_cents": 25_500},
    {"ticket": "T-105", "order_id": "A-1005", "issue": "changed mind", "paid_cents": 1_500},
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rekor", action="store_true", help="anchor in the public Sigstore Rekor log")
    args = ap.parse_args()

    home = HERE / ".gleipnir"
    shutil.rmtree(home, ignore_errors=True)  # fresh demo each run
    payments = FakePayments()

    rec = gleipnir.Recorder(
        agent_id="support-agent", agent_version="0.3.1", home=home,
        anchor="rekor" if args.rekor else "local", segment_max_records=2, background=False,
    )

    def refund_booked_as_requested(call: gleipnir.Call, response: dict) -> gleipnir.Outcome:
        booked = payments.get_refund(response["refund_id"])  # read back from the system of record
        return gleipnir.Outcome.compare(
            expected={"order_id": call.args["order_id"], "amount_cents": call.args["amount_cents"]},
            observed={"order_id": booked["order_id"], "amount_cents": booked["amount_cents"]},
        )

    @rec.tool(system="payments-api", redact=["card_number"], verify_outcome=refund_booked_as_requested,
              claim=lambda a, r: f"Refunded {a['amount_cents'] / 100:.2f} on order {a['order_id']}")
    def issue_refund(order_id: str, amount_cents: int, card_number: str) -> dict:
        return payments.refund(order_id, amount_cents, card_number)

    with rec.context(model={"provider": "example", "name": "toy-rules", "version": "1"},
                     versions={"prompt": "refund-policy-v4"},
                     identity={"principal": "svc-support-agent", "credential_id": "cred-7f2",
                               "scope": "refunds:write"}):
        for t in TICKETS:
            with rec.context(on_behalf_of=f"ticket:{t['ticket']}"):
                if t["issue"] == "changed mind":
                    print(f"{t['ticket']}: no refund (policy)")
                    continue
                result = issue_refund(t["order_id"], t["paid_cents"], card_number="4111111111111111")
                print(f"{t['ticket']}: refund {result['refund_id']} for {t['paid_cents'] / 100:.2f}")

    bundle = rec.export(HERE / "bundle.zip")
    pack = rec.pack(HERE / "security-review-pack.zip")
    print()
    print(f"signing key: {rec.key_id}")
    print(f"bundle:      {bundle.name}")
    print(f"pack:        {pack.name} (open summary.html inside)")
    print()
    print("Verify, as the buyer would:")
    print(f"  uv run gleipnir-verify bundle.zip --expect-key {rec.key_id}")
    print("Then tamper with it and verify again:")
    print("  uv run python tamper.py bundle.zip tampered.zip && uv run gleipnir-verify tampered.zip")


if __name__ == "__main__":
    main()
