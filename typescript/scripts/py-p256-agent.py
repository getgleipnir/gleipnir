"""Python SDK side of the P-256 / approval / proof interop check (run with `uv run python -I`).

Usage: py-p256-agent.py OUT_DIR
Writes OUT_DIR/py-p256-bundle.zip, OUT_DIR/py-p256-proof.zip and OUT_DIR/py-refunds.csv, and
prints the key id and the proved action id.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import gleipnir
from gleipnir.kms import EcdsaP256Signer

out = Path(sys.argv[1])
home = out / ".gleipnir-py-p256"
shutil.rmtree(home, ignore_errors=True)
rec = gleipnir.Recorder(agent_id="support-agent", agent_version="0.3.1", home=home, signer=EcdsaP256Signer(),
                        segment_max_records=3, background=False, quiet=True)


@rec.tool(system="payments-api", redact=["card_number"])
def issue_refund(order_id: str, amount_cents: int, card_number: str) -> dict:
    return {"refund_id": "re_" + order_id, "status": "succeeded"}


approval = rec.approve(issue_refund, {"order_id": "A-1", "amount_cents": 25_500, "card_number": "4111"},
                       approver="ops:anna", rule="amount>100")
with rec.context(approval=approval):
    issue_refund("A-1", 25_500, "4111")
for i in range(2, 6):
    issue_refund(f"A-{i}", 1_000 * i, "4111")
target = next(r["id"] for r in rec.chain.store.read_all() if r.get("kind") == "action")
rec.export(out / "py-p256-bundle.zip")
rec.prove(target, out / "py-p256-proof.zip")
(out / "py-refunds.csv").write_text("refund_id,amount\nre_A-1,255\nre_A-2,20\nre_A-3,30\nre_A-4,40\nre_A-5,50\n")
print(f"signing key: {rec.key_id}")
print(f"action: {target}")
