"""`gleipnir demo`: a support agent issues refunds through a payments API with a hidden bug.

Runs in about a second with no API keys or network. Every refund is recorded with the
payments system's real response, read back from the system of record, signed, chained and
anchored. The demo then verifies the bundle as a buyer would, edits one record, and shows
verification failing. Output: an evidence report (summary.html), the bundle and the pack.
"""

from __future__ import annotations

import itertools
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any

from gleipnir_verify.verifier import verify_bundle

TICKETS = [
    {"ticket": "T-101", "order_id": "A-1001", "issue": "damaged item", "paid_cents": 4_210},
    {"ticket": "T-102", "order_id": "A-1002", "issue": "late delivery", "paid_cents": 18_000},
    {"ticket": "T-103", "order_id": "A-1003", "issue": "wrong size", "paid_cents": 2_999},
    {"ticket": "T-104", "order_id": "A-1004", "issue": "never arrived", "paid_cents": 25_500},
    {"ticket": "T-105", "order_id": "A-1005", "issue": "changed mind", "paid_cents": 1_500},
]


class FakePayments:
    """A payments API with one realistic bug: large refunds are booked 50 cents short,
    but the API reports the amount it was asked for."""

    def __init__(self) -> None:
        self._ids = itertools.count(1001)
        self.refunds: dict[str, dict[str, Any]] = {}

    def refund(self, order_id: str, amount_cents: int, card_number: str) -> dict[str, Any]:
        if amount_cents <= 0:
            raise ValueError("amount must be positive")
        refund_id = f"R-{next(self._ids)}"
        booked = amount_cents - 50 if amount_cents > 10_000 else amount_cents
        self.refunds[refund_id] = {"refund_id": refund_id, "order_id": order_id, "amount_cents": booked}
        return {"refund_id": refund_id, "status": "accepted", "amount_cents": amount_cents}

    def get_refund(self, refund_id: str) -> dict[str, Any]:
        return dict(self.refunds[refund_id])


def tamper(src: Path, dst: Path) -> int | None:
    """Flip the first outcome mismatch to "match", as someone tidying records before a review might.
    Returns the seq of the edited record."""
    with zipfile.ZipFile(src) as zin:
        files = {n: zin.read(n) for n in zin.namelist()}
    lines = files["records.jsonl"].decode().splitlines()
    edited = None
    for i, line in enumerate(lines):
        rec = json.loads(line)
        if rec.get("kind") == "action" and rec.get("outcome", {}).get("check") == "mismatch":
            rec["outcome"] = {"check": "match", "method": "verify_outcome"}
            lines[i] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
            edited = rec["seq"]
            break
    files["records.jsonl"] = ("\n".join(lines) + "\n").encode()
    with zipfile.ZipFile(dst, "w") as zout:
        for name, data in files.items():
            zout.writestr(name, data)
    return edited


def _money(cents: int) -> str:
    return f"{cents / 100:,.2f}"


def run(out_dir: str | Path = "gleipnir-demo", *, anchor: str = "local", echo: Any = print) -> dict[str, Any]:
    """Run the demo into out_dir (replaced if it exists). Returns paths and results for tests."""
    import gleipnir

    out = Path(out_dir)
    if out.exists():
        if not (out / ".gleipnir-demo").exists():
            raise FileExistsError(f"{out} exists and is not a previous demo folder; choose another with -o")
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / ".gleipnir-demo").write_text("created by `gleipnir demo`; safe to delete\n")
    payments = FakePayments()
    rec = gleipnir.Recorder(agent_id="support-agent", agent_version="0.3.1", home=out / ".gleipnir",
                            anchor=anchor, segment_max_records=2, background=False, quiet=True)

    def refund_booked_as_requested(call: gleipnir.Call, response: dict[str, Any]) -> gleipnir.Outcome:
        booked = payments.get_refund(response["refund_id"])  # read back from the system of record
        return gleipnir.Outcome.compare(
            expected={"order_id": call.args["order_id"], "amount_cents": call.args["amount_cents"]},
            observed={"order_id": booked["order_id"], "amount_cents": booked["amount_cents"]},
        )

    @rec.tool(system="payments-api", redact=["card_number"], verify_outcome=refund_booked_as_requested,
              claim=lambda a, r: f"Refunded {_money(a['amount_cents'])} on order {a['order_id']}")
    def issue_refund(order_id: str, amount_cents: int, card_number: str) -> dict[str, Any]:
        return payments.refund(order_id, amount_cents, card_number)

    echo("A support agent works through 5 tickets. The payments API has a hidden bug.\n")
    with rec.context(model={"provider": "example", "name": "toy-rules", "version": "1"},
                     versions={"prompt": "refund-policy-v4"},
                     identity={"principal": "svc-support-agent", "credential_id": "cred-7f2",
                               "scope": "refunds:write"}):
        for t in TICKETS:
            with rec.context(on_behalf_of=f"ticket:{t['ticket']}"):
                if t["issue"] == "changed mind":
                    echo(f"  {t['ticket']}  no refund (policy)")
                    continue
                r = issue_refund(t["order_id"], t["paid_cents"], card_number="4111111111111111")
                booked = payments.get_refund(r["refund_id"])["amount_cents"]
                note = "agent says done, system agrees" if booked == t["paid_cents"] else \
                    f"agent says done, system booked {_money(booked)}  <- outcome mismatch"
                echo(f"  {t['ticket']}  refund {_money(t['paid_cents']):>7}  {note}")

    bundle = rec.export(out / "bundle.zip")
    pack = rec.pack(out / "security-review-pack.zip")
    with zipfile.ZipFile(pack) as z:
        (out / "summary.html").write_bytes(z.read("summary.html"))
    key = rec.key_id
    rec.close()

    good = verify_bundle(bundle, expect_key=key, require_full=True)
    tampered = out / "tampered.zip"
    seq = tamper(bundle, tampered)
    bad = verify_bundle(tampered, expect_key=key, require_full=True)

    echo(f"\nEvery action is signed ({key}), chained to the one before, and anchored "
         f"({'public Sigstore log' if anchor == 'rekor' else 'local test anchor'}).\n")
    echo(f"  1. Verify as the buyer would            {'VALID' if good.valid() else 'INVALID'}")
    codes = sorted({f.code for f in bad.errors})
    echo(f"  2. Edit record {seq} to hide the mismatch   "
         f"{'VALID (unexpected!)' if bad.valid() else 'INVALID: ' + ', '.join(codes)}")
    echo("\nYour evidence report and files:")
    echo(f"  {out / 'summary.html'}              open in a browser")
    echo(f"  {bundle}                hand this to the buyer")
    echo(f"  {pack}  report + CSV + bundle")
    echo("\nCheck it yourself, offline:")
    anchor_flag = " --require-anchor rekor" if anchor == "rekor" else ""
    echo(f"  gleipnir-verify {bundle} --expect-key {key}{anchor_flag} --require-full")
    return {"out": out, "bundle": bundle, "pack": pack, "summary": out / "summary.html", "key": key,
            "valid": good.valid(), "tampered_valid": bad.valid(), "tampered_codes": codes}
