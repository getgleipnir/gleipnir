#!/usr/bin/env node
/**
 * The examples/refund-agent demo, written with @getgleipnir/sdk (requires `npm run build`).
 * Usage: node scripts/ts-refund-agent.mjs OUT_DIR
 * Writes OUT_DIR/ts-bundle.zip and a tampered copy OUT_DIR/ts-tampered.zip.
 */

import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";
import { Outcome, Recorder } from "@getgleipnir/sdk";

const out = process.argv[2] ?? ".";
const home = join(out, ".gleipnir-ts");
rmSync(home, { recursive: true, force: true });

/** A fake payments API with a bug: refunds over $100 are booked 50 cents short. */
class FakePayments {
  refunds = new Map();
  refund(orderId, amountCents) {
    const id = `re_${this.refunds.size + 1}`;
    const booked = amountCents > 10000 ? amountCents - 50 : amountCents;
    this.refunds.set(id, { refund_id: id, order_id: orderId, amount_cents: booked });
    return { refund_id: id, status: "succeeded", amount_cents: amountCents };
  }
  getRefund(id) {
    return this.refunds.get(id);
  }
}

const TICKETS = [
  { ticket: "T-101", order_id: "A-1001", issue: "damaged item", paid_cents: 4210 },
  { ticket: "T-102", order_id: "A-1002", issue: "late delivery", paid_cents: 18000 },
  { ticket: "T-103", order_id: "A-1003", issue: "wrong size", paid_cents: 2999 },
  { ticket: "T-104", order_id: "A-1004", issue: "never arrived", paid_cents: 25500 },
  { ticket: "T-105", order_id: "A-1005", issue: "changed mind", paid_cents: 1500 },
];

const payments = new FakePayments();
const rec = new Recorder({
  agentId: "support-agent",
  agentVersion: "0.3.1",
  home,
  segmentMaxRecords: 2,
  background: false,
  quiet: true,
});

const issueRefund = rec.tool((order_id, amount_cents, card_number) => payments.refund(order_id, amount_cents, card_number), {
  system: "payments-api",
  name: "issue_refund",
  params: ["order_id", "amount_cents", "card_number"],
  redact: ["card_number"],
  verifyOutcome: (call, response) => {
    const booked = payments.getRefund(response.refund_id);
    return Outcome.compare(
      { order_id: call.args.order_id, amount_cents: call.args.amount_cents },
      { order_id: booked.order_id, amount_cents: booked.amount_cents },
    );
  },
  claim: (a) => `Refunded ${(a.amount_cents / 100).toFixed(2)} on order ${a.order_id}`,
});

rec.context(
  {
    model: { provider: "example", name: "toy-rules", version: "1" },
    versions: { prompt: "refund-policy-v4" },
    identity: { principal: "svc-support-agent", credential_id: "cred-7f2", scope: "refunds:write" },
  },
  () => {
    for (const t of TICKETS) {
      rec.context({ on_behalf_of: `ticket:${t.ticket}` }, () => {
        if (t.issue === "changed mind") return console.log(`${t.ticket}: no refund (policy)`);
        const r = issueRefund(t.order_id, t.paid_cents, "4111111111111111");
        console.log(`${t.ticket}: refund ${r.refund_id} for ${(t.paid_cents / 100).toFixed(2)}`);
      });
    }
  },
);
rec.note("Gr\u00fc\u00dfe \u20ac \u{1f600} unicode note", { big: 9007199254740991, small: 1e-7, neg: -0, ratio: 42.1 });

const bundle = await rec.export(join(out, "ts-bundle.zip"));
console.log(`signing key: ${rec.keyId}`);
console.log(`bundle:      ${bundle}`);

// Tampered copy: replace the first outcome mismatch with a match (like examples/refund-agent/tamper.py).
const files = unzipSync(readFileSync(bundle));
const lines = strFromU8(files["records.jsonl"]).split("\n");
const i = lines.findIndex((l) => l.includes('"check":"mismatch"'));
lines[i] = lines[i].replace(/"outcome":\{[^}]*\{[^}]*\}[^}]*\}|"outcome":\{[^}]*\}/, '"outcome":{"check":"match","method":"verify_outcome"}');
files["records.jsonl"] = strToU8(lines.join("\n"));
writeFileSync(join(out, "ts-tampered.zip"), zipSync(files));
