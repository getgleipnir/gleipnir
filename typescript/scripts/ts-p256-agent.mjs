#!/usr/bin/env node
/**
 * TypeScript SDK side of the P-256 / approval / proof interop check (requires `npm run build`).
 * Usage: node scripts/ts-p256-agent.mjs OUT_DIR
 * Writes OUT_DIR/ts-p256-bundle.zip, OUT_DIR/ts-p256-proof.zip and OUT_DIR/ts-refunds.csv.
 */

import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { EcdsaP256Signer, Recorder } from "@getgleipnir/sdk";

const out = process.argv[2] ?? ".";
const home = join(out, ".gleipnir-ts-p256");
rmSync(home, { recursive: true, force: true });

const rec = new Recorder({
  agentId: "support-agent",
  agentVersion: "0.3.1",
  home,
  signer: EcdsaP256Signer.generate(),
  segmentMaxRecords: 3,
  background: false,
  quiet: true,
});
const issueRefund = rec.tool((order_id) => ({ refund_id: `re_${order_id}`, status: "succeeded" }), {
  system: "payments-api",
  name: "issue_refund",
  params: ["order_id", "amount_cents", "card_number"],
  redact: ["card_number"],
});

const approval = rec.approve(issueRefund, { order_id: "A-1", amount_cents: 25500, card_number: "4111" }, { approver: "ops:anna", rule: "amount>100" });
rec.context({ approval }, () => issueRefund("A-1", 25500, "4111"));
for (let i = 2; i < 6; i++) issueRefund(`A-${i}`, 1000 * i, "4111");
const target = rec.chain.store.readAll().find((r) => r.kind === "action").id;
await rec.export(join(out, "ts-p256-bundle.zip"));
await rec.prove(target, join(out, "ts-p256-proof.zip"));
// re_A-5 missing from the buyer's system, re_A-9 never recorded
writeFileSync(join(out, "ts-refunds.csv"), "refund_id\nre_A-1\nre_A-2\nre_A-3\nre_A-4\nre_A-9\n");
console.log(`signing key: ${rec.keyId}`);
console.log(`action: ${target}`);
