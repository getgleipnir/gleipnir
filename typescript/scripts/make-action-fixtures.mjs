#!/usr/bin/env node
/**
 * Make the bundles the GitHub Action is tested against (action/test/fixtures/):
 *   valid.zip     a TypeScript SDK bundle, every segment anchored on public Rekor v2 and
 *                 timestamped by Sigstore's TSA (so require-anchor and max-anchor-delay apply)
 *   tampered.zip  the same bundle with one recorded refund amount changed afterwards
 *   fixtures.json the signing key id and head of valid.zip, for the workflow's inputs
 *
 * Publishes a few test hashes to public Rekor. Requires `npm run build` first.
 * Usage (in typescript/): NODE_USE_ENV_PROXY=1 node scripts/make-action-fixtures.mjs
 */

import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";
import { Recorder } from "@getgleipnir/sdk";
import { verifyBundle } from "@getgleipnir/verify";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "../../action/test/fixtures");
mkdirSync(OUT, { recursive: true });

const home = mkdtempSync(join(tmpdir(), "gleipnir-action-fixture-"));
const warnings = [];
const rec = new Recorder({
  agentId: "action-fixture-agent",
  agentVersion: "1.0.0",
  home,
  quiet: true,
  background: false,
  anchor: "rekor",
  segmentMaxRecords: 3,
  onWarning: (m) => warnings.push(m),
});
const refund = rec.tool((order_id, amount_cents) => ({ refund_id: `re_${order_id}`, amount_cents }), {
  system: "payments-api",
  name: "issue_refund",
  params: ["order_id", "amount_cents"],
});
for (const [o, a] of [["A-1", 4210], ["A-2", 18000], ["A-3", 2999], ["A-4", 25500]]) refund(o, a);
const bundle = await rec.export(join(home, "bundle.zip"));
if (warnings.length) throw new Error(warnings.join("\n"));

const bytes = readFileSync(bundle);
const report = verifyBundle(bytes, { expectKey: rec.keyId, requireAnchor: ["rekor", "rfc3161"], maxAnchorDelay: 3600, requireFull: true });
if (!report.valid(true)) throw new Error(JSON.stringify(report.findings));
writeFileSync(join(OUT, "valid.zip"), bytes);

const files = unzipSync(bytes);
const lines = strFromU8(files["records.jsonl"]).split("\n");
const i = lines.findIndex((l) => l.includes('"issue_refund"') && l.includes("18000"));
lines[i] = lines[i].replaceAll("18000", "1800");
files["records.jsonl"] = strToU8(lines.join("\n"));
writeFileSync(join(OUT, "tampered.zip"), zipSync(files));

const head = report.summary["head"];
writeFileSync(
  join(OUT, "fixtures.json"),
  JSON.stringify({ key: rec.keyId, head: `${head.seq}:${head.hash}`, segments: report.summary["segments"] }, null, 2) + "\n",
);
console.log(`wrote action/test/fixtures (key ${rec.keyId}, ${report.summary["segments"]} segments, head ${head.seq})`);
