#!/usr/bin/env node
/**
 * Record the network responses the SDK's RekorAnchor and TimestampAnchor unit tests replay
 * (packages/sdk/test/fixtures/anchor_responses.json). Publishes one test hash to public Rekor
 * and asks Sigstore's TSA for one timestamp. Requires `npm run build` first.
 *
 * Usage (in typescript/): node scripts/record-anchor-fixtures.mjs
 * (Behind an HTTPS proxy, Node >= 22.21 needs NODE_USE_ENV_PROXY=1 for fetch to use it.)
 */

import { generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { RekorAnchor, TimestampAnchor } from "@getgleipnir/sdk";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "../packages/sdk/test/fixtures/anchor_responses.json");

const exchanges = [];
const recording = async (url, init) => {
  const resp = await fetch(url, init);
  const body = new Uint8Array(await resp.clone().arrayBuffer());
  exchanges.push({ url, status: resp.status, body: Buffer.from(body).toString("base64") });
  return resp;
};

// A throwaway anchor key, used only for this fixture (its public key is in a public Rekor entry).
const pem = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "pem", type: "pkcs8" });
const segmentHash = "sha256:" + "5e".repeat(32);
const req = { segmentHash, chain: "ch_fixture", segmentSeq: 3 };

const rekor = await new RekorAnchor("unused", { privateKey: pem, fetch: recording }).anchor(req);
const rekorResponse = exchanges.at(-1);
const tsa = await new TimestampAnchor(undefined, { fetch: recording }).anchor(req);
const tsaResponse = exchanges.at(-1);

writeFileSync(
  OUT,
  JSON.stringify(
    {
      note: "Recorded by typescript/scripts/record-anchor-fixtures.mjs: real responses from Sigstore Rekor v2 and TSA.",
      segment_hash: segmentHash,
      anchor_key_pem: pem,
      rekor: { url: rekorResponse.url, response_b64: rekorResponse.body, log_index: rekor.entry.logIndex },
      tsa: { url: tsaResponse.url, response_b64: tsaResponse.body, observed_at: tsa.observed_at },
    },
    null,
    1,
  ) + "\n",
);
console.log(`wrote ${OUT} (Rekor index ${rekor.entry.logIndex})`);
