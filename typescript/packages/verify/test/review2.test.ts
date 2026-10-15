/** Second independent review (Python 315ae62): ids, unbound approvals, proofs of non-actions, trusted time, lines, Rekor ints. */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { actionDigest, hasDropped, jsonLines, verifyBundle, verifyRecords, verifyRekorReceipt, type Report } from "@getgleipnir/verify";
import { Builder, proofFiles, proofZip, resign, zipBundle } from "./chainbuilder.js";

const codes = (r: Report) => new Set(r.errors.map((f) => f.code));

describe("verifier", () => {
  it("rejects duplicate record ids", () => {
    const b = new Builder();
    b.action(1);
    b.action(2);
    b.records[2]!["id"] = b.records[1]!["id"];
    resign(b.records, b.key, 2);
    const r = verifyRecords(b.records);
    expect(r.errors.find((f) => f.code === "duplicate_id")).toEqual({
      level: "error",
      code: "duplicate_id",
      message: `record id '${b.records[1]!["id"]}' is used twice`,
      seq: 2,
    });
  });

  it("an approval over a dropped argument is not binding", () => {
    const b = new Builder();
    const args = { order: "o1", amount: { redacted: "dropped" } };
    b.add({ kind: "review", id: "rev1", review: { action_digest: actionDigest("refund", "pay", args), decision: "approved", reviewer: "x" } });
    b.action(1, { approval: "rev1", args });
    expect(codes(verifyRecords(b.records))).toEqual(new Set(["approval_unbound_field"]));
    expect(hasDropped({ a: [{ b: { redacted: "dropped" } }] })).toBe(true);
    expect(hasDropped({ redacted: "dropped", extra: 1 })).toBe(false);
    expect(hasDropped({ redacted: "hmac-sha256:00" })).toBe(false);
  });

  it("a proof must prove an action", () => {
    const b = new Builder();
    b.action(1);
    const note = b.add({ kind: "note", note: { text: "n" } });
    b.anchor(b.segment());
    const { manifest, records } = proofFiles(b, note["id"]);
    const r = verifyBundle(proofZip(b, manifest, records));
    expect(r.errors.map((f) => [f.code, f.message])).toEqual([["proof_not_action", "the proven record is a 'note' record, not an action"]]);
  });

  it("--max-anchor-delay fails segments without a verified RFC 3161 timestamp", () => {
    const b = new Builder().standard();
    const r = verifyRecords(b.records, { anchorOptions: { localAnchorEntries: b.anchorLog }, maxAnchorDelay: 0 });
    expect(r.errors.map((f) => f.code)).toEqual(["no_trusted_time", "no_trusted_time", "no_trusted_time"]);
  });

  it("record lines: split on \\n, skip blank lines, reject non-JSON whitespace", () => {
    expect(jsonLines('{"a":1}\n \t\r\n\n{"b":2}\r\n')).toEqual(['{"a":1}', '{"b":2}\r']);
    const b = new Builder().standard();
    const zipWith = (sep: string, suffix = "") =>
      zipBundle({
        "manifest.json": JSON.stringify({ format: 1, chain: b.chain, from_seq: 1, to_seq: b.records[b.records.length - 1]!["seq"] }),
        "records.jsonl": b.records.map((r) => JSON.stringify(r) + suffix).join(sep),
        "anchors/local-anchor-log.jsonl": b.anchorLog.map((e) => JSON.stringify(e) + "\n").join(""),
      });
    expect(verifyBundle(zipWith("\n")).valid()).toBe(true);
    expect(verifyBundle(zipWith("\n \t\r\n\n")).valid()).toBe(true);
    expect(verifyBundle(zipWith("\r\n")).valid()).toBe(true);
    expect(verifyBundle(zipWith("\n", " ")).valid()).toBe(true);
    for (const bad of ["\u000b", "\u000c", "\u001c", "\u0085", " "]) {
      expect(verifyBundle(zipWith("\n", bad)).errors.map((f) => f.code), JSON.stringify(bad)).toEqual(["bad_bundle"]);
      expect(verifyBundle(zipWith(bad)).errors.map((f) => f.code), JSON.stringify(bad)).toEqual(["bad_bundle"]);
    }
  });
});

describe("Rekor logIndex / treeSize are plain non-negative decimals (_strict_uint)", () => {
  const FIX = fileURLToPath(new URL("./fixtures/", import.meta.url));
  const REKOR = JSON.parse(readFileSync(FIX + "rekor_v2_receipt.json", "utf8"));
  const SEG = REKOR.segment_hash as string;
  for (const bad of ["+152640350", " 152640350 ", "152_640_350", "١٥٢", 152640350.5, true, -1, "", "0x10"]) {
    it(`rejects ${JSON.stringify(bad)}`, () => {
      const a = structuredClone(REKOR.anchor);
      a.receipt.entry.inclusionProof.logIndex = bad;
      expect(verifyRekorReceipt(a, SEG, {}).ok).toBe(false);
      const t = structuredClone(REKOR.anchor);
      t.receipt.entry.inclusionProof.treeSize = bad;
      expect(verifyRekorReceipt(t, SEG, {}).ok).toBe(false);
    });
  }
  it("accepts the value as an int, too", () => {
    const a = structuredClone(REKOR.anchor);
    a.receipt.entry.inclusionProof.logIndex = Number(a.receipt.entry.inclusionProof.logIndex);
    expect(verifyRekorReceipt(a, SEG, {}).ok).toBe(true);
  });
});
