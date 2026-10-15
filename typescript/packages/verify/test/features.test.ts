/** ECDSA P-256 keys, approvals bound to actions, single-action proofs and reconcile (ports of the Python tests). */

import { describe, expect, it } from "vitest";
import {
  actionDigest,
  csvColumn,
  decodePublicKey,
  externalIds,
  keyId,
  reconcile,
  recordHash,
  recordMessage,
  verifyBundle,
  verifyRecords,
  verifySignature,
  type Report,
} from "@getgleipnir/verify";
import { Builder, Key, P256Key, proofFiles, proofZip, resign, writeBundle, zipBundle, type Rec } from "./chainbuilder.js";

const codes = (r: Report) => new Set(r.errors.map((f) => f.code));
const run = (b: Builder, recs: Rec[] = b.records) => verifyRecords(recs, { anchorOptions: { localAnchorEntries: b.anchorLog } });

describe("ECDSA P-256 record keys", () => {
  it("a P-256 chain verifies, with k_p256_ key ids", () => {
    const k = new P256Key();
    expect(k.id).toMatch(/^k_p256_[0-9a-f]{16}$/);
    expect(k.public.startsWith("ecdsa-p256:")).toBe(true);
    const b = new Builder({ key: k }).standard();
    const r = run(b);
    expect(r.valid(true), JSON.stringify(r.findings)).toBe(true);
    expect(r.summary["keys"]).toEqual([k.id]);
  });

  it("detects tampering and wrong keys", () => {
    const b = new Builder({ key: new P256Key() }).standard();
    const recs = b.copy();
    recs[2]!["args"]["amount"] = 999;
    expect(codes(run(b, recs))).toContain("bad_signature");
    expect(codes(verifyRecords(b.records, { expectKey: "k_p256_0000000000000000" }))).toContain("unexpected_key");
  });

  it("rotates between key types in both directions", () => {
    const b = new Builder();
    b.action(1);
    const p = new P256Key();
    b.rotate(p);
    b.action(2);
    const e = new Key();
    b.rotate(e);
    b.action(3);
    b.anchor(b.segment());
    const r = run(b);
    expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
    expect((r.summary["keys"] as string[]).length).toBe(3);
    // the rotated-out P-256 key may not sign later records
    const stale = b.copy();
    resign(stale, p, stale.length - 2);
    expect(codes(run(b, stale))).toContain("stale_key");
  });

  it("rejects signatures of the other type and malformed keys", () => {
    const k = new P256Key();
    const pub = decodePublicKey(k.public);
    const msg = recordMessage("sha256:" + "00".repeat(32));
    const sig = k.sign("sha256:" + "00".repeat(32));
    expect(verifySignature(pub, msg, sig)).toBe(true);
    expect(verifySignature(pub, msg, sig.replace("ecdsa-p256:", "ed25519:"))).toBe(false);
    expect(verifySignature(decodePublicKey(new Key().public), msg, sig)).toBe(false);
    expect(() => decodePublicKey("ecdsa-p256:")).toThrow();
    expect(() => decodePublicKey(new Key().public.replace("ed25519:", "ecdsa-p256:"))).toThrow();
    expect(() => decodePublicKey(42)).toThrow("public key must be a string");
    expect(keyId(pub)).toBe(k.id);
  });
});

describe("approvals bound to actions", () => {
  it("an approved action executed as approved is valid", () => {
    const b = new Builder();
    const id = b.approve({ order: "o1", amount: 1 });
    b.action(1, { approval: id });
    b.anchor(b.segment());
    expect(run(b).valid(), JSON.stringify(run(b).findings)).toBe(true);
  });

  it("executing something different from what was approved is caught", () => {
    const b = new Builder();
    const id = b.approve({ order: "o1", amount: 1 });
    b.action(1, { approval: id, args: { order: "o1", amount: 5000 } });
    expect(codes(run(b))).toEqual(new Set(["approval_mismatch"]));
  });

  it("an approval covers exactly one action", () => {
    const b = new Builder();
    const id = b.approve({ order: "o1", amount: 1 });
    const first = b.action(1, { approval: id, args: { order: "o1", amount: 1 } });
    b.action(1, { approval: id, args: { order: "o1", amount: 1 } });
    b.action(1, { approval: id, args: { order: "o1", amount: 1 } });
    const r = run(b);
    expect(r.errors.map((f) => [f.code, f.seq])).toEqual([
      ["approval_reused", 3],
      ["approval_reused", 4],
    ]);
    expect(r.errors[0]!.message).toBe(`approval already used by the action at seq ${first["seq"]}; an approval covers exactly one action`);
  });

  it("the approval must come first, decide 'approved', and exist", () => {
    let b = new Builder();
    b.action(1, { approval: "rev_later" });
    b.add({ kind: "review", id: "rev_later", review: { action_digest: actionDigest("refund", "pay", { order: "o1", amount: 1 }), decision: "approved" } });
    expect(codes(run(b))).toContain("approval_after_action");

    b = new Builder();
    const id = b.approve({ order: "o1", amount: 1 }, { decision: "rejected" });
    b.action(1, { approval: id });
    const r = run(b);
    expect(codes(r)).toEqual(new Set(["approval_not_approved"]));
    expect(r.errors[0]!.message).toBe("the referenced review decided 'rejected'");

    b = new Builder();
    b.action(1, { approval: "rev_nope" });
    expect(run(b).errors.find((f) => f.code === "approval_missing")!.message).toBe(
      "action names approval 'rev_nope', which is not in this bundle",
    );
  });

  it("a missing approval in a partial bundle is a warning", () => {
    const b = new Builder();
    const id = b.approve({ order: "o1", amount: 1 });
    const seg = b.segment();
    b.anchor(seg);
    b.action(1, { approval: id });
    b.anchor(b.segment());
    const partial = [b.records[0]!, ...b.records.slice(b.records.indexOf(seg) + 1)];
    const r = run(b, partial);
    expect(r.valid()).toBe(true);
    expect(r.warnings.map((f) => f.code)).toContain("approval_missing");
  });

  it("the digest covers tool, system and arguments (JCS)", () => {
    expect(actionDigest("refund", "pay", { b: 1, a: 2 })).toBe(actionDigest("refund", "pay", { a: 2, b: 1 }));
    expect(actionDigest("refund", "pay", { a: 1 })).not.toBe(actionDigest("refund", "other", { a: 1 }));
    expect(actionDigest("refund", "pay", { a: 1 })).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe("single-action proofs", () => {
  const build = (key: Key | P256Key = new Key()) => {
    const b = new Builder({ key });
    for (let i = 0; i < 7; i++) b.action(i);
    b.anchor(b.segment());
    return b;
  };

  it("verifies for every position in the segment, for both key types", () => {
    for (const key of [new Key(), new P256Key()]) {
      const b = build(key);
      for (const a of b.records.filter((r) => r["kind"] === "action")) {
        const { manifest, records } = proofFiles(b, a["id"]);
        const r = verifyBundle(proofZip(b, manifest, records), { expectKey: key.id });
        expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
        expect(r.summary).toMatchObject({ type: "proof", action: a["id"], action_seq: a["seq"], keys: [key.id], segments: 1 });
      }
    }
  });

  it("catches a tampered action, wrong positions and a wrong key", () => {
    const b = build();
    const a = b.records[4]!;
    const { manifest, records } = proofFiles(b, a["id"]);
    const t = structuredClone(records);
    t[1]!["args"]["order"] = "other";
    expect(codes(verifyBundle(proofZip(b, manifest, t)))).toEqual(new Set(["bad_signature", "proof_invalid"]));
    // an attacker holding the key re-signs: the Merkle proof still fails
    delete t[1]!["sig"];
    t[1]!["sig"] = b.key.sign(recordHash(t[1]!));
    expect(codes(verifyBundle(proofZip(b, manifest, t)))).toEqual(new Set(["proof_invalid"]));
    expect(codes(verifyBundle(proofZip(b, { ...manifest, leaf_index: 1 }, records)))).toContain("proof_position");
    expect(codes(verifyBundle(proofZip(b, { ...manifest, tree_size: 9 }, records)))).toContain("proof_position");
    expect(codes(verifyBundle(proofZip(b, manifest, records), { expectKey: "k_ed25519_0000000000000000" }))).toContain("unexpected_key");
    expect(codes(verifyBundle(proofZip(b, manifest, records), { requireAnchor: "rekor" }))).toContain("anchor_required");
    expect(codes(verifyBundle(proofZip(b, manifest, records.slice(0, 2))))).toEqual(new Set(["malformed"]));
  });

  it("reports a bad proof path or leaf index as a finding, not as malformed input", () => {
    const b = build();
    const { manifest, records } = proofFiles(b, b.records[2]!["id"]);
    const bad = (m: Rec) => new Set(verifyBundle(proofZip(b, { ...manifest, ...m }, records)).errors.map((f) => f.code));
    expect(bad({ proof: ["zz"] })).toEqual(new Set(["proof_invalid"]));
    expect(bad({ proof: [1, 2] })).toEqual(new Set(["proof_invalid"]));
    expect(bad({ leaf_index: "1" })).toEqual(new Set(["proof_position"]));
    expect(bad({ leaf_index: true })).toEqual(new Set(["proof_position"]));
    expect(bad({ tree_size: "7" })).toEqual(new Set(["proof_position"]));
  });

  it("warns when the segment has no verified anchor, and checks the manifest chain and key", () => {
    const b = new Builder();
    for (let i = 0; i < 3; i++) b.action(i);
    b.segment();
    const { manifest, records } = proofFiles(b, b.records[2]!["id"]);
    const r = verifyBundle(proofZip(b, manifest, records));
    expect(r.valid()).toBe(true);
    expect(r.valid(true)).toBe(false);
    expect(r.warnings.map((f) => f.code)).toEqual(["unanchored_segments"]);
    const a = build();
    const p = proofFiles(a, a.records[2]!["id"]);
    const codesOf = (m: Rec, recs = p.records) => verifyBundle(proofZip(a, m, recs)).findings.map((f) => `${f.level}:${f.code}`);
    expect(codesOf({ ...p.manifest, chain: "ch_other" })).toEqual(["error:manifest_chain"]);
    expect(codesOf({ ...p.manifest, key: "k_ed25519_0000000000000000" })).toEqual(["error:manifest_key"]);
    expect(codesOf({ ...p.manifest, key: null })).toEqual([]);
    const unknown = structuredClone(p.records);
    unknown[3]!["anchor"]["type"] = "carrier-pigeon";
    delete unknown[3]!["sig"];
    unknown[3]!["sig"] = a.key.sign(recordHash(unknown[3]!));
    expect(codesOf(p.manifest, unknown)).toEqual(["warn:anchor_type", "warn:unanchored_segments"]);
    // a local receipt with no log to check it against is "not checked"
    const files = { manifest: p.manifest, records: p.records };
    const noLog = verifyBundle(zipBundle({
      "manifest.json": JSON.stringify(files.manifest),
      "records.jsonl": files.records.map((x) => JSON.stringify(x)).join("\n"),
    }));
    expect(noLog.findings.map((f) => `${f.level}:${f.code}`)).toEqual(["info:anchor_unchecked", "warn:unanchored_segments"]);
  });
});

describe("reconcile", () => {
  const b = new Builder();
  ["R1", "R2", "R3"].forEach((rid, i) => b.action(i, { response: { status: "ok", body: { refund_id: rid, nested: { order_id: `O${i}` } } } }));
  b.anchor(b.segment());
  const bundle = writeBundle(b);

  it("external ids", () => {
    const body = { id: 5, refund_id: "R1", x: { customerId: "C9", flag: true }, items: [{ sku_id: "S" }] };
    expect(externalIds(body)).toEqual(new Set(["5", "R1", "C9", "S"]));
    expect(externalIds(body, "refund_id")).toEqual(new Set(["R1"]));
  });

  it("finds both kinds of difference", () => {
    const res = reconcile(bundle, "refund_id,amount\nR1,10\nR2,20\nR9,99\n", { column: "refund_id" });
    expect(res.matched).toEqual(new Set(["R1", "R2"]));
    expect(res.onlyInSystem).toEqual(new Set(["R9"]));
    expect(res.onlyInRecords).toEqual(new Set(["R3"]));
    expect(res.ok).toBe(false);
    expect(reconcile(bundle, "refund_id\nR1\nR2\nR3\n", { column: "refund_id" }).ok).toBe(true);
    expect(reconcile(bundle, "oid\nO0\nO1\nO2\n", { column: "oid", field: "order_id" }).ok).toBe(true);
  });

  it("does not reconcile a bundle that does not verify, and needs the column", () => {
    const bad = b.copy();
    bad[1]!["args"]["order"] = "x";
    let read = false;
    const res = reconcile(writeBundle(b, bad), () => ((read = true), "refund_id\nR1\n"), { column: "refund_id" });
    expect(res.report.valid()).toBe(false);
    expect(read).toBe(false);
    expect(() => reconcile(bundle, "x\n1\n", { column: "refund_id", csvName: "s.csv" })).toThrow("column 'refund_id' not found in s.csv");
    expect(csvColumn("﻿a,b\n x ,1\n\n,2\n", "a")).toEqual(new Set(["x"]));
  });

  it("skips short CSV rows and actions whose response is not an object", () => {
    expect(reconcile(bundle, "amount,refund_id\n10,R1\n5\n20,R2\n30,R3\n", { column: "refund_id" }).ok).toBe(true);
    const odd = new Builder();
    odd.action(1, { response: "ok" });
    odd.action(2, { response: { status: "ok", body: { refund_id: "R1" } } });
    odd.anchor(odd.segment());
    const res = reconcile(writeBundle(odd), "refund_id\nR1\n", { column: "refund_id" });
    expect(res.ok).toBe(true);
  });
});
