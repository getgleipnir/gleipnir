/** SDK: injected signers of either key type, approve() and prove(); checked by both verifiers. */

import { createSign, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { unzipSync, strFromU8 } from "fflate";
import { describe, expect, it } from "vitest";
import { parseJsonl, verifyBundle, verifyRecords } from "@getgleipnir/verify";
import {
  ChainWriter,
  EcdsaP256Signer,
  Ed25519Signer,
  MemoryStore,
  Recorder,
  SpkiSigner,
  checkSigner,
  type Rec,
  type Signer,
} from "@getgleipnir/sdk";
import { pythonAvailable, pythonCli } from "../../verify/test/oracle.js";

const tmp = () => mkdtempSync(join(tmpdir(), "gleipnir-sdk-f-"));

function recorder(extra: Partial<ConstructorParameters<typeof Recorder>[0]> = {}) {
  return new Recorder({ agentId: "a", agentVersion: "1", home: tmp(), background: false, quiet: true, ...extra });
}

/** An Ed25519 or P-256 key held "elsewhere" (node:crypto KeyObject stands in for a KMS). */
function kmsSigner(type: "ed25519" | "p256", format: "der" | "raw" = "der"): SpkiSigner {
  const { privateKey, publicKey } =
    type === "ed25519" ? generateKeyPairSync("ed25519") : generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = new Uint8Array(publicKey.export({ format: "der", type: "spki" }));
  return new SpkiSigner({
    spki,
    signatureFormat: format,
    signMessage: (m) =>
      type === "ed25519"
        ? new Uint8Array(nodeSign(null, m, privateKey))
        : new Uint8Array(createSign("sha256").update(m).sign({ key: privateKey, dsaEncoding: format === "raw" ? "ieee-p1363" : "der" })),
  });
}

describe("signers", () => {
  it("EcdsaP256Signer: k_p256_ key id, deterministic signatures, PEM round trip", () => {
    const s = EcdsaP256Signer.generate();
    expect(s.keyId).toMatch(/^k_p256_[0-9a-f]{16}$/);
    checkSigner(s);
    const msg = new TextEncoder().encode("x");
    expect(s.sign(msg)).toBe(s.sign(msg));
    const again = EcdsaP256Signer.fromPem(s.privatePem());
    expect(again.keyId).toBe(s.keyId);
    expect(again.sign(msg)).toBe(s.sign(msg));
    expect(() => EcdsaP256Signer.fromPem(Ed25519Signer.generate().privatePem())).toThrow();
  });

  it("SpkiSigner wraps external Ed25519 and P-256 keys (DER and raw r||s signatures)", () => {
    for (const s of [kmsSigner("ed25519"), kmsSigner("p256"), kmsSigner("p256", "raw")]) checkSigner(s);
    expect(kmsSigner("ed25519").keyId).toMatch(/^k_ed25519_/);
    expect(kmsSigner("p256").keyId).toMatch(/^k_p256_/);
    const rsa = generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey.export({ format: "der", type: "spki" });
    expect(() => new SpkiSigner({ spki: new Uint8Array(rsa), signMessage: () => new Uint8Array() })).toThrow("Ed25519 or ECDSA P-256");
    const p256Spki = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "der", type: "spki" });
    const broken = new SpkiSigner({ spki: new Uint8Array(p256Spki), signMessage: () => new Uint8Array(70) });
    expect(() => broken.sign(new Uint8Array(1))).toThrow("does not verify");
  });

  it("records with an injected P-256 signer, and rotates between key types", async () => {
    const store = new MemoryStore();
    const p = kmsSigner("p256");
    const w = new ChainWriter(store, p, { background: false });
    w.append("note", { note: { text: "a" } });
    const e: Signer = Ed25519Signer.generate();
    w.rotateKey(e);
    w.append("note", { note: { text: "b" } });
    w.rotateKey(EcdsaP256Signer.generate());
    w.append("note", { note: { text: "c" } });
    await w.close();
    const recs = store.readAll();
    expect((recs[0]!["public_key"] as Rec)["public"]).toMatch(/^ecdsa-p256:/);
    const r = verifyRecords(recs, { expectKey: p.keyId });
    expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
    expect(r.summary["keys"]).toHaveLength(3);
  });

  it("a Recorder with a P-256 signer exports a bundle both verifiers accept", async () => {
    const signer = EcdsaP256Signer.generate();
    const rec = recorder({ signer });
    const refund = rec.tool((order: string) => ({ refund_id: `R-${order}` }), { system: "payments", name: "refund", params: ["order"] });
    refund("A1");
    refund("A2");
    const out = await rec.export(join(rec.home, "bundle.zip"));
    const r = verifyBundle(readFileSync(out), { expectKey: signer.keyId, requireFull: true });
    expect(r.valid(true), JSON.stringify(r.findings)).toBe(true);
    if (pythonAvailable) {
      const py = pythonCli([out, "--expect-key", signer.keyId, "--require-full", "--strict"]);
      expect(py.code, py.out).toBe(0);
    }
  });
});

describe("approve()", () => {
  it("binds an approval to the exact action (Recorder.approve, as in Python)", async () => {
    const rec = recorder();
    const refund = rec.tool((order: string, amount: number, card: string) => (void card, { ok: true }), {
      system: "payments",
      name: "refund",
      params: ["order", "amount", "card"],
      redact: ["card"],
    });
    const approval = rec.approve(refund, { order: "A1", amount: 500, card: "4111" }, { approver: "ops:anna", rule: "amount>100" });
    rec.context({ approval }, () => refund("A1", 500, "4111"));
    let recs = rec.chain.store.readAll();
    const review = recs.find((r) => r["id"] === approval)!;
    expect(review["kind"]).toBe("review");
    expect(review["review"]).toMatchObject({ tool: "refund", system: "payments", reviewer: "ops:anna", decision: "approved", before_execution: true, rule: "amount>100" });
    const action = recs.find((r) => r["kind"] === "action")!;
    expect(action["approval"]).toBe(approval);
    expect(verifyRecords(recs).valid(), JSON.stringify(verifyRecords(recs).findings)).toBe(true);
    // executing something different from what was approved is caught
    rec.context({ approval }, () => refund("A1", 5000, "4111"));
    recs = rec.chain.store.readAll();
    // ... and so is a second use of the same approval
    expect(new Set(verifyRecords(recs).errors.map((f) => f.code))).toEqual(new Set(["approval_mismatch", "approval_reused"]));
    if (pythonAvailable) {
      const out = await rec.export(join(rec.home, "bundle.zip"));
      const py = JSON.parse(pythonCli([out, "--json"]).out);
      const ts = verifyBundle(readFileSync(out)).toJSON();
      expect(py.findings.map((f: any) => f.code)).toEqual(ts.findings.map((f) => f.code));
      expect(py.findings.map((f: any) => f.code)).toContain("approval_mismatch");
    }
  });

  it("works with a tool name and system, and needs both", () => {
    const rec = recorder();
    const id = rec.approve("delete_user", { user: "u1" }, { approver: "x", system: "crm", reason: "GDPR request" });
    rec.context({ approval: id }, () => rec.recordAction({ tool: "delete_user", system: "crm", args: { user: "u1" } }));
    expect(verifyRecords(rec.chain.store.readAll()).valid()).toBe(true);
    expect(() => rec.approve("refund", {}, { approver: "x" })).toThrow("tool name together with system");
    expect(() => rec.context({ approval: id, bogus: 1 } as never, () => 0)).toThrow("unknown context keys");
  });
});

describe("prove()", () => {
  it("writes a single-action proof both verifiers accept, and tampering is caught", async () => {
    for (const signer of [Ed25519Signer.generate(), EcdsaP256Signer.generate()]) {
      const rec = recorder({ signer, segmentMaxRecords: 3 });
      const refund = rec.tool((order: string) => ({ refund_id: "R-" + order }), { system: "payments", name: "refund", params: ["order"] });
      for (let i = 0; i < 7; i++) refund(`o${i}`);
      const actions = rec.chain.store.readAll().filter((r) => r["kind"] === "action");
      const target = actions[3]!["id"] as string;
      const path = await rec.prove(target, join(rec.home, "proof.zip"));
      const zip = readFileSync(path);
      const r = verifyBundle(zip, { expectKey: rec.keyId });
      expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
      expect(r.summary["action"]).toBe(target);
      const files = unzipSync(zip);
      const manifest = JSON.parse(strFromU8(files["manifest.json"]!));
      expect(manifest).toMatchObject({ format: 1, type: "proof", action: target, key: rec.keyId });
      expect(parseJsonl(strFromU8(files["records.jsonl"]!)).map((x: any) => x.kind)).toEqual(["genesis", "action", "segment", "anchor"]);
      // tamper with the action inside the proof
      const lines = strFromU8(files["records.jsonl"]!).split("\n");
      const a = JSON.parse(lines[1]!);
      a.args.order = "other";
      lines[1] = JSON.stringify(a);
      const bad = join(rec.home, "bad.zip");
      const { zipSync, strToU8 } = await import("fflate");
      writeFileSync(bad, zipSync({ ...files, "records.jsonl": strToU8(lines.join("\n")) }));
      const codes = new Set(verifyBundle(readFileSync(bad)).errors.map((f) => f.code));
      expect(codes).toEqual(new Set(["bad_signature", "proof_invalid"]));
      if (pythonAvailable) {
        for (const [p, flags] of [[path, ["--expect-key", rec.keyId]], [bad, []]] as const) {
          const py = pythonCli([p, "--json", ...flags]);
          const ts = verifyBundle(readFileSync(p), { expectKey: (flags[1] as string) ?? null }).toJSON();
          expect(JSON.parse(py.out)).toEqual(JSON.parse(JSON.stringify(ts)));
        }
      }
    }
  });

  it("refuses unknown actions and chains with rotations", async () => {
    const rec = recorder();
    rec.recordAction({ tool: "t", system: "s", args: {} });
    await expect(rec.prove("act_nope", join(rec.home, "p.zip"))).rejects.toThrow("no record with id");
    rec.chain.rotateKey(Ed25519Signer.generate());
    const id = rec.chain.store.readAll().find((r) => r["kind"] === "action")!["id"] as string;
    await expect(rec.prove(id, join(rec.home, "p.zip"))).rejects.toThrow("key rotations");
  });
});
