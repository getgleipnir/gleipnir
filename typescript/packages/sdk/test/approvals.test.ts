/** SDK: signed approvals (approve({signature}), ApproverKey), checked by both verifiers. */

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyBundle, verifyRecords } from "@getgleipnir/verify";
import { ApproverKey, Recorder, approvalDigest, approvalMessage } from "@getgleipnir/sdk";
import { pythonAvailable, pythonCli } from "../../verify/test/oracle.js";

const tmp = () => mkdtempSync(join(tmpdir(), "gleipnir-sdk-a-"));
const recorder = () => new Recorder({ agentId: "a", agentVersion: "1", home: tmp(), background: false, quiet: true });

describe("signed approvals", () => {
  it("records a pre-made approver signature that both verifiers accept against the registry", async () => {
    const rec = recorder();
    const refund = rec.tool((order: string, amount: number, card: string) => (void card, { ok: true }), {
      system: "payments",
      name: "refund",
      params: ["order", "amount", "card"],
      redact: ["card"],
    });
    const anna = ApproverKey.generate("ops:anna", "ecdsa-p256");
    const args = { order: "A1", amount: 500, card: "4111" };
    const digest = rec.approvalDigest(refund, args);
    expect(digest).not.toBe(approvalDigest("refund", args, "payments")); // the card is hmac-redacted
    const approval = rec.approve(refund, args, { signature: JSON.stringify(anna.sign(digest)) });
    rec.context({ approval }, () => refund("A1", 500, "4111"));
    const recs = rec.chain.store.readAll();
    const review = recs.find((r) => r["id"] === approval)!;
    expect((review["review"] as Record<string, unknown>)["reviewer"]).toBe("ops:anna");
    const registry = [anna.registryEntry("Anna Berger", ["refunds"])];
    const r = verifyRecords(recs, { approvers: registry, requireSignedApprovals: true });
    expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
    expect(r.findings.map((f) => f.code)).toContain("approval_verified");
    if (pythonAvailable) {
      const out = await rec.export(join(rec.home, "bundle.zip"));
      const regPath = join(rec.home, "approvers.json");
      writeFileSync(regPath, JSON.stringify(registry));
      const py = JSON.parse(pythonCli([out, "--json", "--approvers", regPath, "--require-signed-approvals"]).out);
      const ts = verifyBundle(readFileSync(out), { approvers: registry, requireSignedApprovals: true }).toJSON();
      expect(py.result).toBe("VALID");
      expect(py.findings).toEqual(JSON.parse(JSON.stringify(ts.findings)));
    }
  });

  it("refuses signatures that do not cover the action, or name someone else", () => {
    const rec = recorder();
    const anna = ApproverKey.generate("ops:anna");
    const good = rec.approvalDigest("refund", { order: "A1" }, { system: "pay" });
    const other = rec.approvalDigest("refund", { order: "A2" }, { system: "pay" });
    expect(() => rec.approve("refund", { order: "A1" }, { system: "pay", signature: anna.sign(other) })).toThrow("approval_bad_signature");
    expect(() => rec.approve("refund", { order: "A1" }, { system: "pay", approver: "ops:boss", signature: anna.sign(good) })).toThrow("differs");
    expect(() => rec.approve("refund", { order: "A1" }, { system: "pay", signature: "nope" })).toThrow("not valid JSON");
    expect(() => rec.approve("refund", { order: "A1" }, { system: "pay" })).toThrow("pass approver");
    expect(() => anna.sign("sha256:00")).toThrow();
    expect(new TextDecoder().decode(approvalMessage("refund", { order: "A1" }, "pay"))).toBe("gleipnir/approval/v1\n" + good);
  });

  it("loads approver keys written by the Python CLI and vice versa (PKCS#8 PEM)", () => {
    for (const kind of ["ed25519", "ecdsa-p256"] as const) {
      const k = ApproverKey.generate("ops:x", kind);
      expect(ApproverKey.fromPem(k.privatePem(), "ops:x").publicKey).toBe(k.publicKey);
    }
  });
});
