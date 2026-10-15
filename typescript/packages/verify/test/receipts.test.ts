import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  b64decodeStrict,
  b64encode,
  embeddedTrustedRoot,
  parseCheckpoint,
  verifyRekorReceipt,
  verifyTimestampReceipt,
} from "@getgleipnir/verify";

const FIX = fileURLToPath(new URL("./fixtures/", import.meta.url));
const REKOR = JSON.parse(readFileSync(FIX + "rekor_v2_receipt.json", "utf8"));
const RFC3161 = JSON.parse(readFileSync(FIX + "rfc3161_receipt.json", "utf8"));
const SEG = REKOR.segment_hash as string;
const TSEG = RFC3161.segment_hash as string;

const clone = <T>(x: T): T => structuredClone(x);
function flip(b64: string, at = -1): string {
  const raw = b64decodeStrict(b64);
  const i = at < 0 ? raw.length + at : at;
  raw[i]! ^= 1;
  return b64encode(raw);
}

describe("Rekor v2 receipt (real fixture from log2025-1.rekor.sigstore.dev)", () => {
  it("verifies offline against the embedded Sigstore trusted root", () => {
    const res = verifyRekorReceipt(clone(REKOR.anchor), SEG, {});
    expect(res.detail).toMatch(/^included in log2025-1\.rekor\.sigstore\.dev at index \d+$/);
    expect(res.ok).toBe(true);
    expect(res.independent).toBe(true);
  });

  it("rejects another segment", () => {
    expect(verifyRekorReceipt(clone(REKOR.anchor), "sha256:" + "00".repeat(32), {}).ok).toBe(false);
  });

  type Anchor = typeof REKOR.anchor;
  const mutations: Array<[string, (a: Anchor) => void]> = [
    ["proof hash", (a) => (a.receipt.entry.inclusionProof.hashes[0] = flip(a.receipt.entry.inclusionProof.hashes[0]))],
    ["proof root", (a) => (a.receipt.entry.inclusionProof.rootHash = flip(a.receipt.entry.inclusionProof.rootHash))],
    ["log index", (a) => (a.receipt.entry.inclusionProof.logIndex = String(BigInt(a.receipt.entry.inclusionProof.logIndex) + 1n))],
    ["body", (a) => (a.receipt.entry.canonicalizedBody = flip(a.receipt.entry.canonicalizedBody))],
    ["anchor key", (a) => (a.receipt.anchor_key.public = flip(a.receipt.anchor_key.public))],
    ["log id", (a) => (a.receipt.entry.logId.keyId = b64encode(new Uint8Array(32)))],
  ];
  for (const [name, mutate] of mutations) {
    it(`rejects a tampered ${name}`, () => {
      const a = clone(REKOR.anchor);
      mutate(a);
      expect(verifyRekorReceipt(a, SEG, {}).ok).toBe(false);
    });
  }

  it("rejects a forged checkpoint signature", () => {
    const a = clone(REKOR.anchor);
    const cp = a.receipt.entry.inclusionProof.checkpoint;
    cp.envelope = (cp.envelope as string)
      .split("\n")
      .map((line) => {
        if (!line.startsWith("— log2025-1")) return line;
        const i = line.lastIndexOf(" ");
        return line.slice(0, i) + " " + flip(line.slice(i + 1));
      })
      .join("\n");
    const res = verifyRekorReceipt(a, SEG, {});
    expect(res.ok).toBe(false);
    expect(res.detail).toBe("checkpoint is not signed by the log key");
  });

  it("requires the checkpoint origin to match the log", () => {
    const a = clone(REKOR.anchor);
    const cp = a.receipt.entry.inclusionProof.checkpoint;
    cp.envelope = (cp.envelope as string).replace("log2025-1.rekor.sigstore.dev\n", "evil.example\n");
    expect(verifyRekorReceipt(a, SEG, {}).ok).toBe(false);
  });

  it("fails against a trusted root without the log", () => {
    const res = verifyRekorReceipt(clone(REKOR.anchor), SEG, { trustedRoot: { tlogs: [] } });
    expect(res.ok).toBe(false);
    expect(res.detail).toContain("trusted root");
  });

  it("reports malformed receipts without throwing", () => {
    for (const bad of [{ receipt: {} }, {}, { receipt: null }, { receipt: { entry: "x" } }, { receipt: [] }]) {
      expect(verifyRekorReceipt(bad, SEG, {}).ok).toBe(false);
    }
  });

  it("embeds exactly the Python verifier's pinned Sigstore trusted root", () => {
    const py = JSON.parse(
      readFileSync(fileURLToPath(new URL("../../../../python/gleipnir-verify/src/gleipnir_verify/data/sigstore_trusted_root.json", import.meta.url)), "utf8"),
    );
    expect(embeddedTrustedRoot()).toEqual(py);
  });

  it("parseCheckpoint rejects malformed notes", () => {
    expect(() => parseCheckpoint("no blank line")).toThrow();
    expect(() => parseCheckpoint("a\n\n— x AAAA\n")).toThrow();
  });
});

describe("RFC 3161 receipt (real fixture from timestamp.sigstore.dev)", () => {
  it("verifies offline against the embedded Sigstore TSA chain", () => {
    const res = verifyTimestampReceipt(clone(RFC3161.anchor), TSEG, {});
    expect(res.detail).toMatch(/^timestamped by https:\/\/timestamp\.sigstore\.dev\/api\/v1\/timestamp at 2026-10-14T/);
    expect(res.ok).toBe(true);
    expect(res.independent).toBe(true);
    expect(res.time).toBe("2026-10-14T21:38:16Z");
  });

  it("rejects another segment", () => {
    const res = verifyTimestampReceipt(clone(RFC3161.anchor), "sha256:" + "00".repeat(32), {});
    expect(res.ok).toBe(false);
  });

  it("rejects a corrupted token at every byte of the signature region and elsewhere", () => {
    const raw = b64decodeStrict(RFC3161.anchor.receipt.response);
    for (const at of [-10, -1, -40, 100, 200, 400, 700, 900, 1000, 1100]) {
      const a = clone(RFC3161.anchor);
      a.receipt.response = flip(a.receipt.response, at < 0 ? raw.length + at : at);
      expect(verifyTimestampReceipt(a, TSEG, {}).ok, `byte ${at}`).toBe(false);
    }
  });

  it("rejects garbage and an empty trusted root", () => {
    const a = clone(RFC3161.anchor);
    a.receipt.response = "not base64!!";
    expect(verifyTimestampReceipt(a, TSEG, {}).ok).toBe(false);
    const res = verifyTimestampReceipt(clone(RFC3161.anchor), TSEG, {
      trustedRoot: { tlogs: [], timestampAuthorities: [] },
    });
    expect(res.ok).toBe(false);
  });
});
