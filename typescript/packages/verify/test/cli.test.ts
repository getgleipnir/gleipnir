import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../src/cli.js";
import { Builder, P256Key, proofFiles, proofZip, writeBundle } from "./chainbuilder.js";
import { pythonAvailable, pythonCli } from "./oracle.js";

function cli(args: string[]) {
  let out = "";
  let err = "";
  const code = main(args, { out: (s) => (out += s), err: (s) => (err += s) });
  return { code, out, err };
}

describe("gleipnir-verify CLI", () => {
  const dir = mkdtempSync(join(tmpdir(), "gleipnir-cli-"));
  const b = new Builder().standard();
  const p = join(dir, "bundle.zip");
  writeFileSync(p, writeBundle(b));

  it("verifies a bundle and prints a summary", () => {
    const r = cli([p]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("result: VALID");
    expect(r.out).toContain(`signing keys: ${b.key.id}`);
    expect(r.out).toContain("segments:     3, anchored 3 (independent anchors: 0)");
    expect(r.out).toMatch(/head: {9}18:sha256:[0-9a-f]{64}/);
  });

  it("prints JSON with --json", () => {
    const r = cli([p, "--json", "--expect-key", b.key.id]);
    expect(r.code).toBe(0);
    const j = JSON.parse(r.out);
    expect(j.result).toBe("VALID");
    expect(j.summary.chain).toBe("ch_test");
  });

  it("fails on the wrong key, late expect-until, required anchors and strict warnings", () => {
    expect(cli([p, "--expect-key", "k_ed25519_0000000000000000"]).code).toBe(1);
    expect(cli([p, "--expect-until", "2030-01-01T00:00:00Z"]).code).toBe(1);
    const r = cli([p, "--require-anchor", "rekor", "--require-anchor", "rfc3161"]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("[FAIL] seq 5 anchor_required: segment has no verified rekor anchor");
    expect(cli([p, "--strict"]).code).toBe(0);
    expect(cli([p, "--known-head", "1:sha256:" + "0".repeat(64)]).code).toBe(1);
  });

  it("rejects bad arguments like argparse (exit 2)", () => {
    expect(cli([]).code).toBe(2);
    expect(cli([p, "--require-anchor", "local"]).code).toBe(2);
    expect(cli([p, "--expect-until", "yesterday"]).code).toBe(2);
    expect(cli([p, "--known-head", "x"]).code).toBe(2);
    expect(cli([p, "--max-anchor-delay", "soon"]).code).toBe(2);
    expect(cli([p, "--bogus"]).code).toBe(2);
    expect(cli(["--help"]).code).toBe(0);
    expect(cli(["--version"]).out).toMatch(/^gleipnir-verify /);
  });

  it("reports unreadable bundles as INVALID without crashing", () => {
    const r = cli([join(dir, "missing.zip")]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("[FAIL] bad_bundle: cannot read bundle: FileNotFoundError");
    const bad = join(dir, "bad.zip");
    writeFileSync(bad, "nope");
    expect(cli([bad, "--json"]).code).toBe(1);
  });

  it("uses --local-anchor-log", () => {
    const log = join(dir, "log.jsonl");
    writeFileSync(log, b.anchorLog.map((e) => JSON.stringify(e)).join("\n") + "\n");
    expect(cli([p, "--local-anchor-log", log]).code).toBe(0);
    expect(cli([p, "--local-anchor-log", join(dir, "nope.jsonl")]).code).toBe(1);
  });

  it("verifies a single-action proof and prints the same text as the Python CLI", () => {
    const pb = new Builder({ key: new P256Key() });
    for (let i = 0; i < 5; i++) pb.action(i);
    pb.anchor(pb.segment());
    const { manifest, records } = proofFiles(pb, pb.records[3]!["id"]);
    const proof = join(dir, "proof.zip");
    writeFileSync(proof, proofZip(pb, manifest, records));
    const r = cli([proof, "--expect-key", pb.key.id]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("result: VALID");
    if (pythonAvailable) {
      for (const flags of [[], ["--json"], ["--expect-key", "k_p256_0000000000000000"], ["--json", "--require-anchor", "rekor"]]) {
        const py = pythonCli([proof, ...flags]);
        const ts = cli([proof, ...flags]);
        expect([ts.code, ts.out], flags.join(" ")).toEqual([py.code, py.out]);
      }
    }
  });
});

describe("gleipnir-verify reconcile", () => {
  const dir = mkdtempSync(join(tmpdir(), "gleipnir-reconcile-"));
  const b = new Builder();
  ["R1", "R2", "R3"].forEach((rid, i) => b.action(i, { response: { status: "ok", body: { refund_id: rid, nested: { order_id: `O${i}` } } } }));
  b.anchor(b.segment());
  const p = join(dir, "b.zip");
  writeFileSync(p, writeBundle(b));
  const csv = join(dir, "system.csv");
  const same = join(dir, "same.csv");
  writeFileSync(csv, "refund_id,amount\nR1,10\nR2,20\nR9,99\n");
  writeFileSync(same, "refund_id\nR1\nR2\nR3\n");
  const tampered = join(dir, "t.zip");
  const recs = structuredClone(b.records);
  recs[1]!["args"]["order"] = "changed";
  writeFileSync(tampered, writeBundle(b, recs));

  it("finds both kinds of difference, and reconciles a matching export", () => {
    const r = cli(["reconcile", p, csv, "--column", "refund_id"]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("in your system only:      1  (agent may have acted without a record)\n  R9\n");
    expect(r.out).toContain("in the records only:      1  (claimed, but not in your system)\n  R3\n");
    expect(r.out).toContain("DIFFERENCES FOUND");
    const ok = cli(["reconcile", p, same, "--column", "refund_id", "--expect-key", b.key.id]);
    expect(ok.code).toBe(0);
    expect(ok.out).toContain("result: RECONCILED");
  });

  it("refuses bundles that do not verify, and bad arguments", () => {
    expect(cli(["reconcile", tampered, same, "--column", "refund_id"]).out).toBe("bundle does not verify; run gleipnir-verify on it first\n");
    expect(cli(["reconcile", p, same, "--column", "refund_id", "--expect-key", "k_ed25519_0000000000000000"]).code).toBe(1);
    expect(cli(["reconcile", p, same]).code).toBe(2);
    expect(cli(["reconcile", p, same, "--column", "nope"]).err).toContain("error: column 'nope' not found in");
    expect(cli(["reconcile", p, join(dir, "missing.csv"), "--column", "x"]).err).toContain("No such file or directory");
    expect(cli(["reconcile", "--help"]).out).toContain("usage: gleipnir-verify reconcile");
  });

  it.runIf(pythonAvailable)("prints exactly what the Python CLI prints", () => {
    const argvs = [
      ["reconcile", p, csv, "--column", "refund_id"],
      ["reconcile", p, same, "--column", "refund_id"],
      ["reconcile", p, csv, "--column", "order_id"],
      ["reconcile", p, csv, "--column", "refund_id", "--field", "order_id"],
      ["reconcile", tampered, same, "--column", "refund_id"],
      ["reconcile", join(dir, "missing.zip"), same, "--column", "refund_id"],
      ["reconcile", p, same, "--column", "nope"],
      ["reconcile", p, same],
      ["reconcile", p, join(dir, "missing.csv"), "--column", "x"],
    ];
    for (const argv of argvs) {
      const py = pythonCli(argv);
      const ts = cli(argv);
      expect([ts.code, ts.out, ts.err], argv.slice(1).join(" ")).toEqual([py.code, py.out, py.err]);
    }
  });
});
