import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../src/cli.js";
import { Builder, writeBundle } from "./chainbuilder.js";

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
});
