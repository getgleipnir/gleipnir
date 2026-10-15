/** The GitHub Action in action/: its bundled verifier is current, and it verifies, summarizes and fails as documented. */

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { pythonAvailable, REPO } from "./oracle.js";

const ACTION = fileURLToPath(new URL("../../../../action/", import.meta.url));
const FIXTURES = JSON.parse(readFileSync(join(ACTION, "test/fixtures/fixtures.json"), "utf8"));

// @ts-expect-error: plain .mjs action entry point
const action = await import("../../../../action/run.mjs");

function runAction(inputs: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "gleipnir-action-"));
  const summary = join(dir, "summary.md");
  const output = join(dir, "output.txt");
  writeFileSync(summary, "");
  writeFileSync(output, "");
  const env: Record<string, string> = { GITHUB_STEP_SUMMARY: summary, GITHUB_OUTPUT: output, GLEIPNIR_ACTION_CWD: REPO };
  for (const [k, v] of Object.entries(inputs)) env[`INPUT_${k.toUpperCase()}`] = v;
  let log = "";
  const code = action.main(env, (s: string) => (log += s));
  const outputs: Record<string, string> = {};
  const raw = readFileSync(output, "utf8");
  for (const m of raw.matchAll(/^([\w-]+)<<(\S+)\n([\s\S]*?)\n\2\n/gm)) outputs[m[1]!] = m[3]!;
  return { code, log, summary: readFileSync(summary, "utf8"), outputs };
}

const ALL_CHECKS = {
  "expect-key": FIXTURES.key,
  "require-anchor": "rekor, rfc3161",
  "require-full": "true",
  "max-anchor-delay": "3600",
  "known-head": FIXTURES.head,
  strict: "true",
};

describe("action/", () => {
  it("dist/gleipnir-verify.mjs is up to date with the verifier source (run `npm run build:action`)", async () => {
    // @ts-expect-error: plain .mjs build script
    const { buildAction } = await import("../../../scripts/build-action.mjs");
    const current = readFileSync(join(ACTION, "dist/gleipnir-verify.mjs"), "utf8");
    expect((await buildAction()) === current, "action/dist/gleipnir-verify.mjs is stale: run `npm run build:action`").toBe(true);
  });

  it("passes a valid, anchored bundle with every check on, and writes a VALID summary", () => {
    const r = runAction({ bundle: "action/test/fixtures/valid.zip", ...ALL_CHECKS });
    expect(r.code, r.log).toBe(0);
    expect(r.outputs["result"]).toBe("VALID");
    expect(r.outputs["head"]).toBe(FIXTURES.head);
    expect(r.summary).toMatch(/^## Gleipnir verify: VALID/);
    expect(r.summary).toContain("--require-anchor rekor --require-anchor rfc3161");
    expect(r.summary).toContain("No findings.");
    expect(JSON.parse(r.outputs["report"]!)[0].summary.segments_timestamped).toBe(FIXTURES.segments);
  });

  it("fails on a tampered bundle, with a findings table and error annotations", () => {
    const r = runAction({ bundle: "action/test/fixtures/tampered.zip", "expect-key": FIXTURES.key });
    expect(r.code).toBe(1);
    expect(r.outputs["result"]).toBe("INVALID");
    expect(r.outputs["invalid"]).toBe("action/test/fixtures/tampered.zip");
    expect(r.summary).toMatch(/^## Gleipnir verify: INVALID/);
    expect(r.summary).toMatch(/\| error \| <code>bad_signature<\/code> \| 2 \| signature does not match/);
    expect(r.log).toMatch(/::error title=Gleipnir bad_signature::action\/test\/fixtures\/tampered.zip: /);
  });

  it("expands globs (and ! excludes) and fails if any bundle is INVALID", () => {
    const both = runAction({ bundle: "action/test/fixtures/*.zip" });
    expect(both.code).toBe(1);
    expect(both.outputs["bundles"]).toBe("2");
    expect(both.outputs["invalid"]).toBe("action/test/fixtures/tampered.zip");
    expect(both.outputs["head"]).toBeUndefined();
    const one = runAction({ bundle: "action/**/*.zip\n!**/tampered.zip" });
    expect(one.code, one.log).toBe(0);
    expect(one.outputs["bundles"]).toBe("1");
  });

  it("fails when a check fails on a valid bundle (wrong key, unknown head, strict)", () => {
    expect(runAction({ bundle: "action/test/fixtures/valid.zip", "expect-key": "k_ed25519_0000000000000000" }).code).toBe(1);
    const head = runAction({ bundle: "action/test/fixtures/valid.zip", "known-head": "3:sha256:" + "00".repeat(32) });
    expect(head.code).toBe(1);
    expect(head.summary).toContain("known_head");
  });

  it("reports bad inputs and no matches as ERROR", () => {
    const cases: Array<Record<string, string>> = [
      { bundle: "" },
      { bundle: "nope/*.zip" },
      { bundle: "action/test/fixtures/valid.zip", "require-anchor": "local" },
      { bundle: "action/test/fixtures/valid.zip", "max-anchor-delay": "soon" },
      { bundle: "action/test/fixtures/valid.zip", verifier: "rust" },
      { bundle: "action/test/fixtures/valid.zip", "require-full": "yes please" },
    ];
    for (const inputs of cases) {
      const r = runAction(inputs);
      expect(r.code, JSON.stringify(inputs)).toBe(1);
      expect(r.outputs["result"]).toBe("ERROR");
      expect(r.summary).toMatch(/^## Gleipnir verify: ERROR/);
    }
  });

  it("escapes findings text in the summary table", () => {
    const md = action.summaryMarkdown(
      [{ bundle: "a|b.zip", valid: false, report: { summary: {}, findings: [{ level: "error", code: "x", message: "<img src=x> | y\nz" }] } }],
      { verifier: "typescript", flags: [] },
    );
    expect(md).toContain("&lt;img src=x&gt; &#124; y<br>z");
    expect(md).not.toContain("<img");
  });

  it("globToRegExp", () => {
    const re = (p: string) => action.globToRegExp(p) as RegExp;
    expect(re("out/*.zip").test("out/a.zip")).toBe(true);
    expect(re("out/*.zip").test("out/x/a.zip")).toBe(false);
    expect(re("out/**/*.zip").test("out/a.zip")).toBe(true);
    expect(re("out/**/*.zip").test("out/x/y/a.zip")).toBe(true);
    expect(re("**/{bundle,proof}.zip").test("a/proof.zip")).toBe(true);
    expect(re("b?.zip").test("b1.zip")).toBe(true);
    expect(re("a.zip").test("abzip")).toBe(false);
  });

  it.runIf(pythonAvailable)("runs the Python verifier when asked, with the same verdicts", () => {
    const py = { verifier: "python", "python-command": "uv run --quiet gleipnir-verify" };
    const ok = runAction({ bundle: "action/test/fixtures/valid.zip", ...ALL_CHECKS, ...py });
    expect(ok.code, ok.log).toBe(0);
    expect(ok.summary).toContain("python verifier");
    const bad = runAction({ bundle: "action/test/fixtures/tampered.zip", ...py });
    expect(bad.code).toBe(1);
    expect(bad.outputs["result"]).toBe("INVALID");
    const ts = runAction({ bundle: "action/test/fixtures/*.zip", ...ALL_CHECKS });
    const pyAll = runAction({ bundle: "action/test/fixtures/*.zip", ...ALL_CHECKS, ...py });
    expect(JSON.parse(pyAll.outputs["report"]!)).toEqual(JSON.parse(ts.outputs["report"]!));
  });
});
