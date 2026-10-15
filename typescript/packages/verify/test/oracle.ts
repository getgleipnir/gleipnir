/** The Python reference as a test oracle (scripts/py_oracle.py, run with `uv`). */

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { pyDumps, type VerifyOptions } from "@getgleipnir/verify";

export const REPO = fileURLToPath(new URL("../../../../", import.meta.url));
const ORACLE = join(REPO, "typescript/scripts/py_oracle.py");

export const pythonAvailable = (() => {
  if (!existsSync(join(REPO, "pyproject.toml"))) return false;
  const r = spawnSync("uv", ["--version"], { encoding: "utf8" });
  return r.status === 0;
})();
if (!pythonAvailable && process.env["GLEIPNIR_REQUIRE_PYTHON"]) throw new Error("uv / Python workspace not available");

export function oracle(cases: unknown[]): any[] {
  const out = execFileSync("uv", ["run", "--quiet", "python", "-I", ORACLE], {
    cwd: REPO,
    input: JSON.stringify(cases),
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"],
  });
  return JSON.parse(out);
}

/** Run the Python CLI (`uv run gleipnir-verify ...`). */
export function pythonCli(args: string[]): { code: number; out: string; err: string } {
  const r = spawnSync("uv", ["run", "--quiet", "gleipnir-verify", ...args], { cwd: REPO, encoding: "utf8" });
  return { code: r.status ?? -1, out: r.stdout, err: r.stderr };
}

/** JSON as the Python side would produce it from the report (sorted keys). */
export function normalizeReport(r: unknown): unknown {
  return JSON.parse(pyDumps(r));
}

/**
 * Findings whose message embeds a host-language exception text are compared up to the
 * exception type; everything else is compared exactly.
 */
const EXCEPTION_TEXT_CODES = new Set(["malformed", "bad_bundle", "unencodable", "bad_genesis_key", "bad_rotation", "bad_segment"]);
export function stripExceptionText(report: any): any {
  if (!report || !Array.isArray(report.findings)) return report;
  return {
    ...report,
    findings: report.findings.map((f: any) =>
      EXCEPTION_TEXT_CODES.has(f.code) ? { ...f, message: String(f.message).split(":").slice(0, f.code === "malformed" ? 2 : 1).join(":") } : f,
    ),
  };
}

export function toTsOptions(o: Record<string, any> = {}): VerifyOptions {
  const out: VerifyOptions = {};
  if (o["expect_key"] != null) out.expectKey = o["expect_key"];
  if (o["expect_until"] != null) out.expectUntil = o["expect_until"];
  if (o["known_head"] != null) out.knownHead = { seq: o["known_head"][0], hash: o["known_head"][1] };
  if (o["require_anchor"] != null) out.requireAnchor = o["require_anchor"];
  if (o["max_anchor_delay"] != null) out.maxAnchorDelay = o["max_anchor_delay"];
  if (o["require_full"]) out.requireFull = true;
  if (o["manifest"] != null) out.manifest = o["manifest"];
  if (o["local_anchor_entries"] != null) out.anchorOptions = { localAnchorEntries: o["local_anchor_entries"] };
  if (o["approvers"] != null) out.approvers = o["approvers"];
  if (o["webauthn_origins"] != null) out.webauthnOrigins = o["webauthn_origins"];
  if (o["require_signed_approvals"]) out.requireSignedApprovals = true;
  return out;
}
