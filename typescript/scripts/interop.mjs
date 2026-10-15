#!/usr/bin/env node
/**
 * Cross-language interop check (run from the repo with `npm run interop` in typescript/).
 *
 * 1. Python SDK -> TypeScript verifier: runs examples/refund-agent/agent.py with `uv run`, then
 *    verifies its bundle.zip with the TypeScript CLI (--expect-key, --require-full). Also checks
 *    that a tampered copy (examples/refund-agent/tamper.py) is INVALID in TypeScript.
 * 2. TypeScript SDK -> Python verifier: records the same refund flow with @getgleipnir/sdk, exports
 *    a bundle, and verifies it with `uv run gleipnir-verify` (--expect-key, --require-full).
 * 3. Both verifiers must print the same --json report for both bundles (exported_at aside,
 *    reports are compared exactly).
 *
 * Requires `npm run build` first, and `uv` with the Python workspace synced.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const TS = join(HERE, "..");
const REPO = join(TS, "..");
const WORK = join(TS, ".interop");
const TS_CLI = join(TS, "packages/verify/dist/cli.js");

let failures = 0;
const ok = (cond, what) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${what}`);
  if (!cond) failures++;
};

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  if (r.error) throw r.error;
  return r;
}

function tsVerify(bundle, flags = []) {
  return sh(process.execPath, [TS_CLI, bundle, ...flags]);
}

function pyVerify(bundle, flags = []) {
  return sh("uv", ["run", "--quiet", "gleipnir-verify", bundle, ...flags], { cwd: REPO });
}

rmSync(WORK, { recursive: true, force: true });
mkdirSync(WORK, { recursive: true });

// ---- 1. Python SDK -> TypeScript verifier ---------------------------------------------------
console.log("== Python SDK bundle (examples/refund-agent/agent.py) -> TypeScript verifier");
const example = join(REPO, "examples/refund-agent");
const agent = sh("uv", ["run", "--quiet", "python", "agent.py"], { cwd: example });
ok(agent.status === 0, "python agent.py ran");
if (agent.status !== 0) process.stderr.write(agent.stderr);
const pyKey = /signing key: (k_ed25519_[0-9a-f]{16})/.exec(agent.stdout)?.[1];
ok(Boolean(pyKey), `python signing key ${pyKey}`);
const pyBundle = join(WORK, "python-bundle.zip");
cpSync(join(example, "bundle.zip"), pyBundle);

let r = tsVerify(pyBundle, ["--expect-key", pyKey, "--require-full"]);
process.stdout.write(r.stdout.replace(/^/gm, "    "));
ok(r.status === 0 && r.stdout.includes("result: VALID"), "TypeScript verifier: Python bundle is VALID");

const tampered = join(WORK, "python-tampered.zip");
const t = sh("uv", ["run", "--quiet", "python", "tamper.py", pyBundle, tampered], { cwd: example });
ok(t.status === 0, "python tamper.py ran");
r = tsVerify(tampered);
ok(r.status === 1 && /bad_signature/.test(r.stdout), "TypeScript verifier: tampered Python bundle is INVALID (bad_signature)");

// ---- 2. TypeScript SDK -> Python verifier ---------------------------------------------------
console.log("\n== TypeScript SDK bundle -> Python verifier (uv run gleipnir-verify)");
const gen = sh(process.execPath, [join(HERE, "ts-refund-agent.mjs"), WORK]);
ok(gen.status === 0, "TypeScript refund agent ran");
if (gen.status !== 0) process.stderr.write(gen.stderr);
const tsKey = /signing key: (k_ed25519_[0-9a-f]{16})/.exec(gen.stdout)?.[1];
const tsBundle = join(WORK, "ts-bundle.zip");
r = pyVerify(tsBundle, ["--expect-key", tsKey, "--require-full"]);
process.stdout.write(r.stdout.replace(/^/gm, "    "));
ok(r.status === 0 && r.stdout.includes("result: VALID"), "Python verifier: TypeScript bundle is VALID");
r = pyVerify(join(WORK, "ts-tampered.zip"));
ok(r.status === 1 && /bad_signature/.test(r.stdout), "Python verifier: tampered TypeScript bundle is INVALID (bad_signature)");

// ---- 3. identical JSON reports ----------------------------------------------------------------
console.log("\n== Both verifiers produce the same --json report");
for (const [name, bundle, key] of [
  ["python bundle", pyBundle, pyKey],
  ["typescript bundle", tsBundle, tsKey],
  ["tampered python bundle", tampered, pyKey],
  ["tampered typescript bundle", join(WORK, "ts-tampered.zip"), tsKey],
]) {
  const flags = ["--json", "--expect-key", key, "--require-full"];
  const a = JSON.parse(tsVerify(bundle, flags).stdout);
  const b = JSON.parse(pyVerify(bundle, flags).stdout);
  const same = JSON.stringify(a) === JSON.stringify(b);
  ok(same, `${name}: reports identical`);
  if (!same) {
    console.log("  ts:", JSON.stringify(a));
    console.log("  py:", JSON.stringify(b));
  }
}

// ---- 4. the TS bundle's records are byte-identical to how Python would write them -----------
console.log("\n== records.jsonl canonical lines match Python's json.dumps(sort_keys=True)");
const check = sh(
  "uv",
  [
    "run", "--quiet", "python", "-I", "-c",
    [
      "import json, sys, zipfile",
      "z = zipfile.ZipFile(sys.argv[1])",
      "raw = z.read('records.jsonl').decode()",
      "lines = [l for l in raw.split('\\n') if l]",
      "redo = [json.dumps(json.loads(l), sort_keys=True, separators=(',', ':')) for l in lines]",
      "m = z.read('manifest.json').decode()",
      "print('records', lines == redo, 'manifest', m == json.dumps(json.loads(m), indent=2, sort_keys=True))",
    ].join("\n"),
    tsBundle,
  ],
  { cwd: REPO },
);
ok(check.stdout.trim() === "records True manifest True", `bundle files are written exactly as Python writes them (${check.stdout.trim()})`);

console.log(failures ? `\n${failures} interop check(s) FAILED` : "\nall interop checks passed");
process.exit(failures ? 1 : 0);
