#!/usr/bin/env node
/**
 * Gleipnir verify action: verify Gleipnir record bundles (bundle.zip / proof.zip) offline,
 * write a job summary and fail the step if any bundle is INVALID.
 *
 * Inputs arrive as INPUT_<NAME> environment variables (GitHub's convention for JavaScript
 * actions), so this also runs locally:  INPUT_BUNDLE='out/*.zip' node action/run.mjs
 * Dependency-free: the TypeScript verifier is bundled in dist/gleipnir-verify.mjs.
 */

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { appendFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const TS_VERIFIER = join(HERE, "dist", "gleipnir-verify.mjs");

/** An input as GitHub passes it (INPUT_ + name upper-cased, spaces as underscores), trimmed. */
export function input(name, env = process.env) {
  return (env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] ?? "").trim();
}

function boolInput(name, env) {
  const v = input(name, env).toLowerCase();
  if (v === "" || v === "false") return false;
  if (v === "true") return true;
  throw new UsageError(`input ${name} must be true or false, got ${JSON.stringify(v)}`);
}

class UsageError extends Error {}

/** Split a list input on commas, whitespace and newlines. */
const list = (text) => text.split(/[\s,]+/).filter(Boolean);

// ---- glob ----------------------------------------------------------------------------------

/** Glob pattern (`*`, `?`, `**`, `[...]`, `{a,b}`) to a RegExp over "/"-separated relative paths. */
export function globToRegExp(pattern) {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        const slash = pattern[i + 2] === "/";
        re += slash ? "(?:[^/]*/)*" : ".*";
        i += slash ? 2 : 1;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else if (c === "[") {
      const end = pattern.indexOf("]", i + 1);
      if (end < 0) re += "\\[";
      else {
        const body = pattern.slice(i + 1, end).replace(/^!/, "^").replace(/\\/g, "\\\\");
        re += `[${body}]`;
        i = end;
      }
    } else if (c === "{") {
      const end = pattern.indexOf("}", i + 1);
      if (end < 0) re += "\\{";
      else {
        re += "(?:" + pattern.slice(i + 1, end).split(",").map((alt) => globToRegExp(alt).source.slice(1, -1)).join("|") + ")";
        i = end;
      }
    } else re += c.replace(/[.+^$()|\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

/** The literal directory a pattern starts in (the part before the first wildcard segment). */
function globBase(pattern) {
  const parts = pattern.split("/");
  const base = [];
  for (const p of parts.slice(0, -1)) {
    if (/[*?[{]/.test(p)) break;
    base.push(p);
  }
  return base.join("/") || ".";
}

function walk(dir, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.name === ".git" || e.name === "node_modules") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.isFile()) out.push(p);
  }
}

/** Files matching any of the newline-separated patterns (a "!" prefix excludes), sorted, relative to cwd. */
export function expandGlobs(patterns, cwd = process.cwd()) {
  const include = [];
  const exclude = [];
  for (const raw of patterns.split("\n").map((s) => s.trim()).filter(Boolean)) {
    (raw.startsWith("!") ? exclude : include).push(raw.replace(/^!/, "").replace(/\\/g, "/").replace(/^\.\//, ""));
  }
  const found = new Set();
  for (const pat of include) {
    if (!/[*?[{]/.test(pat)) {
      const abs = resolve(cwd, pat);
      try {
        if (statSync(abs).isFile()) found.add(relative(cwd, abs).split(sep).join("/"));
      } catch {
        /* no such file: reported as no match */
      }
      continue;
    }
    const re = globToRegExp(pat);
    const files = [];
    walk(resolve(cwd, globBase(pat)), files);
    for (const f of files) {
      const rel = relative(cwd, f).split(sep).join("/");
      if (re.test(rel)) found.add(rel);
    }
  }
  const ex = exclude.map(globToRegExp);
  return [...found].filter((f) => !ex.some((re) => re.test(f))).sort();
}

// ---- verification --------------------------------------------------------------------------

/** Verifier command-line flags from the action inputs. */
export function verifierFlags(env = process.env) {
  const flags = [];
  const key = input("expect-key", env);
  if (key) flags.push("--expect-key", key);
  for (const t of list(input("require-anchor", env))) {
    if (t !== "rekor" && t !== "rfc3161") throw new UsageError(`require-anchor: unknown anchor type ${JSON.stringify(t)} (use rekor, rfc3161)`);
    flags.push("--require-anchor", t);
  }
  if (boolInput("require-full", env)) flags.push("--require-full");
  const delay = input("max-anchor-delay", env);
  if (delay) {
    if (!/^\d+(\.\d+)?$/.test(delay)) throw new UsageError(`max-anchor-delay must be a number of seconds, got ${JSON.stringify(delay)}`);
    flags.push("--max-anchor-delay", delay);
  }
  const head = input("known-head", env);
  if (head) flags.push("--known-head", head);
  const until = input("expect-until", env);
  if (until) flags.push("--expect-until", until);
  const root = input("trusted-root", env);
  if (root) flags.push("--trusted-root", root);
  if (boolInput("strict", env)) flags.push("--strict");
  return flags;
}

/** The verifier to run: [command, ...args]. */
export function verifierCommand(env = process.env) {
  const which = (input("verifier", env) || "typescript").toLowerCase();
  if (which === "typescript" || which === "ts") return { name: "typescript", cmd: [process.execPath, TS_VERIFIER] };
  if (which === "python" || which === "py") {
    const cmd = list(input("python-command", env) || "pipx run gleipnir-verify");
    return { name: "python", cmd };
  }
  throw new UsageError(`verifier must be typescript or python, got ${JSON.stringify(which)}`);
}

function run(cmd, args) {
  const r = spawnSync(cmd[0], [...cmd.slice(1), ...args], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`cannot run ${cmd.join(" ")}: ${r.error.message}`);
  return r;
}

/** Verify one bundle: the verifier's text report (for the log) and its JSON report. */
export function verifyOne(verifier, bundle, flags) {
  const text = run(verifier.cmd, [bundle, ...flags]);
  const json = run(verifier.cmd, [bundle, ...flags, "--json"]);
  let report = null;
  try {
    report = JSON.parse(json.stdout);
  } catch {
    /* handled below */
  }
  if (!report || (report.result !== "VALID" && report.result !== "INVALID") || text.status === 2 || json.status === 2) {
    throw new Error(`verifier failed on ${bundle} (exit ${json.status}):\n${(json.stderr || json.stdout || text.stderr).trim()}`);
  }
  // The exit code is the verdict (it accounts for --strict); the report must agree with it.
  const valid = text.status === 0 && json.status === 0 && report.result === "VALID";
  return { bundle, valid, report, text: text.stdout };
}

// ---- summary -------------------------------------------------------------------------------

const esc = (s) =>
  String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\|/g, "&#124;")
    .replace(/\r?\n/g, "<br>");
const code = (s) => (s === undefined || s === null || s === "" ? "" : `<code>${esc(s)}</code>`);

/** Markdown job summary for the results. */
export function summaryMarkdown(results, { verifier, flags }) {
  const allValid = results.every((r) => r.valid);
  let md = `## Gleipnir verify: ${allValid ? "VALID" : "INVALID"}\n\n`;
  md += `${results.length} bundle${results.length === 1 ? "" : "s"} checked with the ${verifier} verifier`;
  md += flags.length ? ` (${code(flags.join(" "))}).\n\n` : ".\n\n";
  md += "| Bundle | Result | Records | Segments | Independently anchored | Covers | Errors | Warnings |\n";
  md += "|---|---|---|---|---|---|---|---|\n";
  for (const r of results) {
    const s = r.report.summary ?? {};
    const f = r.report.findings ?? [];
    const isProof = s.type === "proof";
    const records = isProof ? `proof of ${esc(s.action)}` : s.records ?? "";
    const segments = isProof ? "" : s.segments ?? "";
    const anchored = isProof ? esc((s.anchors_independent ?? []).join(", ")) : s.anchors_independent ?? "";
    const covers = s.covered_from ? `${esc(s.covered_from)} .. ${esc(s.covered_until)}` : "";
    md += `| ${code(r.bundle)} | ${r.valid ? "VALID" : "**INVALID**"} | ${records} | ${segments} | ${anchored} | ${covers} | `;
    md += `${f.filter((x) => x.level === "error").length} | ${f.filter((x) => x.level === "warning").length} |\n`;
  }
  for (const r of results) {
    const f = r.report.findings ?? [];
    const s = r.report.summary ?? {};
    md += `\n### ${code(r.bundle)}: ${r.valid ? "VALID" : "INVALID"}\n\n`;
    if (s.keys) md += `Signing key${s.keys.length === 1 ? "" : "s"}: ${s.keys.map(code).join(", ")}\n\n`;
    if (s.head) md += `Head: ${code(`${s.head.seq}:${s.head.hash}`)} (pass as \`known-head\` next time to detect truncation)\n\n`;
    if (f.length === 0) {
      md += "No findings.\n";
      continue;
    }
    md += "| Level | Code | Seq | Message |\n|---|---|---|---|\n";
    for (const x of f) md += `| ${esc(x.level)} | ${code(x.code)} | ${x.seq ?? ""} | ${esc(x.message)} |\n`;
  }
  return md;
}

// ---- main ----------------------------------------------------------------------------------

function ghEscape(s) {
  return String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function setOutput(name, value, env) {
  if (!env.GITHUB_OUTPUT) return;
  const delim = `gleipnir_${randomBytes(12).toString("hex")}`; // cannot occur in the value
  appendFileSync(env.GITHUB_OUTPUT, `${name}<<${delim}\n${value}\n${delim}\n`);
}

/** Run the action; returns the process exit code (0 VALID, 1 INVALID or error). */
export function main(env = process.env, log = (s) => process.stdout.write(s)) {
  let results;
  let verifier;
  let flags;
  let cwd;
  try {
    const pattern = input("bundle", env);
    if (!pattern) throw new UsageError("input bundle is required (a path or glob, e.g. out/**/*.zip)");
    flags = verifierFlags(env);
    verifier = verifierCommand(env);
    cwd = env.GLEIPNIR_ACTION_CWD || process.cwd();
    const bundles = expandGlobs(pattern, cwd);
    if (bundles.length === 0) throw new UsageError(`no files match bundle: ${pattern}`);
    results = [];
    for (const b of bundles) {
      log(`::group::${b}\n`);
      const r = verifyOne(verifier, resolve(cwd, b), flags);
      r.bundle = b;
      log(r.text);
      log("::endgroup::\n");
      for (const f of r.report.findings ?? []) {
        if (f.level === "error") log(`::error title=Gleipnir ${ghEscape(f.code)}::${ghEscape(b)}: ${ghEscape(f.message)}\n`);
        else if (f.level === "warning") log(`::warning title=Gleipnir ${ghEscape(f.code)}::${ghEscape(b)}: ${ghEscape(f.message)}\n`);
      }
      log(`${r.valid ? "VALID  " : "INVALID"}  ${b}\n`);
      results.push(r);
    }
  } catch (exc) {
    const msg = exc instanceof Error ? exc.message : String(exc);
    log(`::error title=Gleipnir verify::${ghEscape(msg)}\n`);
    if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `## Gleipnir verify: ERROR\n\n${esc(msg)}\n`);
    setOutput("result", "ERROR", env);
    return 1;
  }
  const allValid = results.every((r) => r.valid);
  const md = summaryMarkdown(results, { verifier: verifier.name, flags });
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, md);
  setOutput("result", allValid ? "VALID" : "INVALID", env);
  setOutput("bundles", String(results.length), env);
  setOutput("invalid", results.filter((r) => !r.valid).map((r) => r.bundle).join("\n"), env);
  const heads = results.map((r) => r.report.summary?.head).filter(Boolean);
  if (results.length === 1 && heads.length === 1) setOutput("head", `${heads[0].seq}:${heads[0].hash}`, env);
  setOutput("report", JSON.stringify(results.map((r) => ({ bundle: r.bundle, valid: r.valid, ...r.report }))), env);
  const bad = results.filter((r) => !r.valid).length;
  log(allValid ? `\nresult: VALID (${results.length} bundle${results.length === 1 ? "" : "s"})\n` : `\nresult: INVALID (${bad} of ${results.length} bundles)\n`);
  if (!allValid) log(`::error title=Gleipnir verify::${bad} of ${results.length} bundle(s) INVALID\n`);
  return allValid ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
