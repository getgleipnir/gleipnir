#!/usr/bin/env node
/** gleipnir-verify: check a Gleipnir record bundle offline (Node). Mirrors the Python CLI. */

import { readFileSync, realpathSync } from "node:fs";
import { basename } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import type { AnchorOptions } from "./anchors.js";
import { parseJsonBytes, pyDumps } from "./json.js";
import { pyFloatRepr } from "./py.js";
import { parseTime } from "./time.js";
import { ERROR, INFO, WARN, badBundleReport, parseKnownHead, verifyBundle, type Report } from "./verifier.js";

const VERSION_STRING = "gleipnir-verify 0.1.0 (typescript)";

const MARK: Record<string, string> = { [ERROR]: "FAIL", [WARN]: "WARN", [INFO]: "info" };
const PROG = "gleipnir-verify";

const USAGE = `usage: ${PROG} [-h] [--json] [--expect-key KEY_ID] [--expect-until TIME] [--known-head SEQ:HASH]
                       [--require-anchor {rekor,rfc3161}] [--max-anchor-delay SECONDS] [--require-full]
                       [--trusted-root PATH] [--local-anchor-log PATH] [--strict] [--version]
                       bundle`;

const HELP = `${USAGE}

Verify a Gleipnir agent action record bundle. Works offline; needs no access to the vendor.

positional arguments:
  bundle                path to bundle .zip

options:
  -h, --help            show this help message and exit
  --json                machine-readable output
  --expect-key KEY_ID   fail unless the chain is signed with this key id
  --expect-until TIME   fail unless records cover at least until this ISO 8601 time (detects truncation)
  --known-head SEQ:HASH
                        fail unless the record with this seq and hash is present (from an earlier bundle);
                        detects truncation and rewritten history
  --require-anchor {rekor,rfc3161}
                        fail unless every segment has a verified independent anchor of this type (rekor = public
                        transparency log, rfc3161 = trusted timestamp); repeatable
  --max-anchor-delay SECONDS
                        fail if a segment was timestamped more than this long after it closed
  --require-full        fail unless the bundle starts at the beginning of the chain
  --trusted-root PATH   Sigstore trusted_root.json to use instead of the embedded one (for newer log shards)
  --local-anchor-log PATH
                        local anchor log to check local receipts against
  --strict              treat warnings as failures
  --version             show program's version number and exit
`;

class Exit extends Error {
  constructor(readonly code: number) {
    super(`exit ${code}`);
  }
}

export interface Io {
  out: (s: string) => void;
  err: (s: string) => void;
}

function usageError(io: Io, message: string): never {
  io.err(`${USAGE}\n${PROG}: error: ${message}\n`);
  throw new Exit(2);
}

/** Python float() on a CLI argument. */
function parseFloatArg(io: Io, text: string): number {
  const t = text.trim().replace(/_/g, "");
  if (/^[+-]?(inf|infinity)$/i.test(t)) return t.startsWith("-") ? -Infinity : Infinity;
  if (/^[+-]?nan$/i.test(t)) return NaN;
  if (!/^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?$/i.test(t)) usageError(io, `argument --max-anchor-delay: invalid float value: '${text}'`);
  return Number(t);
}

/** Run the CLI; returns the exit code. */
export function main(argv: string[], io: Io = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s) }): number {
  try {
    return run(argv, io);
  } catch (exc) {
    if (exc instanceof Exit) return exc.code;
    throw exc;
  }
}

function run(argv: string[], io: Io): number {
  if (argv.includes("-h") || argv.includes("--help")) {
    io.out(HELP);
    return 0;
  }
  if (argv.includes("--version")) {
    io.out(`${VERSION_STRING}\n`);
    return 0;
  }
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        json: { type: "boolean" },
        "expect-key": { type: "string" },
        "expect-until": { type: "string" },
        "known-head": { type: "string" },
        "require-anchor": { type: "string", multiple: true },
        "max-anchor-delay": { type: "string" },
        "require-full": { type: "boolean" },
        "trusted-root": { type: "string" },
        "local-anchor-log": { type: "string" },
        strict: { type: "boolean" },
      },
    });
  } catch (exc) {
    usageError(io, exc instanceof Error ? exc.message : String(exc));
  }
  const a = parsed.values;
  if (parsed.positionals.length === 0) usageError(io, "the following arguments are required: bundle");
  if (parsed.positionals.length > 1) usageError(io, `unrecognized arguments: ${parsed.positionals.slice(1).join(" ")}`);
  const bundlePath = parsed.positionals[0]!;
  for (const t of a["require-anchor"] ?? []) {
    if (t !== "rekor" && t !== "rfc3161") {
      usageError(io, `argument --require-anchor: invalid choice: '${t}' (choose from 'rekor', 'rfc3161')`);
    }
  }
  const expectUntil = a["expect-until"] || null;
  if (expectUntil) {
    try {
      parseTime(expectUntil);
    } catch {
      usageError(io, "--expect-until needs an ISO 8601 time with a timezone, e.g. 2026-10-14T18:00:00Z");
    }
  }
  const options: AnchorOptions = {};
  if (a["local-anchor-log"]) {
    try {
      options.localAnchorLog = { bytes: readFileSync(a["local-anchor-log"]) };
    } catch (exc) {
      options.localAnchorLog = { error: osError(exc, a["local-anchor-log"]) };
    }
  }
  if (a["trusted-root"]) {
    // The reference reads the trusted root lazily and fails hard if it is unreadable.
    const text = readFileSync(a["trusted-root"]);
    options.trustedRoot = parseJsonBytes(text);
  }
  let knownHead: { seq: number; hash: string } | null = null;
  if (a["known-head"]) {
    knownHead = parseKnownHead(a["known-head"]);
    if (knownHead === null) usageError(io, "--known-head must look like 12:sha256:<64 hex>");
  }
  const maxDelay = a["max-anchor-delay"] !== undefined ? parseFloatArg(io, a["max-anchor-delay"]) : null;

  let report: Report;
  let bytes: Uint8Array | null = null;
  try {
    bytes = readFileSync(bundlePath);
  } catch (exc) {
    bytes = null;
    report = badBundleReport(`cannot read bundle: ${pyOsErrorName(exc)}: ${osError(exc, bundlePath).slice(0, 300)}`);
  }
  if (bytes !== null) {
    report = verifyBundle(bytes, {
      expectKey: a["expect-key"] ?? null,
      expectUntil,
      knownHead,
      requireAnchor: a["require-anchor"] ?? null,
      maxAnchorDelay: maxDelay,
      requireFull: a["require-full"] ?? false,
      anchorOptions: options,
    });
  }
  report = report!;
  const strict = a.strict ?? false;
  const valid = report.valid(strict);

  if (a.json) {
    io.out(pyDumps(report.toJSON(strict), { indent: 2, sortKeys: true }) + "\n");
    return valid ? 0 : 1;
  }

  const s = report.summary;
  let out = "";
  if (Object.keys(s).length > 0) {
    out += `chain:        ${pstr(s["chain"])}\n`;
    out += `signing keys: ${((s["keys"] as string[]) ?? []).join(", ")}\n`;
    out += `records:      ${pstr(s["records"])} (seq ${pstr(s["first_seq"])}..${pstr(s["last_seq"])})\n`;
    const byKind = (s["by_kind"] ?? {}) as Record<string, number>;
    const kinds = Object.keys(byKind)
      .sort((x, y) => (x < y ? -1 : x > y ? 1 : 0))
      .map((k) => `${k} ${byKind[k]}`)
      .join(", ");
    out += `by kind:      ${kinds}\n`;
    out += `segments:     ${pstr(s["segments"])}, anchored ${pstr(s["segments_anchored"])} (independent anchors: ${pstr(s["anchors_independent"])})\n`;
    out += `covers:       ${pstr(s["covered_from"])} .. ${pstr(s["covered_until"])}\n`;
    const head = s["head"] as { seq: unknown; hash: unknown } | undefined;
    if (head) {
      out += `head:         ${pstr(head.seq)}:${pstr(head.hash)}\n`;
      out += "              (keep this; pass it as --known-head next time to detect truncation)\n";
    }
    if (s["segments_timestamped"]) {
      out += `trusted time: ${pstr(s["segments_timestamped"])} segments timestamped (RFC 3161), max delay after close ${pstr(s["max_timestamp_delay_s"])}s\n`;
    }
    if (s["anchored_until"]) out += `anchored to:  ${pstr(s["anchored_until"])}\n`;
  }
  if (report.findings.length > 0) {
    out += "\n";
    for (const f of report.findings) {
      const where = f.seq !== undefined ? ` seq ${pstr(f.seq)}` : "";
      out += `[${MARK[f.level]}]${where} ${f.code}: ${f.message}\n`;
    }
  }
  out += "\n";
  if (valid) out += "result: VALID\n";
  else {
    const n = report.errors.length + (strict ? report.warnings.length : 0);
    out += `result: INVALID (${n} problem${n !== 1 ? "s" : ""})\n`;
  }
  io.out(out);
  return valid ? 0 : 1;
}

/** Python str() of a summary value. */
function pstr(x: unknown): string {
  if (x === null || x === undefined) return "None";
  if (x === true) return "True";
  if (x === false) return "False";
  if (typeof x === "number") return Number.isInteger(x) ? String(x) : pyFloatRepr(x);
  if (typeof x === "string") return x;
  return pyDumps(x);
}

function osError(exc: unknown, path: string): string {
  const e = exc as NodeJS.ErrnoException;
  const strerror: Record<string, string> = {
    ENOENT: "No such file or directory",
    EACCES: "Permission denied",
    EISDIR: "Is a directory",
  };
  const errno: Record<string, number> = { ENOENT: 2, EACCES: 13, EISDIR: 21 };
  if (e && e.code && strerror[e.code]) return `[Errno ${errno[e.code]}] ${strerror[e.code]}: '${path}'`;
  return e instanceof Error ? e.message : String(exc);
}

function pyOsErrorName(exc: unknown): string {
  const code = (exc as NodeJS.ErrnoException)?.code;
  if (code === "ENOENT") return "FileNotFoundError";
  if (code === "EACCES") return "PermissionError";
  if (code === "EISDIR") return "IsADirectoryError";
  return "OSError";
}

const invokedDirectly = (() => {
  const arg = process.argv[1];
  if (!arg) return false;
  try {
    const self = realpathSync(fileURLToPath(import.meta.url));
    return realpathSync(arg) === self;
  } catch {
    return basename(arg) === "gleipnir-verify";
  }
})();

if (invokedDirectly) {
  process.exitCode = main(process.argv.slice(2));
}
