/** Export bundles that buyers verify with gleipnir-verify (Python or TypeScript). */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname } from "node:path";
import { zipSync, strToU8 } from "fflate";
import { FORMAT_VERSION, parseTime, pyDumps } from "@getgleipnir/verify";
import type { Rec } from "./store.js";
import { iso, utcnow } from "./util.js";
import { VERSION } from "./version.js";

const VERIFY_README = (command: string, nodeCommand: string) => `# How to verify this bundle

This bundle contains signed, hash-chained records of actions taken by an AI agent.
You can check it yourself, offline, without access to the vendor's systems:

    ${command}

or, with Node.js:

    ${nodeCommand}

What the options do:

    --expect-key KEY        fail unless the chain is signed with this key
                            (compare with the key id the vendor publishes)
    --require-anchor rekor  fail unless every segment is anchored in the public
                            Sigstore Rekor log (so receipts cannot be silently removed)
    --require-anchor rfc3161
                            fail unless every segment carries a trusted RFC 3161 timestamp
    --max-anchor-delay SEC  fail if a segment was timestamped long after it closed
                            (catches history that was rebuilt and re-anchored later)
    --require-full          fail unless the bundle starts at the beginning of the chain
    --known-head SEQ:HASH   fail unless the head you saw in an earlier bundle is still
                            there, unchanged (detects truncation and rewritten history)
    --expect-until TIME     fail if the records stop earlier than this
    --json                  machine-readable result

A VALID result means: no record was edited, removed, reordered or inserted after it was
written, every segment's Merkle root matches, and anchor receipts check out. It does not
mean the agent's decisions were correct, and it cannot show actions the vendor never
recorded: reconcile the external object ids in the records with your own systems.
`;

/** The flags a buyer should pass for this bundle. */
function verifyFlags(records: Rec[], name: string, full: boolean): string[] {
  const parts = [name, "--expect-key", (records[0]!["public_key"] as Rec)["id"] as string];
  const types = new Set(records.filter((r) => r["kind"] === "anchor").map((r) => (r["anchor"] as Rec)["type"]));
  for (const t of ["rekor", "rfc3161"]) if (types.has(t)) parts.push("--require-anchor", t);
  if (full) parts.push("--require-full");
  return parts;
}

/** The gleipnir-verify command a buyer should run for this bundle. */
export function verifyCommand(records: Rec[], name: string, full: boolean): string {
  return ["pipx run gleipnir-verify", ...verifyFlags(records, name, full)].join(" ");
}

function nodeVerifyCommand(records: Rec[], name: string, full: boolean): string {
  return ["npx -p @getgleipnir/verify gleipnir-verify", ...verifyFlags(records, name, full)].join(" ");
}

const micros = (d: Date) => BigInt(d.getTime()) * 1000n;

/**
 * Genesis plus the complete segments overlapping [since, until].
 *
 * A partial bundle always starts at a segment boundary, so the verifier can check its first
 * record through the segment's Merkle root. It is extended to include the anchor receipts of
 * the chosen segments (which are written into later segments).
 */
export function selectRecords(records: Rec[], since?: Date | null, until?: Date | null): Rec[] {
  if (!records.length) return [];
  if (!since && !until) return records;
  const [genesis, ...body] = records as [Rec, ...Rec[]];
  if (body.some((r) => r["kind"] === "key_rotation")) {
    throw new Error("date-range export of a chain with key rotations is not supported yet; export the whole chain");
  }
  const segPos = body.flatMap((r, i) => (r["kind"] === "segment" ? [i] : []));
  const starts = [0, ...segPos.slice(0, -1).map((i) => i + 1)];
  const chosen: Array<[number, number]> = [];
  segPos.forEach((end, j) => {
    const seg = body[end]!["segment"] as Rec;
    const opened = parseTime(seg["opened_at"]);
    const closed = parseTime(seg["closed_at"]);
    if ((!since || closed >= micros(since)) && (!until || opened <= micros(until))) chosen.push([starts[j]!, end]);
  });
  const tailStart = segPos.length ? segPos[segPos.length - 1]! + 1 : 0;
  const includeTail = !until;
  if (!chosen.length) {
    if (includeTail && tailStart < body.length) return [genesis, ...body.slice(tailStart)];
    return [genesis];
  }
  const first = chosen[0]![0];
  let last = chosen[chosen.length - 1]![1];
  const wanted = new Set(chosen.map(([, end]) => body[end]!["seq"]));
  const receiptPos = body.flatMap((r, i) =>
    r["kind"] === "anchor" && wanted.has((r["anchor"] as Rec)["segment_seq"]) ? [i] : [],
  );
  if (receiptPos.length && Math.max(...receiptPos) > last) {
    const need = Math.max(...receiptPos);
    const later = segPos.filter((i) => i >= need);
    last = later.length ? later[0]! : body.length - 1;
  }
  if (includeTail) last = body.length - 1;
  return [genesis, ...body.slice(first, last + 1)];
}

export interface ExportOptions {
  since?: Date | null;
  until?: Date | null;
  /** Path of the local anchor log to include as anchors/local-anchor-log.jsonl. */
  localAnchorLog?: string | null;
}

/** Build a bundle zip in memory. */
export function buildBundle(records: Rec[], name: string, opts: ExportOptions = {}): Uint8Array {
  const picked = selectRecords(records, opts.since, opts.until);
  if (!picked.length) throw new Error("no records to export");
  const body = picked.filter((r) => r["seq"] !== 0);
  const manifest: Rec = {
    format: FORMAT_VERSION,
    chain: picked[0]!["chain"],
    from_seq: body.length ? body[0]!["seq"] : null,
    to_seq: picked[picked.length - 1]!["seq"],
    exported_at: iso(utcnow()),
    key: (picked[0]!["public_key"] as Rec)["id"],
    tool: `@getgleipnir/sdk ${VERSION}`,
  };
  if (opts.since) manifest["since"] = iso(opts.since);
  if (opts.until) manifest["until"] = iso(opts.until);
  const full = body.length > 0 && body[0]!["seq"] === 1;
  const files: Record<string, Uint8Array> = {
    "manifest.json": strToU8(pyDumps(manifest, { indent: 2, sortKeys: true })),
    // ASCII-only lines (non-ASCII escaped), as the Python SDK writes bundles.
    "records.jsonl": strToU8(picked.map((r) => pyDumps(r, { sortKeys: true, separators: [",", ":"] }) + "\n").join("")),
    "VERIFY.md": strToU8(VERIFY_README(verifyCommand(picked, name, full), nodeVerifyCommand(picked, name, full))),
  };
  if (opts.localAnchorLog && existsSync(opts.localAnchorLog)) {
    files["anchors/local-anchor-log.jsonl"] = readFileSync(opts.localAnchorLog);
  }
  return zipSync(files, { level: 6 });
}

/** Write a verification bundle to `out`; returns the path. */
export function exportBundle(records: Rec[], out: string, opts: ExportOptions = {}): string {
  const zip = buildBundle(records, basename(out), opts);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, zip);
  return out;
}
