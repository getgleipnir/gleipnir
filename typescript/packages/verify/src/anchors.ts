/**
 * Verification of anchor receipts.
 *
 * An anchor receipt proves that a segment hash was published outside the vendor's control at
 * some point in time. Each anchor type registers a verifier function.
 */

import { canonicalize, sha256Tagged } from "./canon.js";
import { decodeUtf8, parseJson } from "./json.js";
import { PyError, dget, isBlank, isDict, isNone, isPyInt, pyEq, pyInt, pyRepr, type JsonDict } from "./py.js";

export interface AnchorResult {
  /** true = verified, false = invalid, null = present but not checked. */
  ok: boolean | null;
  detail: string;
  /** True if the anchor is outside the vendor's control. */
  independent: boolean;
  /** Trusted time attested by the anchor, if any (RFC 3339, UTC). */
  time: string | null;
}

export function anchorResult(ok: boolean | null, detail = "", independent = false, time: string | null = null): AnchorResult {
  return { ok, detail, independent, time };
}

/** A local anchor log supplied separately from the bundle (the CLI's --local-anchor-log). */
export type LocalAnchorLogSource =
  | { bytes: Uint8Array }
  /** The log could not be read (for example the file does not exist). */
  | { error: string };

export interface AnchorOptions {
  /** Entries of the local anchor log (set automatically from a bundle's anchors/local-anchor-log.jsonl). */
  localAnchorEntries?: unknown[] | null;
  /** A local anchor log file's contents; takes precedence over `localAnchorEntries`. */
  localAnchorLog?: LocalAnchorLogSource;
  /** A Sigstore trusted_root.json (parsed) to use instead of the embedded one. */
  trustedRoot?: unknown;
  /** @internal per-verification cache. */
  _localCache?: { entries: unknown[] | null; error: string | null };
}

export interface AnchorContext {
  segmentHash: string;
  chain: unknown;
  options: AnchorOptions;
}

export type AnchorVerifier = (anchor: JsonDict, ctx: AnchorContext) => AnchorResult;

export function localLogEntryHash(entry: JsonDict): string {
  const body: JsonDict = {};
  for (const k of Object.keys(entry)) if (k !== "hash") body[k] = entry[k];
  return sha256Tagged(canonicalize(body));
}

/** Return null if the local anchor log is internally consistent, else a reason. */
export function checkLocalLog(entries: unknown[]): string | null {
  let prev: unknown = null;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (!pyEq(dget(e, "index"), i)) return `entry ${i} has index ${pyRepr(dget(e, "index"))}`;
    if (!pyEq(dget(e, "prev"), prev)) return `entry ${i} does not link to entry ${i - 1}`;
    const h = localLogEntryHash(e as JsonDict);
    if (!pyEq(dget(e, "hash"), h)) return `entry ${i} hash mismatch`;
    prev = h;
  }
  return null;
}

/** Parse a local anchor log file the way the reference reads it (text mode, universal newlines). */
function readLocalLog(bytes: Uint8Array): unknown[] {
  const text = decodeUtf8(bytes).replace(/\r\n?/g, "\n");
  const out: unknown[] = [];
  for (const line of text.split(/(?<=\n)/)) {
    if (!isBlank(line)) out.push(parseJson(line));
  }
  return out;
}

function localEntries(options: AnchorOptions): { entries: unknown[] | null; error: string | null } {
  if (options._localCache) return options._localCache;
  let entries: unknown[] | null = null;
  let error: string | null = null;
  const src = options.localAnchorLog;
  if (src) {
    if ("error" in src) error = `cannot read local anchor log: ${src.error}`;
    else {
      try {
        entries = readLocalLog(src.bytes);
      } catch (exc) {
        if (exc instanceof PyError && exc.name === "JSONDecodeError") error = `cannot read local anchor log: ${exc.message}`;
        else throw exc;
      }
    }
  } else if (!isNone(options.localAnchorEntries)) {
    entries = options.localAnchorEntries;
  }
  if (entries !== null && error === null) {
    const problem = checkLocalLog(entries);
    if (problem) error = `local anchor log is inconsistent: ${problem}`;
  }
  options._localCache = { entries, error };
  return options._localCache;
}

export const verifyLocal: AnchorVerifier = (receipt, { segmentHash, chain, options }) => {
  const { entries, error } = localEntries(options);
  if (error) return anchorResult(false, error);
  if (entries === null) {
    return anchorResult(
      null,
      "local anchor log not provided (use --local-anchor-log); local anchors are for testing and are not independent of the vendor",
    );
  }
  const r = dget(receipt, "receipt", {});
  const idx = dget(r, "index");
  if (!isPyInt(idx) || !(pyInt(idx) >= 0 && pyInt(idx) < entries.length)) {
    return anchorResult(false, `receipt index ${pyRepr(idx)} not in local anchor log`);
  }
  const entry = entries[pyInt(idx)];
  if (!pyEq(dget(entry, "hash"), dget(r, "entry_hash"))) return anchorResult(false, "receipt does not match the log entry");
  if (!pyEq(dget(entry, "segment_hash"), segmentHash) || !pyEq(dget(entry, "chain"), chain)) {
    return anchorResult(false, "log entry is for a different segment");
  }
  return anchorResult(true, "local anchor log entry found (not independent of the vendor)", false);
};

export { isDict };
