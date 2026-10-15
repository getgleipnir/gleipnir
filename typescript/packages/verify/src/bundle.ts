/** Reading bundle zip files (manifest.json, records.jsonl, anchors/local-anchor-log.jsonl). */

import { unzipSync } from "fflate";
import { decodeUtf8, parseJson, parseJsonBytes } from "./json.js";
import { PyError } from "./py.js";

/** Uncompressed size limit per member, against zip bombs. */
export const MAX_MEMBER_BYTES = 512 * 1024 * 1024;

function members(zipBytes: Uint8Array): Map<string, Uint8Array> {
  let total = 0;
  let files: Record<string, Uint8Array>;
  try {
    files = unzipSync(zipBytes, {
      filter: (f) => {
        if (f.originalSize > MAX_MEMBER_BYTES) throw new PyError("BadZipFile", `member ${f.name} is too large`);
        total += f.originalSize;
        if (total > 4 * MAX_MEMBER_BYTES) throw new PyError("BadZipFile", "bundle is too large");
        return f.name === "manifest.json" || f.name === "records.jsonl" || f.name === "anchors/local-anchor-log.jsonl";
      },
    });
  } catch (exc) {
    if (exc instanceof PyError) throw exc;
    throw new PyError("BadZipFile", exc instanceof Error ? exc.message : String(exc));
  }
  return new Map(Object.entries(files));
}

/**
 * JSON Lines as the spec defines them: split on "\n" only; a line that is empty or holds only
 * JSON whitespace other than newline (space, tab, CR) is skipped; every other line must be
 * exactly one JSON value (so VT, FF, U+0085 or U+2028 after a value are an error, as in Python).
 */
export function jsonLines(text: string): string[] {
  return text.split("\n").filter((l) => !/^[ \t\r]*$/.test(l));
}

/** Read a bundle: [manifest, records, local anchor log entries or null]. Throws on unreadable bundles. */
export function readBundle(zipBytes: Uint8Array): [unknown, unknown[], unknown[] | null] {
  const m = members(zipBytes);
  const get = (name: string): Uint8Array => {
    const b = m.get(name);
    if (b === undefined) throw new PyError("KeyError", `"There is no item named '${name}' in the archive"`);
    return b;
  };
  const manifest = parseJsonBytes(get("manifest.json"));
  const lines = jsonLines(decodeUtf8(get("records.jsonl")));
  let localLog: unknown[] | null = null;
  const log = m.get("anchors/local-anchor-log.jsonl");
  if (log !== undefined) {
    localLog = jsonLines(decodeUtf8(log)).map((l) => parseJson(l));
  }
  const records = lines.map((l) => parseJson(l));
  return [manifest, records, localLog];
}

/** Parse a records.jsonl text (as written by the SDK store or a bundle), with the bundle line rules. */
export function parseJsonl(text: string): unknown[] {
  return jsonLines(text).map((l) => parseJson(l));
}
