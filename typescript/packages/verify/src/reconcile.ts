/**
 * Reconcile a verified bundle against the buyer's own system of record (port of
 * python/gleipnir-verify/src/gleipnir_verify/reconcile.py).
 *
 * Signed records cannot show actions the vendor never recorded. The buyer closes that gap by
 * comparing object ids in the records (refund ids, ticket ids, ...) with an export from its own
 * system, filtered to what the agent's identity touched:
 *
 *     gleipnir-verify reconcile bundle.zip refunds_by_agent.csv --column refund_id
 *
 * - in your system, not in the records: the agent may have acted without recording it
 * - in the records, not in your system: an action was claimed that your system does not show
 */

import { readBundle } from "./bundle.js";
import { decodeUtf8 } from "./json.js";
import { BigIntLiteral, PyError, isDict, pyRepr, type JsonDict } from "./py.js";
import { verifyBundle, type Report, type VerifyOptions } from "./verifier.js";

/** Id-like values (keys `id`, `*_id`, `*Id`) in a response body, optionally only key `wanted`. */
export function externalIds(value: unknown, wanted?: string | null): Set<string> {
  const out = new Set<string>();
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const v = stack.pop();
    if (isDict(v)) {
      for (const [k, x] of Object.entries(v)) {
        const isInt = (typeof x === "number" && Number.isInteger(x)) || x instanceof BigIntLiteral;
        if (typeof x === "string" || isInt) {
          const idLike = k === "id" || k.endsWith("_id") || k.endsWith("Id");
          if ((wanted && k === wanted) || (!wanted && idLike)) {
            out.add(typeof x === "string" ? x : x instanceof BigIntLiteral ? x.value.toString() : String(x));
          }
        } else if (isDict(x) || Array.isArray(x)) {
          stack.push(x);
        }
      }
    } else if (Array.isArray(v)) {
      stack.push(...v.slice(0, 1000));
    }
  }
  return out;
}

// ---- CSV, as Python's csv module reads it (excel dialect, file opened with newline="") ----------

/** Lines with their endings kept, split like Python's universal newlines (\n, \r, \r\n). */
function lines(text: string): string[] {
  const out: string[] = [];
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      out.push(text.slice(start, i + 1));
      start = i + 1;
    }
  }
  if (start < text.length) out.push(text.slice(start));
  return out;
}

const enum S {
  StartRecord,
  StartField,
  InField,
  InQuotedField,
  QuoteInQuotedField,
  EatCrnl,
}

/** Rows of a CSV text, exactly as `csv.reader` (excel dialect, strict=False) yields them. */
export function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let fields: string[] = [];
  let field = "";
  let state: S = S.StartRecord;
  const save = () => {
    fields.push(field);
    field = "";
  };
  const EOL = null;
  const step = (c: string | null): void => {
    const eol = c === "\n" || c === "\r" || c === EOL;
    switch (state) {
      case S.StartRecord:
        if (c === EOL) return;
        if (c === "\n" || c === "\r") {
          state = S.EatCrnl;
          return;
        }
        state = S.StartField;
      // falls through
      case S.StartField:
        if (eol) {
          save();
          state = c === EOL ? S.StartRecord : S.EatCrnl;
        } else if (c === '"') state = S.InQuotedField;
        else if (c === ",") save();
        else {
          field += c;
          state = S.InField;
        }
        return;
      case S.InField:
        if (eol) {
          save();
          state = c === EOL ? S.StartRecord : S.EatCrnl;
        } else if (c === ",") {
          save();
          state = S.StartField;
        } else field += c;
        return;
      case S.InQuotedField:
        if (c === EOL) return;
        if (c === '"') state = S.QuoteInQuotedField;
        else field += c;
        return;
      case S.QuoteInQuotedField:
        if (c === '"') {
          field += c;
          state = S.InQuotedField;
        } else if (c === ",") {
          save();
          state = S.StartField;
        } else if (eol) {
          save();
          state = c === EOL ? S.StartRecord : S.EatCrnl;
        } else {
          field += c;
          state = S.InField;
        }
        return;
      case S.EatCrnl:
        if (c === "\n" || c === "\r") return;
        if (c === EOL) {
          state = S.StartRecord;
          return;
        }
        throw new PyError("Error", "new-line character seen in unquoted field - do you need to open the file with newline=''?");
    }
  };
  for (const line of lines(text)) {
    for (const c of line) step(c);
    step(EOL);
    if (state === S.StartRecord) {
      rows.push(fields);
      fields = [];
    }
  }
  if (field.length !== 0 || (state as S) === S.InQuotedField) {
    save();
    rows.push(fields);
  }
  return rows;
}

/** Python `str.strip()`: Unicode whitespace as Python defines it (JS \s includes U+FEFF, Python does not). */
function stripPy(s: string): string {
  const ws = (c: string) => c !== "﻿" && /[\s\u001c-\u001f\u0085]/u.test(c);
  let a = 0;
  let b = s.length;
  while (a < b && ws(s[a]!)) a++;
  while (b > a && ws(s[b - 1]!)) b--;
  return s.slice(a, b);
}

/**
 * The non-empty, stripped values of `column` in a CSV export (UTF-8, optional BOM), like
 * `csv.DictReader` over the file. Throws a ValueError-type PyError when the column is missing.
 */
export function csvColumn(csv: Uint8Array | string, column: string, name = "the CSV"): Set<string> {
  let text = typeof csv === "string" ? csv : decodeUtf8(csv);
  if (text.startsWith("﻿")) text = text.slice(1);
  const rows = parseCsvRows(text);
  const header = rows[0];
  if (header === undefined || !header.includes(column)) {
    throw new PyError("ValueError", `column ${pyRepr(column)} not found in ${name}`);
  }
  const idx = header.lastIndexOf(column); // DictReader: a repeated name keeps the last column
  const out = new Set<string>();
  for (const row of rows.slice(1)) {
    if (row.length === 0) continue;
    // A short row has no value for the column. (The reference crashes on this with an
    // AttributeError on None.strip(); here it simply contributes no id.)
    const v = row[idx];
    if (v === undefined) continue;
    const t = stripPy(v);
    if (t) out.add(t);
  }
  return out;
}

export interface Reconciliation {
  report: Report;
  matched: Set<string>;
  onlyInSystem: Set<string>;
  onlyInRecords: Set<string>;
  /** The bundle verifies and both sides have exactly the same ids. */
  ok: boolean;
}

export interface ReconcileOptions extends VerifyOptions {
  /** Id column in the CSV, e.g. "refund_id". */
  column: string;
  /** Response field holding that id in the records (default: the column name). */
  field?: string | null;
  /** Name of the CSV for error messages. */
  csvName?: string;
}

/** Ids in the `ok` action responses of a bundle's records. */
export function recordIds(records: unknown[], field: string): Set<string> {
  const ids = new Set<string>();
  for (const r of records) {
    if (!isDict(r) || r["kind"] !== "action") continue;
    const resp = r["response"];
    // The reference assumes response is an object (it raises AttributeError otherwise).
    if (!isDict(resp) || resp["status"] !== "ok") continue;
    for (const id of externalIds((resp as JsonDict)["body"] ?? null, field)) ids.add(id);
  }
  return ids;
}

/**
 * Verify a bundle, then compare its object ids with the buyer's CSV export. `systemCsv` may be
 * a function: it is only called (the CSV only read) once the bundle has verified.
 */
export function reconcile(
  bundle: Uint8Array,
  systemCsv: Uint8Array | string | (() => Uint8Array | string),
  opts: ReconcileOptions,
): Reconciliation {
  const { column, field, csvName, ...verifyOptions } = opts;
  const report = verifyBundle(bundle, verifyOptions);
  const result: Reconciliation = { report, matched: new Set(), onlyInSystem: new Set(), onlyInRecords: new Set(), ok: false };
  if (!report.valid()) return result;
  const [, records] = readBundle(bundle);
  const ids = recordIds(records, field || column);
  const system = csvColumn(typeof systemCsv === "function" ? systemCsv() : systemCsv, column, csvName);
  for (const x of ids) (system.has(x) ? result.matched : result.onlyInRecords).add(x);
  for (const x of system) if (!ids.has(x)) result.onlyInSystem.add(x);
  result.ok = result.onlyInSystem.size === 0 && result.onlyInRecords.size === 0;
  return result;
}
