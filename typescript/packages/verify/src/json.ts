/**
 * JSON parsing and serialization with the reference implementation's (Python `json`) semantics.
 *
 * `parseJson` keeps what `JSON.parse` loses and what decides verification results:
 * - integer literals outside the IEEE 754 safe range stay exact ({@link BigIntLiteral}), so
 *   canonicalization rejects them as the spec and the Python verifier do;
 * - integral float literals (`1.0`, `1e2`) are {@link PyFloat}, so `seq: 1.0` is not an integer;
 * - `NaN`, `Infinity` and `-Infinity` are accepted (and then fail canonicalization);
 * - duplicate keys keep the last value, `__proto__` is an ordinary key.
 */

import { BigIntLiteral, PyError, PyFloat, codePointCompare, isDict, isWellFormed, pyFloatRepr } from "./py.js";

export const MAX_DEPTH = 900;
const INT_DIGITS_LIMIT = 4300;

export function jsonError(message: string, pos: number): PyError {
  return new PyError("JSONDecodeError", `${message}: char ${pos}`);
}

/** Parse one JSON text. Throws PyError("JSONDecodeError" | "RecursionError" | "ValueError"). */
export function parseJson(text: string): unknown {
  let i = 0;
  const n = text.length;
  const ws = () => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const parseString = (): string => {
    // at opening quote
    i++;
    let out = "";
    let start = i;
    for (;;) {
      if (i >= n) throw jsonError("Unterminated string starting at", start - 1);
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(start, i);
        i++;
        return out;
      }
      if (c < 0x20) throw jsonError("Invalid control character at", i);
      if (c === 0x5c) {
        out += text.slice(start, i);
        const e = text[i + 1];
        switch (e) {
          case '"': out += '"'; i += 2; break;
          case "\\": out += "\\"; i += 2; break;
          case "/": out += "/"; i += 2; break;
          case "b": out += "\b"; i += 2; break;
          case "f": out += "\f"; i += 2; break;
          case "n": out += "\n"; i += 2; break;
          case "r": out += "\r"; i += 2; break;
          case "t": out += "\t"; i += 2; break;
          case "u": {
            const hex = text.slice(i + 2, i + 6);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw jsonError("Invalid \\uXXXX escape", i + 1);
            out += String.fromCharCode(parseInt(hex, 16));
            i += 6;
            break;
          }
          default:
            throw jsonError("Invalid \\escape", i);
        }
        start = i;
        continue;
      }
      i++;
    }
  };

  const NUM = /-?(?:0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?/y;
  const parseNumber = (): unknown => {
    NUM.lastIndex = i;
    const m = NUM.exec(text);
    if (!m) throw jsonError("Expecting value", i);
    const lit = m[0];
    i += lit.length;
    if (m[1] === undefined && m[2] === undefined) {
      const digits = lit.replace("-", "");
      if (digits.length > INT_DIGITS_LIMIT) {
        throw new PyError("ValueError", `Exceeds the limit (${INT_DIGITS_LIMIT}) for integer string conversion`);
      }
      const v = Number(lit);
      if (Number.isSafeInteger(v)) return v === 0 ? 0 : v;
      return new BigIntLiteral(lit);
    }
    const v = Number(lit);
    return Number.isInteger(v) ? new PyFloat(v) : v;
  };

  const parseValue = (depth: number): unknown => {
    if (depth > MAX_DEPTH) throw new PyError("RecursionError", "maximum recursion depth exceeded while decoding JSON");
    if (i >= n) throw jsonError("Expecting value", i);
    const c = text[i];
    if (c === '"') return parseString();
    if (c === "{") {
      i++;
      const obj: Record<string, unknown> = {};
      ws();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') throw jsonError("Expecting property name enclosed in double quotes", i);
        const key = parseString();
        ws();
        if (text[i] !== ":") throw jsonError("Expecting ':' delimiter", i);
        i++;
        ws();
        const val = parseValue(depth + 1);
        if (key === "__proto__") {
          Object.defineProperty(obj, key, { value: val, enumerable: true, writable: true, configurable: true });
        } else {
          obj[key] = val;
        }
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return obj;
        }
        throw jsonError("Expecting ',' delimiter", i);
      }
    }
    if (c === "[") {
      i++;
      const arr: unknown[] = [];
      ws();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      for (;;) {
        ws();
        arr.push(parseValue(depth + 1));
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return arr;
        }
        throw jsonError("Expecting ',' delimiter", i);
      }
    }
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    if (text.startsWith("NaN", i)) { i += 3; return NaN; }
    if (text.startsWith("Infinity", i)) { i += 8; return Infinity; }
    if (text.startsWith("-Infinity", i)) { i += 9; return -Infinity; }
    return parseNumber();
  };

  if (text.charCodeAt(0) === 0xfeff) throw jsonError("Unexpected UTF-8 BOM (decode using utf-8-sig)", 0);
  ws();
  const value = parseValue(0);
  ws();
  if (i !== n) throw jsonError("Extra data", i);
  return value;
}

/** Strict UTF-8 decoding, like Python's `bytes.decode("utf-8")` (a BOM is kept as U+FEFF). */
export function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new PyError("UnicodeDecodeError", utf8ErrorMessage(bytes));
  }
}

/** CPython's message for the first invalid UTF-8 sequence ("can't decode byte 0xe9 in position 2: ..."). */
function utf8ErrorMessage(b: Uint8Array): string {
  const hex = (x: number) => "0x" + x.toString(16).padStart(2, "0");
  const fail = (start: number, len: number, reason: string) =>
    len <= 1
      ? `'utf-8' codec can't decode byte ${hex(b[start]!)} in position ${start}: ${reason}`
      : `'utf-8' codec can't decode bytes in position ${start}-${start + len - 1}: ${reason}`;
  const cont = (x: number | undefined) => x !== undefined && (x & 0xc0) === 0x80;
  let i = 0;
  while (i < b.length) {
    const c = b[i]!;
    if (c < 0x80) {
      i++;
      continue;
    }
    let need: number;
    let lo = 0x80;
    let hi = 0xbf;
    if (c >= 0xc2 && c <= 0xdf) need = 1;
    else if (c >= 0xe0 && c <= 0xef) {
      need = 2;
      if (c === 0xe0) lo = 0xa0;
      if (c === 0xed) hi = 0x9f;
    } else if (c >= 0xf0 && c <= 0xf4) {
      need = 3;
      if (c === 0xf0) lo = 0x90;
      if (c === 0xf4) hi = 0x8f;
    } else return fail(i, 1, "invalid start byte");
    // the second byte has the narrowed range; later ones are plain continuation bytes
    let k = 1;
    for (; k <= need; k++) {
      const x = b[i + k];
      if (x === undefined) return fail(i, k, "unexpected end of data");
      const ok = k === 1 ? x >= lo && x <= hi : cont(x);
      if (!ok) return fail(i, k, "invalid continuation byte");
    }
    i += need + 1;
  }
  return "'utf-8' codec can't decode bytes: invalid UTF-8";
}

/** Python `json.loads(bytes)` for UTF-8 input (a leading UTF-8 BOM is skipped). */
export function parseJsonBytes(bytes: Uint8Array): unknown {
  const skip = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  return parseJson(decodeUtf8(bytes.subarray(skip)));
}

/** Strict UTF-8 encoding: lone surrogates are an error (Python `str.encode("utf-8")`). */
export function encodeUtf8(text: string): Uint8Array {
  if (!isWellFormed(text)) {
    throw new PyError("UnicodeEncodeError", "'utf-8' codec can't encode a lone surrogate");
  }
  return new TextEncoder().encode(text);
}

export interface DumpOptions {
  /** Escape non-ASCII as \uXXXX (Python's default `ensure_ascii=True`). */
  ensureAscii?: boolean;
  sortKeys?: boolean;
  /** Pretty-print with this many spaces (Python `indent=`). */
  indent?: number;
  /** [item separator, key separator]; defaults as in Python. */
  separators?: [string, string];
}

/** Python `json.dumps` output for JSON-like values, including PyFloat and BigIntLiteral. */
export function pyDumps(value: unknown, opts: DumpOptions = {}): string {
  const ensureAscii = opts.ensureAscii ?? true;
  const indent = opts.indent;
  const [itemSep, keySep] = opts.separators ?? (indent !== undefined ? [",", ": "] : [", ", ": "]);
  const str = (s: string) => dumpString(s, ensureAscii);
  const go = (v: unknown, level: number): string => {
    if (v === null || v === undefined) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (v instanceof PyFloat) return dumpFloat(v.value);
    if (v instanceof BigIntLiteral) return v.value.toString();
    if (typeof v === "bigint") return v.toString();
    if (typeof v === "number") return dumpNumber(v);
    if (typeof v === "string") return str(v);
    const nl = indent !== undefined ? "\n" + " ".repeat(indent * (level + 1)) : "";
    const end = indent !== undefined ? "\n" + " ".repeat(indent * level) : "";
    if (Array.isArray(v)) {
      if (v.length === 0) return "[]";
      return "[" + nl + v.map((x) => go(x, level + 1)).join(itemSep + nl) + end + "]";
    }
    if (isDict(v)) {
      let keys = Object.keys(v).filter((k) => v[k] !== undefined);
      if (keys.length === 0) return "{}";
      if (opts.sortKeys) keys = keys.sort(codePointCompare);
      return "{" + nl + keys.map((k) => str(k) + keySep + go(v[k], level + 1)).join(itemSep + nl) + end + "}";
    }
    return str(String(v));
  };
  return go(value, 0);
}

function dumpFloat(x: number): string {
  if (Number.isNaN(x)) return "NaN";
  if (x === Infinity) return "Infinity";
  if (x === -Infinity) return "-Infinity";
  return pyFloatRepr(x);
}

/**
 * A plain JS number. Safe integers are written as integers; other numbers in Python float
 * notation, so that a reader that distinguishes ints from floats (the Python verifier) reads
 * a large integral JS number as a float and canonicalizes it exactly as JCS here does.
 */
function dumpNumber(x: number): string {
  if (Number.isSafeInteger(x)) return Object.is(x, -0) ? "0" : String(x);
  return dumpFloat(x);
}

function dumpString(s: string, ensureAscii: boolean): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x0c) out += "\\f";
    else if (c < 0x20 || (ensureAscii && c > 0x7e)) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += s[i];
  }
  return out + '"';
}
