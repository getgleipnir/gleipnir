/**
 * Helpers that reproduce the Python reference verifier's semantics on untyped JSON.
 *
 * The Python verifier walks records with `dict.get`, `x["k"]`, `int(...)` and `==`, and turns
 * some exception types into specific findings while others fall through to a generic
 * "malformed" finding. To report the same finding codes on hostile input, this port raises
 * errors with the same Python exception names in the same places.
 *
 * JSON numbers: Python distinguishes `1` (int) from `1.0` (float) and keeps big integers exact.
 * The bundle parser therefore produces plain numbers for safe integers and non-integral
 * floats, {@link PyFloat} for integral float literals such as `1.0` or `1e2`, and
 * {@link BigIntLiteral} for integers outside the IEEE 754 safe range.
 */

export class PyError extends Error {
  constructor(name: string, message: string) {
    super(message);
    this.name = name;
  }
}
const mk = (name: string) => (message: string) => new PyError(name, message);
export const KeyError = (key: string) => new PyError("KeyError", pyRepr(key));
export const TypeErr = mk("TypeError");
export const ValueErr = mk("ValueError");
export const AttributeErr = mk("AttributeError");
export const OverflowErr = mk("OverflowError");

/** Exception classes as Python's `except (...)` clauses see them (subclasses included). */
const SUBCLASSES: Record<string, string[]> = {
  ValueError: ["ValueError", "JSONDecodeError", "UnicodeDecodeError", "UnicodeEncodeError", "Error" /* binascii */],
  KeyError: ["KeyError"],
  TypeError: ["TypeError"],
  AttributeError: ["AttributeError"],
};

/** True when `err` would be caught by `except (names...)` in Python. */
export function caught(err: unknown, ...names: string[]): boolean {
  if (!(err instanceof PyError)) return false;
  return names.some((n) => (SUBCLASSES[n] ?? [n]).includes(err.name));
}

/** A JSON integer literal outside the IEEE 754 safe range (kept exact so JCS can reject it). */
export class BigIntLiteral {
  readonly value: bigint;
  constructor(readonly text: string) {
    this.value = BigInt(text);
  }
  /** `JSON.stringify` writes the nearest double (exactness needs `pyDumps`). */
  toJSON(): number {
    return Number(this.value);
  }
}

/** A JSON float literal whose value is integral (`1.0`, `1e2`, `-0.0`): a Python float, not an int. */
export class PyFloat {
  constructor(readonly value: number) {}
  toJSON(): number {
    return this.value;
  }
}

export type JsonDict = { [key: string]: unknown };

export function isDict(x: unknown): x is JsonDict {
  if (x === null || typeof x !== "object" || Array.isArray(x)) return false;
  const proto = Object.getPrototypeOf(x);
  return proto === Object.prototype || proto === null;
}

export function hasKey(d: JsonDict, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(d, key);
}

export function isNone(x: unknown): x is null | undefined {
  return x === null || x === undefined;
}

/** Python `d.get(key, default)`; AttributeError when `d` is not a dict. */
export function dget(d: unknown, key: string, dflt: unknown = null): unknown {
  if (!isDict(d)) throw AttributeErr(`'${pyTypeName(d)}' object has no attribute 'get'`);
  return hasKey(d, key) ? d[key] : dflt;
}

/** Python `d[key]` for a string key: KeyError when missing, TypeError when not a dict. */
export function sub(d: unknown, key: string): unknown {
  if (isDict(d)) {
    if (!hasKey(d, key)) throw KeyError(key);
    return d[key];
  }
  if (typeof d === "string" || Array.isArray(d)) {
    throw TypeErr(`${pyTypeName(d) === "str" ? "string" : "list"} indices must be integers or slices, not str`);
  }
  throw TypeErr(`'${pyTypeName(d)}' object is not subscriptable`);
}

/** Python `key in d` / `d[key] = ...` on a value used as a dict key. */
export function requireHashable(x: unknown): void {
  if (Array.isArray(x) || isDict(x)) throw TypeErr(`unhashable type: '${pyTypeName(x)}'`);
}

function isNumeric(x: unknown): boolean {
  return typeof x === "number" || typeof x === "boolean" || x instanceof PyFloat || x instanceof BigIntLiteral;
}

/** Python `isinstance(x, int)` (bool is an int in Python). */
export function isPyInt(x: unknown): boolean {
  return (typeof x === "number" && Number.isInteger(x)) || typeof x === "boolean" || x instanceof BigIntLiteral;
}

/** The numeric value of a JSON number, PyFloat, BigIntLiteral or bool. */
export function num(x: unknown): number {
  if (typeof x === "number") return x;
  if (typeof x === "boolean") return x ? 1 : 0;
  if (x instanceof PyFloat) return x.value;
  if (x instanceof BigIntLiteral) return Number(x.value);
  throw TypeErr(`unsupported operand type(s): '${pyTypeName(x)}'`);
}

/** Python truthiness of a JSON value. */
export function truthy(x: unknown): boolean {
  if (isNone(x) || x === false || x === "") return false;
  if (isNumeric(x)) return x instanceof BigIntLiteral ? x.value !== 0n : num(x) !== 0;
  if (Array.isArray(x)) return x.length > 0;
  if (isDict(x)) return Object.keys(x).length > 0;
  return true;
}

const INT_DIGITS_LIMIT = 4300; // CPython's default int max str digits (3.10.7+)

function pyIntFromString(x: string): bigint {
  const t = x.replace(/^[\s\u001c-\u001f\u0085]+|[\s\u001c-\u001f\u0085]+$/gu, "");
  if (!/^[+-]?[0-9](_?[0-9])*$/.test(t)) throw ValueErr(`invalid literal for int() with base 10: ${pyRepr(x)}`);
  const digits = t.replace(/[+_-]/g, "");
  if (digits.length > INT_DIGITS_LIMIT) {
    throw ValueErr(`Exceeds the limit (${INT_DIGITS_LIMIT}) for integer string conversion`);
  }
  return BigInt(t.replace(/_/g, ""));
}

/** Python `int(x)` for JSON values, exact. */
export function pyIntBig(x: unknown): bigint {
  if (typeof x === "boolean") return x ? 1n : 0n;
  if (x instanceof BigIntLiteral) return x.value;
  if (typeof x === "number" || x instanceof PyFloat) {
    const v = num(x);
    if (Number.isNaN(v)) throw ValueErr("cannot convert float NaN to integer");
    if (!Number.isFinite(v)) throw OverflowErr("cannot convert float infinity to integer");
    return BigInt(Math.trunc(v));
  }
  if (typeof x === "string") return pyIntFromString(x);
  throw TypeErr(`int() argument must be a string, a bytes-like object or a real number, not '${pyTypeName(x)}'`);
}

/** Python `int(x)` as a JS number (callers only use it where values are small). */
export function pyInt(x: unknown): number {
  return Number(pyIntBig(x));
}

/** Python iteration over a JSON value: lists yield items, strings characters, dicts keys. */
export function pyIter(x: unknown): unknown[] {
  if (Array.isArray(x)) return x;
  if (typeof x === "string") return Array.from(x);
  if (isDict(x)) return Object.keys(x);
  throw TypeErr(`'${pyTypeName(x)}' object is not iterable`);
}

function numEq(a: unknown, b: unknown): boolean {
  if (a instanceof BigIntLiteral || b instanceof BigIntLiteral) {
    const ex = (v: unknown): bigint | null => {
      if (v instanceof BigIntLiteral) return v.value;
      const n = num(v);
      return Number.isInteger(n) ? BigInt(n) : null;
    };
    const ea = ex(a);
    const eb = ex(b);
    return ea !== null && eb !== null && ea === eb;
  }
  return num(a) === num(b);
}

/** Python `a == b` on decoded JSON values (1 == 1.0 == True). */
export function pyEq(a: unknown, b: unknown): boolean {
  if (isNone(a) || isNone(b)) return isNone(a) && isNone(b);
  if (isNumeric(a) || isNumeric(b)) return isNumeric(a) && isNumeric(b) && numEq(a, b);
  if (typeof a === "string" || typeof b === "string") return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => pyEq(v, b[i]));
  }
  if (isDict(a) && isDict(b)) {
    const ka = Object.keys(a);
    if (ka.length !== Object.keys(b).length) return false;
    return ka.every((k) => hasKey(b, k) && pyEq(a[k], b[k]));
  }
  return a === b;
}

let nanCounter = 0;
/** A string key with Python dict-key equality (1, 1.0 and True collide; strings do not). */
export function pyKey(x: unknown): string {
  requireHashable(x);
  if (isNone(x)) return "none";
  if (typeof x === "string") return "s:" + x;
  if (x instanceof BigIntLiteral) return "n:" + x.value.toString();
  if (isNumeric(x)) {
    const v = num(x);
    if (Number.isNaN(v)) return `nan:${nanCounter++}`;
    return Number.isInteger(v) ? "n:" + BigInt(v).toString() : "f:" + String(v);
  }
  return "o:" + String(x);
}

/** True when the string has no lone surrogates (is valid Unicode). */
export function isWellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        i++;
        continue;
      }
      return false;
    }
    if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

/** Python `str.splitlines()` (no keepends). */
export function splitlines(text: string): string[] {
  const parts = text.split(/\r\n|[\n\r\u000b\u000c\u001c\u001d\u001e\u0085\u2028\u2029]/u);
  if (parts.length > 0 && parts[parts.length - 1] === "") parts.pop();
  return parts;
}

const PY_BLANK = /^[\t\n\u000b\u000c\r\u001c-\u001f \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/u;

/** Python `not s.strip()`. */
export function isBlank(text: string): boolean {
  return PY_BLANK.test(text);
}

/** Sort strings by Unicode code point, as Python's `sorted()` does. */
export function codePointCompare(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done || y.done) return x.done && y.done ? 0 : x.done ? -1 : 1;
    const cx = (x.value as string).codePointAt(0) as number;
    const cy = (y.value as string).codePointAt(0) as number;
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

export function pyTypeName(x: unknown): string {
  if (isNone(x)) return "NoneType";
  if (typeof x === "boolean") return "bool";
  if (typeof x === "number") return Number.isInteger(x) ? "int" : "float";
  if (x instanceof PyFloat) return "float";
  if (x instanceof BigIntLiteral) return "int";
  if (typeof x === "string") return "str";
  if (Array.isArray(x)) return "list";
  if (isDict(x)) return "dict";
  if (x instanceof Uint8Array) return "bytes";
  return typeof x;
}

/** Python `repr()` of a JSON value, for messages. */
export function pyRepr(x: unknown, depth = 0): string {
  if (depth > 20) return "...";
  if (isNone(x)) return "None";
  if (x === true) return "True";
  if (x === false) return "False";
  if (x instanceof PyFloat) return pyFloatRepr(x.value);
  if (x instanceof BigIntLiteral) return x.value.toString();
  if (typeof x === "number") return Number.isInteger(x) && Math.abs(x) <= Number.MAX_SAFE_INTEGER ? String(x) : pyFloatRepr(x);
  if (typeof x === "string") return pyStrRepr(x);
  if (Array.isArray(x)) return "[" + x.map((v) => pyRepr(v, depth + 1)).join(", ") + "]";
  if (isDict(x)) {
    return "{" + Object.keys(x).map((k) => `${pyStrRepr(k)}: ${pyRepr(x[k], depth + 1)}`).join(", ") + "}";
  }
  return String(x);
}

/** Python `str()` of a JSON value. */
export function pyStr(x: unknown): string {
  return typeof x === "string" ? x : pyRepr(x);
}

/** Python `repr(float)`: shortest round-trip digits, exponent form outside 1e-4 <= |x| < 1e16. */
export function pyFloatRepr(x: number): string {
  if (Number.isNaN(x)) return "nan";
  if (x === Infinity) return "inf";
  if (x === -Infinity) return "-inf";
  if (x === 0) return Object.is(x, -0) ? "-0.0" : "0.0";
  const sign = x < 0 ? "-" : "";
  const [mant, expText] = Math.abs(x).toExponential().split("e") as [string, string];
  const digits = mant.replace(".", "");
  const exp = Number(expText);
  if (exp < -4 || exp >= 16) {
    const m = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    const e = Math.abs(exp) < 10 ? `0${Math.abs(exp)}` : String(Math.abs(exp));
    return `${sign}${m}e${exp < 0 ? "-" : "+"}${e}`;
  }
  if (exp < 0) return `${sign}0.${"0".repeat(-exp - 1)}${digits}`;
  if (digits.length <= exp + 1) return `${sign}${digits}${"0".repeat(exp + 1 - digits.length)}.0`;
  return `${sign}${digits.slice(0, exp + 1)}.${digits.slice(exp + 1)}`;
}

function pyStrRepr(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    if (ch === quote || ch === "\\") out += "\\" + ch;
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (cp < 0x20 || cp === 0x7f) out += "\\x" + cp.toString(16).padStart(2, "0");
    else if (cp >= 0xd800 && cp <= 0xdfff) out += "\\u" + cp.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + quote;
}

/** Python `f"{x:.{digits}f}"`: exact decimal expansion, ties to even. */
export function formatFixed(x: number, digits: number): string {
  if (!Number.isFinite(x)) return Number.isNaN(x) ? "nan" : x > 0 ? "inf" : "-inf";
  const neg = x < 0 || Object.is(x, -0);
  const exact = Math.abs(x).toFixed(100); // exact for doubles below 1e21
  if (Math.abs(x) >= 1e21) return (neg ? "-" : "") + BigInt(Math.abs(x)).toString() + (digits ? "." + "0".repeat(digits) : "");
  const [ip, fp] = exact.split(".") as [string, string];
  let keep = BigInt(ip + fp.slice(0, digits));
  const rest = fp.slice(digits);
  const first = rest.charCodeAt(0) - 48;
  const tail = rest.slice(1).replace(/0+$/, "");
  if (first > 5 || (first === 5 && (tail.length > 0 || keep % 2n === 1n))) keep += 1n;
  let s = keep.toString().padStart(digits + 1, "0");
  if (digits) s = s.slice(0, -digits) + "." + s.slice(-digits);
  return (neg ? "-" : "") + s;
}

/** Python `round(x, digits)` for a float, as a float. */
export function pyRound(x: number, digits: number): number {
  return Number(formatFixed(x, digits));
}

export function errorText(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  return `Error: ${String(err)}`;
}
