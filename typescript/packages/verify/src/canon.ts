/**
 * Canonical JSON (RFC 8785 / JCS) and record hashing.
 *
 * Implemented here rather than with a generic package because the verifier must reject what
 * the reference implementation rejects: integers outside the IEEE 754 safe range, NaN and
 * infinities, and strings that are not valid Unicode (lone surrogates).
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { encodeUtf8 } from "./json.js";
import { BigIntLiteral, PyError, PyFloat, isDict, isWellFormed, pyRepr } from "./py.js";
import { bytesToHex, hexToBytes } from "./bytes.js";

export const HASH_PREFIX = "sha256:";
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
/** Nesting limit; deeper values are reported as not canonicalizable (the reference hits its recursion limit). */
export const CANON_MAX_DEPTH = 985;

export class CanonicalizationError extends PyError {
  constructor(kind: string, message: string) {
    super(kind, message);
  }
}

function serializeNumber(x: number): string {
  if (!Number.isFinite(x)) throw new CanonicalizationError("FloatDomainError", `${x} is not representable in JCS`);
  // ECMAScript Number.prototype.toString is exactly the JCS number serialization; -0 becomes "0".
  return Object.is(x, -0) ? "0" : String(x);
}

function serializeString(s: string): string {
  if (!isWellFormed(s)) throw new CanonicalizationError("CanonicalizationError", "input contains non-UTF-8 codepoints");
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c < 0x20) {
      if (c === 0x08) out += "\\b";
      else if (c === 0x09) out += "\\t";
      else if (c === 0x0a) out += "\\n";
      else if (c === 0x0c) out += "\\f";
      else if (c === 0x0d) out += "\\r";
      else out += "\\u" + c.toString(16).padStart(4, "0");
    } else out += s[i];
  }
  return out + '"';
}

/** UTF-16 code unit order, as RFC 8785 section 3.2.3 requires. */
function utf16Compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function serialize(value: unknown, depth: number): string {
  if (depth > CANON_MAX_DEPTH) throw new PyError("RecursionError", "maximum recursion depth exceeded");
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return serializeString(value);
  if (typeof value === "number") {
    // A JS number that is an integer beyond 2^53 is indistinguishable from a float; it is
    // serialized like one (as the reference does for Python floats).
    return serializeNumber(value);
  }
  if (value instanceof PyFloat) return serializeNumber(value.value);
  if (value instanceof BigIntLiteral || typeof value === "bigint") {
    const v = value instanceof BigIntLiteral ? value.value : (value as bigint);
    if (v > BigInt(MAX_SAFE) || v < -BigInt(MAX_SAFE)) {
      throw new CanonicalizationError("IntegerDomainError", `${v} exceeds safe integer domain for JSON floats`);
    }
    return v.toString();
  }
  if (Array.isArray(value)) return "[" + value.map((v) => serialize(v, depth + 1)).join(",") + "]";
  if (isDict(value)) {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort(utf16Compare);
    return "{" + keys.map((k) => serializeString(k) + ":" + serialize(value[k], depth + 1)).join(",") + "}";
  }
  throw new CanonicalizationError("CanonicalizationError", `unsupported type: ${typeof value}`);
}

/** The RFC 8785 canonical form of a JSON value, as a string. */
export function canonicalizeString(value: unknown): string {
  return serialize(value, 0);
}

/** The RFC 8785 canonical UTF-8 encoding of a JSON value. */
export function canonicalize(value: unknown): Uint8Array {
  return encodeUtf8(canonicalizeString(value));
}

export function sha256Tagged(data: Uint8Array): string {
  return HASH_PREFIX + bytesToHex(sha256(data));
}

/** The record without its `sig` field. */
export function recordBody(record: Record<string, unknown>): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const k of Object.keys(record)) {
    if (k === "sig") continue;
    Object.defineProperty(body, k, { value: record[k], enumerable: true, writable: true, configurable: true });
  }
  return body;
}

/** `sha256:` + hex SHA-256 over the JCS encoding of the record without its `sig` field. */
export function recordHash(record: Record<string, unknown>): string {
  return sha256Tagged(canonicalize(recordBody(record)));
}

export function hashToBytes(tagged: unknown): Uint8Array {
  if (typeof tagged !== "string" || !tagged.startsWith(HASH_PREFIX)) {
    throw new PyError("ValueError", `not a sha256 hash: ${pyRepr(tagged)}`);
  }
  const raw = hexToBytes(tagged.slice(HASH_PREFIX.length));
  if (raw.length !== 32) throw new PyError("ValueError", `wrong hash length: ${tagged}`);
  return raw;
}

export function bytesToHash(raw: Uint8Array): string {
  return HASH_PREFIX + bytesToHex(raw);
}
