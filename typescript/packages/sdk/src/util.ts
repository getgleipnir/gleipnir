/** Small helpers: ids, clocks, JSON conversion. */

import { randomBytes } from "node:crypto";
import { BigIntLiteral, PyFloat, bytesToHex, isoMillis } from "@getgleipnir/verify";

export type Clock = () => Date;

export const utcnow: Clock = () => new Date();

/** RFC 3339 UTC with millisecond precision and a Z suffix. */
export function iso(d: Date): string {
  if (Number.isNaN(d.getTime())) throw new RangeError("invalid Date");
  return isoMillis(BigInt(d.getTime()) * 1000n);
}

/** Time-ordered unique id: <prefix>_<ms since epoch, hex, 12 digits><80 random bits, hex>. */
export function newId(prefix: string): string {
  return `${prefix}_${Date.now().toString(16).padStart(12, "0")}${bytesToHex(randomBytes(10))}`;
}

function reprOf(value: unknown): string {
  try {
    if (typeof value === "function") return `<function ${value.name || "anonymous"}>`;
    if (typeof value === "symbol") return value.toString();
    const ctor = (value as object)?.constructor?.name;
    const s = String(value);
    return ctor && s === "[object Object]" ? `<${ctor} object>` : s;
  } catch {
    return "<unrepresentable>";
  }
}

/**
 * Convert a tool argument or response into a JSON value that JCS can encode, with the same
 * mapping as the Python SDK's `to_jsonable` where JS has an equivalent:
 * NaN/Infinity become {"float": "nan"|"inf"|"-inf"}, integers outside the safe range
 * {"int": "<decimal>"} (the Python SDK raises on those instead), bytes {"bytes_len": n}, dates RFC 3339,
 * Sets sorted lists, Maps objects, anything else {"repr": "..."}; depth is capped at 50.
 */
export function toJsonable(value: unknown, depth = 0): unknown {
  if (depth > 50) return { repr: "<max depth>" };
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (Number.isNaN(value)) return { float: "nan" };
    if (!Number.isFinite(value)) return { float: value > 0 ? "inf" : "-inf" };
    return value;
  }
  if (typeof value === "bigint" || value instanceof BigIntLiteral) {
    // The spec allows only IEEE 754 safe integers; larger ones are kept exactly as a string.
    const v = typeof value === "bigint" ? value : value.value;
    return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : { int: v.toString() };
  }
  if (value instanceof PyFloat) return value;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? { repr: "Invalid Date" } : iso(value);
  if (value instanceof Uint8Array || value instanceof ArrayBuffer) return { bytes_len: value.byteLength };
  if (ArrayBuffer.isView(value)) return { bytes_len: value.byteLength };
  if (Array.isArray(value)) return value.map((v) => toJsonable(v, depth + 1));
  if (value instanceof Set) {
    const items = [...value].map((v) => toJsonable(v, depth + 1));
    return items.sort((a, b) => {
      const x = JSON.stringify(a) ?? "";
      const y = JSON.stringify(b) ?? "";
      return x < y ? -1 : x > y ? 1 : 0;
    });
  }
  if (value instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of value) setKey(out, String(k), toJsonable(v, depth + 1));
    return out;
  }
  if (value instanceof Error) return { repr: `${value.name}: ${value.message}`.slice(0, 2000) };
  if (typeof value === "object") {
    const toJSON = (value as { toJSON?: unknown }).toJSON;
    if (typeof toJSON === "function") {
      try {
        return toJsonable(toJSON.call(value), depth + 1);
      } catch {
        /* fall through */
      }
    }
    const proto = Object.getPrototypeOf(value);
    if (proto === Object.prototype || proto === null || typeof proto?.constructor === "function") {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(value)) {
        const v = (value as Record<string, unknown>)[k];
        if (v === undefined || typeof v === "function" || typeof v === "symbol") continue;
        setKey(out, k, toJsonable(v, depth + 1));
      }
      return out;
    }
  }
  return { repr: reprOf(value).slice(0, 2000) };
}

/** Assign without invoking the `__proto__` setter. */
export function setKey(obj: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}
