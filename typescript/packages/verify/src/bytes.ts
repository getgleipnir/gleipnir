/**
 * Byte helpers: hex and base64 with exactly the acceptance rules of the reference
 * implementation (Python `bytes.fromhex`, `base64.b64decode(validate=True)` and
 * `base64.urlsafe_b64decode`), so both verifiers accept and reject the same encodings.
 */

import { PyError } from "./py.js";

const HEX = "0123456789abcdef";

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += HEX[x >> 4]! + HEX[x & 15]!;
  return s;
}

function hexVal(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x37;
  if (c >= 0x61 && c <= 0x66) return c - 0x57;
  return -1;
}

const ASCII_WS = new Set([0x20, 0x09, 0x0a, 0x0b, 0x0c, 0x0d]);

/** Python `bytes.fromhex`: pairs of hex digits, ASCII whitespace allowed between pairs. */
export function hexToBytes(text: string): Uint8Array {
  const out: number[] = [];
  let i = 0;
  for (;;) {
    while (i < text.length && ASCII_WS.has(text.charCodeAt(i))) i++;
    if (i >= text.length) break;
    const hi = hexVal(text.charCodeAt(i));
    if (hi < 0) throw new PyError("ValueError", `non-hexadecimal number found in fromhex() arg at position ${i}`);
    const lo = i + 1 < text.length ? hexVal(text.charCodeAt(i + 1)) : -1;
    if (lo < 0) throw new PyError("ValueError", `non-hexadecimal number found in fromhex() arg at position ${i + 1}`);
    out.push((hi << 4) | lo);
    i += 2;
  }
  return Uint8Array.from(out);
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_VAL = new Int16Array(256).fill(-1);
for (let i = 0; i < 64; i++) B64_VAL[B64.charCodeAt(i)] = i;

/** `binascii.Error` (a ValueError subclass; its type name is "Error"). */
function binasciiError(message: string): PyError {
  return new PyError("Error", message);
}

function asciiBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c > 0x7f) throw new PyError("ValueError", "string argument should contain only ASCII characters");
    out[i] = c;
  }
  return out;
}

/** CPython `binascii.a2b_base64` in its default (non-strict) mode. */
function a2bBase64(data: Uint8Array): Uint8Array {
  const out: number[] = [];
  let quad = 0;
  let left = 0;
  let pads = 0;
  let dataChars = 0;
  for (const ch of data) {
    if (ch === 0x3d) {
      if (quad >= 2 && quad + ++pads >= 4) return Uint8Array.from(out);
      continue;
    }
    const v = B64_VAL[ch]!;
    if (v < 0) continue;
    dataChars++;
    pads = 0;
    switch (quad) {
      case 0:
        quad = 1;
        left = v;
        break;
      case 1:
        quad = 2;
        out.push(((left << 2) | (v >> 4)) & 0xff);
        left = v & 0x0f;
        break;
      case 2:
        quad = 3;
        out.push(((left << 4) | (v >> 2)) & 0xff);
        left = v & 0x03;
        break;
      default:
        quad = 0;
        out.push(((left << 6) | v) & 0xff);
        left = 0;
    }
  }
  if (quad === 1) {
    throw binasciiError(
      `Invalid base64-encoded string: number of data characters (${dataChars}) cannot be 1 more than a multiple of 4`,
    );
  }
  if (quad !== 0) throw binasciiError("Incorrect padding");
  return Uint8Array.from(out);
}

/** Python `base64.b64decode(text, validate=True)`. */
export function b64decodeStrict(text: unknown): Uint8Array {
  if (typeof text !== "string") {
    throw new PyError("TypeError", "argument should be a bytes-like object or ASCII string");
  }
  const raw = asciiBytes(text);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw binasciiError("Non-base64 digit found");
  return a2bBase64(raw);
}

/** Python `base64.urlsafe_b64decode(text + padding)` as used for keys and signatures. */
export function b64uDecode(text: string): Uint8Array {
  const padded = text + "=".repeat((4 - (text.length % 4)) % 4);
  const raw = asciiBytes(padded);
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] === 0x2d) raw[i] = 0x2b;
    else if (raw[i] === 0x5f) raw[i] = 0x2f;
  }
  return a2bBase64(raw);
}

export function b64encode(b: Uint8Array): string {
  let s = "";
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
    s += B64[n >> 18]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + B64[n & 63]!;
  }
  if (i < b.length) {
    const n = (b[i]! << 16) | ((b[i + 1] ?? 0) << 8);
    s += B64[n >> 18]! + B64[(n >> 12) & 63]!;
    s += i + 1 < b.length ? B64[(n >> 6) & 63]! + "=" : "==";
  }
  return s;
}

/** base64url without padding. */
export function b64uEncode(b: Uint8Array): string {
  return b64encode(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
