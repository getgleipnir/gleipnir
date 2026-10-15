/** Ed25519 keys and record signatures. Pure JavaScript (noble), so it runs in browsers too. */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { b64uDecode, b64uEncode, bytesEqual, bytesToHex, concatBytes, utf8 } from "./bytes.js";
import { PyError, pyTypeName } from "./py.js";

export const RECORD_DOMAIN = "gleipnir/record/v1\n";
export const PUBKEY_PREFIX = "ed25519:";
export const SIG_PREFIX = "ed25519:";

/** The exact bytes a record signature covers. */
export function recordMessage(recordHash: string): Uint8Array {
  return utf8(RECORD_DOMAIN + recordHash);
}

export function encodePublicKey(raw: Uint8Array): string {
  return PUBKEY_PREFIX + b64uEncode(raw);
}

export function decodePublicKey(text: unknown): Uint8Array {
  if (typeof text !== "string") {
    throw new PyError("AttributeError", `'${pyTypeName(text)}' object has no attribute 'startswith'`);
  }
  if (!text.startsWith(PUBKEY_PREFIX)) throw new PyError("ValueError", "unsupported public key type");
  const raw = b64uDecode(text.slice(PUBKEY_PREFIX.length));
  if (raw.length !== 32) throw new PyError("ValueError", "bad ed25519 public key length");
  return raw;
}

/** Short, stable identifier of a public key (also its fingerprint). */
export function keyId(rawPublic: Uint8Array): string {
  return "k_ed25519_" + bytesToHex(sha256(rawPublic)).slice(0, 16);
}

export function encodeSignature(sig: Uint8Array): string {
  return SIG_PREFIX + b64uEncode(sig);
}

const Point = ed25519.Point;
const L = Point.Fn.ORDER;

function bytesToNumberLE(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n;
}

/**
 * RFC 8032 Ed25519 verification with OpenSSL's acceptance rules (the reference implementation
 * verifies through `cryptography`/OpenSSL): S must be canonical (< L), and the cofactorless
 * equation is checked by re-encoding [S]B - [k]A and comparing it byte for byte with R, so a
 * non-canonical R never verifies. Public keys are decoded strictly (canonical y).
 */
export function ed25519Verify(sig: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (sig.length !== 64 || publicKey.length !== 32) return false;
  try {
    const rBytes = sig.subarray(0, 32);
    const s = bytesToNumberLE(sig.subarray(32, 64));
    if (s >= L) return false;
    const A = Point.fromBytes(publicKey, false);
    const k = bytesToNumberLE(sha512(concatBytes(rBytes, publicKey, message))) % L;
    const sB = s === 0n ? Point.ZERO : Point.BASE.multiply(s);
    const kA = k === 0n ? Point.ZERO : A.multiplyUnsafe(k);
    return bytesEqual(sB.subtract(kA).toBytes(), rBytes);
  } catch {
    return false;
  }
}

export function verifySignature(rawPublic: Uint8Array, message: Uint8Array, sigText: unknown): boolean {
  if (typeof sigText !== "string" || !sigText.startsWith(SIG_PREFIX)) return false;
  let sig: Uint8Array;
  try {
    sig = b64uDecode(sigText.slice(SIG_PREFIX.length));
  } catch {
    return false;
  }
  return ed25519Verify(sig, message, rawPublic);
}

export function ed25519PublicFromSeed(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}

export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, seed);
}
