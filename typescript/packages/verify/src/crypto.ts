/**
 * Record signing keys and signatures. Pure JavaScript (noble), so it runs in browsers too.
 *
 * Two key types, as in the reference (python/gleipnir-verify/src/gleipnir_verify/crypto.py):
 *
 * - `ed25519` (default): public key `"ed25519:" + b64url(raw 32 bytes)`, signature
 *   `"ed25519:" + b64url(64 bytes)`, key id `k_ed25519_<16 hex of SHA-256(raw)>`.
 * - `ecdsa-p256` (KMS/HSM setups without Ed25519): public key `"ecdsa-p256:" + b64url(DER SPKI)`,
 *   signature `"ecdsa-p256:" + b64url(DER ECDSA-SHA256 signature)`, key id
 *   `k_p256_<16 hex of SHA-256(DER SPKI)>`.
 *
 * The signed message is `"gleipnir/record/v1\n" + record_hash` for both.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { b64uDecode, b64uEncode, bytesEqual, bytesToHex, concatBytes, hexToBytes, utf8 } from "./bytes.js";
import { DerError, OID, Reader, TAG, parseOne, readBitStringBytes, readInteger, readOid, type Tlv } from "./der.js";
import { PyError } from "./py.js";

export const RECORD_DOMAIN = "gleipnir/record/v1\n";
export const PUBKEY_PREFIX = "ed25519:";
export const SIG_PREFIX = "ed25519:";
export const P256_PREFIX = "ecdsa-p256:";

/** A decoded ECDSA P-256 record key. */
export interface P256PublicKey {
  readonly kind: "ecdsa-p256";
  /** The DER SubjectPublicKeyInfo exactly as published (the key id hashes these bytes). */
  readonly spki: Uint8Array;
  /** The uncompressed SEC1 point. */
  readonly point: Uint8Array;
}

/** A decoded record key: raw Ed25519 bytes, or a P-256 key. */
export type RecordPublicKey = Uint8Array | P256PublicKey;

/** The exact bytes a record signature covers. */
export function recordMessage(recordHash: string): Uint8Array {
  return utf8(RECORD_DOMAIN + recordHash);
}

export function encodePublicKey(raw: Uint8Array): string {
  return PUBKEY_PREFIX + b64uEncode(raw);
}

export function encodeP256PublicKey(spkiDer: Uint8Array): string {
  return P256_PREFIX + b64uEncode(spkiDer);
}

/** DER SubjectPublicKeyInfo (named curve P-256, uncompressed point) for a SEC1 point. */
export function p256Spki(point: Uint8Array): Uint8Array {
  const uncompressed = p256.Point.fromBytes(point).toBytes(false);
  return concatBytes(SPKI_P256_PREFIX, uncompressed);
}

const SPKI_P256_PREFIX = hexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200");

// Explicit EC parameters that OpenSSL maps back to P-256 (with and without the curve seed).
const P256_FIELD = "06072a8648ce3d01010221" + "00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const P256_A = "0420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
const P256_B = "04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
const P256_SEED = "031500c49d360886e704936a6678e1139d26b7819f7e90";
const P256_G =
  "044104" +
  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const P256_N = "022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
function explicitParams(withSeed: boolean): string {
  const curve = P256_A + P256_B + (withSeed ? P256_SEED : "");
  const body =
    "020101" +
    "302c" + P256_FIELD +
    "30" + (curve.length / 2).toString(16).padStart(2, "0") + curve +
    P256_G + P256_N + "020101";
  return "3081" + (body.length / 2).toString(16).padStart(2, "0") + body;
}
const P256_EXPLICIT = new Set([explicitParams(true), explicitParams(false)]);

/** Curves `cryptography` knows (a key on one of them is "not P-256", a ValueError). */
const KNOWN_CURVES = new Set([
  "1.2.840.10045.3.1.1", "1.2.840.10045.3.1.7", "1.3.132.0.10", "1.3.132.0.33", "1.3.132.0.34", "1.3.132.0.35",
  "1.3.36.3.3.2.8.1.1.7", "1.3.36.3.3.2.8.1.1.11", "1.3.36.3.3.2.8.1.1.13",
]);
/** Key algorithms `cryptography` knows (anything else is UnsupportedAlgorithm). */
const KNOWN_ALGORITHMS = new Set<string>([
  OID.rsaEncryption, OID.rsaPss, OID.dsa, OID.ed25519, OID.ed448, OID.x25519, OID.x448,
  "1.2.840.113549.1.3.1", "1.2.840.10046.2.1",
]);

const NOT_DESERIALIZABLE =
  "Could not deserialize key data. The data may be in an incorrect format, it may be encrypted with an unsupported " +
  "algorithm, or it may be an unsupported key type (e.g. EC curves with explicit parameters).";

/** Looks like ECParameters (SEQUENCE {version, fieldID, curve, base, order[, cofactor]}). */
function isEcParametersShape(t: Tlv): boolean {
  try {
    const r = new Reader(t, TAG.SEQUENCE);
    readInteger(r.next(TAG.INTEGER));
    r.next(TAG.SEQUENCE);
    r.next(TAG.SEQUENCE);
    r.next(TAG.OCTET_STRING);
    readInteger(r.next(TAG.INTEGER));
    if (!r.done()) readInteger(r.next(TAG.INTEGER));
    r.end();
    return true;
  } catch {
    return false;
  }
}

/** A SEC1 point on P-256 as an uncompressed point; ValueError("Invalid key") otherwise. */
function p256Point(bits: Uint8Array): Uint8Array {
  let enc = bits;
  // OpenSSL also accepts the "hybrid" form (0x06/0x07 + x + y) when the parity bit matches y.
  if (enc.length === 65 && (enc[0] === 0x06 || enc[0] === 0x07)) {
    if ((enc[64]! & 1) !== (enc[0]! & 1)) throw new PyError("ValueError", "Invalid key");
    enc = concatBytes(Uint8Array.of(0x04), enc.subarray(1));
  }
  if (enc.length === 1 && enc[0] === 0) {
    throw new PyError("ValueError", "Cannot load an EC public key where the point is at infinity");
  }
  try {
    const pt = p256.Point.fromBytes(enc);
    pt.assertValidity();
    return pt.toBytes(false);
  } catch {
    throw new PyError("ValueError", "Invalid key");
  }
}

/**
 * Decode a DER SPKI as the reference does (`serialization.load_der_public_key`, then "is it an
 * EC key on secp256r1"). Errors carry the same Python exception names: ValueError for bad DER,
 * invalid points and keys of other types or curves; UnsupportedAlgorithm for algorithms and
 * curves OpenSSL does not know.
 */
function decodeP256Spki(der: Uint8Array): P256PublicKey {
  let alg: Reader;
  let bits: Tlv;
  let oid: string;
  try {
    const r = new Reader(parseOne(der), TAG.SEQUENCE);
    alg = new Reader(r.next(TAG.SEQUENCE));
    oid = readOid(alg.next());
    bits = r.next(TAG.BIT_STRING);
    r.end();
  } catch (exc) {
    if (exc instanceof DerError) throw new PyError("ValueError", `${NOT_DESERIALIZABLE} Details: ASN.1 parsing error: ${exc.message}`);
    throw exc;
  }
  const bad = () => new PyError("ValueError", NOT_DESERIALIZABLE);
  if (oid !== OID.ecPublicKey) {
    if (KNOWN_ALGORITHMS.has(oid)) throw new PyError("ValueError", "not an ECDSA P-256 public key");
    throw new PyError("UnsupportedAlgorithm", `Unknown key type: ${oid}`);
  }
  if (alg.done()) throw bad();
  const params = alg.next();
  if (!alg.done()) throw bad();
  const keyBits = (): Uint8Array => {
    try {
      return readBitStringBytes(bits);
    } catch {
      throw new PyError("ValueError", "Invalid key");
    }
  };
  if (params.tag === TAG.OID) {
    let curve: string;
    try {
      curve = readOid(params);
    } catch {
      throw bad();
    }
    if (!KNOWN_CURVES.has(curve)) throw new PyError("UnsupportedAlgorithm", `Curve ${curve} is not supported`);
    // Another known curve: OpenSSL either rejects the point or loads a non-P-256 key; both are ValueErrors.
    if (curve !== OID.p256) throw new PyError("ValueError", "not an ECDSA P-256 public key");
    return { kind: "ecdsa-p256", spki: Uint8Array.from(der), point: p256Point(keyBits()) };
  }
  if (params.tag === TAG.NULL || (params.tag === TAG.SEQUENCE && isEcParametersShape(params))) {
    if (params.tag === TAG.SEQUENCE && P256_EXPLICIT.has(bytesToHex(params.raw))) {
      return { kind: "ecdsa-p256", spki: Uint8Array.from(der), point: p256Point(keyBits()) };
    }
    throw new PyError(
      "UnsupportedAlgorithm",
      "ECDSA keys with explicit parameters are only supported when they map to secp256r1, secp384r1, or secp521r1. No custom curves are supported.",
    );
  }
  throw bad();
}

/** Decode a record public key ("ed25519:..." or "ecdsa-p256:..."). Throws PyError like the reference. */
export function decodePublicKey(text: unknown): RecordPublicKey {
  if (typeof text !== "string") throw new PyError("ValueError", "public key must be a string");
  if (text.startsWith(PUBKEY_PREFIX)) {
    const raw = b64uDecode(text.slice(PUBKEY_PREFIX.length));
    if (raw.length !== 32) throw new PyError("ValueError", "bad ed25519 public key length");
    return raw;
  }
  if (text.startsWith(P256_PREFIX)) return decodeP256Spki(b64uDecode(text.slice(P256_PREFIX.length)));
  throw new PyError("ValueError", "unsupported public key type");
}

/** Short, stable identifier of a public key (also its fingerprint). */
export function keyId(publicKey: RecordPublicKey): string {
  if (publicKey instanceof Uint8Array) return "k_ed25519_" + bytesToHex(sha256(publicKey)).slice(0, 16);
  return "k_p256_" + bytesToHex(sha256(publicKey.spki)).slice(0, 16);
}

export function encodeSignature(sig: Uint8Array): string {
  return SIG_PREFIX + b64uEncode(sig);
}

export function encodeP256Signature(derSig: Uint8Array): string {
  return P256_PREFIX + b64uEncode(derSig);
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

const P256_ORDER = p256.Point.Fn.ORDER;

function to32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/**
 * ECDSA P-256 / SHA-256 verification with OpenSSL's rules: the signature must be strict DER
 * (SEQUENCE of two minimal, positive INTEGERs, nothing trailing), 0 < r, s < n; high S is
 * accepted.
 */
export function p256Verify(derSig: Uint8Array, message: Uint8Array, point: Uint8Array): boolean {
  let r: bigint;
  let s: bigint;
  try {
    const rd = new Reader(parseOne(derSig), TAG.SEQUENCE);
    r = readInteger(rd.next(TAG.INTEGER));
    s = readInteger(rd.next(TAG.INTEGER));
    rd.end();
  } catch {
    return false;
  }
  if (r <= 0n || s <= 0n || r >= P256_ORDER || s >= P256_ORDER) return false;
  try {
    return p256.verify(concatBytes(to32(r), to32(s)), sha256(message), point, { prehash: false, lowS: false, format: "compact" });
  } catch {
    return false;
  }
}

/** Verify a record signature ("ed25519:..." or "ecdsa-p256:...") with a decoded key of the matching type. */
export function verifySignature(publicKey: RecordPublicKey, message: Uint8Array, sigText: unknown): boolean {
  if (typeof sigText !== "string") return false;
  const prefix = publicKey instanceof Uint8Array ? SIG_PREFIX : P256_PREFIX;
  if (!sigText.startsWith(prefix)) return false;
  let sig: Uint8Array;
  try {
    sig = b64uDecode(sigText.slice(prefix.length));
  } catch {
    return false;
  }
  return publicKey instanceof Uint8Array ? ed25519Verify(sig, message, publicKey) : p256Verify(sig, message, publicKey.point);
}

export function ed25519PublicFromSeed(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}

export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, seed);
}

/** The DER SPKI of the P-256 public key for a 32-byte private scalar. */
export function p256SpkiFromScalar(scalar: Uint8Array): Uint8Array {
  return p256Spki(p256.getPublicKey(scalar, false));
}

/**
 * Deterministic (RFC 6979) ECDSA P-256 / SHA-256 signature, DER encoded. S is not normalized,
 * so signatures are byte-identical to OpenSSL's deterministic signatures (the spec test vector).
 */
export function p256Sign(scalar: Uint8Array, message: Uint8Array): Uint8Array {
  return p256.sign(message, scalar, { format: "der", lowS: false });
}
