/**
 * Public keys (SubjectPublicKeyInfo), signature verification and X.509 certificates, in pure
 * JavaScript. Covers the algorithms Sigstore uses: ECDSA P-256/P-384/P-521, Ed25519 and RSA
 * PKCS#1 v1.5.
 */

import { p256, p384, p521 } from "@noble/curves/nist.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { bytesEqual, concatBytes } from "./bytes.js";
import { ed25519Verify } from "./crypto.js";
import {
  DerError,
  OID,
  Reader,
  TAG,
  ctx,
  parseOne,
  readBitFlags,
  readBitStringBytes,
  readBoolean,
  readInteger,
  readOid,
  readTime,
  type Tlv,
} from "./der.js";

export type HashName = "sha256" | "sha384" | "sha512";

export const HASHES: Record<HashName, (data: Uint8Array) => Uint8Array> = {
  sha256: (d) => sha256(d),
  sha384: (d) => sha384(d),
  sha512: (d) => sha512(d),
};

export function hashFromOid(oid: string): HashName | undefined {
  if (oid === OID.sha256) return "sha256";
  if (oid === OID.sha384) return "sha384";
  if (oid === OID.sha512) return "sha512";
  return undefined;
}

export type PublicKey =
  | { kind: "ec"; curve: "p256" | "p384" | "p521"; point: Uint8Array }
  | { kind: "ed25519"; raw: Uint8Array }
  | { kind: "rsa"; n: bigint; e: bigint }
  /** A key type recognised but not supported for verification here. */
  | { kind: "other"; name: string };

/** Thrown for a well-formed key of an algorithm or curve that is not known at all. */
export class UnsupportedAlgorithm extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsupportedAlgorithm";
  }
}

const CURVES = { p256, p384, p521 } as const;

/** Parse a DER SubjectPublicKeyInfo. Throws DerError on bad DER, UnsupportedAlgorithm on unknown types. */
export function parseSpki(der: Uint8Array): PublicKey {
  const r = new Reader(parseOne(der), TAG.SEQUENCE);
  const alg = new Reader(r.next(TAG.SEQUENCE));
  const oid = readOid(alg.next());
  const keyBits = readBitStringBytes(r.next(TAG.BIT_STRING));
  r.end();
  if (oid === OID.ecPublicKey) {
    const params = alg.next();
    alg.end();
    if (params.tag !== TAG.OID) throw new UnsupportedAlgorithm("explicit EC parameters are not supported");
    const curveOid = readOid(params);
    const curve = curveOid === OID.p256 ? "p256" : curveOid === OID.p384 ? "p384" : curveOid === OID.p521 ? "p521" : null;
    if (curve === null) {
      // Curves the reference (OpenSSL) knows but this implementation does not.
      return { kind: "other", name: `EC curve ${curveOid}` };
    }
    try {
      CURVES[curve].Point.fromBytes(keyBits).assertValidity();
    } catch {
      throw new DerError("invalid EC point");
    }
    return { kind: "ec", curve, point: keyBits };
  }
  if (oid === OID.ed25519) {
    if (!alg.done()) throw new DerError("unexpected Ed25519 parameters");
    if (keyBits.length !== 32) throw new DerError("bad Ed25519 key length");
    return { kind: "ed25519", raw: keyBits };
  }
  if (oid === OID.rsaEncryption) {
    const rk = new Reader(parseOne(keyBits), TAG.SEQUENCE);
    const n = readInteger(rk.next());
    const e = readInteger(rk.next());
    rk.end();
    if (n <= 0n || e <= 0n) throw new DerError("bad RSA key");
    return { kind: "rsa", n, e };
  }
  const known: Record<string, string> = {
    [OID.ed448]: "Ed448",
    [OID.x25519]: "X25519",
    [OID.x448]: "X448",
    [OID.dsa]: "DSA",
    [OID.rsaPss]: "RSA-PSS",
  };
  if (known[oid]) return { kind: "other", name: known[oid] };
  throw new UnsupportedAlgorithm(`unsupported public key algorithm ${oid}`);
}

/** ECDSA over `digest` (already hashed), DER signature, high-S accepted (as OpenSSL does). */
export function ecdsaVerifyDigest(key: PublicKey & { kind: "ec" }, digest: Uint8Array, sigDer: Uint8Array): boolean {
  try {
    return CURVES[key.curve].verify(sigDer, digest, key.point, { prehash: false, lowS: false, format: "der" });
  } catch {
    return false;
  }
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

const DIGEST_INFO_PREFIX: Record<HashName, string> = {
  sha256: "3031300d060960864801650304020105000420",
  sha384: "3041300d060960864801650304020205000430",
  sha512: "3051300d060960864801650304020305000440",
};

function hexBytes(h: string): Uint8Array {
  return Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
}

/** RSASSA-PKCS1-v1_5 verification over a digest. */
export function rsaPkcs1Verify(key: PublicKey & { kind: "rsa" }, hash: HashName, digest: Uint8Array, sig: Uint8Array): boolean {
  const k = Math.ceil(key.n.toString(16).length / 2);
  if (sig.length !== k || k < 64) return false;
  let s = 0n;
  for (const b of sig) s = (s << 8n) | BigInt(b);
  if (s >= key.n) return false;
  let m = modPow(s, key.e, key.n);
  const em = new Uint8Array(k);
  for (let i = k - 1; i >= 0; i--) {
    em[i] = Number(m & 0xffn);
    m >>= 8n;
  }
  const t = concatBytes(hexBytes(DIGEST_INFO_PREFIX[hash]), digest);
  if (k < t.length + 11) return false;
  const expected = new Uint8Array(k);
  expected[0] = 0;
  expected[1] = 1;
  expected.fill(0xff, 2, k - t.length - 1);
  expected[k - t.length - 1] = 0;
  expected.set(t, k - t.length);
  return bytesEqual(em, expected);
}

/** Verify `sig` over `data` with an X.509 signature algorithm OID. */
export function verifyWithAlgorithm(key: PublicKey, algOid: string, data: Uint8Array, sig: Uint8Array): boolean {
  const ecdsa: Record<string, HashName> = {
    [OID.ecdsaSha256]: "sha256",
    [OID.ecdsaSha384]: "sha384",
    [OID.ecdsaSha512]: "sha512",
  };
  const rsa: Record<string, HashName> = {
    [OID.sha256Rsa]: "sha256",
    [OID.sha384Rsa]: "sha384",
    [OID.sha512Rsa]: "sha512",
  };
  const eh = ecdsa[algOid];
  if (eh) return key.kind === "ec" && ecdsaVerifyDigest(key, HASHES[eh](data), sig);
  const rh = rsa[algOid];
  if (rh) return key.kind === "rsa" && rsaPkcs1Verify(key, rh, HASHES[rh](data), sig);
  if (algOid === OID.ed25519) return key.kind === "ed25519" && ed25519Verify(sig, data, key.raw);
  return false;
}

export interface Certificate {
  raw: Uint8Array;
  tbs: Uint8Array;
  serial: bigint;
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: bigint;
  notAfter: bigint;
  spki: Uint8Array;
  signatureAlgorithm: string;
  signature: Uint8Array;
  /** Extensions by OID: [critical, value]. */
  extensions: Map<string, { critical: boolean; value: Uint8Array }>;
}

function algorithmOid(t: Tlv): string {
  const r = new Reader(t, TAG.SEQUENCE);
  const oid = readOid(r.next());
  if (!r.done()) {
    const p = r.next();
    if (p.tag !== TAG.NULL && oid !== OID.rsaPss) throw new DerError("unexpected algorithm parameters");
    r.end();
  }
  return oid;
}

export function parseCertificate(der: Uint8Array): Certificate {
  const top = parseOne(der, TAG.SEQUENCE);
  const r = new Reader(top);
  const tbsTlv = r.next(TAG.SEQUENCE);
  const sigAlg = algorithmOid(r.next(TAG.SEQUENCE));
  const signature = readBitStringBytes(r.next(TAG.BIT_STRING));
  r.end();
  const t = new Reader(tbsTlv);
  const ver = t.optional(ctx(0, true));
  if (ver) {
    const v = readInteger(new Reader(ver).next());
    if (v !== 2n && v !== 1n) throw new DerError("unsupported certificate version");
  }
  const serial = readInteger(t.next(TAG.INTEGER));
  const innerAlg = algorithmOid(t.next(TAG.SEQUENCE));
  if (innerAlg !== sigAlg) throw new DerError("signature algorithm mismatch");
  const issuer = t.next(TAG.SEQUENCE).raw;
  const validity = new Reader(t.next(TAG.SEQUENCE));
  const notBefore = readTime(validity.next());
  const notAfter = readTime(validity.next());
  validity.end();
  const subject = t.next(TAG.SEQUENCE).raw;
  const spki = t.next(TAG.SEQUENCE).raw;
  t.optional(ctx(1, false));
  t.optional(ctx(2, false));
  const extensions = new Map<string, { critical: boolean; value: Uint8Array }>();
  const extWrap = t.optional(ctx(3, true));
  t.end();
  if (extWrap) {
    const list = new Reader(new Reader(extWrap).next(TAG.SEQUENCE));
    while (!list.done()) {
      const e = new Reader(list.next(TAG.SEQUENCE));
      const oid = readOid(e.next());
      const crit = e.peekTag() === TAG.BOOLEAN ? readBoolean(e.next()) : false;
      const value = e.next(TAG.OCTET_STRING).value;
      e.end();
      if (extensions.has(oid)) throw new DerError("duplicate extension");
      extensions.set(oid, { critical: crit, value });
    }
  }
  return {
    raw: der,
    tbs: tbsTlv.raw,
    serial,
    issuer,
    subject,
    notBefore,
    notAfter,
    spki,
    signatureAlgorithm: sigAlg,
    signature,
    extensions,
  };
}

/** Extended key usage OIDs, or undefined when the extension is absent. */
export function extKeyUsage(cert: Certificate): { critical: boolean; oids: string[] } | undefined {
  const ext = cert.extensions.get(OID.extKeyUsage);
  if (!ext) return undefined;
  const r = new Reader(parseOne(ext.value), TAG.SEQUENCE);
  const oids: string[] = [];
  while (!r.done()) oids.push(readOid(r.next()));
  return { critical: ext.critical, oids };
}

export function isCa(cert: Certificate): boolean {
  const ext = cert.extensions.get(OID.basicConstraints);
  if (!ext) return false;
  const r = new Reader(parseOne(ext.value), TAG.SEQUENCE);
  return r.peekTag() === TAG.BOOLEAN ? readBoolean(r.next()) : false;
}

export function canSignCertificates(cert: Certificate): boolean {
  const ext = cert.extensions.get(OID.keyUsage);
  if (!ext) return true;
  return readBitFlags(parseOne(ext.value)).has(5);
}

/** Verify that `cert` is signed by `issuer` (names and signature). */
export function issuedBy(cert: Certificate, issuer: Certificate): boolean {
  if (!bytesEqual(cert.issuer, issuer.subject)) return false;
  return verifyWithAlgorithm(parseSpki(issuer.spki), cert.signatureAlgorithm, cert.tbs, cert.signature);
}
