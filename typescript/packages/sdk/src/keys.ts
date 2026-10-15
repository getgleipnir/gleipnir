/**
 * Signing keys.
 *
 * Records are signed with Ed25519 by default, or with ECDSA P-256 for KMS/HSM setups without
 * Ed25519 (Azure Key Vault, Cloud KMS HSM keys); verifiers accept both, and a chain may rotate
 * between them. The default signer keeps an Ed25519 private key in a local file (PKCS#8 PEM, the
 * same file the Python SDK writes, so both SDKs can share a home directory), which is fine for
 * development and pilots. Production deployments should inject a signer backed by a KMS or HSM:
 * implement the `Signer` interface, or wrap the KMS with {@link SpkiSigner}.
 */

import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { createPrivateKey, generateKeyPairSync, randomBytes, type JsonWebKey } from "node:crypto";
import {
  b64encode,
  b64uEncode,
  decodePublicKey,
  ed25519PublicFromSeed,
  ed25519Sign,
  encodeP256PublicKey,
  encodeP256Signature,
  encodePublicKey,
  encodeSignature,
  keyId,
  p256Sign,
  p256SpkiFromScalar,
  recordMessage,
  verifySignature,
} from "@getgleipnir/verify";

/**
 * Signs records. `sign` must be synchronous (records are written synchronously); a KMS client
 * with only an async API needs a synchronous bridge or a local signing service.
 */
export interface Signer {
  readonly keyId: string;
  /** "ed25519:" + base64url-nopad(raw public key), or "ecdsa-p256:" + base64url-nopad(DER SPKI). */
  readonly publicKey: string;
  /**
   * Sign the exact message bytes; returns "ed25519:" + base64url-nopad(64-byte signature), or
   * "ecdsa-p256:" + base64url-nopad(DER ECDSA-SHA256 signature) for a P-256 key.
   */
  sign(message: Uint8Array): string;
}

const PKCS8_ED25519_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

export class Ed25519Signer implements Signer {
  readonly keyId: string;
  readonly publicKey: string;
  readonly #seed: Uint8Array;

  constructor(seed: Uint8Array) {
    if (seed.length !== 32) throw new RangeError("Ed25519 seed must be 32 bytes");
    this.#seed = Uint8Array.from(seed);
    const raw = ed25519PublicFromSeed(this.#seed);
    this.keyId = keyId(raw);
    this.publicKey = encodePublicKey(raw);
  }

  static generate(): Ed25519Signer {
    return new Ed25519Signer(randomBytes(32));
  }

  /** Load from a PKCS#8 PEM (as written by this SDK, the Python SDK or `openssl genpkey -algorithm ed25519`). */
  static fromPem(pem: string): Ed25519Signer {
    const body = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
    const der = Uint8Array.from(Buffer.from(body, "base64"));
    if (der.length !== 48 || !PKCS8_ED25519_PREFIX.every((b, i) => der[i] === b)) {
      throw new Error("not an unencrypted PKCS#8 Ed25519 private key");
    }
    return new Ed25519Signer(der.subarray(16));
  }

  sign(message: Uint8Array): string {
    return encodeSignature(ed25519Sign(this.#seed, message));
  }

  privatePem(): string {
    const der = new Uint8Array(48);
    der.set(PKCS8_ED25519_PREFIX);
    der.set(this.#seed, 16);
    const b64 = b64encode(der);
    return `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
  }
}

const b64u = (b: Uint8Array) => b64uEncode(b);
const fromB64u = (s: string) => Uint8Array.from(Buffer.from(s, "base64url"));

/**
 * Local ECDSA P-256 signer (tests, or a key exported from an HSM-less setup). Signatures are
 * deterministic (RFC 6979), DER encoded.
 */
export class EcdsaP256Signer implements Signer {
  readonly alg = "ecdsa-p256";
  readonly keyId: string;
  readonly publicKey: string;
  readonly spki: Uint8Array;
  readonly #scalar: Uint8Array;

  /** `scalar`: the 32-byte private key (big-endian). */
  constructor(scalar: Uint8Array) {
    if (scalar.length !== 32) throw new RangeError("P-256 private key must be 32 bytes");
    this.#scalar = Uint8Array.from(scalar);
    this.spki = p256SpkiFromScalar(this.#scalar);
    this.publicKey = encodeP256PublicKey(this.spki);
    this.keyId = keyId(decodePublicKey(this.publicKey));
  }

  static generate(): EcdsaP256Signer {
    const jwk = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }) as JsonWebKey;
    return new EcdsaP256Signer(fromB64u(jwk.d!).subarray(-32));
  }

  /** Load from a PEM (PKCS#8 "PRIVATE KEY" or SEC1 "EC PRIVATE KEY") holding a P-256 key. */
  static fromPem(pem: string): EcdsaP256Signer {
    const jwk = createPrivateKey(pem).export({ format: "jwk" }) as JsonWebKey;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d) throw new Error("not an ECDSA P-256 private key");
    return new EcdsaP256Signer(fromB64u(jwk.d).subarray(-32));
  }

  sign(message: Uint8Array): string {
    return encodeP256Signature(p256Sign(this.#scalar, message));
  }

  /** Unencrypted PKCS#8 PEM. */
  privatePem(): string {
    const spki = this.spki;
    const point = spki.subarray(spki.length - 64);
    const jwk: JsonWebKey = { kty: "EC", crv: "P-256", d: b64u(this.#scalar), x: b64u(point.subarray(0, 32)), y: b64u(point.subarray(32)) };
    return createPrivateKey({ key: jwk, format: "jwk" }).export({ format: "pem", type: "pkcs8" }) as string;
  }
}

const ED25519_SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

export interface SpkiSignerOptions {
  /** The key's public key as DER SubjectPublicKeyInfo (what KMS/HSM APIs return). */
  spki: Uint8Array;
  /**
   * Sign the exact message bytes with the external key: Ed25519 over the message, or ECDSA
   * P-256 with SHA-256 over the message (for a KMS that signs digests, pass SHA-256(message)
   * through). Returns the signature bytes.
   */
  signMessage: (message: Uint8Array) => Uint8Array;
  /**
   * Encoding of a P-256 signature returned by `signMessage`: "der" (AWS KMS, Google Cloud KMS)
   * or "raw" r||s (Azure Key Vault, PKCS#11). Default "der".
   */
  signatureFormat?: "der" | "raw";
  /** Check every signature locally before it is used (default true; costs ~1 ms per record). */
  verify?: boolean;
}

/**
 * A signer around an external key (KMS, HSM, remote signing service) of either type: the key
 * type is taken from its SubjectPublicKeyInfo. Mirrors the Python SDK's KMS signers.
 */
export class SpkiSigner implements Signer {
  readonly alg: "ed25519" | "ecdsa-p256";
  readonly keyId: string;
  readonly publicKey: string;
  readonly #sign: (message: Uint8Array) => Uint8Array;
  readonly #raw: boolean;
  readonly #verify: boolean;

  constructor(opts: SpkiSignerOptions) {
    const spki = Uint8Array.from(opts.spki);
    const isEd = spki.length === 44 && ED25519_SPKI_PREFIX.every((b, i) => spki[i] === b);
    if (isEd) {
      this.alg = "ed25519";
      this.publicKey = encodePublicKey(spki.subarray(12));
    } else {
      this.alg = "ecdsa-p256";
      this.publicKey = encodeP256PublicKey(spki);
      try {
        decodePublicKey(this.publicKey);
      } catch {
        throw new Error("external key must be Ed25519 or ECDSA P-256");
      }
    }
    this.keyId = keyId(decodePublicKey(this.publicKey));
    this.#sign = opts.signMessage;
    this.#raw = (opts.signatureFormat ?? "der") === "raw";
    this.#verify = opts.verify ?? true;
  }

  sign(message: Uint8Array): string {
    let sig = this.#sign(message);
    if (this.alg === "ecdsa-p256" && this.#raw) sig = rawToDer(sig);
    const text = this.alg === "ed25519" ? encodeSignature(sig) : encodeP256Signature(sig);
    if (this.#verify && !verifySignature(decodePublicKey(this.publicKey), message, text)) {
      throw new Error(`external signer returned a signature that does not verify with ${this.keyId}`);
    }
    return text;
  }
}

/** Raw r||s (64 bytes) to a DER ECDSA signature. */
function rawToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) throw new Error("raw P-256 signature must be 64 bytes (r || s)");
  const int = (b: Uint8Array): number[] => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = [...b.subarray(i)];
    if (v[0]! & 0x80) v.unshift(0);
    return [0x02, v.length, ...v];
  };
  const body = [...int(raw.subarray(0, 32)), ...int(raw.subarray(32))];
  return Uint8Array.from([0x30, body.length, ...body]);
}

/** Check a signer once: it signs, and the signature verifies with its own public key and key id. */
export function checkSigner(signer: Signer): void {
  const pub = decodePublicKey(signer.publicKey);
  if (keyId(pub) !== signer.keyId) throw new Error(`signer key id ${signer.keyId} does not match its public key`);
  const msg = recordMessage("sha256:" + "00".repeat(32));
  if (!verifySignature(pub, msg, signer.sign(msg))) throw new Error(`signer ${signer.keyId} produced an invalid signature`);
}

const DEV_KEY_WARNING =(path: string, kid: string) => `gleipnir: generated a new LOCAL signing key at ${path}
  key id: ${kid}
  This key is fine for development and pilots. Anyone who can read this file can sign
  records as you, so for production keep the key in a KMS/HSM and pass a custom Signer.
  Publish the key id where buyers can see it (for example your trust center).
`;

/** Create a file readable only by the owner; fails if it exists. */
export function writePrivateFile(path: string, data: Uint8Array | string): void {
  mkdirSync(dirname(path), { recursive: true });
  const fd = openSync(path, "wx", 0o600);
  try {
    writeSync(fd, typeof data === "string" ? Buffer.from(data, "utf8") : data);
  } finally {
    closeSync(fd);
  }
}

export function loadOrCreateSigner(home: string, quiet = false): Ed25519Signer {
  const path = join(home, "keys", "signing-ed25519.pem");
  if (existsSync(path)) return Ed25519Signer.fromPem(readFileSync(path, "utf8"));
  const signer = Ed25519Signer.generate();
  writePrivateFile(path, signer.privatePem());
  if (!quiet) process.stderr.write(DEV_KEY_WARNING(path, signer.keyId));
  return signer;
}

export function loadOrCreateSecret(home: string, name: string): Uint8Array {
  const path = join(home, "keys", name);
  if (existsSync(path)) return readFileSync(path);
  const secret = randomBytes(32);
  writePrivateFile(path, secret);
  return secret;
}
