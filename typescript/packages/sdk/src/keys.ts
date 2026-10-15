/**
 * Signing keys.
 *
 * Records are signed with Ed25519. The default signer keeps a private key in a local file
 * (PKCS#8 PEM, the same file the Python SDK writes, so both SDKs can share a home directory),
 * which is fine for development and pilots. Production deployments should plug in a signer
 * backed by a KMS or HSM (implement the `Signer` interface).
 */

import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  b64encode,
  ed25519PublicFromSeed,
  ed25519Sign,
  encodePublicKey,
  encodeSignature,
  keyId,
} from "@getgleipnir/verify";

export interface Signer {
  readonly keyId: string;
  /** "ed25519:" + base64url-nopad(raw public key). */
  readonly publicKey: string;
  /** Sign the exact message bytes; returns "ed25519:" + base64url-nopad(signature). */
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

const DEV_KEY_WARNING = (path: string, kid: string) => `gleipnir: generated a new LOCAL signing key at ${path}
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
