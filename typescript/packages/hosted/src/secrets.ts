/**
 * Secrets of the hosted checker, all derived from MASTER_KEY (an environment secret, never stored):
 * - each tenant's Ed25519 checker seed, stored only encrypted (AES-256-GCM, bound to the tenant id);
 * - API keys, stored only as an HMAC-SHA256 under a key derived from MASTER_KEY, compared in constant time.
 */

import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

export const MIN_SECRET = 32;
const TENANT_RE = /^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/;

export function tenantIdOk(id: unknown): id is string {
  return typeof id === "string" && TENANT_RE.test(id) && !id.includes("--");
}

export class Secrets {
  private readonly encKey: Buffer;
  private readonly macKey: Buffer;

  constructor(master: string) {
    if (master.length < MIN_SECRET) throw new Error(`MASTER_KEY must be at least ${MIN_SECRET} characters`);
    const derive = (info: string) =>
      Buffer.from(hkdfSync("sha256", Buffer.from(master, "utf8"), "gleipnir-hosted-checker", info, 32));
    this.encKey = derive("tenant-seed-encryption/v1");
    this.macKey = derive("api-key-hash/v1");
  }

  sealSeed(seed: Uint8Array, tenant: string): string {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.encKey, iv);
    c.setAAD(Buffer.from(`tenant:${tenant}`, "utf8"));
    const ct = Buffer.concat([c.update(seed), c.final(), c.getAuthTag()]);
    return `v1.${iv.toString("base64url")}.${ct.toString("base64url")}`;
  }

  /** Throws if the blob was not sealed for this tenant under this MASTER_KEY. */
  openSeed(sealed: string, tenant: string): Uint8Array {
    const [v, ivText, ctText] = sealed.split(".");
    if (v !== "v1" || !ivText || !ctText) throw new Error("unknown seed format");
    const iv = Buffer.from(ivText, "base64url"), all = Buffer.from(ctText, "base64url");
    if (iv.length !== 12 || all.length !== 32 + 16) throw new Error("bad sealed seed");
    const d = createDecipheriv("aes-256-gcm", this.encKey, iv);
    d.setAAD(Buffer.from(`tenant:${tenant}`, "utf8"));
    d.setAuthTag(all.subarray(32));
    return new Uint8Array(Buffer.concat([d.update(all.subarray(0, 32)), d.final()]));
  }

  /** A new API key for a tenant: gks_<tenant>_<256 random bits>. Returned once; only its hash is stored. */
  newApiKey(tenant: string): { key: string; hash: string } {
    const key = `gks_${tenant}_${randomBytes(32).toString("base64url")}`;
    return { key, hash: this.hashKey(key) };
  }

  hashKey(key: string): string {
    return createHmac("sha256", this.macKey).update(key, "utf8").digest("hex");
  }

  /** Constant time in the key (both sides are fixed-length MACs). */
  keyMatches(key: string, storedHash: string): boolean {
    const a = Buffer.from(this.hashKey(key), "hex"), b = Buffer.from(storedHash, "hex");
    return a.length === b.length && timingSafeEqual(a, b);
  }

  /** Constant-time comparison of two secrets of any length. */
  same(given: string, expected: string): boolean {
    const a = createHmac("sha256", this.macKey).update(given, "utf8").digest();
    const b = createHmac("sha256", this.macKey).update(expected, "utf8").digest();
    return timingSafeEqual(a, b);
  }
}

/** The tenant an API key claims to belong to (not yet verified), or null if it is not one of ours. */
export function tenantOfKey(key: string): string | null {
  const m = /^gks_([a-z0-9-]+)_([A-Za-z0-9_-]{43})$/.exec(key);
  return m && tenantIdOk(m[1]) ? m[1]! : null;
}
