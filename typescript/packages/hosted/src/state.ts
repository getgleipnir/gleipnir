/**
 * Tenant state on a KV store with conditional writes: the payment log and period ledger the Checker expects
 * (spec 7), stored revocations, and tenant records.
 *
 * Every read-modify-write is a compare-and-swap on the entry's ETag, retried a few times; if it cannot get
 * through it throws, and the Checker turns that into `checker_unavailable`. Every value written carries the
 * random op ids of its last writes (`ops`), so a write whose answer was lost (the store committed it, then a
 * retry of the same request saw 412) is recognised on the next read and never applied twice.
 */

import { createHash, randomBytes } from "node:crypto";
import { periodKey, type Ledger, type PaymentLog } from "@getgleipnir/verify/mandate";
import type { AuthorityDoc } from "./authority.js";
import type { KV } from "./kv.js";

type J = Record<string, unknown>;

const RETRIES = 8;
const KEEP_OPS = 16;

export function h(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function newOp(): string {
  return randomBytes(12).toString("base64url");
}

const isDict = (v: unknown): v is J => typeof v === "object" && v !== null && !Array.isArray(v);

function opsOf(v: J | null): string[] {
  return v !== null && Array.isArray(v.ops) ? (v.ops as unknown[]).filter((x): x is string => typeof x === "string") : [];
}

async function backoff(i: number): Promise<void> {
  await new Promise((r) => setTimeout(r, Math.random() * 10 * 2 ** Math.min(i, 5)));
}

export class ContentionError extends Error {
  constructor(what: string) {
    super(`could not update ${what}: too much contention`);
  }
}

/**
 * Compare-and-swap loop: `f(current)` returns the new value (or undefined to write nothing) and a result.
 * Returns the result of the attempt whose write went through, also when its answer was lost.
 */
export async function update<T>(kv: KV, key: string, f: (cur: J | null) => [J | undefined, T]): Promise<T> {
  const mine = new Map<string, T>();
  for (let i = 0; i < RETRIES; i++) {
    const e = await kv.get(key);
    const cur = e === null ? null : (JSON.parse(e.data) as J);
    for (const op of opsOf(cur)) if (mine.has(op)) return mine.get(op)!; // an earlier attempt of ours landed
    const [next, out] = f(cur);
    if (next === undefined) return out;
    const op = newOp();
    mine.set(op, out);
    const value = { ...next, ops: [...opsOf(cur), op].slice(-KEEP_OPS) };
    if (await kv.put(key, JSON.stringify(value), e === null ? { ifNew: true } : { ifMatch: e.etag })) return out;
    await backoff(i);
  }
  throw new ContentionError(key);
}

/** Create-only write; true if this call created it (also when the store's answer was lost). */
async function createOnce(kv: KV, key: string, value: J): Promise<boolean> {
  const op = newOp();
  if (await kv.put(key, JSON.stringify({ ...value, ops: [op] }), { ifNew: true })) return true;
  const back = await kv.get(key);
  return back !== null && opsOf(JSON.parse(back.data) as J).includes(op);
}

// ---------- payment log (idempotency, replay protection) ----------

export class KVPaymentLog implements PaymentLog {
  constructor(private readonly kv: KV, private readonly tenant: string) {}

  private k(key: string): string {
    return `t/${this.tenant}/payments/${h(key)}`;
  }

  async lookup(key: string, paymentHash: string): Promise<J | null> {
    const e = await this.kv.get(this.k(key));
    if (e === null) return null;
    const v = JSON.parse(e.data) as { hash: string; decision: J | null };
    return v.hash === paymentHash ? v.decision : null;
  }

  async register(key: string, paymentHash: string): Promise<boolean> {
    return createOnce(this.kv, this.k(key), { hash: paymentHash, decision: null });
  }

  async remember(key: string, decision: J): Promise<void> {
    await update(this.kv, this.k(key), (cur) => [cur === null ? undefined : { hash: cur.hash, decision }, undefined]);
  }

  async forget(key: string): Promise<void> {
    await this.kv.del(this.k(key));
  }

  /**
   * Hosted release: if the key holds an allow for this payment that `isIt` recognises, keep the key claimed but
   * clear the decision, recording why (`released`). The payment id stays used: a later check of any payment under
   * it finds the key claimed and is blocked `duplicate_payment`, never checked afresh. true if this call (or an
   * earlier attempt of it whose answer was lost) did it, or the key already records this release.
   */
  async holdReleased(key: string, paymentHash: string, isIt: (decision: J) => boolean, released: J): Promise<boolean> {
    return update(this.kv, this.k(key), (cur) => {
      if (!cur || cur.hash !== paymentHash) return [undefined, false];
      const d = cur.decision as J | null | undefined;
      if (d === null && isDict(cur.released) && isDict(released.decision)
        && (cur.released.decision as J | undefined)?.hash === released.decision.hash) return [undefined, true];
      if (!d || typeof d !== "object" || !isIt(d)) return [undefined, false];
      return [{ hash: cur.hash, decision: null, released }, true];
    });
  }

  async take(key: string, paymentHash: string, decisionId: string): Promise<boolean> {
    return update(this.kv, this.k(key), (cur) => {
      const d = cur?.decision as J | null | undefined;
      if (!cur || cur.hash !== paymentHash || !d || typeof d !== "object" || d.id !== decisionId) return [undefined, false];
      return [{ hash: cur.hash, decision: null }, true];
    });
  }
}

// ---------- period ledger ----------

export class KVLedger implements Ledger {
  constructor(private readonly kv: KV, private readonly tenant: string) {}

  private k(key: string, period: string, at: bigint): string {
    return `t/${this.tenant}/ledger/${h(`${key}|${periodKey(period, at)}`)}`;
  }

  async reserve(key: string, period: string, amount: bigint, limit: bigint | null, at: bigint): Promise<boolean> {
    return update(this.kv, this.k(key, period, at), (cur) => {
      const total = BigInt((cur?.total as string | undefined) ?? "0") + amount;
      if (limit !== null && total > limit) return [undefined, false];
      return [{ total: total.toString() }, true];
    });
  }

  async release(key: string, period: string, amount: bigint, at: bigint): Promise<void> {
    await update(this.kv, this.k(key, period, at), (cur) => {
      if (cur === null) return [undefined, undefined];
      const total = BigInt(cur.total as string) - amount;
      return [{ total: (total < 0n ? 0n : total).toString() }, undefined];
    });
  }
}

// ---------- revocations: one small blob per revoked object (mandate hash or delegation hash) ----------

/** Per object, the earliest revocations are kept; one valid revocation already switches it off. */
export const MAX_PER_TARGET = 32;

interface RevEntry {
  r: J;
  until: string | null; // valid_until of the revoked object: after that the revocation is moot and is dropped
}

function revKey(tenant: string, target: string): string {
  return `t/${tenant}/rev/${h(target)}`;
}

function live(entries: unknown, nowMs: number): RevEntry[] {
  if (!Array.isArray(entries)) return [];
  return (entries as RevEntry[]).filter((e) => e.until === null || !(Date.parse(e.until) < nowMs));
}

/** The stored revocations of these objects (mandate and delegation hashes). Throws if the store is down. */
export async function loadRevocationsFor(kv: KV, tenant: string, targets: string[], nowMs: number): Promise<J[]> {
  const out: J[] = [];
  for (const t of new Set(targets)) {
    const e = await kv.get(revKey(tenant, t));
    if (e !== null) out.push(...live((JSON.parse(e.data) as J).entries, nowMs).map((x) => x.r));
  }
  return out;
}

/** Store a (verified) revocation of `target`. Never refused for capacity: the earliest ones are kept. */
export async function addRevocation(kv: KV, tenant: string, target: string, r: J, until: string | null, nowMs: number,
  canonical: (v: unknown) => string): Promise<void> {
  const want = canonical(r);
  await update(kv, revKey(tenant, target), (cur) => {
    const list = live(cur?.entries, nowMs);
    if (list.some((x) => canonical(x.r) === want)) return [undefined, undefined];
    const at = (x: RevEntry) => Date.parse(String(x.r.revoked_at)) || 0;
    const entries = [...list, { r, until }].sort((a, b) => at(a) - at(b)).slice(0, MAX_PER_TARGET);
    return [{ target, entries }, undefined];
  });
}

/** Every stored, live revocation of a tenant, for the signed list (bounded). */
export async function listRevocations(kv: KV, tenant: string, nowMs: number, maxTargets = 500): Promise<J[]> {
  const keys = await kv.list(`t/${tenant}/rev/`, maxTargets);
  const out: J[] = [];
  for (const k of keys) {
    const e = await kv.get(k);
    if (e !== null) out.push(...live((JSON.parse(e.data) as J).entries, nowMs).map((x) => x.r));
  }
  return out;
}

// ---------- tenants ----------

export interface Tenant {
  v: 1;
  id: string;
  checker: string;
  created_at: string;
  public_key: string;
  seed: string; // sealed with MASTER_KEY, never returned
  api_key_hash: string; // HMAC of the check key, never returned
  kyb_key_hash: string; // HMAC of the KYB key (authority table only), never returned
  authority: AuthorityDoc;
  authority_version: number;
  authority_hash: string;
}

export interface PublicInfo {
  checker: string;
  public_key: string;
}

export function tenantKey(id: string): string {
  return `t/${id}/tenant`;
}

export async function loadTenant(kv: KV, id: string): Promise<Tenant | null> {
  const e = await kv.get(tenantKey(id));
  return e === null ? null : (JSON.parse(e.data) as Tenant);
}

/** The public part of a tenant, in its own blob, so public endpoints never read the record with secrets. */
export async function loadPublic(kv: KV, id: string): Promise<PublicInfo | null> {
  const e = await kv.get(`t/${id}/public`);
  if (e === null) return null;
  const v = JSON.parse(e.data) as J;
  return { checker: v.checker as string, public_key: v.public_key as string };
}

export async function savePublic(kv: KV, id: string, p: PublicInfo): Promise<void> {
  await kv.put(`t/${id}/public`, JSON.stringify({ ...p, ops: [newOp()] }), null);
}

/** false if the tenant exists, or data of a deleted tenant with this id is still in the store. */
export async function createTenant(kv: KV, t: Tenant): Promise<boolean> {
  if ((await kv.list(`t/${t.id}/`, 1)).length) return false;
  if (!(await createOnce(kv, tenantKey(t.id), t as unknown as J))) return false;
  await savePublic(kv, t.id, { checker: t.checker, public_key: t.public_key });
  return true;
}

/** Change a stored tenant. `f` returns null to abort (e.g. the key it authenticated with was rotated meanwhile). */
export async function changeTenant(kv: KV, id: string, f: (t: Tenant) => Tenant | null): Promise<"ok" | "missing" | "aborted"> {
  return update(kv, tenantKey(id), (cur) => {
    if (cur === null) return [undefined, "missing"];
    const next = f(cur as unknown as Tenant);
    return next === null ? [undefined, "aborted"] : [next as unknown as J, "ok"];
  });
}

/** Append-only record of every authority table a tenant has had (written before the table is switched). */
export async function logAuthority(kv: KV, id: string, version: number, entry: J): Promise<void> {
  const key = `t/${id}/authority-log/${String(version).padStart(8, "0")}-${newOp()}`;
  if (!(await createOnce(kv, key, entry))) throw new Error("authority log entry exists");
}

// ---------- deleting a tenant ----------

/** Keys deleted per listing round, and the most rounds before giving up (the caller retries). */
const DELETE_PAGE = 1000;
const DELETE_ROUNDS = 1000;

/**
 * Delete a tenant and everything stored under it: the tenant record (with its sealed checker key and key hashes)
 * first, so its check and KYB keys stop working at once, then every other key under `t/<id>/`: the public key
 * blob, the authority log, the payment log, the period ledger, revocations and release markers. Returns how many
 * keys it deleted (0: nothing was there). Throws if the store fails; deleting again finishes the job.
 */
export async function deleteTenant(kv: KV, id: string): Promise<number> {
  let n = 0;
  if ((await kv.get(tenantKey(id))) !== null) {
    await kv.del(tenantKey(id));
    n += 1;
  }
  for (let round = 0; round < DELETE_ROUNDS; round++) {
    const keys = await kv.list(`t/${id}/`, DELETE_PAGE);
    if (!keys.length) return n;
    for (const k of keys) {
      await kv.del(k);
      n += 1;
    }
  }
  throw new Error(`tenant ${id}: data not fully deleted, delete again`);
}

// ---------- releasing an allowed payment that was not executed ----------

/**
 * Mark one allow decision as released, once: true for exactly one caller (also when the store's answer was lost),
 * false if it was released before. The marker is keyed by the decision's hash.
 */
export async function markReleased(kv: KV, tenant: string, decisionHash: string, value: J): Promise<boolean> {
  return createOnce(kv, releasedKey(tenant, decisionHash), value);
}

export async function wasReleased(kv: KV, tenant: string, decisionHash: string): Promise<J | null> {
  const e = await kv.get(releasedKey(tenant, decisionHash));
  return e === null ? null : (JSON.parse(e.data) as J);
}

function releasedKey(tenant: string, decisionHash: string): string {
  return `t/${tenant}/released/${h(decisionHash)}`;
}
