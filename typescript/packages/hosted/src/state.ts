/**
 * Tenant state on a KV store with conditional writes: the payment log and period ledger the Checker expects
 * (spec 7), stored revocations, and tenant records. Every read-modify-write is a compare-and-swap on the
 * entry's ETag, retried a few times; if it cannot get through it throws, and the Checker turns that into
 * `checker_unavailable` (fail closed).
 */

import { createHash } from "node:crypto";
import { accountProblem, periodKey, type Authority, type Holds, type Ledger, type PaymentLog } from "@getgleipnir/verify/mandate";
import type { KV } from "./kv.js";

type J = Record<string, unknown>;

const RETRIES = 8;

function h(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
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
 * Returns the result of the call whose write went through.
 */
async function update<T>(kv: KV, key: string, f: (cur: J | null) => [J | undefined | "delete", T]): Promise<T> {
  for (let i = 0; i < RETRIES; i++) {
    const e = await kv.get(key);
    const cur = e === null ? null : (JSON.parse(e.data) as J);
    const [next, out] = f(cur);
    if (next === undefined) return out;
    if (next === "delete") {
      await kv.del(key);
      return out;
    }
    if (await kv.put(key, JSON.stringify(next), e === null ? { ifNew: true } : { ifMatch: e.etag })) return out;
    await backoff(i);
  }
  throw new ContentionError(key);
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
    return this.kv.put(this.k(key), JSON.stringify({ hash: paymentHash, decision: null }), { ifNew: true });
  }

  async remember(key: string, decision: J): Promise<void> {
    await update(this.kv, this.k(key), (cur) => [cur === null ? undefined : { hash: cur.hash, decision }, undefined]);
  }

  async forget(key: string): Promise<void> {
    await this.kv.del(this.k(key));
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

// ---------- revocations ----------

export const MAX_REVOCATIONS = 1000;

export async function loadRevocations(kv: KV, tenant: string): Promise<J[]> {
  const e = await kv.get(`t/${tenant}/revocations`);
  return e === null ? [] : ((JSON.parse(e.data) as { revocations: J[] }).revocations);
}

/** Adds a revocation (no-op if already stored). "full" if the sandbox store is full. */
export async function addRevocation(kv: KV, tenant: string, r: J, canonical: (v: unknown) => string): Promise<"ok" | "full"> {
  const want = canonical(r);
  return update(kv, `t/${tenant}/revocations`, (cur) => {
    const list = (cur?.revocations as J[] | undefined) ?? [];
    if (list.some((x) => canonical(x) === want)) return [undefined, "ok"];
    if (list.length >= MAX_REVOCATIONS) return [undefined, "full"];
    return [{ revocations: [...list, r] }, "ok"];
  });
}

// ---------- tenants ----------

export interface AuthorityDoc {
  source?: string;
  signers: { company: string; signer: string; keys: string[]; may_sign?: boolean; joint?: number;
    retired?: Record<string, string>; person?: string }[];
  accounts: { company: string; account: J; customer?: string }[];
  officers?: string[];
  require_payees?: boolean;
  webauthn?: { rp_id?: string; origins?: string[] };
}

export interface Tenant {
  v: 1;
  id: string;
  checker: string;
  created_at: string;
  public_key: string;
  seed: string; // sealed with MASTER_KEY, never returned
  api_key_hash: string; // HMAC of the API key, never returned
  authority: AuthorityDoc;
}

export const EMPTY_AUTHORITY: AuthorityDoc = { source: "bank_kyb", signers: [], accounts: [] };

export function tenantKey(id: string): string {
  return `t/${id}/tenant`;
}

export async function loadTenant(kv: KV, id: string): Promise<Tenant | null> {
  const e = await kv.get(tenantKey(id));
  return e === null ? null : (JSON.parse(e.data) as Tenant);
}

export async function createTenant(kv: KV, t: Tenant): Promise<boolean> {
  return kv.put(tenantKey(t.id), JSON.stringify(t), { ifNew: true });
}

/** Change a stored tenant; false if it does not exist. */
export async function changeTenant(kv: KV, id: string, f: (t: Tenant) => Tenant): Promise<boolean> {
  return update(kv, tenantKey(id), (cur) => (cur === null ? [undefined, false] : [f(cur as unknown as Tenant) as unknown as J, true]));
}

const MAX_ROWS = 1000;
const str = (v: unknown, max = 512): v is string => typeof v === "string" && v.length > 0 && v.length <= max;
const isObj = (v: unknown): v is J => typeof v === "object" && v !== null && !Array.isArray(v);
const only = (o: J, keys: string[]) => Object.keys(o).every((k) => keys.includes(k));
const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/;

/**
 * Why this is not an authority document, or null. The same shape as the KYB file of `gleipnir mandate serve
 * --authority`, plus the sandbox policy (officers, require_payees, webauthn).
 */
export function authorityProblem(doc: unknown): string | null {
  if (!isObj(doc)) return "authority must be an object";
  if (!only(doc, ["source", "signers", "accounts", "officers", "require_payees", "webauthn"])) {
    return "authority: unknown field (allowed: source, signers, accounts, officers, require_payees, webauthn)";
  }
  if (doc.source !== undefined && !str(doc.source, 64)) return "authority.source must be a short string";
  if (!Array.isArray(doc.signers) || doc.signers.length > MAX_ROWS) return `authority.signers must be a list of at most ${MAX_ROWS}`;
  for (const [i, s] of doc.signers.entries()) {
    const at = `authority.signers[${i}]`;
    if (!isObj(s) || !only(s, ["company", "signer", "keys", "may_sign", "joint", "retired", "person"])) return `${at}: unknown field or not an object`;
    if (!str(s.company) || !str(s.signer)) return `${at}: company and signer must be non-empty strings`;
    if (!Array.isArray(s.keys) || s.keys.length < 1 || s.keys.length > 16 || !s.keys.every((k) => str(k, 2048))) {
      return `${at}.keys must be 1 to 16 public keys`;
    }
    if (s.may_sign !== undefined && typeof s.may_sign !== "boolean") return `${at}.may_sign must be true or false`;
    if (s.joint !== undefined && !(Number.isInteger(s.joint) && (s.joint as number) >= 1 && (s.joint as number) <= 16)) {
      return `${at}.joint must be an integer from 1 to 16`;
    }
    if (s.retired !== undefined && (!isObj(s.retired) || Object.keys(s.retired).length > 16
      || !Object.values(s.retired).every((t) => typeof t === "string" && TS_RE.test(t)))) {
      return `${at}.retired must map keys to RFC 3339 UTC times`;
    }
    if (s.person !== undefined && !str(s.person)) return `${at}.person must be a non-empty string`;
  }
  if (!Array.isArray(doc.accounts) || doc.accounts.length > MAX_ROWS) return `authority.accounts must be a list of at most ${MAX_ROWS}`;
  for (const [i, a] of doc.accounts.entries()) {
    const at = `authority.accounts[${i}]`;
    if (!isObj(a) || !only(a, ["company", "account", "customer"])) return `${at}: unknown field or not an object`;
    if (!str(a.company)) return `${at}.company must be a non-empty string`;
    const bad = accountProblem(a.account);
    if (bad) return `${at}.account: ${bad}`;
    if (a.customer !== undefined && !str(a.customer)) return `${at}.customer must be a non-empty string`;
  }
  if (doc.officers !== undefined && (!Array.isArray(doc.officers) || doc.officers.length > 16 || !doc.officers.every((k) => str(k, 2048)))) {
    return "authority.officers must be at most 16 public keys";
  }
  if (doc.require_payees !== undefined && typeof doc.require_payees !== "boolean") return "authority.require_payees must be true or false";
  if (doc.webauthn !== undefined) {
    const w = doc.webauthn;
    if (!isObj(w) || !only(w, ["rp_id", "origins"]) || (w.rp_id !== undefined && !str(w.rp_id, 253))
      || (w.origins !== undefined && (!Array.isArray(w.origins) || w.origins.length > 16 || !w.origins.every((o) => str(o, 2048))))) {
      return "authority.webauthn must be {rp_id, origins}";
    }
  }
  return null;
}

/** Accounts compared exactly, as the bank's systems would: same fields, same values. */
function accountText(acc: unknown): string {
  const o = acc as Record<string, string>;
  return JSON.stringify(Object.keys(o).sort().map((k) => [k, o[k]]));
}

/** authority(company, personId) from the tenant's KYB table, as `gleipnir mandate serve --authority`. */
export function authorityOf(doc: AuthorityDoc): Authority {
  const table = new Map(doc.signers.map((s) => [JSON.stringify([s.company, s.signer]), s]));
  return (company, personId) => {
    const s = table.get(JSON.stringify([company.name, personId]));
    if (!s) return null;
    return { source: doc.source ?? "bank_kyb", keys: s.keys, maySign: s.may_sign ?? true, joint: s.joint ?? 1,
      retired: s.retired ?? {}, person: s.person ?? null };
  };
}

/** holds(company, account): the customer id (default: the company name), as `gleipnir mandate serve`. */
export function holdsOf(doc: AuthorityDoc): Holds {
  const held = new Map(doc.accounts.map((a) => [JSON.stringify([a.company, accountText(a.account)]), a.customer ?? a.company]));
  return (company, account) => held.get(JSON.stringify([company.name, accountText(account)])) ?? null;
}
