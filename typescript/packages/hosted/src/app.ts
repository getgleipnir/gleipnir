/**
 * Gleipnir hosted checker, SANDBOX. Not for real money.
 *
 * The HTTP contract of `gleipnir mandate serve` (python/gleipnir/src/gleipnir/mandate_service.py), multi-tenant:
 *
 *   POST /v1/check        {"mandate", "payment"}                         -> the signed decision (200)
 *   POST /v1/resolve      {"mandate", "payment", "decision", "override"} -> the decision after a signed override
 *   POST /v1/revoke       {"revocation", "mandate"}                      -> {"ok": true}
 *   GET  /v1/revocations  -> the signed list of stored revocations, current for an hour
 *   GET  /v1/keys         -> {"checker", "keys"}
 *   GET  /t/<tenant>/keys, /t/<tenant>/.well-known/gleipnir-checker.json  (public, no auth)
 *   POST /v1/admin/tenants                    (ADMIN_TOKEN)          {"id"[, "authority"]} -> api_key, once
 *   POST /v1/admin/tenants/<id>/api-key       (ADMIN_TOKEN)          -> a new api_key, once; the old one stops working
 *   PUT  /v1/admin/tenants/<id>/authority     (ADMIN_TOKEN or the tenant's key) the KYB table
 *   GET  /v1/admin/tenants/<id>/authority     (ADMIN_TOKEN or the tenant's key)
 *
 * Everything else needs `Authorization: Bearer <tenant api key>`. Bodies are strict JSON (parseStrict: no
 * duplicate keys, no floats), 1 byte to 1 MiB, Content-Type application/json. Errors are {"error": text}.
 */

import {
  Checker,
  keyset,
  newSeed,
  parseStrict,
  publicKeyOf,
  revocationList,
  revocationProblem,
  fmtTs,
} from "@getgleipnir/verify/mandate";
import type { KV } from "./kv.js";
import { Secrets, MIN_SECRET, tenantIdOk, tenantOfKey } from "./secrets.js";
import {
  EMPTY_AUTHORITY,
  KVLedger,
  KVPaymentLog,
  MAX_REVOCATIONS,
  addRevocation,
  authorityOf,
  authorityProblem,
  changeTenant,
  createTenant,
  holdsOf,
  loadRevocations,
  loadTenant,
  type AuthorityDoc,
  type Tenant,
} from "./state.js";

type J = Record<string, unknown>;

export const MAX_BODY = 1 << 20;
const MAX_REVOCATION = 4096;
export const SANDBOX_NOTICE = "SANDBOX: test checker, not for real money. Decisions are signed by a sandbox key.";

export interface Env {
  ADMIN_TOKEN?: string;
  MASTER_KEY?: string;
  /** Comma-separated browser origins allowed to call authenticated endpoints (default: none). */
  ALLOW_ORIGINS?: string;
  /** Requests per minute per API key (default 120). */
  RATE_LIMIT_PER_MIN?: string;
}

export interface Deps {
  kv: KV;
  env: Env;
  /** Client IP, for limiting unauthenticated and failed requests. */
  ip?: string;
  clock?: () => Date;
  limiter?: RateLimiter;
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

// ---------- rate limiting: fixed one-minute windows, per function instance (best effort) ----------

export class RateLimiter {
  private readonly hits = new Map<string, { start: number; n: number }>();

  /** true if this request is within `limit` per minute for `who`. */
  allow(who: string, limit: number, now = Date.now()): boolean {
    if (this.hits.size > 50_000) this.hits.clear(); // bound memory under a flood of distinct callers
    const e = this.hits.get(who);
    if (!e || now - e.start >= 60_000) {
      this.hits.set(who, { start: now, n: 1 });
      return true;
    }
    e.n += 1;
    return e.n <= limit;
  }

  /** true if `who` has used up `limit` in the current window (without counting this call). */
  spent(who: string, limit: number, now = Date.now()): boolean {
    const e = this.hits.get(who);
    return e !== undefined && now - e.start < 60_000 && e.n >= limit;
  }
}

const defaultLimiter = new RateLimiter();
const PUBLIC_PER_MIN = 120; // per IP, unauthenticated GETs
const FAILED_AUTH_PER_MIN = 20; // per IP

// ---------- responses ----------

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Gleipnir-Environment": "sandbox",
      ...extra,
    },
  });
}

async function readBody(req: Request): Promise<unknown> {
  const declared = req.headers.get("Content-Length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) <= 0 || Number(declared) > MAX_BODY)) {
    throw new HttpError(400, `body must be 1 byte to ${MAX_BODY} bytes`);
  }
  if (req.body === null) throw new HttpError(400, `body must be 1 byte to ${MAX_BODY} bytes`);
  const reader = req.body.getReader();
  const parts: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > MAX_BODY) {
      await reader.cancel().catch(() => undefined);
      throw new HttpError(400, `body must be 1 byte to ${MAX_BODY} bytes`);
    }
    parts.push(value);
  }
  if (n === 0) throw new HttpError(400, `body must be 1 byte to ${MAX_BODY} bytes`);
  const bytes = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    bytes.set(p, off);
    off += p.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new HttpError(400, "body is not UTF-8");
  }
  try {
    return parseStrict(text);
  } catch (e) {
    throw new HttpError(400, `body: ${e instanceof Error ? e.message : "not JSON"}`);
  }
}

function exactly(body: unknown, keys: string[], what: string): J {
  if (typeof body !== "object" || body === null || Array.isArray(body)) throw new HttpError(400, `expected ${what}`);
  const got = Object.keys(body).sort(), want = [...keys].sort();
  if (got.length !== want.length || got.some((k, i) => k !== want[i])) throw new HttpError(400, `expected ${what}`);
  return body as J;
}

// ---------- the handler ----------

/** One request in, one response out. Never throws. */
export async function handle(req: Request, deps: Deps): Promise<Response> {
  try {
    return await route(req, deps);
  } catch (e) {
    if (e instanceof HttpError) return json(e.status, { error: e.message });
    return json(500, { error: "internal error" });
  }
}

interface Ctx {
  deps: Deps;
  secrets: Secrets;
  limiter: RateLimiter;
  ip: string;
  now: () => Date;
}

async function route(req: Request, deps: Deps): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = req.method.toUpperCase();
  const master = deps.env.MASTER_KEY ?? "";
  if (master.length < MIN_SECRET) throw new HttpError(503, "checker not configured (MASTER_KEY)");
  const ctx: Ctx = {
    deps, secrets: new Secrets(master), limiter: deps.limiter ?? defaultLimiter, ip: deps.ip ?? "unknown",
    now: deps.clock ?? (() => new Date()),
  };

  if (path === "/" || path === "/v1") {
    if (method !== "GET") throw new HttpError(405, "method not allowed");
    return json(200, { service: "gleipnir hosted checker", environment: "sandbox", warning: SANDBOX_NOTICE,
      docs: "https://github.com/getgleipnir/gleipnir/tree/main/typescript/packages/hosted" });
  }

  // Public: a tenant's checker keys, so companies and auditors can verify decisions.
  const pub = /^\/t\/([^/]+)\/(keys|\.well-known\/gleipnir-checker\.json)$/.exec(path);
  if (pub) {
    if (method !== "GET") throw new HttpError(405, "method not allowed");
    if (!ctx.limiter.allow(`ip:${ctx.ip}`, PUBLIC_PER_MIN)) throw new HttpError(429, "too many requests");
    const t = tenantIdOk(pub[1]) ? await storeCall(() => loadTenant(deps.kv, pub[1]!)) : null;
    if (t === null) throw new HttpError(404, "not found");
    const cors = { "Access-Control-Allow-Origin": "*", "Gleipnir-Checker": t.checker };
    if (pub[2] === "keys") return json(200, { checker: t.checker, keys: [t.public_key] }, cors);
    return json(200, keyset(t.checker, [{ public_key: t.public_key }], fmtTs(BigInt(ctx.now().getTime()) * 1000n)), cors);
  }

  if (!path.startsWith("/v1/")) throw new HttpError(404, "not found");

  // Browsers only from configured origins (servers send no Origin), as the reference server.
  const origin = req.headers.get("Origin");
  const origins = (deps.env.ALLOW_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (origin !== null && !origins.includes(origin)) throw new HttpError(403, "origin not allowed");
  if (method === "POST" || method === "PUT") {
    const ctype = (req.headers.get("Content-Type") ?? "").split(";")[0]!.trim().toLowerCase();
    if (ctype !== "application/json") throw new HttpError(415, "Content-Type must be application/json");
  }

  const admin = /^\/v1\/admin\/tenants(?:\/([^/]+)\/(authority|api-key))?$/.exec(path);
  if (admin) return adminRoute(req, ctx, method, admin[1], admin[2]);

  const t = await authTenant(req, ctx);
  const hdr = { "Gleipnir-Checker": t.checker };
  const id = `${method} ${path}`;
  if (id === "POST /v1/check") {
    const b = exactly(await readBody(req), ["mandate", "payment"], '{"mandate": ..., "payment": ...}');
    return json(200, await (await checkerFor(t, ctx)).check(b.mandate, b.payment), hdr);
  }
  if (id === "POST /v1/resolve") {
    const b = exactly(await readBody(req), ["mandate", "payment", "decision", "override"],
      '{"mandate", "payment", "decision", "override"}');
    return json(200, await (await checkerFor(t, ctx)).resolve(b.mandate, b.payment, b.decision, b.override), hdr);
  }
  if (id === "POST /v1/revoke") {
    const b = exactly(await readBody(req), ["revocation", "mandate"], '{"revocation": ..., "mandate": ...}');
    await revokeFor(t, ctx, b.revocation, b.mandate);
    return json(200, { ok: true, checker: t.checker }, hdr);
  }
  if (id === "GET /v1/revocations") {
    const revs = await storeCall(() => loadRevocations(deps.kv, t.id));
    const now = BigInt(ctx.now().getTime()) * 1000n;
    return json(200, revocationList(revs, { issuer: t.checker, seed: seedOf(t, ctx), issuedAt: fmtTs(now),
      nextUpdate: fmtTs(now + 3600n * 1_000_000n) }), hdr);
  }
  if (id === "GET /v1/keys") return json(200, { checker: t.checker, keys: [t.public_key] }, hdr);
  if (["/v1/check", "/v1/resolve", "/v1/revoke", "/v1/revocations", "/v1/keys"].includes(path)) {
    throw new HttpError(405, "method not allowed");
  }
  throw new HttpError(404, "not found");
}

/** A store call that fails closed: the caller gets 503, never a guess. */
async function storeCall<T>(f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch {
    throw new HttpError(503, "store unavailable");
  }
}

function bearer(req: Request): string | null {
  const m = /^Bearer ([\x21-\x7e]{1,256})$/.exec(req.headers.get("Authorization") ?? "");
  return m ? m[1]! : null;
}

function failedAuth(ctx: Ctx, message = "missing or wrong bearer token"): never {
  ctx.limiter.allow(`fail:${ctx.ip}`, FAILED_AUTH_PER_MIN);
  throw new HttpError(401, message);
}

function perMinute(ctx: Ctx): number {
  const n = Number(ctx.deps.env.RATE_LIMIT_PER_MIN ?? "120");
  return Number.isInteger(n) && n > 0 ? n : 120;
}

/** The tenant whose API key this request carries. 401 otherwise; 429 over the rate limit. */
async function authTenant(req: Request, ctx: Ctx): Promise<Tenant> {
  if (tooManyFailures(ctx)) throw new HttpError(429, "too many failed attempts");
  const key = bearer(req);
  const tid = key === null ? null : tenantOfKey(key);
  if (key === null || tid === null) failedAuth(ctx);
  const t = await storeCall(() => loadTenant(ctx.deps.kv, tid));
  if (t === null || !ctx.secrets.keyMatches(key, t.api_key_hash)) failedAuth(ctx);
  if (!ctx.limiter.allow(`tenant:${t.id}`, perMinute(ctx))) throw new HttpError(429, "too many requests");
  return t;
}

/** Failed attempts are counted by failedAuth(); this only looks whether the IP has used up its window. */
function tooManyFailures(ctx: Ctx): boolean {
  return ctx.limiter.spent(`fail:${ctx.ip}`, FAILED_AUTH_PER_MIN);
}

function isAdmin(req: Request, ctx: Ctx): boolean {
  const token = ctx.deps.env.ADMIN_TOKEN ?? "";
  const given = bearer(req);
  return token.length >= MIN_SECRET && given !== null && ctx.secrets.same(given, token);
}

function seedOf(t: Tenant, ctx: Ctx): Uint8Array {
  try {
    return ctx.secrets.openSeed(t.seed, t.id);
  } catch {
    throw new HttpError(503, "checker key unavailable (MASTER_KEY changed?)");
  }
}

/**
 * A Checker for this tenant on the shared store. The revocations are read first; if that read fails, the
 * checker is built with a `holds` that fails, so every payment gets a signed escalate `checker_unavailable`
 * (fail closed, and the same outcome the library gives when the ledger or payment log is down).
 */
async function checkerFor(t: Tenant, ctx: Ctx, withState = true): Promise<Checker> {
  const seed = seedOf(t, ctx);
  let revocations: J[] = [];
  let down = false;
  if (withState) {
    try {
      revocations = await loadRevocations(ctx.deps.kv, t.id);
    } catch {
      down = true;
    }
  }
  const a = t.authority;
  return new Checker({
    id: t.checker,
    seed,
    authority: authorityOf(a),
    holds: down ? () => { throw new Error("revocation store unavailable"); } : holdsOf(a),
    ledger: withState ? new KVLedger(ctx.deps.kv, t.id) : null,
    payments: new KVPaymentLog(ctx.deps.kv, t.id),
    revocations,
    status: null, // status_url is not fetched in the sandbox: such mandates escalate status_unavailable
    officers: a.officers ?? [],
    requirePayees: a.require_payees ?? false,
    webauthn: { rpId: a.webauthn?.rp_id, origins: a.webauthn?.origins },
    clock: ctx.now,
  });
}

async function revokeFor(t: Tenant, ctx: Ctx, r: unknown, mandate: unknown): Promise<void> {
  const problem = revocationProblem(r);
  if (problem) throw new HttpError(400, `revocation rejected: ${problem}`);
  if (new TextEncoder().encode(canonicalText(r)).byteLength > MAX_REVOCATION) throw new HttpError(400, `revocation rejected: larger than ${MAX_REVOCATION} bytes`);
  if (!(await (await checkerFor(t, ctx, false)).revocationCounts(mandate, r))) {
    throw new HttpError(400, "revocation rejected: not a valid revocation of this mandate by someone who may revoke it");
  }
  const res = await storeCall(() => addRevocation(ctx.deps.kv, t.id, r as J, canonicalText));
  if (res === "full") {
    throw new HttpError(400, `revocation store is full: this sandbox keeps at most ${MAX_REVOCATIONS} per tenant`);
  }
}

/** Key-sorted JSON, to tell two stored revocations apart. */
function canonicalText(v: unknown): string {
  const sort = (x: unknown): unknown => Array.isArray(x) ? x.map(sort)
    : x && typeof x === "object" ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, sort((x as J)[k])])) : x;
  return JSON.stringify(sort(v));
}

// ---------- admin ----------

async function adminRoute(req: Request, ctx: Ctx, method: string, tid: string | undefined, what: string | undefined): Promise<Response> {
  const kv = ctx.deps.kv;
  if (tooManyFailures(ctx)) throw new HttpError(429, "too many failed attempts");
  const admin = isAdmin(req, ctx);

  if (tid === undefined) { // POST /v1/admin/tenants
    if (method !== "POST") throw new HttpError(405, "method not allowed");
    if (!admin) failedAuth(ctx);
    const body = await readBody(req);
    if (typeof body !== "object" || body === null || Array.isArray(body)
      || !Object.keys(body).every((k) => k === "id" || k === "authority") || !("id" in body)) {
      throw new HttpError(400, 'expected {"id": "<tenant id>"[, "authority": {...}]}');
    }
    const b = body as J;
    if (!tenantIdOk(b.id)) throw new HttpError(400, "id must be 3 to 40 of a-z, 0-9 and single hyphens, e.g. \"acme-psp\"");
    const authority = (b.authority ?? EMPTY_AUTHORITY) as AuthorityDoc;
    const problem = authorityProblem(authority);
    if (problem) throw new HttpError(400, problem);
    const seed = newSeed();
    const { key, hash } = ctx.secrets.newApiKey(b.id);
    const t: Tenant = {
      v: 1, id: b.id, checker: `sandbox:${b.id}`, created_at: ctx.now().toISOString(), public_key: publicKeyOf(seed),
      seed: ctx.secrets.sealSeed(seed, b.id), api_key_hash: hash, authority,
    };
    if (!(await storeCall(() => createTenant(kv, t)))) throw new HttpError(409, "tenant exists");
    return json(201, {
      id: t.id, checker: t.checker, public_key: t.public_key, api_key: key,
      keys: `/t/${t.id}/keys`, keyset: `/t/${t.id}/.well-known/gleipnir-checker.json`,
      note: "The api_key is shown once; only its hash is stored. " + SANDBOX_NOTICE,
    }, { "Gleipnir-Checker": t.checker });
  }

  if (!tenantIdOk(tid)) throw new HttpError(404, "not found");
  // The tenant itself may read and set its own authority table; only the admin may issue keys.
  let self = false;
  if (!admin && what === "authority") {
    const key = bearer(req);
    if (key !== null && tenantOfKey(key) === tid) {
      const t = await storeCall(() => loadTenant(kv, tid));
      self = t !== null && ctx.secrets.keyMatches(key, t.api_key_hash);
      if (self && !ctx.limiter.allow(`tenant:${tid}`, perMinute(ctx))) throw new HttpError(429, "too many requests");
    }
  }
  if (!admin && !self) failedAuth(ctx);

  if (what === "api-key") {
    if (method !== "POST") throw new HttpError(405, "method not allowed");
    const { key, hash } = ctx.secrets.newApiKey(tid);
    if (!(await storeCall(() => changeTenant(kv, tid, (t) => ({ ...t, api_key_hash: hash }))))) throw new HttpError(404, "not found");
    return json(200, { id: tid, api_key: key, note: "Shown once; the previous key no longer works." });
  }
  if (method === "GET") {
    const t = await storeCall(() => loadTenant(kv, tid));
    if (t === null) throw new HttpError(404, "not found");
    return json(200, t.authority, { "Gleipnir-Checker": t.checker });
  }
  if (method !== "PUT") throw new HttpError(405, "method not allowed");
  const doc = await readBody(req);
  const problem = authorityProblem(doc);
  if (problem) throw new HttpError(400, problem);
  if (!(await storeCall(() => changeTenant(kv, tid, (t) => ({ ...t, authority: doc as AuthorityDoc }))))) {
    throw new HttpError(404, "not found");
  }
  return json(200, { ok: true, checker: `sandbox:${tid}`, signers: (doc as AuthorityDoc).signers.length,
    accounts: (doc as AuthorityDoc).accounts.length });
}
