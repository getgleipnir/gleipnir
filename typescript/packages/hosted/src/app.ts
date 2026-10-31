/**
 * Gleipnir hosted checker, SANDBOX. Not for real money.
 *
 * The HTTP contract of `gleipnir mandate serve` (python/gleipnir/src/gleipnir/mandate_service.py), multi-tenant:
 *
 *   POST /v1/check        {"mandate", "payment"[, "payee_approvals"]}    -> the signed decision (200)
 *   POST /v1/resolve      {"mandate", "payment", "decision", "override"[, "payee_approvals"]} -> the decision after
 *                         a signed override
 *   POST /v1/revoke       {"revocation", "mandate"[, "payee_approval"]}  -> {"ok": true, "checker"}
 *   POST /v1/release      {"mandate", "payment", "decision"}             -> {"released": true, ...}: the bank did not
 *                         execute this allowed payment; its period reservations are given back, once, within
 *                         RELEASE_WINDOW_HOURS (off by default) and the same limit period; the payment id stays used
 *   GET  /v1/revocations  -> the signed list of stored revocations, current for an hour
 *   GET  /v1/keys         -> {"checker", "keys"}
 *   GET  /t/<tenant>/keys, /t/<tenant>/.well-known/gleipnir-checker.json  (public, no auth)
 *
 *   POST /v1/admin/tenants                 (ADMIN_TOKEN) {["id"][, "authority"]} -> api_key and kyb_key, once
 *   DELETE /v1/admin/tenants/<id>          (ADMIN_TOKEN) the tenant and ALL its data (keys, authority table and log,
 *                                          payment log, ledger, revocations, release markers)
 *   POST /v1/admin/tenants/<id>/api-key    (ADMIN_TOKEN) -> a new check key, once; the old one stops working
 *   POST /v1/admin/tenants/<id>/kyb-key    (ADMIN_TOKEN) -> a new KYB key, once; the old one stops working
 *   PUT  /v1/admin/tenants/<id>/authority  (ADMIN_TOKEN or the tenant's KYB key) the authority table
 *   GET  /v1/admin/tenants/<id>/authority  (ADMIN_TOKEN or the tenant's KYB key)
 *
 * The check key (gks_...) only checks; the KYB key (gkk_...) only maintains the authority table, so a leaked
 * check key cannot add signers. Bodies are strict JSON (parseStrict: no duplicate keys, no floats), 1 byte to
 * 1 MiB, Content-Type application/json. Errors are {"error": text}.
 */

import {
  Checker,
  delegationHash,
  fmtTs,
  keyset,
  mandateHash,
  mandateProblem,
  newSeed,
  objHash,
  parseAmount,
  periodKey,
  parseStrict,
  payeeApprovalHash,
  payeeApprovalProblem,
  paymentKey,
  paymentProblem,
  publicKeyOf,
  revocationList,
  revocationProblem,
  verifyDecision,
} from "@getgleipnir/verify/mandate";
import { randomBytes } from "node:crypto";
import { EMPTY_AUTHORITY, authorityOf, authorityProblem, holdsOf, type AuthorityDoc } from "./authority.js";
import type { KV } from "./kv.js";
import { Secrets, MIN_SECRET, tenantIdOk, tenantOfKey } from "./secrets.js";
import {
  KVLedger,
  KVPaymentLog,
  addRevocation,
  changeTenant,
  createTenant,
  deleteTenant,
  h,
  listRevocations,
  loadPublic,
  loadRevocationsFor,
  loadTenant,
  logAuthority,
  markReleased,
  savePublic,
  wasReleased,
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
  /** Hours after an allow during which /v1/release may give its reservation back (default: off; unset, blank or 0 disables; max 744). */
  RELEASE_WINDOW_HOURS?: string;
}

export interface Deps {
  kv: KV;
  env: Env;
  /** Client IP, for limiting unauthenticated and failed requests. Unknown: no per-IP limits (never one shared bucket). */
  ip?: string;
  clock?: () => Date;
  limiter?: RateLimiter;
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const isDict = (v: unknown): v is J => typeof v === "object" && v !== null && !Array.isArray(v);

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
const REVOCATIONS_PER_SIGNER_PER_MIN = 10;

// ---------- responses ----------

const SECURITY_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Strict-Transport-Security": "max-age=31536000",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "Gleipnir-Environment": "sandbox",
};

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS, ...extra },
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

function exactly(body: unknown, keys: string[], what: string, optional: string[] = []): J {
  if (!isDict(body)) throw new HttpError(400, `expected ${what}`);
  const got = Object.keys(body).filter((k) => !optional.includes(k)).sort(), want = [...keys].sort();
  if (got.length !== want.length || got.some((k, i) => k !== want[i])) throw new HttpError(400, `expected ${what}`);
  return body;
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
  ip: string | null;
  now: () => Date;
}

async function route(req: Request, deps: Deps): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = req.method.toUpperCase();
  const master = deps.env.MASTER_KEY ?? "";
  if (master.length < MIN_SECRET) throw new HttpError(503, "checker not configured (MASTER_KEY)");
  const ctx: Ctx = {
    deps, secrets: new Secrets(master), limiter: deps.limiter ?? defaultLimiter, ip: deps.ip || null,
    now: deps.clock ?? (() => new Date()),
  };

  if (path === "/" || path === "/v1") {
    if (method !== "GET") throw new HttpError(405, "method not allowed");
    return json(200, { service: "gleipnir hosted checker", environment: "sandbox", warning: SANDBOX_NOTICE });
  }

  // Public: a tenant's checker keys, so companies and auditors can verify decisions.
  const pub = /^\/t\/([^/]+)\/(keys|\.well-known\/gleipnir-checker\.json)$/.exec(path);
  if (pub) {
    if (method !== "GET") throw new HttpError(405, "method not allowed");
    if (ctx.ip !== null && !ctx.limiter.allow(`ip:${ctx.ip}`, PUBLIC_PER_MIN)) throw new HttpError(429, "too many requests");
    const info = tenantIdOk(pub[1]) ? await storeCall(() => publicInfo(deps.kv, pub[1]!)) : null;
    if (info === null) throw new HttpError(404, "not found");
    const cors = { "Access-Control-Allow-Origin": "*", "Gleipnir-Checker": info.checker };
    if (pub[2] === "keys") return json(200, { checker: info.checker, keys: [info.public_key] }, cors);
    return json(200, keyset(info.checker, [{ public_key: info.public_key }], fmtTs(BigInt(ctx.now().getTime()) * 1000n)), cors);
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

  const admin = /^\/v1\/admin\/tenants(?:\/([^/]+)(?:\/(authority|api-key|kyb-key))?)?$/.exec(path);
  if (admin) return adminRoute(req, ctx, method, admin[1], admin[2]);

  const t = await authTenant(req, ctx);
  const hdr = { "Gleipnir-Checker": t.checker };
  const id = `${method} ${path}`;
  if (id === "POST /v1/check") {
    const b = exactly(await readBody(req), ["mandate", "payment"], '{"mandate": ..., "payment": ...[, "payee_approvals": [...]]}',
      ["payee_approvals"]);
    return json(200, await (await checkerFor(t, ctx, b.mandate, true, b.payee_approvals)).check(b.mandate, b.payment,
      b.payee_approvals), hdr);
  }
  if (id === "POST /v1/resolve") {
    const b = exactly(await readBody(req), ["mandate", "payment", "decision", "override"],
      '{"mandate", "payment", "decision", "override"[, "payee_approvals"]}', ["payee_approvals"]);
    return json(200, await (await checkerFor(t, ctx, b.mandate, true, b.payee_approvals)).resolve(b.mandate, b.payment,
      b.decision, b.override, b.payee_approvals), hdr);
  }
  if (id === "POST /v1/revoke") {
    const b = exactly(await readBody(req), ["revocation", "mandate"], '{"revocation": ..., "mandate": ...[, "payee_approval": ...]}',
      ["payee_approval"]);
    await revokeFor(t, ctx, b.revocation, b.mandate, b.payee_approval);
    return json(200, { ok: true, checker: t.checker }, hdr);
  }
  if (id === "POST /v1/release") {
    const b = exactly(await readBody(req), ["mandate", "payment", "decision"], '{"mandate", "payment", "decision"}');
    return json(200, await releaseFor(t, ctx, b.mandate, b.payment, b.decision), hdr);
  }
  if (id === "GET /v1/revocations") {
    const nowMs = ctx.now().getTime();
    const revs = await storeCall(() => listRevocations(deps.kv, t.id, nowMs));
    const now = BigInt(nowMs) * 1000n;
    return json(200, revocationList(revs, { issuer: t.checker, seed: seedOf(t, ctx), issuedAt: fmtTs(now),
      nextUpdate: fmtTs(now + 3600n * 1_000_000n) }), hdr);
  }
  if (id === "GET /v1/keys") return json(200, { checker: t.checker, keys: [t.public_key] }, hdr);
  if (["/v1/check", "/v1/resolve", "/v1/revoke", "/v1/release", "/v1/revocations", "/v1/keys"].includes(path)) {
    throw new HttpError(405, "method not allowed");
  }
  throw new HttpError(404, "not found");
}

/** The public blob; for a tenant created before it existed (or whose public write failed), from the record. */
async function publicInfo(kv: KV, id: string) {
  const p = await loadPublic(kv, id);
  if (p !== null) return p;
  const t = await loadTenant(kv, id);
  if (t === null) return null;
  const info = { checker: t.checker, public_key: t.public_key };
  await savePublic(kv, id, info).catch(() => undefined);
  return info;
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
  if (ctx.ip !== null) ctx.limiter.allow(`fail:${ctx.ip}`, FAILED_AUTH_PER_MIN);
  throw new HttpError(401, message);
}

/** Failed attempts are counted by failedAuth(); this only looks whether the IP has used up its window. */
function tooManyFailures(ctx: Ctx): boolean {
  return ctx.ip !== null && ctx.limiter.spent(`fail:${ctx.ip}`, FAILED_AUTH_PER_MIN);
}

function perMinute(ctx: Ctx): number {
  const n = Number(ctx.deps.env.RATE_LIMIT_PER_MIN ?? "120");
  return Number.isInteger(n) && n > 0 ? n : 120;
}

/** The tenant whose check key this request carries. 401 otherwise; 429 over the rate limit. */
async function authTenant(req: Request, ctx: Ctx): Promise<Tenant> {
  if (tooManyFailures(ctx)) throw new HttpError(429, "too many failed attempts");
  const key = bearer(req);
  const tid = key === null ? null : tenantOfKey(key, "check");
  if (key === null || tid === null) failedAuth(ctx);
  const t = await storeCall(() => loadTenant(ctx.deps.kv, tid));
  if (t === null || !ctx.secrets.keyMatches(key, t.api_key_hash)) failedAuth(ctx);
  if (!ctx.limiter.allow(`tenant:${t.id}`, perMinute(ctx))) throw new HttpError(429, "too many requests");
  return t;
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

/** At most this many payee approvals per request (the checker refuses more, spec 7.2). */
const MAX_APPROVALS = 16;

/**
 * The objects whose revocations matter for this payment: the mandate, each link of its chain, and each payee
 * approval presented with it.
 */
function targetsOf(mandate: unknown, approvals?: unknown): string[] {
  const out: string[] = [];
  try {
    if (!isDict(mandate)) return [];
    const chain = Array.isArray(mandate.delegation) ? (mandate.delegation as unknown[]).filter(isDict) : [];
    out.push(mandateHash(mandate), ...chain.map((d) => delegationHash(d)));
  } catch {
    return []; // not hashable: the checker refuses it as malformed before revocations matter
  }
  if (Array.isArray(approvals) && approvals.length <= MAX_APPROVALS) {
    for (const a of approvals) {
      if (payeeApprovalProblem(a) === null) out.push(payeeApprovalHash(a as J)); // malformed ones are refused anyway
    }
  }
  return out;
}

/**
 * A Checker for this tenant on the shared store. The revocations of this mandate and its chain are read first;
 * if that read fails, the checker is built with a `holds` that fails, so every payment gets a signed escalate
 * `checker_unavailable` (fail closed, as when the ledger or payment log is down).
 */
async function checkerFor(t: Tenant, ctx: Ctx, mandate: unknown, withState = true, approvals?: unknown): Promise<Checker> {
  const seed = seedOf(t, ctx);
  let revocations: J[] = [];
  let down = false;
  if (withState) {
    try {
      revocations = await loadRevocationsFor(ctx.deps.kv, t.id, targetsOf(mandate, approvals), ctx.now().getTime());
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

async function revokeFor(t: Tenant, ctx: Ctx, r: unknown, mandate: unknown, approval?: unknown): Promise<void> {
  const problem = revocationProblem(r);
  if (problem) throw new HttpError(400, `revocation rejected: ${problem}`);
  const rd = r as J;
  if (new TextEncoder().encode(canonicalText(r)).byteLength > MAX_REVOCATION) {
    throw new HttpError(400, `revocation rejected: larger than ${MAX_REVOCATION} bytes`);
  }
  // Every link of the chain must be for the mandate's company: the authority table is asked per company.
  const md = isDict(mandate) ? mandate : {};
  const company = isDict(md.company) ? md.company.name : undefined;
  const chain = Array.isArray(md.delegation) ? (md.delegation as unknown[]) : [];
  if (chain.some((d) => !isDict(d) || !isDict(d.company) || d.company.name !== company)) {
    throw new HttpError(400, "revocation rejected: a delegation link is for another company");
  }
  const signer = isDict(rd.signer) ? String(rd.signer.public_key) : "";
  if (!ctx.limiter.allow(`revoke:${t.id}:${signer}`, REVOCATIONS_PER_SIGNER_PER_MIN)) {
    throw new HttpError(429, "too many revocations from this signer; try again in a minute");
  }
  let counts: boolean;
  try {
    counts = await (await checkerFor(t, ctx, mandate, false)).revocationCounts(mandate, r, approval);
  } catch {
    counts = false;
  }
  if (!counts) {
    throw new HttpError(400, "revocation rejected: not a valid revocation of this mandate by someone who may revoke it");
  }
  // revocationCounts matched the target: the mandate itself, one link of its chain, or the given payee approval.
  let target: string, until: string | null;
  if (typeof rd.payee_approval_hash === "string") {
    target = rd.payee_approval_hash;
    const a = approval as J; // revocationCounts verified it names this mandate and has this hash
    // Moot once the approval or its mandate has expired, whichever comes first.
    const mu = typeof md.valid_until === "string" ? md.valid_until : null;
    until = typeof a.valid_until === "string" && (mu === null || Date.parse(a.valid_until) < Date.parse(mu)) ? a.valid_until : mu;
  } else {
    target = typeof rd.mandate_hash === "string" ? rd.mandate_hash : rd.delegation_hash as string;
    const obj = typeof rd.mandate_hash === "string" ? md
      : (chain as J[]).find((d) => { try { return delegationHash(d) === target; } catch { return false; } });
    until = obj && typeof obj.valid_until === "string" ? obj.valid_until : null;
  }
  await storeCall(() => addRevocation(ctx.deps.kv, t.id, target, rd, until, ctx.now().getTime(), canonicalText));
}

/**
 * Default for RELEASE_WINDOW_HOURS: 0, release is off unless the operator turns it on. Release trusts the check key
 * holder's word that the bank did not execute an allowed payment, and each released allow frees its amount from the
 * period limit, so with fresh payment ids a key holder could keep claiming non-execution and get past the limit.
 * Turn it on only where the check key holder is the party executing the payments.
 */
export const RELEASE_WINDOW_HOURS = 0;
const MAX_RELEASE_WINDOW_HOURS = 24 * 31;

/** The release window in microseconds; 0 disables /v1/release. A bad setting is 503 (never a guess). */
function releaseWindow(ctx: Ctx): bigint {
  const raw = (ctx.deps.env.RELEASE_WINDOW_HOURS ?? "").trim();
  if (raw === "") return BigInt(RELEASE_WINDOW_HOURS) * 3600n * 1_000_000n;
  if (!/^\d{1,4}$/.test(raw) || Number(raw) > MAX_RELEASE_WINDOW_HOURS) {
    throw new HttpError(503, "checker not configured (RELEASE_WINDOW_HOURS)");
  }
  return BigInt(raw) * 3600n * 1_000_000n;
}

/**
 * The bank did not execute an allowed payment: give back the period reservations the allow made, once, and keep
 * the payment id used.
 *
 * - Bound to the decision by its hash, which must be one this tenant's checker signed, an allow naming exactly this
 *   payment and mandate, and the one the payment log holds for this payment now.
 * - Off by default (RELEASE_WINDOW_HOURS unset or 0: 403). When on, only within RELEASE_WINDOW_HOURS of the decision's `checked_at`, and only while every limit period
 *   it reserved in (the mandate's, and each delegation link's with a period limit) is still the current one. Later
 *   the reservation stands.
 * - The payment id is NOT freed: the payment log keeps the key claimed and records the release, so the same payment
 *   (or any other under its id) sent again is blocked `duplicate_payment`. A payment that is to be tried again
 *   needs a new id, checked afresh against the limits.
 * - Idempotent: the result is stored in a release marker keyed by the decision hash, written first; a repeated call
 *   answers exactly that result and releases nothing (also after the window closed).
 *
 * If the store fails half way (503), what is left is stricter, never looser: reservations stay reserved, and the
 * payment log keeps either the allow or the released claim.
 */
async function releaseFor(t: Tenant, ctx: Ctx, mandate: unknown, payment: unknown, decision: unknown): Promise<J> {
  const window = releaseWindow(ctx);
  if (window === 0n) throw new HttpError(403, "release is disabled on this checker (set RELEASE_WINDOW_HOURS to enable)");
  if (mandateProblem(mandate) || paymentProblem(payment)) throw new HttpError(400, "release rejected: malformed mandate or payment");
  const m = mandate as J, p = payment as J;
  if (!verifyDecision(decision, [t.public_key])) throw new HttpError(400, "release rejected: not a decision of this checker");
  const d = decision as J;
  const pHash = objHash(p, "agent_sig"), mh = mandateHash(m);
  const ref = (v: unknown) => (isDict(v) ? v : {});
  if (d.outcome !== "allow" || ref(d.payment).id !== p.id || ref(d.payment).hash !== pHash || ref(d.mandate).hash !== mh
    || ref(p.mandate).hash !== mh) {
    throw new HttpError(400, "release rejected: the decision is not an allow of this payment under this mandate");
  }
  const dh = objHash(d);
  // Released before: the same answer again, nothing released twice.
  const before = await storeCall(() => wasReleased(ctx.deps.kv, t.id, dh));
  if (before !== null && isDict(before.result)) return before.result;

  let customer: string | null;
  try {
    const c = await holdsOf(t.authority)(m.company as J, p.from_account as J);
    customer = typeof c === "string" && c ? c : null;
  } catch {
    customer = null;
  }
  if (customer === null) throw new HttpError(400, "release rejected: this tenant does not hold the debtor account");

  // The window: within RELEASE_WINDOW_HOURS of the decision, and in the limit periods it reserved in.
  const nowUs = BigInt(ctx.now().getTime()) * 1000n;
  const at = BigInt(Date.parse(String(d.checked_at))) * 1000n;
  if (nowUs - at > window) {
    throw new HttpError(409, `release rejected: the decision is older than the release window (${window / 3_600_000_000n} hours)`);
  }
  // What step 23 reserved: only when the allow went through it (within_period_limit, or approved over the limit).
  const checks = Array.isArray(d.checks) ? d.checks : [];
  const reserved = checks.includes("within_period_limit") || checks.includes("over_period_limit_approved");
  const wanted: [string, string][] = [];
  if (reserved) {
    const chain = Array.isArray(m.delegation) ? (m.delegation as J[]) : [];
    const periodOf = (sc: unknown) => (isDict(sc) && isDict(sc.max_per_period) ? String(sc.max_per_period.period) : null);
    const mp = periodOf(m.scope);
    if (mp !== null) wanted.push([`mandate:${mh}`, mp]);
    for (const link of chain) {
      const lp = periodOf(link.scope);
      if (lp !== null) wanted.push([`delegation:${delegationHash(link)}`, lp]);
    }
    if (wanted.some(([, period]) => periodKey(period, at) !== periodKey(period, nowUs))) {
      throw new HttpError(409, "release rejected: the limit period the reservation was made in has ended");
    }
  }

  const key = paymentKey(customer, p.id as string);
  const log = new KVPaymentLog(ctx.deps.kv, t.id);
  const held = await storeCall(() => log.lookup(key, pHash));
  if (!isDict(held) || held.id !== d.id || objHash(held) !== dh) {
    throw new HttpError(409, "release rejected: this checker does not hold this allow for this payment");
  }
  const result: J = {
    released: true, checker: t.checker, decision: { id: d.id, hash: dh }, payment: { id: p.id, hash: pHash },
    reservations: wanted.map(([k]) => k), payment_id: "held", released_at: ctx.now().toISOString(),
  };
  // Marker first, holding the answer: exactly one caller goes on; any other (or later) one gets this result.
  const first = await storeCall(() => markReleased(ctx.deps.kv, t.id, dh, { result }));
  if (!first) {
    const won = await storeCall(() => wasReleased(ctx.deps.kv, t.id, dh));
    if (won !== null && isDict(won.result)) return won.result;
    throw new HttpError(503, "store unavailable");
  }
  // Keep the payment id claimed, recording the release, so the allow is no longer served and the id stays used.
  const kept = await storeCall(() => log.holdReleased(key, pHash, (x) => x.id === d.id && objHash(x) === dh,
    { decision: { id: d.id, hash: dh }, at: result.released_at }));
  if (!kept) throw new HttpError(503, "store unavailable: the payment log changed meanwhile; reservations stay");
  const ledger = new KVLedger(ctx.deps.kv, t.id);
  const amount = parseAmount(p.amount, p.currency);
  for (const [k, period] of wanted) await storeCall(() => ledger.release(k, period, amount, at));
  return result;
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
    if (!isDict(body) || !Object.keys(body).every((k) => k === "id" || k === "authority")) {
      throw new HttpError(400, 'expected {["id": "<tenant id>"][, "authority": {...}]}');
    }
    const id = body.id ?? `t-${randomBytes(8).toString("hex")}`;
    if (!tenantIdOk(id)) throw new HttpError(400, "id must be 3 to 40 of a-z, 0-9 and single hyphens, e.g. \"acme-psp\"");
    const authority = (body.authority ?? EMPTY_AUTHORITY) as AuthorityDoc;
    const problem = authorityProblem(authority);
    if (problem) throw new HttpError(400, problem);
    const seed = newSeed();
    const check = ctx.secrets.newApiKey(id, "check"), kyb = ctx.secrets.newApiKey(id, "kyb");
    const t: Tenant = {
      v: 1, id, checker: `sandbox:${id}`, created_at: ctx.now().toISOString(), public_key: publicKeyOf(seed),
      seed: ctx.secrets.sealSeed(seed, id), api_key_hash: check.hash, kyb_key_hash: kyb.hash, authority,
      authority_version: 1, authority_hash: h(canonicalText(authority)),
    };
    if (!(await storeCall(() => createTenant(kv, t)))) throw new HttpError(409, "tenant exists");
    await storeCall(() => logAuthority(kv, id, 1, { at: t.created_at, by: "admin", hash: t.authority_hash, authority: authority as unknown as J }));
    return json(201, {
      id: t.id, checker: t.checker, public_key: t.public_key, api_key: check.key, kyb_key: kyb.key,
      keys: `/t/${t.id}/keys`, keyset: `/t/${t.id}/.well-known/gleipnir-checker.json`,
      note: "api_key checks payments; kyb_key only maintains the authority table. Both are shown once; only "
        + "their hashes are stored. Tenant ids appear in public URLs. " + SANDBOX_NOTICE,
    }, { "Gleipnir-Checker": t.checker });
  }

  if (!tenantIdOk(tid)) throw new HttpError(404, "not found");

  if (what === undefined) { // DELETE /v1/admin/tenants/<id>: the tenant and all its data, admin only
    if (method !== "DELETE") throw new HttpError(405, "method not allowed");
    if (!admin) failedAuth(ctx);
    const n = await storeCall(() => deleteTenant(kv, tid));
    if (n === 0) throw new HttpError(404, "not found");
    return json(200, { deleted: true, id: tid, keys: n,
      note: "The tenant, its keys, authority table and log, payment log, ledger, revocations and release markers "
        + "are deleted. Decisions it signed can no longer be verified against /t/<id>/keys." });
  }

  if (what === "api-key" || what === "kyb-key") { // admin only
    if (method !== "POST") throw new HttpError(405, "method not allowed");
    if (!admin) failedAuth(ctx);
    const kind = what === "api-key" ? "check" : "kyb";
    const { key, hash } = ctx.secrets.newApiKey(tid, kind);
    const res = await storeCall(() => changeTenant(kv, tid, (t) =>
      kind === "check" ? { ...t, api_key_hash: hash } : { ...t, kyb_key_hash: hash }));
    if (res !== "ok") throw new HttpError(404, "not found");
    return json(200, { id: tid, [kind === "check" ? "api_key" : "kyb_key"]: key, note: "Shown once; the previous key no longer works." });
  }

  // The authority table: the admin, or the tenant's KYB key (never its check key).
  let kybHash: string | null = null;
  if (!admin) {
    const key = bearer(req);
    if (key !== null && tenantOfKey(key, "kyb") === tid) {
      const t = await storeCall(() => loadTenant(kv, tid));
      if (t !== null && typeof t.kyb_key_hash === "string" && ctx.secrets.keyMatches(key, t.kyb_key_hash)) kybHash = t.kyb_key_hash;
    }
    if (kybHash === null) failedAuth(ctx);
    if (!ctx.limiter.allow(`kyb:${tid}`, perMinute(ctx))) throw new HttpError(429, "too many requests");
  }
  const t = await storeCall(() => loadTenant(kv, tid));
  if (t === null) throw new HttpError(404, "not found");
  if (method === "GET") return json(200, t.authority, { "Gleipnir-Checker": t.checker });
  if (method !== "PUT") throw new HttpError(405, "method not allowed");
  const doc = await readBody(req);
  const problem = authorityProblem(doc);
  if (problem) throw new HttpError(400, problem);
  const version = (t.authority_version ?? 1) + 1;
  const hash = h(canonicalText(doc));
  // Log first (append-only), then switch the table only if nothing changed meanwhile and the key still holds.
  await storeCall(() => logAuthority(kv, tid, version, { at: ctx.now().toISOString(), by: admin ? "admin" : "kyb_key",
    hash, previous_hash: t.authority_hash ?? null, authority: doc as J }));
  const res = await storeCall(() => changeTenant(kv, tid, (cur) => {
    if ((cur.authority_version ?? 1) !== version - 1) return null;
    if (kybHash !== null && cur.kyb_key_hash !== kybHash) return null;
    return { ...cur, authority: doc as AuthorityDoc, authority_version: version, authority_hash: hash };
  }));
  if (res === "missing") throw new HttpError(404, "not found");
  if (res === "aborted") throw new HttpError(409, "the authority table or the key changed meanwhile; read it again and retry");
  return json(200, { ok: true, checker: t.checker, version, hash, signers: (doc as AuthorityDoc).signers.length,
    accounts: (doc as AuthorityDoc).accounts.length });
}
