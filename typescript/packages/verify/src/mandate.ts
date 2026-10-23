/**
 * Mandates for AI agents that pay (spec/mandate.md v0.1), TypeScript port of the Python reference
 * `gleipnir_verify.mandate`. Same hashes, signatures, check order and reason codes; conformance is
 * pinned by the shared vectors in test/fixtures/mandate-vectors.json.
 *
 * A company signatory signs a mandate for one agent. The bank checks every payment the agent starts
 * against it and signs a decision: allow, block or escalate.
 *
 * Wiring a Checker (all are the bank's own systems; each may be sync or async):
 * - `authority(company, signerId)`: who may sign for the company and with which keys, from the bank's
 *   KYB records, a company register or vLEI. Never from the mandate.
 * - `payments`: payment log for idempotency (`InMemoryPaymentLog` for tests; persistent in production).
 * - `ledger`: atomic period ledger (`InMemoryLedger` for tests). Required for mandates with a period limit.
 *
 * Amounts are handled as bigint minor units (cents; yen for JPY), never as floats.
 */

import { b64uEncode, hexToBytes, utf8, concatBytes } from "./bytes.js";
import { canonicalize, hashToBytes, sha256Tagged } from "./canon.js";
import { decodePublicKey, ed25519PublicFromSeed, ed25519Sign, encodePublicKey, verifySignature } from "./crypto.js";
import { webauthnProblem } from "./approvals.js";
import { hasKey, isDict, type JsonDict } from "./py.js";
import { isoMillis, microsFromDate, parseTime, type Micros } from "./time.js";

export const MANDATE_VERSION = "0.1";
const V = MANDATE_VERSION;
export const RAILS: ReadonlySet<string> = new Set(["sepa", "sepa_instant", "ach", "wire", "faster_payments", "fednow", "rtp"]);
export const PERIODS: ReadonlySet<string> = new Set(["P1D", "P7D", "P1M"]);
/** ISO 4217 minor units of the currencies supported in 0.1. */
export const MINOR_UNITS: Readonly<Record<string, number>> = {
  EUR: 2, USD: 2, GBP: 2, CHF: 2, SEK: 2, NOK: 2, DKK: 2, PLN: 2, CZK: 2, HUF: 2, JPY: 0,
};
const AMOUNT_RE: Record<number, RegExp> = { 0: /^(0|[1-9][0-9]*)$/, 2: /^(0|[1-9][0-9]*)\.[0-9]{2}$/ };
export const ESCALATE: ReadonlySet<string> = new Set([
  "signer_unknown", "status_unavailable", "over_payment_limit", "over_period_limit", "ledger_missing", "checker_unavailable",
]);

export type Outcome = "allow" | "block" | "escalate";
export type Awaitable<T> = T | Promise<T>;

// ---------- hashing and signing ----------

/** sha256 over the JCS encoding of the object without its signature field. */
export function objHash(obj: JsonDict, sigField = "sig"): string {
  const body: JsonDict = {};
  for (const k of Object.keys(obj)) if (k !== sigField) body[k] = obj[k];
  return sha256Tagged(canonicalize(body));
}

/** The exact bytes a signature of this kind covers: "gleipnir/<kind>/v0.1\n" + hash. */
export function mandateMessage(kind: string, hash: string): Uint8Array {
  return concatBytes(utf8(`gleipnir/${kind}/v${V}\n`), utf8(hash));
}

/** An Ed25519 private key as its 32-byte seed. */
export type Seed = Uint8Array;

export function newSeed(): Seed {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

export function publicKeyOf(seed: Seed): string {
  return encodePublicKey(ed25519PublicFromSeed(seed));
}

export function seedFromHex(hex: string): Seed {
  const s = hexToBytes(hex);
  if (s.length !== 32) throw new Error("an Ed25519 seed is 32 bytes");
  return s;
}

function sign(seed: Seed, kind: string, obj: JsonDict, sigField = "sig"): JsonDict {
  const out: JsonDict = {};
  for (const k of Object.keys(obj)) if (k !== sigField) out[k] = obj[k];
  out[sigField] = "ed25519:" + b64uEncode(ed25519Sign(seed, mandateMessage(kind, objHash(out, sigField))));
  return out;
}

export function fmtTs(t: Micros): string {
  return isoMillis(t);
}

function nowMicros(): Micros {
  return microsFromDate(new Date());
}

/** Strict RFC 3339 in UTC (`YYYY-MM-DDTHH:MM:SS[.ffffff]Z`), same grammar as the Python reference. */
function ts(text: unknown): Micros {
  if (typeof text !== "string" || !text.endsWith("Z")) throw new Error(`bad timestamp: ${JSON.stringify(text)}`);
  return parseTime(text);
}

/** A strictly formatted, positive amount as bigint minor units, else throws. */
export function parseAmount(text: unknown, currency: unknown): bigint {
  if (typeof currency !== "string" || !Object.prototype.hasOwnProperty.call(MINOR_UNITS, currency)) {
    throw new Error(`unsupported currency: ${JSON.stringify(currency)}`);
  }
  const units = MINOR_UNITS[currency]!;
  if (typeof text !== "string" || !AMOUNT_RE[units]!.test(text)) {
    throw new Error(`bad amount for ${currency}: ${JSON.stringify(text)}`);
  }
  const v = BigInt(text.replace(".", ""));
  if (v <= 0n) throw new Error(`amount must be positive: ${JSON.stringify(text)}`);
  return v;
}

/** Python `str(v)` for the JSON scalars an account field can hold. */
function pyStr(v: unknown): string {
  if (typeof v === "string") return v;
  if (v === true) return "True";
  if (v === false) return "False";
  if (v === null) return "None";
  return typeof v === "number" ? String(v) : JSON.stringify(v);
}

export function normAccount(acc: JsonDict): string {
  if (hasKey(acc, "iban")) return JSON.stringify({ iban: pyStr(acc.iban).replaceAll(" ", "").toUpperCase() });
  const keys = Object.keys(acc).sort();
  return JSON.stringify(keys.map((k) => [k, pyStr(acc[k]).replaceAll(" ", "")]));
}

// ---------- issuing ----------

export interface IssueOptions {
  id: string;
  company: JsonDict;
  agent: JsonDict;
  signer: JsonDict;
  scope: JsonDict;
  validUntil: string;
  validFrom?: string;
  statusUrl?: string;
}

/** An unsigned mandate. Sign it with signMandate() or a passkey. */
export function issue(o: IssueOptions): JsonDict {
  const m: JsonDict = {
    v: `gleipnir/mandate/${V}`, id: o.id, company: o.company, agent: o.agent, signer: o.signer, scope: o.scope,
    valid_until: o.validUntil, issued_at: fmtTs(nowMicros()),
  };
  if (o.validFrom) m.valid_from = o.validFrom;
  if (o.statusUrl) m.status_url = o.statusUrl;
  const problem = mandateProblem(m);
  if (problem) throw new Error(problem);
  return m;
}

export function signMandate(mandate: JsonDict, seed: Seed): JsonDict {
  return sign(seed, "mandate", mandate);
}

/** The WebAuthn challenge a signatory's passkey signs: the 32 raw bytes of the mandate hash. */
export function passkeyChallenge(mandate: JsonDict): Uint8Array {
  return hashToBytes(objHash(mandate));
}

export function revoke(
  mandate: JsonDict,
  o: { signer: JsonDict; seed: Seed; id: string; reason?: string; revokedAt?: string },
): JsonDict {
  const r: JsonDict = {
    v: `gleipnir/revocation/${V}`, id: o.id, mandate: mandate.id, mandate_hash: objHash(mandate),
    revoked_at: o.revokedAt ?? fmtTs(nowMicros()), signer: o.signer,
  };
  if (o.reason) r.reason = o.reason;
  return sign(o.seed, "revocation", r);
}

/** A payment that relies on this mandate, signed by the agent when the mandate names an agent key. */
export function attach(
  mandate: JsonDict,
  o: {
    id: string; rail: string; amount: string; currency: string; payee: JsonDict; reference?: string;
    agentSeed?: Seed; requestedAt?: string;
  },
): JsonDict {
  let p: JsonDict = {
    v: `gleipnir/payment/${V}`, id: o.id, mandate: { id: mandate.id, hash: objHash(mandate) },
    rail: o.rail, amount: o.amount, currency: o.currency, payee: o.payee, requested_at: o.requestedAt ?? fmtTs(nowMicros()),
  };
  if (o.reference) p.reference = o.reference;
  if (o.agentSeed) p = sign(o.agentSeed, "payment", p, "agent_sig");
  return p;
}

// ---------- validation ----------

function get(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const part of path.split(".")) cur = isDict(cur) && hasKey(cur, part) ? cur[part] : null;
  return cur;
}

function strFields(obj: unknown, paths: readonly string[]): string | null {
  for (const p of paths) {
    const v = get(obj, p);
    if (typeof v !== "string" || !v) return `missing ${p}`;
  }
  return null;
}

function jcsOk(obj: unknown): boolean {
  try {
    canonicalize(obj);
    return true;
  } catch {
    return false;
  }
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Why this is not a well-formed mandate, or null. */
export function mandateProblem(m: unknown): string | null {
  if (!isDict(m) || m.v !== `gleipnir/mandate/${V}`) return "unknown mandate version";
  const bad = strFields(m, ["id", "company.name", "company.country", "agent.id", "signer.id", "signer.public_key",
    "scope.currency", "scope.max_per_payment", "valid_until"]);
  if (bad) return bad;
  if (!jcsOk(m)) return "mandate is not valid I-JSON";
  const sc = m.scope as JsonDict;
  try {
    parseAmount(sc.max_per_payment, sc.currency);
    if (hasKey(sc, "max_per_period")) {
      const per = sc.max_per_period;
      if (!isDict(per) || typeof per.period !== "string" || !PERIODS.has(per.period)) {
        return "max_per_period needs a period of P1D, P7D or P1M";
      }
      parseAmount(per.amount, sc.currency);
    }
    const until = ts(m.valid_until);
    if (hasKey(m, "valid_from") && ts(m.valid_from) > until) return "valid_from is after valid_until";
  } catch (e) {
    return msg(e);
  }
  const rails = hasKey(sc, "rails") ? sc.rails : [];
  if (!Array.isArray(rails) || !rails.every((r) => typeof r === "string")) return "rails must be a list of strings";
  const unknown = [...new Set(rails as string[])].filter((r) => !RAILS.has(r)).sort();
  if (unknown.length) return `unknown rails: ${JSON.stringify(unknown)}`;
  const payees = hasKey(sc, "payees") ? sc.payees : [];
  if (!Array.isArray(payees) || !payees.every((x) => isDict(x) && isDict(x.account) && Object.keys(x.account).length > 0)) {
    return "every payee needs an account object";
  }
  if (hasKey(m, "status_url") && typeof m.status_url !== "string") return "status_url must be a string";
  return null;
}

/** Why this is not a well-formed payment, or null. */
export function paymentProblem(p: unknown): string | null {
  if (!isDict(p) || p.v !== `gleipnir/payment/${V}`) return "unknown payment version";
  const bad = strFields(p, ["id", "mandate.id", "mandate.hash", "rail", "currency", "requested_at"]);
  if (bad) return bad;
  const acc = get(p, "payee.account");
  if (!isDict(acc) || Object.keys(acc).length === 0) return "missing payee.account";
  if (!jcsOk(p)) return "payment is not valid I-JSON";
  try {
    parseAmount(hasKey(p, "amount") ? p.amount : null, p.currency);
    ts(p.requested_at);
  } catch (e) {
    return msg(e);
  }
  return null;
}

export function revocationProblem(r: unknown): string | null {
  if (!isDict(r) || r.v !== `gleipnir/revocation/${V}`) return "unknown revocation version";
  const bad = strFields(r, ["id", "mandate", "mandate_hash", "revoked_at", "signer.id", "signer.public_key"]);
  if (bad || !jcsOk(r)) return bad ?? "revocation is not valid I-JSON";
  try {
    ts(r.revoked_at);
  } catch (e) {
    return msg(e);
  }
  return null;
}

// ---------- the bank's systems ----------

/** What an authority source (bank KYB, register, vLEI) says about one person at one company. */
export interface AuthorityResult {
  source: string; // "bank_kyb", "register", "vlei"
  keys: readonly string[]; // public keys the source binds to this person
  maySign?: boolean; // default true
}

/** authority(company, signerId) -> AuthorityResult, or null if no source knows the person. */
export type Authority = (company: JsonDict, signerId: string) => Awaitable<AuthorityResult | null>;

export interface PaymentLog {
  /**
   * Atomically register a payment id. null: new (now registered). A decision: this id and hash were
   * decided before. "duplicate": the id is known with another hash, or is still being checked.
   */
  seen(paymentId: string, paymentHash: string): Awaitable<JsonDict | "duplicate" | null>;
  /** Store the decision for a registered payment id. */
  remember(paymentId: string, decision: JsonDict): Awaitable<void>;
}

export interface Ledger {
  /** Atomically add amount (minor units) to the period total if the total stays within limit. */
  reserve(mandateId: string, period: string, amount: bigint, limit: bigint, at: Micros): Awaitable<boolean>;
}

/** Payment log for tests and demos. Production needs a persistent, shared store. */
export class InMemoryPaymentLog implements PaymentLog {
  private items = new Map<string, { hash: string; decision: JsonDict | null }>();

  seen(paymentId: string, paymentHash: string): JsonDict | "duplicate" | null {
    const e = this.items.get(paymentId);
    if (e === undefined) {
      this.items.set(paymentId, { hash: paymentHash, decision: null });
      return null;
    }
    return e.hash === paymentHash && e.decision !== null ? e.decision : "duplicate";
  }

  remember(paymentId: string, decision: JsonDict): void {
    const e = this.items.get(paymentId);
    if (e) e.decision = decision;
  }
}

function pad(n: number, w = 2): string {
  return String(n).padStart(w, "0");
}

/** The calendar period (UTC) a time falls in: 2026-10-23, 2026-W43 (ISO week) or 2026-10. */
export function periodKey(period: string, at: Micros): string {
  const d = new Date(Number(at / 1000n));
  const y = d.getUTCFullYear(), mo = d.getUTCMonth() + 1, day = d.getUTCDate();
  if (period === "P1D") return `${pad(y, 4)}-${pad(mo)}-${pad(day)}`;
  if (period === "P1M") return `${pad(y, 4)}-${pad(mo)}`;
  if (period === "P7D") {
    const t = new Date(Date.UTC(y, mo - 1, day));
    const dow = t.getUTCDay() || 7;
    t.setUTCDate(t.getUTCDate() + 4 - dow); // Thursday of this ISO week decides the year
    const isoYear = t.getUTCFullYear();
    const week = Math.ceil(((t.getTime() - Date.UTC(isoYear, 0, 1)) / 86_400_000 + 1) / 7);
    return `${pad(isoYear, 4)}-W${pad(week)}`;
  }
  throw new Error(`unknown period ${JSON.stringify(period)}`);
}

/** Period ledger for tests and demos: calendar periods in UTC. */
export class InMemoryLedger implements Ledger {
  readonly totals = new Map<string, bigint>();

  reserve(mandateId: string, period: string, amount: bigint, limit: bigint, at: Micros): boolean {
    const key = `${mandateId}|${periodKey(period, at)}`;
    const total = (this.totals.get(key) ?? 0n) + amount;
    if (total > limit) return false;
    this.totals.set(key, total);
    return true;
  }

  release(mandateId: string, period: string, amount: bigint, at: Micros): void {
    const key = `${mandateId}|${periodKey(period, at)}`;
    const total = (this.totals.get(key) ?? 0n) - amount;
    this.totals.set(key, total < 0n ? 0n : total);
  }
}

class Stop extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

// ---------- checking ----------

export interface CheckerOptions {
  id: string;
  /** The bank's Ed25519 signing key (32-byte seed). */
  seed: Seed;
  authority: Authority;
  ledger?: Ledger | null;
  payments?: PaymentLog;
  revocations?: readonly unknown[];
  /** status(url) -> "active" | "revoked"; throws (or rejects) when unreachable. */
  status?: ((url: string) => Awaitable<string>) | null;
  clock?: () => Date;
  maxSkewMs?: number;
  webauthn?: { rpId?: string; origins?: readonly string[] };
}

export class Checker {
  readonly id: string;
  readonly publicKey: string;
  private readonly seed: Seed;
  private readonly authority: Authority;
  private readonly ledger: Ledger | null;
  private readonly payments: PaymentLog;
  revocations: unknown[];
  private readonly status: ((url: string) => Awaitable<string>) | null;
  private readonly clock: () => Date;
  private readonly maxSkew: Micros;
  private readonly webauthn: { rpId?: string; origins?: readonly string[] };

  constructor(o: CheckerOptions) {
    this.id = o.id;
    this.seed = o.seed;
    this.publicKey = publicKeyOf(o.seed);
    this.authority = o.authority;
    this.ledger = o.ledger ?? null;
    this.payments = o.payments ?? new InMemoryPaymentLog();
    this.revocations = [...(o.revocations ?? [])];
    this.status = o.status ?? null;
    this.clock = o.clock ?? (() => new Date());
    this.maxSkew = BigInt(Math.round(o.maxSkewMs ?? 60_000)) * 1000n;
    this.webauthn = o.webauthn ?? {};
  }

  private sigOk(kind: string, obj: JsonDict, pubText: unknown, sigField = "sig"): boolean {
    try {
      const pub = decodePublicKey(pubText);
      const sig = hasKey(obj, sigField) ? obj[sigField] : null;
      const h = objHash(obj, sigField);
      if (isDict(sig) && sig.type === "webauthn" && kind === "mandate") {
        return webauthnProblem(sig, pub, h, this.webauthn.rpId ?? "", this.webauthn.origins ?? [], null) === null;
      }
      return verifySignature(pub, mandateMessage(kind, h), sig);
    } catch {
      return false; // any malformed key or signature fails closed
    }
  }

  /** The source's answer for this signer, checked against the key the signer used. Throws Stop. */
  private async authorized(company: JsonDict, signer: JsonDict): Promise<AuthorityResult> {
    let res: AuthorityResult | null;
    try {
      res = await this.authority(company, signer.id as string);
    } catch {
      throw new Stop("checker_unavailable");
    }
    if (res === null || res === undefined) throw new Stop("signer_unknown");
    if (typeof res !== "object" || typeof res.source !== "string" || !Array.isArray(res.keys)) throw new Stop("checker_unavailable");
    if (res.maySign === false || !res.keys.includes(signer.public_key as string)) throw new Stop("signer_not_authorized");
    return res;
  }

  /** Check one payment against one mandate. Never throws on input; always resolves to a signed decision. */
  async check(mandate: unknown, payment: unknown): Promise<JsonDict> {
    const at = microsFromDate(this.clock());
    const checks: string[] = [];
    const state = { registered: false };
    const pHash = isDict(payment) && jcsOk(payment) ? objHash(payment, "agent_sig") : null;
    let reason: string | JsonDict | null;
    try {
      reason = await this.run(mandate, payment, pHash, at, checks, state);
    } catch (e) {
      reason = e instanceof Stop ? e.reason : "payment_malformed"; // unexpected input never allows
    }
    if (isDict(reason)) return reason; // idempotent retry: the earlier decision, unchanged
    const d = this.decision(mandate, payment, pHash, reason, checks, at);
    if (state.registered) {
      try {
        await this.payments.remember((payment as JsonDict).id as string, d);
      } catch {
        // the decision still stands; the log is the bank's to fix
      }
    }
    return d;
  }

  private decision(m: unknown, p: unknown, pHash: string | null, reason: string | null, checks: string[], at: Micros): JsonDict {
    const outcome: Outcome = reason === null ? "allow" : ESCALATE.has(reason) ? "escalate" : "block";
    const pid = isDict(p) && typeof p.id === "string" ? p.id : null;
    const mid = isDict(m) && typeof m.id === "string" ? m.id : null;
    const mh = isDict(m) && jcsOk(m) ? objHash(m) : null;
    const rnd = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const d: JsonDict = {
      v: `gleipnir/decision/${V}`, id: "d_" + [...rnd].map((b) => b.toString(16).padStart(2, "0")).join(""),
      payment: { id: pid, hash: pHash }, mandate: { id: mid, hash: mh }, outcome, reasons: reason ? [reason] : [],
      checks, checked_at: fmtTs(at), checker: { id: this.id, public_key: this.publicKey },
    };
    return sign(this.seed, "decision", d);
  }

  private async run(
    m: unknown, p: unknown, pHash: string | null, at: Micros, checks: string[], state: { registered: boolean },
  ): Promise<string | JsonDict | null> {
    if (mandateProblem(m)) return "mandate_malformed";
    if (pHash === null || paymentProblem(p)) return "payment_malformed";
    const md = m as JsonDict, pd = p as JsonDict;
    let prior: JsonDict | "duplicate" | null;
    try {
      prior = await this.payments.seen(pd.id as string, pHash);
    } catch {
      return "checker_unavailable";
    }
    if (isDict(prior)) return prior;
    if (prior !== null && prior !== undefined) return "duplicate_payment";
    state.registered = true;
    const mh = objHash(md);
    if ((pd.mandate as JsonDict).hash !== mh) return "mandate_mismatch";
    const skew = ts(pd.requested_at) - at;
    if ((skew < 0n ? -skew : skew) > this.maxSkew) return "clock_skew";
    const signer = md.signer as JsonDict;
    if (!this.sigOk("mandate", md, signer.public_key)) return "mandate_bad_signature";
    checks.push("mandate_valid");
    const src = await this.authorized(md.company as JsonDict, signer);
    checks.push(`signer_authorized:${src.source}`);
    if (hasKey(md, "valid_from") && at < ts(md.valid_from)) return "mandate_not_yet_valid";
    if (at > ts(md.valid_until)) return "mandate_expired";
    if (await this.revoked(md, mh, at)) return "mandate_revoked";
    if (hasKey(md, "status_url")) {
      if (this.status === null) return "status_unavailable";
      let st: string;
      try {
        st = await this.status(md.status_url as string);
      } catch {
        return "status_unavailable";
      }
      if (st === "revoked") return "mandate_revoked";
      if (st !== "active") return "status_unavailable";
    }
    checks.push("not_revoked");
    const agent = md.agent as JsonDict;
    if (hasKey(agent, "public_key")) {
      if (!this.sigOk("payment", pd, agent.public_key, "agent_sig")) return "agent_bad_signature";
      checks.push("agent_signed");
    }
    const sc = md.scope as JsonDict;
    if (hasKey(sc, "rails") && !(sc.rails as string[]).includes(pd.rail as string)) return "rail_not_allowed";
    if (pd.currency !== sc.currency) return "currency_mismatch";
    if (hasKey(sc, "payees")) {
      const want = normAccount((pd.payee as JsonDict).account as JsonDict);
      if (!(sc.payees as JsonDict[]).some((x) => normAccount(x.account as JsonDict) === want)) return "payee_not_on_mandate";
      checks.push("payee_on_mandate");
    }
    const amt = parseAmount(pd.amount, pd.currency);
    if (amt > parseAmount(sc.max_per_payment, sc.currency)) return "over_payment_limit";
    checks.push("within_payment_limit");
    if (hasKey(sc, "max_per_period")) {
      const per = sc.max_per_period as JsonDict;
      if (this.ledger === null) return "ledger_missing";
      let ok: boolean;
      try {
        ok = await this.ledger.reserve(md.id as string, per.period as string, amt, parseAmount(per.amount, sc.currency), at);
      } catch {
        return "checker_unavailable";
      }
      if (!ok) return "over_period_limit";
      checks.push("within_period_limit");
    }
    return null;
  }

  private async revoked(m: JsonDict, mh: string, at: Micros): Promise<boolean> {
    for (const r of this.revocations) {
      if (revocationProblem(r)) continue;
      const rd = r as JsonDict;
      if (rd.mandate_hash !== mh || ts(rd.revoked_at) > at) continue;
      const signer = rd.signer as JsonDict;
      if (!this.sigOk("revocation", rd, signer.public_key)) continue;
      try {
        await this.authorized(m.company as JsonDict, signer);
      } catch (e) {
        if (e instanceof Stop && e.reason === "checker_unavailable") throw e;
        continue;
      }
      return true;
    }
    return false;
  }
}

/**
 * True if the decision was signed by one of the bank's known checker keys and not changed since.
 * checkerKeys come from the bank (its published key list), never from the decision itself.
 */
export function verifyDecision(decision: unknown, checkerKeys: Iterable<string>): boolean {
  const keys = new Set(checkerKeys);
  try {
    if (!isDict(decision) || !isDict(decision.checker)) return false;
    const pubText = decision.checker.public_key;
    if (typeof pubText !== "string" || !keys.has(pubText)) return false;
    return verifySignature(decodePublicKey(pubText), mandateMessage("decision", objHash(decision)),
      hasKey(decision, "sig") ? decision.sig : null);
  } catch {
    return false;
  }
}
