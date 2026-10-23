/**
 * Mandates for AI agents that pay (spec/mandate.md v0.2), TypeScript port of the Python reference
 * `gleipnir_verify.mandate`. Same hashes, signatures, check order and reason codes; conformance is
 * pinned by the shared vectors in test/fixtures/mandate-vectors.json.
 *
 * A company signatory (or a threshold of signatories) signs a mandate for one agent, possibly on the
 * strength of a signed delegation chain (CEO -> CFO). The bank checks every payment the agent starts
 * against it and signs a decision: allow, block or escalate.
 *
 * Wiring a Checker (all are the bank's own systems; each may be sync or async):
 * - `authority(company, personId)`: who may sign for the company, how (alone or jointly) and with which
 *   keys, from the bank's KYB records, a company register or vLEI. Never from the mandate.
 *   `combine(kyb, vlei)` asks several sources in order.
 * - `payments`: payment log for idempotency (`InMemoryPaymentLog` for tests; persistent in production).
 * - `ledger`: atomic period ledger (`InMemoryLedger` for tests). Required for mandates with a period limit.
 *
 * Gleipnir does not verify identities: the bank or a vLEI issuer binds keys to people (spec section 3).
 * Amounts are handled as bigint minor units (cents; yen for JPY), never as floats.
 */

import { b64uEncode, hexToBytes, utf8, concatBytes } from "./bytes.js";
import { canonicalize, canonicalizeString, hashToBytes, sha256Tagged } from "./canon.js";
import { decodePublicKey, ed25519PublicFromSeed, ed25519Sign, encodePublicKey, verifySignature } from "./crypto.js";
import { webauthnProblem } from "./approvals.js";
import { hasKey, isDict, type JsonDict } from "./py.js";
import { isoMillis, microsFromDate, parseTime, type Micros } from "./time.js";

export const MANDATE_VERSION = "0.2";
const V = MANDATE_VERSION;
export const RAILS: ReadonlySet<string> = new Set(["sepa", "sepa_instant", "ach", "wire", "faster_payments", "fednow", "rtp"]);
export const PERIODS: ReadonlySet<string> = new Set(["P1D", "P7D", "P1M"]);
/** ISO 4217 minor units of the currencies supported in 0.2. */
export const MINOR_UNITS: Readonly<Record<string, number>> = {
  EUR: 2, USD: 2, GBP: 2, CHF: 2, SEK: 2, NOK: 2, DKK: 2, PLN: 2, CZK: 2, HUF: 2, JPY: 0,
};
const AMOUNT_RE: Record<number, RegExp> = { 0: /^(0|[1-9][0-9]*)$/, 2: /^(0|[1-9][0-9]*)\.[0-9]{2}$/ };
export const ESCALATE: ReadonlySet<string> = new Set([
  "signer_unknown", "status_unavailable", "over_payment_limit", "over_period_limit", "ledger_missing", "checker_unavailable",
]);
export const MANDATE_SIG_FIELDS: readonly string[] = ["sig", "sigs"];
/** Outcomes the payment log never caches: a retry once the dependency is back gets a fresh check. */
export const TRANSIENT: ReadonlySet<string> = new Set([
  "checker_unavailable", "status_unavailable", "ledger_missing", "mandate_not_yet_valid", "over_period_limit",
]);
const COUNTRY_RE = /^[A-Z]{2}$/;
const IBAN_RE = /^[A-Za-z0-9 ]+$/;

/** Set an own property, also for keys like "__proto__" that plain assignment would not create. */
function put(obj: JsonDict, key: string, value: unknown): void {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}
export const MAX_DELEGATION_DEPTH = 5;

export type Outcome = "allow" | "block" | "escalate";
export type Awaitable<T> = T | Promise<T>;

// ---------- hashing and signing ----------

/** sha256 over the JCS encoding of the object without its signature field(s). */
export function objHash(obj: JsonDict, sigField: string | readonly string[] = "sig"): string {
  const skip = typeof sigField === "string" ? [sigField] : sigField;
  const body: JsonDict = {};
  for (const k of Object.keys(obj)) if (!skip.includes(k)) put(body, k, obj[k]);
  return sha256Tagged(canonicalize(body));
}

/** The hash every mandate signature covers: the mandate minus `sig` and `sigs`. */
export function mandateHash(mandate: JsonDict): string {
  return objHash(mandate, MANDATE_SIG_FIELDS);
}

export function delegationHash(delegation: JsonDict): string {
  return objHash(delegation);
}

/** The exact bytes a signature of this kind covers: "gleipnir/<kind>/v0.2\n" + hash. */
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

function sigText(seed: Seed, kind: string, hash: string): string {
  return "ed25519:" + b64uEncode(ed25519Sign(seed, mandateMessage(kind, hash)));
}

function without(obj: JsonDict, field: string): JsonDict {
  const out: JsonDict = {};
  for (const k of Object.keys(obj)) if (k !== field) put(out, k, obj[k]);
  return out;
}

function sign(seed: Seed, kind: string, obj: JsonDict, sigField = "sig"): JsonDict {
  const out = without(obj, sigField);
  put(out, sigField, sigText(seed, kind, objHash(out, sigField)));
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

/** Account fields are strings (checked by accountProblem); IBANs ASCII, uppercased without spaces. */
export function normAccount(acc: JsonDict): string {
  if (hasKey(acc, "iban")) return JSON.stringify({ iban: String(acc.iban).replaceAll(" ", "").toUpperCase() });
  const keys = Object.keys(acc).sort();
  return JSON.stringify(keys.map((k) => [k, String(acc[k]).replaceAll(" ", "")]));
}

function accountProblem(acc: unknown): string | null {
  if (!isDict(acc) || Object.keys(acc).length === 0) return "every payee needs an account object";
  if (!Object.values(acc).every((v) => typeof v === "string" && v.length > 0)) return "account fields must be non-empty strings";
  if (hasKey(acc, "iban") && !IBAN_RE.test(acc.iban as string)) return "IBAN must be ASCII letters, digits and spaces";
  return null;
}

// ---------- parsing ----------

/** The first key that appears twice in one JSON object of a valid JSON text, or null. */
export function duplicateKey(text: string): string | null {
  const stack: (Set<string> | null)[] = []; // one Set per open object, null for arrays
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "{") stack.push(new Set());
    else if (c === "[") stack.push(null);
    else if (c === "}" || c === "]") stack.pop();
    else if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      let k = j + 1;
      while (k < text.length && " \t\n\r".includes(text[k]!)) k++;
      const top = stack[stack.length - 1];
      if (text[k] === ":" && top) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.has(key)) return key;
        top.add(key);
      }
      i = j;
    }
  }
  return null;
}

/** The first number literal that is not an I-JSON integer (a float, or beyond 2^53 - 1), or null. */
export function nonIntegerNumber(text: string): string | null {
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '"') {
      i++;
      while (text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i + 1;
      while (j < text.length && /[0-9eE.+-]/.test(text[j]!)) j++;
      const tok = text.slice(i, j);
      if (/[.eE]/.test(tok) || !Number.isSafeInteger(Number(tok))) return tok;
      i = j - 1;
    }
  }
  return null;
}

/**
 * ALWAYS parse wire input with this, not JSON.parse: JavaScript cannot tell 2.0 from 2 once parsed, so only
 * the text shows a float (spec 13). The Checker refuses unsafe integers and non-integers, but not 2.0.
 *
 * Parse JSON from the wire as spec section 13 requires: no duplicate keys (two parsers could read
 * different objects behind one hash), no NaN or Infinity, no floats, integers within 2^53 - 1 (so 2.0
 * and 2 cannot mean different things to different checkers). Throws on violation.
 */
export function parseStrict(text: string): unknown {
  const value = JSON.parse(text) as unknown;
  const dup = duplicateKey(text);
  if (dup !== null) throw new Error(`duplicate JSON key ${JSON.stringify(dup)}`);
  const num = nonIntegerNumber(text);
  if (num !== null) throw new Error(`number ${num} is not an I-JSON integer`);
  return value;
}

// ---------- issuing ----------

export interface IssueOptions {
  id: string;
  company: JsonDict;
  agent: JsonDict;
  scope: JsonDict;
  validUntil: string;
  /** One signatory (sign with signMandate), or `signers` {threshold, of} (cosign). */
  signer?: JsonDict;
  signers?: { threshold: number; of: JsonDict[] };
  delegation?: JsonDict[];
  validFrom?: string;
  statusUrl?: string;
}

/** An unsigned mandate. */
export function issue(o: IssueOptions): JsonDict {
  const m: JsonDict = {
    v: `gleipnir/mandate/${V}`, id: o.id, company: o.company, agent: o.agent, scope: o.scope,
    valid_until: o.validUntil, issued_at: fmtTs(nowMicros()),
  };
  if (o.signer) m.signer = o.signer;
  if (o.signers) m.signers = o.signers;
  if (o.delegation && o.delegation.length) m.delegation = o.delegation;
  if (o.validFrom) m.valid_from = o.validFrom;
  if (o.statusUrl) m.status_url = o.statusUrl;
  const problem = mandateProblem(m);
  if (problem) throw new Error(problem);
  return m;
}

/** Sign a single-signer mandate. */
export function signMandate(mandate: JsonDict, seed: Seed): JsonDict {
  const out = without(mandate, "sig");
  put(out, "sig", sigText(seed, "mandate", mandateHash(out)));
  return out;
}

/** Add (or replace) one co-signature on a multi-signature mandate. Co-signers sign the same hash. */
export function cosign(mandate: JsonDict, seed: Seed, signerId: string): JsonDict {
  const entry = { signer: signerId, sig: sigText(seed, "mandate", mandateHash(mandate)) };
  const prior = Array.isArray(mandate.sigs) ? (mandate.sigs as JsonDict[]) : [];
  return { ...mandate, sigs: [...prior.filter((s) => s.signer !== signerId), entry] };
}

/**
 * What a signatory's passkey signs: SHA-256 of the domain-separated mandate message (spec 4.3), so a
 * mandate passkey signature is never valid as an approval of an agent action, and the reverse.
 */
export function passkeyDigest(mandate: JsonDict): string {
  return sha256Tagged(mandateMessage("mandate", mandateHash(mandate)));
}

/** The WebAuthn challenge: the 32 raw bytes of passkeyDigest(mandate). */
export function passkeyChallenge(mandate: JsonDict): Uint8Array {
  return hashToBytes(passkeyDigest(mandate));
}

/** A signed delegation from `from` (who signs with `seed`) to `to`. `parent`: the link above. */
export function delegate(o: {
  id: string; company: JsonDict; from: JsonDict; to: JsonDict; scope: JsonDict; validUntil: string; seed: Seed;
  parent?: JsonDict; validFrom?: string; issuedAt?: string;
}): JsonDict {
  const d: JsonDict = {
    v: `gleipnir/delegation/${V}`, id: o.id, company: o.company, from: o.from, to: o.to, scope: o.scope,
    valid_until: o.validUntil, issued_at: o.issuedAt ?? fmtTs(nowMicros()),
  };
  if (o.parent) d.parent = { id: o.parent.id, hash: delegationHash(o.parent) };
  if (o.validFrom) d.valid_from = o.validFrom;
  const problem = delegationProblem(d);
  if (problem) throw new Error(problem);
  return sign(o.seed, "delegation", d);
}

/** A signed revocation of a mandate or of a delegation link. */
export function revoke(
  target: JsonDict,
  o: { signer: JsonDict; seed: Seed; id: string; reason?: string; revokedAt?: string },
): JsonDict {
  const r: JsonDict = { v: `gleipnir/revocation/${V}`, id: o.id };
  if (String(target.v ?? "").startsWith("gleipnir/delegation/")) {
    r.delegation = target.id;
    r.delegation_hash = delegationHash(target);
  } else {
    r.mandate = target.id;
    r.mandate_hash = mandateHash(target);
  }
  r.revoked_at = o.revokedAt ?? fmtTs(nowMicros());
  r.signer = o.signer;
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
    v: `gleipnir/payment/${V}`, id: o.id, mandate: { id: mandate.id, hash: mandateHash(mandate) },
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

/** I-JSON as spec 13 profiles it: numbers are safe integers (JS cannot tell 2.0 from 2: use parseStrict). */
function numbersOk(obj: unknown, depth = 0): boolean {
  if (depth > 900) return false;
  if (obj === null || typeof obj === "string" || typeof obj === "boolean") return true;
  if (typeof obj === "number") return Number.isSafeInteger(obj);
  if (Array.isArray(obj)) return obj.every((x) => numbersOk(x, depth + 1));
  if (isDict(obj)) return Object.keys(obj).every((k) => numbersOk(obj[k], depth + 1));
  return false;
}

function jcsOk(obj: unknown): boolean {
  try {
    canonicalize(obj);
  } catch {
    return false;
  }
  return numbersOk(obj);
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function personProblem(p: unknown, what: string): string | null {
  if (!isDict(p) || strFields(p, ["id", "public_key"])) return `missing ${what}.id or ${what}.public_key`;
  return null;
}

/** Scope rules shared by mandates and delegations. */
function scopeProblem(sc: JsonDict): string | null {
  try {
    parseAmount(sc.max_per_payment, sc.currency);
    if (hasKey(sc, "max_per_period")) {
      const per = sc.max_per_period;
      if (!isDict(per) || typeof per.period !== "string" || !PERIODS.has(per.period)) {
        return "max_per_period needs a period of P1D, P7D or P1M";
      }
      parseAmount(hasKey(per, "amount") ? per.amount : null, sc.currency);
    }
  } catch (e) {
    return msg(e);
  }
  const rails = hasKey(sc, "rails") ? sc.rails : [];
  if (!Array.isArray(rails) || !rails.every((r) => typeof r === "string")) return "rails must be a list of strings";
  const unknown = [...new Set(rails as string[])].filter((r) => !RAILS.has(r)).sort();
  if (unknown.length) return `unknown rails: ${JSON.stringify(unknown)}`;
  const payees = hasKey(sc, "payees") ? sc.payees : [];
  if (!Array.isArray(payees) || !payees.every((x) => isDict(x))) return "every payee needs an account object";
  for (const x of payees as JsonDict[]) {
    const bad = accountProblem(hasKey(x, "account") ? x.account : null);
    if (bad) return bad;
  }
  return null;
}

function validityProblem(obj: JsonDict): string | null {
  try {
    const until = ts(obj.valid_until);
    if (hasKey(obj, "valid_from") && ts(obj.valid_from) > until) return "valid_from is after valid_until";
  } catch (e) {
    return msg(e);
  }
  return null;
}

function signersProblem(m: JsonDict): string | null {
  if (hasKey(m, "signer") === hasKey(m, "signers")) return "exactly one of signer or signers";
  if (hasKey(m, "signer")) {
    if (hasKey(m, "sigs")) return "a single signer signs in sig, not sigs";
    return personProblem(m.signer, "signer");
  }
  const ss = m.signers;
  if (hasKey(m, "sig") || hasKey(m, "delegation")) return "multi-signature mandates sign in sigs and take no delegation";
  if (!isDict(ss) || !Array.isArray(ss.of) || ss.of.length === 0) return "signers needs a non-empty list 'of'";
  const of = ss.of as unknown[];
  const th = ss.threshold;
  if (typeof th !== "number" || !Number.isInteger(th) || th < 1 || th > of.length) {
    return "signers.threshold must be an integer between 1 and the number of signers";
  }
  const ids: string[] = [];
  for (const p of of) {
    const bad = personProblem(p, "signers.of[]");
    if (bad) return bad;
    ids.push((p as JsonDict).id as string);
  }
  if (new Set(ids).size !== ids.length) return "duplicate signer id";
  if (new Set((of as JsonDict[]).map((p) => p.public_key)).size !== of.length) return "duplicate signer key: one person cannot count twice";
  const sigs = hasKey(m, "sigs") ? m.sigs : [];
  if (!Array.isArray(sigs) || !sigs.every((s) => isDict(s) && typeof s.signer === "string" && ids.includes(s.signer)
    && (typeof s.sig === "string" || isDict(s.sig)))) {
    return "every sigs entry needs a signer from signers.of and a sig";
  }
  if (new Set(sigs.map((s) => (s as JsonDict).signer)).size !== sigs.length) return "one signature per signer";
  return null;
}

/** Why this is not a well-formed mandate, or null. */
export function mandateProblem(m: unknown): string | null {
  if (!isDict(m) || m.v !== `gleipnir/mandate/${V}`) return "unknown mandate version";
  const bad = strFields(m, ["id", "company.name", "company.country", "agent.id", "scope.currency",
    "scope.max_per_payment", "valid_until"]);
  if (bad) return bad;
  if (!jcsOk(m)) return "mandate is not valid I-JSON";
  if (!COUNTRY_RE.test((m.company as JsonDict).country as string)) return "company.country must be an ISO 3166-1 alpha-2 code";
  const bad2 = signersProblem(m) ?? scopeProblem(m.scope as JsonDict) ?? validityProblem(m);
  if (bad2) return bad2;
  if (hasKey(m, "status_url") && typeof m.status_url !== "string") return "status_url must be a string";
  if (hasKey(m, "delegation")) {
    const chain = m.delegation;
    if (!Array.isArray(chain) || chain.length < 1 || chain.length > MAX_DELEGATION_DEPTH) {
      return `delegation must be a list of 1 to ${MAX_DELEGATION_DEPTH} links`;
    }
    for (const d of chain) {
      const b = delegationProblem(d);
      if (b) return `delegation: ${b}`;
    }
  }
  return null;
}

/** Why this is not a well-formed delegation, or null. */
export function delegationProblem(d: unknown): string | null {
  if (!isDict(d) || d.v !== `gleipnir/delegation/${V}`) return "unknown delegation version";
  const bad = strFields(d, ["id", "company.name", "from.id", "from.public_key", "to.id", "to.public_key",
    "scope.currency", "scope.max_per_payment", "valid_until"]);
  if (bad) return bad;
  if (!jcsOk(d)) return "delegation is not valid I-JSON";
  if (hasKey(d, "parent") && strFields(d.parent, ["id", "hash"])) return "parent needs id and hash";
  return scopeProblem(d.scope as JsonDict) ?? validityProblem(d);
}

/** Why this is not a well-formed payment, or null. */
export function paymentProblem(p: unknown): string | null {
  if (!isDict(p) || p.v !== `gleipnir/payment/${V}`) return "unknown payment version";
  const bad = strFields(p, ["id", "mandate.id", "mandate.hash", "rail", "currency", "requested_at"]);
  if (bad) return bad;
  const acc = get(p, "payee.account");
  if (!isDict(acc) || Object.keys(acc).length === 0) return "missing payee.account";
  if (!jcsOk(p)) return "payment is not valid I-JSON";
  if (!RAILS.has(p.rail as string)) return `unknown rail: ${JSON.stringify(p.rail)}`;
  const accBad = accountProblem(acc);
  if (accBad) return accBad;
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
  if (hasKey(r, "mandate_hash") === hasKey(r, "delegation_hash")) return "a revocation targets exactly one mandate or delegation";
  const target = hasKey(r, "mandate_hash") ? ["mandate", "mandate_hash"] : ["delegation", "delegation_hash"];
  const bad = strFields(r, [...target, "id", "revoked_at", "signer.id", "signer.public_key"]);
  if (bad || !jcsOk(r)) return bad ?? "revocation is not valid I-JSON";
  try {
    ts(r.revoked_at);
  } catch (e) {
    return msg(e);
  }
  return null;
}

type Signed = [JsonDict, unknown];

/** (signer, signature) pairs present on a well-formed mandate, and the mandate's threshold. */
function signatures(m: JsonDict): [Signed[], number] {
  if (hasKey(m, "signer")) return [hasKey(m, "sig") ? [[m.signer as JsonDict, m.sig]] : [], 1];
  const ss = m.signers as JsonDict;
  const byId = new Map((ss.of as JsonDict[]).map((p) => [p.id as string, p]));
  const sigs = hasKey(m, "sigs") ? (m.sigs as JsonDict[]) : [];
  return [sigs.map((s) => [byId.get(s.signer as string)!, s.sig] as Signed), ss.threshold as number];
}

export interface WebauthnOptions {
  rpId?: string;
  origins?: readonly string[];
}

function verify(kind: string, hash: string, sig: unknown, pubText: unknown, wa: WebauthnOptions): boolean {
  try {
    const pub = decodePublicKey(pubText);
    if (isDict(sig) && sig.type === "webauthn" && kind === "mandate") {
      return webauthnProblem(sig, pub, sha256Tagged(mandateMessage(kind, hash)), wa.rpId ?? "", wa.origins ?? [], null) === null;
    }
    return verifySignature(pub, mandateMessage(kind, hash), sig);
  } catch {
    return false; // any malformed key or signature fails closed
  }
}

function samePerson(a: JsonDict, b: JsonDict): boolean {
  return a.id === b.id && a.public_key === b.public_key;
}

/** A link names the mandate's company: same name, and the same country and ids where the link gives them. */
function sameCompany(link: JsonDict, mandate: JsonDict): boolean {
  if (link.name !== mandate.name) return false;
  for (const k of ["country", "ids"]) {
    if (hasKey(link, k) && canonicalizeOrNull(link[k]) !== canonicalizeOrNull(hasKey(mandate, k) ? mandate[k] : undefined)) return false;
  }
  return true;
}

function canonicalizeOrNull(v: unknown): string | null {
  if (v === undefined) return null;
  try {
    return new TextDecoder().decode(canonicalize(v));
  } catch {
    return null;
  }
}

/** Linkage and signatures of a delegation chain (spec section 5, steps 1-2), or null. */
function chainProblem(m: JsonDict, chain: JsonDict[], wa: WebauthnOptions): string | null {
  for (let i = 0; i < chain.length; i++) {
    const d = chain[i]!;
    if (!sameCompany(d.company as JsonDict, m.company as JsonDict)) return "delegation_broken";
    if (i === 0) {
      if (hasKey(d, "parent")) return "delegation_broken";
    } else {
      const prev = chain[i - 1]!;
      if (!samePerson(d.from as JsonDict, prev.to as JsonDict) || get(d, "parent.hash") !== delegationHash(prev)
        || get(d, "parent.id") !== prev.id) {
        return "delegation_broken";
      }
    }
  }
  if (!samePerson(m.signer as JsonDict, chain[chain.length - 1]!.to as JsonDict)) return "delegation_broken";
  for (const d of chain) {
    if (!verify("delegation", delegationHash(d), hasKey(d, "sig") ? d.sig : null, (d.from as JsonDict).public_key, wa)) {
      return "delegation_bad_signature";
    }
  }
  return null;
}

/** True if the child's scope and validity are no wider than the parent's (spec section 5, step 4). */
function within(child: JsonDict, parent: JsonDict): boolean {
  const cs = child.scope as JsonDict, ps = parent.scope as JsonDict;
  if (cs.currency !== ps.currency) return false;
  const cur = ps.currency;
  if (parseAmount(cs.max_per_payment, cur) > parseAmount(ps.max_per_payment, cur)) return false;
  if (hasKey(ps, "rails")) {
    if (!hasKey(cs, "rails")) return false;
    const allowed = new Set(ps.rails as string[]);
    if (!(cs.rails as string[]).every((r) => allowed.has(r))) return false;
  }
  if (hasKey(ps, "payees")) {
    const allowed = new Set((ps.payees as JsonDict[]).map((x) => normAccount(x.account as JsonDict)));
    if (!hasKey(cs, "payees") || !(cs.payees as JsonDict[]).every((x) => allowed.has(normAccount(x.account as JsonDict)))) {
      return false;
    }
  }
  if (hasKey(ps, "max_per_period")) {
    const pp = ps.max_per_period as JsonDict, cp = hasKey(cs, "max_per_period") ? cs.max_per_period : null;
    if (!isDict(cp) || cp.period !== pp.period || parseAmount(cp.amount, cur) > parseAmount(pp.amount, cur)) return false;
  }
  if (ts(child.valid_until) > ts(parent.valid_until)) return false;
  if (hasKey(parent, "valid_from") && (!hasKey(child, "valid_from") || ts(child.valid_from) < ts(parent.valid_from))) {
    return false;
  }
  return true;
}

// ---------- the bank's systems ----------

/** What an authority source (bank KYB, register, vLEI) says about one person at one company. */
export interface AuthorityResult {
  source: string; // "bank_kyb", "register", "vlei"
  keys: readonly string[]; // public keys the source binds to this person (enrollment, spec section 3)
  maySign?: boolean; // signing power of their own (default true); false for a person known only as a delegate
  joint?: number; // signatures their power requires, including their own (default 1; Gesamtprokura: 2)
}

/** authority(company, personId) -> AuthorityResult, or null if no source knows the person. */
export type Authority = (company: JsonDict, personId: string) => Awaitable<AuthorityResult | null>;

/** Ask several authority sources in order (bank KYB first, then vLEI); the first that knows the person wins. */
export function combine(...sources: Authority[]): Authority {
  return async (company, personId) => {
    for (const src of sources) {
      const res = await src(company, personId);
      if (res !== null && res !== undefined) return res;
    }
    return null;
  };
}

/** Idempotency per payer (spec 7). `key` is paymentKey(company, payment id). */
export interface PaymentLog {
  /** The earlier final decision for this key and this exact payment, or null. */
  lookup(key: string, paymentHash: string): Awaitable<JsonDict | null>;
  /** Atomically claim the key. false if it is already claimed (by any payment). */
  register(key: string, paymentHash: string): Awaitable<boolean>;
  /** Store the final decision for a claimed key. */
  remember(key: string, decision: JsonDict): Awaitable<void>;
  /** Release a claim without a decision (a transient failure), so a retry is checked afresh. */
  forget(key: string): Awaitable<void>;
}

/** Period totals (spec 7). `key` is "mandate:<hash>" or "delegation:<hash>"; `at` picks the period. */
export interface Ledger {
  /** Atomically add amount (minor units) to the period total if the total stays within limit. */
  reserve(key: string, period: string, amount: bigint, limit: bigint, at: Micros): Awaitable<boolean>;
  /** Give back a reservation (a later step failed, or the bank did not execute). */
  release(key: string, period: string, amount: bigint, at: Micros): Awaitable<void>;
}

/** The payment log key: payment ids are unique per payer, so the payer is part of the key. */
export function paymentKey(company: JsonDict, paymentId: string): string {
  // JCS of [country, name, ids, id]: unambiguous, and the same bytes as the Python reference.
  return canonicalizeString([company.country ?? null, company.name ?? null, company.ids ?? null, paymentId]);
}

/** Payment log for tests and demos. Production needs a persistent, shared store. */
export class InMemoryPaymentLog implements PaymentLog {
  private items = new Map<string, { hash: string; decision: JsonDict | null }>();

  lookup(key: string, paymentHash: string): JsonDict | null {
    const e = this.items.get(key);
    return e && e.hash === paymentHash ? e.decision : null;
  }

  register(key: string, paymentHash: string): boolean {
    if (this.items.has(key)) return false;
    this.items.set(key, { hash: paymentHash, decision: null });
    return true;
  }

  remember(key: string, decision: JsonDict): void {
    const e = this.items.get(key);
    if (e) e.decision = decision;
  }

  forget(key: string): void {
    this.items.delete(key);
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

  reserve(key: string, period: string, amount: bigint, limit: bigint, at: Micros): boolean {
    const k = `${key}|${periodKey(period, at)}`;
    const total = (this.totals.get(k) ?? 0n) + amount;
    if (total > limit) return false;
    this.totals.set(k, total);
    return true;
  }

  release(key: string, period: string, amount: bigint, at: Micros): void {
    const k = `${key}|${periodKey(period, at)}`;
    const total = (this.totals.get(k) ?? 0n) - amount;
    this.totals.set(k, total < 0n ? 0n : total);
  }
}

class Stop extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

interface Accepted {
  source: string;
  maySign: boolean;
  joint: number;
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
  webauthn?: WebauthnOptions;
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
  private readonly webauthn: WebauthnOptions;

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

  /** The source's answer for this person, checked against the key they used. Throws Stop. */
  private async authorized(company: JsonDict, person: JsonDict, needPower = true): Promise<Accepted> {
    let res: AuthorityResult | null;
    try {
      res = await this.authority(company, person.id as string);
    } catch {
      throw new Stop("checker_unavailable");
    }
    if (res === null || res === undefined) throw new Stop("signer_unknown");
    const joint: unknown = typeof res === "object" ? (res.joint === undefined ? 1 : res.joint) : 0;
    const maySignRaw: unknown = typeof res === "object" ? (res.maySign === undefined ? true : res.maySign) : null;
    if (typeof res !== "object" || typeof res.source !== "string" || !Array.isArray(res.keys)
      || !res.keys.every((k) => typeof k === "string") || typeof joint !== "number" || !Number.isInteger(joint)
      || joint < 1 || typeof maySignRaw !== "boolean") {
      throw new Stop("checker_unavailable");
    }
    const maySign = maySignRaw;
    if (!res.keys.includes(person.public_key as string) || (needPower && !maySign)) throw new Stop("signer_not_authorized");
    return { source: res.source, maySign, joint };
  }

  /** Check one payment against one mandate. Never throws on input; always resolves to a signed decision. */
  async check(mandate: unknown, payment: unknown): Promise<JsonDict> {
    const at = microsFromDate(this.clock());
    const checks: string[] = [];
    const state = { registered: false, key: "" };
    let pHash: string | null = null;
    try {
      pHash = isDict(payment) && jcsOk(payment) ? objHash(payment, "agent_sig") : null;
    } catch {
      pHash = null;
    }
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
        if (reason !== null && TRANSIENT.has(reason)) await this.payments.forget(state.key);
        else await this.payments.remember(state.key, d);
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
    let mh: string | null = null;
    try {
      mh = isDict(m) && jcsOk(m) ? mandateHash(m) : null;
    } catch {
      mh = null;
    }
    const rnd = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const d: JsonDict = {
      v: `gleipnir/decision/${V}`, id: "d_" + [...rnd].map((b) => b.toString(16).padStart(2, "0")).join(""),
      payment: { id: pid, hash: pHash }, mandate: { id: mid, hash: mh }, outcome, reasons: reason ? [reason] : [],
      checks, checked_at: fmtTs(at), checker: { id: this.id, public_key: this.publicKey },
    };
    return sign(this.seed, "decision", d);
  }

  /** Steps 8-10: every signer through authority separately, then threshold and joint. Throws Stop. */
  private async signersOk(m: JsonDict, sigs: Signed[], threshold: number, checks: string[]): Promise<void> {
    const counted: Accepted[] = [];
    let unknown = false;
    const seenKeys = new Set<unknown>();
    for (const [signer] of sigs) {
      if (seenKeys.has(signer.public_key)) continue; // one person counts once
      seenKeys.add(signer.public_key);
      try {
        counted.push(await this.authorized(m.company as JsonDict, signer));
      } catch (e) {
        if (!(e instanceof Stop) || e.reason !== "signer_unknown") throw e;
        unknown = true;
      }
    }
    const needed = Math.max(threshold, ...counted.map((r) => r.joint));
    if (counted.length < needed) {
      if (unknown) throw new Stop("signer_unknown");
      throw new Stop(counted.length >= threshold ? "joint_signature_required" : "signature_threshold_not_met");
    }
    checks.push(...counted.map((r) => `signer_authorized:${r.source}`));
    if (hasKey(m, "signers")) checks.push(`signatures:${counted.length}/${needed}`);
  }

  /** Section 5, steps 3-4: authority per link and narrowing. Throws Stop; returns a reason or null. */
  private async chainOk(m: JsonDict, chain: JsonDict[], checks: string[]): Promise<string | null> {
    const company = m.company as JsonDict;
    const root = await this.authorized(company, chain[0]!.from as JsonDict);
    if (root.joint > 1) throw new Stop("joint_signature_required");
    for (const d of chain) await this.authorized(company, d.to as JsonDict, false);
    checks.push(`delegation:${chain.length}`, `signer_authorized:${root.source}`);
    const children = [...chain.slice(1), m];
    for (let i = 0; i < chain.length; i++) if (!within(children[i]!, chain[i]!)) return "scope_exceeds_delegation";
    return null;
  }

  private async run(
    m: unknown, p: unknown, pHash: string | null, at: Micros, checks: string[], state: { registered: boolean; key: string },
  ): Promise<string | JsonDict | null> {
    if (mandateProblem(m)) return "mandate_malformed";
    if (pHash === null || paymentProblem(p)) return "payment_malformed";
    const md = m as JsonDict, pd = p as JsonDict;
    const key = paymentKey(md.company as JsonDict, pd.id as string);
    let prior: JsonDict | null;
    try {
      prior = await this.payments.lookup(key, pHash);
    } catch {
      return "checker_unavailable";
    }
    if (isDict(prior)) return prior; // idempotent retry, read-only: unknown payers cannot write to the log
    const mh = mandateHash(md);
    if ((pd.mandate as JsonDict).hash !== mh) return "mandate_mismatch";
    const skew = ts(pd.requested_at) - at;
    if ((skew < 0n ? -skew : skew) > this.maxSkew) return "clock_skew";
    const [sigs, threshold] = signatures(md);
    if (sigs.length === 0 || !sigs.every(([s, sig]) => verify("mandate", mh, sig, s.public_key, this.webauthn))) {
      return "mandate_bad_signature";
    }
    const chain = hasKey(md, "delegation") ? (md.delegation as JsonDict[]) : [];
    if (chain.length) {
      const bad = chainProblem(md, chain, this.webauthn);
      if (bad) return bad;
    }
    checks.push("mandate_valid");
    if (chain.length) {
      const bad = await this.chainOk(md, chain, checks);
      if (bad) return bad;
    } else {
      await this.signersOk(md, sigs, threshold, checks);
    }
    const agent = md.agent as JsonDict;
    if (hasKey(agent, "public_key")) {
      if (!verify("payment", pHash, hasKey(pd, "agent_sig") ? pd.agent_sig : null, agent.public_key, this.webauthn)) {
        return "agent_bad_signature";
      }
      checks.push("agent_signed");
    }
    // Authentic from here on: only now may the payment id be claimed (spec 7, step 13).
    let claimed: boolean;
    try {
      claimed = await this.payments.register(key, pHash);
    } catch {
      return "checker_unavailable";
    }
    if (!claimed) return "duplicate_payment";
    state.registered = true;
    state.key = key;
    if (hasKey(md, "valid_from") && at < ts(md.valid_from)) return "mandate_not_yet_valid";
    if (at > ts(md.valid_until)) return "mandate_expired";
    const revoked = await this.revoked(md, mh, chain, sigs, at);
    if (revoked) return revoked;
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
    return this.reserve(md, mh, chain, amt, at, checks);
  }

  /**
   * Step 21: reserve the amount against the mandate's period limit and against every delegation link's own
   * period limit (a link's limit is shared by all mandates under it), all or nothing.
   */
  private async reserve(m: JsonDict, mh: string, chain: JsonDict[], amt: bigint, at: Micros, checks: string[]): Promise<string | null> {
    const wanted: [string, JsonDict][] = [];
    if (hasKey(m.scope as JsonDict, "max_per_period")) wanted.push([`mandate:${mh}`, m.scope as JsonDict]);
    for (const d of chain) if (hasKey(d.scope as JsonDict, "max_per_period")) wanted.push([`delegation:${delegationHash(d)}`, d.scope as JsonDict]);
    if (!wanted.length) return null;
    if (this.ledger === null) return "ledger_missing";
    const done: [string, string][] = [];
    try {
      for (const [key, sc] of wanted) {
        const per = sc.max_per_period as JsonDict;
        if (!(await this.ledger.reserve(key, per.period as string, amt, parseAmount(per.amount, sc.currency), at))) {
          await this.releaseAll(done, amt, at);
          return "over_period_limit";
        }
        done.push([key, per.period as string]);
      }
    } catch {
      await this.releaseAll(done, amt, at);
      return "checker_unavailable";
    }
    checks.push("within_period_limit");
    return null;
  }

  private async releaseAll(done: [string, string][], amt: bigint, at: Micros): Promise<void> {
    for (const [key, period] of done) {
      try {
        await this.ledger!.release(key, period, amt, at);
      } catch {
        // best effort; the bank reconciles its ledger
      }
    }
  }

  /** Section 9: a valid revocation of the mandate or of any delegation link, by an allowed person. */
  private async revoked(m: JsonDict, mh: string, chain: JsonDict[], sigs: Signed[], at: Micros): Promise<string | null> {
    const key = (p: JsonDict) => JSON.stringify([p.id, p.public_key]);
    const people = (links: JsonDict[]) => links.flatMap((d) => [key(d.from as JsonDict), key(d.to as JsonDict)]);
    // The line of authority of each target: for the mandate, its signers and whole chain; for a link, that
    // link and the links above it (a delegate below cannot cut their delegator's authority).
    const mandateParties = new Set([...sigs.map(([s]) => key(s)), ...people(chain)]);
    const linkParties = new Map(chain.map((d, i) => [delegationHash(d), new Set(people(chain.slice(0, i + 1)))]));
    for (const r of this.revocations) {
      if (revocationProblem(r)) continue;
      const rd = r as JsonDict;
      if (ts(rd.revoked_at) > at) continue;
      let reason: string;
      let parties: Set<string>;
      if (hasKey(rd, "mandate_hash")) {
        if (rd.mandate_hash !== mh) continue;
        reason = "mandate_revoked";
        parties = mandateParties;
      } else if (linkParties.has(rd.delegation_hash as string)) {
        reason = "delegation_revoked";
        parties = linkParties.get(rd.delegation_hash as string)!;
      } else continue;
      const signer = rd.signer as JsonDict;
      if (!verify("revocation", objHash(rd), hasKey(rd, "sig") ? rd.sig : null, signer.public_key, this.webauthn)) continue;
      let res: Accepted;
      try {
        res = await this.authorized(m.company as JsonDict, signer, false);
      } catch (e) {
        if (e instanceof Stop && e.reason === "checker_unavailable") throw e;
        continue;
      }
      if (res.maySign || parties.has(key(signer))) return reason;
    }
    return null;
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

export interface Receipt {
  valid: boolean;
  problems: string[];
  outcome: unknown;
  reasons: unknown;
  checked_at: unknown;
  checker: unknown;
  company: unknown;
  agent: unknown;
  signed_by: string[];
  delegation: string[];
  authority: string[];
  payment: { id: unknown; amount: unknown; currency: unknown; payee: unknown };
}

/**
 * Check a receipt offline, months later, without the bank: who authorized this payment, what was decided.
 * Verifies the decision against the bank's known keys, that it names exactly this mandate and payment, and
 * every signature in the mandate, its delegation chain and the payment. It cannot re-run the bank's authority
 * check; the decision's `signer_authorized:<source>` checks record which source the bank relied on.
 */
export function verifyReceipt(
  mandate: unknown, payment: unknown, decision: unknown, checkerKeys: Iterable<string>, opts: { webauthn?: WebauthnOptions } = {},
): Receipt {
  const wa = opts.webauthn ?? {};
  const problems: string[] = [];
  let signedBy: string[] = [];
  let chainView: string[] = [];
  if (!verifyDecision(decision, checkerKeys)) problems.push("decision_bad_signature");
  const mOk = mandateProblem(mandate) === null;
  const md = mandate as JsonDict;
  if (!mOk) problems.push("mandate_malformed");
  else {
    const mh = mandateHash(md);
    if (get(decision, "mandate.hash") !== mh) problems.push("decision_mandate_mismatch");
    const [sigs] = signatures(md);
    signedBy = sigs.filter(([s, sig]) => verify("mandate", mh, sig, s.public_key, wa)).map(([s]) => s.id as string);
    if (sigs.length === 0 || signedBy.length !== sigs.length) problems.push("mandate_bad_signature");
    const chain = hasKey(md, "delegation") ? (md.delegation as JsonDict[]) : [];
    chainView = chain.map((d) => `${(d.from as JsonDict).id} -> ${(d.to as JsonDict).id}`);
    const bad = chain.length ? chainProblem(md, chain, wa) : null;
    if (bad) problems.push(bad);
  }
  if (paymentProblem(payment)) problems.push("payment_malformed");
  else {
    const pd = payment as JsonDict;
    const ph = objHash(pd, "agent_sig");
    if (get(decision, "payment.hash") !== ph) problems.push("decision_payment_mismatch");
    if (mOk) {
      if ((pd.mandate as JsonDict).hash !== mandateHash(md)) problems.push("payment_mandate_mismatch");
      const agent = md.agent as JsonDict;
      if (hasKey(agent, "public_key") && !verify("payment", ph, hasKey(pd, "agent_sig") ? pd.agent_sig : null, agent.public_key, wa)) {
        problems.push("agent_bad_signature");
      }
    }
  }
  const checks = get(decision, "checks");
  return {
    valid: problems.length === 0,
    problems,
    outcome: get(decision, "outcome"),
    reasons: get(decision, "reasons"),
    checked_at: get(decision, "checked_at"),
    checker: get(decision, "checker.id"),
    company: get(mandate, "company.name"),
    agent: get(mandate, "agent.id"),
    signed_by: signedBy,
    delegation: chainView,
    authority: Array.isArray(checks) ? checks.filter((c): c is string => typeof c === "string" && c.startsWith("signer_authorized:")) : [],
    payment: { id: get(payment, "id"), amount: get(payment, "amount"), currency: get(payment, "currency"), payee: get(payment, "payee.account") },
  };
}
