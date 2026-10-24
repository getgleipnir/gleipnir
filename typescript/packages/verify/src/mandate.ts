/**
 * Mandates for AI agents that pay (spec/mandate.md v0.3), TypeScript port of the Python reference
 * `gleipnir_verify.mandate`. Same hashes, signatures, check order and reason codes; conformance is
 * pinned by the shared vectors in test/fixtures/mandate-vectors.json.
 *
 * A company signatory (or a threshold of signatories) signs a mandate for one agent, possibly on the
 * strength of a signed delegation chain (CEO -> CFO). The bank checks every payment the agent starts
 * against it and signs a decision: allow, block or escalate. An escalation is resolved by a signed override.
 *
 * Wiring a Checker (all are the bank's own systems; each may be sync or async):
 * - `authority(company, personId)`: who may sign for the company, how (alone or jointly) and with which
 *   keys, from the bank's KYB records, a company register or vLEI. Never from the mandate.
 *   `combine(kyb, vlei)` asks several sources in order.
 * - `holds(company, account)`: does this company hold this account at this bank (the debtor side). Required.
 * - `payments`: payment log for idempotency (`InMemoryPaymentLog` for tests; persistent in production).
 * - `ledger`: atomic period ledger (`InMemoryLedger` for tests). Required for mandates with a period limit.
 * - `status(url)`: fetches the signed status response, for mandates with a `status_url`.
 * - `officers`: public keys of bank staff who may sign overrides.
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
import { parseXml, type XmlElement } from "./xml.js";

export const MANDATE_VERSION = "0.4";
const V = MANDATE_VERSION;

// ---------- accounts and rails (spec section 6) ----------

/** Each scheme: its fields and their canonical grammar. Accounts are compared exactly, so producers normalize. */
export const SCHEMES: Readonly<Record<string, Readonly<Record<string, RegExp>>>> = {
  iban: { iban: /^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/ },
  us_aba: { routing: /^[0-9]{9}$/, account: /^[0-9]{1,17}$/ },
  uk_sort_code: { sort_code: /^[0-9]{6}$/, account: /^[0-9]{8}$/ },
  ca_eft: { institution: /^[0-9]{3}$/, transit: /^[0-9]{5}$/, account: /^[0-9]{7,12}$/ },
  au_bsb: { bsb: /^[0-9]{6}$/, account: /^[0-9]{5,10}$/ },
  in_ifsc: { ifsc: /^[A-Z]{4}0[A-Z0-9]{6}$/, account: /^[0-9]{9,18}$/ },
  mx_clabe: { clabe: /^[0-9]{18}$/ },
  swift: { bic: /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/, account: /^[A-Z0-9]{1,34}$/ },
};
const ALL_SCHEMES: ReadonlySet<string> = new Set(Object.keys(SCHEMES));
/** rail -> [account schemes it can carry, the only currency it can carry or null for any]. */
export const RAIL_RULES: Readonly<Record<string, readonly [ReadonlySet<string>, string | null]>> = {
  sepa: [new Set(["iban"]), "EUR"],
  sepa_instant: [new Set(["iban"]), "EUR"],
  ach: [new Set(["us_aba"]), "USD"],
  fednow: [new Set(["us_aba"]), "USD"],
  rtp: [new Set(["us_aba"]), "USD"],
  faster_payments: [new Set(["uk_sort_code"]), "GBP"],
  bacs: [new Set(["uk_sort_code"]), "GBP"],
  chaps: [new Set(["uk_sort_code"]), "GBP"],
  ca_eft: [new Set(["ca_eft"]), "CAD"],
  npp: [new Set(["au_bsb"]), "AUD"],
  becs: [new Set(["au_bsb"]), "AUD"],
  neft: [new Set(["in_ifsc"]), "INR"],
  rtgs: [new Set(["in_ifsc"]), "INR"],
  imps: [new Set(["in_ifsc"]), "INR"],
  spei: [new Set(["mx_clabe"]), "MXN"],
  wire: [ALL_SCHEMES, null],
};
export const RAILS: ReadonlySet<string> = new Set(Object.keys(RAIL_RULES));
export const PERIODS: ReadonlySet<string> = new Set(["P1D", "P7D", "P1M"]);
/** ISO 4217 minor units of the currencies supported in 0.3. */
export const MINOR_UNITS: Readonly<Record<string, number>> = {
  EUR: 2, USD: 2, GBP: 2, CHF: 2, SEK: 2, NOK: 2, DKK: 2, PLN: 2, CZK: 2, HUF: 2, RON: 2, CAD: 2, AUD: 2, NZD: 2,
  SGD: 2, HKD: 2, INR: 2, MXN: 2, JPY: 0,
};
const AMOUNT_RE: Record<number, RegExp> = { 0: /^(0|[1-9][0-9]*)$/, 2: /^(0|[1-9][0-9]*)\.[0-9]{2}$/ };
export const ESCALATE: ReadonlySet<string> = new Set([
  "signer_unknown", "status_unavailable", "over_payment_limit", "over_period_limit", "ledger_missing", "checker_unavailable",
  "override_invalid", "override_not_authorized",
]);
/** Escalations that keep the payment id while a person decides; every other non-allow outcome releases it. */
export const HOLDS: ReadonlySet<string> = new Set(["over_payment_limit"]);
/** Escalations a company signatory may resolve; every escalation may be resolved by a bank officer. */
export const COMPANY_OVERRIDABLE: ReadonlySet<string> = new Set(["over_payment_limit", "over_period_limit"]);
/** Escalations no override can resolve: the bank fixes the dependency and the agent retries. */
export const NOT_OVERRIDABLE: ReadonlySet<string> = new Set(["ledger_missing", "checker_unavailable", "override_invalid", "override_not_authorized"]);
/** A re-check after an override that stops on one of these keeps the escalation, so the override can be retried. */
const RETRYABLE: ReadonlySet<string> = new Set(["checker_unavailable", "status_unavailable", "ledger_missing"]);
/** Nesting of objects and arrays (spec 13). */
export const MAX_DEPTH = 32;
/** Entries in signers.of, and signatures on an override. */
export const MAX_SIGNERS = 16;
export const MANDATE_SIG_FIELDS: readonly string[] = ["sig", "sigs"];
const COUNTRY_RE = /^[A-Z]{2}$/;
export const MAX_DELEGATION_DEPTH = 5;
const MAX_URL = 2048;

/** Set an own property, also for keys like "__proto__" that plain assignment would not create. */
function put(obj: JsonDict, key: string, value: unknown): void {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

export type Outcome = "allow" | "block" | "escalate";
export type Awaitable<T> = T | Promise<T>;

const isAscii = (s: string) => /^[\x00-\x7f]*$/.test(s);

function ibanChecksumOk(text: string): boolean {
  const r = text.slice(4) + text.slice(0, 4);
  let rem = 0;
  for (const c of r) {
    const v = parseInt(c, 36);
    rem = v >= 10 ? (rem * 100 + v) % 97 : (rem * 10 + v) % 97;
  }
  return rem === 1;
}

function abaChecksumOk(r: string): boolean {
  const d = [...r].map(Number);
  return (3 * (d[0]! + d[3]! + d[6]!) + 7 * (d[1]! + d[4]! + d[7]!) + (d[2]! + d[5]! + d[8]!)) % 10 === 0;
}

function clabeChecksumOk(c: string): boolean {
  const w = [3, 7, 1];
  let s = 0;
  for (let i = 0; i < 17; i++) s += (Number(c[i]) * w[i % 3]!) % 10;
  return (10 - (s % 10)) % 10 === Number(c[17]);
}

/** Why this is not a canonical account object of a known scheme, or null. */
export function accountProblem(acc: unknown): string | null {
  if (!isDict(acc)) return "an account must be an object";
  const scheme = hasKey(acc, "scheme") ? acc.scheme : null;
  if (typeof scheme !== "string" || !Object.prototype.hasOwnProperty.call(SCHEMES, scheme)) {
    return `unknown account scheme: ${pyRepr(scheme)}`;
  }
  const want = SCHEMES[scheme]!;
  const names = Object.keys(want);
  const keys = Object.keys(acc);
  if (keys.length !== names.length + 1 || !keys.every((k) => k === "scheme" || names.includes(k))) {
    return `a ${scheme} account has exactly the fields ${pyList([...names].sort())}`;
  }
  for (const name of names) {
    const v = acc[name];
    if (typeof v !== "string" || !isAscii(v) || !want[name]!.test(v)) return `${scheme}.${name} is not in canonical form`;
  }
  if (scheme === "iban" && !ibanChecksumOk(acc.iban as string)) return "IBAN check digits are wrong";
  if (scheme === "us_aba" && !abaChecksumOk(acc.routing as string)) return "ABA routing number check digit is wrong";
  if (scheme === "mx_clabe" && !clabeChecksumOk(acc.clabe as string)) return "CLABE check digit is wrong";
  return null;
}

/** A canonical account from human input: spaces and hyphens removed, letters uppercased. Throws if bad. */
export function account(scheme: string, fields: Record<string, string>): JsonDict {
  const acc: JsonDict = { scheme };
  for (const [k, v] of Object.entries(fields)) put(acc, k, v.replace(/[\s-]/g, "").toUpperCase());
  const problem = accountProblem(acc);
  if (problem) throw new Error(problem);
  return acc;
}

/** `account("iban", {iban: text})`: accepts "AT61 1904 3002 3457 3201". */
export function iban(text: string): JsonDict {
  return account("iban", { iban: text });
}

/** True if the rail can carry this currency between accounts of these schemes. */
export function railFits(rail: string, currency: string, accounts: readonly JsonDict[]): boolean {
  const [schemes, cur] = RAIL_RULES[rail]!;
  return (cur === null || cur === currency) && accounts.every((a) => schemes.has(a.scheme as string));
}

function pyStr(t: string): string {
  const q = t.includes("'") && !t.includes('"') ? '"' : "'";
  let out = "";
  for (const ch of t) {
    const c = ch.codePointAt(0)!;
    if (ch === "\\") out += "\\\\";
    else if (ch === q) out += "\\" + q;
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (c < 0x20 || (c >= 0x7f && c <= 0xa0) || c === 0xad) out += "\\x" + c.toString(16).padStart(2, "0");
    else if (c >= 0xd800 && c <= 0xdfff) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return q + out + q;
}

/** Python's repr() of a JSON value, for messages identical to the reference. */
function pyRepr(v: unknown): string {
  if (v === null || v === undefined) return "None";
  if (typeof v === "string") return pyStr(v);
  if (typeof v === "boolean") return v ? "True" : "False";
  if (Array.isArray(v)) return pyList(v);
  if (isDict(v)) return `{${Object.keys(v).map((k) => `${pyStr(k)}: ${pyRepr(v[k])}`).join(", ")}}`;
  return String(v);
}

function pyList(v: readonly unknown[]): string {
  return `[${v.map(pyRepr).join(", ")}]`;
}

function accKey(a: unknown): string {
  return canonicalizeString(a);
}

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

/** The hash every override signature covers: the override minus `sigs`. */
export function overrideHash(override: JsonDict): string {
  return objHash(override, "sigs");
}

/** The exact bytes a signature of this kind covers: "gleipnir/<kind>/v0.3\n" + hash. */
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
  if (typeof text !== "string" || !text.endsWith("Z")) throw new Error(`bad timestamp: ${pyRepr(text)}`);
  return parseTime(text);
}

/** A strictly formatted, positive amount as bigint minor units, else throws. */
export function parseAmount(text: unknown, currency: unknown): bigint {
  if (typeof currency !== "string" || !Object.prototype.hasOwnProperty.call(MINOR_UNITS, currency)) {
    throw new Error(`unsupported currency: ${pyRepr(currency)}`);
  }
  const units = MINOR_UNITS[currency]!;
  if (typeof text !== "string" || !AMOUNT_RE[units]!.test(text)) {
    throw new Error(`bad amount for ${currency}: ${pyRepr(text)}`);
  }
  const v = BigInt(text.replace(".", ""));
  if (v <= 0n) throw new Error(`amount must be positive: ${pyRepr(text)}`);
  return v;
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
  issuedAt?: string;
}

/** An unsigned mandate. */
export function issue(o: IssueOptions): JsonDict {
  const m: JsonDict = {
    v: `gleipnir/mandate/${V}`, id: o.id, company: o.company, agent: o.agent, scope: o.scope,
    valid_until: o.validUntil, issued_at: o.issuedAt ?? fmtTs(nowMicros()),
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

/**
 * A payment that relies on this mandate, signed by the agent when the mandate names an agent key.
 * `fromAccount` defaults to the mandate's only debtor account; it is required when the mandate lists several.
 */
export function attach(
  mandate: JsonDict,
  o: {
    id: string; rail: string; amount: string; currency: string; payee: JsonDict; reference?: string;
    fromAccount?: JsonDict; agentSeed?: Seed; requestedAt?: string;
  },
): JsonDict {
  let from = o.fromAccount;
  if (from === undefined) {
    const accounts = get(mandate, "scope.from_accounts");
    if (!Array.isArray(accounts) || accounts.length !== 1) {
      throw new Error("the mandate lists several from_accounts: pass fromAccount");
    }
    from = accounts[0] as JsonDict;
  }
  let p: JsonDict = {
    v: `gleipnir/payment/${V}`, id: o.id, mandate: { id: mandate.id, hash: mandateHash(mandate) },
    rail: o.rail, amount: o.amount, currency: o.currency, from_account: from, payee: o.payee,
    requested_at: o.requestedAt ?? fmtTs(nowMicros()),
  };
  if (o.reference) p.reference = o.reference;
  if (o.agentSeed) p = sign(o.agentSeed, "payment", p, "agent_sig");
  return p;
}

/** What a `status_url` answers: a signed, timed statement about exactly this mandate (spec 9.1). */
export function statusResponse(
  mandate: JsonDict, o: { status: "active" | "revoked"; signer: JsonDict; seed: Seed; at?: string },
): JsonDict {
  const s: JsonDict = {
    v: `gleipnir/status/${V}`, mandate: { id: mandate.id, hash: mandateHash(mandate) }, status: o.status,
    at: o.at ?? fmtTs(nowMicros()), signer: o.signer,
  };
  return sign(o.seed, "status", s);
}

/** An unsigned override of an escalate decision; add signatures with signOverride (spec 7.1). */
export function makeOverride(
  decision: JsonDict, o: { outcome: "allow" | "block"; id: string; reason?: string; decidedAt?: string },
): JsonDict {
  const out: JsonDict = {
    v: `gleipnir/override/${V}`, id: o.id, decision: { id: hasKey(decision, "id") ? decision.id : null, hash: objHash(decision) },
    outcome: o.outcome, decided_at: o.decidedAt ?? fmtTs(nowMicros()), sigs: [],
  };
  if (o.reason) out.reason = o.reason;
  return out;
}

/** Add (or replace) one signature on an override. `signer`: {id, public_key} of the person signing. */
export function signOverride(override: JsonDict, seed: Seed, signer: JsonDict): JsonDict {
  const entry = { signer, sig: sigText(seed, "override", overrideHash(override)) };
  const prior = Array.isArray(override.sigs) ? (override.sigs as JsonDict[]) : [];
  return { ...override, sigs: [...prior.filter((s) => get(s, "signer.id") !== signer.id), entry] };
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

/** At most MAX_DEPTH nested objects and arrays, counted without recursion (spec 13). */
function depthOk(obj: unknown): boolean {
  const stack: [unknown, number][] = [[obj, 1]];
  while (stack.length) {
    const [v, d] = stack.pop()!;
    if (Array.isArray(v) || isDict(v)) {
      if (d > MAX_DEPTH) return false;
      for (const x of Array.isArray(v) ? v : Object.keys(v).map((k) => (v as JsonDict)[k])) stack.push([x, d + 1]);
    }
  }
  return true;
}

function jcsOk(obj: unknown): boolean {
  if (!depthOk(obj)) return false;
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

// ---------- shapes: every object has a closed set of fields (spec 13, "Versioning") ----------
// An unknown field makes an object malformed; producers put anything a checker must not act on under "x".

type Kind = "any" | "x" | "ids" | ["s", number] | ["o", string] | ["l", string];
const A: Kind = "any";
const S = (n: number): Kind => ["s", n];
const O = (n: string): Kind => ["o", n];
const L = (n: string): Kind => ["l", n];

export const SHAPES: Readonly<Record<string, Readonly<Record<string, Kind>>>> = {
  person: { id: A, public_key: A, name: S(140), role: S(140) },
  company: { name: S(140), country: A, ids: "ids" },
  agent: { id: A, name: S(140), public_key: A },
  payee: { name: S(140), account: A },
  period: { amount: A, period: A },
  scope: { from_accounts: A, rails: A, currency: A, max_per_payment: A, max_per_period: O("period"), payees: L("payee"),
    purpose: S(500) },
  signers: { threshold: A, of: L("person") },
  sigentry: { signer: A, sig: A },
  ref: { id: A, hash: A },
  mandate: { v: A, id: S(128), company: O("company"), agent: O("agent"), signer: O("person"), signers: O("signers"),
    sigs: L("sigentry"), sig: A, scope: O("scope"), valid_from: A, valid_until: A, issued_at: A, status_url: A,
    delegation: A, x: "x" },
  delegation: { v: A, id: S(128), company: O("company"), from: O("person"), to: O("person"), scope: O("scope"),
    valid_from: A, valid_until: A, issued_at: A, parent: O("ref"), sig: A, x: "x" },
  payment: { v: A, id: S(35), mandate: O("ref"), rail: A, amount: A, currency: A, from_account: A, payee: O("payee"),
    reference: S(140), requested_at: A, agent_sig: A, x: "x" },
  revocation: { v: A, id: S(128), mandate: A, mandate_hash: A, delegation: A, delegation_hash: A, revoked_at: A,
    signer: O("person"), reason: S(500), sig: A, x: "x" },
  status: { v: A, mandate: O("ref"), status: A, at: A, signer: O("person"), sig: A },
  osig: { signer: O("person"), sig: A },
  override: { v: A, id: S(128), decision: O("ref"), outcome: A, decided_at: A, reason: S(500), sigs: L("osig"), x: "x" },
};

/** Code-point order of keys, like Python's sorted(). */
function pySorted(keys: string[]): string[] {
  return [...keys].sort((a, b) => {
    const p = [...a].map((c) => c.codePointAt(0)!), q = [...b].map((c) => c.codePointAt(0)!);
    for (let i = 0; i < Math.min(p.length, q.length); i++) if (p[i] !== q[i]) return p[i]! - q[i]!;
    return p.length - q.length;
  });
}

function shapeProblem(obj: unknown, shape: string, path: string): string | null {
  if (!isDict(obj)) return null;
  const spec = SHAPES[shape]!;
  for (const k of pySorted(Object.keys(obj))) {
    const where = path ? `${path}.${k}` : k;
    if (!Object.prototype.hasOwnProperty.call(spec, k)) return `unknown field ${where}`;
    const kind = spec[k]!, v = obj[k];
    if (kind === "x" || kind === "ids") {
      if (!isDict(v)) return `${where} must be an object`;
    } else if (Array.isArray(kind) && kind[0] === "s") {
      if (typeof v !== "string") return `${where} must be a string`;
      if ([...v].length > kind[1]) return `${where} is longer than ${kind[1]} characters`;
    } else if (Array.isArray(kind) && kind[0] === "o") {
      const bad = shapeProblem(v, kind[1], where);
      if (bad) return bad;
    } else if (Array.isArray(kind) && kind[0] === "l" && Array.isArray(v)) {
      for (const item of v) {
        const bad = shapeProblem(item, kind[1], `${where}[]`);
        if (bad) return bad;
      }
    }
  }
  return null;
}

function personProblem(p: unknown, what: string): string | null {
  if (!isDict(p) || strFields(p, ["id", "public_key"])) return `missing ${what}.id or ${what}.public_key`;
  return null;
}

function accountsProblem(accs: unknown, what: string): string | null {
  if (!Array.isArray(accs) || accs.length === 0) return `${what} must be a non-empty list of accounts`;
  for (const a of accs) {
    const bad = accountProblem(a);
    if (bad) return `${what}: ${bad}`;
  }
  if (new Set(accs.map(accKey)).size !== accs.length) return `${what} lists an account twice`;
  return null;
}

/** Scope rules shared by mandates and delegations. */
function scopeProblem(sc: JsonDict, debtorRequired: boolean): string | null {
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
  if (unknown.length) return `unknown rails: ${pyList(unknown)}`;
  if (hasKey(sc, "payees")) {
    const payees = sc.payees;
    if (!Array.isArray(payees) || payees.length === 0 || !payees.every((x) => isDict(x))) {
      return "payees must be a non-empty list of {name, account}";
    }
    const bad = accountsProblem((payees as JsonDict[]).map((x) => (hasKey(x, "account") ? x.account : null)), "payees");
    if (bad) return bad;
  }
  if (hasKey(sc, "from_accounts") || debtorRequired || hasKey(sc, "max_per_period")) {
    if (!hasKey(sc, "from_accounts")) return "from_accounts is required" + (debtorRequired ? "" : " with a period limit");
    const bad = accountsProblem(sc.from_accounts, "from_accounts");
    if (bad) return bad;
  }
  return null;
}

function validityProblem(obj: JsonDict): string | null {
  try {
    const until = ts(obj.valid_until);
    ts(obj.issued_at);
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
  if (ss.of.length > MAX_SIGNERS) return `at most ${MAX_SIGNERS} signers`;
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
    "scope.max_per_payment", "valid_until", "issued_at"]);
  if (bad) return bad;
  if (!jcsOk(m)) return "mandate is not valid I-JSON";
  const shapeBad = shapeProblem(m, "mandate", "");
  if (shapeBad) return shapeBad;
  if (!COUNTRY_RE.test((m.company as JsonDict).country as string)) return "company.country must be an ISO 3166-1 alpha-2 code";
  const bad2 = signersProblem(m) ?? scopeProblem(m.scope as JsonDict, true) ?? validityProblem(m);
  if (bad2) return bad2;
  if (hasKey(m, "status_url")) {
    const url = m.status_url;
    if (typeof url !== "string" || !url.startsWith("https://") || url.length > MAX_URL || !isAscii(url)) {
      return "status_url must be an https URL";
    }
  }
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
    "scope.currency", "scope.max_per_payment", "valid_until", "issued_at"]);
  if (bad) return bad;
  if (!jcsOk(d)) return "delegation is not valid I-JSON";
  const shapeBad = shapeProblem(d, "delegation", "");
  if (shapeBad) return shapeBad;
  if (hasKey(d, "parent") && strFields(d.parent, ["id", "hash"])) return "parent needs id and hash";
  return scopeProblem(d.scope as JsonDict, false) ?? validityProblem(d);
}

/** Why this is not a well-formed payment, or null. */
export function paymentProblem(p: unknown): string | null {
  if (!isDict(p) || p.v !== `gleipnir/payment/${V}`) return "unknown payment version";
  const bad = strFields(p, ["id", "mandate.id", "mandate.hash", "rail", "currency", "requested_at"]);
  if (bad) return bad;
  if (!isDict(hasKey(p, "payee") ? p.payee : null)) return "missing payee";
  if (!jcsOk(p)) return "payment is not valid I-JSON";
  const shapeBad = shapeProblem(p, "payment", "");
  if (shapeBad) return shapeBad;
  if (!RAILS.has(p.rail as string)) return `unknown rail: ${pyRepr(p.rail)}`;
  const payee = p.payee as JsonDict;
  const accBad = accountProblem(hasKey(payee, "account") ? payee.account : null);
  if (accBad) return `payee.account: ${accBad}`;
  const fromBad = accountProblem(hasKey(p, "from_account") ? p.from_account : null);
  if (fromBad) return `from_account: ${fromBad}`;
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
  const shapeBad = shapeProblem(r, "revocation", "");
  if (shapeBad) return shapeBad;
  try {
    ts(r.revoked_at);
  } catch (e) {
    return msg(e);
  }
  return null;
}

export function statusProblem(s: unknown): string | null {
  if (!isDict(s) || s.v !== `gleipnir/status/${V}`) return "unknown status version";
  const bad = strFields(s, ["mandate.id", "mandate.hash", "status", "at", "signer.id", "signer.public_key"]);
  if (bad || !jcsOk(s)) return bad ?? "status is not valid I-JSON";
  const shapeBad = shapeProblem(s, "status", "");
  if (shapeBad) return shapeBad;
  if (s.status !== "active" && s.status !== "revoked") return "status must be active or revoked";
  try {
    ts(s.at);
  } catch (e) {
    return msg(e);
  }
  return null;
}

export function overrideProblem(o: unknown): string | null {
  if (!isDict(o) || o.v !== `gleipnir/override/${V}`) return "unknown override version";
  const bad = strFields(o, ["id", "decision.id", "decision.hash", "outcome", "decided_at"]);
  if (bad || !jcsOk(o)) return bad ?? "override is not valid I-JSON";
  const shapeBad = shapeProblem(o, "override", "");
  if (shapeBad) return shapeBad;
  if (o.outcome !== "allow" && o.outcome !== "block") return "outcome must be allow or block";
  if (hasKey(o, "reason") && typeof o.reason !== "string") return "reason must be a string";
  const sigs = hasKey(o, "sigs") ? o.sigs : null;
  if (!Array.isArray(sigs) || sigs.length === 0) return "an override needs at least one signature";
  if (sigs.length > MAX_SIGNERS) return `at most ${MAX_SIGNERS} signatures`;
  for (const s of sigs) {
    if (!isDict(s) || personProblem(hasKey(s, "signer") ? s.signer : null, "sigs[].signer")
      || !(typeof s.sig === "string" || isDict(s.sig))) {
      return "every sigs entry needs a signer {id, public_key} and a sig";
    }
  }
  const people = (sigs as JsonDict[]).map((s) => s.signer as JsonDict);
  if (new Set(people.map((p) => p.id)).size !== sigs.length || new Set(people.map((p) => p.public_key)).size !== sigs.length) {
    return "one signature per person and per key";
  }
  try {
    ts(o.decided_at);
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

/** A signature over mandateMessage(kind, hash). Passkeys are accepted for what people sign: mandates, overrides. */
function verify(kind: string, hash: string, sig: unknown, pubText: unknown, wa: WebauthnOptions): boolean {
  try {
    const pub = decodePublicKey(pubText);
    if (isDict(sig) && sig.type === "webauthn" && (kind === "mandate" || kind === "override")) {
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

function canonicalizeOrNull(v: unknown): string | null {
  if (v === undefined) return null;
  try {
    return canonicalizeString(v);
  } catch {
    return null;
  }
}

/** Exact JSON equality (what Python's == means on parsed JSON). */
function same(a: unknown, b: unknown): boolean {
  const x = canonicalizeOrNull(a);
  return x !== null && x === canonicalizeOrNull(b);
}

/** A link names the mandate's company: same name, and the same country and ids where the link gives them. */
function sameCompany(link: JsonDict, mandate: JsonDict): boolean {
  if (link.name !== mandate.name) return false;
  for (const k of ["country", "ids"]) {
    // exact JSON equality; absent is not null, true is not 1
    if (hasKey(link, k) && !(hasKey(mandate, k) && same(link[k], mandate[k]))) return false;
  }
  return true;
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
    const allowed = new Set((ps.payees as JsonDict[]).map((x) => accKey(x.account)));
    if (!hasKey(cs, "payees") || !(cs.payees as JsonDict[]).every((x) => allowed.has(accKey(x.account)))) return false;
  }
  if (hasKey(ps, "from_accounts")) {
    const allowed = new Set((ps.from_accounts as JsonDict[]).map(accKey));
    if (!hasKey(cs, "from_accounts") || !(cs.from_accounts as JsonDict[]).every((a) => allowed.has(accKey(a)))) return false;
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
  keys: readonly string[]; // current public keys the source binds to this person (enrollment, spec section 3)
  maySign?: boolean; // signing power of their own (default true); false for a person known only as a delegate
  joint?: number; // signatures their power requires, including their own (default 1; joint signing with one other: 2)
  /** Rotated-out keys -> retirement time: still accepted for objects issued before that time (spec 8). */
  retired?: Readonly<Record<string, string>>;
  /** The source's own id for this person; several ids or keys of one person count once (spec 8). */
  person?: string | null;
}

/** authority(company, personId) -> AuthorityResult, or null if no source knows the person. */
export type Authority = (company: JsonDict, personId: string) => Awaitable<AuthorityResult | null>;

/**
 * holds(company, account) -> the bank's customer id of the holder if this company holds this account at this
 * bank, else null. The customer id keys the payment log.
 */
export type Holds = (company: JsonDict, account: JsonDict) => Awaitable<string | null | false>;

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
  /** The decision this key holds for this exact payment, or null. */
  lookup(key: string, paymentHash: string): Awaitable<JsonDict | null>;
  /** Atomically claim the key. false if it is already claimed (by any payment). */
  register(key: string, paymentHash: string): Awaitable<boolean>;
  /** Store the decision a claimed key holds (an allow, or an escalation waiting for a person). */
  remember(key: string, decision: JsonDict): Awaitable<void>;
  /** Release a claim, so the payment id may be used again. */
  forget(key: string): Awaitable<void>;
  /**
   * Atomically take over a held escalation for resolving: if the key holds decision `decisionId` for this payment,
   * clear it (claimed, being checked) and return true; otherwise false. Two concurrent overrides must not both re-check.
   */
  take(key: string, paymentHash: string, decisionId: string): Awaitable<boolean>;
}

/** Period totals (spec 7). `key` is "mandate:<hash>" or "delegation:<hash>"; `at` picks the period. */
export interface Ledger {
  /** Atomically add amount (minor units) to the period total if the total stays within limit (null: an override, add). */
  reserve(key: string, period: string, amount: bigint, limit: bigint | null, at: Micros): Awaitable<boolean>;
  /** Give back a reservation (a later step failed, or the bank did not execute). */
  release(key: string, period: string, amount: bigint, at: Micros): Awaitable<void>;
}

/**
 * The payment log key: payment ids are unique per payer, so the payer is part of the key. `customer` is the
 * bank's own id for the account holder (what `holds` returns), never text from the mandate. JCS of [customer, id].
 */
export function paymentKey(customer: string, paymentId: string): string {
  return canonicalizeString([customer, paymentId]);
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

  take(key: string, paymentHash: string, decisionId: string): boolean {
    const e = this.items.get(key);
    if (!e || e.hash !== paymentHash || !e.decision || e.decision.id !== decisionId) return false;
    e.decision = null;
    return true;
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
  throw new Error(`unknown period ${pyRepr(period)}`);
}

/** Period ledger for tests and demos: calendar periods in UTC. */
export class InMemoryLedger implements Ledger {
  readonly totals = new Map<string, bigint>();

  reserve(key: string, period: string, amount: bigint, limit: bigint | null, at: Micros): boolean {
    const k = `${key}|${periodKey(period, at)}`;
    const total = (this.totals.get(k) ?? 0n) + amount;
    if (limit !== null && total > limit) return false;
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
  person: string | null;
}

type Person = { id: string; public_key: string };

/** Whether the payment log keeps this decision (and so the payment id): spec 7, "Idempotency". */
function holdsId(d: JsonDict): boolean {
  const r = d.reasons as string[];
  return d.outcome === "allow" || (r.length === 1 && (HOLDS.has(r[0]!) || r[0] === "blocked_by_override"));
}

/** A list of {id, public_key} as person keys, or null if it is not one. */
function persons(v: unknown): string[] | null {
  if (!Array.isArray(v) || !v.every((x) => isDict(x) && Object.keys(x).length === 2 && typeof x.id === "string"
    && typeof x.public_key === "string")) return null;
  return (v as JsonDict[]).map(personKey);
}

function unkey(k: string): Person {
  const [id, public_key] = JSON.parse(k) as [string, string];
  return { id, public_key };
}

type State = {
  registered: boolean; key: string; refs?: JsonDict; signers?: Person[]; unknown?: string[]; restore?: JsonDict;
};

// ---------- checking ----------

export interface CheckerOptions {
  id: string;
  /** The bank's Ed25519 signing key (32-byte seed). */
  seed: Seed;
  authority: Authority;
  /** holds(company, account): the bank's customer id if the company holds this account here. Required. */
  holds?: Holds | null;
  ledger?: Ledger | null;
  payments?: PaymentLog;
  revocations?: readonly unknown[];
  /** revocationFeed() -> revocations from a signed, current list (revocationsFromList); throws if none is current. */
  revocationFeed?: (() => Awaitable<unknown[]>) | null;
  /** status(url) -> the signed status response; throws (or rejects) when unreachable. */
  status?: ((url: string) => Awaitable<unknown>) | null;
  clock?: () => Date;
  maxSkewMs?: number;
  statusMaxAgeMs?: number;
  overrideWindowMs?: number;
  /** Public keys of bank staff who may sign overrides. */
  officers?: readonly string[];
  /** Policy: block mandates without a payee list (payees_required). */
  requirePayees?: boolean;
  webauthn?: WebauthnOptions;
}

export class Checker {
  readonly id: string;
  readonly publicKey: string;
  private readonly seed: Seed;
  private readonly authority: Authority;
  private readonly holds: Holds | null;
  private readonly ledger: Ledger | null;
  private readonly payments: PaymentLog;
  revocations: unknown[];
  private readonly revocationFeed: (() => Awaitable<unknown[]>) | null;
  private readonly status: ((url: string) => Awaitable<unknown>) | null;
  private readonly clock: () => Date;
  private readonly maxSkew: Micros;
  private readonly statusMaxAge: Micros;
  private readonly overrideWindow: Micros;
  private readonly officers: ReadonlySet<string>;
  private readonly requirePayees: boolean;
  private readonly webauthn: WebauthnOptions;

  constructor(o: CheckerOptions) {
    const ms = (v: number) => BigInt(Math.round(v)) * 1000n;
    this.id = o.id;
    this.seed = o.seed;
    this.publicKey = publicKeyOf(o.seed);
    this.authority = o.authority;
    this.holds = o.holds ?? null;
    this.ledger = o.ledger ?? null;
    this.payments = o.payments ?? new InMemoryPaymentLog();
    this.revocations = [...(o.revocations ?? [])];
    this.revocationFeed = o.revocationFeed ?? null;
    this.status = o.status ?? null;
    this.clock = o.clock ?? (() => new Date());
    this.maxSkew = ms(o.maxSkewMs ?? 60_000);
    this.statusMaxAge = ms(o.statusMaxAgeMs ?? 5 * 60_000);
    this.overrideWindow = ms(o.overrideWindowMs ?? 72 * 3_600_000);
    this.officers = new Set(o.officers ?? []);
    this.requirePayees = o.requirePayees ?? false;
    this.webauthn = o.webauthn ?? {};
  }

  /**
   * The source's answer for this person, checked against the key they used. Throws Stop.
   * `issued`: when the object this key signed was issued; a retired key counts only for objects issued before
   * its retirement. null: current keys only.
   */
  private async authorized(company: JsonDict, person: JsonDict, needPower = true, issued: unknown = null): Promise<Accepted> {
    let res: AuthorityResult | null;
    try {
      res = await this.authority(company, person.id as string);
    } catch {
      throw new Stop("checker_unavailable");
    }
    if (res === null || res === undefined) throw new Stop("signer_unknown");
    const joint: unknown = typeof res === "object" ? (res.joint === undefined ? 1 : res.joint) : 0;
    const maySignRaw: unknown = typeof res === "object" ? (res.maySign === undefined ? true : res.maySign) : null;
    const retired: unknown = typeof res === "object" ? (res.retired === undefined ? {} : res.retired) : null;
    const who: unknown = typeof res === "object" ? (res.person === undefined ? null : res.person) : 0;
    if (typeof res !== "object" || typeof res.source !== "string" || !Array.isArray(res.keys)
      || !res.keys.every((k) => typeof k === "string") || typeof joint !== "number" || !Number.isInteger(joint)
      || joint < 1 || typeof maySignRaw !== "boolean" || !isDict(retired) || !(who === null || typeof who === "string")) {
      throw new Stop("checker_unavailable");
    }
    const key = person.public_key as string;
    let ok = res.keys.includes(key);
    if (!ok && issued !== null && hasKey(retired, key)) {
      try {
        ok = ts(issued) < ts(retired[key]);
      } catch {
        throw new Stop("checker_unavailable");
      }
    }
    if (!ok || (needPower && !maySignRaw)) throw new Stop("signer_not_authorized");
    return { source: res.source, maySign: maySignRaw, joint, person: who as string | null };
  }

  /** Check one payment against one mandate. Never throws on input; always resolves to a signed decision. */
  async check(mandate: unknown, payment: unknown): Promise<JsonDict> {
    return this.checked(mandate, payment, (pHash, at, checks, state) => this.run(mandate, payment, pHash, at, checks, state));
  }

  /**
   * Apply a signed override to one of this checker's escalate decisions (spec 7.1). Never throws on input.
   * Returns the final decision (allow or block, signed, naming the escalation and the override), a later
   * escalation if re-checking hit another one, or an escalate `override_invalid` / `override_not_authorized`.
   */
  async resolve(mandate: unknown, payment: unknown, decision: unknown, override: unknown): Promise<JsonDict> {
    return this.checked(mandate, payment, (pHash, at, checks, state) =>
      this.resolveRun(mandate, payment, decision, override, pHash, at, checks, state));
  }

  /**
   * Whether this revocation would switch off this mandate (or a link of its chain) now: well formed, validly
   * signed, aimed at it, by someone who may revoke it (section 9). For a store that accepts revocations from
   * outside. Never throws; a source that is down gives false.
   */
  async revocationCounts(mandate: unknown, revocation: unknown): Promise<boolean> {
    try {
      if (mandateProblem(mandate) || revocationProblem(revocation)) return false;
      const md = mandate as JsonDict, r = revocation as JsonDict;
      const [sigs] = signatures(md);
      const chain = hasKey(md, "delegation") ? (md.delegation as JsonDict[]) : [];
      const [mandateParties, linkParties] = Checker.parties(chain, sigs);
      let parties: Set<string>;
      if (hasKey(r, "mandate_hash")) {
        if (r.mandate_hash !== mandateHash(md)) return false;
        parties = mandateParties;
      } else if (linkParties.has(r.delegation_hash as string)) parties = linkParties.get(r.delegation_hash as string)!;
      else return false;
      const signer = r.signer as JsonDict;
      if (!verify("revocation", objHash(r), hasKey(r, "sig") ? r.sig : null, signer.public_key, this.webauthn)) return false;
      return await this.mayRevoke(md, signer, parties, r.revoked_at);
    } catch {
      return false;
    }
  }

  private async checked(
    mandate: unknown, payment: unknown,
    run: (pHash: string | null, at: Micros, checks: string[], state: State) => Promise<string | JsonDict | null>,
  ): Promise<JsonDict> {
    const at = microsFromDate(this.clock());
    const checks: string[] = [];
    const state: State = { registered: false, key: "" };
    let pHash: string | null = null;
    try {
      pHash = isDict(payment) && jcsOk(payment) ? objHash(payment, "agent_sig") : null;
    } catch {
      pHash = null;
    }
    let reason: string | JsonDict | null;
    try {
      reason = await run(pHash, at, checks, state);
    } catch (e) {
      reason = e instanceof Stop ? e.reason : "payment_malformed"; // unexpected input never allows
    }
    if (isDict(reason)) return reason; // idempotent retry: the decision the log holds, unchanged
    const extra: JsonDict = { ...(state.refs ?? {}) };
    if (state.signers) extra.signers = state.signers;
    if (reason === "signer_unknown" && state.unknown && state.unknown.length) extra.unknown = state.unknown.map(unkey);
    const d = this.decision(mandate, payment, pHash, reason, checks, at, extra);
    if (state.registered) {
      try {
        if (holdsId(d)) await this.payments.remember(state.key, d);
        else if (state.restore && reason !== null && RETRYABLE.has(reason)) await this.payments.remember(state.key, state.restore);
        else await this.payments.forget(state.key);
      } catch {
        // the decision still stands; the log is the bank's to fix
      }
    }
    return d;
  }

  private decision(
    m: unknown, p: unknown, pHash: string | null, reason: string | null, checks: string[], at: Micros, extra: JsonDict,
  ): JsonDict {
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
      checks, checked_at: fmtTs(at), checker: { id: this.id, public_key: this.publicKey }, ...extra,
    };
    return sign(this.seed, "decision", d);
  }

  /** authorized(), except for unknown people: null if a bank override vouched for exactly this person, else recorded. */
  private async person(
    company: JsonDict, p: JsonDict, needPower: boolean, issued: unknown, vouched: ReadonlySet<string>, unknown: string[],
  ): Promise<Accepted | null> {
    try {
      return await this.authorized(company, p, needPower, issued);
    } catch (e) {
      if (e instanceof Stop && e.reason === "signer_unknown") {
        const k = personKey(p);
        if (vouched.has(k)) return null;
        if (!unknown.includes(k)) unknown.push(k);
      }
      throw e;
    }
  }

  /** Steps 10-12: every signer through authority separately, then threshold and joint. Throws Stop. */
  private async signersOk(m: JsonDict, sigs: Signed[], threshold: number, checks: string[], vouched: ReadonlySet<string>,
    state: State): Promise<void> {
    const counted: Accepted[] = [];
    const signers: Person[] = [];
    const seen = new Set<string>();
    let nVouched = 0;
    const unknown = (state.unknown ??= []);
    for (const [signer] of sigs) {
      let res: Accepted | null;
      try {
        res = await this.person(m.company as JsonDict, signer, true, m.issued_at, vouched, unknown);
      } catch (e) {
        if (!(e instanceof Stop) || e.reason !== "signer_unknown") throw e;
        continue;
      }
      const who = res === null || res.person === null ? "id:" + (signer.id as string) : "person:" + res.person;
      if (seen.has(who)) continue; // one person counts once, whatever ids or keys they appear under
      seen.add(who);
      signers.push({ id: signer.id as string, public_key: signer.public_key as string });
      if (res === null) nVouched += 1; // unknown to every source, vouched for by a bank officer's override
      else counted.push(res);
    }
    const needed = Math.max(threshold, ...counted.map((r) => r.joint));
    const have = counted.length + nVouched;
    if (have < needed) {
      if (unknown.length) throw new Stop("signer_unknown");
      throw new Stop(have >= threshold ? "joint_signature_required" : "signature_threshold_not_met");
    }
    checks.push(...counted.map((r) => `signer_authorized:${r.source}`));
    for (let i = 0; i < nVouched; i++) checks.push("signer_authorized:override");
    if (hasKey(m, "signers")) checks.push(`signatures:${have}/${needed}`);
    state.signers = signers;
  }

  /** Section 5, steps 3-4: authority per link and narrowing. Throws Stop; returns a reason or null. */
  private async chainOk(m: JsonDict, chain: JsonDict[], checks: string[], vouched: ReadonlySet<string>,
    state: State): Promise<string | null> {
    const company = m.company as JsonDict;
    const unknown = (state.unknown ??= []);
    const children = [...chain.slice(1), m];
    // Each delegate's key is checked as of the object it signed next: the next link, or the mandate.
    const people: [JsonDict, boolean, unknown][] = [[chain[0]!.from as JsonDict, true, chain[0]!.issued_at],
      ...chain.map((d, i) => [d.to as JsonDict, false, children[i]!.issued_at] as [JsonDict, boolean, unknown])];
    const answers: (Accepted | null)[] = [];
    for (const [p, power, issued] of people) { // everyone, so an escalation names every unknown person
      try {
        answers.push(await this.person(company, p, power, issued, vouched, unknown));
      } catch (e) {
        if (!(e instanceof Stop) || e.reason !== "signer_unknown") throw e;
      }
    }
    if (unknown.length) throw new Stop("signer_unknown");
    const root = answers[0]!;
    if (root !== null && root.joint > 1) throw new Stop("joint_signature_required");
    checks.push(`delegation:${chain.length}`, `signer_authorized:${root ? root.source : "override"}`);
    for (let i = 0; i < chain.length; i++) if (!within(children[i]!, chain[i]!)) return "scope_exceeds_delegation";
    const sg = m.signer as JsonDict;
    state.signers = [{ id: sg.id as string, public_key: sg.public_key as string }];
    return null;
  }

  /** Steps 1-6: parse, then every signature on the objects themselves. No external system is asked. */
  private authentic(m: unknown, p: unknown, pHash: string | null): string | null {
    if (mandateProblem(m)) return "mandate_malformed";
    if (pHash === null || paymentProblem(p)) return "payment_malformed";
    const md = m as JsonDict, pd = p as JsonDict;
    const mh = mandateHash(md);
    if ((pd.mandate as JsonDict).hash !== mh) return "mandate_mismatch";
    const [sigs] = signatures(md);
    if (sigs.length === 0 || !sigs.every(([s, sig]) => verify("mandate", mh, sig, s.public_key, this.webauthn))) {
      return "mandate_bad_signature";
    }
    const chain = hasKey(md, "delegation") ? (md.delegation as JsonDict[]) : [];
    if (chain.length) {
      const bad = chainProblem(md, chain, this.webauthn);
      if (bad) return bad;
    }
    const agent = md.agent as JsonDict;
    if (hasKey(agent, "public_key")
      && !verify("payment", pHash, hasKey(pd, "agent_sig") ? pd.agent_sig : null, agent.public_key, this.webauthn)) {
      return "agent_bad_signature";
    }
    return null;
  }

  /**
   * The check (spec 7). `claimed` is set when resolving an override: true if this payment already holds its id,
   * false if it must claim it; then the lookup and the clock-skew step are skipped.
   */
  private async run(
    m: unknown, p: unknown, pHash: string | null, at: Micros, checks: string[], state: State,
    waive: ReadonlySet<string> = new Set(), claimed: boolean | null = null, vouched: ReadonlySet<string> = new Set(),
  ): Promise<string | JsonDict | null> {
    const bad = this.authentic(m, p, pHash);
    if (bad) return bad;
    const md = m as JsonDict, pd = p as JsonDict;
    const mh = mandateHash(md);
    const chain = hasKey(md, "delegation") ? (md.delegation as JsonDict[]) : [];
    const [notHeld, customer] = await this.held(md, chain, pd.from_account as JsonDict);
    if (notHeld) return notHeld;
    const key = paymentKey(customer, pd.id as string);
    state.key = key;
    if (claimed) state.registered = true; // the held escalation was taken over: whatever happens must settle it
    if (claimed === null) {
      let prior: JsonDict | null;
      try {
        prior = await this.payments.lookup(key, pHash!);
      } catch {
        return "checker_unavailable";
      }
      if (isDict(prior)) return prior; // idempotent retry, read-only, and only for an authentic payment
      const skew = ts(pd.requested_at) - at;
      if ((skew < 0n ? -skew : skew) > this.maxSkew) return "clock_skew";
    }
    checks.push("mandate_valid");
    const agent = md.agent as JsonDict;
    if (hasKey(agent, "public_key")) checks.push("agent_signed");
    checks.push("account_held");
    const [sigs, threshold] = signatures(md);
    if (chain.length) {
      const b = await this.chainOk(md, chain, checks, vouched, state);
      if (b) return b;
    } else {
      await this.signersOk(md, sigs, threshold, checks, vouched, state);
    }
    // Authentic and authorized from here on: only now may the payment id be claimed (step 14).
    if (!claimed) {
      let ok: boolean;
      try {
        ok = await this.payments.register(key, pHash!);
      } catch {
        return "checker_unavailable";
      }
      if (!ok) return "duplicate_payment";
      state.registered = true;
    }
    if (hasKey(md, "valid_from") && at < ts(md.valid_from)) return "mandate_not_yet_valid";
    if (at > ts(md.valid_until)) return "mandate_expired";
    const revoked = await this.revoked(md, mh, chain, sigs, at, this.revocations);
    if (revoked) return revoked;
    if (this.revocationFeed !== null) {
      let fed: unknown;
      try {
        fed = await this.revocationFeed();
      } catch {
        fed = null;
      }
      if (Array.isArray(fed)) {
        const r = await this.revoked(md, mh, chain, sigs, at, fed);
        if (r) return r;
        checks.push("revocation_list_current");
      } else if (waive.has("status_unavailable")) checks.push("revocation_list_unavailable_approved");
      else return "status_unavailable";
    }
    if (hasKey(md, "status_url")) {
      const st = await this.statusOf(md, mh, chain, sigs, at);
      if (st === "revoked") return "mandate_revoked";
      if (st === "active") checks.push("status_active");
      else if (waive.has("status_unavailable")) checks.push("status_unavailable_approved");
      else return "status_unavailable";
    }
    checks.push("not_revoked");
    const sc = md.scope as JsonDict;
    const fa = pd.from_account as JsonDict;
    if (hasKey(sc, "rails") && !(sc.rails as string[]).includes(pd.rail as string)) return "rail_not_allowed";
    const payeeAcc = (pd.payee as JsonDict).account as JsonDict;
    if (!railFits(pd.rail as string, pd.currency as string, [fa, payeeAcc])) return "rail_mismatch";
    if (pd.currency !== sc.currency) return "currency_mismatch";
    if (hasKey(sc, "payees")) {
      const want = accKey(payeeAcc);
      if (!(sc.payees as JsonDict[]).some((x) => accKey(x.account) === want)) return "payee_not_on_mandate";
      checks.push("payee_on_mandate");
    } else if (this.requirePayees) return "payees_required";
    const amt = parseAmount(pd.amount, pd.currency);
    if (amt > parseAmount(sc.max_per_payment, sc.currency)) {
      if (!waive.has("over_payment_limit")) return "over_payment_limit";
      checks.push("over_payment_limit_approved");
    } else checks.push("within_payment_limit");
    // A bank officer's waiver lifts every period limit; the company's own signatories lift only the mandate's.
    const force = waive.has("over_period_limit") ? "links" : waive.has("over_period_limit:mandate") ? "mandate" : "";
    return this.reserve(md, mh, chain, amt, at, checks, force);
  }

  /**
   * Step 7: the debtor account is on the mandate and the bank holds it for this company; with a period limit,
   * the bank holds every account the limited object lists, for the same customer. Returns ["", customer] or [reason, ""].
   */
  private async held(m: JsonDict, chain: JsonDict[], fa: JsonDict): Promise<[string, string]> {
    if (!((m.scope as JsonDict).from_accounts as JsonDict[]).some((a) => accKey(a) === accKey(fa))) {
      return ["account_not_on_mandate", ""];
    }
    if (this.holds === null) return ["checker_unavailable", ""];
    const wanted: JsonDict[] = [fa];
    for (const obj of [m, ...chain]) {
      const sc = obj.scope as JsonDict;
      if (hasKey(sc, "max_per_period")) wanted.push(...(sc.from_accounts as JsonDict[]));
    }
    const customers = new Set<string>();
    const seen = new Set<string>();
    for (const acc of wanted) {
      const k = accKey(acc);
      if (seen.has(k)) continue;
      seen.add(k);
      let c: unknown;
      try {
        c = await this.holds(m.company as JsonDict, acc);
      } catch {
        return ["checker_unavailable", ""];
      }
      if (c === null || c === undefined || c === false) return ["account_not_held", ""];
      if (typeof c !== "string" || !c) return ["checker_unavailable", ""];
      customers.add(c);
    }
    if (customers.size !== 1) return ["account_not_held", ""];
    return ["", [...customers][0]!];
  }

  /**
   * Step 23: reserve the amount against the mandate's period limit and against every delegation link's own
   * period limit (a link's limit is shared by all mandates under it), all or nothing. `force`: an override
   * approved going over ("mandate": the mandate's own limit; "links": every limit).
   */
  private async reserve(
    m: JsonDict, mh: string, chain: JsonDict[], amt: bigint, at: Micros, checks: string[], force = "",
  ): Promise<string | null> {
    const wanted: [string, JsonDict, boolean][] = [];
    if (hasKey(m.scope as JsonDict, "max_per_period")) wanted.push([`mandate:${mh}`, m.scope as JsonDict, force !== ""]);
    for (const d of chain) {
      if (hasKey(d.scope as JsonDict, "max_per_period")) wanted.push([`delegation:${delegationHash(d)}`, d.scope as JsonDict, force === "links"]);
    }
    if (!wanted.length) return null;
    if (this.ledger === null) return "ledger_missing";
    const done: [string, string][] = [];
    try {
      for (const [key, sc, forced] of wanted) {
        const per = sc.max_per_period as JsonDict;
        const limit = forced ? null : parseAmount(per.amount, sc.currency);
        if (!(await this.ledger.reserve(key, per.period as string, amt, limit, at))) {
          await this.releaseAll(done, amt, at);
          return "over_period_limit";
        }
        done.push([key, per.period as string]);
      }
    } catch {
      await this.releaseAll(done, amt, at);
      return "checker_unavailable";
    }
    checks.push(force ? "over_period_limit_approved" : "within_period_limit");
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

  private static parties(chain: JsonDict[], sigs: Signed[]): [Set<string>, Map<string, Set<string>>] {
    const people = (links: JsonDict[]) => links.flatMap((d) => [personKey(d.from as JsonDict), personKey(d.to as JsonDict)]);
    // The line of authority of each target: for the mandate, its signers and whole chain; for a link, that
    // link and the links above it (a delegate below cannot cut their delegator's authority).
    const mandateParties = new Set([...sigs.map(([s]) => personKey(s)), ...people(chain)]);
    const linkParties = new Map(chain.map((d, i) => [delegationHash(d), new Set(people(chain.slice(0, i + 1)))]));
    return [mandateParties, linkParties];
  }

  /** Known with that key, and may sign for the company or is in the line of authority. Throws Stop on a down source. */
  private async mayRevoke(m: JsonDict, signer: JsonDict, parties: Set<string>, issued: unknown): Promise<boolean> {
    let res: Accepted;
    try {
      res = await this.authorized(m.company as JsonDict, signer, false, issued);
    } catch (e) {
      if (e instanceof Stop && e.reason === "checker_unavailable") throw e;
      return false;
    }
    return res.maySign || parties.has(personKey(signer));
  }

  /**
   * Section 9: a valid revocation of the mandate or of any delegation link, by an allowed person.
   * One signatory of a jointly signed mandate may revoke it alone: switching off needs no co-signer.
   */
  private async revoked(m: JsonDict, mh: string, chain: JsonDict[], sigs: Signed[], at: Micros,
    revocations: readonly unknown[]): Promise<string | null> {
    const [mandateParties, linkParties] = Checker.parties(chain, sigs);
    for (const r of revocations) {
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
      if (await this.mayRevoke(m, signer, parties, rd.revoked_at)) return reason;
    }
    return null;
  }

  /**
   * Step 17: "active" or "revoked" from a valid, fresh status response signed by someone who could revoke the
   * mandate; null if there is no such answer.
   */
  private async statusOf(m: JsonDict, mh: string, chain: JsonDict[], sigs: Signed[], at: Micros): Promise<string | null> {
    if (this.status === null) return null;
    let s: unknown;
    try {
      s = await this.status(m.status_url as string);
    } catch {
      return null;
    }
    if (statusProblem(s)) return null;
    const sd = s as JsonDict;
    if (!same(sd.mandate, { id: m.id, hash: mh })) return null;
    const t = ts(sd.at);
    if (t > at + this.maxSkew || at - t > this.statusMaxAge) return null;
    const signer = sd.signer as JsonDict;
    if (!verify("status", objHash(sd), hasKey(sd, "sig") ? sd.sig : null, signer.public_key, this.webauthn)) return null;
    const [mandateParties] = Checker.parties(chain, sigs);
    if (!(await this.mayRevoke(m, signer, mandateParties, null))) return null;
    return sd.status as string;
  }

  private async resolveRun(
    m: unknown, p: unknown, d: unknown, o: unknown, pHash: string | null, at: Micros, checks: string[], state: State,
  ): Promise<string | JsonDict | null> {
    const bad = this.authentic(m, p, pHash);
    if (bad) return bad;
    const md = m as JsonDict, pd = p as JsonDict;
    const mh = mandateHash(md);
    if (overrideProblem(o) || !verifyDecision(d, [this.publicKey])) return "override_invalid";
    const dd = d as JsonDict, od = o as JsonDict;
    if (dd.outcome !== "escalate" || !Array.isArray(dd.reasons) || dd.reasons.length !== 1
      || !same(dd.payment, { id: pd.id, hash: pHash }) || get(dd, "mandate.hash") !== mh
      || !same(od.decision, { id: hasKey(dd, "id") ? dd.id : null, hash: objHash(dd) })) {
      return "override_invalid";
    }
    // The window runs from the first escalation of this payment, however many overrides follow.
    const first = hasKey(dd, "escalated_at") ? dd.escalated_at : dd.checked_at;
    const earlier = hasKey(dd, "waived") ? dd.waived : [];
    const vouchedBefore = persons(hasKey(dd, "vouched") ? dd.vouched : []);
    const unknown = persons(hasKey(dd, "unknown") ? dd.unknown : []);
    if (!Array.isArray(earlier) || !earlier.every((x) => typeof x === "string") || vouchedBefore === null || unknown === null) {
      return "override_invalid";
    }
    let escalated: Micros, decided: Micros, checked: Micros;
    try {
      escalated = ts(first);
      decided = ts(od.decided_at);
      checked = ts(dd.checked_at);
    } catch {
      return "override_invalid";
    }
    if (at - escalated > this.overrideWindow || decided < checked || decided > at + this.maxSkew) return "override_invalid";
    const oh = overrideHash(od);
    const osigs = od.sigs as JsonDict[];
    if (!osigs.every((s) => verify("override", oh, s.sig, (s.signer as JsonDict).public_key, this.webauthn))) return "override_invalid";
    const reason = dd.reasons[0] as string;
    if (NOT_OVERRIDABLE.has(reason)) return "override_not_authorized";
    const bankSigs = osigs.filter((s) => this.officers.has((s.signer as JsonDict).public_key as string));
    let who: string, waiver: string, approvers: JsonDict[];
    if (bankSigs.length) {
      who = "override:bank";
      waiver = reason;
      approvers = bankSigs.map((s) => ({ ...(s.signer as JsonDict), role: "bank" }));
    } else if (COMPANY_OVERRIDABLE.has(reason)) {
      [who, approvers] = await this.companyOverride(md, od);
      waiver = reason === "over_period_limit" ? "over_period_limit:mandate" : reason;
    } else return "override_not_authorized";
    // Overrides add up; a signer_unknown waiver vouches only for the people that escalation named.
    const waive = new Set<string>([...(earlier as string[]), waiver]);
    const vouched = new Set<string>([...vouchedBefore, ...(reason === "signer_unknown" ? unknown : [])]);
    state.refs = {
      escalation: { id: dd.id, hash: objHash(dd) }, override: { id: od.id, hash: oh },
      approvers: approvers.map((a) => ({ id: a.id, public_key: a.public_key, role: a.role })),
      waived: [...waive].sort(), escalated_at: first,
    };
    if (vouched.size) state.refs.vouched = [...vouched].sort(pyCompare).map(unkey);
    checks.push(who);
    const [notHeld, customer] = await this.held(md, hasKey(md, "delegation") ? (md.delegation as JsonDict[]) : [],
      pd.from_account as JsonDict);
    if (notHeld) return notHeld;
    const key = paymentKey(customer, pd.id as string);
    let prior: JsonDict | null;
    try {
      prior = await this.payments.lookup(key, pHash!);
    } catch {
      return "checker_unavailable";
    }
    const heldHere = isDict(prior) && prior.id === dd.id;
    if (isDict(prior) && !heldHere) return prior; // already resolved: the same answer again, never a second reservation
    if (heldHere) {
      let took: boolean;
      try {
        took = await this.payments.take(key, pHash!, dd.id as string);
      } catch {
        return "checker_unavailable";
      }
      if (!took) { // another override of this escalation got there first
        let again: JsonDict | null;
        try {
          again = await this.payments.lookup(key, pHash!);
        } catch {
          return "checker_unavailable";
        }
        return isDict(again) ? again : "duplicate_payment";
      }
      state.restore = dd;
    }
    if (od.outcome === "block") {
      if (!heldHere) {
        try {
          if (!(await this.payments.register(key, pHash!))) return "duplicate_payment";
        } catch {
          return "checker_unavailable";
        }
      }
      state.registered = true;
      state.key = key;
      return "blocked_by_override";
    }
    return this.run(m, p, pHash, at, checks, state, waive, heldHere, vouched);
  }

  /**
   * Company signatories resolving an over-limit escalation: as many authorized people as the mandate itself
   * needed (its threshold and the joint rule of everyone who signed it or the override). Throws Stop.
   */
  private async companyOverride(m: JsonDict, o: JsonDict): Promise<[string, JsonDict[]]> {
    const [sigs, threshold] = signatures(m);
    const joints = [threshold];
    for (const [signer] of sigs) {
      try {
        joints.push((await this.authorized(m.company as JsonDict, signer, true, m.issued_at)).joint);
      } catch (e) {
        if (e instanceof Stop && e.reason === "checker_unavailable") throw e;
      }
    }
    const seen = new Set<string>();
    const approvers: JsonDict[] = [];
    for (const s of o.sigs as JsonDict[]) {
      let res: Accepted;
      try {
        res = await this.authorized(m.company as JsonDict, s.signer as JsonDict, true);
      } catch (e) {
        if (e instanceof Stop && e.reason === "checker_unavailable") throw e;
        throw new Stop("override_not_authorized");
      }
      const who = res.person !== null ? "person:" + res.person : "id:" + ((s.signer as JsonDict).id as string);
      if (seen.has(who)) continue;
      seen.add(who);
      joints.push(res.joint);
      approvers.push({ ...(s.signer as JsonDict), role: "company" });
    }
    const needed = Math.max(...joints);
    if (approvers.length < needed) throw new Stop("override_not_authorized");
    return [`override:company:${approvers.length}/${needed}`, approvers];
  }
}

/** Python's sort order on (id, public_key) tuples: by code point, like the reference. */
function pyCompare(a: string, b: string): number {
  const [x, y] = [JSON.parse(a) as string[], JSON.parse(b) as string[]];
  for (let i = 0; i < 2; i++) {
    const p = [...x[i]!].map((c) => c.codePointAt(0)!), q = [...y[i]!].map((c) => c.codePointAt(0)!);
    for (let j = 0; j < Math.min(p.length, q.length); j++) if (p[j] !== q[j]) return p[j]! - q[j]!;
    if (p.length !== q.length) return p.length - q.length;
  }
  return 0;
}

function personKey(p: JsonDict): string {
  return JSON.stringify([p.id, p.public_key]);
}

/**
 * True if the decision was signed by one of the bank's known checker keys and not changed since.
 * checkerKeys come from the bank (its published key list), never from the decision itself.
 */
/** The bank's published checker keys (spec 10.1), served at /.well-known/gleipnir-checker.json. */
export function keyset(checkerId: string, keys: JsonDict[], issuedAt?: string): JsonDict {
  const ks: JsonDict = { v: `gleipnir/keys/${V}`, checker: checkerId, issued_at: issuedAt ?? fmtTs(nowMicros()), keys };
  const problem = keysetProblem(ks);
  if (problem) throw new Error(problem);
  return ks;
}

export function keysetProblem(ks: unknown): string | null {
  if (!isDict(ks) || ks.v !== `gleipnir/keys/${V}`) return "unknown key set version";
  const bad = strFields(ks, ["checker", "issued_at"]);
  if (bad || !jcsOk(ks)) return bad ?? "key set is not valid I-JSON";
  const extra = pySorted(Object.keys(ks).filter((k) => !["v", "checker", "issued_at", "keys"].includes(k)));
  if (extra.length) return `unknown field ${extra[0]}`;
  const keys = hasKey(ks, "keys") ? ks.keys : null;
  if (!Array.isArray(keys) || keys.length === 0) return "keys must be a non-empty list";
  for (const k of keys) {
    if (!isDict(k) || typeof k.public_key !== "string"
      || Object.keys(k).some((f) => !["public_key", "from", "until", "compromised"].includes(f))) {
      return "every key needs public_key, and only from, until, compromised besides";
    }
    if (hasKey(k, "compromised") && typeof k.compromised !== "boolean") return "compromised must be true or false";
    try {
      for (const f of ["from", "until"]) if (hasKey(k, f)) ts(k[f]);
      if (hasKey(k, "from") && hasKey(k, "until") && ts(k.from) >= ts(k.until)) return "a key's from must be before its until";
    } catch (e) {
      return msg(e);
    }
  }
  if (new Set((keys as JsonDict[]).map((k) => k.public_key)).size !== keys.length) return "a key is listed twice";
  try {
    ts(ks.issued_at);
  } catch (e) {
    return msg(e);
  }
  return null;
}

function keyValid(ks: JsonDict, pub: unknown, at: unknown): boolean {
  for (const k of ks.keys as JsonDict[]) {
    if (k.public_key === pub) {
      if (k.compromised === true) return false;
      const t = ts(at);
      return (!hasKey(k, "from") || ts(k.from) <= t) && (!hasKey(k, "until") || t < ts(k.until));
    }
  }
  return false;
}

/**
 * True if the decision was signed by one of the bank's known checker keys and not changed since.
 * checkerKeys come from the bank, never from the decision itself: a list of public keys, or the bank's key set
 * (spec 10.1), in which case the decision must name that checker and fall in the key's window.
 */
export function verifyDecision(decision: unknown, checkerKeys: Iterable<string> | JsonDict): boolean {
  try {
    if (!isDict(decision) || !isDict(decision.checker)) return false;
    const pubText = decision.checker.public_key;
    if (typeof pubText !== "string") return false;
    if (isDict(checkerKeys) && !(Symbol.iterator in checkerKeys)) {
      if (keysetProblem(checkerKeys) || decision.checker.id !== checkerKeys.checker
        || !keyValid(checkerKeys, pubText, decision.checked_at)) return false;
    } else if (!new Set(checkerKeys as Iterable<string>).has(pubText)) return false;
    return verifySignature(decodePublicKey(pubText), mandateMessage("decision", objHash(decision)),
      hasKey(decision, "sig") ? decision.sig : null);
  } catch {
    return false;
  }
}

/** A signed list of the revocations a checker knows (spec 9.2), for checkers that are not told directly. */
export function revocationList(revocations: unknown[], o: { issuer: string; seed: Seed; nextUpdate: string; issuedAt?: string }): JsonDict {
  const doc: JsonDict = {
    v: `gleipnir/revocations/${V}`, issuer: { id: o.issuer, public_key: publicKeyOf(o.seed) },
    issued_at: o.issuedAt ?? fmtTs(nowMicros()), next_update: o.nextUpdate, revocations: [...revocations],
  };
  return sign(o.seed, "revocations", doc);
}

export function revocationListProblem(doc: unknown): string | null {
  if (!isDict(doc) || doc.v !== `gleipnir/revocations/${V}`) return "unknown revocation list version";
  const bad = strFields(doc, ["issuer.id", "issuer.public_key", "issued_at", "next_update"]);
  if (bad || !jcsOk(doc)) return bad ?? "revocation list is not valid I-JSON";
  if (Object.keys(doc).some((k) => !["v", "issuer", "issued_at", "next_update", "revocations", "sig"].includes(k))
    || Object.keys(doc.issuer as JsonDict).some((k) => k !== "id" && k !== "public_key")) {
    return "unknown field in revocation list";
  }
  if (!Array.isArray(hasKey(doc, "revocations") ? doc.revocations : null)) return "revocations must be a list";
  try {
    if (ts(doc.next_update) <= ts(doc.issued_at)) return "next_update must be after issued_at";
  } catch (e) {
    return msg(e);
  }
  return null;
}

/**
 * The revocations of a current, validly signed list from a trusted issuer, else throws (spec 9.2). Current: issued
 * no later than `at` (plus a minute) and `at` before `next_update`.
 */
export function revocationsFromList(doc: unknown, issuerKeys: Iterable<string> | JsonDict, at: Date): JsonDict[] {
  const problem = revocationListProblem(doc);
  if (problem) throw new Error(problem);
  const d = doc as JsonDict;
  const issuer = d.issuer as JsonDict;
  const pub = issuer.public_key as string;
  if (isDict(issuerKeys) && !(Symbol.iterator in issuerKeys)) {
    if (keysetProblem(issuerKeys) || issuerKeys.checker !== issuer.id || !keyValid(issuerKeys, pub, d.issued_at)) {
      throw new Error("revocation list issuer key not trusted");
    }
  } else if (!new Set(issuerKeys as Iterable<string>).has(pub)) throw new Error("revocation list issuer key not trusted");
  if (!verify("revocations", objHash(d), hasKey(d, "sig") ? d.sig : null, pub, {})) {
    throw new Error("revocation list signature is invalid");
  }
  const now = microsFromDate(at);
  if (ts(d.issued_at) > now + 60_000_000n || now >= ts(d.next_update)) throw new Error("revocation list is not current");
  return (d.revocations as unknown[]).filter((r): r is JsonDict => isDict(r));
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
  approved_by: string[];
  payment: { id: unknown; amount: unknown; currency: unknown; from: unknown; payee: unknown };
}

/**
 * Check a receipt offline, months later, without the bank: who authorized this payment, what was decided.
 * Verifies the decision against the bank's known keys, that it names exactly this mandate and payment, and
 * every signature in the mandate, its delegation chain and the payment. A decision made on an override also
 * needs that override: its hash must match and its signatures must be valid. It cannot re-run the bank's
 * authority check; `signer_authorized:<source>` and `override:<who>` checks record what the bank relied on.
 */
export function verifyReceipt(
  mandate: unknown, payment: unknown, decision: unknown, checkerKeys: Iterable<string> | JsonDict,
  opts: { webauthn?: WebauthnOptions; override?: unknown } = {},
): Receipt {
  const wa = opts.webauthn ?? {};
  const problems: string[] = [];
  let signedBy: string[] = [];
  let chainView: string[] = [];
  let approvedBy: string[] = [];
  if (!verifyDecision(decision, checkerKeys)) problems.push("decision_bad_signature");
  const mOk = mandateProblem(mandate) === null;
  const md = mandate as JsonDict;
  if (!mOk) problems.push("mandate_malformed");
  else {
    const mh = mandateHash(md);
    if (get(decision, "mandate.hash") !== mh) problems.push("decision_mandate_mismatch");
    const [sigs] = signatures(md);
    const valid = sigs.filter(([s, sig]) => verify("mandate", mh, sig, s.public_key, wa)).map(([s]) => s);
    signedBy = valid.map((s) => s.id as string);
    if (sigs.length === 0 || valid.length !== sigs.length) problems.push("mandate_bad_signature");
    const recorded = get(decision, "signers");
    if (recorded !== null) {
      // The bank recorded whom it counted; the receipt shows exactly those, each with a valid signature here.
      const counted = persons(recorded);
      const have = new Set(valid.map(personKey));
      if (counted === null || !counted.every((k) => have.has(k))) problems.push("mandate_signers_mismatch");
      else signedBy = counted.map((k) => unkey(k).id);
    }
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
  const ref = get(decision, "override");
  const ov = opts.override;
  if (ref !== null || (ov !== undefined && ov !== null)) {
    if (ov === undefined || ov === null) problems.push("override_missing");
    else if (overrideProblem(ov) || !isDict(ref)
      || !same(ref, { id: (ov as JsonDict).id, hash: overrideHash(ov as JsonDict) })
      || !same((ov as JsonDict).decision, get(decision, "escalation"))) {
      problems.push("override_mismatch");
    } else {
      const od = ov as JsonDict;
      const oh = overrideHash(od);
      const valid = new Set((od.sigs as JsonDict[])
        .filter((s) => verify("override", oh, s.sig, (s.signer as JsonDict).public_key, wa)).map((s) => personKey(s.signer as JsonDict)));
      const approvers = get(decision, "approvers");
      const listed = Array.isArray(approvers) && approvers.every((a) => isDict(a))
        ? persons((approvers as JsonDict[]).map((a) => ({ id: hasKey(a, "id") ? a.id : null, public_key: hasKey(a, "public_key") ? a.public_key : null })))
        : null;
      // Who approved is what the bank recorded, each with a valid signature on this override.
      if (listed === null || listed.length === 0 || !listed.every((k) => valid.has(k))) problems.push("override_bad_signature");
      else approvedBy = (approvers as JsonDict[]).map((a) => a.id as string);
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
    authority: Array.isArray(checks)
      ? checks.filter((c): c is string => typeof c === "string" && (c.startsWith("signer_authorized:") || c.startsWith("override:")))
      : [],
    approved_by: approvedBy,
    payment: {
      id: get(payment, "id"), amount: get(payment, "amount"), currency: get(payment, "currency"),
      from: get(payment, "from_account"), payee: get(payment, "payee.account"),
    },
  };
}

// ---------- ISO 20022 (spec 6.2) ----------

export const PAIN001_NS = "urn:iso:std:iso:20022:tech:xsd:pain.001.001.09";
const GNS = `urn:gleipnir:payment:${V}`;
const MAX_XML = 1 << 20;
const CLEARING: Record<string, [string, string | null]> = {
  us_aba: ["USABA", "routing"], uk_sort_code: ["GBDSC", "sort_code"], ca_eft: ["CACPA", null], au_bsb: ["AUBSB", "bsb"],
  in_ifsc: ["INFSC", "ifsc"],
};

function xesc(t: string): string {
  return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function xel(name: string, children: string[] | { text: string }, attrs = ""): string {
  const inner = Array.isArray(children) ? children.join("") : xesc(children.text);
  return `<${name}${attrs}>${inner}</${name}>`;
}

const T = (text: string) => ({ text });

function xmember(acc: JsonDict): string | null {
  const c = CLEARING[acc.scheme as string];
  if (!c) return null;
  return c[1] === null ? "0" + (acc.institution as string) + (acc.transit as string) : (acc[c[1]] as string);
}

function xaccount(acc: JsonDict): string {
  if (acc.scheme === "iban") return xel("Id", [xel("IBAN", T(acc.iban as string))]);
  if (acc.scheme === "mx_clabe") {
    return xel("Id", [xel("Othr", [xel("Id", T(acc.clabe as string)), xel("SchmeNm", [xel("Prtry", T("CLABE"))])])]);
  }
  return xel("Id", [xel("Othr", [xel("Id", T(acc.account as string))])]);
}

function xagent(acc: JsonDict): string {
  if (acc.scheme === "swift") return xel("FinInstnId", [xel("BICFI", T(acc.bic as string))]);
  const member = xmember(acc);
  if (member !== null) {
    const code = CLEARING[acc.scheme as string]![0];
    return xel("FinInstnId", [xel("ClrSysMmbId", [xel("ClrSysId", [xel("Cd", T(code))]), xel("MmbId", T(member))])]);
  }
  return xel("FinInstnId", [xel("Othr", [xel("Id", T("NOTPROVIDED"))])]);
}

function xpaymentType(rail: string): string {
  if (rail === "sepa") return xel("PmtTpInf", [xel("SvcLvl", [xel("Cd", T("SEPA"))])]);
  if (rail === "sepa_instant") {
    return xel("PmtTpInf", [xel("SvcLvl", [xel("Cd", T("SEPA"))]), xel("LclInstrm", [xel("Cd", T("INST"))])]);
  }
  return xel("PmtTpInf", [xel("LclInstrm", [xel("Prtry", T(rail))])]);
}

/** The pain.001.001.09 Document for one checked payment (spec 6.2). Throws for a malformed payment. */
export function pain001(mandate: JsonDict, payment: JsonDict, decision?: JsonDict | null): string {
  const problem = mandateProblem(mandate) ?? paymentProblem(payment);
  if (problem) throw new Error(problem);
  const p = payment, co = (mandate.company as JsonDict).name as string;
  const payee = p.payee as JsonDict;
  const payeeAcc = payee.account as JsonDict, from = p.from_account as JsonDict;
  const env = [xel("Mandate", T(mandateHash(mandate))), xel("Payment", T(objHash(p, "agent_sig")))];
  if (decision) env.push(xel("Decision", T(objHash(decision))));
  const tx = [xel("PmtId", [xel("EndToEndId", T(p.id as string))]),
    xel("Amt", [xel("InstdAmt", T(p.amount as string), ` Ccy="${p.currency as string}"`)]),
    xel("CdtrAgt", [xagent(payeeAcc)]),
    xel("Cdtr", [xel("Nm", T(typeof payee.name === "string" && payee.name ? payee.name : "NOTPROVIDED"))]),
    xel("CdtrAcct", [xaccount(payeeAcc)])];
  if (typeof p.reference === "string" && p.reference) tx.push(xel("RmtInf", [xel("Ustrd", T(p.reference))]));
  tx.push(xel("SplmtryData", [xel("PlcAndNm", T("Gleipnir")), xel("Envlp", [xel("Gleipnir", env, ` xmlns="${GNS}"`)])]));
  const amount = p.amount as string;
  const pmt = xel("PmtInf", [xel("PmtInfId", T(p.id as string)), xel("PmtMtd", T("TRF")), xel("NbOfTxs", T("1")),
    xel("CtrlSum", T(amount)), xpaymentType(p.rail as string),
    xel("ReqdExctnDt", [xel("Dt", T((p.requested_at as string).slice(0, 10)))]), xel("Dbtr", [xel("Nm", T(co))]),
    xel("DbtrAcct", [xaccount(from)]), xel("DbtrAgt", [xagent(from)]), xel("CdtTrfTxInf", tx)]);
  const hdr = xel("GrpHdr", [xel("MsgId", T(p.id as string)), xel("CreDtTm", T(p.requested_at as string)),
    xel("NbOfTxs", T("1")), xel("CtrlSum", T(amount)), xel("InitgPty", [xel("Nm", T(co))])]);
  return '<?xml version="1.0" encoding="UTF-8"?>' + xel("Document", [xel("CstmrCdtTrfInitn", [hdr, pmt])], ` xmlns="${PAIN001_NS}"`);
}

class XBad extends Error {}

function xscreen(xml: unknown): string {
  if (typeof xml !== "string" || new TextEncoder().encode(xml).length > MAX_XML) throw new XBad("xml_malformed");
  const upper = xml.toUpperCase();
  if (upper.includes("<!DOCTYPE") || upper.includes("<!ENTITY") || upper.includes("<![CDATA[")) throw new XBad("xml_malformed");
  for (let k = xml.indexOf("<?"); k >= 0; k = xml.indexOf("<?", k + 1)) {
    if (k !== 0 || !xml.startsWith("<?xml ")) throw new XBad("xml_malformed");
  }
  return xml;
}

function xcheckNs(el: XmlElement, ns: string): void {
  for (const c of el.children) {
    if (c.ns !== ns) throw new XBad("xml_malformed");
    if (c.local === "Envlp") {
      const walk = (x: XmlElement) => {
        if (x.ns !== GNS) throw new XBad("xml_malformed");
        x.children.forEach(walk);
      };
      c.children.forEach(walk);
    } else xcheckNs(c, ns);
  }
}

function xfind(el: XmlElement | null, path: string, ns = PAIN001_NS): XmlElement | null {
  for (const part of path.split("/")) {
    if (el === null) return null;
    const hits = el.children.filter((c) => c.ns === ns && c.local === part);
    if (hits.length !== 1) return null;
    el = hits[0]!;
  }
  return el;
}

function xtext(el: XmlElement | null, path: string, ns = PAIN001_NS): string | null {
  const f = xfind(el, path, ns);
  if (f === null || f.children.length) return null;
  return f.text.trim();
}

function xreadAccount(acct: XmlElement | null, agent: XmlElement | null, like: JsonDict): JsonDict | null {
  const scheme = like.scheme as string;
  if (scheme === "iban") {
    const v = xtext(acct, "Id/IBAN");
    return v === null ? null : { scheme: "iban", iban: v };
  }
  if (scheme === "mx_clabe") {
    if (xtext(acct, "Id/Othr/SchmeNm/Prtry") !== "CLABE") return null;
    const v = xtext(acct, "Id/Othr/Id");
    return v === null ? null : { scheme: "mx_clabe", clabe: v };
  }
  const number = xtext(acct, "Id/Othr/Id");
  if (number === null) return null;
  if (scheme === "swift") {
    const bic = xtext(agent, "FinInstnId/BICFI");
    return bic === null ? null : { scheme: "swift", bic, account: number };
  }
  const [code, field] = CLEARING[scheme]!;
  if (xtext(agent, "FinInstnId/ClrSysMmbId/ClrSysId/Cd") !== code) return null;
  const member = xtext(agent, "FinInstnId/ClrSysMmbId/MmbId");
  if (member === null) return null;
  if (field === null) {
    if ([...member].length !== 9 || !member.startsWith("0")) return null;
    return { scheme: "ca_eft", institution: member.slice(1, 4), transit: member.slice(4), account: number };
  }
  return { scheme, [field]: member, account: number };
}

/**
 * Why this pain.001 is not exactly the payment the checker decided on, or [] if it is (spec 6.2): the one
 * transaction whose EndToEndId is the payment id, compared on amount, currency, debtor and creditor accounts and
 * the Gleipnir envelope.
 */
export function pain001Problems(xml: unknown, mandate: JsonDict, payment: JsonDict, decision?: JsonDict | null): string[] {
  if (mandateProblem(mandate) || paymentProblem(payment)) return ["payment_malformed"];
  let hits: [XmlElement, XmlElement][];
  try {
    let root: XmlElement;
    try {
      root = parseXml(xscreen(xml));
    } catch (e) {
      if (e instanceof XBad) throw e;
      throw new XBad("xml_malformed");
    }
    if (root.ns !== PAIN001_NS || root.local !== "Document") throw new XBad("xml_not_pain001");
    xcheckNs(root, PAIN001_NS);
    const initn = xfind(root, "CstmrCdtTrfInitn");
    if (initn === null) throw new XBad("xml_not_pain001");
    hits = [];
    for (const pmt of initn.children) {
      if (pmt.ns !== PAIN001_NS || pmt.local !== "PmtInf") continue;
      for (const tx of pmt.children) {
        if (tx.ns === PAIN001_NS && tx.local === "CdtTrfTxInf" && xtext(tx, "PmtId/EndToEndId") === payment.id) hits.push([pmt, tx]);
      }
    }
  } catch (e) {
    return [e instanceof XBad ? e.message : "xml_malformed"];
  }
  if (hits.length === 0) return ["end_to_end_id_not_found"];
  if (hits.length > 1) return ["end_to_end_id_not_unique"];
  const [pmt, tx] = hits[0]!;
  const problems: string[] = [];
  const amt = xfind(tx, "Amt/InstdAmt");
  if (amt === null || amt.children.length || amt.text.trim() !== payment.amount) problems.push("amount_mismatch");
  if (amt === null || amt.attrs.Ccy !== payment.currency) problems.push("currency_mismatch");
  const from = payment.from_account as JsonDict;
  if (!same(xreadAccount(xfind(pmt, "DbtrAcct"), xfind(pmt, "DbtrAgt"), from), from)) problems.push("debtor_account_mismatch");
  const payeeAcc = (payment.payee as JsonDict).account as JsonDict;
  if (!same(xreadAccount(xfind(tx, "CdtrAcct"), xfind(tx, "CdtrAgt"), payeeAcc), payeeAcc)) problems.push("creditor_account_mismatch");
  const env = xfind(tx, "SplmtryData/Envlp");
  const g = env ? env.children.filter((c) => c.ns === GNS && c.local === "Gleipnir") : [];
  const gl = g.length === 1 ? g[0]! : null;
  if (xtext(gl, "Mandate", GNS) !== mandateHash(mandate)) problems.push("mandate_reference_mismatch");
  if (xtext(gl, "Payment", GNS) !== objHash(payment, "agent_sig")) problems.push("payment_reference_mismatch");
  if (decision && xtext(gl, "Decision", GNS) !== objHash(decision)) problems.push("decision_reference_mismatch");
  return problems;
}
