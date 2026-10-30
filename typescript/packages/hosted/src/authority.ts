/**
 * A tenant's authority table (what its KYB knows): who may sign for which company with which keys, and which
 * accounts each company holds. Same shape as the --authority file of `gleipnir mandate serve`.
 */

import { accountProblem, type Authority, type Holds } from "@getgleipnir/verify/mandate";

type J = Record<string, unknown>;

export interface AuthorityDoc {
  source?: string;
  signers: { company: string; signer: string; keys: string[]; may_sign?: boolean; joint?: number;
    retired?: Record<string, string>; person?: string }[];
  accounts: { company: string; account: J; customer?: string }[];
  officers?: string[];
  require_payees?: boolean;
  webauthn?: { rp_id?: string; origins?: string[] };
}

export const EMPTY_AUTHORITY: AuthorityDoc = { source: "bank_kyb", signers: [], accounts: [] };

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
