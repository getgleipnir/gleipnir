/**
 * Shared machinery for the ready-made outcome read-back checks (mirrors `gleipnir.outcomes._core`).
 *
 * Each factory builds an async `verifyOutcome` callback that reads the object back from the system
 * of record through an injected client, compares only the requested fields, and returns `match`,
 * `mismatch` (with the mismatched fields; a missing object is `fields: ["exists"]`) or `error`.
 * It never throws. Optional bounded retries with exponential backoff (default off).
 *
 * The callbacks are async, so wrap an async tool (the recorder awaits checks only for async tools).
 */

import { Outcome, type Call } from "../recorder.js";

export const SKIP: unique symbol = Symbol("SKIP");
export const ABSENT: unique symbol = Symbol("ABSENT");
type Skip = typeof SKIP;
type Absent = typeof ABSENT;

/**
 * How a factory learns an expected value or an id: a tool argument name (missing = error), a
 * function `(call, response) => value` (return `SKIP` to skip), or `null` (don't check).
 */
export type Spec = string | ((call: Call, response: unknown) => unknown) | null | undefined;

/** Which fields to compare: names (= tool args of the same name), a `{field: value}` map, or a function returning one. */
export type Fields =
  | readonly string[]
  | Record<string, unknown>
  | ((call: Call, response: unknown) => Record<string, unknown> | null | undefined)
  | null
  | undefined;

export class NotFound extends Error {
  override name = "NotFound";
}

export class ConfigError extends Error {
  override name = "ConfigError";
}

export class HttpError extends Error {
  override name = "HttpError";
  constructor(readonly status: number, readonly url: string, readonly body = "") {
    super(`HTTP ${status} from ${url}${body ? `: ${body.slice(0, 200)}` : ""}`);
  }
}

// ---- specs ------------------------------------------------------------------------------------
export function arg(name: string): (call: Call) => unknown {
  return (call) => {
    if (!Object.prototype.hasOwnProperty.call(call.args, name)) throw new ConfigError(`call has no argument "${name}"`);
    return call.args[name];
  };
}

export function optArg(name: string): (call: Call) => unknown {
  return (call) => {
    const v = call.args[name];
    return v === null || v === undefined ? SKIP : v;
  };
}

export function resp(path: string): (call: Call, response: unknown) => unknown {
  return (_call, response) => {
    const v = getPath(response, path);
    return v === ABSENT || v === null || v === undefined ? SKIP : v;
  };
}

export function constant(value: unknown): () => unknown {
  return () => value;
}

export function firstOf(...specs: Spec[]): (call: Call, response: unknown) => unknown {
  return (call, response) => {
    for (const s of specs) {
      const v = resolve(s, call, response);
      if (v !== SKIP) return v;
    }
    return SKIP;
  };
}

export function resolve(spec: Spec, call: Call, response: unknown): unknown {
  if (spec === null || spec === undefined) return SKIP;
  if (typeof spec === "string") return arg(spec)(call);
  if (typeof spec === "function") {
    const v = spec(call, response);
    return v === undefined ? SKIP : v;
  }
  throw new ConfigError("a spec must be an argument name, a function or null");
}

export function resolveId(spec: Spec, call: Call, response: unknown, what: string): string {
  let v = resolve(spec, call, response);
  if (v === SKIP || v === null || v === "") throw new ConfigError(`could not determine the ${what} to read back`);
  if (typeof v === "object") v = getPath(v, "id");
  if (v === ABSENT || v === null || v === undefined) throw new ConfigError(`could not determine the ${what} to read back`);
  return String(v);
}

export function resolveFields(fields: Fields, call: Call, response: unknown): Record<string, unknown> {
  if (fields === null || fields === undefined) return {};
  let entries: [string, unknown][];
  if (typeof fields === "function") {
    const got = fields(call, response);
    if (got === null || got === undefined) return {};
    if (typeof got !== "object" || Array.isArray(got)) throw new ConfigError("a fields function must return an object");
    entries = Object.entries(got);
  } else if (Array.isArray(fields)) {
    entries = (fields as readonly string[])
      .filter((f) => Object.prototype.hasOwnProperty.call(call.args, f))
      .map((f) => [f, call.args[f]]);
  } else {
    entries = Object.entries(fields).map(([k, v]) => [k, typeof v === "function" ? (v as (c: Call, r: unknown) => unknown)(call, response) : v]);
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of entries) if (v !== SKIP && v !== undefined) out[k] = v;
  return out;
}

// ---- reading ----------------------------------------------------------------------------------
export function getPath(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const part of path.split(".")) {
    if (cur === null || cur === undefined || typeof cur !== "object") return ABSENT;
    if (Array.isArray(cur)) {
      if (!/^\d+$/.test(part) || Number(part) >= cur.length) return ABSENT;
      cur = cur[Number(part)];
      continue;
    }
    if (!Object.prototype.hasOwnProperty.call(cur, part)) return ABSENT;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

export function objectId(v: unknown): unknown {
  if (v === null || v === undefined || v === ABSENT || typeof v !== "object") return v;
  const id = getPath(v, "id");
  return id === ABSENT ? v : id;
}

// ---- comparing --------------------------------------------------------------------------------
function num(v: unknown): number | null {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "bigint") return Number(v);
  if (typeof v === "string" && /^\s*[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\s*$/.test(v)) return Number(v);
  return null;
}

/** Same rules as the Python side: numbers numerically, ids as text, booleans accept "true"/"false",
 * null accepts missing/empty, arrays element-wise, objects as a subset. */
export function valuesEqual(expected: unknown, observed: unknown): boolean {
  if (expected === SKIP) return true;
  if (expected === ABSENT) return observed === ABSENT;
  if (expected === null) return observed === null || observed === undefined || observed === ABSENT || observed === "";
  if (observed === ABSENT || observed === undefined) return false;
  if (typeof expected === "boolean") {
    if (typeof observed === "boolean") return observed === expected;
    return typeof observed === "string" && observed.trim().toLowerCase() === String(expected);
  }
  if (Array.isArray(expected)) {
    return Array.isArray(observed) && observed.length === expected.length && expected.every((e, i) => valuesEqual(e, observed[i]));
  }
  if (typeof expected === "object") {
    if (observed === null || typeof observed !== "object" || Array.isArray(observed)) return false;
    return Object.entries(expected as Record<string, unknown>).every(([k, v]) =>
      valuesEqual(v, Object.prototype.hasOwnProperty.call(observed, k) ? (observed as Record<string, unknown>)[k] : ABSENT));
  }
  if (typeof observed === "boolean") return typeof expected === "string" && expected.trim().toLowerCase() === String(observed);
  const a = num(expected);
  const b = num(observed);
  if (a !== null && b !== null && !(typeof expected === "string" && typeof observed === "string")) return a === b;
  if (typeof expected === "string" || typeof observed === "string") return String(expected) === String(observed);
  return expected === observed;
}

export function ciEqual(expected: unknown, observed: unknown): boolean {
  if (typeof expected === "string" && typeof observed === "string") return expected.toLowerCase() === observed.toLowerCase();
  return valuesEqual(expected, observed);
}

export function oneOf(expected: unknown, observed: unknown): boolean {
  if (Array.isArray(expected)) return expected.some((e) => valuesEqual(e, observed));
  return valuesEqual(expected, observed);
}

function strSet(v: unknown): Set<string> | null {
  if (typeof v === "string") return new Set([v]);
  if (Array.isArray(v)) return new Set(v.map(String));
  return null;
}

export function sameSet(expected: unknown, observed: unknown): boolean {
  const a = strSet(expected);
  const b = strSet(observed);
  return a !== null && b !== null && a.size === b.size && [...a].every((x) => b.has(x));
}

export function includesAll(expected: unknown, observed: unknown): boolean {
  const a = strSet(expected);
  const b = strSet(observed);
  return a !== null && b !== null && [...a].every((x) => b.has(x));
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

export function normText(v: unknown): string {
  if (v === null || v === undefined || v === ABSENT) return "";
  return String(v)
    .replace(/<[^>]+>/g, " ")
    .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
      if (e[0] === "#") {
        const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return Number.isFinite(code) ? String.fromCodePoint(code) : m;
      }
      return ENTITIES[e.toLowerCase()] ?? m;
    })
    .replace(/\s+/g, " ")
    .trim();
}

type Eq = (expected: unknown, observed: unknown) => boolean;

function clean(v: unknown): unknown {
  return v === ABSENT || v === undefined ? null : v;
}

export class Check {
  readonly observed: Record<string, unknown> = {};
  readonly mismatched: string[] = [];
  compared = 0;
  constructor(readonly method: string) {}

  field(name: string, expected: unknown, observed: unknown, eq: Eq = valuesEqual): void {
    if (expected === SKIP) return;
    this.compared++;
    this.observed[name] = clean(observed);
    if (!eq(expected, observed)) this.mismatched.push(name);
  }

  note(name: string, value: unknown): void {
    this.observed[name] = clean(value);
  }

  fail(name: string, observed: unknown): void {
    this.compared++;
    this.observed[name] = clean(observed);
    this.mismatched.push(name);
  }

  require(name: string, ok: boolean, observed: unknown): void {
    if (ok) {
      this.compared++;
      this.observed[name] = clean(observed);
    } else this.fail(name, observed);
  }

  outcome(): Outcome {
    if (!this.compared) return new Outcome("error", null, [], "no fields to compare: every expected value was skipped", this.method);
    if (this.mismatched.length) {
      const fields = [...new Set(this.mismatched)].sort();
      return new Outcome("mismatch", { ...this.observed }, fields, `mismatched: ${fields.join(", ")}`, this.method);
    }
    return new Outcome("match", { ...this.observed }, [], null, this.method);
  }
}

// ---- money ------------------------------------------------------------------------------------
const EXP0 = "BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF".split(" ");
const EXP3 = "BHD IQD JOD KWD LYD OMR TND".split(" ");

export function currencyExponent(currency: string): number {
  const c = currency.toUpperCase();
  if (EXP0.includes(c)) return 0;
  if (EXP3.includes(c)) return 3;
  if (c === "CLF" || c === "UYW") return 4;
  return 2;
}

/** `"209.00"` USD -> 20900, exactly (string arithmetic, no floats). */
export function toMinorUnits(amount: unknown, currency: string): number {
  const s = typeof amount === "number" ? String(amount) : typeof amount === "string" ? amount.trim() : "";
  const m = /^([+-]?)(\d*)(?:\.(\d*))?$/.exec(s);
  if (!s || !m || (!m[2] && !m[3])) throw new Error(`not a decimal amount: ${JSON.stringify(amount)}`);
  const exp = currencyExponent(currency);
  const frac = (m[3] ?? "").replace(/0+$/, "");
  if (frac.length > exp) throw new Error(`${s} has more decimals than ${currency.toUpperCase()} allows`);
  const v = Number((m[2] || "0") + frac.padEnd(exp, "0"));
  return m[1] === "-" ? -v : v;
}

export function expectMinor(v: unknown, what = "amount"): unknown {
  if (v === SKIP) return v;
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new ConfigError(`expected ${what} must be an integer in minor units (cents), got ${JSON.stringify(v)}`);
  }
  return v;
}

// ---- errors and retries -----------------------------------------------------------------------
export function httpStatus(exc: unknown): number | null {
  if (!exc || typeof exc !== "object") return null;
  const e = exc as Record<string, unknown>;
  for (const k of ["status", "statusCode", "http_status"]) {
    const v = e[k];
    if (typeof v === "number" && v >= 100 && v < 600) return v;
  }
  const r = e["response"] as Record<string, unknown> | undefined;
  if (r && typeof r === "object") for (const k of ["status", "statusCode"]) {
    const v = r[k];
    if (typeof v === "number" && v >= 100 && v < 600) return v;
  }
  return null;
}

export function classify(exc: unknown): "not_found" | "transient" | "fatal" {
  if (exc instanceof NotFound) return "not_found";
  if (exc instanceof ConfigError) return "fatal";
  const st = httpStatus(exc);
  const e = (exc && typeof exc === "object" ? exc : {}) as Record<string, unknown>;
  const code = e["code"];
  const name = String(e["name"] ?? (exc as object)?.constructor?.name ?? "");
  if (st === 404 || code === "resource_missing" || code === "RecordNotFound" || name.includes("NotFound")) return "not_found";
  if (st !== null) return [408, 409, 425, 429].includes(st) || st >= 500 ? "transient" : "fatal";
  if (typeof code === "string" && ["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "EAI_AGAIN", "ENOTFOUND", "EPIPE", "UND_ERR_CONNECT_TIMEOUT"].includes(code)) return "transient";
  if (/Timeout|Connection|RateLimit|Abort|Network|Fetch/i.test(name)) return "transient";
  if (exc instanceof TypeError && /fetch failed/i.test(exc.message)) return "transient";
  return "fatal";
}

export function errorText(exc: unknown): string {
  const st = httpStatus(exc);
  const name = exc instanceof Error ? exc.name : typeof exc;
  const msg = exc instanceof Error ? exc.message : String(exc);
  return `${name}${st ? ` (HTTP ${st})` : ""}: ${msg}`.slice(0, 500);
}

export interface RetryOptions {
  /** Extra reads after the first (0-10, default 0). */
  retries?: number;
  /** First delay in seconds (default 0.5), doubled each time. */
  backoff?: number;
  /** Delay cap in seconds (default 4). */
  maxBackoff?: number;
  /** Injected sleeper (ms), for tests. */
  sleep?: (ms: number) => Promise<void> | void;
}

export type OutcomeCheckFn = (call: Call, response: unknown) => Promise<Outcome>;

export function checkFn(method: string, read: (call: Call, response: unknown) => Promise<Outcome>, opts: RetryOptions = {}): OutcomeCheckFn {
  const retries = opts.retries ?? 0;
  if (!Number.isInteger(retries) || retries < 0 || retries > 10) throw new RangeError("retries must be an integer from 0 to 10");
  const backoff = opts.backoff ?? 0.5;
  const maxBackoff = opts.maxBackoff ?? 4;
  if (backoff < 0 || maxBackoff < 0) throw new RangeError("backoff and maxBackoff must be >= 0");
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const attempts = retries + 1;
  return async (call, response) => {
    let outcome = new Outcome("error", null, [], "not run", method);
    let i = 0;
    for (; i < attempts; i++) {
      let retryable: boolean;
      try {
        outcome = await read(call, response);
        retryable = outcome.check === "mismatch";
      } catch (exc) {
        const kind = classify(exc);
        if (kind === "not_found") {
          const m = exc instanceof Error && exc.message ? ` (${exc.message})` : "";
          outcome = new Outcome("mismatch", { exists: false }, ["exists"], `object not found${m}`.slice(0, 500), method);
          retryable = true;
        } else {
          outcome = new Outcome("error", null, [], (exc instanceof ConfigError ? "configuration: " : "") + errorText(exc), method);
          retryable = kind === "transient";
        }
      }
      if (outcome.check === "match" || !retryable || i === attempts - 1) break;
      try {
        await sleep(Math.min(backoff * 2 ** i, maxBackoff) * 1000);
      } catch {
        break;
      }
    }
    if (attempts > 1 && i > 0) {
      const note = `after ${i + 1} attempts`;
      outcome = new Outcome(outcome.check, outcome.observed, outcome.fields, outcome.detail ? `${outcome.detail}; ${note}` : note, method);
    }
    return outcome;
  };
}

/** A minimal JSON fetcher: `path => parsed JSON`. */
export type JsonFetch = (path: string) => unknown | Promise<unknown>;

export interface JsonGetOptions {
  headers?: Record<string, string>;
  timeoutMs?: number;
  /** Injected fetch (default: global fetch). */
  fetch?: typeof globalThis.fetch;
}

/** `jsonGet("https://acme.zendesk.com", {headers})("/api/v2/tickets/1.json")`. Non-2xx throws HttpError. */
export function jsonGet(baseUrl: string, opts: JsonGetOptions = {}): JsonFetch {
  const base = baseUrl.replace(/\/+$/, "");
  const headers = { Accept: "application/json", ...(opts.headers ?? {}) };
  const f = opts.fetch ?? globalThis.fetch;
  return async (path: string) => {
    const url = /^https?:\/\//.test(path) ? path : `${base}/${path.replace(/^\/+/, "")}`;
    const res = await f(url, { method: "GET", headers, signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000) });
    const text = await res.text();
    if (!res.ok) throw new HttpError(res.status, url, text);
    return text ? JSON.parse(text) : null;
  };
}

export type { Skip, Absent };
