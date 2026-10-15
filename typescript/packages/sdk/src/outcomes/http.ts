/**
 * Generic read-back over HTTP/JSON (mirrors `gleipnir.outcomes.http`): build the object's URL from
 * the call and the tool's response, fetch it, and compare expected fields (dotted paths).
 */

import type { Call } from "../recorder.js";
import {
  ABSENT,
  Check,
  ConfigError,
  NotFound,
  checkFn,
  getPath,
  resolveFields,
  valuesEqual,
  type Fields,
  type OutcomeCheckFn,
  type RetryOptions,
} from "./core.js";

export interface HttpJsonMatchesOptions extends RetryOptions {
  getUrl: (call: Call, response: unknown) => string;
  fetch: (url: string) => unknown | Promise<unknown>;
  expected: Fields;
  /** Dotted path to the object inside the body, e.g. "data". */
  root?: string;
  /** Per-field comparison overrides. */
  eq?: Record<string, (expected: unknown, observed: unknown) => boolean>;
  method?: string;
}

export function httpJsonMatches(opts: HttpJsonMatchesOptions): OutcomeCheckFn {
  if (typeof opts?.getUrl !== "function" || typeof opts.fetch !== "function") throw new TypeError("getUrl and fetch must be functions");
  const method = opts.method ?? "http.json_matches";
  return checkFn(method, async (call, response) => {
    const url = opts.getUrl(call, response);
    if (typeof url !== "string" || !url) throw new ConfigError("getUrl returned no URL");
    const want = resolveFields(opts.expected, call, response);
    const body = await opts.fetch(url);
    const obj = opts.root === undefined ? body : getPath(body, opts.root);
    if (obj === null || obj === undefined || obj === ABSENT || (typeof obj === "object" && Object.keys(obj as object).length === 0)) {
      throw new NotFound(url);
    }
    const c = new Check(method);
    for (const [k, v] of Object.entries(want)) c.field(k, v, getPath(obj, k), opts.eq?.[k] ?? valuesEqual);
    return c.outcome();
  }, opts);
}
