/**
 * Ready-made outcome read-back checks (Stripe, Zendesk, generic HTTP). Same semantics as the Python
 * `gleipnir.outcomes` package; see docs/outcome-checks.md.
 */

export {
  ABSENT,
  ConfigError,
  HttpError,
  NotFound,
  SKIP,
  arg,
  constant,
  firstOf,
  jsonGet,
  optArg,
  resp,
  toMinorUnits,
  valuesEqual,
  type Fields,
  type JsonFetch,
  type JsonGetOptions,
  type OutcomeCheckFn,
  type RetryOptions,
  type Spec,
} from "./core.js";
export { httpJsonMatches, type HttpJsonMatchesOptions } from "./http.js";
export * as stripe from "./stripe.js";
export * as zendesk from "./zendesk.js";
