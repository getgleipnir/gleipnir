/**
 * Stripe read-back checks (mirrors `gleipnir.outcomes.stripe`).
 *
 * Field names and statuses from the Stripe API reference:
 * - Refund object: https://docs.stripe.com/api/refunds/object (`amount` in the smallest currency
 *   unit, `currency` lowercase, `charge`, `payment_intent`, `status` one of `pending`,
 *   `requires_action`, `succeeded`, `failed`, `canceled`; `failure_reason`; `metadata`)
 * - PaymentIntent object: https://docs.stripe.com/api/payment_intents/object
 * - Customer object: https://docs.stripe.com/api/customers/object (deleted: `{id, deleted: true}`)
 * - Errors: https://docs.stripe.com/error-handling (404 / `resource_missing`)
 *
 * `client` is a `stripe` Node client (`client.refunds.retrieve(id)`; `client.v1.refunds` also
 * works) or a function `path => JSON` such as `jsonGet("https://api.stripe.com", {headers})`.
 */

import type { Call, Outcome } from "../recorder.js";
import {
  ABSENT,
  Check,
  ConfigError,
  NotFound,
  checkFn,
  ciEqual,
  expectMinor,
  firstOf,
  getPath,
  objectId,
  oneOf,
  optArg,
  resolve,
  resolveFields,
  resolveId,
  resp,
  type Fields,
  type OutcomeCheckFn,
  type RetryOptions,
  type Spec,
} from "./core.js";

export const DOCS = "https://docs.stripe.com/api";
export const REFUND_OK_STATUSES = ["pending", "requires_action", "succeeded"] as const;

type Resource = "refunds" | "payment_intents" | "customers";
const CAMEL: Record<Resource, string> = { refunds: "refunds", payment_intents: "paymentIntents", customers: "customers" };

function service(root: unknown, resource: Resource): { retrieve: (id: string) => unknown } | null {
  if (!root || (typeof root !== "object" && typeof root !== "function")) return null;
  const r = root as Record<string, unknown>;
  for (const k of [CAMEL[resource], resource]) {
    const s = r[k] as { retrieve?: unknown } | undefined;
    if (s && typeof s.retrieve === "function") return s as { retrieve: (id: string) => unknown };
  }
  return null;
}

export async function retrieve(client: unknown, resource: Resource, id: string): Promise<unknown> {
  const svc = service((client as Record<string, unknown> | null)?.["v1"], resource) ?? service(client, resource);
  if (svc) return await svc.retrieve(id);
  if (typeof client === "function") return await (client as (p: string) => unknown)(`/v1/${resource}/${encodeURIComponent(id)}`);
  throw new ConfigError("unsupported Stripe client: pass a stripe client or a path => JSON function");
}

async function fetchObj(client: unknown, resource: Resource, id: string): Promise<unknown> {
  const obj = await retrieve(client, resource, id);
  if (obj === null || obj === undefined) throw new NotFound(`${resource}/${id}`);
  if (getPath(obj, "deleted") === true) throw new NotFound(`${resource}/${id} is deleted`);
  return obj;
}

export interface RefundMatchesOptions extends RetryOptions {
  refundId?: Spec;
  amount?: Spec;
  currency?: Spec;
  charge?: Spec;
  paymentIntent?: Spec;
  metadata?: Spec;
  allowedStatus?: readonly string[];
}

/** Re-fetch the refund by id; check amount (minor units), currency, charge / payment_intent and that status is not failed/canceled. */
export function refundMatches(client: unknown, opts: RefundMatchesOptions = {}): OutcomeCheckFn {
  const o = {
    refundId: resp("id"), amount: optArg("amount"), currency: optArg("currency"), charge: optArg("charge"),
    paymentIntent: optArg("payment_intent"), metadata: null, allowedStatus: REFUND_OK_STATUSES, ...opts,
  };
  return checkFn("stripe.refund_matches", async (call: Call, response: unknown): Promise<Outcome> => {
    const id = resolveId(o.refundId, call, response, "refund id");
    const obj = await fetchObj(client, "refunds", id);
    const c = new Check("stripe.refund_matches");
    c.note("id", getPath(obj, "id"));
    c.field("amount", expectMinor(resolve(o.amount, call, response)), getPath(obj, "amount"));
    c.field("currency", resolve(o.currency, call, response), getPath(obj, "currency"), ciEqual);
    c.field("charge", objectId(resolve(o.charge, call, response)), objectId(getPath(obj, "charge")));
    c.field("payment_intent", objectId(resolve(o.paymentIntent, call, response)), objectId(getPath(obj, "payment_intent")));
    c.field("metadata", resolve(o.metadata, call, response), getPath(obj, "metadata"));
    const status = getPath(obj, "status");
    c.require("status", typeof status === "string" && o.allowedStatus.includes(status), status);
    const reason = getPath(obj, "failure_reason");
    if (reason !== null && reason !== ABSENT) c.note("failure_reason", reason);
    return c.outcome();
  }, opts);
}

export interface PaymentIntentMatchesOptions extends RetryOptions {
  paymentIntentId?: Spec;
  amount?: Spec;
  amountReceived?: Spec;
  currency?: Spec;
  customer?: Spec;
  /** One value or an array of acceptable values. */
  status?: Spec;
  metadata?: Spec;
}

export function paymentIntentMatches(client: unknown, opts: PaymentIntentMatchesOptions = {}): OutcomeCheckFn {
  const o = {
    paymentIntentId: firstOf(optArg("payment_intent_id"), resp("id")), amount: optArg("amount"), amountReceived: null,
    currency: optArg("currency"), customer: optArg("customer"), status: null, metadata: null, ...opts,
  };
  return checkFn("stripe.payment_intent_matches", async (call, response) => {
    const id = resolveId(o.paymentIntentId, call, response, "PaymentIntent id");
    const obj = await fetchObj(client, "payment_intents", id);
    const c = new Check("stripe.payment_intent_matches");
    c.note("id", getPath(obj, "id"));
    c.field("amount", expectMinor(resolve(o.amount, call, response)), getPath(obj, "amount"));
    c.field("amount_received", expectMinor(resolve(o.amountReceived, call, response), "amount_received"), getPath(obj, "amount_received"));
    c.field("currency", resolve(o.currency, call, response), getPath(obj, "currency"), ciEqual);
    c.field("customer", objectId(resolve(o.customer, call, response)), objectId(getPath(obj, "customer")));
    c.field("status", resolve(o.status, call, response), getPath(obj, "status"), oneOf);
    c.field("metadata", resolve(o.metadata, call, response), getPath(obj, "metadata"));
    return c.outcome();
  }, opts);
}

export interface CustomerUpdatedOptions extends RetryOptions {
  fields: Fields;
  customerId?: Spec;
}

/** Re-fetch the customer and check the listed fields (dotted paths; an object is a subset match). */
export function customerUpdated(client: unknown, opts: CustomerUpdatedOptions): OutcomeCheckFn {
  if (!opts || opts.fields === null || opts.fields === undefined) throw new TypeError("customerUpdated needs fields");
  const customerId = opts.customerId ?? firstOf(optArg("customer_id"), optArg("customer"), resp("id"));
  return checkFn("stripe.customer_updated", async (call, response) => {
    const id = resolveId(customerId, call, response, "customer id");
    const expected = resolveFields(opts.fields, call, response);
    const obj = await fetchObj(client, "customers", id);
    const c = new Check("stripe.customer_updated");
    c.note("id", getPath(obj, "id"));
    for (const [k, v] of Object.entries(expected)) c.field(k, v, getPath(obj, k));
    return c.outcome();
  }, opts);
}
