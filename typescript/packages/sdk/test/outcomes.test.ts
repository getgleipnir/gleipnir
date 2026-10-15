/** Outcome read-back checks: Stripe, Zendesk, generic HTTP (same semantics as the Python package). */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Recorder, outcomes, type Call } from "@getgleipnir/sdk";

const { stripe, zendesk, httpJsonMatches, HttpError, NotFound, jsonGet, toMinorUnits, valuesEqual } = outcomes;

const call = (args: Record<string, unknown> = {}): Call => ({ actionId: "act_1", tool: "t", system: "s", args });
const noSleep = () => undefined;

// https://docs.stripe.com/api/refunds/object
const REFUND = {
  id: "re_1Nispe2eZvKYlo2Cd31jOCgZ", object: "refund", amount: 1000, balance_transaction: "txn_1Nispe2eZvKYlo2CYezqFhEx",
  charge: "ch_1NirD82eZvKYlo2CIvbtLWuY", created: 1692942318, currency: "usd", metadata: { ticket: "T-101" },
  payment_intent: "pi_1GszsK2eZvKYlo2CfhZyoZLp", reason: null, receipt_number: null, status: "succeeded",
};
const PI = {
  id: "pi_3MtwBwLkdIwHu7ix28a3tqPa", object: "payment_intent", amount: 2000, amount_received: 2000, currency: "usd",
  customer: "cus_NffrFeUfNV2Hib", status: "succeeded", metadata: {},
};
const CUSTOMER = {
  id: "cus_NffrFeUfNV2Hib", object: "customer", email: "jennyrosen@example.com", name: "Jenny Rosen",
  address: { city: "Vienna", country: "AT" }, metadata: { tier: "gold" }, phone: null,
};

class StripeError extends Error {
  constructor(message: string, readonly statusCode?: number, readonly code?: string, override readonly name = "StripeInvalidRequestError") {
    super(message);
  }
}

function fakeStripe(objs: Record<string, unknown>[], failures: Error[] = []) {
  const counter = { calls: 0 };
  const svc = (kind: string) => ({
    async retrieve(id: string) {
      counter.calls++;
      const f = failures.shift();
      if (f) throw f;
      const o = objs.find((x) => x["object"] === kind && x["id"] === id);
      if (!o) throw new StripeError(`No such ${kind}: '${id}'`, 404, "resource_missing");
      return structuredClone(o);
    },
  });
  return { counter, refunds: svc("refund"), paymentIntents: svc("payment_intent"), customers: svc("customer") };
}

describe("stripe.refundMatches", () => {
  it("matches and records only compared fields", async () => {
    const o = await stripe.refundMatches(fakeStripe([REFUND]))(
      call({ payment_intent: REFUND.payment_intent, amount: 1000, currency: "USD" }), { id: REFUND.id });
    expect(o.check).toBe("match");
    expect(o.method).toBe("stripe.refund_matches");
    expect(o.observed).toEqual({ id: REFUND.id, amount: 1000, currency: "usd", payment_intent: REFUND.payment_intent, status: "succeeded" });
  });

  it("amount mismatch in minor units", async () => {
    const o = await stripe.refundMatches(fakeStripe([{ ...REFUND, amount: 950 }]))(call({ amount: 1000 }), { id: REFUND.id });
    expect(o.check).toBe("mismatch");
    expect(o.fields).toEqual(["amount"]);
    expect((o.observed as Record<string, unknown>)["amount"]).toBe(950);
  });

  it.each(["failed", "canceled"])("status %s is a mismatch", async (status) => {
    const o = await stripe.refundMatches(fakeStripe([{ ...REFUND, status, failure_reason: "declined" }]))(call({ amount: 1000 }), { id: REFUND.id });
    expect(o.fields).toEqual(["status"]);
    expect((o.observed as Record<string, unknown>)["failure_reason"]).toBe("declined");
  });

  it("missing refund, float amount, no id", async () => {
    const chk = stripe.refundMatches(fakeStripe([REFUND]));
    expect((await chk(call({ amount: 1000 }), { id: "re_x" })).fields).toEqual(["exists"]);
    const f = await chk(call({ amount: 10.5 }), { id: REFUND.id });
    expect(f.check).toBe("error");
    expect(f.detail).toContain("minor units");
    expect((await chk(call({ amount: 1000 }), {})).check).toBe("error");
  });

  it("retries transient errors with backoff, bounded", async () => {
    const client = fakeStripe([REFUND], [new StripeError("conn", undefined, undefined, "StripeConnectionError"), new StripeError("rl", 429)]);
    const sleeps: number[] = [];
    const o = await stripe.refundMatches(client, { retries: 3, backoff: 0.1, sleep: (ms) => void sleeps.push(ms) })(call({ amount: 1000 }), { id: REFUND.id });
    expect(o.check).toBe("match");
    expect(client.counter.calls).toBe(3);
    expect(sleeps).toEqual([100, 200]);
    expect(o.detail).toContain("after 3 attempts");

    const down = fakeStripe([], Array.from({ length: 10 }, () => new StripeError("conn", 503)));
    const e = await stripe.refundMatches(down, { retries: 2, sleep: noSleep })(call({ amount: 1 }), { id: "re_1" });
    expect(e.check).toBe("error");
    expect(down.counter.calls).toBe(3);
    expect(() => stripe.refundMatches(down, { retries: 99 })).toThrow(RangeError);
  });

  it("auth errors are not retried and never throw", async () => {
    const client = fakeStripe([REFUND], [new StripeError("Invalid API Key", 401, undefined, "StripeAuthenticationError")]);
    const o = await stripe.refundMatches(client, { retries: 5, sleep: noSleep })(call({ amount: 1000 }), { id: REFUND.id });
    expect(o.check).toBe("error");
    expect(o.detail).toContain("HTTP 401");
    expect(client.counter.calls).toBe(1);
  });

  it("works with a path => JSON function", async () => {
    const seen: string[] = [];
    const o = await stripe.refundMatches(async (p: string) => (seen.push(p), REFUND))(call({ amount: 1000 }), { id: REFUND.id });
    expect(o.check).toBe("match");
    expect(seen).toEqual([`/v1/refunds/${REFUND.id}`]);
  });
});

describe("stripe.paymentIntentMatches / customerUpdated", () => {
  it("payment intent", async () => {
    const chk = stripe.paymentIntentMatches(fakeStripe([PI]), { amountReceived: "amount", status: () => ["succeeded", "processing"] });
    expect((await chk(call({ amount: 2000, currency: "usd", customer: PI.customer }), { id: PI.id })).check).toBe("match");
    const bad = stripe.paymentIntentMatches(fakeStripe([{ ...PI, amount_received: 0, status: "requires_action" }]), { amountReceived: "amount", status: () => "succeeded" });
    expect((await bad(call({ amount: 2000 }), { id: PI.id })).fields).toEqual(["amount_received", "status"]);
  });

  it("customer fields, nested, deleted", async () => {
    const chk = stripe.customerUpdated(fakeStripe([CUSTOMER]), { fields: ["email", "name"] });
    expect((await chk(call({ customer_id: CUSTOMER.id, email: CUSTOMER.email, name: CUSTOMER.name }), {})).check).toBe("match");
    expect((await chk(call({ customer_id: CUSTOMER.id, email: "x@y.z", name: CUSTOMER.name }), {})).fields).toEqual(["email"]);
    const nested = stripe.customerUpdated(fakeStripe([CUSTOMER]), { fields: { "address.city": "Vienna", metadata: { tier: "gold" }, phone: null } });
    expect((await nested(call({ customer_id: CUSTOMER.id }), {})).check).toBe("match");
    const gone = stripe.customerUpdated(fakeStripe([{ id: "cus_gone", object: "customer", deleted: true }]), { fields: { email: "a" } });
    expect((await gone(call({ customer_id: "cus_gone" }), {})).fields).toEqual(["exists"]);
  });
});

// https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/ and .../ticket_comments/
const TICKET = {
  ticket: {
    id: 35436, assignee_id: 235323, group_id: 98738, requester_id: 20978392, subject: "Help, my printer is on fire!",
    description: "The fire is very colorful.", priority: "high", status: "open", type: "incident", tags: ["enterprise", "other_tag"],
    custom_fields: [{ id: 27642, value: "745" }, { id: 27648, value: "yes" }],
  },
};
const COMMENTS = {
  comments: [
    { id: 1274, author_id: 235323, public: true, body: "Thanks for your help!", html_body: "<p>Thanks for your help!</p>", plain_body: "Thanks for your help!" },
    { id: 1275, author_id: 235323, public: false, body: "Internal: refund approved", html_body: "<p>Internal: refund approved</p>", plain_body: "Internal: refund approved" },
  ],
};

function fakeZendesk(failures: Error[] = []) {
  const paths: string[] = [];
  const fetch = async (path: string) => {
    paths.push(path);
    const f = failures.shift();
    if (f) throw f;
    if (path.startsWith("/api/v2/tickets/35436/comments.json")) {
      const c = structuredClone(COMMENTS);
      if (path.includes("sort_order=desc")) c.comments.reverse();
      return c;
    }
    if (path === "/api/v2/tickets/35436.json") return structuredClone(TICKET);
    throw new HttpError(404, path, '{"error":"RecordNotFound"}');
  };
  return { fetch, paths };
}

describe("zendesk", () => {
  it("ticketUpdated: match with public comment", async () => {
    const z = fakeZendesk();
    const o = await zendesk.ticketUpdated(z.fetch, { comment: "reply", commentPublic: () => true })(
      call({ ticket_id: 35436, status: "open", priority: "high", assignee_id: "235323", tags: ["enterprise"], reply: "Thanks for your help!" }), {});
    expect(o.check).toBe("match");
    expect(z.paths).toEqual(["/api/v2/tickets/35436.json", "/api/v2/tickets/35436/comments.json?sort_order=desc"]);
  });

  it("ticketUpdated: mismatches, custom fields, comment visibility", async () => {
    const z = fakeZendesk();
    const o = await zendesk.ticketUpdated(z.fetch)(call({ ticket_id: 35436, status: "solved", assignee_id: 9, tags: ["vip"] }), {});
    expect(o.fields).toEqual(["assignee_id", "status", "tags"]);
    const cf = await zendesk.ticketUpdated(z.fetch, { tagsExact: true, customFields: { 27642: "745", 27648: "no" } })(call({ ticket_id: 35436, tags: ["enterprise"] }), {});
    expect(cf.fields).toEqual(["custom_fields.27648", "tags"]);
    const pub = await zendesk.ticketUpdated(z.fetch, { comment: "reply", commentPublic: () => true })(call({ ticket_id: 35436, reply: "refund approved" }), {});
    expect(pub.fields).toEqual(["comment"]);
  });

  it("missing ticket, transient retry, forbidden not retried", async () => {
    expect((await zendesk.ticketUpdated(fakeZendesk().fetch)(call({ ticket_id: 1, status: "open" }), {})).fields).toEqual(["exists"]);
    const flaky = fakeZendesk([new HttpError(503, "/x"), new HttpError(429, "/x")]);
    expect((await zendesk.ticketUpdated(flaky.fetch, { retries: 2, sleep: noSleep })(call({ ticket_id: 35436, status: "open" }), {})).check).toBe("match");
    expect(flaky.paths.length).toBe(3);
    const forbidden = fakeZendesk([new HttpError(403, "/x")]);
    const o = await zendesk.ticketUpdated(forbidden.fetch, { retries: 3, sleep: noSleep })(call({ ticket_id: 35436, status: "open" }), {});
    expect(o.check).toBe("error");
    expect(forbidden.paths.length).toBe(1);
  });

  it("ticketCreated", async () => {
    const chk = zendesk.ticketCreated(fakeZendesk().fetch);
    const args = { subject: "Help, my printer is on fire!", requester_id: 20978392, priority: "high", type: "incident", comment: { body: "The fire is very colorful." } };
    expect((await chk(call(args), { ticket: { id: 35436 } })).check).toBe("match");
    expect((await chk(call({ ...args, subject: "x" }), { ticket: { id: 35436 } })).fields).toEqual(["subject"]);
    expect((await chk(call(args), { ticket: { id: 99 } })).fields).toEqual(["exists"]);
  });
});

describe("httpJsonMatches and comparisons", () => {
  it("match, mismatch, missing, custom eq, never throws", async () => {
    const db: Record<string, unknown> = { "/orders/o1": { data: { status: "booked", total_cents: 4210, customer: { id: 7 } } } };
    const chk = httpJsonMatches({
      getUrl: (_c, r) => `/orders/${(r as { order_id: string }).order_id}`,
      fetch: (u) => { if (!(u in db)) throw new NotFound(u); return db[u]; },
      expected: (c) => ({ status: "booked", total_cents: c.args["total_cents"], "customer.id": c.args["customer"] }),
      root: "data",
    });
    expect((await chk(call({ total_cents: 4210, customer: "7" }), { order_id: "o1" })).check).toBe("match");
    expect((await chk(call({ total_cents: 4200, customer: "7" }), { order_id: "o1" })).fields).toEqual(["total_cents"]);
    expect((await chk(call({ total_cents: 1, customer: 1 }), { order_id: "o2" })).fields).toEqual(["exists"]);
    const boom = httpJsonMatches({ getUrl: () => { throw new Error("no id"); }, fetch: () => ({}), expected: { a: 1 } });
    expect((await boom(call(), {})).check).toBe("error");
    const near = httpJsonMatches({ getUrl: () => "/x", fetch: () => ({ total: 1001 }), expected: { total: 1000 }, eq: { total: (e, g) => Math.abs((e as number) - (g as number)) <= 1 } });
    expect((await near(call(), {})).check).toBe("match");
  });

  it("jsonGet with injected fetch", async () => {
    const f = (async (url: string, init?: RequestInit) => {
      expect((init?.headers as Record<string, string>)["Authorization"]).toBe("Bearer t");
      return url.endsWith("/ok") ? new Response('{"status":"booked"}', { status: 200 }) : new Response("nope", { status: 404 });
    }) as typeof fetch;
    const get = jsonGet("https://api.example.com/", { headers: { Authorization: "Bearer t" }, fetch: f });
    expect(await get("/ok")).toEqual({ status: "booked" });
    const chk = httpJsonMatches({ getUrl: (_c, r) => r as string, fetch: get, expected: { status: "booked" } });
    expect((await chk(call(), "/ok")).check).toBe("match");
    expect((await chk(call(), "/missing")).fields).toEqual(["exists"]);
  });

  it.each([
    [1500, "1500.00", true], [42.1, 42.10, true], [123, "123", true], [true, "true", true], [null, "", true],
    ["abc", "ABC", false], [1, true, false], [{ a: 1 }, { a: 1, b: 2 }, true], [[1, 2], [1, 2, 3], false], ["01", "1", false],
  ])("valuesEqual(%j, %j) = %s", (a, b, eq) => {
    expect(valuesEqual(a, b)).toBe(eq);
  });

  it("toMinorUnits", () => {
    expect(toMinorUnits("209.00", "USD")).toBe(20900);
    expect(toMinorUnits("500", "JPY")).toBe(500);
    expect(toMinorUnits("1.234", "KWD")).toBe(1234);
    expect(() => toMinorUnits("1.005", "USD")).toThrow();
  });
});

describe("with the recorder", () => {
  it("records a mismatch on an async tool", async () => {
    const rec = new Recorder({ agentId: "a", agentVersion: "1", home: mkdtempSync(join(tmpdir(), "gleipnir-outcomes-")), background: false, quiet: true });
    const client = fakeStripe([{ ...REFUND, amount: 950 }]);
    const refund = rec.tool(async (payment_intent: string, amount: number) => ({ id: REFUND.id, payment_intent, amount }), {
      name: "refund", system: "stripe", params: ["payment_intent", "amount"], verifyOutcome: stripe.refundMatches(client),
    });
    await refund("pi_1GszsK2eZvKYlo2CfhZyoZLp", 1000);
    const action = rec.chain.store.readAll().find((r) => r["kind"] === "action") as Record<string, Record<string, unknown>>;
    expect(action["outcome"]!["check"]).toBe("mismatch");
    expect(action["outcome"]!["method"]).toBe("stripe.refund_matches");
    expect(action["outcome"]!["fields"]).toEqual(["amount"]);
    await rec.close();
  });
});
