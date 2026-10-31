import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";
import {
  Checker,
  attach,
  iban,
  issue,
  makeOverride,
  newSeed,
  publicKeyOf,
  revocationsFromList,
  revoke,
  seedFromHex,
  signMandate,
  signOverride,
  verifyDecision,
} from "@getgleipnir/verify/mandate";
import { MAX_BODY, RateLimiter, handle, type Env } from "../src/app.js";
import { MemoryKV } from "../src/kv.js";
import { KVLedger, KVPaymentLog } from "../src/state.js";

type J = Record<string, unknown>;

const ENV: Env = { ADMIN_TOKEN: "admin-" + "x".repeat(40), MASTER_KEY: "master-" + "k".repeat(40) };
const BASE = "https://gleipnir-check.example";
const COMPANY = { name: "Nordhafen Logistik GmbH", country: "AT" };
const FROM = iban("AT483200000012345864");
const BRENNER = { name: "Brenner Stahl AG", account: iban("AT611904300234573201") };
const MALLORY = { name: "Brenner Stahl AG", account: iban("DE89370400440532013000") };

let kv: MemoryKV;
let limiter: RateLimiter;
let env: Env;

let ip: string | undefined = "203.0.113.7";

async function call(method: string, path: string, body?: unknown, token?: string, extra: Record<string, string> = {}): Promise<[number, J, Headers]> {
  const headers: Record<string, string> = { ...extra };
  if (body !== undefined) headers["Content-Type"] ??= "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  const init: RequestInit = { method, headers };
  if (body !== undefined) init.body = typeof body === "string" ? body : JSON.stringify(body);
  const res = await handle(new Request(BASE + path, init), { kv, env, limiter, ip });
  const text = await res.text();
  return [res.status, text ? (JSON.parse(text) as J) : {}, res.headers];
}

/** A tenant with a company whose signatory K. Berger may sign alone, and a mandate for its AP agent. */
async function setup(tenant = "acme-psp") {
  const signerSeed = newSeed(), agentSeed = newSeed();
  const signer = { id: "kberger@nordhafen.at", public_key: publicKeyOf(signerSeed) };
  const [st, created] = await call("POST", "/v1/admin/tenants", { id: tenant }, ENV.ADMIN_TOKEN);
  expect(st).toBe(201);
  const apiKey = created.api_key as string, kybKey = created.kyb_key as string;
  const authority = {
    source: "bank_kyb",
    signers: [{ company: COMPANY.name, signer: signer.id, keys: [signer.public_key] }],
    accounts: [{ company: COMPANY.name, account: FROM }],
  };
  const [st2, put] = await call("PUT", `/v1/admin/tenants/${tenant}/authority`, authority, kybKey);
  expect([st2, put.version]).toEqual([200, 2]);
  const mandate = signMandate(issue({
    id: "m_ap_2026", company: COMPANY, agent: { id: "ap-agent", public_key: publicKeyOf(agentSeed) },
    signer: { ...signer, name: "K. Berger" },
    scope: { rails: ["sepa", "sepa_instant"], currency: "EUR", max_per_payment: "25000.00",
      max_per_period: { amount: "40000.00", period: "P1M" }, payees: [BRENNER], from_accounts: [FROM] },
    validUntil: "2099-12-31T23:59:59.000Z",
  }), signerSeed);
  const pay = (id: string, amount: string, payee: J = BRENNER) =>
    attach(mandate, { id, rail: "sepa", amount, currency: "EUR", payee, agentSeed });
  return { apiKey, kybKey, mandate, pay, signer, signerSeed, checkerId: created.checker as string, publicKey: created.public_key as string };
}

beforeEach(() => {
  kv = new MemoryKV();
  limiter = new RateLimiter();
  env = { ...ENV };
  ip = "203.0.113.7";
});

describe("hosted sandbox checker", () => {
  it("allows a covered payment with a signed sandbox decision that verifies against the public key set", async () => {
    const s = await setup();
    const [st, d, h] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("INV-1", "18400.00") }, s.apiKey);
    expect(st).toBe(200);
    expect(d.outcome).toBe("allow");
    expect(d.checker).toEqual({ id: "sandbox:acme-psp", public_key: s.publicKey });
    expect(h.get("Gleipnir-Environment")).toBe("sandbox");
    const [ks, keyset] = await call("GET", "/t/acme-psp/.well-known/gleipnir-checker.json");
    expect(ks).toBe(200);
    expect(verifyDecision(d, keyset)).toBe(true);
    const [, keys] = await call("GET", "/t/acme-psp/keys");
    expect(keys).toEqual({ checker: "sandbox:acme-psp", keys: [s.publicKey] });
  });

  it("blocks a tricked agent paying an account that is not on the mandate", async () => {
    const s = await setup();
    const [st, d] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("INV-2", "18400.00", MALLORY) }, s.apiKey);
    expect(st).toBe(200);
    expect(d.outcome).toBe("block");
    expect(d.reasons).toEqual(["payee_not_on_mandate"]);
  });

  it("escalates over the payment limit, and a company signatory's override resolves it to allow, once", async () => {
    const s = await setup();
    const payment = s.pay("INV-3", "30000.00");
    const [, esc] = await call("POST", "/v1/check", { mandate: s.mandate, payment }, s.apiKey);
    expect(esc.outcome).toBe("escalate");
    expect(esc.reasons).toEqual(["over_payment_limit"]);
    const override = signOverride(makeOverride(esc, { outcome: "allow", id: "o_1", reason: "annual contract" }),
      s.signerSeed, s.signer);
    const [st, fin] = await call("POST", "/v1/resolve", { mandate: s.mandate, payment, decision: esc, override }, s.apiKey);
    expect(st).toBe(200);
    expect(fin.outcome).toBe("allow");
    expect(fin.checks).toContain("override:company:1/1");
    // The same override again: the same decision, no second reservation.
    const [, again] = await call("POST", "/v1/resolve", { mandate: s.mandate, payment, decision: esc, override }, s.apiKey);
    expect(again.id).toBe(fin.id);
    // A stranger's override is refused.
    const stranger = newSeed();
    const bad = signOverride(makeOverride(esc, { outcome: "allow", id: "o_2" }), stranger, { id: "x", public_key: publicKeyOf(stranger) });
    const s2 = s.pay("INV-3b", "30000.00");
    const [, esc2] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s2 }, s.apiKey);
    const bad2 = signOverride(makeOverride(esc2, { outcome: "allow", id: "o_3" }), stranger, { id: "x", public_key: publicKeyOf(stranger) });
    const [, r2] = await call("POST", "/v1/resolve", { mandate: s.mandate, payment: s2, decision: esc2, override: bad2 }, s.apiKey);
    expect(r2.reasons).toEqual(["override_not_authorized"]);
    expect(bad).toBeTruthy();
  });

  it("replays: the same payment gets the same decision; another payment under the same id is a duplicate", async () => {
    const s = await setup();
    const p = s.pay("INV-4", "1000.00");
    const [, d1] = await call("POST", "/v1/check", { mandate: s.mandate, payment: p }, s.apiKey);
    const [, d2] = await call("POST", "/v1/check", { mandate: s.mandate, payment: p }, s.apiKey);
    expect(d1.outcome).toBe("allow");
    expect(d2).toEqual(d1);
    const [, d3] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("INV-4", "999.00") }, s.apiKey);
    expect(d3.outcome).toBe("block");
    expect(d3.reasons).toEqual(["duplicate_payment"]);
  });

  it("keeps the period limit across calls", async () => {
    const s = await setup();
    for (const [id, amt] of [["P-1", "20000.00"], ["P-2", "20000.00"]] as const) {
      const [, d] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay(id, amt) }, s.apiKey);
      expect(d.outcome).toBe("allow");
    }
    const [, d] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("P-3", "0.01") }, s.apiKey);
    expect(d.outcome).toBe("escalate");
    expect(d.reasons).toEqual(["over_period_limit"]);
  });

  it("keeps the period limit under concurrent checks (ETag compare-and-swap)", async () => {
    const s = await setup();
    const results = await Promise.all(Array.from({ length: 12 }, (_, i) =>
      call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay(`C-${i}`, "5000.00") }, s.apiKey)));
    const allowed = results.filter(([, d]) => d.outcome === "allow").length;
    expect(allowed).toBe(8); // 8 x 5000 = 40000, the monthly limit
    for (const [, d] of results) if (d.outcome !== "allow") expect(d.reasons).toEqual(["over_period_limit"]);
  });

  it("accepts a signatory's revocation, then blocks the mandate, and lists it signed", async () => {
    const s = await setup();
    const r = revoke(s.mandate, { signer: s.signer, seed: s.signerSeed, id: "r_1", reason: "agent compromised",
      revokedAt: new Date(Date.now() - 1000).toISOString() });
    const [st, ok] = await call("POST", "/v1/revoke", { revocation: r, mandate: s.mandate }, s.apiKey);
    expect([st, ok]).toEqual([200, { ok: true, checker: "sandbox:acme-psp" }]);
    const [, d] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("INV-5", "100.00") }, s.apiKey);
    expect(d.outcome).toBe("block");
    expect(d.reasons).toEqual(["mandate_revoked"]);
    const [, list] = await call("GET", "/v1/revocations", undefined, s.apiKey);
    expect(revocationsFromList(list, [s.publicKey], new Date())).toEqual([r]);
    // A revocation by someone who may not revoke is refused.
    const x = newSeed();
    const fake = revoke(s.mandate, { signer: { id: "x", public_key: publicKeyOf(x) }, seed: x, id: "r_2" });
    const [st2, e2] = await call("POST", "/v1/revoke", { revocation: fake, mandate: s.mandate }, s.apiKey);
    expect(st2).toBe(400);
    expect(e2.error).toMatch(/not a valid revocation/);
  });

  it("refuses missing, wrong and foreign credentials, and never returns secrets", async () => {
    const s = await setup();
    const other = await setup("other-bank");
    const body = { mandate: s.mandate, payment: s.pay("INV-6", "1.00") };
    expect((await call("POST", "/v1/check", body))[0]).toBe(401);
    expect((await call("POST", "/v1/check", body, "nope"))[0]).toBe(401);
    expect((await call("POST", "/v1/check", body, s.apiKey.slice(0, -2) + "AA"))[0]).toBe(401);
    expect((await call("POST", "/v1/check", body, ENV.ADMIN_TOKEN))[0]).toBe(401);
    expect((await call("POST", "/v1/admin/tenants", { id: "evil" }, s.apiKey))[0]).toBe(401);
    expect((await call("PUT", "/v1/admin/tenants/acme-psp/authority", { signers: [], accounts: [] }, other.kybKey))[0]).toBe(401);
    // The check key cannot touch the authority table (a leaked check key cannot add signers).
    expect((await call("PUT", "/v1/admin/tenants/acme-psp/authority", { signers: [], accounts: [] }, s.apiKey))[0]).toBe(401);
    expect((await call("GET", "/v1/admin/tenants/acme-psp/authority", undefined, s.apiKey))[0]).toBe(401);
    // And the KYB key cannot check payments or rotate keys.
    expect((await call("POST", "/v1/check", body, s.kybKey))[0]).toBe(401);
    expect((await call("POST", "/v1/admin/tenants/acme-psp/kyb-key", {}, s.kybKey))[0]).toBe(401);
    expect((await call("POST", "/v1/admin/tenants/acme-psp/api-key", {}, s.apiKey))[0]).toBe(401);
    expect((await call("GET", "/v1/revocations"))[0]).toBe(401);
    // Another tenant's key works, but for its own checker: K. Berger is unknown there.
    const [, d] = await call("POST", "/v1/check", body, other.apiKey);
    expect((d.checker as J).id).toBe("sandbox:other-bank");
    expect(d.outcome).not.toBe("allow");
    // Creating an existing tenant is refused; no response ever carries the seed or the key hash.
    expect((await call("POST", "/v1/admin/tenants", { id: "acme-psp" }, ENV.ADMIN_TOKEN))[0]).toBe(409);
    const stored = kv.items.get("t/acme-psp/tenant")!.data;
    expect(stored).not.toContain(s.apiKey);
    const t = JSON.parse(stored) as J;
    for (const [, r] of [await call("GET", "/t/acme-psp/keys"), await call("GET", "/v1/admin/tenants/acme-psp/authority", undefined, s.kybKey)]) {
      expect(JSON.stringify(r)).not.toContain(t.seed as string);
      expect(JSON.stringify(r)).not.toContain(t.api_key_hash as string);
    }
  });

  it("rotates an API key: the old one stops working", async () => {
    const s = await setup();
    const [st, r] = await call("POST", "/v1/admin/tenants/acme-psp/api-key", {}, ENV.ADMIN_TOKEN);
    expect(st).toBe(200);
    expect((await call("GET", "/v1/keys", undefined, s.apiKey))[0]).toBe(401);
    expect((await call("GET", "/v1/keys", undefined, r.api_key as string))[0]).toBe(200);
  });

  it("fails closed without configuration", async () => {
    env = { ADMIN_TOKEN: ENV.ADMIN_TOKEN };
    expect((await call("GET", "/t/acme-psp/keys"))[0]).toBe(503);
    env = { MASTER_KEY: ENV.MASTER_KEY, ADMIN_TOKEN: "short" };
    expect((await call("POST", "/v1/admin/tenants", { id: "acme" }, "short"))[0]).toBe(401);
  });

  it("rate-limits per API key, and failed attempts per IP", async () => {
    const s = await setup();
    env = { ...ENV, RATE_LIMIT_PER_MIN: "3" };
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await call("GET", "/v1/keys", undefined, s.apiKey))[0]);
    expect(codes).toEqual([200, 200, 200, 429, 429]);
    limiter = new RateLimiter();
    const fails = [];
    for (let i = 0; i < 22; i++) fails.push((await call("GET", "/v1/keys", undefined, "wrong"))[0]);
    expect(fails.slice(0, 20).every((c) => c === 401)).toBe(true);
    expect(fails.slice(20)).toEqual([429, 429]);
    // Even the right key is refused from that IP for the rest of the window.
    expect((await call("GET", "/v1/keys", undefined, s.apiKey))[0]).toBe(429);
  });

  it("caps the body at 1 MiB, and wants strict JSON with exactly the expected fields", async () => {
    const s = await setup();
    const big = JSON.stringify({ mandate: s.mandate, payment: "x".repeat(MAX_BODY) });
    const [st, e] = await call("POST", "/v1/check", big, s.apiKey);
    expect([st, e.error]).toEqual([400, "body must be 1 byte to 1048576 bytes"]);
    const [st2, e2] = await call("POST", "/v1/check", '{"mandate": {}, "payment": {}, "payment": {}}', s.apiKey);
    expect(st2).toBe(400);
    expect(e2.error).toMatch(/duplicate JSON key "payment"/);
    const [st3, e3] = await call("POST", "/v1/check", '{"mandate": {"n": 1.5}, "payment": {}}', s.apiKey);
    expect(st3).toBe(400);
    expect(e3.error).toMatch(/not an I-JSON integer/);
    expect((await call("POST", "/v1/check", { mandate: s.mandate }, s.apiKey))[0]).toBe(400);
    expect((await call("POST", "/v1/check", "", s.apiKey))[0]).toBe(400);
    expect((await call("POST", "/v1/check", "{}", s.apiKey, { "Content-Type": "text/plain" }))[0]).toBe(415);
    expect((await call("POST", "/v1/check", "{}", s.apiKey, { Origin: "https://evil.example" }))[0]).toBe(403);
    expect((await call("PUT", "/v1/admin/tenants/acme-psp/authority", { signers: [{ company: "x" }], accounts: [] }, s.kybKey))[0]).toBe(400);
    expect((await call("POST", "/v1/admin/tenants", { id: "../etc" }, ENV.ADMIN_TOKEN))[0]).toBe(400);
  });

  it("authority changes: KYB key or admin only, versioned, logged append-only, refused with a rotated key", async () => {
    const s = await setup();
    const [, cur] = await call("GET", "/v1/admin/tenants/acme-psp/authority", undefined, s.kybKey);
    const [st, put] = await call("PUT", "/v1/admin/tenants/acme-psp/authority", { ...cur, require_payees: true }, ENV.ADMIN_TOKEN);
    expect([st, put.version]).toEqual([200, 3]);
    const log = [...kv.items.keys()].filter((k) => k.startsWith("t/acme-psp/authority-log/"));
    expect(log.length).toBe(3);
    expect(JSON.parse(kv.items.get(log.sort()[2]!)!.data).by).toBe("admin");
    const [, rot] = await call("POST", "/v1/admin/tenants/acme-psp/kyb-key", {}, ENV.ADMIN_TOKEN);
    expect((await call("PUT", "/v1/admin/tenants/acme-psp/authority", cur, s.kybKey))[0]).toBe(401);
    expect((await call("PUT", "/v1/admin/tenants/acme-psp/authority", cur, rot.kyb_key as string))[0]).toBe(200);
  });

  it("creates opaque tenant ids when none is given", async () => {
    const [st, t] = await call("POST", "/v1/admin/tenants", {}, ENV.ADMIN_TOKEN);
    expect(st).toBe(201);
    expect(t.id).toMatch(/^t-[0-9a-f]{16}$/);
    expect((await call("GET", `/t/${t.id as string}/keys`))[1].checker).toBe(`sandbox:${t.id as string}`);
  });

  it("stores revocations per revoked mandate: no tenant-wide cap, per-signer rate limit", async () => {
    const s = await setup();
    const signed = (id: string) => signMandate(issue({
      id, company: COMPANY, agent: { id: "ap-agent" }, signer: s.signer,
      scope: { currency: "EUR", max_per_payment: "100.00", from_accounts: [FROM] }, validUntil: "2099-12-31T23:59:59.000Z",
    }), s.signerSeed);
    const codes: number[] = [];
    for (let i = 0; i < 12; i++) {
      const m = signed(`m_${i}`);
      const r = revoke(m, { signer: s.signer, seed: s.signerSeed, id: `r_${i}` });
      codes.push((await call("POST", "/v1/revoke", { revocation: r, mandate: m }, s.apiKey))[0]);
    }
    expect(codes).toEqual([...Array(10).fill(200), 429, 429]);
    expect([...kv.items.keys()].filter((k) => k.startsWith("t/acme-psp/rev/")).length).toBe(10);
    const [, list] = await call("GET", "/v1/revocations", undefined, s.apiKey);
    expect((list.revocations as unknown[]).length).toBe(10);
    // The payment mandate is unaffected by revocations of other mandates.
    const [, d] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("INV-R", "10.00") }, s.apiKey);
    expect(d.outcome).toBe("allow");
  });

  it("applies a write once when the store commits it but the answer is lost", async () => {
    const s = await setup();
    kv.lostAnswer = (key) => key.includes("/ledger/") || key.includes("/payments/");
    const p = s.pay("L-1", "20000.00");
    const [, d1] = await call("POST", "/v1/check", { mandate: s.mandate, payment: p }, s.apiKey);
    const [, d2] = await call("POST", "/v1/check", { mandate: s.mandate, payment: p }, s.apiKey);
    expect(d1.outcome).toBe("allow");
    expect(d2.id).toBe(d1.id); // the claim was ours, and the retry gets the same decision
    const [, d3] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("L-2", "20000.00") }, s.apiKey);
    expect(d3.outcome).toBe("allow");
    const [, d] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("L-3", "0.01") }, s.apiKey);
    expect(d.reasons).toEqual(["over_period_limit"]); // 40000.00 counted exactly, not twice
  });

  it("without a client IP, failed attempts are not pooled into one shared bucket", async () => {
    ip = undefined;
    const codes = [];
    for (let i = 0; i < 25; i++) codes.push((await call("GET", "/v1/keys", undefined, "wrong"))[0]);
    expect(new Set(codes)).toEqual(new Set([401]));
  });

  it("sets security headers on API responses", async () => {
    const [, , hd] = await call("GET", "/v1");
    expect(hd.get("Strict-Transport-Security")).toMatch(/max-age/);
    expect(hd.get("Content-Security-Policy")).toMatch(/default-src 'none'/);
  });

  it("fails closed when the store is down: escalate checker_unavailable, signed", async () => {
    const s = await setup();
    for (const part of ["/ledger/", "/payments/", "/rev/"]) {
      kv.failOn = (_op, key) => key.includes(part);
      const [st, d] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay(`F${part}`, "10.00") }, s.apiKey);
      expect(st).toBe(200);
      expect([d.outcome, d.reasons]).toEqual(["escalate", ["checker_unavailable"]]);
      expect(verifyDecision(d, [s.publicKey])).toBe(true);
    }
    kv.failOn = () => true;
    const [st] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("F-all", "10.00") }, s.apiKey);
    expect(st).toBe(503);
    kv.failOn = null;
    const [, d] = await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("F-ok", "10.00") }, s.apiKey);
    expect(d.outcome).toBe("allow");
  });
});

// ---------- the shared conformance vectors, with the payment log and ledger on the KV store ----------

interface Vector {
  name: string; mandate: unknown; payments: unknown[]; now: string[];
  authority: { company: string; signer: string; source: string; keys: string[]; may_sign: boolean; joint?: number;
    retired?: Record<string, string>; person?: string }[];
  revocations: unknown[]; status: unknown;
  holds: { company: string; account: J; customer?: string }[];
  policy: { require_payees?: boolean }; officers: string[]; feed?: unknown;
  ops?: ("check" | { resolve: { of: number; id: string; outcome: "allow" | "block"; decided_at: string; reason?: string;
    decision_hash?: string; signers: { seed: string; id: string }[] } })[];
  expect: J[]; webauthn: { rp_id?: string; origins?: string[] }; mandates?: unknown[]; which?: number[];
  ledger: boolean | "error" | "junk"; payment_log?: "error" | "junk";
}

/** The KV ledger, failing as a vector asks (spec 0.4.1: "error" throws, "junk" answers a non-boolean). */
class BrokenKVLedger extends KVLedger {
  constructor(kv: MemoryKV, private readonly mode: "error" | "junk") { super(kv, "vectors"); }
  override async reserve(): Promise<boolean> {
    if (this.mode === "error") throw new Error("ledger down");
    return "ok" as unknown as boolean;
  }
}

/** The KV payment log, failing as a vector asks: "error" throws on lookup, "junk" claims with a non-boolean. */
class BrokenKVPaymentLog extends KVPaymentLog {
  constructor(kv: MemoryKV, private readonly mode: "error" | "junk") { super(kv, "vectors"); }
  override async lookup(key: string, paymentHash: string): Promise<J | null> {
    if (this.mode === "error") throw new Error("payment log down");
    return super.lookup(key, paymentHash);
  }
  override async register(key: string, paymentHash: string): Promise<boolean> {
    await super.register(key, paymentHash);
    return 1 as unknown as boolean;
  }
}

const VECTORS = JSON.parse(readFileSync(fileURLToPath(
  new URL("../../verify/test/fixtures/mandate-vectors.json", import.meta.url)), "utf8")) as {
  bank: { id: string; seed_hex: string; public_key: string }; cases: Vector[];
};

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys((v as J)[k])]));
  return v;
}

function expected(decisions: J[]): J[] {
  const first = new Map<unknown, number>();
  return decisions.map((d, i) => {
    let row: J = Object.fromEntries(Object.entries(d).filter(([k]) => k !== "id" && k !== "sig"));
    if (row.escalation) row.escalation = { step: first.get((row.escalation as J).id) ?? null };
    if (row.override) row.override = { id: (row.override as J).id };
    if (first.has(d.id)) row = { same_as: first.get(d.id) };
    if (!first.has(d.id)) first.set(d.id, i);
    return row;
  });
}

describe("conformance vectors on the KV-backed payment log and ledger", () => {
  it.each(VECTORS.cases.map((c) => [c.name, c] as const))("%s", async (_n, c) => {
    const store = new MemoryKV();
    let now = c.now[0]!;
    const checker = new Checker({
      id: VECTORS.bank.id, seed: seedFromHex(VECTORS.bank.seed_hex),
      authority: (company, signerId) => {
        const row = c.authority.find((r) => r.company === company.name && r.signer === signerId);
        return row ? { source: row.source, keys: row.keys, maySign: row.may_sign, joint: row.joint ?? 1,
          retired: row.retired ?? {}, person: row.person ?? null } : null;
      },
      holds: (company, account) => {
        const r = c.holds.find((x) => x.company === company.name && JSON.stringify(sortKeys(x.account)) === JSON.stringify(sortKeys(account)));
        return r ? r.customer ?? `cust:${r.company}` : null;
      },
      requirePayees: c.policy.require_payees ?? false,
      revocationFeed: c.feed === undefined ? null : () => {
        if (c.feed === "error") throw new Error("unreachable");
        const f = c.feed as { doc: unknown; keys: string[] };
        return revocationsFromList(f.doc, f.keys, new Date(now));
      },
      officers: c.officers,
      ledger: c.ledger === true ? new KVLedger(store, "vectors") : c.ledger ? new BrokenKVLedger(store, c.ledger) : null,
      payments: c.payment_log ? new BrokenKVPaymentLog(store, c.payment_log) : new KVPaymentLog(store, "vectors"),
      revocations: c.revocations,
      status: c.status === null ? null : async () => {
        if (c.status === "error") throw new Error("unreachable");
        return c.status;
      },
      clock: () => new Date(now),
      webauthn: { rpId: c.webauthn.rp_id, origins: c.webauthn.origins },
    });
    const out: J[] = [];
    for (let i = 0; i < c.payments.length; i++) {
      now = c.now[i]!;
      const md = (c.mandates ?? [c.mandate])[(c.which ?? [])[i] ?? 0];
      const op = (c.ops ?? [])[i] ?? "check";
      if (op === "check") out.push(await checker.check(md, c.payments[i]));
      else {
        const d = out[op.resolve.of]!;
        let o = makeOverride(d, { outcome: op.resolve.outcome, id: op.resolve.id, reason: op.resolve.reason ?? "", decidedAt: op.resolve.decided_at });
        if (op.resolve.decision_hash) o = { ...o, decision: { ...(o.decision as J), hash: op.resolve.decision_hash } };
        for (const sg of op.resolve.signers) {
          const seed = seedFromHex(sg.seed);
          o = signOverride(o, seed, { id: sg.id, public_key: publicKeyOf(seed) });
        }
        out.push(await checker.resolve(md, c.payments[i], d, o));
      }
    }
    expect(expected(out)).toEqual(c.expect);
  });
});
