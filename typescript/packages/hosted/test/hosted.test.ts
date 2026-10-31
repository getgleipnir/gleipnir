import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";
import {
  Checker,
  approvePayee,
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
  signPayeeApproval,
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
let clock: (() => Date) | undefined;

async function call(method: string, path: string, body?: unknown, token?: string, extra: Record<string, string> = {}): Promise<[number, J, Headers]> {
  const headers: Record<string, string> = { ...extra };
  if (body !== undefined) headers["Content-Type"] ??= "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  const init: RequestInit = { method, headers };
  if (body !== undefined) init.body = typeof body === "string" ? body : JSON.stringify(body);
  const res = await handle(new Request(BASE + path, init), { kv, env, limiter, ip, clock });
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
  return { apiKey, kybKey, mandate, pay, signer, signerSeed, agentSeed, checkerId: created.checker as string, publicKey: created.public_key as string };
}

beforeEach(() => {
  kv = new MemoryKV();
  limiter = new RateLimiter();
  env = { ...ENV };
  ip = "203.0.113.7";
  clock = undefined;
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

// ---------- tenant deletion (admin) ----------

describe("deleting a tenant", () => {
  it("deletes the tenant and all its data, and nothing of other tenants", async () => {
    const a = await setup("acme");
    const b = await setup("acme-psp");
    for (const s of [a, b]) {
      expect((await call("POST", "/v1/check", { mandate: s.mandate, payment: s.pay("p_1", "100.00") }, s.apiKey))[1].outcome).toBe("allow");
      const r = revoke(s.mandate, { signer: s.signer, seed: s.signerSeed, id: "r_1", revokedAt: new Date(Date.now() + 3_600_000).toISOString() });
      expect((await call("POST", "/v1/revoke", { revocation: r, mandate: s.mandate }, s.apiKey))[0]).toBe(200);
    }
    const before = [...kv.items.keys()];
    const kinds = (id: string) => new Set(before.filter((k) => k.startsWith(`t/${id}/`)).map((k) => k.split("/")[2]));
    expect(kinds("acme")).toEqual(new Set(["tenant", "public", "authority-log", "payments", "ledger", "rev"]));

    // Only the admin: not the tenant's own keys, not without a token.
    expect((await call("DELETE", "/v1/admin/tenants/acme", undefined, a.apiKey))[0]).toBe(401);
    expect((await call("DELETE", "/v1/admin/tenants/acme", undefined, a.kybKey))[0]).toBe(401);
    expect((await call("DELETE", "/v1/admin/tenants/acme"))[0]).toBe(401);
    expect((await call("GET", "/v1/admin/tenants/acme", undefined, ENV.ADMIN_TOKEN))[0]).toBe(405);

    const [st, out] = await call("DELETE", "/v1/admin/tenants/acme", undefined, ENV.ADMIN_TOKEN);
    expect([st, out.deleted, out.id]).toEqual([200, true, "acme"]);
    expect(out.keys).toBe(before.filter((k) => k.startsWith("t/acme/")).length);
    expect([...kv.items.keys()].filter((k) => k.startsWith("t/acme/"))).toEqual([]);
    expect([...kv.items.keys()].filter((k) => k.startsWith("t/acme-psp/"))).toEqual(before.filter((k) => k.startsWith("t/acme-psp/")));

    // Its keys stop working; its public key set is gone; the other tenant is untouched.
    expect((await call("POST", "/v1/check", { mandate: a.mandate, payment: a.pay("p_2", "1.00") }, a.apiKey))[0]).toBe(401);
    expect((await call("GET", "/t/acme/keys"))[0]).toBe(404);
    expect((await call("POST", "/v1/check", { mandate: b.mandate, payment: b.pay("p_9", "100.00") }, b.apiKey))[1].outcome).toBe("allow");

    // Deleting again: nothing there. The id can be used again, with nothing of the old tenant in it.
    expect((await call("DELETE", "/v1/admin/tenants/acme", undefined, ENV.ADMIN_TOKEN))[0]).toBe(404);
    const again = await setup("acme");
    const [, d] = await call("POST", "/v1/check", { mandate: a.mandate, payment: a.pay("p_1", "100.00") }, again.apiKey);
    // A fresh authority table: the old tenant's enrolled key for this signer is gone too.
    expect(d.reasons).toEqual(["signer_not_authorized"]);
  });

  it("finishes a deletion that was interrupted, and refuses to reuse an id whose data is still there", async () => {
    const a = await setup("acme");
    await call("POST", "/v1/check", { mandate: a.mandate, payment: a.pay("p_1", "100.00") }, a.apiKey);
    let dels = 0;
    kv.failOn = (op) => op === "del" && ++dels > 2;
    expect((await call("DELETE", "/v1/admin/tenants/acme", undefined, ENV.ADMIN_TOKEN))[0]).toBe(503);
    kv.failOn = null;
    expect(kv.items.has("t/acme/tenant")).toBe(false); // the record goes first: the keys stopped working at once
    expect((await call("POST", "/v1/check", { mandate: a.mandate, payment: a.pay("p_2", "1.00") }, a.apiKey))[0]).toBe(401);
    expect((await call("POST", "/v1/admin/tenants", { id: "acme" }, ENV.ADMIN_TOKEN))[0]).toBe(409);
    const [st, out] = await call("DELETE", "/v1/admin/tenants/acme", undefined, ENV.ADMIN_TOKEN);
    expect([st, out.deleted]).toEqual([200, true]);
    expect([...kv.items.keys()].filter((k) => k.startsWith("t/acme/"))).toEqual([]);
    expect((await call("POST", "/v1/admin/tenants", { id: "acme" }, ENV.ADMIN_TOKEN))[0]).toBe(201);
  });

  it("deletes more keys than one listing page", async () => {
    await setup("acme");
    for (let i = 0; i < 2500; i++) kv.items.set(`t/acme/payments/${String(i).padStart(5, "0")}`, { data: "{}", etag: `"x${i}"` });
    const [st, out] = await call("DELETE", "/v1/admin/tenants/acme", undefined, ENV.ADMIN_TOKEN);
    expect([st, (out.keys as number) > 2500]).toEqual([200, true]);
    expect([...kv.items.keys()].filter((k) => k.startsWith("t/acme/"))).toEqual([]);
  });
});

// ---------- releasing an allowed payment that was not executed ----------

describe("releasing a reservation", () => {
  // Release is off by default; these tests turn it on with the window an operator would set.
  beforeEach(() => {
    env = { ...ENV, RELEASE_WINDOW_HOURS: "24" };
  });
  const check = (s: Awaited<ReturnType<typeof setup>>, payment: J) => call("POST", "/v1/check", { mandate: s.mandate, payment }, s.apiKey);
  const release = (s: Awaited<ReturnType<typeof setup>>, payment: J, decision: J) =>
    call("POST", "/v1/release", { mandate: s.mandate, payment, decision }, s.apiKey);

  it("review 05 M1: check + release of the same payment cannot be repeated to get past the period limit", async () => {
    // 25 000 per payment, 40 000 per month. Before the fix: 5 x 20 000 allowed under one id (100 000).
    const s = await setup();
    const p = s.pay("INV-LOOP", "20000.00");
    let allowed = 0n;
    for (let i = 0; i < 5; i++) {
      const [st, d] = await check(s, p);
      expect(st).toBe(200);
      if (d.outcome === "allow") allowed += 2_000_000n;
      await release(s, p, d);
    }
    expect(allowed).toBe(2_000_000n); // once
    const [, again] = await check(s, p);
    expect([again.outcome, again.reasons]).toEqual(["block", ["duplicate_payment"]]);
    // A released id stays used for any payment under it, too.
    const [, other] = await check(s, s.pay("INV-LOOP", "10.00"));
    expect(other.reasons).toEqual(["duplicate_payment"]);
    // New ids are checked against the limit as usual: 40 000 a month in total, never more.
    const [, a] = await check(s, s.pay("INV-A", "20000.00"));
    const [, b] = await check(s, s.pay("INV-B", "20000.00"));
    const [, c] = await check(s, s.pay("INV-C", "0.01"));
    expect([a.outcome, b.outcome, c.reasons]).toEqual(["allow", "allow", ["over_period_limit"]]);
  });

  it("gives back the period reservation once, keeps the payment id used, and answers a repeat with the same result", async () => {
    const s = await setup();
    const p1 = s.pay("p_1", "20000.00"), p2 = s.pay("p_2", "20000.00");
    const [, d1] = await check(s, p1);
    const [, d2] = await check(s, p2);
    expect([d1.outcome, d2.outcome]).toEqual(["allow", "allow"]);
    expect((await check(s, s.pay("p_3", "1.00")))[1].reasons).toEqual(["over_period_limit"]);

    const [st, r] = await release(s, p2, d2);
    expect(st).toBe(200);
    expect(r).toMatchObject({ released: true, payment_id: "held", decision: { id: d2.id }, payment: { id: "p_2" } });
    expect((r.reservations as string[]).length).toBe(1);
    expect(r).not.toHaveProperty("payment_id_freed");
    // Idempotent: the same release again is a no-op with exactly the same answer.
    const [st2, r2] = await release(s, p2, d2);
    expect([st2, r2]).toEqual([200, r]);
    // 20 000 is free again, exactly once.
    expect((await check(s, s.pay("p_3", "1.00")))[1].outcome).toBe("allow");
    expect((await check(s, s.pay("p_4", "19999.00")))[1].outcome).toBe("allow");
    expect((await check(s, s.pay("p_5", "0.01")))[1].reasons).toEqual(["over_period_limit"]);
    // p_2 sent again: a terminal block, not the old allow and not a fresh check.
    const [, again] = await check(s, p2);
    expect([again.outcome, again.reasons]).toEqual(["block", ["duplicate_payment"]]);
    // The payment log records the release.
    const entry = [...kv.items.entries()].find(([k, v]) => k.includes("/payments/") && v.data.includes("released"));
    expect(JSON.parse(entry![1].data)).toMatchObject({ decision: null, released: { decision: { id: d2.id } } });
    // And a third release still gives the same answer, releasing nothing.
    expect((await release(s, p2, d2))[1]).toEqual(r);
    expect((await check(s, s.pay("p_6", "0.01")))[1].reasons).toEqual(["over_period_limit"]);
  });

  it("concurrent releases of one decision release once and all get the same answer", async () => {
    const s = await setup();
    const p1 = s.pay("p_1", "20000.00"), p2 = s.pay("p_2", "20000.00");
    await check(s, p1);
    const [, d2] = await check(s, p2);
    const all = await Promise.all(Array.from({ length: 6 }, () => release(s, p2, d2)));
    expect(all.every(([st]) => st === 200)).toBe(true);
    for (const [, r] of all) expect(r).toEqual(all[0]![1]);
    expect((await check(s, s.pay("p_3", "20000.00")))[1].outcome).toBe("allow");
    expect((await check(s, s.pay("p_4", "0.01")))[1].reasons).toEqual(["over_period_limit"]);
  });

  it("release is off by default (RELEASE_WINDOW_HOURS unset or blank: 403)", async () => {
    const s = await setup();
    const p = attach(s.mandate, { id: "off_1", rail: "sepa", amount: "15000.00", currency: "EUR", payee: BRENNER,
      agentSeed: s.agentSeed, requestedAt: new Date().toISOString() });
    const [, d] = await check(s, p);
    expect(d.outcome).toBe("allow");
    for (const off of [undefined, "", "  "]) {
      env = { ...ENV };
      if (off !== undefined) env.RELEASE_WINDOW_HOURS = off;
      else delete env.RELEASE_WINDOW_HOURS;
      expect((await release(s, p, d))[0]).toBe(403);
    }
  });

  it("only within the release window after the decision (RELEASE_WINDOW_HOURS=24)", async () => {
    const s = await setup();
    let now = Date.parse("2026-10-05T08:00:00.000Z");
    clock = () => new Date(now);
    const pay = (id: string) => attach(s.mandate, { id, rail: "sepa", amount: "15000.00", currency: "EUR", payee: BRENNER,
      agentSeed: s.agentSeed, requestedAt: new Date(now).toISOString() });
    const p1 = pay("w_1"), p2 = pay("w_2");
    const [, d1] = await check(s, p1);
    const [, d2] = await check(s, p2);
    expect([d1.outcome, d2.outcome]).toEqual(["allow", "allow"]);
    // 24 h + 1 ms later: refused, the reservation stands.
    now += 24 * 3600_000 + 1;
    const [st, err] = await release(s, p1, d1);
    expect([st, err.error]).toEqual([409, "release rejected: the decision is older than the release window (24 hours)"]);
    // Exactly 24 h is still inside.
    now -= 1;
    const [st2, r2] = await release(s, p2, d2);
    expect([st2, r2.released]).toEqual([200, true]);
    // Once released, a repeat gives the same answer even after the window has closed.
    now += 72 * 3600_000;
    expect(await release(s, p2, d2)).toEqual([200, r2, expect.anything()]);
    // Configurable: 1 hour.
    env = { ...ENV, RELEASE_WINDOW_HOURS: "1" };
    const p3 = pay("w_3");
    const [, d3] = await check(s, p3);
    now += 3600_000 + 1;
    expect((await release(s, p3, d3))[0]).toBe(409);
    // 0 disables release; a bad setting fails closed.
    env = { ...ENV, RELEASE_WINDOW_HOURS: "0" };
    expect((await release(s, p3, d3))[0]).toBe(403);
    for (const bad of ["-1", "1.5", "24h", "745", "99999"]) {
      env = { ...ENV, RELEASE_WINDOW_HOURS: bad };
      expect((await release(s, p3, d3))[0]).toBe(503);
    }
  });

  it("only in the limit period the reservation was made in", async () => {
    const s = await setup();
    let now = Date.parse("2026-10-31T23:30:00.000Z");
    clock = () => new Date(now);
    const pay = (id: string, amount = "20000.00") => attach(s.mandate, { id, rail: "sepa", amount, currency: "EUR", payee: BRENNER,
      agentSeed: s.agentSeed, requestedAt: new Date(now).toISOString() });
    const p1 = pay("x_1"), p2 = pay("x_2");
    const [, d1] = await check(s, p1);
    const [, d2] = await check(s, p2);
    expect([d1.outcome, d2.outcome]).toEqual(["allow", "allow"]);
    // 00:30 the next day is inside 24 h but in November: October's reservation cannot be given back any more.
    now = Date.parse("2026-11-01T00:30:00.000Z");
    const [st, err] = await release(s, p1, d1);
    expect([st, err.error]).toEqual([409, "release rejected: the limit period the reservation was made in has ended"]);
    // Still in October: allowed, and the October total goes down.
    now = Date.parse("2026-10-31T23:59:59.000Z");
    expect((await release(s, p2, d2))[1].released).toBe(true);
    expect((await check(s, pay("x_3")))[1].outcome).toBe("allow");
    expect((await check(s, pay("x_4", "0.01")))[1].reasons).toEqual(["over_period_limit"]);
  });

  it("refuses what it must not release", async () => {
    const s = await setup();
    const p1 = s.pay("p_1", "100.00");
    const [, d1] = await check(s, p1);
    const big = s.pay("p_big", "30000.00");
    const [, esc] = await check(s, big);
    const rel = (body: J, key = s.apiKey) => call("POST", "/v1/release", body, key);
    expect((await rel({ mandate: s.mandate, payment: big, decision: esc }))[0]).toBe(400); // not an allow
    expect((await rel({ mandate: s.mandate, payment: s.pay("p_1", "100.01"), decision: d1 }))[0]).toBe(400); // other payment
    expect((await rel({ mandate: s.mandate, payment: p1, decision: { ...d1, checks: [] } }))[0]).toBe(400); // edited
    expect((await rel({ mandate: s.mandate, payment: p1 }))[0]).toBe(400);
    expect((await rel({ mandate: s.mandate, payment: p1, decision: d1 }, "gks_nope"))[0]).toBe(401);
    // Another tenant cannot release this tenant's decision: it is not signed by its checker.
    const o = await setup("other-psp");
    expect((await rel({ mandate: s.mandate, payment: p1, decision: d1 }, o.apiKey))[0]).toBe(400);
    // Released once; the payment sent again is blocked, and that block cannot be released.
    const [, first] = await rel({ mandate: s.mandate, payment: p1, decision: d1 });
    expect(first.released).toBe(true);
    const [, d1b] = await check(s, p1);
    expect(d1b.reasons).toEqual(["duplicate_payment"]);
    expect((await rel({ mandate: s.mandate, payment: p1, decision: d1b }))[0]).toBe(400);
    expect((await rel({ mandate: s.mandate, payment: p1, decision: d1 }))[1]).toEqual(first);
    // A real allow of this checker that the log does not hold for the payment: 409.
    const p9 = s.pay("p_9", "1.00");
    const [, d9] = await check(s, p9);
    for (const k of [...kv.items.keys()]) if (k.includes("/payments/")) kv.items.delete(k);
    expect((await rel({ mandate: s.mandate, payment: p9, decision: d9 }))[0]).toBe(409);
    expect((await call("GET", "/v1/release", undefined, s.apiKey))[0]).toBe(405);
  });

  it("a release interrupted by the store leaves limits stricter, never looser", async () => {
    const s = await setup();
    const p1 = s.pay("p_1", "20000.00"), p2 = s.pay("p_2", "20000.00");
    await check(s, p1);
    const [, d2] = await check(s, p2);
    // The store fails right after the release marker is written.
    const put = kv.put.bind(kv);
    let fail = false;
    kv.put = async (k, v, c) => {
      if (fail) throw new Error("store down");
      const ok = await put(k, v, c);
      if (k.includes("/released/")) fail = true;
      return ok;
    };
    expect((await release(s, p2, d2))[0]).toBe(503);
    kv.put = put;
    // The reservation stands, and nothing is released later either.
    expect((await release(s, p2, d2))[1].released).toBe(true);
    expect((await check(s, s.pay("p_3", "0.01")))[1].reasons).toEqual(["over_period_limit"]);
  });
});

// ---------- 0.5: payee approvals on /check ----------

describe("payee approvals on the hosted checker", () => {
  it("escalates a new payee, accepts a signatory's approval, and honours its revocation", async () => {
    const s = await setup();
    const m5 = signMandate(issue({
      id: "m_ap5", company: COMPANY, agent: s.mandate.agent as J, signer: { ...s.signer, name: "K. Berger" },
      scope: { rails: ["sepa"], currency: "EUR", max_per_payment: "25000.00", payees: [BRENNER], from_accounts: [FROM],
        unlisted_payees: "escalate", max_per_unlisted_payee: "5000.00" },
      validUntil: "2099-12-31T23:59:59.000Z",
    }), s.signerSeed);
    const kranbau = { name: "Kranbau Wels GmbH", account: iban("AT131100000622300000") };
    const a = signPayeeApproval(approvePayee(m5, { payee: kranbau, id: "pa_1" }), s.signerSeed, s.signer);
    const pay5 = (id: string, payee: J) => attach(m5, { id, rail: "sepa", amount: "100.00", currency: "EUR", payee,
      agentSeed: s.agentSeed });
    const check = (p: J, approvals?: unknown[]) => call("POST", "/v1/check",
      approvals ? { mandate: m5, payment: p, payee_approvals: approvals } : { mandate: m5, payment: p }, s.apiKey);
    expect((await check(pay5("p_1", kranbau)))[1].reasons).toEqual(["new_payee"]);
    expect((await check(pay5("p_2", MALLORY)))[1].reasons).toEqual(["payee_account_changed"]);
    const [, ok] = await check(pay5("p_3", kranbau), [a]);
    expect([ok.v, ok.outcome, (ok.payee_approval as J).id]).toEqual(["gleipnir/decision/0.5", "allow", "pa_1"]);
    expect((await call("POST", "/v1/check", { mandate: m5, payment: pay5("p_4", kranbau), payee_approvals: [a], x: 1 },
      s.apiKey))[0]).toBe(400);

    const r = revoke(a, { signer: s.signer, seed: s.signerSeed, id: "r_pa", revokedAt: new Date(Date.now() - 1000).toISOString() });
    expect((await call("POST", "/v1/revoke", { revocation: r, mandate: m5 }, s.apiKey))[0]).toBe(400); // needs the approval
    expect((await call("POST", "/v1/revoke", { revocation: r, mandate: m5, payee_approval: a }, s.apiKey))[0]).toBe(200);
    const [, after] = await check(pay5("p_5", kranbau), [a]);
    expect([after.reasons, (after.checks as string[]).includes("payee_approval_revoked")]).toEqual([["new_payee"], true]);
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
  ledger: boolean | "error" | "junk"; payment_log?: LogMode; approvals?: (unknown[] | null)[];
}

/** The KV ledger, failing as a vector asks (spec 0.4.1: "error" throws, "junk" answers a non-boolean). */
class BrokenKVLedger extends KVLedger {
  constructor(kv: MemoryKV, private readonly mode: "error" | "junk") { super(kv, "vectors"); }
  override async reserve(): Promise<boolean> {
    if (this.mode === "error") throw new Error("ledger down");
    return "ok" as unknown as boolean;
  }
}

type LogMode = "error" | "junk" | "junk_take" | "junk_late_register";

/**
 * The KV payment log, failing as a vector asks: "error" throws on every call, "junk" claims and answers a
 * non-boolean, "junk_take" takes and answers a non-boolean, "junk_late_register" answers a non-boolean from every
 * register after the first.
 */
class BrokenKVPaymentLog extends KVPaymentLog {
  private registers = 0;
  constructor(kv: MemoryKV, private readonly mode: LogMode) { super(kv, "vectors"); }
  private down(): void {
    if (this.mode === "error") throw new Error("payment log down");
  }
  override async lookup(key: string, paymentHash: string): Promise<J | null> {
    this.down();
    return super.lookup(key, paymentHash);
  }
  override async register(key: string, paymentHash: string): Promise<boolean> {
    this.down();
    this.registers += 1;
    const ok = await super.register(key, paymentHash);
    return this.mode === "junk" || (this.mode === "junk_late_register" && this.registers > 1) ? 1 as unknown as boolean : ok;
  }
  override async remember(key: string, decision: J): Promise<void> {
    this.down();
    await super.remember(key, decision);
  }
  override async forget(key: string): Promise<void> {
    this.down();
    await super.forget(key);
  }
  override async take(key: string, paymentHash: string, decisionId: string): Promise<boolean> {
    this.down();
    const took = await super.take(key, paymentHash, decisionId);
    return this.mode === "junk_take" ? 1 as unknown as boolean : took;
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
      const ap = (c.approvals ?? [])[i] ?? undefined;
      if (op === "check") out.push(await checker.check(md, c.payments[i], ap));
      else {
        const d = out[op.resolve.of]!;
        let o = makeOverride(d, { outcome: op.resolve.outcome, id: op.resolve.id, reason: op.resolve.reason ?? "", decidedAt: op.resolve.decided_at });
        if (op.resolve.decision_hash) o = { ...o, decision: { ...(o.decision as J), hash: op.resolve.decision_hash } };
        for (const sg of op.resolve.signers) {
          const seed = seedFromHex(sg.seed);
          o = signOverride(o, seed, { id: sg.id, public_key: publicKeyOf(seed) });
        }
        out.push(await checker.resolve(md, c.payments[i], d, o, ap));
      }
    }
    expect(expected(out)).toEqual(c.expect);
  });
});
