#!/usr/bin/env node
// Smoke test for the SANDBOX hosted checker: the three demo cases against a live deployment.
//
//   GLEIPNIR_API_KEY=gks_... GLEIPNIR_KYB_KEY=gkk_... node scripts/hosted-smoke.mjs <base-url>
//   (keys from the environment only, so they stay out of shell history and process lists;
//    the base URL may also come from GLEIPNIR_BASE_URL)
//
// 1. allow:     the agent pays a payee on the mandate, within limits
// 2. block:     a tricked agent pays a new account (payee_not_on_mandate)
// 3. escalate:  over the per-payment limit; the company signatory signs an override; resolve -> allow
//
// With the KYB key it adds a throwaway company ("Gleipnir Smoke ...") with a fresh signatory key to the tenant's
// authority table (keeping every other row, and dropping earlier smoke rows). Use a dedicated smoke tenant. Needs the library built once:
//   cd typescript && npm ci && npm run build -w @getgleipnir/verify

import {
  attach, iban, issue, makeOverride, newSeed, publicKeyOf, signMandate, signOverride, verifyDecision,
} from "@getgleipnir/verify/mandate";

const base = (process.argv[2] ?? process.env.GLEIPNIR_BASE_URL ?? "").replace(/\/+$/, "");
const apiKey = process.env.GLEIPNIR_API_KEY ?? "";
const kybKey = process.env.GLEIPNIR_KYB_KEY ?? "";
const tenant = /^gks_([a-z0-9-]+)_/.exec(apiKey)?.[1];
if (!base || !tenant || /^gkk_([a-z0-9-]+)_/.exec(kybKey)?.[1] !== tenant) {
  console.error("usage: GLEIPNIR_API_KEY=gks_... GLEIPNIR_KYB_KEY=gkk_... node scripts/hosted-smoke.mjs <base-url>");
  process.exit(2);
}

async function call(method, path, body, auth = apiKey) {
  const headers = {};
  if (auth) headers.Authorization = `Bearer ${auth}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  if (!res.ok) throw new Error(`${method} ${path}: HTTP ${res.status} ${JSON.stringify(json)}`);
  return json;
}

let failed = 0;
function expectCase(name, d, outcome, reasons) {
  const ok = d.outcome === outcome && JSON.stringify(d.reasons) === JSON.stringify(reasons);
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}: ${d.outcome} ${JSON.stringify(d.reasons)}  (decision ${d.id}, checker ${d.checker?.id})`);
}

const run = new Date().toISOString().replace(/\D/g, "").slice(0, 14) + "-" + Math.random().toString(36).slice(2, 6);
const company = { name: `Gleipnir Smoke ${run}`, country: "AT" };
const from = iban("AT483200000012345864");
const brenner = { name: "Brenner Stahl AG", account: iban("AT611904300234573201") };
const mallory = { name: "Brenner Stahl AG", account: iban("DE89370400440532013000") };
const signerSeed = newSeed(), agentSeed = newSeed();
const signer = { id: `cfo@smoke-${run}.example`, public_key: publicKeyOf(signerSeed) };

const keys = await call("GET", "/v1/keys");
if (!String(keys.checker).includes("sandbox")) throw new Error(`not a sandbox checker: ${keys.checker}`);
const keyset = await call("GET", `/t/${tenant}/.well-known/gleipnir-checker.json`, undefined, null);
console.log(`checker ${keys.checker} at ${base}`);

const authority = await call("GET", `/v1/admin/tenants/${tenant}/authority`, undefined, kybKey);
const keep = (rows) => rows.filter((r) => !String(r.company).startsWith("Gleipnir Smoke "));
await call("PUT", `/v1/admin/tenants/${tenant}/authority`, {
  ...authority,
  signers: [...keep(authority.signers), { company: company.name, signer: signer.id, keys: [signer.public_key] }],
  accounts: [...keep(authority.accounts), { company: company.name, account: from }],
}, kybKey);

const mandate = signMandate(issue({
  id: `m_smoke_${run}`, company, agent: { id: "ap-agent", public_key: publicKeyOf(agentSeed) },
  signer: { ...signer, name: "Smoke CFO" },
  scope: { rails: ["sepa", "sepa_instant"], currency: "EUR", max_per_payment: "25000.00",
    max_per_period: { amount: "100000.00", period: "P1M" }, payees: [brenner], from_accounts: [from] },
  validUntil: new Date(Date.now() + 86_400_000).toISOString(),
}), signerSeed);
const pay = (n, amount, payee = brenner) =>
  attach(mandate, { id: `smoke-${run}-${n}`, rail: "sepa", amount, currency: "EUR", payee, agentSeed });

const d1 = await call("POST", "/v1/check", { mandate, payment: pay(1, "18400.00") });
expectCase("1 allow (payee on mandate, within limits)", d1, "allow", []);

const d2 = await call("POST", "/v1/check", { mandate, payment: pay(2, "18400.00", mallory) });
expectCase("2 block (tricked agent, new payee account)", d2, "block", ["payee_not_on_mandate"]);

const p3 = pay(3, "30000.00");
const d3 = await call("POST", "/v1/check", { mandate, payment: p3 });
expectCase("3a escalate (over the per-payment limit)", d3, "escalate", ["over_payment_limit"]);
const override = signOverride(makeOverride(d3, { outcome: "allow", id: `o_smoke_${run}`, reason: "smoke test" }), signerSeed, signer);
const d4 = await call("POST", "/v1/resolve", { mandate, payment: p3, decision: d3, override });
expectCase("3b override by the signatory -> allow", d4, "allow", []);

for (const d of [d1, d2, d3, d4]) {
  if (!verifyDecision(d, keyset)) {
    failed++;
    console.log(`FAIL  decision ${d.id} does not verify against ${base}/t/${tenant}/.well-known/gleipnir-checker.json`);
  }
}
console.log(failed ? `${failed} problem(s)` : "all decisions signed by the published sandbox key");
process.exit(failed ? 1 : 0);
