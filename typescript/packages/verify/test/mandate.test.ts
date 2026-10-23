import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  Checker,
  InMemoryLedger,
  attach,
  issue,
  newSeed,
  parseAmount,
  periodKey,
  publicKeyOf,
  combine,
  cosign,
  delegate,
  revoke,
  seedFromHex,
  signMandate,
  verifyDecision,
  verifyReceipt,
  type AuthorityResult,
} from "@getgleipnir/verify/mandate";

type J = Record<string, unknown>;
interface Vector {
  name: string;
  mandate: unknown;
  payments: unknown[];
  now: string[];
  authority: { company: string; signer: string; source: string; keys: string[]; may_sign: boolean; joint?: number }[];
  revocations: unknown[];
  status: string | null;
  ledger: boolean;
  expect: J[];
  receipt: J;
  webauthn: { rp_id?: string; origins?: string[] };
}

const DATA = JSON.parse(
  readFileSync(fileURLToPath(new URL("./fixtures/mandate-vectors.json", import.meta.url)), "utf8"),
) as { bank: { id: string; seed_hex: string; public_key: string }; other_public_key: string; cases: Vector[]; signed: J[] };

async function run(c: Vector): Promise<J[]> {
  let now = c.now[0]!;
  const checker = new Checker({
    id: DATA.bank.id,
    seed: seedFromHex(DATA.bank.seed_hex),
    authority: (company, signerId) => {
      const row = c.authority.find((r) => r.company === company.name && r.signer === signerId);
      return row ? { source: row.source, keys: row.keys, maySign: row.may_sign, joint: row.joint ?? 1 } : null;
    },
    ledger: c.ledger ? new InMemoryLedger() : null,
    revocations: c.revocations,
    status:
      c.status === null
        ? null
        : async (url) => {
            if (c.status === "error") throw new Error(`unreachable ${url}`);
            return c.status!;
          },
    clock: () => new Date(now),
    webauthn: { rpId: c.webauthn.rp_id, origins: c.webauthn.origins },
  });
  const out: J[] = [];
  for (let i = 0; i < c.payments.length; i++) {
    now = c.now[i]!;
    out.push(await checker.check(c.mandate, c.payments[i]));
  }
  return out;
}

function expected(decisions: J[]): J[] {
  const first = new Map<unknown, number>();
  return decisions.map((d, i) => {
    let row: J = Object.fromEntries(Object.entries(d).filter(([k]) => k !== "id" && k !== "sig"));
    if (first.has(d.id)) row = { same_as: first.get(d.id) };
    if (!first.has(d.id)) first.set(d.id, i);
    return row;
  });
}

describe("mandate conformance vectors (shared with the Python reference)", () => {
  it.each(DATA.cases.map((c) => [c.name, c] as const))("%s", async (_name, c) => {
    const decisions = await run(c);
    expect(expected(decisions)).toEqual(c.expect);
    for (const d of decisions) expect(verifyDecision(d, [DATA.bank.public_key])).toBe(true);
    const receipt: J = { ...verifyReceipt(c.mandate, c.payments[0], decisions[0], [DATA.bank.public_key], {
      webauthn: { rpId: c.webauthn.rp_id, origins: c.webauthn.origins },
    }) };
    delete receipt.checked_at;
    expect(receipt).toEqual(c.receipt);
  });

  it("verifies decisions signed by the Python reference, and rejects edits and unknown keys", () => {
    expect(DATA.signed.length).toBeGreaterThan(20);
    for (const d of DATA.signed) {
      expect(verifyDecision(d, [DATA.bank.public_key])).toBe(true);
      expect(verifyDecision({ ...d, outcome: d.outcome === "allow" ? "block" : "allow" }, [DATA.bank.public_key])).toBe(false);
      expect(verifyDecision(d, [DATA.other_public_key])).toBe(false);
      expect(verifyDecision({ ...d, sig: undefined }, [DATA.bank.public_key])).toBe(false);
    }
    expect(verifyDecision(null, [DATA.bank.public_key])).toBe(false);
    expect(verifyDecision("x", [DATA.bank.public_key])).toBe(false);
  });
});

describe("mandate flow in TypeScript", () => {
  const signerSeed = newSeed(), agentSeed = newSeed(), bankSeed = newSeed();
  const brenner = { name: "Brenner Stahl AG", account: { iban: "AT611904300234573201" } };
  const m = signMandate(
    issue({
      id: "m_ts",
      company: { name: "Nordhafen Logistik GmbH", country: "AT" },
      agent: { id: "ap-agent", public_key: publicKeyOf(agentSeed) },
      signer: { id: "kberger@nordhafen.at", public_key: publicKeyOf(signerSeed) },
      scope: { rails: ["sepa"], currency: "EUR", max_per_payment: "25000.00", payees: [brenner] },
      validUntil: "2099-01-01T00:00:00.000Z",
    }),
    signerSeed,
  );
  const kyb = (): AuthorityResult => ({ source: "bank_kyb", keys: [publicKeyOf(signerSeed)] });

  it("allows, blocks a revoked mandate, and verifies", async () => {
    const bank = new Checker({ id: "bank:ts", seed: bankSeed, authority: kyb });
    const p = attach(m, { id: "p_1", rail: "sepa", amount: "18400.00", currency: "EUR", payee: brenner, agentSeed });
    const d = await bank.check(m, p);
    expect(d.outcome).toBe("allow");
    expect(verifyDecision(d, [bank.publicKey])).toBe(true);
    bank.revocations.push(revoke(m, { signer: { id: "kberger@nordhafen.at", public_key: publicKeyOf(signerSeed) },
      seed: signerSeed, id: "r_1", revokedAt: "2000-01-01T00:00:00.000Z" }));
    const p2 = attach(m, { id: "p_2", rail: "sepa", amount: "1.00", currency: "EUR", payee: brenner, agentSeed });
    expect((await bank.check(m, p2)).reasons).toEqual(["mandate_revoked"]);
  });

  it("never throws: broken systems escalate, junk input blocks", async () => {
    const p = attach(m, { id: "p_1", rail: "sepa", amount: "1.00", currency: "EUR", payee: brenner, agentSeed });
    const down = new Checker({ id: "b", seed: bankSeed, authority: async () => { throw new Error("kyb down"); } });
    expect((await down.check(m, p)).reasons).toEqual(["checker_unavailable"]);
    const weird = new Checker({ id: "b", seed: bankSeed, authority: () => 42 as unknown as AuthorityResult });
    expect((await weird.check(m, { ...p, id: "p_2" })).reasons).toEqual(["checker_unavailable"]);
    const ok = new Checker({ id: "b", seed: bankSeed, authority: kyb });
    for (const junk of [undefined, null, 1, [], { v: "gleipnir/payment/0.1" }, { ...p, amount: 1e400 }]) {
      expect((await ok.check(m, junk)).outcome).toBe("block");
    }
    expect((await ok.check(undefined, p)).reasons).toEqual(["mandate_malformed"]);
  });

  it("two signers, a delegation chain and a second bank via vLEI", async () => {
    const hoferSeed = newSeed(), ceoSeed = newSeed();
    const berger = { id: "kberger@nordhafen.at", public_key: publicKeyOf(signerSeed) };
    const hofer = { id: "mhofer@nordhafen.at", public_key: publicKeyOf(hoferSeed) };
    const company = { name: "Nordhafen Logistik GmbH", country: "AT" };
    const scope = { rails: ["sepa"], currency: "EUR", max_per_payment: "25000.00", payees: [brenner] };
    let joint = issue({ id: "m_joint", company, agent: { id: "ap-agent", public_key: publicKeyOf(agentSeed) },
      signers: { threshold: 2, of: [berger, hofer] }, scope, validUntil: "2099-01-01T00:00:00.000Z" });
    joint = cosign(cosign(joint, signerSeed, berger.id), hoferSeed, hofer.id);
    const kyb = (_c: Record<string, unknown>, id: string): AuthorityResult | null =>
      id === berger.id ? { source: "bank_kyb", keys: [berger.public_key] }
        : id === hofer.id ? { source: "bank_kyb", keys: [hofer.public_key] } : null;
    const bank = new Checker({ id: "bank:ts", seed: bankSeed, authority: kyb });
    const p = attach(joint, { id: "p_j", rail: "sepa", amount: "100.00", currency: "EUR", payee: brenner, agentSeed });
    const d = await bank.check(joint, p);
    expect(d.checks).toContain("signatures:2/2");
    expect(verifyReceipt(joint, p, d, [bank.publicKey]).signed_by).toEqual([berger.id, hofer.id]);

    const ceo = { id: "ceo@nordhafen.at", public_key: publicKeyOf(ceoSeed) };
    const link = delegate({ id: "g1", company, from: ceo, to: berger, seed: ceoSeed,
      scope: { ...scope, max_per_payment: "50000.00" }, validUntil: "2099-06-01T00:00:00.000Z" });
    const viaChain = signMandate(issue({ id: "m_chain", company, agent: { id: "ap-agent" }, signer: berger,
      delegation: [link], scope, validUntil: "2099-01-01T00:00:00.000Z" }), signerSeed);
    const people = combine(
      (_c, id) => (id === ceo.id ? { source: "bank_kyb", keys: [ceo.public_key] } : null),
      async (_c, id) => (id === berger.id ? { source: "vlei", keys: [berger.public_key], maySign: false } : null),
    );
    const second = new Checker({ id: "bank:second", seed: bankSeed, authority: people });
    const pc = attach(viaChain, { id: "p_c", rail: "sepa", amount: "100.00", currency: "EUR", payee: brenner });
    expect((await second.check(viaChain, pc)).checks).toContain("delegation:1");
    second.revocations.push(revoke(link, { signer: ceo, seed: ceoSeed, id: "r_g1", revokedAt: "2000-01-01T00:00:00.000Z" }));
    const pc2 = attach(viaChain, { id: "p_c2", rail: "sepa", amount: "100.00", currency: "EUR", payee: brenner });
    expect((await second.check(viaChain, pc2)).reasons).toEqual(["delegation_revoked"]);
    expect(() => delegate({ id: "g", company, from: ceo, to: berger, seed: ceoSeed, scope: {}, validUntil: "x" })).toThrow();
  });

  it("amounts are exact minor units", () => {
    expect(parseAmount("18400.00", "EUR")).toBe(1_840_000n);
    expect(parseAmount("120000", "JPY")).toBe(120_000n);
    for (const bad of ["1.5", "01.00", "1e3", "-1.00", "0.00", " 1.00", "1.000"]) {
      expect(() => parseAmount(bad, "EUR")).toThrow();
    }
    expect(() => parseAmount("1.00", "XXX")).toThrow();
    expect(() => parseAmount("1.00", "toString")).toThrow();
  });

  it("period keys are UTC calendar periods (ISO weeks)", () => {
    const t = (s: string) => BigInt(Date.parse(s)) * 1000n;
    expect(periodKey("P1D", t("2026-10-23T23:59:59Z"))).toBe("2026-10-23");
    expect(periodKey("P1M", t("2026-10-23T00:00:00Z"))).toBe("2026-10");
    expect(periodKey("P7D", t("2026-10-25T23:59:59Z"))).toBe("2026-W43");
    expect(periodKey("P7D", t("2026-10-26T00:00:00Z"))).toBe("2026-W44");
    expect(periodKey("P7D", t("2027-01-01T00:00:00Z"))).toBe("2026-W53");
    expect(periodKey("P7D", t("2024-12-30T00:00:00Z"))).toBe("2025-W01");
    expect(() => periodKey("P1Y", 0n)).toThrow();
  });
});
