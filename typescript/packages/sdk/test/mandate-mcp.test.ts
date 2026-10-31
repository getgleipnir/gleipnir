import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { approvePayee, issue, mandateHash, publicKeyOf, signMandate, signPayeeApproval, verifyDecision } from "@getgleipnir/verify/mandate";
import { MandateTools, TOOLS, adviceFor, handle, parseArgs, seedFromPem, serveLines } from "../src/mandate-mcp.js";

type J = Record<string, unknown>;
const IBAN = "AT611904300234573201";
const PAYEE = `Brenner Stahl AG=${IBAN}`;
const DEBTOR = { scheme: "iban", iban: "AT483200000012345864" };
let dir: string;

function pem(name: string): string {
  const { privateKey } = generateKeyPairSync("ed25519");
  const path = join(dir, `${name}.pem`);
  writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }));
  return path;
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "gleipnir-mcp-"));
  const signer = seedFromPem(readFileSync(pem("signer"), "utf8"));
  const agent = seedFromPem(readFileSync(pem("agent"), "utf8"));
  pem("bank");
  const m = signMandate(issue({
    id: "m_ap", company: { name: "Nordhafen Logistik GmbH", country: "AT" },
    agent: { id: "ap-agent", public_key: publicKeyOf(agent) },
    signer: { id: "kberger@nordhafen.at", public_key: publicKeyOf(signer) },
    scope: { rails: ["sepa"], currency: "EUR", max_per_payment: "25000.00",
      max_per_period: { amount: "40000.00", period: "P1M" }, payees: [{ name: "Brenner Stahl AG", account: { scheme: "iban", iban: IBAN } }],
      from_accounts: [DEBTOR] },
    validUntil: "2099-01-01T00:00:00.000Z",
  }), signer);
  writeFileSync(join(dir, "mandate.json"), JSON.stringify(m));
  writeFileSync(join(dir, "kyb.json"), JSON.stringify({ source: "bank_kyb", signers: [
    { company: "Nordhafen Logistik GmbH", signer: "kberger@nordhafen.at", keys: [publicKeyOf(signer)], may_sign: true }],
  accounts: [{ company: "Nordhafen Logistik GmbH", account: DEBTOR }] }));
});

const tools = (extra: J = {}) => new MandateTools({ mandate: join(dir, "mandate.json"), agentKey: join(dir, "agent.pem"),
  bankKey: join(dir, "bank.pem"), authority: join(dir, "kyb.json"), drafts: join(dir, "drafts"), ...extra });

async function call(t: MandateTools, name: string, args: unknown): Promise<J> {
  const r = await handle(t, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });
  return r!.result as J;
}

describe("gleipnir-mandate-mcp (TypeScript)", () => {
  it("speaks MCP: initialize, tools, resources", async () => {
    const t = tools();
    const init = (await handle(t, { jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-03-26" } }))!;
    expect((init.result as J).protocolVersion).toBe("2025-03-26");
    expect(await handle(t, { jsonrpc: "2.0", method: "notifications/initialized" })).toBeNull();
    const list = (await handle(t, { jsonrpc: "2.0", id: 1, method: "tools/list" }))!.result as J;
    expect((list.tools as J[]).map((x) => x.name)).toEqual(["mandate_scope", "request_mandate", "attach_mandate", "check_payment"]);
    const read = (await handle(t, { jsonrpc: "2.0", id: 2, method: "resources/read", params: { uri: "gleipnir://mandate/current" } }))!;
    expect(JSON.parse(((read.result as J).contents as J[])[0]!.text as string).id).toBe("m_ap");
    expect(((await handle(t, { jsonrpc: "2.0", id: 3, method: "resources/read", params: { uri: "file:///etc/passwd" } }))!.error as J).code).toBe(-32002);
    expect(((await handle(t, { jsonrpc: "2.0", id: 4, method: "nope" }))!.error as J).code).toBe(-32601);
    expect(((await handle(t, "x"))!.error as J).code).toBe(-32600);
  });

  it("runs the demo: allow, changed IBAN blocked, over limit escalated", async () => {
    const t = tools();
    const scope = (await call(t, "mandate_scope", {})).structuredContent as J;
    expect(scope.max_per_payment).toBe("25000.00");
    const outcomes = [];
    for (const [pid, amount, payee] of [["INV-1", "18400.00", PAYEE], ["INV-2", "18400.00", "Brenner Stahl AG=LT121000011101001000"],
      ["INV-3", "26000.00", PAYEE]] as const) {
      const p = (await call(t, "attach_mandate", { payment_id: pid, amount, payee })).structuredContent as J;
      const r = (await call(t, "check_payment", p)).structuredContent as J;
      outcomes.push([r.outcome, r.reasons]);
    }
    expect(outcomes).toEqual([["allow", []], ["block", ["payee_not_on_mandate"]], ["escalate", ["over_payment_limit"]]]);
  });

  it("drafts mandates for a person to sign, never signs them", async () => {
    const out = (await call(tools(), "request_mandate", { company: "Nordhafen Logistik GmbH", country: "AT",
      signer_id: "kberger@nordhafen.at", signer_public_key: publicKeyOf(seedFromPem(readFileSync(join(dir, "signer.pem"), "utf8"))),
      currency: "EUR", max_per_payment: "5000.00", max_per_month: "20000.00", payees: [PAYEE],
      from_accounts: ["AT48 3200 0000 1234 5864"], valid_until: "2099-01-01T00:00:00.000Z" })).structuredContent as J;
    const draft = JSON.parse(readFileSync(out.draft as string, "utf8")) as J;
    expect(draft.sig).toBeUndefined();
    expect((draft.scope as J).from_accounts).toEqual([DEBTOR]);
    expect(mandateHash(draft)).toBe(out.mandate_hash);
  });

  it.each([
    ["attach_mandate", { payment_id: "x", amount: 100, payee: PAYEE }, "amount must be a string"],
    ["attach_mandate", { payment_id: "x", amount: "1.00", payee: PAYEE, agentKey: "/x" }, "unknown arguments"],
    ["attach_mandate", { payment_id: "x", amount: "1.5", payee: PAYEE }, "bad amount"],
    ["attach_mandate", { payment_id: "x", amount: "1.00", payee: "no-iban" }, "NAME=ACCOUNT"],
    ["attach_mandate", { payment_id: "x", amount: "1.00", payee: PAYEE, constructor: "x" }, "unknown arguments"],
    ["attach_mandate", JSON.parse('{"payment_id": "x", "amount": "1.00", "payee": "a=b", "__proto__": "x"}'), "unknown arguments"],
    ["attach_mandate", { payment_id: "x", amount: "1.00", payee: "X=AT62 1904 3002 3457 3201" }, "check digits"],
    ["attach_mandate", { payment_id: "x", amount: "1.00", payee: "X=telex:1" }, "unknown account scheme"],
    ["check_payment", { payment: [] }, "payment must be a object"],
    ["mandate_scope", [], "arguments must be an object"],
  ])("rejects bad arguments for %s", async (name, args, text) => {
    const r = await call(tools(), name, args);
    expect(r.isError).toBe(true);
    expect(((r.content as J[])[0]!.text as string)).toContain(text);
  });

  it("errors are tool results, never crashes", async () => {
    expect(((await call(tools({ bankKey: undefined }), "check_payment", { payment: {} })).content as J[])[0]!.text).toContain("no checker configured");
    expect(((await call(tools({ bankUrl: "http://127.0.0.1:9" }), "check_payment", { payment: {} })).content as J[])[0]!.text).toContain("unreachable");
    expect(((await call(tools({ mandate: undefined }), "mandate_scope", {})).content as J[])[0]!.text).toContain("no mandate loaded");
    expect(((await call(tools({ agentKey: undefined }), "attach_mandate", { payment_id: "x", amount: "1.00", payee: PAYEE })).content as J[])[0]!.text).toContain("--agent-key");
    expect(((await handle(tools(), { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "pay_all" } }))!.error as J).code).toBe(-32602);
  });

  it("serves newline-delimited JSON-RPC", async () => {
    const lines: string[] = [];
    await serveLines(tools(), Readable.from(['{"jsonrpc":"2.0","id":1,"method":"ping"}\n', "\n", "not json\n",
      '{"jsonrpc":"2.0","id":2,"id":3,"method":"ping"}\n']), (l) => lines.push(l));
    const out = lines.map((l) => JSON.parse(l) as J);
    expect(out[0]!.result).toEqual({});
    expect((out[1]!.error as J).code).toBe(-32700);
    expect(((out[2]!.error as J).message as string)).toContain("duplicate");
    expect(() => parseArgs(["--nope", "x"])).toThrow("usage");
    expect(TOOLS.every((t) => (t.inputSchema as J).additionalProperties === false)).toBe(true);
  });

  const BIN = fileURLToPath(new URL("../dist/mandate-mcp.js", import.meta.url));
  it.skipIf(!existsSync(BIN))("runs as a process (what npx starts)", () => {
    const input = [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "attach_mandate", arguments: { payment_id: "INV-P", amount: "100.00", payee: PAYEE } } },
    ].map((x) => JSON.stringify(x)).join("\n") + "\n";
    const r = spawnSync(process.execPath, [BIN, "--mandate", join(dir, "mandate.json"), "--agent-key", join(dir, "agent.pem")],
      { input, encoding: "utf8", timeout: 30000 });
    const out = r.stdout.trim().split("\n").map((l) => JSON.parse(l) as J);
    expect(((out[0]!.result as J).serverInfo as J).name).toBe("gleipnir-mandate");
    expect((((out[1]!.result as J).structuredContent as J).payment as J).id).toBe("INV-P");
    const bad = spawnSync(process.execPath, [BIN, "--what"], { encoding: "utf8", timeout: 30000 });
    expect(bad.status).toBe(2);
  });

  it("decisions from the local demo checker verify", async () => {
    const t = tools();
    const p = (await call(t, "attach_mandate", { payment_id: "INV-V", amount: "10.00", payee: PAYEE })).structuredContent as J;
    const r = (await call(t, "check_payment", p)).structuredContent as J;
    const bank = publicKeyOf(seedFromPem(readFileSync(join(dir, "bank.pem"), "utf8")));
    expect(verifyDecision(r.decision, [bank])).toBe(true);
  });
});


describe("0.5: the agent sees a new-payee escalation, and gets no new power", () => {
  it("escalates a new payee, blocks a changed account, and pays an approved payee only with the operator's approval", async () => {
    const signer = seedFromPem(readFileSync(join(dir, "signer.pem"), "utf8"));
    const agent = seedFromPem(readFileSync(join(dir, "agent.pem"), "utf8"));
    const m = signMandate(issue({
      id: "m_ap5", company: { name: "Nordhafen Logistik GmbH", country: "AT" },
      agent: { id: "ap-agent", public_key: publicKeyOf(agent) },
      signer: { id: "kberger@nordhafen.at", public_key: publicKeyOf(signer) },
      scope: { rails: ["sepa"], currency: "EUR", max_per_payment: "25000.00", unlisted_payees: "escalate",
        payees: [{ name: "Brenner Stahl AG", account: { scheme: "iban", iban: IBAN } }], from_accounts: [DEBTOR] },
      validUntil: "2099-01-01T00:00:00.000Z",
    }), signer);
    expect(m.v).toBe("gleipnir/mandate/0.5");
    writeFileSync(join(dir, "mandate5.json"), JSON.stringify(m));
    const kranbau = { name: "Kranbau Wels GmbH", account: { scheme: "iban", iban: "AT131100000622300000" } };
    const a = signPayeeApproval(approvePayee(m, { payee: kranbau, id: "pa_1" }), signer,
      { id: "kberger@nordhafen.at", public_key: publicKeyOf(signer) });
    writeFileSync(join(dir, "pa.json"), JSON.stringify(a));
    const t = tools({ mandate: join(dir, "mandate5.json") });
    const scope = (await call(t, "mandate_scope", {})).structuredContent as J;
    expect([scope.unlisted_payee, scope.approved_payees]).toEqual(["waits for a person to approve it (new_payee)", []]);
    const results: J[] = [];
    for (const [pid, payee] of [["INV-1", "Kranbau Wels GmbH=AT131100000622300000"], ["INV-2", "Brenner-Stahl AG=LT121000011101001000"]]) {
      const p = (await call(t, "attach_mandate", { payment_id: pid, amount: "100.00", payee })).structuredContent as J;
      results.push((await call(t, "check_payment", p)).structuredContent as J);
    }
    expect(results.map((r) => [r.outcome, r.reasons, r.new_payee])).toEqual([
      ["escalate", ["new_payee"], true], ["block", ["payee_account_changed"], false]]);
    expect(results[0]!.advice).toContain("waits for a person");
    expect(results[1]!.advice).toContain("changed bank details");
    const withApproval = tools({ mandate: join(dir, "mandate5.json"), payeeApprovals: [join(dir, "pa.json")] });
    expect(((await call(withApproval, "mandate_scope", {})).structuredContent as J).approved_payees).toEqual([kranbau]);
    const p = (await call(withApproval, "attach_mandate", { payment_id: "INV-3", amount: "100.00",
      payee: "Kranbau Wels GmbH=AT131100000622300000" })).structuredContent as J;
    const r = (await call(withApproval, "check_payment", p)).structuredContent as J;
    expect([r.outcome, ((r.decision as J).payee_approval as J).id]).toEqual(["allow", "pa_1"]);
    expect(TOOLS.map((x) => x.name)).toEqual(["mandate_scope", "request_mandate", "attach_mandate", "check_payment"]);
    expect(parseArgs(["--payee-approval", "a.json", "--payee-approval", "b.json"]).payeeApprovals).toEqual(["a.json", "b.json"]);
    expect(adviceFor("allow", ["new_payee"])).toBe("Covered. Submit this exact payment with the mandate.");
  });
});

describe("second audit: the MCP KYB loader fails closed (F10)", () => {
  it.each([{ may_sign: null }, { joint: "2" }])("%j", async (bad) => {
    const signer = seedFromPem(readFileSync(join(dir, "signer.pem"), "utf8"));
    const path = join(dir, `kyb-${JSON.stringify(bad).replace(/\W/g, "")}.json`);
    writeFileSync(path, JSON.stringify({ source: "bank_kyb", signers: [{ company: "Nordhafen Logistik GmbH",
      signer: "kberger@nordhafen.at", keys: [publicKeyOf(signer)], may_sign: true, ...bad }],
    accounts: [{ company: "Nordhafen Logistik GmbH", account: DEBTOR }] }));
    const t = tools({ authority: path });
    const p = (await call(t, "attach_mandate", { payment_id: `INV-${path.length}`, amount: "1.00", payee: PAYEE })).structuredContent as J;
    expect(((await call(t, "check_payment", p)).structuredContent as J).reasons).toEqual(["checker_unavailable"]);
  });
});
