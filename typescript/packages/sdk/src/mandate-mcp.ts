#!/usr/bin/env node
/**
 * gleipnir-mandate-mcp: an MCP server (stdio) for AI agents that pay under a Gleipnir mandate.
 * Same tools and behaviour as the Python `gleipnir mandate mcp`:
 *
 * - mandate_scope: what the agent may pay under the loaded mandate.
 * - request_mandate: an unsigned draft for a person to review and sign (the agent never signs a mandate).
 * - attach_mandate: a payment under the mandate, signed with the agent key.
 * - check_payment: ask the bank's checker (--bank-url) whether a payment is covered; a local demo checker
 *   answers with --bank-key and --authority instead. Payee approvals the operator configured (--payee-approval,
 *   0.5 mandates) for that payee account go with it. The answer says when a payment waits for a person because the
 *   payee is new (new_payee) and when it is blocked as changed bank details; the agent gets no new power.
 *
 *   npx -p @getgleipnir/sdk gleipnir-mandate-mcp --mandate mandate.json --agent-key agent.pem --bank-url http://127.0.0.1:8787
 */

import { createPrivateKey, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import {
  Checker,
  InMemoryLedger,
  MANDATE_VERSION,
  MANDATE_VERSION_05,
  MAX_APPROVALS,
  SCHEMES,
  account,
  attach,
  issue,
  mandateHash,
  mandateProblem,
  parseStrict,
  payeeApprovalProblem,
  paymentProblem,
  publicKeyOf,
  versionOf,
  type AuthorityResult,
  type Seed,
} from "@getgleipnir/verify/mandate";

type J = Record<string, unknown>;

export const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];
export const RESOURCE_URI = "gleipnir://mandate/current";

class ToolError extends Error {}

const schema = (props: Record<string, J>, required: string[]): J => ({
  type: "object", properties: props, required, additionalProperties: false,
});

export const TOOLS: J[] = [
  {
    name: "mandate_scope",
    description: "What you may pay under the loaded mandate: company, payees (name and account) and payees "
      + "approved since, what happens to a payee that is not listed (blocked, or it waits for a person), "
      + "limits, rails, validity, who signed. Read this before paying; anything outside it will be "
      + "refused.",
    inputSchema: schema({}, []),
    annotations: { title: "What may I pay?", readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "request_mandate",
    description: "Draft an unsigned mandate for a company signatory to review and sign in their bank's app. "
      + "You cannot sign it yourself; until a person signs, you cannot pay under it.",
    inputSchema: schema({
      company: { type: "string" }, country: { type: "string", description: "ISO 3166 code" },
      signer_id: { type: "string", description: "the signatory who will sign, as the bank knows them" },
      signer_public_key: { type: "string" },
      currency: { type: "string" }, max_per_payment: { type: "string", description: "e.g. 25000.00" },
      max_per_month: { type: "string" },
      payees: { type: "array", items: { type: "string", description: "NAME=ACCOUNT" } },
      from_accounts: { type: "array", items: { type: "string" },
        description: "the company's accounts to pay from: IBAN, or SCHEME:FIELD/FIELD" },
      valid_until: { type: "string", description: "RFC 3339 UTC" }, purpose: { type: "string" },
    }, ["company", "country", "signer_id", "signer_public_key", "currency", "max_per_payment", "payees", "from_accounts",
      "valid_until"]),
    annotations: { title: "Ask a person for a mandate", readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  },
  {
    name: "attach_mandate",
    description: "Build a payment under the loaded mandate, from one of its accounts, signed with your agent key. Submit the result "
      + "to the bank together with the mandate. Check it first with check_payment.",
    inputSchema: schema({
      payment_id: { type: "string", description: "unique per payer, e.g. the invoice number" },
      amount: { type: "string", description: "e.g. 18400.00" },
      payee: { type: "string", description: "NAME=ACCOUNT exactly as on the invoice: an IBAN, or SCHEME:FIELD/FIELD "
        + "(us_aba:ROUTING/ACCOUNT, uk_sort_code:SORT_CODE/ACCOUNT, ...)" },
      from_account: { type: "string", description: "which mandate account to pay from (default: the only one)" },
      reference: { type: "string" }, rail: { type: "string" },
    }, ["payment_id", "amount", "payee"]),
    annotations: { title: "Prepare a payment", readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "check_payment",
    description: "Submit a payment built by attach_mandate to the bank's check. This is the real check, not a "
      + "dry run: an allowed payment is recorded under its id and counts against the limits, so "
      + "call it only for a payment you intend to make. Returns allow, block or escalate with a "
      + "reason. Never pay on block; on escalate, ask a person (they sign an override at the bank). "
      + "new_payee means the payee is not on the mandate and waits for a person; "
      + "payee_account_changed means a listed payee's name with another account (changed bank details): "
      + "never pay, tell a person. To retry, resubmit the same payment; after a block you may correct it "
      + "and reuse the id.",
    inputSchema: schema({ payment: { type: "object" } }, ["payment"]),
    annotations: { title: "Ask the bank", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
];

const isObj = (x: unknown): x is J => typeof x === "object" && x !== null && !Array.isArray(x);

/** Check tool arguments against the tool's schema: required keys, no extra keys, types. */
export function argumentsProblem(spec: J, args: unknown): string | null {
  if (!isObj(args)) return "arguments must be an object";
  const props = spec.properties as Record<string, J>;
  const own = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
  const missing = (spec.required as string[]).filter((k) => !own(args, k));
  if (missing.length) return `missing arguments: ${JSON.stringify(missing)}`;
  const extra = Object.keys(args).filter((k) => !own(props, k)).sort();
  if (extra.length) return `unknown arguments: ${JSON.stringify(extra)}`;
  for (const [k, v] of Object.entries(args)) {
    const type = props[k]!.type;
    const ok = type === "string" ? typeof v === "string" : type === "array" ? Array.isArray(v) : isObj(v);
    if (!ok) return `${k} must be a ${type}`;
    if (type === "array" && !(v as unknown[]).every((x) => typeof x === "string")) return `${k} must be a list of strings`;
    if (type === "string" && (v as string).length > 2000) return `${k} is too long`;
  }
  return null;
}

/** An IBAN ("AT61 1904 ..."), or SCHEME:FIELD/FIELD in the scheme's field order ("us_aba:021000021/1234"). */
export function parseAccount(text: string): J {
  const i = text.indexOf(":");
  const scheme = i < 0 ? "iban" : text.slice(0, i).trim().toLowerCase();
  const rest = i < 0 ? text : text.slice(i + 1);
  if (!Object.prototype.hasOwnProperty.call(SCHEMES, scheme)) {
    throw new ToolError(`unknown account scheme ${JSON.stringify(scheme)}: one of ${Object.keys(SCHEMES).join(", ")}`);
  }
  const names = Object.keys(SCHEMES[scheme]!);
  const parts = rest.split("/");
  if (parts.length !== names.length) {
    throw new ToolError(`a ${scheme} account is ${scheme}:${names.map((n) => n.toUpperCase()).join("/")}, got ${JSON.stringify(text)}`);
  }
  try {
    return account(scheme, Object.fromEntries(names.map((n, k) => [n, parts[k]!])));
  } catch (e) {
    throw new ToolError(`bad account ${JSON.stringify(text)}: ${(e as Error).message}`);
  }
}

export function parsePayee(text: string): J {
  const i = text.lastIndexOf("=");
  const name = text.slice(0, i).trim(), acc = text.slice(i + 1).trim();
  if (i < 0 || !name || !acc) throw new ToolError(`payee must be NAME=ACCOUNT, got ${JSON.stringify(text)}`);
  return { name, account: parseAccount(acc) };
}

/** The 32-byte seed of an Ed25519 private key PEM (as written by `gleipnir mandate keygen`). */
export function seedFromPem(pem: string): Seed {
  const jwk = createPrivateKey(pem).export({ format: "jwk" });
  if (jwk.crv !== "Ed25519" || typeof jwk.d !== "string") throw new ToolError("not an Ed25519 private key");
  return new Uint8Array(Buffer.from(jwk.d, "base64url"));
}

function readJson(path: string): unknown {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new ToolError(`cannot read ${path}: ${(e as Error).message}`);
  }
  try {
    return parseStrict(text);
  } catch (e) {
    throw new ToolError(`${path} is not valid JSON: ${(e as Error).message}`);
  }
}

export interface Options {
  mandate?: string;
  agentKey?: string;
  bankUrl?: string;
  bankKey?: string;
  authority?: string;
  drafts?: string;
  /** Signed payee approvals to present with payments to those payees (0.5 mandates); set by the operator. */
  payeeApprovals?: string[];
}

const ADVICE: Record<string, string> = {
  allow: "Covered. Submit this exact payment with the mandate.",
  block: "Not covered. Do not pay. Tell the person why.",
  escalate: "Needs a person before it can be paid. Do not retry with a new id.",
};
const REASON_ADVICE: Record<string, string> = {
  new_payee: "This payee is not on the mandate. The payment waits for a person: a signatory approves it at the "
    + "bank (an override), or approves the payee for later payments. Do not change the payee, the "
    + "account or the payment id to get around this; ask the person and wait.",
  payee_account_changed: "The payee's name is on the mandate, but this account is not: this looks like changed "
    + "bank details, the most common invoice fraud. Do not pay and do not retry with "
    + "another name. Tell a person; only a signatory can approve the new account, after "
    + "confirming it with the payee by phone.",
  over_unlisted_payee_limit: "Too large for a payee that is not on the mandate. Do not pay and do not split it. "
    + "Tell a person.",
  payee_approval_invalid: "A payee approval presented with this payment is not valid. Do not pay. Tell a person.",
};

/** What the agent should do with a decision; never more than the decision allows. */
export function adviceFor(outcome: unknown, reasons: unknown): string {
  const r = Array.isArray(reasons) ? reasons : [];
  if ((outcome === "block" || outcome === "escalate") && r.length === 1 && typeof r[0] === "string"
    && Object.prototype.hasOwnProperty.call(REASON_ADVICE, r[0])) return REASON_ADVICE[r[0]]!;
  return typeof outcome === "string" && Object.prototype.hasOwnProperty.call(ADVICE, outcome) ? ADVICE[outcome]!
    : "Unknown answer. Do not pay.";
}

function loadHolds(path: string) {
  const doc = readJson(path) as J;
  const rows = (doc.accounts ?? []) as J[];
  const key = (v: unknown) => JSON.stringify(v, Object.keys((v ?? {}) as J).sort());
  return (company: J, acc: J): string | null => {
    const r = rows.find((x) => x.company === company.name && key(x.account) === key(acc));
    return r ? String(r.customer ?? r.company) : null;
  };
}

function loadAuthority(path: string) {
  const doc = readJson(path) as J;
  const rows = (doc.signers ?? []) as J[];
  return (company: J, personId: string): AuthorityResult | null => {
    const r = rows.find((x) => x.company === company.name && x.signer === personId);
    // Pass the values through as they are: the Checker refuses odd ones (fail closed), never coerces them.
    return r ? { source: String(doc.source ?? "bank_kyb"), keys: r.keys as string[],
      maySign: (r.may_sign === undefined ? true : r.may_sign) as boolean,
      joint: (r.joint === undefined ? 1 : r.joint) as number,
      retired: (r.retired === undefined ? {} : r.retired) as Record<string, string> } : null;
  };
}

export class MandateTools {
  private readonly agentSeed: Seed | null;
  private readonly local: Checker | null;

  constructor(private readonly o: Options) {
    this.agentSeed = o.agentKey ? seedFromPem(readFileSync(o.agentKey, "utf8")) : null;
    this.local = !o.bankUrl && o.bankKey && o.authority
      ? new Checker({ id: "bank:local-demo", seed: seedFromPem(readFileSync(o.bankKey, "utf8")),
        authority: loadAuthority(o.authority), holds: loadHolds(o.authority), ledger: new InMemoryLedger() })
      : null;
  }

  get hasMandate(): boolean {
    return Boolean(this.o.mandate);
  }

  mandate(): J {
    if (!this.o.mandate) throw new ToolError("no mandate loaded: start the server with --mandate, or use request_mandate first");
    return readJson(this.o.mandate) as J;
  }

  /** The operator's payee approvals that name this mandate (signed by people; the bank verifies them per payment). */
  approvals(m: J): J[] {
    const out: J[] = [];
    let mh: string;
    try {
      mh = mandateHash(m);
    } catch {
      return out;
    }
    for (const path of this.o.payeeApprovals ?? []) {
      const a = readJson(path);
      if (payeeApprovalProblem(a) === null && JSON.stringify((a as J).mandate) === JSON.stringify({ id: m.id, hash: mh })) out.push(a as J);
    }
    return out;
  }

  mandate_scope(): J {
    const m = this.mandate();
    const sc = (m.scope ?? {}) as J;
    const signedBy = isObj(m.signer) ? [m.signer.id] : ((m.sigs ?? []) as J[]).map((s) => s.signer);
    const controlled = "payees" in sc || "unlisted_payees" in sc;
    const policy = controlled ? (sc.unlisted_payees ?? "block") : "";
    const unlisted = policy === "block" ? "blocked: only listed and approved payees can be paid"
      : policy === "escalate" ? "waits for a person to approve it (new_payee)" : "allowed (no payee list)";
    const approved = versionOf(m, "mandate") === MANDATE_VERSION_05 ? this.approvals(m).map((a) => a.payee) : [];
    return {
      mandate: m.id, company: (m.company as J | undefined)?.name, agent: (m.agent as J | undefined)?.id,
      currency: sc.currency, max_per_payment: sc.max_per_payment, max_per_period: sc.max_per_period ?? null,
      rails: sc.rails ?? "any", payees: sc.payees ?? (controlled ? [] : "any payee"), approved_payees: approved,
      unlisted_payee: unlisted, max_per_unlisted_payee: sc.max_per_unlisted_payee ?? null,
      from_accounts: sc.from_accounts ?? null,
      valid_from: m.valid_from ?? null,
      valid_until: m.valid_until, signed_by: signedBy,
      delegation: ((m.delegation ?? []) as J[]).map((d) => `${(d.from as J).id} -> ${(d.to as J).id}`),
      problem: mandateProblem(m),
    };
  }

  request_mandate(a: J): J {
    const scope: J = { rails: ["sepa", "sepa_instant"], currency: a.currency, max_per_payment: a.max_per_payment,
      payees: (a.payees as string[]).map(parsePayee), from_accounts: (a.from_accounts as string[]).map(parseAccount) };
    if (a.max_per_month) scope.max_per_period = { amount: a.max_per_month, period: "P1M" };
    if (a.purpose) scope.purpose = a.purpose;
    const agent: J = { id: "agent" };
    if (this.agentSeed) agent.public_key = publicKeyOf(this.agentSeed);
    let draft: J;
    try {
      draft = issue({ id: "m_" + randomBytes(8).toString("hex"), company: { name: a.company, country: a.country }, agent,
        signer: { id: a.signer_id, public_key: a.signer_public_key }, scope, validUntil: a.valid_until as string });
    } catch (e) {
      throw new ToolError(`mandate rejected: ${(e as Error).message}`);
    }
    const dir = this.o.drafts ?? "mandate-drafts";
    mkdirSync(dir, { recursive: true });
    const path = join(dir, `${draft.id as string}.json`);
    writeFileSync(path, JSON.stringify(draft, null, 2) + "\n");
    return { status: "awaiting_signature", draft: path, mandate_hash: mandateHash(draft),
      next: "A signatory reviews and signs it (bank app, passkey, or `gleipnir mandate sign`). You cannot pay under it until then." };
  }

  attach_mandate(a: J): J {
    const m = this.mandate();
    if (!this.agentSeed && isObj(m.agent) && "public_key" in m.agent) {
      throw new ToolError("the mandate requires an agent signature: start the server with --agent-key");
    }
    const sc = m.scope;
    if (!isObj(sc)) throw new ToolError("cannot use the loaded mandate: no scope");
    const rails = Array.isArray(sc.rails) ? (sc.rails as string[]) : [];
    let p: J;
    try {
      p = attach(m, { id: a.payment_id as string, rail: (a.rail as string | undefined) || rails[0] || "sepa",
        amount: a.amount as string, currency: sc.currency as string, payee: parsePayee(a.payee as string),
        fromAccount: a.from_account ? parseAccount(a.from_account as string) : undefined,
        reference: (a.reference as string | undefined) ?? "", agentSeed: this.agentSeed ?? undefined });
    } catch (e) {
      if (e instanceof ToolError) throw e;
      throw new ToolError(`cannot use the loaded mandate: ${(e as Error).message}`);
    }
    const problem = paymentProblem(p);
    if (problem) throw new ToolError(`payment rejected: ${problem}`);
    return { payment: p };
  }

  async check_payment(a: J): Promise<J> {
    const m = this.mandate();
    let approvals: J[] | undefined;
    if ((this.o.payeeApprovals ?? []).length && versionOf(m, "mandate") === MANDATE_VERSION_05 && isObj(a.payment)) {
      const payee = a.payment.payee;
      const acc = isObj(payee) ? JSON.stringify(payee.account, Object.keys((payee.account ?? {}) as J).sort()) : null;
      approvals = this.approvals(m).filter((x) => {
        const xa = (x.payee as J).account as J;
        return JSON.stringify(xa, Object.keys(xa).sort()) === acc;
      }).slice(0, MAX_APPROVALS);
    }
    let decision: J;
    if (this.o.bankUrl) {
      let resp: Response;
      const body: J = { mandate: m, payment: a.payment };
      if (approvals && approvals.length) body.payee_approvals = approvals;
      try {
        resp = await fetch(this.o.bankUrl.replace(/\/+$/, "") + "/check", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body), signal: AbortSignal.timeout(10000),
        });
      } catch (e) {
        throw new ToolError(`bank checker unreachable: ${(e as Error).message}`);
      }
      try {
        decision = parseStrict(await resp.text()) as J;
      } catch (e) {
        throw new ToolError(`bank response is not valid JSON: ${(e as Error).message}`);
      }
    } else if (this.local) {
      decision = await this.local.check(m, a.payment, approvals);
    } else {
      throw new ToolError("no checker configured: start the server with --bank-url (or --bank-key and --authority)");
    }
    const outcome = decision.outcome as string;
    const reasons = Array.isArray(decision.reasons) ? decision.reasons : [];
    return { outcome, reasons, new_payee: reasons.length === 1 && reasons[0] === "new_payee",
      advice: adviceFor(outcome, reasons), decision };
  }
}

const result = (id: unknown, r: unknown): J => ({ jsonrpc: "2.0", id, result: r });
const error = (id: unknown, code: number, message: string): J => ({ jsonrpc: "2.0", id, error: { code, message } });

/** One JSON-RPC message in, one response out (null for notifications). */
export async function handle(tools: MandateTools, msg: unknown): Promise<J | null> {
  if (!isObj(msg) || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    return error(isObj(msg) ? msg.id ?? null : null, -32600, "invalid request");
  }
  if (!("id" in msg)) return null;
  const { id, method } = msg;
  const params = isObj(msg.params) ? msg.params : {};
  switch (method) {
    case "initialize": {
      const asked = params.protocolVersion;
      return result(id, {
        protocolVersion: typeof asked === "string" && PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
        capabilities: { tools: {}, resources: {} },
        serverInfo: { name: "gleipnir-mandate", version: MANDATE_VERSION },
        instructions: "Pay only under a mandate a person signed. Check every payment with check_payment first; never pay on block.",
      });
    }
    case "ping":
      return result(id, {});
    case "tools/list":
      return result(id, { tools: TOOLS });
    case "resources/list":
      return result(id, { resources: tools.hasMandate ? [{ uri: RESOURCE_URI, name: "Current mandate",
        description: "The signed mandate this agent pays under", mimeType: "application/json" }] : [] });
    case "resources/read": {
      if (params.uri !== RESOURCE_URI || !tools.hasMandate) return error(id, -32002, "resource not found");
      try {
        return result(id, { contents: [{ uri: RESOURCE_URI, mimeType: "application/json", text: JSON.stringify(tools.mandate(), null, 2) }] });
      } catch (e) {
        return error(id, -32603, (e as Error).message);
      }
    }
    case "tools/call": {
      const name = params.name;
      const spec = TOOLS.find((t) => t.name === name);
      if (!spec || typeof name !== "string") return error(id, -32602, `unknown tool ${JSON.stringify(name)}`);
      const args = params.arguments === undefined || params.arguments === null ? {} : params.arguments;
      const bad = argumentsProblem(spec.inputSchema as J, args);
      if (bad) return result(id, { content: [{ type: "text", text: bad }], isError: true });
      try {
        const fn = (tools as unknown as Record<string, (a: J) => J | Promise<J>>)[name]!;
        const out = await fn.call(tools, args as J);
        return result(id, { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out, isError: false });
      } catch (e) {
        return result(id, { content: [{ type: "text", text: (e as Error).message }], isError: true });
      }
    }
    default:
      return error(id, -32601, `method not found: ${method}`);
  }
}

/** Serve newline-delimited JSON-RPC on the given streams (stdio by default). Resolves when input ends. */
export async function serveLines(tools: MandateTools, input: NodeJS.ReadableStream = process.stdin,
  write: (line: string) => void = (l) => process.stdout.write(l)): Promise<void> {
  const rl = createInterface({ input, crlfDelay: Infinity });
  for await (const raw of rl) {
    const line = raw.trim();
    if (!line) continue;
    let msg: unknown;
    try {
      msg = parseStrict(line);
    } catch (e) {
      write(JSON.stringify(error(null, -32700, (e as Error).message)) + "\n");
      continue;
    }
    const resp = await handle(tools, msg);
    if (resp) write(JSON.stringify(resp) + "\n");
  }
}

export function parseArgs(argv: string[]): Options {
  const o: Options = {};
  const keys: Record<string, keyof Options> = {
    "--mandate": "mandate", "--agent-key": "agentKey", "--bank-url": "bankUrl", "--bank-key": "bankKey",
    "--authority": "authority", "--drafts": "drafts",
  };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--payee-approval" && argv[i + 1] !== undefined) { // repeatable
      (o.payeeApprovals ??= []).push(argv[++i]!);
      continue;
    }
    const k = keys[argv[i]!];
    if (!k || argv[i + 1] === undefined) {
      throw new Error(`usage: gleipnir-mandate-mcp [${[...Object.keys(keys), "--payee-approval"].join(" X] [")} X]`);
    }
    (o as Record<string, unknown>)[k] = argv[++i]!;
  }
  return o;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    await serveLines(new MandateTools(parseArgs(process.argv.slice(2))));
  } catch (e) {
    process.stderr.write(`gleipnir-mandate-mcp: ${(e as Error).message}\n`);
    process.exit(2);
  }
}
