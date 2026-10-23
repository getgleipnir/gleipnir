#!/usr/bin/env node
/**
 * gleipnir-mandate-mcp: an MCP server (stdio) for AI agents that pay under a Gleipnir mandate.
 * Same tools and behaviour as the Python `gleipnir mandate mcp`:
 *
 * - mandate_scope: what the agent may pay under the loaded mandate.
 * - request_mandate: an unsigned draft for a person to review and sign (the agent never signs a mandate).
 * - attach_mandate: a payment under the mandate, signed with the agent key.
 * - check_payment: ask the bank's checker (--bank-url) whether a payment is covered; a local demo checker
 *   answers with --bank-key and --authority instead.
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
  attach,
  issue,
  mandateHash,
  mandateProblem,
  parseStrict,
  paymentProblem,
  publicKeyOf,
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
    description: "What you may pay under the loaded mandate: company, payees (name and account), limits, rails, "
      + "validity, who signed. Read this before paying; anything outside it will be refused.",
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
      payees: { type: "array", items: { type: "string", description: "NAME=IBAN" } },
      valid_until: { type: "string", description: "RFC 3339 UTC" }, purpose: { type: "string" },
    }, ["company", "country", "signer_id", "signer_public_key", "currency", "max_per_payment", "payees", "valid_until"]),
    annotations: { title: "Ask a person for a mandate", readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  },
  {
    name: "attach_mandate",
    description: "Build a payment under the loaded mandate, signed with your agent key. Submit the result "
      + "to the bank together with the mandate. Check it first with check_payment.",
    inputSchema: schema({
      payment_id: { type: "string", description: "unique per payer, e.g. the invoice number" },
      amount: { type: "string", description: "e.g. 18400.00" },
      payee: { type: "string", description: "NAME=IBAN, exactly as on the invoice" },
      reference: { type: "string" }, rail: { type: "string" },
    }, ["payment_id", "amount", "payee"]),
    annotations: { title: "Prepare a payment", readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "check_payment",
    description: "Submit a payment built by attach_mandate to the bank's check. This is the real check, not a "
      + "dry run: an allowed payment is recorded under its id and counts against the limits, so "
      + "call it only for a payment you intend to make. Returns allow, block or escalate with a "
      + "reason. Never pay on block; on escalate, ask a person. To retry, resubmit the same payment.",
    inputSchema: schema({ payment: { type: "object" } }, ["payment"]),
    annotations: { title: "Ask the bank", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
];

const isObj = (x: unknown): x is J => typeof x === "object" && x !== null && !Array.isArray(x);

/** Check tool arguments against the tool's schema: required keys, no extra keys, types. */
export function argumentsProblem(spec: J, args: unknown): string | null {
  if (!isObj(args)) return "arguments must be an object";
  const props = spec.properties as Record<string, J>;
  const missing = (spec.required as string[]).filter((k) => !(k in args));
  if (missing.length) return `missing arguments: ${JSON.stringify(missing)}`;
  const extra = Object.keys(args).filter((k) => !(k in props)).sort();
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

export function parsePayee(text: string): J {
  const i = text.lastIndexOf("=");
  const name = text.slice(0, i).trim(), iban = text.slice(i + 1).trim();
  if (i < 0 || !name || !iban) throw new ToolError(`payee must be NAME=IBAN, got ${JSON.stringify(text)}`);
  return { name, account: { iban } };
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
}

function loadAuthority(path: string) {
  const doc = readJson(path) as J;
  const rows = (doc.signers ?? []) as J[];
  return (company: J, personId: string): AuthorityResult | null => {
    const r = rows.find((x) => x.company === company.name && x.signer === personId);
    // Pass the values through as they are: the Checker refuses odd ones (fail closed), never coerces them.
    return r ? { source: String(doc.source ?? "bank_kyb"), keys: r.keys as string[],
      maySign: (r.may_sign === undefined ? true : r.may_sign) as boolean,
      joint: (r.joint === undefined ? 1 : r.joint) as number } : null;
  };
}

export class MandateTools {
  private readonly agentSeed: Seed | null;
  private readonly local: Checker | null;

  constructor(private readonly o: Options) {
    this.agentSeed = o.agentKey ? seedFromPem(readFileSync(o.agentKey, "utf8")) : null;
    this.local = !o.bankUrl && o.bankKey && o.authority
      ? new Checker({ id: "bank:local-demo", seed: seedFromPem(readFileSync(o.bankKey, "utf8")),
        authority: loadAuthority(o.authority), ledger: new InMemoryLedger() })
      : null;
  }

  get hasMandate(): boolean {
    return Boolean(this.o.mandate);
  }

  mandate(): J {
    if (!this.o.mandate) throw new ToolError("no mandate loaded: start the server with --mandate, or use request_mandate first");
    return readJson(this.o.mandate) as J;
  }

  mandate_scope(): J {
    const m = this.mandate();
    const sc = (m.scope ?? {}) as J;
    const signedBy = isObj(m.signer) ? [m.signer.id] : ((m.sigs ?? []) as J[]).map((s) => s.signer);
    return {
      mandate: m.id, company: (m.company as J | undefined)?.name, agent: (m.agent as J | undefined)?.id,
      currency: sc.currency, max_per_payment: sc.max_per_payment, max_per_period: sc.max_per_period ?? null,
      rails: sc.rails ?? "any", payees: sc.payees ?? "any payee", valid_from: m.valid_from ?? null,
      valid_until: m.valid_until, signed_by: signedBy,
      delegation: ((m.delegation ?? []) as J[]).map((d) => `${(d.from as J).id} -> ${(d.to as J).id}`),
      problem: mandateProblem(m),
    };
  }

  request_mandate(a: J): J {
    const scope: J = { rails: ["sepa", "sepa_instant"], currency: a.currency, max_per_payment: a.max_per_payment,
      payees: (a.payees as string[]).map(parsePayee) };
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
    const p = attach(m, { id: a.payment_id as string, rail: (a.rail as string | undefined) || rails[0] || "sepa",
      amount: a.amount as string, currency: sc.currency as string, payee: parsePayee(a.payee as string),
      reference: (a.reference as string | undefined) ?? "", agentSeed: this.agentSeed ?? undefined });
    const problem = paymentProblem(p);
    if (problem) throw new ToolError(`payment rejected: ${problem}`);
    return { payment: p };
  }

  async check_payment(a: J): Promise<J> {
    const m = this.mandate();
    let decision: J;
    if (this.o.bankUrl) {
      let resp: Response;
      try {
        resp = await fetch(this.o.bankUrl.replace(/\/+$/, "") + "/check", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mandate: m, payment: a.payment }), signal: AbortSignal.timeout(10000),
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
      decision = await this.local.check(m, a.payment);
    } else {
      throw new ToolError("no checker configured: start the server with --bank-url (or --bank-key and --authority)");
    }
    const advice: Record<string, string> = {
      allow: "Covered. Submit this exact payment with the mandate.",
      block: "Not covered. Do not pay. Tell the person why.",
      escalate: "Needs a person before it can be paid. Do not retry with a new id.",
    };
    const outcome = decision.outcome as string;
    return { outcome, reasons: decision.reasons ?? [], advice: advice[outcome] ?? "Unknown answer. Do not pay.", decision };
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
        serverInfo: { name: "gleipnir-mandate", version: "0.2" },
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
    const k = keys[argv[i]!];
    if (!k || argv[i + 1] === undefined) throw new Error(`usage: gleipnir-mandate-mcp [${Object.keys(keys).join(" X] [")} X]`);
    o[k] = argv[++i]!;
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
