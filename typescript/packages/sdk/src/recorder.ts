/** Recorder: the public API for wrapping agent tool calls. */

import { AsyncLocalStorage } from "node:async_hooks";
import { join } from "node:path";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { actionDigest, bytesToHex, canonicalize } from "@getgleipnir/verify";
import { LocalFileAnchor, type Anchor } from "./anchor.js";
import { ChainWriter } from "./chain.js";
import { exportBundle, exportProof, type ExportOptions } from "./export.js";
import { loadOrCreateSecret, loadOrCreateSigner, type Signer } from "./keys.js";
import { JsonlStore, type Rec, type Store } from "./store.js";
import { iso, newId, setKey, toJsonable, utcnow, type Clock } from "./util.js";

const CONTEXT_KEYS = new Set(["trace_id", "span_id", "session", "on_behalf_of", "run_id", "parent_action", "tool_call_id"]);
const TOP_LEVEL_KEYS = ["model", "versions", "identity", "approval"] as const;

// ---- outcomes ------------------------------------------------------------------------------
export type OutcomeCheck = "match" | "mismatch" | "error" | "not_checked";

/**
 * Result of checking the external system after an action. `check` is `match`, `mismatch`,
 * `error` (the check itself failed) or `not_checked`.
 */
export class Outcome {
  constructor(
    readonly check: OutcomeCheck,
    readonly observed: unknown = null,
    readonly fields: string[] = [],
    readonly detail: string | null = null,
    readonly method = "verify_outcome",
  ) {}

  static match(observed: unknown = null, detail: string | null = null): Outcome {
    return new Outcome("match", observed, [], detail);
  }

  static mismatch(observed: unknown = null, fields: string[] = [], detail: string | null = null): Outcome {
    return new Outcome("mismatch", observed, fields, detail);
  }

  static notChecked(detail: string | null = null): Outcome {
    return new Outcome("not_checked", null, [], detail);
  }

  static error(detail: string): Outcome {
    return new Outcome("error", null, [], detail);
  }

  /** Compare expected and observed values field by field. */
  static compare(expected: Record<string, unknown>, observed: Record<string, unknown>): Outcome {
    const diff = Object.keys(expected)
      .filter((k) => !Object.prototype.hasOwnProperty.call(observed, k) || !jsonEqual(observed[k], expected[k]))
      .sort(codePoint);
    return diff.length ? new Outcome("mismatch", { ...observed }, diff) : new Outcome("match", { ...observed });
  }

  toRecord(): Rec {
    const d: Rec = { check: this.check, method: this.method };
    if (this.observed !== null && this.observed !== undefined) d["observed"] = toJsonable(this.observed);
    if (this.fields.length) d["fields"] = [...this.fields];
    if (this.detail) d["detail"] = this.detail;
    return d;
  }
}

function codePoint(a: string, b: string): number {
  const x = Array.from(a, (c) => c.codePointAt(0)!);
  const y = Array.from(b, (c) => c.codePointAt(0)!);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
  return x.length - y.length;
}

function jsonEqual(a: unknown, b: unknown): boolean {
  const x = toJsonable(a);
  const y = toJsonable(b);
  try {
    return bytesToHex(canonicalize(x)) === bytesToHex(canonicalize(y));
  } catch {
    return false;
  }
}

/** What a `verifyOutcome` callback receives about the action it checks. */
export interface Call {
  actionId: string;
  tool: string;
  system: string;
  args: Record<string, unknown>;
}

export type OutcomeValue = Outcome | boolean | null | undefined;
export type OutcomeFn<R = unknown> = (call: Call, result: R) => OutcomeValue | Promise<OutcomeValue>;

function coerceOutcome(value: unknown): Outcome {
  if (value instanceof Outcome) return value;
  if (value === true) return Outcome.match();
  if (value === false) return Outcome.mismatch();
  if (value === null || value === undefined) return new Outcome("not_checked");
  throw new TypeError("verifyOutcome must return Outcome, boolean, null or undefined");
}

function errorText(error: unknown): string {
  if (error instanceof Error) return `${error.name}: ${error.message}`.slice(0, 2000);
  return String(error).slice(0, 2000);
}

function isThenable(x: unknown): x is PromiseLike<unknown> {
  return x !== null && (typeof x === "object" || typeof x === "function") && typeof (x as { then?: unknown }).then === "function";
}

// ---- redaction -------------------------------------------------------------------------------
export type RedactionRule = "drop" | "hmac" | ((value: unknown) => unknown);
export type RedactSpec = readonly string[] | Record<string, RedactionRule> | null | undefined;

const DROP = Symbol("drop");

/** Applies field-level redaction before anything is hashed or stored. */
export class Redactor {
  readonly defaultRule: "drop" | "hmac";
  constructor(
    readonly hmacKey: Uint8Array | null,
    defaultRule: "drop" | "hmac" = "hmac",
  ) {
    this.defaultRule = hmacKey && hmacKey.length ? defaultRule : "drop";
  }

  rules(spec: RedactSpec): Map<string, RedactionRule> {
    if (!spec) return new Map();
    if (Array.isArray(spec)) return new Map(spec.map((name) => [name, this.defaultRule] as [string, RedactionRule]));
    return new Map(Object.entries(spec as Record<string, RedactionRule>));
  }

  apply(value: unknown, rules: Map<string, RedactionRule>, depth = 0): unknown {
    if (!rules.size || depth > 50) return value;
    if (Array.isArray(value)) return value.map((v) => this.apply(v, rules, depth + 1));
    if (value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
      const out: Rec = {};
      for (const [k, v] of Object.entries(value as Rec)) {
        if (rules.has(k)) {
          const red = this.redact(v, rules.get(k)!);
          setKey(out, k, red === DROP ? { redacted: "dropped" } : red);
        } else {
          setKey(out, k, this.apply(v, rules, depth + 1));
        }
      }
      return out;
    }
    return value;
  }

  private redact(value: unknown, rule: RedactionRule): unknown {
    if (typeof rule === "function") return toJsonable(rule(value));
    if (rule === "drop") return DROP;
    if (rule === "hmac") {
      if (!this.hmacKey || !this.hmacKey.length) return DROP;
      const digest = hmac(sha256, this.hmacKey, canonicalize(toJsonable(value)));
      return { redacted: "hmac-sha256:" + bytesToHex(digest) };
    }
    throw new Error(`unknown redaction rule ${JSON.stringify(rule)}`);
  }
}

// ---- recorder ----------------------------------------------------------------------------------
export interface ContextValues {
  trace_id?: string;
  span_id?: string;
  session?: string;
  run_id?: string;
  on_behalf_of?: string;
  parent_action?: string;
  /** The framework's or model's id for this tool call. */
  tool_call_id?: string;
  /** An approval id from {@link Recorder.approve}: the action must be exactly what was approved. */
  approval?: string;
  model?: Record<string, unknown>;
  versions?: Record<string, unknown>;
  identity?: Record<string, unknown>;
}

export interface RecorderOptions {
  agentId: string;
  agentVersion: string;
  /** Directory for keys, chains and the local anchor log (default ".gleipnir"). */
  home?: string;
  chain?: string;
  signer?: Signer;
  store?: Store;
  /** "local" (test anchor, default), an Anchor, a list of Anchors, or null. */
  anchor?: "local" | Anchor | Anchor[] | null;
  segmentMaxRecords?: number;
  heartbeatSeconds?: number;
  background?: boolean;
  clock?: Clock;
  redactionKey?: Uint8Array | null;
  defaultRedaction?: "drop" | "hmac";
  fsync?: boolean;
  quiet?: boolean;
  onWarning?: (message: string) => void;
}

export interface RecordActionOptions {
  tool: string;
  system: string;
  args: Record<string, unknown>;
  response?: unknown;
  error?: unknown;
  claim?: string | null;
  outcome?: Outcome | null;
  start?: Date;
  end?: Date;
  redact?: RedactSpec;
  actionId?: string;
  /** Documents or records the action relied on, e.g. [{type: "kb", id: "faq-7", version: "3"}]. */
  sources?: Array<Record<string, unknown>>;
  /** Outbound services called for this action, e.g. [{service: "provider-a", endpoint: "chat"}]. */
  calls?: Array<Record<string, unknown>>;
}

/** A tool wrapped with {@link Recorder.tool}: carries its name, system and redaction for {@link Recorder.approve}. */
export interface WrappedTool {
  readonly gleipnirTool: string;
  readonly gleipnirSystem: string;
  readonly gleipnirRedact: RedactSpec;
}

export interface ApproveOptions {
  /** Who approved, e.g. "ops:anna". */
  approver: string;
  /** The oversight rule that required the approval, e.g. "amount>100". */
  rule?: string;
  /** The tool's system; required when `tool` is a name rather than a wrapped tool. */
  system?: string;
  /** Redaction of the arguments (default: the wrapped tool's); must match how the action records them. */
  redact?: RedactSpec;
  reason?: string;
}

export interface ToolOptions<A extends unknown[], R> {
  system: string;
  /** Tool name (default: the function's name). */
  name?: string;
  /**
   * Names for positional parameters, so arguments are recorded as {name: value}. Without it a
   * call with a single plain-object argument records that object, and any other call records
   * {"args": [...]}.
   */
  params?: readonly string[];
  redact?: RedactSpec;
  verifyOutcome?: OutcomeFn<Awaited<R>>;
  claim?: (args: Record<string, unknown>, result: Awaited<R>) => string | null | undefined;
  /** @internal */
  _types?: A;
}

/**
 * Records agent tool calls as signed, chained, anchorable records.
 *
 * ```ts
 * const rec = new Recorder({ agentId: "support-agent", agentVersion: "3.2.4" });
 * const issueRefund = rec.tool(refund, { system: "payments-api", redact: ["card_number"], verifyOutcome: check });
 * ```
 */
export class Recorder {
  readonly agent: { id: string; version: string };
  readonly home: string;
  readonly clock: Clock;
  readonly redactor: Redactor;
  readonly chain: ChainWriter;
  readonly tools = new Map<string, { system: string; verifyOutcome: boolean; redact: boolean }>();
  readonly features = new Set<string>();
  private readonly ctx = new AsyncLocalStorage<ContextValues>();

  constructor(opts: RecorderOptions) {
    this.agent = { id: opts.agentId, version: opts.agentVersion };
    this.home = opts.home ?? ".gleipnir";
    this.clock = opts.clock ?? utcnow;
    const signer = opts.signer ?? loadOrCreateSigner(this.home, opts.quiet ?? false);
    const store = opts.store ?? new JsonlStore(join(this.home, "chains", opts.chain ?? "default"), opts.fsync ?? true);
    const anchor = this.resolveAnchor(opts.anchor === undefined ? "local" : opts.anchor);
    const key = opts.redactionKey === undefined ? loadOrCreateSecret(this.home, "redaction-hmac.key") : opts.redactionKey;
    this.redactor = new Redactor(key, opts.defaultRedaction ?? "hmac");
    this.chain = new ChainWriter(store, signer, {
      clock: this.clock,
      anchor,
      segmentMaxRecords: opts.segmentMaxRecords ?? 1000,
      heartbeatSeconds: opts.heartbeatSeconds ?? 600,
      background: opts.background ?? true,
      ...(opts.onWarning ? { onWarning: opts.onWarning } : {}),
    });
  }

  private resolveAnchor(anchor: RecorderOptions["anchor"]): Anchor | Anchor[] | null {
    if (anchor === "local") return new LocalFileAnchor(join(this.home, "anchors", "local-anchor-log.jsonl"), this.clock);
    if (typeof anchor === "string") {
      throw new Error(`unknown anchor ${JSON.stringify(anchor)}; use "local" or pass Anchor instances`);
    }
    return anchor ?? null;
  }

  // -- context ---------------------------------------------------------------------------
  /**
   * Run `fn` with context attached to every record made inside it (across awaits).
   *
   * Known keys: trace_id, span_id, session, run_id, on_behalf_of, parent_action, plus
   * model, versions (prompt/config/policy) and identity (principal, credential_id, scope).
   */
  context<T>(values: ContextValues, fn: () => T): T {
    const unknown = Object.keys(values).filter((k) => !CONTEXT_KEYS.has(k) && !(TOP_LEVEL_KEYS as readonly string[]).includes(k));
    if (unknown.length) throw new Error(`unknown context keys: ${JSON.stringify(unknown.sort())}`);
    const merged = { ...(this.ctx.getStore() ?? {}), ...values };
    return this.ctx.run(merged, fn);
  }

  private contextFields(): Rec {
    const ctx = (this.ctx.getStore() ?? {}) as Record<string, unknown>;
    const out: Rec = {};
    const plain: Rec = {};
    for (const [k, v] of Object.entries(ctx)) if (CONTEXT_KEYS.has(k)) plain[k] = v;
    if (Object.keys(plain).length) out["context"] = toJsonable(plain);
    for (const k of TOP_LEVEL_KEYS) {
      if (k in ctx) {
        out[k] = toJsonable(ctx[k]);
        this.features.add(k);
      }
    }
    return out;
  }

  // -- recording --------------------------------------------------------------------------
  /** Record one action. Use this directly when the `tool()` wrapper does not fit. */
  recordAction(o: RecordActionOptions): Rec {
    const rules = this.redactor.rules(o.redact);
    const now = this.clock();
    const fields: Rec = {
      id: o.actionId ?? newId("act"),
      agent: this.agent,
      tool: { name: o.tool, system: o.system },
      args: this.redactor.apply(toJsonable({ ...o.args }), rules),
      t: { start: iso(o.start ?? now), end: iso(o.end ?? now) },
    };
    if (o.error !== undefined && o.error !== null) {
      fields["response"] = { status: "error", error: errorText(o.error) };
    } else {
      fields["response"] = { status: "ok", body: this.redactor.apply(toJsonable(o.response), rules) };
    }
    if (o.claim) fields["claim"] = { text: o.claim };
    if (o.outcome) fields["outcome"] = o.outcome.toRecord();
    if (o.sources?.length) fields["sources"] = toJsonable(o.sources.map((x) => ({ ...x })));
    if (o.calls?.length) fields["calls"] = toJsonable(o.calls.map((x) => ({ ...x })));
    if (rules.size) fields["redaction"] = { fields: [...rules.keys()].sort(codePoint), default: this.redactor.defaultRule };
    Object.assign(fields, this.contextFields());
    return this.chain.append("action", fields);
  }

  /** Attach the agent's own statement about an action already recorded. */
  claim(actionId: string, text: string): Rec {
    return this.chain.append("claim", { claim: { action: actionId, text } });
  }

  /** Record a human review, approval, override or reversal of an action. */
  review(
    actionId: string,
    o: { reviewer: string; decision: string; rule?: string; beforeExecution?: boolean; reason?: string; changes?: Record<string, unknown> },
  ): Rec {
    const body: Rec = { action: actionId, reviewer: o.reviewer, decision: o.decision };
    if (o.rule !== undefined) body["rule"] = o.rule;
    if (o.beforeExecution !== undefined) body["before_execution"] = o.beforeExecution;
    if (o.reason) body["reason"] = o.reason;
    if (o.changes && Object.keys(o.changes).length) body["changes"] = toJsonable({ ...o.changes });
    return this.chain.append("review", { review: body });
  }

  /**
   * Record an approval of one specific action *before* it runs; returns the approval id.
   *
   * Run the action inside `rec.context({ approval: id }, () => ...)`. The verifier then checks
   * that the approval came first and that the action's tool, system and arguments are exactly
   * what was approved. `tool` is a function wrapped with `rec.tool(...)` or a tool name (then
   * pass `system`). `args` are the arguments as the action will record them (before redaction).
   */
  approve(tool: WrappedTool | ((...a: never[]) => unknown) | string, args: Record<string, unknown>, o: ApproveOptions): string {
    const meta = (typeof tool === "function" ? tool : null) as Partial<WrappedTool> | null;
    const name = typeof tool === "string" ? tool : meta?.gleipnirTool;
    const system = o.system || meta?.gleipnirSystem;
    if (typeof name !== "string" || !system) throw new Error("pass a rec.tool() function, or a tool name together with system");
    const rules = this.redactor.rules(o.redact !== undefined && o.redact !== null ? o.redact : meta?.gleipnirRedact);
    const digest = actionDigest(name, system, this.redactor.apply(toJsonable({ ...args }), rules));
    const body: Rec = { action_digest: digest, tool: name, system, reviewer: o.approver, decision: "approved", before_execution: true };
    if (o.rule) body["rule"] = o.rule;
    if (o.reason) body["reason"] = o.reason;
    return this.chain.append("review", { review: body })["id"] as string;
  }

  note(text: string, data: Record<string, unknown> = {}): Rec {
    return this.chain.append("note", { note: { text, ...(toJsonable(data) as Rec) } });
  }

  /**
   * Wrap a tool function so every call is recorded. Works for sync and async functions: the
   * wrapper returns what the function returns (a Promise for async functions), and errors are
   * recorded and re-thrown.
   */
  tool<A extends unknown[], R>(fn: (...args: A) => R, opts: ToolOptions<A, R>): (...args: A) => R {
    const toolName = opts.name ?? (fn.name || "tool");
    const system = opts.system;
    const verifyOutcome = opts.verifyOutcome;
    this.tools.set(toolName, { system, verifyOutcome: verifyOutcome !== undefined, redact: Boolean(opts.redact && Object.keys(opts.redact).length) });

    const bind = (a: unknown[]): Record<string, unknown> => {
      if (opts.params) {
        const out: Record<string, unknown> = {};
        opts.params.forEach((p, i) => {
          if (i < a.length) setKey(out, p, a[i]);
        });
        if (a.length > opts.params.length) out["args"] = a.slice(opts.params.length);
        return out;
      }
      const only = a[0];
      if (a.length === 1 && only !== null && typeof only === "object" && Object.getPrototypeOf(only) === Object.prototype) {
        return { ...(only as Record<string, unknown>) };
      }
      return { args: [...a] };
    };

    const finish = (actionId: string, args: Record<string, unknown>, start: Date, result: unknown, error: unknown, outcome: Outcome | null, end: Date) => {
      let claimText: string | null = null;
      if (opts.claim && error === undefined) {
        try {
          claimText = opts.claim(args, result as Awaited<R>) ?? null;
        } catch {
          claimText = null;
        }
      }
      this.recordAction({
        tool: toolName,
        system,
        args,
        response: result,
        error: error === undefined ? null : error,
        claim: claimText,
        outcome,
        start,
        end,
        redact: opts.redact,
        actionId,
      });
    };

    const call = (actionId: string, args: Record<string, unknown>): Call => ({ actionId, tool: toolName, system, args });

    const wrapper = (...a: A): R => {
      const args = bind(a);
      const start = this.clock();
      const actionId = newId("act");
      let result: R;
      try {
        result = fn(...a);
      } catch (exc) {
        finish(actionId, args, start, null, exc ?? new Error(String(exc)), null, this.clock());
        throw exc;
      }
      if (isThenable(result)) {
        return (async () => {
          let value: Awaited<R>;
          try {
            value = (await result) as Awaited<R>;
          } catch (exc) {
            finish(actionId, args, start, null, exc ?? new Error(String(exc)), null, this.clock());
            throw exc;
          }
          const end = this.clock();
          let outcome: Outcome | null = null;
          if (verifyOutcome) {
            try {
              outcome = coerceOutcome(await verifyOutcome(call(actionId, args), value));
            } catch (exc) {
              outcome = Outcome.error(errorText(exc));
            }
          }
          finish(actionId, args, start, value, undefined, outcome, end);
          return value;
        })() as R;
      }
      const end = this.clock();
      let outcome: Outcome | null = null;
      if (verifyOutcome) {
        try {
          const v = verifyOutcome(call(actionId, args), result as Awaited<R>);
          if (isThenable(v)) {
            (v as Promise<unknown>).catch(() => undefined);
            outcome = Outcome.error("verifyOutcome returned a Promise for a synchronous tool; make the tool async to await the check");
          } else outcome = coerceOutcome(v);
        } catch (exc) {
          outcome = Outcome.error(errorText(exc));
        }
      }
      finish(actionId, args, start, result, undefined, outcome, end);
      return result;
    };
    Object.defineProperty(wrapper, "name", { value: toolName });
    Object.defineProperty(wrapper, "gleipnirTool", { value: toolName });
    Object.defineProperty(wrapper, "gleipnirSystem", { value: system });
    Object.defineProperty(wrapper, "gleipnirRedact", { value: opts.redact ?? null });
    return wrapper;
  }

  // -- lifecycle ---------------------------------------------------------------------------
  /** Close the open segment, anchor what is pending, and write a verification bundle. */
  async export(out: string, opts: Omit<ExportOptions, "localAnchorLog"> = {}): Promise<string> {
    await this.flush();
    const local = this.chain.anchors.find((a): a is LocalFileAnchor => a instanceof LocalFileAnchor);
    return exportBundle(this.chain.store.readAll(), out, { ...opts, ...(local ? { localAnchorLog: local.path } : {}) });
  }

  /** Flush and write a single-action proof (record, segment, Merkle proof, anchors) to `out`. */
  async prove(actionId: string, out: string): Promise<string> {
    await this.flush();
    const local = this.chain.anchors.find((a): a is LocalFileAnchor => a instanceof LocalFileAnchor);
    return exportProof(this.chain.store.readAll(), actionId, out, local ? { localAnchorLog: local.path } : {});
  }

  flush(): Promise<void> {
    return this.chain.flush();
  }

  close(): Promise<void> {
    return this.chain.close();
  }

  get keyId(): string {
    return this.chain.signer.keyId;
  }
}
