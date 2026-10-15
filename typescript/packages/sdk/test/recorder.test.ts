import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { unzipSync, strFromU8 } from "fflate";
import { describe, expect, it } from "vitest";
import { parseJsonl, recordHash, verifyBundle, verifyRecords } from "@getgleipnir/verify";
import {
  ChainWriter,
  Ed25519Signer,
  JsonlStore,
  LocalFileAnchor,
  MemoryStore,
  Outcome,
  Recorder,
  buildBundle,
  selectRecords,
  type Anchor,
  type Rec,
} from "@getgleipnir/sdk";

const tmp = () => mkdtempSync(join(tmpdir(), "gleipnir-sdk-"));

/** A deterministic clock advancing one second per call. */
function steppingClock(start = Date.UTC(2026, 9, 14, 9, 0, 0)) {
  let t = start;
  const clock = () => new Date(t);
  return {
    clock,
    advance: (s: number) => (t += s * 1000),
    tick: () => {
      t += 1000;
      return new Date(t);
    },
  };
}

function recorder(home = tmp(), extra: Partial<ConstructorParameters<typeof Recorder>[0]> = {}) {
  return new Recorder({ agentId: "support-agent", agentVersion: "3.2.4", home, background: false, quiet: true, ...extra });
}

function bundleRecords(zip: Uint8Array): Rec[] {
  return parseJsonl(strFromU8(unzipSync(zip)["records.jsonl"]!)) as Rec[];
}

describe("Recorder", () => {
  it("records sync tool calls with outcome checks and claims, and the bundle verifies", async () => {
    const home = tmp();
    const rec = recorder(home, { segmentMaxRecords: 2 });
    const book = new Map<string, number>();
    const refund = rec.tool(
      (order_id: string, amount_cents: number, card_number: string) => {
        void card_number;
        book.set(order_id, amount_cents > 10000 ? amount_cents - 50 : amount_cents);
        return { refund_id: `R-${order_id}`, amount_cents };
      },
      {
        system: "payments-api",
        name: "issue_refund",
        params: ["order_id", "amount_cents", "card_number"],
        redact: ["card_number"],
        verifyOutcome: (call, res) =>
          Outcome.compare({ amount_cents: call.args["amount_cents"] }, { amount_cents: book.get(res.refund_id.slice(2)) }),
        claim: (a) => `Refunded ${(a["amount_cents"] as number) / 100} on ${a["order_id"]}`,
      },
    );
    rec.context({ model: { provider: "x", name: "y" }, identity: { principal: "svc" } }, () => {
      rec.context({ on_behalf_of: "ticket:T-1" }, () => {
        expect(refund("A-1", 4210, "4111111111111111")).toEqual({ refund_id: "R-A-1", amount_cents: 4210 });
        refund("A-2", 18000, "4111111111111111");
      });
    });
    const out = await rec.export(join(home, "bundle.zip"));
    const zip = readFileSync(out);
    const report = verifyBundle(zip, { expectKey: rec.keyId, requireFull: true });
    expect(report.valid(true), JSON.stringify(report.findings)).toBe(true);

    const actions = bundleRecords(zip).filter((r) => r["kind"] === "action");
    expect(actions).toHaveLength(2);
    const [a1, a2] = actions as [Rec, Rec];
    expect((a1["args"] as Rec)["card_number"]).toEqual({ redacted: expect.stringMatching(/^hmac-sha256:[0-9a-f]{64}$/) });
    expect(a1["redaction"]).toEqual({ fields: ["card_number"], default: "hmac" });
    expect((a1["outcome"] as Rec)["check"]).toBe("match");
    expect((a2["outcome"] as Rec)["check"]).toBe("mismatch");
    expect((a2["outcome"] as Rec)["fields"]).toEqual(["amount_cents"]);
    expect(a1["context"]).toEqual({ on_behalf_of: "ticket:T-1" });
    expect(a1["model"]).toEqual({ provider: "x", name: "y" });
    expect(a1["claim"]).toEqual({ text: "Refunded 42.1 on A-1" });
    expect(a1["agent"]).toEqual({ id: "support-agent", version: "3.2.4" });
    const manifest = JSON.parse(strFromU8(unzipSync(zip)["manifest.json"]!));
    expect(manifest).toMatchObject({ format: 1, from_seq: 1, key: rec.keyId });
    const verifyMd = strFromU8(unzipSync(zip)["VERIFY.md"]!);
    expect(verifyMd).toContain(`pipx run gleipnir-verify bundle.zip --expect-key ${rec.keyId} --require-full`);
  });

  it("records async tools, async outcome checks, errors and context across awaits", async () => {
    const rec = recorder(tmp());
    const lookup = rec.tool(
      async ({ id }: { id: string }) => {
        await new Promise((r) => setTimeout(r, 5));
        if (id === "bad") throw new TypeError("no such order");
        return { id, status: "shipped" };
      },
      {
        system: "orders",
        name: "lookup",
        verifyOutcome: async (_call, res) => {
          await new Promise((r) => setTimeout(r, 1));
          return res.status === "shipped";
        },
      },
    );
    await rec.context({ session: "s-1", run_id: "run-9" }, async () => {
      await expect(lookup({ id: "A" })).resolves.toEqual({ id: "A", status: "shipped" });
      await expect(lookup({ id: "bad" })).rejects.toThrow("no such order");
    });
    await rec.flush();
    const recs = rec.chain.store.readAll();
    const actions = recs.filter((r) => r["kind"] === "action");
    expect(actions[0]!["args"]).toEqual({ id: "A" });
    expect((actions[0]!["outcome"] as Rec)["check"]).toBe("match");
    expect(actions[0]!["context"]).toEqual({ session: "s-1", run_id: "run-9" });
    expect(actions[1]!["response"]).toEqual({ status: "error", error: "TypeError: no such order" });
    expect(actions[1]!["outcome"]).toBeUndefined();
    expect(actions[1]!["context"]).toEqual({ session: "s-1", run_id: "run-9" });
    expect(verifyRecords(recs).valid()).toBe(true);
  });

  it("records sync throws and re-throws them; a failing check becomes an error outcome", () => {
    const rec = recorder(tmp());
    const boom = rec.tool(() => {
      throw new Error("down");
    }, { system: "x", name: "boom" });
    expect(() => boom()).toThrow("down");
    const checked = rec.tool((n: number) => n * 2, {
      system: "x",
      name: "double",
      verifyOutcome: () => {
        throw new RangeError("checker broke");
      },
    });
    expect(checked(2)).toBe(4);
    const acts = rec.chain.store.readAll().filter((r) => r["kind"] === "action");
    expect(acts[0]!["response"]).toEqual({ status: "error", error: "Error: down" });
    expect(acts[1]!["args"]).toEqual({ args: [2] });
    expect(acts[1]!["outcome"]).toEqual({ check: "error", method: "verify_outcome", detail: "RangeError: checker broke" });
  });

  it("supports drop, hmac and callable redaction, nested and in lists", () => {
    const rec = recorder(tmp());
    const fields = rec.recordAction({
      tool: "t",
      system: "s",
      args: { a: { ssn: "123", keep: 1 }, list: [{ ssn: "9" }], token: "secret", email: "x@y.z" },
      response: { token: "t2" },
      redact: { ssn: "drop", token: "hmac", email: (v) => String(v).replace(/^[^@]+/, "***") },
    });
    expect(fields["args"]).toEqual({
      a: { ssn: { redacted: "dropped" }, keep: 1 },
      list: [{ ssn: { redacted: "dropped" } }],
      token: { redacted: expect.stringMatching(/^hmac-sha256:/) },
      email: "***@y.z",
    });
    expect((fields["response"] as Rec)["body"]).toEqual({ token: { redacted: expect.stringMatching(/^hmac-sha256:/) } });
    expect(fields["redaction"]).toEqual({ fields: ["email", "ssn", "token"], default: "hmac" });
    const noKey = recorder(tmp(), { redactionKey: null });
    const f2 = noKey.recordAction({ tool: "t", system: "s", args: { token: "x" }, redact: ["token"] });
    expect(f2["args"]).toEqual({ token: { redacted: "dropped" } });
    expect(f2["redaction"]).toEqual({ fields: ["token"], default: "drop" });
  });

  it("hmac redaction matches the spec: HMAC-SHA256 over the JCS of the value", async () => {
    const { hmac } = await import("@noble/hashes/hmac.js");
    const { sha256 } = await import("@noble/hashes/sha2.js");
    const { canonicalize, bytesToHex } = await import("@getgleipnir/verify");
    const key = new Uint8Array(32).fill(7);
    const rec = recorder(tmp(), { redactionKey: key });
    const value = { b: [1, 2.5, "\u20ac"], a: null };
    const f = rec.recordAction({ tool: "t", system: "s", args: { v: value }, redact: ["v"] });
    expect((f["args"] as Rec)["v"]).toEqual({ redacted: "hmac-sha256:" + bytesToHex(hmac(sha256, key, canonicalize(value))) });
  });

  it("rejects unknown context keys and unknown anchors", () => {
    const rec = recorder(tmp());
    expect(() => rec.context({ nope: 1 } as never, () => 0)).toThrow(/unknown context keys/);
    expect(() => recorder(tmp(), { anchor: "rekor" as never })).toThrow(/unknown anchor/);
  });

  it("writes claims, reviews and notes", async () => {
    const rec = recorder(tmp());
    const a = rec.recordAction({ tool: "t", system: "s", args: {} });
    rec.claim(a["id"] as string, "done");
    rec.review(a["id"] as string, { reviewer: "ops", decision: "approved", beforeExecution: false, reason: "ok" });
    rec.note("hello", { x: 1 });
    await rec.flush();
    const kinds = rec.chain.store.readAll().map((r) => r["kind"]);
    expect(kinds).toEqual(["genesis", "action", "claim", "review", "note", "segment", "anchor"]);
    expect(verifyRecords(rec.chain.store.readAll()).valid()).toBe(true);
  });

  it("converts awkward values to JSON (NaN, bigint, Date, bytes, Map, Set, class instances)", () => {
    const rec = recorder(tmp());
    class Thing {
      constructor(readonly x = 1) {}
    }
    const f = rec.recordAction({
      tool: "t",
      system: "s",
      args: {
        nan: NaN,
        inf: -Infinity,
        big: 2n ** 70n,
        small: 5n,
        d: new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 6)),
        b: new Uint8Array(3),
        m: new Map([["k", 1]]),
        s: new Set([3, 1]),
        t: new Thing(),
        u: undefined,
      },
    });
    expect(f["args"]).toMatchObject({
      nan: { float: "nan" },
      inf: { float: "-inf" },
      small: 5,
      d: "2026-01-02T03:04:05.006Z",
      b: { bytes_len: 3 },
      m: { k: 1 },
      s: [1, 3],
      t: { x: 1 },
    });
  });
});

describe("ChainWriter", () => {
  it("closes segments by size and heartbeat, links them and anchors them", async () => {
    const c = steppingClock();
    const store = new MemoryStore();
    const anchorPath = join(tmp(), "log.jsonl");
    const w = new ChainWriter(store, Ed25519Signer.generate(), {
      clock: c.clock,
      anchor: new LocalFileAnchor(anchorPath, c.clock),
      segmentMaxRecords: 3,
      heartbeatSeconds: 60,
      background: false,
    });
    for (let i = 0; i < 7; i++) {
      c.advance(1);
      w.append("note", { note: { text: `n${i}` } });
    }
    await w.anchorPending();
    c.advance(61);
    expect(w.maybeHeartbeat()).not.toBeNull();
    expect(w.maybeHeartbeat()).toBeNull();
    await w.close();
    const recs = store.readAll();
    const segs = recs.filter((r) => r["kind"] === "segment");
    expect(segs.length).toBeGreaterThanOrEqual(3);
    expect(segs.some((s) => (s["segment"] as Rec)["heartbeat"] === true)).toBe(true);
    const log = parseJsonl(readFileSync(anchorPath, "utf8"));
    const r = verifyRecords(recs, { anchorOptions: { localAnchorEntries: log } });
    expect(r.valid(true), JSON.stringify(r.findings)).toBe(true);
    expect(r.summary["segments_anchored"]).toBe(segs.length);
  });

  it("recovers state from a JSONL store and continues the chain", async () => {
    const dir = tmp();
    const signer = Ed25519Signer.generate();
    const c = steppingClock();
    const w1 = new ChainWriter(new JsonlStore(dir), signer, { clock: c.tick, background: false, segmentMaxRecords: 2 });
    for (let i = 0; i < 3; i++) w1.append("note", { note: { text: String(i) } });
    const w2 = new ChainWriter(new JsonlStore(dir), signer, { clock: c.tick, background: false, segmentMaxRecords: 2 });
    expect(w2.chainId).toBe(w1.chainId);
    w2.append("note", { note: { text: "3" } });
    await w2.close();
    const recs = new JsonlStore(dir).readAll();
    const r = verifyRecords(recs);
    expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
    expect(recs.map((x) => x["seq"])).toEqual(recs.map((_, i) => i));
    expect(() => new ChainWriter(new JsonlStore(dir), Ed25519Signer.generate(), { background: false })).toThrow(/is signed with/);
  });

  it("rotates keys", async () => {
    const store = new MemoryStore();
    const w = new ChainWriter(store, Ed25519Signer.generate(), { background: false });
    w.append("note", { note: { text: "a" } });
    const next = Ed25519Signer.generate();
    w.rotateKey(next);
    w.append("note", { note: { text: "b" } });
    await w.close();
    const r = verifyRecords(store.readAll());
    expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
    expect(r.summary["keys"]).toHaveLength(2);
  });

  it("retries failing anchors without breaking recording, and supports async anchors", async () => {
    const warnings: string[] = [];
    let fail = true;
    const flaky: Anchor = {
      type: "rekor",
      anchor: async ({ segmentHash }) => {
        await new Promise((r) => setTimeout(r, 1));
        if (fail) throw new Error("network down");
        return { fake: segmentHash };
      },
    };
    const store = new MemoryStore();
    const w = new ChainWriter(store, Ed25519Signer.generate(), { anchor: flaky, background: false, onWarning: (m) => warnings.push(m) });
    w.append("note", { note: { text: "a" } });
    await w.flush();
    expect(warnings[0]).toMatch(/rekor anchoring of segment 2 failed, will retry: network down/);
    expect(w.pendingAnchor.size).toBe(1);
    fail = false;
    await w.anchorPending();
    expect(w.pendingAnchor.size).toBe(0);
    const anchors = store.readAll().filter((r) => r["kind"] === "anchor");
    expect(anchors).toHaveLength(1);
    // a fake "rekor" receipt is reported invalid by the verifier, as it must be
    expect(verifyRecords(store.readAll()).errors.map((f) => f.code)).toContain("anchor_invalid");
  });

  it("writes unicode safely: line separators cannot split a stored record", () => {
    const dir = tmp();
    const w = new ChainWriter(new JsonlStore(dir), Ed25519Signer.generate(), { background: false });
    w.append("note", { note: { text: "a\u2028b\u2029c\u0085d \u20ac \u{1f600}" } });
    const recs = new JsonlStore(dir).readAll();
    expect(recs).toHaveLength(2);
    expect((recs[1]!["note"] as Rec)["text"]).toBe("a\u2028b\u2029c\u0085d \u20ac \u{1f600}");
    expect(verifyRecords(recs).valid()).toBe(true);
    const raw = readFileSync(join(dir, "records.jsonl"), "utf8");
    expect(raw).toContain("\u20ac");
    expect(raw).not.toContain("\u2028");
  });

  it("hashes exactly what a reader parses back (numbers beyond 2^53, -0, unicode keys)", () => {
    const store = new MemoryStore();
    const w = new ChainWriter(store, Ed25519Signer.generate(), { background: false });
    const rec = w.append("note", { note: { text: "x", big: 2 ** 60, neg: -0, "\u00e9": 1 } });
    const back = store.readAll()[1]!;
    expect(recordHash(back)).toBe(recordHash(rec));
    expect(verifyRecords(store.readAll()).valid()).toBe(true);
  });
});

describe("export", () => {
  it("selects complete segments for a date range and the bundle verifies as partial", async () => {
    const c = steppingClock();
    const home = tmp();
    const rec = recorder(home, { clock: c.clock, segmentMaxRecords: 2 });
    for (let i = 0; i < 6; i++) {
      c.advance(60);
      rec.recordAction({ tool: "t", system: "s", args: { i } });
      await rec.chain.anchorPending();
    }
    await rec.flush();
    const all = rec.chain.store.readAll();
    const segs = all.filter((r) => r["kind"] === "segment");
    const since = new Date(Date.parse((segs[1]!["segment"] as Rec)["opened_at"] as string) + 1000);
    const picked = selectRecords(all, since, null);
    expect(picked[0]!["kind"]).toBe("genesis");
    expect(picked[1]!["seq"]).toBe((segs[1]!["segment"] as Rec)["from"]);
    const zip = buildBundle(all, "part.zip", { since, localAnchorLog: join(home, "anchors", "local-anchor-log.jsonl") });
    const r = verifyBundle(zip);
    expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
    expect(r.findings.some((f) => f.code === "partial_bundle")).toBe(true);
    expect(verifyBundle(zip, { requireFull: true }).valid()).toBe(false);
  });
});
