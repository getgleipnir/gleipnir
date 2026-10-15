/**
 * RekorAnchor and TimestampAnchor: request bodies, receipt format and checks, replayed against
 * recorded Sigstore responses (test/fixtures/anchor_responses.json, made by
 * scripts/record-anchor-fixtures.mjs) through a fake fetch; and non-blocking anchoring.
 *
 * GLEIPNIR_LIVE_REKOR=1 also runs a live test that anchors a few segments on public Rekor and
 * Sigstore's TSA and verifies the bundle with both verifiers.
 */

import { execFileSync } from "node:child_process";
import { createPublicKey, generateKeyPairSync, verify as nodeVerify } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import {
  anchorMessage,
  b64decodeStrict,
  b64encode,
  bytesToHex,
  timestampMessage,
  verifyBundle,
  verifyRecords,
  verifyRekorReceipt,
  verifyTimestampReceipt,
} from "@getgleipnir/verify";
import {
  ChainWriter,
  DEFAULT_REKOR_V2_URL,
  DEFAULT_TSA_URL,
  Ed25519Signer,
  MemoryStore,
  Recorder,
  RekorAnchor,
  TimestampAnchor,
  timestampRequest,
  type FetchLike,
  type Rec,
} from "@getgleipnir/sdk";
import { REPO, normalizeReport, pythonAvailable, pythonCli } from "../../verify/test/oracle.js";

const FIX = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/anchor_responses.json", import.meta.url)), "utf8"));
const SEG: string = FIX.segment_hash;
const REQ = { segmentHash: SEG, chain: "ch_fixture", segmentSeq: 3 };
const tmp = () => mkdtempSync(join(tmpdir(), "gleipnir-anchor-"));
const fixedClock = () => new Date(Date.UTC(2026, 9, 15, 12, 0, 0, 250));

interface Call {
  url: string;
  init: RequestInit;
}

/** A fetch that answers every request with `body` (status 200 unless given) and logs the calls. */
function fakeFetch(body: Uint8Array | string, status = 200): FetchLike & { calls: Call[] } {
  const calls: Call[] = [];
  const f = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(typeof body === "string" ? body : Buffer.from(body), { status });
  }) as FetchLike & { calls: Call[] };
  f.calls = calls;
  return f;
}

const rekorBytes = () => b64decodeStrict(FIX.rekor.response_b64);
const tsaBytes = () => b64decodeStrict(FIX.tsa.response_b64);

/** Run Python with the workspace (only when uv is available). */
function py(code: string, input: unknown): any {
  const out = execFileSync("uv", ["run", "--quiet", "python", "-I", "-c", code], {
    cwd: REPO,
    input: JSON.stringify(input),
    encoding: "utf8",
  });
  return JSON.parse(out);
}

describe("RekorAnchor", () => {
  it("creates a P-256 anchor key under the home dir (mode 600) and reuses it", () => {
    const home = tmp();
    const a1 = new RekorAnchor(home);
    const a2 = new RekorAnchor(home);
    expect(bytesToHex(a1.publicDer)).toBe(bytesToHex(a2.publicDer));
    const path = join(home, "keys", "anchor-ecdsa-p256.pem");
    expect(readFileSync(path, "utf8")).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(a1.url).toBe(DEFAULT_REKOR_V2_URL);
  });

  it("rejects keys that are not ECDSA P-256", () => {
    const ed = generateKeyPairSync("ed25519").privateKey;
    expect(() => new RekorAnchor(tmp(), { privateKey: ed })).toThrow(/ECDSA P-256/);
    const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" }).privateKey;
    expect(() => new RekorAnchor(tmp(), { privateKey: p384 })).toThrow(/ECDSA P-256/);
  });

  it("sends a hashedrekord v0.0.2 request over the anchor message, signed with the anchor key", async () => {
    const f = fakeFetch(rekorBytes());
    const a = new RekorAnchor("unused", { privateKey: FIX.anchor_key_pem, fetch: f, url: DEFAULT_REKOR_V2_URL + "/" });
    await a.anchor(REQ);
    expect(f.calls).toHaveLength(1);
    const { url, init } = f.calls[0]!;
    expect(url).toBe(`${DEFAULT_REKOR_V2_URL}/api/v2/log/entries`);
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({ "Content-Type": "application/json", Accept: "application/json", "User-Agent": "gleipnir-sdk" });
    const body = JSON.parse(String(init.body));
    const req = body.hashedRekordRequestV002;
    expect(Object.keys(body)).toEqual(["hashedRekordRequestV002"]);
    expect(req.digest).toBe(b64encode(sha256(anchorMessage(SEG))));
    expect(req.signature.verifier).toEqual({ publicKey: { rawBytes: b64encode(a.publicDer) }, keyDetails: "PKIX_ECDSA_P256_SHA_256" });
    const pub = createPublicKey({ key: Buffer.from(a.publicDer), format: "der", type: "spki" });
    expect(nodeVerify("sha256", anchorMessage(SEG), pub, Buffer.from(req.signature.content, "base64"))).toBe(true);
  });

  it("returns the receipt in the Python SDK's format, verified before it is returned", async () => {
    const a = new RekorAnchor("unused", { privateKey: FIX.anchor_key_pem, fetch: fakeFetch(rekorBytes()), clock: fixedClock });
    const receipt = await a.anchor(REQ);
    expect(Object.keys(receipt).sort()).toEqual(["anchor_key", "entry", "log_url", "observed_at"]);
    expect(receipt["log_url"]).toBe(DEFAULT_REKOR_V2_URL);
    expect(receipt["anchor_key"]).toEqual({ alg: "ecdsa-p256-sha256", public: b64encode(a.publicDer) });
    expect(receipt["observed_at"]).toBe("2026-10-15T12:00:00.250Z");
    expect((receipt["entry"] as Rec)["logIndex"]).toBe(FIX.rekor.log_index);
    const res = verifyRekorReceipt({ receipt }, SEG, {});
    expect(res.ok, res.detail).toBe(true);
  });

  it("refuses a response that is not a receipt for this segment, key or log", async () => {
    const other = new RekorAnchor(tmp(), { fetch: fakeFetch(rekorBytes()) }); // a different anchor key
    await expect(other.anchor(REQ)).rejects.toThrow(/does not verify: log entry was made with a different anchor key/);
    const a = (fetch: FetchLike) => new RekorAnchor("unused", { privateKey: FIX.anchor_key_pem, fetch });
    await expect(a(fakeFetch(rekorBytes())).anchor({ ...REQ, segmentHash: "sha256:" + "00".repeat(32) })).rejects.toThrow(
      /log entry digest is not this segment/,
    );
    await expect(a(fakeFetch('{"not": "a receipt"}')).anchor(REQ)).rejects.toThrow(/malformed Rekor receipt/);
    await expect(a(fakeFetch("<html>")).anchor(REQ)).rejects.toThrow();
    await expect(a(fakeFetch('{"error":"busy"}', 503)).anchor(REQ)).rejects.toThrow(/HTTP 503 .*busy/);
  });

  it.runIf(pythonAvailable)("the Python SDK loads the same key file, and the Python verifier accepts the receipt", async () => {
    const home = tmp();
    const a = new RekorAnchor(home);
    const fromPython = py(
      [
        "import json, sys, base64",
        "from gleipnir import RekorAnchor",
        "print(json.dumps(base64.b64encode(RekorAnchor(json.load(sys.stdin)['home']).public_der).decode()))",
      ].join("\n"),
      { home },
    );
    expect(fromPython).toBe(b64encode(a.publicDer));

    const receipt = await new RekorAnchor("unused", { privateKey: FIX.anchor_key_pem, fetch: fakeFetch(rekorBytes()) }).anchor(REQ);
    const res = py(
      [
        "import json, sys",
        "from gleipnir_verify.rekor import verify_rekor_receipt",
        "d = json.load(sys.stdin)",
        "r = verify_rekor_receipt({'receipt': d['receipt']}, segment_hash=d['seg'], options={})",
        "print(json.dumps([r.ok, r.detail]))",
      ].join("\n"),
      { receipt, seg: SEG },
    );
    expect(res[0], res[1]).toBe(true);
  });
});

describe("TimestampAnchor", () => {
  it("builds the same TimeStampReq as the Python SDK: v1, SHA-512 imprint, 64-bit nonce, certReq", () => {
    const msg = timestampMessage(SEG);
    const der = timestampRequest(msg);
    const hex = bytesToHex(der);
    // Same bytes as rfc3161-client's TimestampRequestBuilder().data(msg).nonce(nonce=True).build(),
    // apart from the random nonce.
    const prefix = "30" + "{len}" + "020101" + "3051300d06096086480165030402030500" + "0440" + bytesToHex(sha512(msg));
    const head = prefix.replace("{len}", bytesToHex(Uint8Array.of(der.length - 2)));
    expect(hex.startsWith(head)).toBe(true);
    expect(hex.endsWith("0101ff")).toBe(true);
    const nonce = der.subarray(head.length / 2, der.length - 3);
    expect(nonce[0]).toBe(0x02);
    expect(nonce[1]).toBe(nonce.length - 2);
    expect(nonce.length - 2).toBeLessThanOrEqual(8);
    expect(nonce[2]! & 0x80).toBe(0); // positive
    expect(bytesToHex(timestampRequest(msg))).not.toBe(hex); // fresh nonce per request
  });

  it.runIf(pythonAvailable)("the Python rfc3161 parser reads the request as the Python builder's", () => {
    const msg = timestampMessage(SEG);
    const res = py(
      [
        "import json, sys, base64",
        "from rfc3161_client._rust import parse_timestamp_request",
        "d = json.load(sys.stdin)",
        "r = parse_timestamp_request(base64.b64decode(d['req']))",
        "print(json.dumps([r.version, r.cert_req, r.nonce is not None, r.policy, base64.b64encode(r.message_imprint.message).decode(),",
        "  r.message_imprint.hash_algorithm.dotted_string]))",
      ].join("\n"),
      { req: b64encode(timestampRequest(msg)) },
    );
    expect(res).toEqual([1, true, true, null, b64encode(sha512(msg)), "2.16.840.1.101.3.4.2.3"]);
  });

  it("posts the request to the TSA and returns the Python SDK's receipt format, verified", async () => {
    const f = fakeFetch(tsaBytes());
    const t = new TimestampAnchor(undefined, { fetch: f, clock: fixedClock });
    const receipt = await t.anchor(REQ);
    expect(f.calls[0]!.url).toBe(DEFAULT_TSA_URL);
    expect(f.calls[0]!.init.headers).toMatchObject({ "Content-Type": "application/timestamp-query", "User-Agent": "gleipnir-sdk" });
    expect(Object.keys(receipt).sort()).toEqual(["observed_at", "response", "tsa_url"]);
    expect(receipt).toEqual({ tsa_url: DEFAULT_TSA_URL, response: FIX.tsa.response_b64, observed_at: "2026-10-15T12:00:00.250Z" });
    const res = verifyTimestampReceipt({ receipt }, SEG, {});
    expect(res.ok, res.detail).toBe(true);
    expect(res.time).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  });

  it("refuses tokens that do not verify, and HTTP errors", async () => {
    const t = (fetch: FetchLike) => new TimestampAnchor(undefined, { fetch });
    await expect(t(fakeFetch(tsaBytes())).anchor({ ...REQ, segmentHash: "sha256:" + "11".repeat(32) })).rejects.toThrow(
      /token that does not verify: .*Mismatch between messages/,
    );
    await expect(t(fakeFetch("garbage")).anchor(REQ)).rejects.toThrow(/malformed timestamp response/);
    await expect(t(fakeFetch("", 500)).anchor(REQ)).rejects.toThrow(/HTTP 500/);
  });

  it.runIf(pythonAvailable)("the Python verifier accepts the receipt", async () => {
    const receipt = await new TimestampAnchor(undefined, { fetch: fakeFetch(tsaBytes()) }).anchor(REQ);
    const res = py(
      [
        "import json, sys",
        "from gleipnir_verify.timestamp import verify_timestamp_receipt",
        "d = json.load(sys.stdin)",
        "r = verify_timestamp_receipt({'receipt': d['receipt']}, segment_hash=d['seg'], options={})",
        "print(json.dumps([r.ok, r.detail]))",
      ].join("\n"),
      { receipt, seg: SEG },
    );
    expect(res[0], res[1]).toBe(true);
  });
});

describe('anchor: "rekor" preset and non-blocking anchoring', () => {
  it('"rekor" = RekorAnchor + TimestampAnchor, with the anchor key under home', () => {
    const home = tmp();
    const rec = new Recorder({ agentId: "a", agentVersion: "1", home, background: false, quiet: true, anchor: "rekor", fsync: false });
    expect(rec.chain.anchors.map((a) => a.type)).toEqual(["rekor", "rfc3161"]);
    expect(rec.chain.anchors[0]).toBeInstanceOf(RekorAnchor);
    expect(rec.chain.anchors[1]).toBeInstanceOf(TimestampAnchor);
    expect(existsSync(join(home, "keys", "anchor-ecdsa-p256.pem"))).toBe(true);
    expect(() => new Recorder({ agentId: "a", agentVersion: "1", home, quiet: true, background: false, anchor: "nope" as never })).toThrow(
      /use "local", "rekor"/,
    );
  });

  it("tool calls never wait for the network; receipts are written when they arrive", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const calls: string[] = [];
    // A Rekor that hangs until released, then answers with a receipt for another segment.
    const slow: FetchLike = async (url) => {
      calls.push(url);
      await gate;
      return new Response(Buffer.from(rekorBytes()));
    };
    const warnings: string[] = [];
    const store = new MemoryStore();
    const w = new ChainWriter(store, Ed25519Signer.generate(), {
      anchor: [new RekorAnchor(tmp(), { fetch: slow }), new TimestampAnchor(undefined, { fetch: fakeFetch("", 500) })],
      background: false,
      segmentMaxRecords: 2,
      onWarning: (m) => warnings.push(m),
    });
    const t0 = Date.now();
    for (let i = 0; i < 6; i++) w.append("note", { note: { text: String(i) } });
    expect(Date.now() - t0).toBeLessThan(1000);
    await new Promise((r) => setTimeout(r, 10));
    expect(calls).toHaveLength(1); // one anchoring run at a time; later segments queue behind it
    expect(store.readAll().filter((r) => r["kind"] === "anchor")).toHaveLength(0);
    expect(w.pendingAnchor.size).toBe(3);
    release();
    await w.anchorPending();
    // the receipt was for another segment and the TSA failed: nothing is written, all retried later
    expect(store.readAll().filter((r) => r["kind"] === "anchor")).toHaveLength(0);
    expect(warnings.some((m) => /rekor anchoring of segment \d+ failed, will retry: .*does not verify/.test(m))).toBe(true);
    expect(warnings.some((m) => /rfc3161 anchoring of segment \d+ failed, will retry: HTTP 500/.test(m))).toBe(true);
    expect(w.pendingAnchor.size).toBe(3);
    expect(verifyRecords(store.readAll()).valid()).toBe(true);
  });

  it("a successful network anchor writes the same anchor record as the Python SDK", async () => {
    // Replays the recorded TSA token for whatever segment is anchored: only its own segment verifies,
    // so a fake anchor wraps the real TimestampAnchor with the fixture's segment hash.
    const store = new MemoryStore();
    const ts = new TimestampAnchor(undefined, { fetch: fakeFetch(tsaBytes()), clock: fixedClock });
    const w = new ChainWriter(store, Ed25519Signer.generate(), {
      anchor: { type: "rfc3161", anchor: () => ts.anchor(REQ) },
      background: false,
    });
    w.append("note", { note: { text: "x" } });
    await w.flush();
    const a = store.readAll().find((r) => r["kind"] === "anchor")!;
    const body = a["anchor"] as Rec;
    expect(Object.keys(body).sort()).toEqual(["receipt", "segment_hash", "segment_seq", "type"]);
    expect(body["type"]).toBe("rfc3161");
    expect(body["receipt"]).toEqual({ tsa_url: DEFAULT_TSA_URL, response: FIX.tsa.response_b64, observed_at: "2026-10-15T12:00:00.250Z" });
  });
});

const LIVE = process.env["GLEIPNIR_LIVE_REKOR"] === "1";

describe.runIf(LIVE)("live: public Rekor v2 + Sigstore TSA (GLEIPNIR_LIVE_REKOR=1)", () => {
  it(
    "anchors segments from the TypeScript SDK; both verifiers accept the bundle with both anchors required",
    async () => {
      const home = tmp();
      const warnings: string[] = [];
      const rec = new Recorder({
        agentId: "live-test",
        agentVersion: "1",
        home,
        background: false,
        quiet: true,
        anchor: "rekor",
        segmentMaxRecords: 3,
        fsync: false,
        onWarning: (m) => warnings.push(m),
      });
      const f = rec.tool((i: number) => ({ i }), { system: "test", name: "f", params: ["i"] });
      for (let i = 0; i < 4; i++) f(i);
      const out = await rec.export(join(home, "live.zip"));
      expect(warnings, warnings.join("\n")).toEqual([]);
      const opts = { expectKey: rec.keyId, requireAnchor: ["rekor", "rfc3161"], maxAnchorDelay: 86400, requireFull: true };
      const r = verifyBundle(readFileSync(out), opts);
      expect(r.valid(true), JSON.stringify(r.findings)).toBe(true);
      const n = r.summary["segments"] as number;
      expect(n).toBeGreaterThanOrEqual(2);
      expect(r.summary["anchors_independent"]).toBe(n); // segments with an independent anchor
      expect(r.summary["segments_anchored"]).toBe(n);
      expect(r.summary["segments_timestamped"]).toBe(n);
      writeFileSync(join(home, "summary.json"), JSON.stringify(r.summary));
      if (pythonAvailable || process.env["GLEIPNIR_REQUIRE_PYTHON"]) {
        const args = [out, "--expect-key", rec.keyId, "--require-anchor", "rekor", "--require-anchor", "rfc3161", "--max-anchor-delay", "86400", "--require-full", "--strict"];
        const p = pythonCli(args);
        expect(p.code, p.out + p.err).toBe(0);
        expect(p.out).toContain("result: VALID");
        const pj = pythonCli([...args, "--json"]);
        expect(JSON.parse(pj.out)).toEqual(normalizeReport(r.toJSON(true)));
        console.log(`live: ${n} segments anchored on Rekor and timestamped; TS and Python verifiers: VALID (${out})`);
      }
    },
    180_000,
  );
});
