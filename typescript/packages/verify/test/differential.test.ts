/**
 * Differential tests against the Python reference (scripts/py_oracle.py, run with `uv`).
 *
 * Canonical bytes, record hashes, timestamp parsing and full verification reports (result,
 * finding codes, levels, seqs and messages) must be identical. Skipped when `uv` or the
 * Python workspace is not available (set GLEIPNIR_REQUIRE_PYTHON=1 to make that an error).
 */

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  canonicalizeString,
  parseJson,
  parseJsonl,
  parseTime,
  pyDumps,
  recordHash,
  verifyBundle,
  verifyRecords,
  type VerifyOptions,
} from "@getgleipnir/verify";
import { Builder, Key, resign, rng, writeBundle, zipBundle, type Rec } from "./chainbuilder.js";

const REPO = fileURLToPath(new URL("../../../../", import.meta.url));
const ORACLE = join(REPO, "typescript/scripts/py_oracle.py");

const available = (() => {
  if (!existsSync(join(REPO, "pyproject.toml"))) return false;
  const r = spawnSync("uv", ["--version"], { encoding: "utf8" });
  return r.status === 0;
})();
if (!available && process.env["GLEIPNIR_REQUIRE_PYTHON"]) throw new Error("uv / Python workspace not available");

function oracle(cases: unknown[]): any[] {
  const out = execFileSync("uv", ["run", "--quiet", "python", "-I", ORACLE], {
    cwd: REPO,
    input: JSON.stringify(cases),
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"],
  });
  return JSON.parse(out);
}

function errorName(fn: () => unknown): { ok: unknown } | { error: string } {
  try {
    return { ok: fn() };
  } catch (e) {
    return { error: (e as Error).name };
  }
}

/** JSON as the Python side would produce it from the report (sorted keys). */
function normalizeReport(r: unknown): unknown {
  return JSON.parse(pyDumps(r));
}

const d = available ? describe : describe.skip;

/**
 * Findings whose message embeds a host-language exception text ("malformed: records could not
 * be processed: TypeError: ...", "unencodable", "bad_genesis_key", "bad_segment", ...) are
 * compared up to the exception type; everything else is compared exactly.
 */
const EXCEPTION_TEXT_CODES = new Set(["malformed", "bad_bundle", "unencodable", "bad_genesis_key", "bad_rotation", "bad_segment"]);
function stripExceptionText(report: any): any {
  if (!report || !Array.isArray(report.findings)) return report;
  return {
    ...report,
    findings: report.findings.map((f: any) =>
      EXCEPTION_TEXT_CODES.has(f.code) ? { ...f, message: String(f.message).split(":").slice(0, f.code === "malformed" ? 2 : 1).join(":") } : f,
    ),
  };
}

d("differential: canonical bytes and hashes match the Python reference", () => {
  const texts = [
    "1", "-0", "-0.0", "0.0", "1.0", "1e2", "1E-7", "1e-7", "5e-324", "1e21", "1e20", "123456789012345678",
    "9007199254740991", "9007199254740992", "-9007199254740992", "-9007199254740991", "1.7976931348623157e308",
    "2.2250738585072014e-308", "0.1", "0.30000000000000004", "100", "1e400", "-1e400", "NaN", "Infinity",
    "4.35", "0.000001", "0.0000001", "1e-6", "123e18", "123e19", "1.5e300", "333333333.33333329",
    '"\\u0000\\u001f\\u007f\\u0080\\u2028\\ud834\\udd1e"', '"\\ud800"', '"\\udc00x"', '"\\"\\\\/\\b\\f\\n\\r\\t"',
    '{"b":1,"a":2,"\\u20ac":3,"\\ud83d\\ude00":4,"\\uff61":5,"\\r":6,"":7}', '{"a":1,"a":2}',
    '{"__proto__":{"x":1},"constructor":2}', "[[],{},[{}]]", "true", "null", '"' + "x".repeat(1000) + '"',
    '{"n":[1,2.5,-3e-10,1e100,12345678901234567890]}', "[" + "[".repeat(300) + "]".repeat(301),
  ];
  const rand = rng(99);
  for (let i = 0; i < 300; i++) {
    // random doubles across the range
    const buf = new DataView(new ArrayBuffer(8));
    buf.setUint32(0, Math.floor(rand() * 2 ** 32));
    buf.setUint32(4, Math.floor(rand() * 2 ** 32));
    const x = buf.getFloat64(0);
    if (Number.isFinite(x)) texts.push(JSON.stringify(x));
    texts.push(String(Math.floor(rand() * 1e6) / 1e3));
  }

  it("canonicalize(json) is byte-identical for numbers, strings, keys and structure", () => {
    const py = oracle(texts.map((text) => ({ kind: "canon", text })));
    texts.forEach((text, i) => {
      const ts = errorName(() => canonicalizeString(parseJson(text)));
      const want = py[i];
      if ("error" in want) expect("error" in ts, `${text}: python ${want.error}, ts ${JSON.stringify(ts)}`).toBe(true);
      else expect(ts, text).toEqual({ ok: want.canonical });
    });
  });

  it("record hashes match for SDK-shaped records with unicode and numbers", () => {
    const b = new Builder().standard(2, 3);
    const recs = b.records.map((r) => JSON.stringify(r));
    recs.push(
      JSON.stringify({ v: 1, seq: 1, args: { note: "Gr\u00fc\u00dfe \u20ac \u{1f600}", n: 42.1, small: 1e-7, big: 9007199254740991, neg: -0 } }),
      '{"v":1,"seq":1,"x":1.0,"y":-0.0,"z":1E400}',
      '{"v":1,"seq":1,"sig":"ignored","x":"\\ud800"}',
    );
    const py = oracle(recs.map((text) => ({ kind: "hash", text })));
    recs.forEach((text, i) => {
      const ts = errorName(() => recordHash(parseJson(text) as Rec));
      if ("error" in py[i]) expect("error" in ts, text).toBe(true);
      else expect(ts, text).toEqual({ ok: py[i].hash });
    });
  });
});

d("differential: timestamps parse identically", () => {
  const cases = [
    "2026-10-14T09:00:00.112Z", "2026-10-14T09:00:00Z", "2026-10-14T09:00Z", "2026-10-14T09Z", "2026-10-14 09:00:00Z",
    "2026-10-14x09:00:00Z", "2026-10-14T09:00:00.1Z", "2026-10-14T09:00:00.123456Z", "2026-10-14T09:00.123Z",
    "2026-10-14T09:00:00+01:00", "2026-10-14T09:00:00+00:99", "2026-10-14T09:00:00", "2026-10-14Z", "2026-10-14T",
    "20261014T090000Z", "2026-10-14T09:00:00.112+00:00:30", "2026-10-14T09:00:00+23:59", "2026-10-14T09:00:00+24:00",
    "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00", "2026-02-30T00:00:00Z", "2024-02-29T00:00:00Z",
    "2026-10-14T24:00:00Z", "2026-10-14\u00e909:00:00Z", "2026-10-14\u20ac09:00:00Z", "2026-10-14\u{1f600}09:00:00Z",
    "2026-10-14T09:00:00.112z", "2026-10-14T09:00:00-00:00", "2026-10-14T09:00:00+0100", "2026-10-14T09:00:00.1234Z",
    "2026-10-14T09:00:00.123456789Z", "2026-10-14T9:00:00Z", "2026-1-14T09:00:00Z", "+2026-10-14T09:00:00Z",
    "2026-10-14T09:00:00+01:00:00.123456", "2026-10-14T09:00:00+01:00:00.123", "2026-10-14T09:00:60Z",
    "2026-10-14T09:60:00Z", "2026-10-14T09:00:00.000+05:30", "2026-10-14T09:00:00Z ", " 2026-10-14T09:00:00Z",
    "2026-10-14T09:00:00ZZ", "2026-10-14T09:00:00+01:00Z", "2026-10-14T09", "2026-10-14T0", "", "Z", "2026",
    "2026-10-14T09:00:00\u0000Z", "\uff12026-10-14T09:00:00Z", "2026-10-14T\uff10\uff19:00:00Z",
    "2026-10-14\ud800T09:00:00Z",
  ];
  it("accepts and rejects the same strings with the same instants", () => {
    // The reference parses with datetime.fromisoformat, which accepts more on Python >= 3.11
    // (e.g. "...09:00:00.1Z", "20261014T090000Z"). This verifier implements the 3.10 grammar;
    // on newer Pythons only well-formed RFC 3339 timestamps are compared.
    const [ver] = oracle([{ kind: "version" }]);
    const py310 = ver.version[0] === 3 && ver.version[1] === 10;
    const rfc3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?(Z|[+-]\d{2}:\d{2})$/;
    const chosen = py310 ? cases : cases.filter((c) => rfc3339.test(c));
    const py = oracle(chosen.map((text) => ({ kind: "time", text })));
    chosen.forEach((text, i) => {
      const ts = errorName(() => Number(parseTime(text)));
      if ("error" in py[i]) expect("error" in ts, `${JSON.stringify(text)} python ${py[i].error} ts ${JSON.stringify(ts)}`).toBe(true);
      else expect(ts, JSON.stringify(text)).toEqual({ ok: py[i].micros });
    });
  });
});

interface Case {
  name: string;
  records: Rec[] | string;
  options?: Record<string, unknown>;
}

function toTsOptions(o: Record<string, any> = {}): VerifyOptions {
  const out: VerifyOptions = {};
  if (o["expect_key"] != null) out.expectKey = o["expect_key"];
  if (o["expect_until"] != null) out.expectUntil = o["expect_until"];
  if (o["known_head"] != null) out.knownHead = { seq: o["known_head"][0], hash: o["known_head"][1] };
  if (o["require_anchor"] != null) out.requireAnchor = o["require_anchor"];
  if (o["max_anchor_delay"] != null) out.maxAnchorDelay = o["max_anchor_delay"];
  if (o["require_full"]) out.requireFull = true;
  if (o["manifest"] != null) out.manifest = o["manifest"];
  if (o["local_anchor_entries"] != null) out.anchorOptions = { localAnchorEntries: o["local_anchor_entries"] };
  return out;
}

d("differential: verification reports are identical", () => {
  const cases: Case[] = [];
  const b = new Builder().standard(3, 4);
  const log = b.anchorLog;
  const N = b.records.length;
  const head = [b.records[N - 1]!["seq"], recordHash(b.records[N - 1]!)];
  const manifest = { chain: b.chain, from_seq: 1, to_seq: b.records[N - 1]!["seq"], format: 1 };
  const full = { local_anchor_entries: log, manifest, expect_key: b.key.id };
  cases.push({ name: "valid", records: b.records, options: full });
  cases.push({ name: "valid no log", records: b.records });
  cases.push({ name: "valid require rekor", records: b.records, options: { ...full, require_anchor: ["rekor", "rfc3161"] } });
  cases.push({ name: "valid expect until late", records: b.records, options: { ...full, expect_until: "2027-01-01T00:00:00Z" } });
  cases.push({ name: "known head ok", records: b.records, options: { ...full, known_head: head } });
  cases.push({ name: "known head wrong", records: b.records, options: { ...full, known_head: [3, "sha256:" + "0".repeat(64)] } });
  cases.push({ name: "known head missing", records: b.records, options: { ...full, known_head: [999, head[1]] } });
  cases.push({ name: "wrong key", records: b.records, options: { ...full, expect_key: "k_ed25519_0000000000000000" } });
  for (let i = 0; i < N; i++) {
    const del = structuredClone(b.records);
    del.splice(i, 1);
    cases.push({ name: `delete ${i}`, records: del, options: full });
    cases.push({ name: `truncate ${i}`, records: structuredClone(b.records.slice(0, i + 1)), options: full });
  }
  for (let i = 0; i < N - 1; i++) {
    const sw = structuredClone(b.records);
    [sw[i], sw[i + 1]] = [sw[i + 1]!, sw[i]!];
    cases.push({ name: `swap ${i}`, records: sw, options: full });
  }
  // random field edits, including type confusion
  const rand = rng(7);
  const values: unknown[] = [0, 1, -1, 1.5, 2 ** 31, "", "x", true, false, null, [], {}, [1], { a: 1 }, "2026-10-01T09:00:00Z", "sha256:" + "ab".repeat(32), 1e300, -0];
  const pathsOf = (o: unknown, p: Array<string | number> = [], out: Array<Array<string | number>> = []) => {
    if (Array.isArray(o)) o.forEach((v, i) => pathsOf(v, [...p, i], out));
    else if (o && typeof o === "object") for (const [k, v] of Object.entries(o)) { out.push([...p, k]); pathsOf(v, [...p, k], out); }
    else out.push(p);
    return out;
  };
  for (let n = 0; n < 250; n++) {
    const recs = structuredClone(b.records);
    const i = Math.floor(rand() * N);
    const paths = pathsOf(recs[i]).filter((p) => p.length > 0);
    const path = paths[Math.floor(rand() * paths.length)]!;
    let t: any = recs[i];
    for (const k of path.slice(0, -1)) t = t[k];
    t[path[path.length - 1]!] = structuredClone(values[Math.floor(rand() * values.length)]);
    if (rand() < 0.5) resign(recs, b.key, i); // an attacker with the key re-signs
    cases.push({ name: `edit ${i} ${path.join(".")}`, records: recs, options: full });
  }
  // partial bundles and segment shapes
  const segs = b.records.flatMap((r, i) => (r["kind"] === "segment" ? [i] : []));
  cases.push({ name: "partial", records: [b.records[0]!, ...b.records.slice(segs[0]! + 1)], options: { local_anchor_entries: log } });
  cases.push({ name: "partial require full", records: [b.records[0]!, ...b.records.slice(segs[0]! + 1)], options: { local_anchor_entries: log, require_full: true } });
  cases.push({ name: "partial misaligned", records: [b.records[0]!, ...b.records.slice(3)], options: { local_anchor_entries: log } });
  // heartbeats, gaps, rotations
  const hb = new Builder({ heartbeat: 60 });
  hb.action();
  hb.tick(3600.25);
  hb.anchor(hb.segment());
  cases.push({ name: "missed heartbeat", records: hb.records, options: { local_anchor_entries: hb.anchorLog } });
  const rot = new Builder();
  rot.action(1);
  const nk = new Key();
  rot.add({ kind: "key_rotation", new_key: { id: nk.id, public: nk.public } });
  rot.action(2);
  rot.key = nk;
  rot.action(3);
  rot.anchor(rot.segment());
  cases.push({ name: "stale key after rotation", records: rot.records, options: { local_anchor_entries: rot.anchorLog } });
  const tail = new Builder();
  tail.action(1);
  tail.segment();
  tail.action(2);
  tail.add({ kind: "anchor", anchor: { segment_seq: 2, segment_hash: "sha256:" + "00".repeat(32), type: "nope", receipt: {} } });
  cases.push({ name: "tail and unknown anchor", records: tail.records });
  // hostile JSON texts (parsed by each side's own JSON parser)
  const g = JSON.stringify(b.records[0]);
  const hostile = [
    "", "[]", "{}", "1", '"x"', "null", '{"seq":0}', `${g}\n{"seq":1.0,"v":1}`, `${g}\n{"seq":true}`,
    `${g}\n{"seq":1,"key":[]}`, `${g}\n{"seq":1,"key":{"a":1}}`, `${g}\n{"seq":12345678901234567890}`,
    `${g}\n{"seq":1,"x":NaN}`, `${g}\n{"seq":1,"x":1e999}`, `${g}\n[1,2]`, `${g}\nnull`,
    g.replace('"v":1', '"v":1.0'), g.replace('"seq":0', '"seq":0.0'), g.replace('"seq":0', '"seq":false'),
    g.replace('"kind":"genesis"', '"kind":["genesis"]'),
    `${g}\n{"seq":1,"chain":"ch_test","v":1,"kind":"segment","segment":{"from":1,"count":0,"root":"x","opened_at":"a","closed_at":"b"}}`,
  ];
  for (const text of hostile) cases.push({ name: `hostile ${text.slice(0, 40)}`, records: text });

  it(`matches on ${cases.length} cases`, () => {
    const py = oracle(
      cases.map((c) => ({
        kind: "records",
        text: typeof c.records === "string" ? c.records : c.records.map((r) => JSON.stringify(r)).join("\n"),
        options: c.options ?? {},
      })),
    );
    cases.forEach((c, i) => {
      const recs = typeof c.records === "string" ? (() => {
        try {
          return parseJsonl(c.records);
        } catch {
          return null;
        }
      })() : parseJsonl(c.records.map((r) => JSON.stringify(r)).join("\n"));
      if (recs === null || "parse_error" in py[i]) {
        // Both JSON parsers must reject the same texts.
        expect(recs === null && "parse_error" in py[i], `${c.name}: ts parsed=${recs !== null}, python=${JSON.stringify(py[i]).slice(0, 80)}`).toBe(true);
        return;
      }
      const ts = normalizeReport(verifyRecords(recs, toTsOptions(c.options)).toJSON()) as any;
      expect(stripExceptionText(ts), c.name).toEqual(stripExceptionText(py[i]));
    });
  });
});

d("differential: bundles", () => {
  it("verifyBundle reports match for good, tampered and broken bundles", () => {
    const dir = mkdtempSync(join(tmpdir(), "gleipnir-diff-"));
    const b = new Builder().standard();
    const bundles: Array<[string, Uint8Array, Record<string, unknown>]> = [
      ["good", writeBundle(b), {}],
      ["good strict opts", writeBundle(b), { expect_key: b.key.id, require_full: true }],
      ["format 9", writeBundle(b, undefined, { format: 9 }), {}],
      ["format 1.0", zipBundle({ "manifest.json": '{"format":1.0,"chain":"ch_test"}', "records.jsonl": b.records.map((r) => JSON.stringify(r)).join("\n") }), {}],
      ["no manifest", zipBundle({ "records.jsonl": "" }), {}],
      ["manifest list", zipBundle({ "manifest.json": "[]", "records.jsonl": "" }), {}],
      ["bad json", zipBundle({ "manifest.json": '{"format":1}', "records.jsonl": "{x\n" }), {}],
      ["bad utf8", zipBundle({ "manifest.json": '{"format":1}', "records.jsonl": new Uint8Array([0xff, 0xfe]) }), {}],
      ["not zip", new TextEncoder().encode("hello"), {}],
      ["log not objects", zipBundle({ "manifest.json": JSON.stringify({ format: 1, chain: b.chain, from_seq: 1, to_seq: 15 }), "records.jsonl": b.records.map((r) => JSON.stringify(r)).join("\n"), "anchors/local-anchor-log.jsonl": "[1]\n" }), {}],
      ["truncated manifest", writeBundle(b, b.records.slice(0, -3)), {}],
    ];
    const cases = bundles.map(([name, bytes, options]) => {
      const p = join(dir, name.replace(/\W/g, "_") + ".zip");
      writeFileSync(p, bytes);
      return { kind: "bundle", path: p, options };
    });
    const py = oracle(cases);
    bundles.forEach(([name, bytes, options], i) => {
      const ts = normalizeReport(verifyBundle(bytes, toTsOptions(options)).toJSON()) as any;
      const want = py[i];
      if (ts.findings?.[0]?.code === "bad_bundle") {
        // messages carry library-specific error text; compare the code and result only
        expect(ts.result, name).toBe(want.result);
        expect(ts.findings.map((f: any) => f.code), name).toEqual(want.findings.map((f: any) => f.code));
      } else {
        expect(ts, name).toEqual(want);
      }
    });
  });
});
