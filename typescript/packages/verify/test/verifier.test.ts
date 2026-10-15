/** Ports of python/gleipnir-verify/tests/test_verifier.py plus tamper property tests. */

import { describe, expect, it } from "vitest";
import {
  anchorResult,
  bytesToHex,
  hashToBytes,
  merkleRoot,
  recordHash,
  verifyBundle,
  verifyRecords,
  type AnchorVerifier,
  type Report,
  type VerifyOptions,
} from "@getgleipnir/verify";
import { Builder, Key, resign, rng, writeBundle, zipBundle, iso, type Rec } from "./chainbuilder.js";

function run(records: Rec[] | Builder, builder?: Builder, kw: VerifyOptions = {}): Report {
  const recs = records instanceof Builder ? records.records : records;
  const log = builder ?? (records instanceof Builder ? records : undefined);
  const anchorOptions = log ? { localAnchorEntries: log.anchorLog } : {};
  return verifyRecords(recs, { anchorOptions, ...kw });
}

const codes = (r: Report) => new Set(r.errors.map((f) => f.code));
const warnCodes = (r: Report) => new Set(r.warnings.map((f) => f.code));

describe("verifier", () => {
  it("accepts a valid chain", () => {
    const b = new Builder().standard();
    const r = run(b);
    expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
    expect(r.valid(true), JSON.stringify(r.findings)).toBe(true);
    expect(r.summary["segments"]).toBe(3);
    expect(r.summary["segments_anchored"]).toBe(3);
  });

  it("reports empty and missing genesis", () => {
    expect(codes(verifyRecords([]))).toEqual(new Set(["empty"]));
    const b = new Builder().standard();
    expect(codes(verifyRecords(b.records.slice(1)))).toEqual(new Set(["no_genesis"]));
  });

  it("detects an edit", () => {
    const b = new Builder().standard();
    const recs = b.copy();
    recs[3]!["args"]["amount"] = 9999;
    expect(codes(run(recs, b)).has("bad_signature")).toBe(true);
  });

  it("detects an edit re-signed with another key", () => {
    const b = new Builder().standard();
    const recs = resign(b.copy(), new Key(), 3);
    recs[3]!["args"]["amount"] = 999;
    resign(recs, new Key(), 3);
    expect(codes(run(recs, b)).has("unknown_key")).toBe(true);
  });

  it("catches a full rewrite with an attacker key via expectKey", () => {
    const b = new Builder().standard();
    const attacker = new Key();
    const recs = b.copy();
    recs[0]!["public_key"] = { id: attacker.id, public: attacker.public };
    resign(recs, attacker, 0);
    expect(codes(run(recs, b, { expectKey: b.key.id })).has("unexpected_key")).toBe(true);
  });

  it("detects a deletion", () => {
    const b = new Builder().standard();
    const recs = b.copy();
    recs.splice(2, 1);
    const c = codes(run(recs, b));
    expect(c.has("gap") && c.has("broken_chain")).toBe(true);
  });

  it("detects reordering", () => {
    const b = new Builder().standard();
    const recs = b.copy();
    [recs[2], recs[3]] = [recs[3]!, recs[2]!];
    const c = codes(run(recs, b));
    expect(c.has("reordered") || c.has("broken_chain")).toBe(true);
  });

  it("detects truncation via manifest, expectUntil and knownHead", () => {
    const b = new Builder().standard();
    const recs = b.copy().slice(0, -6);
    const manifest = { chain: b.chain, from_seq: 1, to_seq: b.records[b.records.length - 1]!["seq"], format: 1 };
    expect(codes(run(recs, b, { manifest })).has("truncated")).toBe(true);
    const manifest2 = { ...manifest, to_seq: recs[recs.length - 1]!["seq"] };
    const later = new Date(b.now + (b.heartbeat + 120) * 1000);
    expect(codes(run(recs, b, { manifest: manifest2, expectUntil: later })).has("coverage")).toBe(true);
    expect(run(recs, b, { manifest: manifest2, expectUntil: new Date(b.now) }).valid()).toBe(true);
    const last = b.records[b.records.length - 1]!;
    const head = { seq: last["seq"] as number, hash: recordHash(last) };
    expect(codes(run(recs, b, { manifest: manifest2, knownHead: head })).has("known_head_missing")).toBe(true);
    const rewritten = b.copy();
    rewritten[rewritten.length - 2]!["id"] = "x";
    resign(rewritten, b.key, rewritten.length - 2);
    expect(codes(run(rewritten, b, { knownHead: head })).has("known_head_changed")).toBe(true);
    expect(codes(run(rewritten, b, { knownHead: `${head.seq}:${head.hash}` })).has("known_head_changed")).toBe(true);
  });

  it("detects a rewritten segment root", () => {
    const b = new Builder().standard();
    const recs = b.copy();
    const seg = recs.find((r) => r["kind"] === "segment")!;
    seg["segment"]["root"] = "sha256:" + "00".repeat(32);
    resign(recs, b.key, seg["seq"]);
    expect(codes(run(recs, b)).has("merkle_mismatch")).toBe(true);
  });

  it("detects a rewritten segment whose receipt was kept", () => {
    const b = new Builder().standard();
    const recs = b.copy();
    recs[2]!["args"]["amount"] = 999;
    const seg = recs.find((r) => r["kind"] === "segment")!;
    resign(recs, b.key, 2);
    const members = [];
    for (let i = seg["segment"]["from"]; i < seg["seq"]; i++) members.push(recordHash(recs[i]!));
    seg["segment"]["root"] = "sha256:" + bytesToHex(merkleRoot(members.map((h) => hashToBytes(h))));
    resign(recs, b.key, seg["seq"]);
    for (const r of recs) {
      if (r["kind"] === "anchor" && r["anchor"]["segment_seq"] === seg["seq"]) r["anchor"]["segment_hash"] = recordHash(seg);
    }
    resign(recs, b.key, seg["seq"] + 1);
    expect(codes(run(recs, b)).has("anchor_invalid")).toBe(true);
  });

  it("warns about unanchored segments and an unsegmented tail", () => {
    const b = new Builder();
    for (let i = 0; i < 3; i++) b.action(i);
    b.segment();
    b.action(99);
    const r = run(b);
    expect(r.valid()).toBe(true);
    const w = warnCodes(r);
    expect(w.has("unanchored_segments") && w.has("unsegmented_tail")).toBe(true);
    expect(r.valid(true)).toBe(false);
  });

  it("warns about a missed heartbeat", () => {
    const b = new Builder({ heartbeat: 60 });
    b.action();
    b.tick(3600);
    const seg = b.segment();
    b.anchor(seg);
    const r = run(b);
    expect(warnCodes(r).has("missed_heartbeat")).toBe(true);
    const f = r.warnings.find((x) => x.code === "missed_heartbeat")!;
    expect(f.message).toBe(
      "segment spans 1:00:02 which is longer than the 60s heartbeat (process down or records withheld?)",
    );
  });

  it("handles key rotation", () => {
    const b = new Builder();
    b.action(1);
    const nk = new Key();
    b.add({ kind: "key_rotation", new_key: { id: nk.id, public: nk.public } });
    b.key = nk;
    b.action(2);
    const seg = b.segment();
    b.anchor(seg);
    expect(run(b).valid()).toBe(true);
    const recs2 = resign(b.copy(), b.key, 0);
    expect(run(recs2, b).valid()).toBe(false);
  });

  it("flags a stale key after rotation", () => {
    const b = new Builder();
    const old = b.key;
    b.action(1);
    const nk = new Key();
    b.add({ kind: "key_rotation", new_key: { id: nk.id, public: nk.public } });
    b.action(2); // still signed with the old key
    void old;
    expect(codes(run(b)).has("stale_key")).toBe(true);
  });

  it("detects wrong chain and version", () => {
    const b = new Builder().standard();
    let recs = b.copy();
    recs[4]!["chain"] = "other";
    resign(recs, b.key, 4);
    expect(codes(run(recs, b)).has("wrong_chain")).toBe(true);
    recs = b.copy();
    recs[0]!["v"] = 2;
    expect(codes(run(recs, b)).has("format_version")).toBe(true);
  });

  it("checks the local anchor log", () => {
    const b = new Builder().standard();
    const log = structuredClone(b.anchorLog);
    log[1]!["segment_hash"] = "sha256:" + "11".repeat(32);
    expect(codes(verifyRecords(b.records, { anchorOptions: { localAnchorEntries: log } })).has("anchor_invalid")).toBe(true);
    const r = verifyRecords(b.records);
    expect(r.valid()).toBe(true);
    expect(r.findings.some((f) => f.code === "anchor_unchecked")).toBe(true);
  });

  it("accepts a partial bundle starting at a segment", () => {
    const b = new Builder().standard(3, 3);
    const segs = b.records.filter((r) => r["kind"] === "segment");
    const start = segs[0]!["seq"] + 1;
    const recs = [b.records[0]!, ...b.records.slice(start)];
    const r = run(recs, b);
    expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
    expect(r.findings.some((f) => f.code === "partial_bundle")).toBe(true);
    expect(codes(run(recs, b, { requireFull: true })).has("partial_bundle")).toBe(true);
  });

  it("rejects a partial bundle not at a segment boundary", () => {
    const b = new Builder().standard(3, 3);
    expect(run([b.records[0]!, ...b.records.slice(3)], b).valid()).toBe(false);
  });

  it("verifies bundles", () => {
    const b = new Builder().standard();
    const zip = writeBundle(b);
    const r = verifyBundle(zip);
    expect(r.valid(true), JSON.stringify(r.findings)).toBe(true);
    expect(verifyBundle(zip, { expectKey: "k_ed25519_0000000000000000" }).valid()).toBe(false);
    expect(verifyBundle(zip, { expectUntil: new Date(b.now + 86400000) }).valid()).toBe(false);
  });

  it("reports unreadable bundles", () => {
    expect(codes(verifyBundle(new TextEncoder().encode("not a zip")))).toEqual(new Set(["bad_bundle"]));
    const b = new Builder().standard();
    expect(codes(verifyBundle(writeBundle(b, undefined, { format: 9 })))).toEqual(new Set(["format_version"]));
    expect(codes(verifyBundle(zipBundle({ "records.jsonl": "" })))).toEqual(new Set(["bad_bundle"]));
    expect(codes(verifyBundle(zipBundle({ "manifest.json": "[]", "records.jsonl": "" })))).toEqual(new Set(["bad_bundle"]));
    expect(codes(verifyBundle(zipBundle({ "manifest.json": "{", "records.jsonl": "" })))).toEqual(new Set(["bad_bundle"]));
    expect(codes(verifyBundle(zipBundle({ "manifest.json": '{"format":1}', "records.jsonl": "{bad\n" })))).toEqual(
      new Set(["bad_bundle"]),
    );
    expect(codes(verifyBundle(new Uint8Array(0)))).toEqual(new Set(["bad_bundle"]));
  });

  it("requires anchors when asked (stripped receipts, non-independent anchors)", () => {
    const b = new Builder().standard();
    const forged = new Builder({ key: b.key });
    for (let s = 0; s < 3; s++) {
      for (let i = 0; i < 4; i++) forged.action(s * 100 + i);
      forged.segment();
    }
    expect(verifyRecords(forged.records).valid()).toBe(true);
    expect(codes(verifyRecords(forged.records, { requireAnchor: "rekor" })).has("anchor_required")).toBe(true);
    const r = verifyRecords(b.records, { anchorOptions: { localAnchorEntries: b.anchorLog }, requireAnchor: "rekor" });
    expect(codes(r).has("anchor_required")).toBe(true);
  });

  it("never throws on malformed input", () => {
    const bads: unknown[] = [
      [{ seq: 0 }],
      [null],
      ["string"],
      [{ kind: "genesis", seq: 0, v: 1, public_key: "x" }],
      [{ kind: "genesis", seq: 0, v: 1, public_key: { id: 1, public: 2 } }],
      [{ kind: "genesis", seq: 0, v: 1, public_key: { id: "x", public: "ed25519:@@" } }],
      "not a list",
      [[]],
      [{ kind: "genesis", seq: 0, v: 1, public_key: { id: [], public: "ed25519:AAAA" } }],
    ];
    for (const bad of bads) {
      const r = verifyRecords(bad);
      expect(r.valid(), JSON.stringify(bad)).toBe(false);
    }
  });

  it("reports unencodable values instead of throwing", () => {
    const b = new Builder().standard();
    const recs = b.copy();
    recs[3]!["args"]["amount"] = 2 ** 60; // a JS number beyond 2^53: canonicalizes like a float, signature fails
    recs[4]!["args"]["amount"] = NaN;
    const r = verifyRecords(recs);
    expect(r.valid()).toBe(false);
    expect(codes(r).has("unencodable")).toBe(true);
  });

  it("reports hostile segment and anchor fields", () => {
    const b = new Builder().standard();
    const mutations: Array<(recs: Rec[]) => void> = [
      (r) => (r[5]!["segment"]["from"] = "x"),
      (r) => (r[5]!["segment"]["opened_at"] = "yesterday"),
      (r) => (r[5]!["segment"] = []),
      (r) => (r[5]!["segment"]["count"] = 1e300),
      (r) => (r[5]!["segment"]["from"] = -1e300),
      (r) => (r[6]!["anchor"] = { segment_seq: [], type: {} }),
      (r) => (r[6]!["anchor"]["type"] = []),
      (r) => (r[6]!["anchor"]["receipt"] = null),
      (r) => (r[0]!["config"] = { heartbeat_seconds: "x" }),
      (r) => (r[0]!["config"] = { heartbeat_seconds: 1e308 }),
      (r) => (r[0]!["config"] = []),
    ];
    for (const m of mutations) {
      const recs = b.copy();
      m(recs);
      resign(recs, b.key, 0);
      const r = verifyRecords(recs, { anchorOptions: { localAnchorEntries: b.anchorLog } });
      expect(r.findings.length, m.toString()).toBeGreaterThan(0);
    }
  });

  it("checks trusted timestamps against segment close (stub verifier)", () => {
    const chainWith = (delayS: number) => {
      const b = new Builder();
      const segs: Rec[] = [];
      for (let i = 0; i < 3; i++) {
        b.action(i);
        segs.push(b.segment());
      }
      for (const s of segs) {
        b.add({ kind: "anchor", anchor: { segment_seq: s["seq"], segment_hash: recordHash(s), type: "rfc3161", receipt: {} } });
      }
      const closes = new Map(segs.map((s) => [s["seq"], s["segment"]["closed_at"] as string]));
      const stub: AnchorVerifier = (a) => {
        const t = Date.parse(closes.get((a as Rec)["segment_seq"])!) + delayS * 1000;
        return anchorResult(true, "stub", true, new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z"));
      };
      return { b, verifiers: { rfc3161: stub } };
    };
    let { b, verifiers } = chainWith(5);
    let r = verifyRecords(b.records, { anchorVerifiers: verifiers, requireAnchor: ["rfc3161"], maxAnchorDelay: 600 });
    expect(r.valid(), JSON.stringify(r.findings)).toBe(true);
    expect(r.summary["segments_timestamped"]).toBe(3);
    ({ b, verifiers } = chainWith(3 * 86400));
    r = verifyRecords(b.records, { anchorVerifiers: verifiers, maxAnchorDelay: 3600 });
    expect(codes(r).has("late_timestamp")).toBe(true);
    expect(r.errors.find((f) => f.code === "late_timestamp")!.message).toBe(
      "segment timestamped 259200s after it closed (limit 3600s): history may have been rebuilt later",
    );
    const r2 = verifyRecords(b.records, { anchorVerifiers: verifiers });
    expect(r2.valid()).toBe(true);
    expect(warnCodes(r2).has("late_timestamp")).toBe(true);
    const missing = new Builder().standard();
    expect(codes(verifyRecords(missing.records, { requireAnchor: ["rfc3161"] })).has("anchor_required")).toBe(true);
  });
});

// ---- property tests: any edit, deletion, reorder or truncation must be caught -------------

describe("tamper property tests", () => {
  const BASE = new Builder().standard(3, 4);
  const N = BASE.records.length;
  const MANIFEST = { chain: BASE.chain, from_seq: 1, to_seq: BASE.records[N - 1]!["seq"], format: 1 };
  const opts: VerifyOptions = {
    manifest: MANIFEST,
    anchorOptions: { localAnchorEntries: BASE.anchorLog },
    expectKey: BASE.key.id,
    expectUntil: new Date(BASE.now),
  };
  const invalid = (records: Rec[]) => !verifyRecords(records, opts).valid();
  const rand = rng(1234);
  const pick = (n: number) => Math.floor(rand() * n);

  it("the base chain is valid", () => {
    const r = verifyRecords(BASE.records, opts);
    expect(r.valid(true), JSON.stringify(r.findings)).toBe(true);
  });

  it("any field edit fails (300 random edits)", () => {
    const values: unknown[] = [0, 1, -1, 42, 2 ** 31, "", "x", "sha256:" + "0".repeat(64), true, false, null, 1.5];
    for (let n = 0; n < 300; n++) {
      const recs = structuredClone(BASE.records);
      const i = pick(N);
      const all = pathsList(recs[i]);
      const path = all[pick(all.length)]!;
      let target: any = recs[i];
      for (const k of path.slice(0, -1)) target = target[k];
      const last = path[path.length - 1]!;
      const old = target[last];
      let nv = values[pick(values.length)];
      while (nv === old || (typeof nv === typeof old && JSON.stringify(nv) === JSON.stringify(old))) nv = values[pick(values.length)];
      target[last] = nv;
      expect(invalid(recs), `record ${i} path ${path.join(".")} -> ${JSON.stringify(nv)}`).toBe(true);
    }
  });

  function pathsList(obj: unknown): Array<Array<string | number>> {
    const out: Array<Array<string | number>> = [];
    const walk = (o: unknown, p: Array<string | number>) => {
      if (Array.isArray(o)) o.forEach((v, i) => walk(v, [...p, i]));
      else if (o && typeof o === "object") for (const [k, v] of Object.entries(o)) walk(v, [...p, k]);
      else out.push(p);
    };
    walk(obj, []);
    return out;
  }

  it("any single deletion fails", () => {
    for (let i = 0; i < N; i++) {
      const recs = structuredClone(BASE.records);
      recs.splice(i, 1);
      expect(invalid(recs), `delete ${i}`).toBe(true);
    }
  });

  it("any swap of two records fails", () => {
    for (let i = 0; i < N - 1; i++) {
      for (let j = i + 1; j < N; j++) {
        const recs = structuredClone(BASE.records);
        [recs[i], recs[j]] = [recs[j]!, recs[i]!];
        expect(invalid(recs), `swap ${i} ${j}`).toBe(true);
      }
    }
  });

  it("any truncation fails", () => {
    for (let k = 1; k < N; k++) expect(invalid(structuredClone(BASE.records.slice(0, k))), `truncate to ${k}`).toBe(true);
  });

  it("any truncation with a rewritten manifest fails given the known head", () => {
    const last = BASE.records[N - 1]!;
    const head = { seq: last["seq"] as number, hash: recordHash(last) };
    for (let k = 1; k < N; k++) {
      const recs = structuredClone(BASE.records.slice(0, k));
      const r = verifyRecords(recs, {
        manifest: { ...MANIFEST, to_seq: recs[recs.length - 1]!["seq"] },
        anchorOptions: { localAnchorEntries: BASE.anchorLog },
        knownHead: head,
      });
      expect(r.valid(), `truncate to ${k}`).toBe(false);
    }
  });

  it("any inserted copy fails", () => {
    for (let i = 1; i < N; i++) {
      const recs = structuredClone(BASE.records);
      const forged = structuredClone(recs[i]!);
      forged["id"] = "forged";
      recs.splice(i, 0, forged);
      expect(invalid(recs), `insert at ${i}`).toBe(true);
    }
  });

  it("a signed insert by the key holder breaks the segment or anchor", () => {
    const recs = structuredClone(BASE.records);
    const forged = structuredClone(recs[2]!);
    forged["id"] = "forged";
    recs.splice(3, 0, forged);
    recs.forEach((r, n) => (r["seq"] = n));
    resign(recs, BASE.key, 3);
    expect(invalid(recs)).toBe(true);
  });

  it("dropping any segment fails", () => {
    const segs = BASE.records.flatMap((r, i) => (r["kind"] === "segment" ? [i] : []));
    for (const s of segs) {
      const recs = structuredClone(BASE.records);
      recs.splice(s, 1);
      expect(invalid(recs)).toBe(true);
    }
  });
});

describe("Python-compatible message formatting", () => {
  it("formats findings like the reference", () => {
    const b = new Builder().standard();
    const recs = b.copy();
    recs.splice(2, 2);
    const r = run(recs, b);
    const gap = r.errors.find((f) => f.code === "gap")!;
    expect(gap.message).toBe("records 2..3 are missing");
    expect(gap.seq).toBe(4);
  });

  it("coverage message uses Python isoformat", () => {
    const b = new Builder().standard();
    const r = run(b, undefined, { expectUntil: "2027-01-01T00:00:00.500Z" });
    expect(r.errors.find((f) => f.code === "coverage")!.message).toBe(
      `records end at ${b.records.filter((x) => x["kind"] === "segment").pop()!["segment"]["closed_at"]}, earlier than expected 2027-01-01T00:00:00.500000+00:00 (truncated?)`,
    );
    // Strict RFC 3339: 1 to 6 fraction digits, a "T" separator and an explicit offset.
    expect(() => run(b, undefined, { expectUntil: "2027-01-01T00:00:00.5Z" })).not.toThrow();
    expect(() => run(b, undefined, { expectUntil: "2027-01-01 00:00:00Z" })).toThrow(RangeError);
  });

  it("time helpers", () => {
    expect(iso(0)).toBe("1970-01-01T00:00:00.000Z");
  });
});
