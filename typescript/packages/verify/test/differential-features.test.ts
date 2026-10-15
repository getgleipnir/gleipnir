/**
 * Differential tests against the Python reference for ECDSA P-256 keys, approvals bound to
 * actions, single-action proofs and reconcile. Skipped when `uv` is not available.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  actionDigest,
  b64uEncode,
  bytesToHex,
  externalIds,
  hexToBytes,
  keyId,
  decodePublicKey,
  parseCsvRows,
  parseJsonl,
  reconcile,
  recordHash,
  recordMessage,
  verifyBundle,
  verifyRecords,
  verifySignature,
} from "@getgleipnir/verify";
import { Builder, Key, P256Key, proofFiles, proofZip, resign, rng, writeBundle, zipBundle, type Rec } from "./chainbuilder.js";
import { normalizeReport, oracle, pythonAvailable, stripExceptionText, toTsOptions } from "./oracle.js";

const d = pythonAvailable ? describe : describe.skip;

function tlv(tag: number, body: Uint8Array): Uint8Array {
  const n = body.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Uint8Array.from([tag, ...len, ...body]);
}
const cat = (...p: Uint8Array[]) => Uint8Array.from(p.flatMap((x) => [...x]));
const h = hexToBytes;
const EC = h("06072a8648ce3d0201");
const P256 = h("06082a8648ce3d030107");
function spkiOf(params: Uint8Array, bits: Uint8Array, alg = EC): Uint8Array {
  return tlv(0x30, cat(tlv(0x30, cat(alg, params)), tlv(0x03, bits)));
}

d("differential: ECDSA P-256 record keys", () => {
  it("decodes public keys and derives key ids exactly as the reference", () => {
    const k = new P256Key();
    const point = k.spki.subarray(k.spki.length - 65);
    const compressed = Uint8Array.from([2 + (point[64]! & 1), ...point.subarray(1, 33)]);
    const hybrid = Uint8Array.from([6 + (point[64]! & 1), ...point.subarray(1)]);
    const hybridBad = Uint8Array.from([7 - (point[64]! & 1), ...point.subarray(1)]);
    const offCurve = Uint8Array.from(point);
    offCurve[64]! ^= 1;
    const oid = (dotted: string) => {
      const parts = dotted.split(".").map(Number);
      const body = [parts[0]! * 40 + parts[1]!];
      for (const p of parts.slice(2)) {
        const enc = [p & 0x7f];
        let x = p >>> 7;
        while (x) {
          enc.unshift(0x80 | (x & 0x7f));
          x >>>= 7;
        }
        body.push(...enc);
      }
      return tlv(0x06, Uint8Array.from(body));
    };
    const ders: Uint8Array[] = [
      k.spki,
      cat(k.spki, Uint8Array.of(0)),
      spkiOf(P256, cat(Uint8Array.of(0), compressed)),
      spkiOf(P256, cat(Uint8Array.of(0), hybrid)),
      spkiOf(P256, cat(Uint8Array.of(0), hybridBad)),
      spkiOf(P256, cat(Uint8Array.of(0), offCurve)),
      spkiOf(P256, Uint8Array.of(0, 0)),
      spkiOf(P256, Uint8Array.of(0, 0xaa)),
      spkiOf(P256, Uint8Array.of(1, 0xaa)),
      spkiOf(P256, Uint8Array.of()),
      spkiOf(h("0500"), cat(Uint8Array.of(0), point)),
      spkiOf(h(""), cat(Uint8Array.of(0), point)),
      spkiOf(h("3000"), cat(Uint8Array.of(0), point)),
      spkiOf(h("020101"), cat(Uint8Array.of(0), point)),
      spkiOf(cat(P256, h("0500")), cat(Uint8Array.of(0), point)),
      h("3000"),
      h(""),
      h("30"),
      h("300e300706032a03040500030300aabb"),
      h("300c300506032a0304030300aabb"),
      spkiOf(h("0500"), Uint8Array.of(0, 0xaa), oid("1.3.101.112")),
      spkiOf(h(""), Uint8Array.of(0, 0xaa), oid("1.3.101.112")),
      spkiOf(h(""), Uint8Array.of(0, 0xaa), oid("1.2.840.113549.1.1.1")),
      spkiOf(h(""), Uint8Array.of(0, 0xaa), oid("1.2.156.10197.1.301")),
    ];
    for (const curve of ["1.2.840.10045.3.1.1", "1.3.132.0.10", "1.3.132.0.34", "1.3.36.3.3.2.8.1.1.7", "1.3.132.0.1", "1.2.3", "1.2.840.10045.3.1.7"]) {
      ders.push(spkiOf(oid(curve), Uint8Array.of(0, 0xaa)));
      ders.push(spkiOf(oid(curve), cat(Uint8Array.of(0), point)));
    }
    // a 30 81 long-form length where short form would do (not DER)
    ders.push(cat(h("3081"), k.spki.subarray(1)));
    const texts: unknown[] = ders.map((x) => "ecdsa-p256:" + b64uEncode(x));
    texts.push("ecdsa-p256:", "ecdsa-p256:a", "ecdsa-p256:!!", "ecdsa-p256:" + b64uEncode(k.spki) + "==", "ed25519:", "", "ECDSA-P256:x", "p256:x");
    const py = oracle(texts.map((text) => ({ kind: "pubkey", text })));
    texts.forEach((text, i) => {
      let ts: unknown;
      try {
        ts = { key_id: keyId(decodePublicKey(text)) };
      } catch (e) {
        ts = { error: (e as Error).name };
      }
      expect(ts, `${String(text).slice(0, 60)} (${i})`).toEqual(py[i]);
    });
  });

  it("accepts and rejects the same signatures", () => {
    const k = new P256Key();
    const msg = "gleipnir/record/v1\nsha256:" + "ab".repeat(32);
    const good = k.sign("sha256:" + "ab".repeat(32));
    const der = Uint8Array.from(Buffer.from(good.slice("ecdsa-p256:".length), "base64url"));
    const n = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    // parse r, s
    const rl = der[3]!;
    const r = BigInt("0x" + bytesToHex(der.subarray(4, 4 + rl)));
    const s = BigInt("0x" + bytesToHex(der.subarray(6 + rl)));
    const int = (v: bigint, pad = 0) => {
      let hex = v.toString(16);
      if (hex.length % 2) hex = "0" + hex;
      let b = h(hex);
      if (b[0]! & 0x80) b = cat(Uint8Array.of(0), b);
      for (let i = 0; i < pad; i++) b = cat(Uint8Array.of(0), b);
      return tlv(0x02, b);
    };
    const sig = (a: Uint8Array) => "ecdsa-p256:" + b64uEncode(a);
    const sigs = [
      good,
      sig(tlv(0x30, cat(int(r), int(n - s)))), // high S: accepted, as by OpenSSL
      sig(cat(der, Uint8Array.of(0))),
      sig(tlv(0x30, cat(int(0n), int(s)))),
      sig(tlv(0x30, cat(int(r), int(0n)))),
      sig(tlv(0x30, cat(int(r), int(n)))),
      sig(tlv(0x30, cat(int(r + n), int(s)))),
      sig(tlv(0x30, cat(int(r, 1), int(s)))),
      sig(cat(h("3081"), der.subarray(1))),
      sig(Uint8Array.of()),
      sig(cat(h(r.toString(16).padStart(64, "0")), h(s.toString(16).padStart(64, "0")))),
      good + "==",
      good.replace(/-/g, "+").replace(/_/g, "/"),
      good.slice(0, 20) + "!" + good.slice(20),
      good.replace("ecdsa-p256:", "ed25519:"),
      "ecdsa-p256:a",
    ];
    const py = oracle(sigs.map((sg) => ({ kind: "sig", public: k.public, message: msg, sig: sg })));
    const pub = decodePublicKey(k.public);
    sigs.forEach((sg, i) => {
      expect(verifySignature(pub, recordMessage("sha256:" + "ab".repeat(32)), sg), `sig ${i}`).toBe(py[i].ok);
    });
  });

  it("verification reports match for P-256 chains, mixed rotations and tampering", () => {
    const cases: Array<{ name: string; records: Rec[]; options?: Record<string, unknown> }> = [];
    const pk = new P256Key();
    const b = new Builder({ key: pk }).standard(2, 3);
    cases.push({ name: "p256 chain", records: b.records, options: { local_anchor_entries: b.anchorLog, expect_key: pk.id } });
    cases.push({ name: "p256 wrong expect", records: b.records, options: { expect_key: "k_p256_0000000000000000" } });
    // Ed25519 -> P-256 -> Ed25519
    const mixed = new Builder();
    mixed.action(1);
    const p = new P256Key();
    mixed.rotate(p);
    mixed.action(2);
    const e = new Key();
    mixed.rotate(e);
    mixed.action(3);
    mixed.anchor(mixed.segment());
    cases.push({ name: "rotation ed->p256->ed", records: mixed.records, options: { local_anchor_entries: mixed.anchorLog } });
    // stale P-256 key after rotating away from it
    const stale = structuredClone(mixed.records);
    resign(stale, p, stale.length - 3);
    cases.push({ name: "stale p256 key", records: stale });
    // a P-256 signature presented for an Ed25519 key id and vice versa
    const swap = structuredClone(b.records);
    swap[2]!["sig"] = (swap[2]!["sig"] as string).replace("ecdsa-p256:", "ed25519:");
    cases.push({ name: "sig prefix swapped", records: swap });
    // genesis key id that does not match its P-256 key, bad P-256 rotation
    const badId = structuredClone(b.records);
    badId[0]!["public_key"]["id"] = "k_p256_ffffffffffffffff";
    cases.push({ name: "p256 key id mismatch", records: badId });
    const badRot = new Builder();
    badRot.add({ kind: "key_rotation", new_key: { id: "k_p256_0000000000000000", public: "ecdsa-p256:MFkw" } });
    cases.push({ name: "bad p256 rotation", records: badRot.records });
    const rand = rng(23);
    for (let n = 0; n < 60; n++) {
      const recs = structuredClone(b.records);
      const i = Math.floor(rand() * recs.length);
      const sig = recs[i]!["sig"] as string;
      const pos = 11 + Math.floor(rand() * (sig.length - 11));
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      recs[i]!["sig"] = sig.slice(0, pos) + chars[Math.floor(rand() * 64)] + sig.slice(pos + 1);
      cases.push({ name: `p256 sig flip ${n}`, records: recs });
    }
    const py = oracle(cases.map((c) => ({ kind: "records", text: c.records.map((r) => JSON.stringify(r)).join("\n"), options: c.options ?? {} })));
    cases.forEach((c, i) => {
      const recs = parseJsonl(c.records.map((r) => JSON.stringify(r)).join("\n"));
      const ts = normalizeReport(verifyRecords(recs, toTsOptions(c.options)).toJSON());
      expect(stripExceptionText(ts), c.name).toEqual(stripExceptionText(py[i]));
    });
  });
});

d("differential: approvals bound to actions", () => {
  it("action digests are identical", () => {
    const inputs = [
      ["refund", "pay", { order: "A1", amount: 5 }],
      ["refund", null, null],
      ["t", "s", { card: { redacted: "hmac-sha256:00" }, n: [1, 2.5, -0, 1e21], u: "Grüße \u{1f600}" }],
      [1, true, []],
    ];
    const py = oracle(inputs.map((x) => ({ kind: "digest", text: JSON.stringify(x) })));
    inputs.forEach((x, i) => expect({ digest: actionDigest(x[0], x[1], x[2]) }, JSON.stringify(x)).toEqual(py[i]));
  });

  it("reports match for approved, mismatched, late, rejected, missing and hostile approvals", () => {
    const cases: Array<{ name: string; records: Rec[] | string; options?: Record<string, unknown> }> = [];
    const mk = () => {
      const b = new Builder();
      return b;
    };
    // approved and executed as approved
    let b = mk();
    let id = b.approve({ order: "o1", amount: 1 });
    b.action(1, { approval: id });
    b.anchor(b.segment());
    cases.push({ name: "approved", records: b.records, options: { local_anchor_entries: b.anchorLog } });
    // executed with different args / tool / system
    for (const [name, extra] of [
      ["args differ", { args: { order: "o1", amount: 1000 } }],
      ["tool differs", { tool: { name: "delete", system: "pay" } }],
      ["system differs", { tool: { name: "refund", system: "other" } }],
      ["tool not object", { tool: "refund" }],
      ["no tool", { tool: undefined }],
      ["args missing", { args: undefined }],
    ] as const) {
      b = mk();
      id = b.approve({ order: "o1", amount: 1 });
      const ex: Rec = { approval: id, ...extra };
      for (const k of Object.keys(ex)) if (ex[k] === undefined) delete ex[k];
      const rec = b.action(1, ex);
      if (extra && "tool" in extra && extra.tool === undefined) {
        delete rec["tool"];
        resign(b.records, b.key, b.records.length - 1);
      }
      if (extra && "args" in extra && extra.args === undefined) {
        delete rec["args"];
        resign(b.records, b.key, b.records.length - 1);
      }
      b.anchor(b.segment());
      cases.push({ name, records: b.records });
    }
    // rejected review, and a review with no review body
    b = mk();
    id = b.approve({ order: "o1", amount: 1 }, { decision: "rejected" });
    b.action(1, { approval: id });
    cases.push({ name: "rejected", records: b.records });
    b = mk();
    const bare = b.add({ kind: "review", review: "yes" });
    b.action(1, { approval: bare["id"] });
    cases.push({ name: "review not object", records: b.records });
    // approval recorded after the action
    b = mk();
    b.action(1, { approval: "rev_late" });
    b.add({ kind: "review", id: "rev_late", review: { action_digest: actionDigest("refund", "pay", { order: "o1", amount: 1 }), decision: "approved" } });
    cases.push({ name: "approval after action", records: b.records });
    // approval references itself / missing / not a string / unhashable
    for (const [name, approval] of [["missing", "rev_nope"], ["number", 7], ["null", null], ["list", ["x"]], ["dict", { a: 1 }], ["bool", true]] as const) {
      b = mk();
      b.action(1, { approval });
      b.anchor(b.segment());
      cases.push({ name: `approval ${name}`, records: b.records });
    }
    // one approval used by several actions: approval_reused from the second on
    b = mk();
    id = b.approve({ order: "o1", amount: 1 });
    b.action(1, { approval: id });
    b.action(1, { approval: id });
    b.action(2, { approval: id });
    cases.push({ name: "approval reused", records: b.records });
    // reuse with non-string approvals (repr keys; 1 and true collide like Python dict keys)
    b = mk();
    b.action(1, { approval: 1 });
    b.action(1, { approval: true });
    b.action(1, { approval: 1.0 });
    b.action(1, { approval: ["x"] });
    b.action(1, { approval: ["x"] });
    b.action(1, { approval: { a: 1 } });
    b.action(1, { approval: null });
    b.action(1, { approval: null });
    b.action(1, { approval: "1" });
    cases.push({ name: "approval reused, odd types", records: b.records });
    // reuse in a partial bundle: the approval is outside, reuse is still an error
    b = mk();
    id = b.approve({ order: "o1", amount: 1 });
    const segR = b.segment();
    b.anchor(segR);
    b.action(1, { approval: id });
    b.action(1, { approval: id });
    b.anchor(b.segment());
    cases.push({ name: "partial: approval reused", records: [b.records[0]!, ...b.records.slice(b.records.indexOf(segR) + 1)], options: { local_anchor_entries: b.anchorLog } });
    // two reviews with the same id: the later one wins in both
    b = mk();
    b.add({ kind: "review", id: "dup", review: { action_digest: actionDigest("refund", "pay", { order: "o1", amount: 1 }), decision: "approved" } });
    b.add({ kind: "review", id: "dup", review: { action_digest: "sha256:00", decision: "approved" } });
    b.action(1, { approval: "dup" });
    cases.push({ name: "duplicate review ids", records: b.records });
    // review ids of other types (1 and 1.0 and true collide in Python dicts)
    b = mk();
    b.add({ kind: "review", id: 1, review: { action_digest: actionDigest("refund", "pay", { order: "o1", amount: 1 }), decision: "approved" } });
    b.action(1, { approval: true });
    cases.push({ name: "numeric review id", records: b.records });
    // missing approval in a partial bundle is a warning
    b = mk();
    id = b.approve({ order: "o1", amount: 1 });
    const seg1 = b.segment();
    b.anchor(seg1);
    b.action(1, { approval: id });
    b.anchor(b.segment());
    const segIdx = b.records.indexOf(seg1);
    cases.push({ name: "partial: approval outside", records: [b.records[0]!, ...b.records.slice(segIdx + 1)], options: { local_anchor_entries: b.anchorLog } });
    cases.push({ name: "partial: approval outside, require full", records: [b.records[0]!, ...b.records.slice(segIdx + 1)], options: { local_anchor_entries: b.anchorLog, require_full: true } });
    // an approved review with a bad action_digest type
    b = mk();
    b.add({ kind: "review", id: "r", review: { action_digest: ["x"], decision: "approved" } });
    b.action(1, { approval: "r" });
    cases.push({ name: "digest list", records: b.records });
    // action args that cannot be canonicalized: a lone surrogate
    b = mk();
    b.add({ kind: "review", id: "r2", review: { action_digest: "sha256:x", decision: "approved" } });
    cases.push({ name: "uncanon base", records: b.records });

    const py = oracle(
      cases.map((c) => ({ kind: "records", text: typeof c.records === "string" ? c.records : c.records.map((r) => JSON.stringify(r)).join("\n"), options: c.options ?? {} })),
    );
    cases.forEach((c, i) => {
      const text = typeof c.records === "string" ? c.records : c.records.map((r) => JSON.stringify(r)).join("\n");
      const ts = normalizeReport(verifyRecords(parseJsonl(text), toTsOptions(c.options)).toJSON());
      expect(stripExceptionText(ts), c.name).toEqual(stripExceptionText(py[i]));
    });
  });
});

d("differential: single-action proofs", () => {
  it("verifyBundle reports match for good, tampered and hostile proofs", () => {
    const dir = mkdtempSync(join(tmpdir(), "gleipnir-proof-"));
    const items: Array<[string, Uint8Array, Record<string, unknown>]> = [];
    for (const [label, key] of [["ed25519", new Key()], ["p256", new P256Key()]] as const) {
      const b = new Builder({ key });
      for (let i = 0; i < 7; i++) b.action(i);
      const seg = b.segment();
      b.anchor(seg);
      b.action(99);
      b.anchor(b.segment());
      const actions = b.records.filter((r) => r["kind"] === "action");
      for (const a of [actions[0]!, actions[3]!, actions[6]!, actions[7]!]) {
        const { manifest, records } = proofFiles(b, a["id"]);
        items.push([`${label} proof ${a["id"]}`, proofZip(b, manifest, records), { expect_key: key.id }]);
      }
      const target = actions[3]!;
      const base = proofFiles(b, target["id"]);
      const variant = (name: string, mut: (m: Rec, r: Rec[]) => void, opts: Record<string, unknown> = {}) => {
        const m = structuredClone(base.manifest);
        const r = structuredClone(base.records);
        mut(m, r);
        const { no_log, ...rest } = opts;
        const { float_fields, ...rest2 } = rest as { float_fields?: string[] };
        let zip = no_log
          ? zipBundle({ "manifest.json": JSON.stringify(m), "records.jsonl": r.map((x) => JSON.stringify(x)).join("\n") })
          : proofZip(b, m, r);
        if (float_fields) {
          // JSON float literals (3.0) that JSON.stringify cannot write: Python reads them as floats.
          let text = JSON.stringify(m);
          for (const f of float_fields) text = text.replace(new RegExp(`"${f}":(-?\\d+)`), `"${f}":$1.0`);
          zip = zipBundle({
            "manifest.json": text,
            "records.jsonl": r.map((x) => JSON.stringify(x)).join("\n"),
            "anchors/local-anchor-log.jsonl": b.anchorLog.map((e) => JSON.stringify(e) + "\n").join(""),
          });
        }
        items.push([`${label} ${name}`, zip, rest2]);
      };
      variant("wrong expect key", () => {}, { expect_key: "k_ed25519_0000000000000000" });
      variant("require rekor", () => {}, { require_anchor: ["rekor"] });
      variant("tampered action", (_m, r) => (r[1]!["args"]["order"] = "other"));
      variant("tampered and re-signed", (_m, r) => {
        r[1]!["args"]["order"] = "other";
        delete r[1]!["sig"];
        r[1]!["sig"] = key.sign(recordHash(r[1]!));
      });
      variant("wrong leaf index", (m) => (m["leaf_index"] = 2));
      variant("float leaf index", (m) => (m["leaf_index"] = 3.0));
      variant("wrong tree size", (m) => (m["tree_size"] = 8));
      variant("string tree size", (m) => (m["tree_size"] = "7"));
      variant("path flipped", (m) => (m["proof"][0] = "00" + m["proof"][0].slice(2)));
      variant("path short", (m) => m["proof"].pop());
      variant("path empty", (m) => (m["proof"] = []));
      variant("path not hex", (m) => (m["proof"][0] = "zz"));
      variant("path not list", (m) => (m["proof"] = "abcd"));
      variant("path numbers", (m) => (m["proof"] = [1, 2]));
      variant("no proof key", (m) => delete m["proof"]);
      variant("other action named", (m) => (m["action"] = "nope"));
      variant("no action named", (m) => delete m["action"]);
      variant("segment swapped for action", (_m, r) => ([r[1], r[2]] = [r[2]!, r[1]!]));
      variant("only two records", (_m, r) => r.splice(2));
      variant("no genesis", (_m, r) => r.shift());
      variant("anchor for other segment", (_m, r) => (r[3]!["anchor"]["segment_hash"] = "sha256:" + "00".repeat(32)));
      variant("unknown anchor type", (_m, r) => (r[3]!["anchor"]["type"] = "carrier-pigeon"));
      variant("anchor is a note", (_m, r) => (r[3]!["kind"] = "note"));
      variant("local log entry wrong", (_m, r) => (r[3]!["anchor"]["receipt"]["entry_hash"] = "sha256:" + "11".repeat(32)));
      variant("record from other chain", (_m, r) => (r[1]!["chain"] = "ch_other"));
      variant("v2 record", (_m, r) => (r[2]!["v"] = 2));
      variant("action key differs", (_m, r) => (r[1]!["key"] = "k_x"));
      variant("genesis key id wrong", (_m, r) => (r[0]!["public_key"]["id"] = "k_ed25519_0000000000000000"));
      variant("genesis key garbage", (_m, r) => (r[0]!["public_key"]["public"] = "rsa:abc"));
      variant("genesis without public_key", (_m, r) => delete r[0]!["public_key"]);
      variant("action seq float", (_m, r) => (r[1]!["seq"] = 4.5));
      variant("action seq string", (_m, r) => (r[1]!["seq"] = "4"));
      variant("action without seq", (_m, r) => delete r[1]!["seq"]);
      variant("segment without seq", (_m, r) => delete r[2]!["seq"]);
      variant("segment body missing", (_m, r) => delete r[2]!["segment"]);
      variant("segment from string", (_m, r) => (r[2]!["segment"]["from"] = "1"));
      variant("segment from junk", (_m, r) => (r[2]!["segment"]["from"] = "x"));
      variant("segment root bad", (_m, r) => (r[2]!["segment"]["root"] = "sha256:00"));
      variant("record not object", (_m, r) => ((r as unknown[])[3] = [1, 2]));
      variant("extra unrelated record", (_m, r) => r.push(structuredClone(b.records[2]!)));
      variant("unencodable record", (_m, r) => (r[1]!["x"] = 2 ** 60));
      variant("manifest chain differs", (m) => (m["chain"] = "ch_other"));
      variant("manifest chain missing", (m) => delete m["chain"]);
      variant("manifest key differs", (m) => (m["key"] = "k_ed25519_0000000000000000"));
      variant("manifest key null", (m) => (m["key"] = null));
      variant("leaf index string", (m) => (m["leaf_index"] = "3"));
      variant("leaf index bool", (m) => (m["leaf_index"] = true));
      variant("leaf index null", (m) => (m["leaf_index"] = null));
      variant("leaf index big", (m) => (m["leaf_index"] = 2 ** 60));
      variant("tree size float", () => {}, { float_fields: ["tree_size"] });
      variant("leaf index float", () => {}, { float_fields: ["leaf_index"] });
      variant("path dict", (m) => (m["proof"] = { a: 1 }));
      variant("path null", (m) => (m["proof"] = null));
      variant("path odd hex", (m) => (m["proof"][0] = "abc"));
      variant("action seq string, index string", (m, r) => {
        m["leaf_index"] = "3";
        r[1]!["seq"] = "4";
      });
      variant("no anchors", (_m, r) => r.splice(3));
      variant("two unknown anchors", (_m, r) => {
        r[3]!["anchor"]["type"] = "x";
        r.push(structuredClone(r[3]!));
      });
      variant("anchor not checked (no log)", () => {}, { no_log: true });
      variant("manifest type proof only", (m) => {
        for (const k of Object.keys(m)) if (k !== "format" && k !== "type") delete m[k];
      });
    }
    // a proof for a one-member segment (empty path)
    const one = new Builder();
    one.action(1);
    one.anchor(one.segment());
    const p1 = proofFiles(one, one.records[1]!["id"]);
    items.push(["one-member segment", proofZip(one, p1.manifest, p1.records), {}]);
    const p1f = structuredClone(p1.manifest);
    p1f["leaf_index"] = 0.0;
    items.push(["one-member float index", proofZip(one, { ...p1f, leaf_index: 0.5 }, p1.records), {}]);
    // a regular bundle is unaffected by "type"
    const bb = new Builder().standard(2, 2);
    items.push(["bundle type other", writeBundle(bb, undefined, { format: 1, chain: bb.chain, type: "bundle" }), {}]);

    const cases = items.map(([name, bytes, options]) => {
      const p = join(dir, name.replace(/\W/g, "_") + ".zip");
      writeFileSync(p, bytes);
      return { kind: "bundle", path: p, options };
    });
    const py = oracle(cases);
    items.forEach(([name, bytes, options], i) => {
      const ts = normalizeReport(verifyBundle(bytes, toTsOptions(options)).toJSON());
      expect(stripExceptionText(ts), name).toEqual(stripExceptionText(py[i]));
    });
  });
});

d("differential: reconcile", () => {
  it("external ids are identical", () => {
    const bodies: Array<[unknown, string | null]> = [
      [{ id: 5, refund_id: "R1", x: { customerId: "C9", flag: true }, items: [{ sku_id: "S" }] }, null],
      [{ id: 5, refund_id: "R1", x: { customerId: "C9", flag: true }, items: [{ sku_id: "S" }] }, "refund_id"],
      [{ id: 1.5, a_id: -3, b_id: 12345678901234567890, c_id: null, d_id: false, Id: "x", ID: "y", _id: "z" }, null],
      [[{ id: "a" }, [{ id: "b" }], "s", 1], null],
      [Array.from({ length: 1005 }, (_, i) => ({ id: `n${i}` })), null],
      ["str", null],
      [null, null],
      [{ nested: { deep: { refund_id: "R7" } }, refund_id: "R8" }, "refund_id"],
      [{ id: "", x_id: " pad " }, null],
    ];
    const py = oracle(bodies.map(([b, w]) => ({ kind: "ids", text: JSON.stringify(b), wanted: w })));
    bodies.forEach(([b, w], i) => {
      const parsed = parseJsonl(JSON.stringify(b))[0];
      expect([...externalIds(parsed, w)].sort(), JSON.stringify(b).slice(0, 60)).toEqual([...py[i].ids].sort());
    });
  });

  it("CSV rows parse as Python's csv module reads them", () => {
    const texts = [
      "a,b\n1,2\n", "a,b\r\n1,2\r\n", "a,b\r1,2\r", '"a",b\n"x""y",2\n', '"ab"cd,2\n', 'ab"cd,2\n', '"a\nb",c\n', '"abc',
      "a,b\n\n\n1,2\n", "\na,b\n1,2\n", "a,b,\n1\n", " a ,b\n 1 ,2\n", 'a\n"x"  \n', 'a\n "x"\n', "a,b\n1,2,3,4\n",
      '"a\r\nb"\n', "a\n1\r\n\r\n2", 'a\n"x\n', 'a\n""\n', 'a\n"""\n', 'a\nx"\n', 'a\n"x"y"z"\n', "a\rb\n", "", "\n",
      ",", ",\n,", "a,\"b\nc\"\r\nd", "é,€\n\u{1f600},x", "a b,c\n", "a\u0085b\n", "x\n\r\n\ry", '"a""', '""""',
    ];
    const py = oracle(texts.map((text) => ({ kind: "csv", text })));
    texts.forEach((text, i) => {
      let ts: unknown;
      try {
        ts = { rows: parseCsvRows(text) };
      } catch (e) {
        ts = { error: (e as Error).name };
      }
      expect(ts, JSON.stringify(text)).toEqual(py[i]);
    });
  });

  it("reconcile results match", () => {
    const dir = mkdtempSync(join(tmpdir(), "gleipnir-rec-"));
    const b = new Builder();
    ["R1", "R2", "R3"].forEach((rid, i) => b.action(i, { response: { status: "ok", body: { refund_id: rid, nested: { order_id: `O${i}` } } } }));
    b.action(9, { response: { status: "error", error: "boom" } });
    b.action(10, { response: { status: "ok", body: { refundId: "R4", refund_id: 77 } } });
    b.action(11, { response: "ok" });
    b.action(12, { response: ["ok"] });
    b.action(13, { response: null });
    b.anchor(b.segment());
    const bundle = writeBundle(b);
    const bp = join(dir, "b.zip");
    writeFileSync(bp, bundle);
    const bad = structuredClone(b.records);
    bad[1]!["args"]["order"] = "tampered";
    const badp = join(dir, "bad.zip");
    writeFileSync(badp, writeBundle(b, bad));
    const csvs: Array<[string, string, string, string | null]> = [
      ["basic", "refund_id,amount\nR1,10\nR2,20\nR9,99\n", "refund_id", null],
      ["all match", "refund_id\nR1\nR2\nR3\n77\n", "refund_id", null],
      ["bom and blanks", "﻿refund_id\n R1 \n\n,\nR2\n\"R3\"\n77\n", "refund_id", null],
      ["field differs", "rid\nR4\n", "rid", "refundId"],
      ["orders", "order_id\nO0\nO1\nO5\n", "order_id", null],
      ["missing column", "x\n1\n", "refund_id", null],
      ["empty csv", "", "refund_id", null],
      ["header only", "refund_id\n", "refund_id", null],
      ["duplicate header", "refund_id,refund_id\nA,R1\n", "refund_id", null],
      ["quoted multiline", 'refund_id,note\nR1,"a\nb"\n', "refund_id", null],
      ["short rows", "amount,refund_id\n10,R1\n5\n\n20\n,R2\n", "refund_id", null],
      ["short rows only", "amount,refund_id\n10\n", "refund_id", null],
    ];
    const cases: any[] = [];
    const ts: any[] = [];
    csvs.forEach(([name, text, column, field], i) => {
      const cp = join(dir, `c${i}.csv`);
      writeFileSync(cp, text);
      for (const [label, path, bytes] of [["good", bp, bundle], ["tampered", badp, null]] as const) {
        cases.push({ kind: "reconcile", bundle: path, csv: cp, column, field });
        let r: unknown;
        try {
          const res = reconcile(bytes ?? writeBundle(b, bad), new TextEncoder().encode(text), { column, field });
          r = {
            valid: res.report.valid(),
            matched: [...res.matched].sort(),
            only_in_system: [...res.onlyInSystem].sort(),
            only_in_records: [...res.onlyInRecords].sort(),
            ok: res.ok,
          };
        } catch (e) {
          r = { error: (e as Error).name };
        }
        ts.push([`${name} ${label}`, r]);
      }
    });
    const py = oracle(cases);
    ts.forEach(([name, r], i) => expect(r, name).toEqual(py[i]));
  });
});
