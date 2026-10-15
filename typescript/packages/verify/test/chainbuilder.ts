/**
 * An independent, minimal chain writer used only by the verifier's tests (a port of
 * python/gleipnir-verify/tests/chainbuilder.py). Written from the spec, separately from the
 * SDK, so the verifier is not only tested against the code that produces its input.
 */

import { randomBytes } from "node:crypto";
import { zipSync, strToU8 } from "fflate";
import { p256 } from "@noble/curves/nist.js";
import {
  actionDigest,
  bytesToHex,
  decodePublicKey,
  ed25519PublicFromSeed,
  ed25519Sign,
  encodeP256PublicKey,
  encodeP256Signature,
  encodePublicKey,
  encodeSignature,
  hashToBytes,
  inclusionProof,
  keyId,
  localLogEntryHash,
  merkleRoot,
  p256Sign,
  p256SpkiFromScalar,
  recordHash,
  recordMessage,
} from "@getgleipnir/verify";

export type Rec = Record<string, any>;

export const T0 = Date.UTC(2026, 9, 1, 9, 0, 0);

export function iso(ms: number): string {
  return new Date(ms).toISOString();
}

export class Key {
  readonly seed: Uint8Array;
  readonly id: string;
  readonly public: string;
  constructor(seed?: Uint8Array) {
    this.seed = seed ?? randomBytes(32);
    const raw = ed25519PublicFromSeed(this.seed);
    this.id = keyId(raw);
    this.public = encodePublicKey(raw);
  }
  sign(h: string): string {
    return encodeSignature(ed25519Sign(this.seed, recordMessage(h)));
  }
}

/** An ECDSA P-256 record key (same interface as Key). */
export class P256Key {
  readonly scalar: Uint8Array;
  readonly spki: Uint8Array;
  readonly id: string;
  readonly public: string;
  constructor(scalar?: Uint8Array) {
    this.scalar = scalar ?? p256.utils.randomSecretKey();
    this.spki = p256SpkiFromScalar(this.scalar);
    this.public = encodeP256PublicKey(this.spki);
    this.id = keyId(decodePublicKey(this.public));
  }
  sign(h: string): string {
    return encodeP256Signature(p256Sign(this.scalar, recordMessage(h)));
  }
}

export type AnyKey = Key | P256Key;

export class Builder {
  key: AnyKey;
  readonly chain: string;
  records: Rec[] = [];
  now = T0;
  open: string[] = [];
  lastSeg: string | null = null;
  opened = T0;
  anchorLog: Rec[] = [];
  readonly heartbeat: number;

  constructor(opts: { key?: AnyKey; heartbeat?: number; chain?: string } = {}) {
    this.key = opts.key ?? new Key();
    this.chain = opts.chain ?? "ch_test";
    this.heartbeat = opts.heartbeat ?? 600;
    this.add({
      kind: "genesis",
      public_key: { id: this.key.id, public: this.key.public },
      config: { heartbeat_seconds: this.heartbeat, segment_max_records: 1000 },
    });
  }

  tick(seconds = 1): void {
    this.now += seconds * 1000;
  }

  add(fields: Rec, key?: AnyKey): Rec {
    const k = key ?? this.key;
    const rec: Rec = {
      v: 1,
      chain: this.chain,
      seq: this.records.length,
      id: `r${this.records.length}`,
      time: iso(this.now),
      key: k.id,
      ...fields,
    };
    if (this.records.length) rec["prev"] = recordHash(this.records[this.records.length - 1]!);
    const h = recordHash(rec);
    rec["sig"] = k.sign(h);
    this.records.push(rec);
    if (rec["kind"] !== "genesis" && rec["kind"] !== "segment") this.open.push(h);
    return rec;
  }

  action(n = 0, extra: Rec = {}): Rec {
    this.tick();
    return this.add({
      kind: "action",
      tool: { name: "refund", system: "pay" },
      args: { order: `o${n}`, amount: n },
      response: { status: "ok" },
      t: { start: iso(this.now), end: iso(this.now) },
      ...extra,
    });
  }

  segment(): Rec {
    this.tick();
    const count = this.open.length;
    const seg: Rec = {
      from: this.records.length - count,
      count,
      root: "sha256:" + bytesToHex(merkleRoot(this.open.map((h) => hashToBytes(h)))),
      opened_at: iso(this.opened),
      closed_at: iso(this.now),
      heartbeat: false,
    };
    if (this.lastSeg) seg["prev_segment"] = this.lastSeg;
    const rec = this.add({ kind: "segment", segment: seg });
    this.open = [];
    this.lastSeg = recordHash(rec);
    this.opened = this.now;
    return rec;
  }

  anchor(seg: Rec): Rec {
    const h = recordHash(seg);
    const entry: Rec = {
      v: 1,
      index: this.anchorLog.length,
      chain: this.chain,
      segment_seq: seg["seq"],
      segment_hash: h,
      time: iso(this.now),
    };
    if (this.anchorLog.length) entry["prev"] = this.anchorLog[this.anchorLog.length - 1]!["hash"];
    entry["hash"] = localLogEntryHash(entry);
    this.anchorLog.push(entry);
    return this.add({
      kind: "anchor",
      anchor: {
        segment_seq: seg["seq"],
        segment_hash: h,
        type: "local",
        receipt: { index: entry["index"], entry_hash: entry["hash"], time: entry["time"] },
      },
    });
  }

  standard(segments = 3, per = 4): this {
    let prev: Rec | null = null;
    for (let s = 0; s < segments; s++) {
      if (prev) this.anchor(prev);
      for (let i = 0; i < per; i++) this.action(s * 100 + i);
      prev = this.segment();
    }
    this.anchor(prev!);
    return this;
  }

  copy(): Rec[] {
    return structuredClone(this.records);
  }

  /** An approval of one exact action (tool, system, args), recorded before it runs; returns its id. */
  approve(args: Rec, o: { tool?: string; system?: string; decision?: string } = {}): string {
    const tool = o.tool ?? "refund";
    const system = o.system ?? "pay";
    const rec = this.add({
      kind: "review",
      review: { action_digest: actionDigest(tool, system, args), tool, system, reviewer: "ops:anna", decision: o.decision ?? "approved", before_execution: true },
    });
    return rec["id"];
  }

  /** Rotate to a new key (of either type); later records are signed by it. */
  rotate(next: AnyKey): Rec {
    const rec = this.add({ kind: "key_rotation", new_key: { id: next.id, public: next.public } });
    this.key = next;
    return rec;
  }
}

/** The files of a single-action proof (manifest type "proof"), as the Python SDK's export_proof writes them. */
export function proofFiles(b: Builder, actionId: string, records: Rec[] = b.records): { manifest: Rec; records: Rec[] } {
  const action = records.find((r) => r["id"] === actionId)!;
  const seq = action["seq"];
  const segment = records.find((r) => r["kind"] === "segment" && r["segment"]["from"] <= seq && seq < r["segment"]["from"] + r["segment"]["count"])!;
  const s = segment["segment"];
  const members = records.filter((r) => s["from"] <= r["seq"] && r["seq"] < s["from"] + s["count"]).map((r) => hashToBytes(recordHash(r)));
  const index = seq - s["from"];
  const anchors = records.filter((r) => r["kind"] === "anchor" && r["anchor"]["segment_seq"] === segment["seq"]);
  const manifest: Rec = {
    format: 1,
    type: "proof",
    chain: b.chain,
    action: actionId,
    action_seq: seq,
    segment_seq: segment["seq"],
    leaf_index: index,
    tree_size: members.length,
    proof: inclusionProof(index, members).map(bytesToHex),
    key: records[0]!["public_key"]["id"],
  };
  return { manifest, records: [records[0]!, action, segment, ...anchors] };
}

export function proofZip(b: Builder, manifest: Rec, records: Rec[]): Uint8Array {
  return zipBundle({
    "manifest.json": JSON.stringify(manifest),
    "records.jsonl": records.map((r) => JSON.stringify(r) + "\n").join(""),
    "anchors/local-anchor-log.jsonl": b.anchorLog.map((e) => JSON.stringify(e) + "\n").join(""),
  });
}

/** Recompute prev/sig from `start` on, as an attacker holding `key` would. */
export function resign(records: Rec[], key: AnyKey, start = 0): Rec[] {
  for (let i = start; i < records.length; i++) {
    const rec = records[i]!;
    delete rec["sig"];
    if (i > 0) rec["prev"] = recordHash(records[i - 1]!);
    rec["key"] = key.id;
    rec["sig"] = key.sign(recordHash(rec));
  }
  return records;
}

export function zipBundle(files: Record<string, string | Uint8Array>): Uint8Array {
  const out: Record<string, Uint8Array> = {};
  for (const [k, v] of Object.entries(files)) out[k] = typeof v === "string" ? strToU8(v) : v;
  return zipSync(out);
}

export function writeBundle(b: Builder, records?: Rec[], manifest?: Rec): Uint8Array {
  const recs = records ?? b.records;
  const m = manifest ?? { format: 1, chain: b.chain, from_seq: 1, to_seq: recs[recs.length - 1]!["seq"] };
  return zipBundle({
    "manifest.json": JSON.stringify(m),
    "records.jsonl": recs.map((r) => JSON.stringify(r) + "\n").join(""),
    "anchors/local-anchor-log.jsonl": b.anchorLog.map((e) => JSON.stringify(e) + "\n").join(""),
  });
}

/** A small seeded PRNG (mulberry32) so property tests are reproducible. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
