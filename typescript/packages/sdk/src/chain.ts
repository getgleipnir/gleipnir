/** Chain writer: signs, hash-chains and segments records, and anchors segments. */

import { FORMAT_VERSION, hashToBytes, merkleRoot, bytesToHex, parseJson, parseTime, recordHash, recordMessage } from "@getgleipnir/verify";
import type { Anchor } from "./anchor.js";
import type { Signer } from "./keys.js";
import { recordLine, type Rec, type Store } from "./store.js";
import { iso, newId, setKey, utcnow, type Clock } from "./util.js";

export interface ChainWriterOptions {
  clock?: Clock;
  anchor?: Anchor | Anchor[] | null;
  segmentMaxRecords?: number;
  heartbeatSeconds?: number;
  /** Run heartbeats and anchoring on a timer (unref'd, so it never keeps the process alive). */
  background?: boolean;
  genesisExtra?: Rec;
  /** Called when background anchoring fails (it is retried); defaults to a console warning. */
  onWarning?: (message: string) => void;
}

/**
 * Normalize to plain JSON exactly as the stored line will be read back, so the hash covers the
 * same value a reader parses (the Python SDK does `json.loads(json.dumps(rec))` for this).
 */
function normalize(rec: Rec): Rec {
  return parseJson(recordLine(rec).slice(0, -1)) as Rec;
}

/**
 * Appends signed, hash-chained records to a store and closes segments.
 *
 * One writer per chain: do not point two processes at the same store. Writing is synchronous;
 * anchoring may be asynchronous (network anchors) and never blocks or breaks recording.
 */
export class ChainWriter {
  readonly store: Store;
  signer: Signer;
  readonly clock: Clock;
  readonly anchors: Anchor[];
  readonly segmentMaxRecords: number;
  readonly heartbeatSeconds: number;
  readonly background: boolean;
  chainId!: string;
  seq!: number;
  lastHash!: string | null;
  lastSegmentHash!: string | null;
  segmentOpenedAt!: string;
  openMembers: string[] = [];
  readonly pendingAnchor = new Map<number, Rec>();
  readonly anchorDone = new Map<number, Set<string>>();
  private readonly warn: (message: string) => void;
  private timer: ReturnType<typeof setInterval> | null = null;
  private anchoring: Promise<number> | null = null;
  private rerun: Promise<number> | null = null;

  constructor(store: Store, signer: Signer, opts: ChainWriterOptions = {}) {
    const segmentMaxRecords = opts.segmentMaxRecords ?? 1000;
    if (!Number.isInteger(segmentMaxRecords) || segmentMaxRecords < 1) throw new RangeError("segmentMaxRecords must be >= 1");
    this.store = store;
    this.signer = signer;
    this.clock = opts.clock ?? utcnow;
    const a = opts.anchor;
    this.anchors = a == null ? [] : Array.isArray(a) ? [...a] : [a];
    if (new Set(this.anchors.map((x) => x.type)).size !== this.anchors.length) throw new Error("at most one anchor per type");
    this.segmentMaxRecords = segmentMaxRecords;
    this.heartbeatSeconds = opts.heartbeatSeconds ?? 600;
    this.background = opts.background ?? true;
    this.warn = opts.onWarning ?? ((m) => console.warn(m));
    this.recover(opts.genesisExtra ?? {});
    if (this.background) this.startBackground();
  }

  // -- state ------------------------------------------------------------------------
  private recover(genesisExtra: Rec): void {
    const records = this.store.readAll();
    if (records.length === 0) {
      this.chainId = newId("ch");
      this.seq = -1;
      this.lastHash = null;
      this.lastSegmentHash = null;
      const now = this.clock();
      this.write(
        {
          kind: "genesis",
          public_key: { id: this.signer.keyId, public: this.signer.publicKey },
          config: { heartbeat_seconds: this.heartbeatSeconds, segment_max_records: this.segmentMaxRecords },
          ...genesisExtra,
        },
        now,
      );
      this.segmentOpenedAt = iso(now);
      return;
    }
    const genesis = records[0]!;
    this.chainId = genesis["chain"] as string;
    const gk = (genesis["public_key"] as Rec)["id"] as string;
    if (gk !== this.signer.keyId) {
      const rotated = records.filter((r) => r["kind"] === "key_rotation");
      const current = rotated.length ? ((rotated[rotated.length - 1]!["new_key"] as Rec)["id"] as string) : gk;
      if (current !== this.signer.keyId) throw new Error(`chain ${this.chainId} is signed with ${current}, not ${this.signer.keyId}`);
    }
    this.seq = records[records.length - 1]!["seq"] as number;
    this.lastHash = recordHash(records[records.length - 1]!);
    this.lastSegmentHash = null;
    this.segmentOpenedAt = genesis["time"] as string;
    for (const r of records) {
      if (r["kind"] === "anchor") {
        const a = r["anchor"] as Rec;
        const s = a["segment_seq"] as number;
        if (!this.anchorDone.has(s)) this.anchorDone.set(s, new Set());
        this.anchorDone.get(s)!.add(a["type"] as string);
      }
    }
    const wanted = this.anchors.map((x) => x.type);
    for (const r of records.slice(1)) {
      if (r["kind"] === "segment") {
        this.openMembers = [];
        this.lastSegmentHash = recordHash(r);
        this.segmentOpenedAt = (r["segment"] as Rec)["closed_at"] as string;
        const done = this.anchorDone.get(r["seq"] as number) ?? new Set();
        if (!wanted.every((t) => done.has(t))) this.pendingAnchor.set(r["seq"] as number, r);
      } else {
        this.openMembers.push(recordHash(r));
      }
    }
  }

  // -- writing ----------------------------------------------------------------------
  private write(fields: Rec, now?: Date): Rec {
    const when = now ?? this.clock();
    const { id, ...rest } = fields;
    const rec: Rec = {
      v: FORMAT_VERSION,
      chain: this.chainId,
      seq: this.seq + 1,
      id: (id as string | undefined) || newId(String(fields["kind"] ?? "rec").slice(0, 3)),
      time: iso(when),
      key: this.signer.keyId,
    };
    for (const k of Object.keys(rest)) setKey(rec, k, rest[k]);
    if (this.lastHash !== null) rec["prev"] = this.lastHash;
    const norm = normalize(rec);
    const h = recordHash(norm);
    norm["sig"] = this.signer.sign(recordMessage(h));
    this.store.append(norm);
    this.seq = norm["seq"] as number;
    this.lastHash = h;
    if (norm["kind"] !== "genesis" && norm["kind"] !== "segment") this.openMembers.push(h);
    return norm;
  }

  append(kind: string, fields: Rec): Rec {
    if (kind === "genesis" || kind === "segment") throw new Error(`${kind} records are written by the chain itself`);
    const rec = this.write({ kind, ...fields });
    if (this.openMembers.length >= this.segmentMaxRecords) {
      this.closeSegment();
      // Without the background timer, anchor right away, but never wait for it: network
      // anchors resolve later and write their receipts as records when they arrive.
      if (!this.background) this.anchorInBackground();
    }
    return rec;
  }

  /** Close the open segment (even if empty) and queue it for anchoring. */
  closeSegment(heartbeat = false): Rec {
    const now = this.clock();
    const count = this.openMembers.length;
    const root = merkleRoot(this.openMembers.map((h) => hashToBytes(h)));
    const seg: Rec = {
      from: this.seq + 1 - count,
      count,
      root: "sha256:" + bytesToHex(root),
      opened_at: this.segmentOpenedAt,
      closed_at: iso(now),
      heartbeat,
    };
    if (this.lastSegmentHash !== null) seg["prev_segment"] = this.lastSegmentHash;
    const rec = this.write({ kind: "segment", segment: seg }, now);
    this.openMembers = [];
    this.lastSegmentHash = this.lastHash;
    this.segmentOpenedAt = seg["closed_at"] as string;
    if (this.anchors.length) this.pendingAnchor.set(rec["seq"] as number, rec);
    return rec;
  }

  maybeHeartbeat(): Rec | null {
    const opened = parseTime(this.segmentOpenedAt);
    const now = BigInt(this.clock().getTime()) * 1000n;
    if (now - opened >= BigInt(Math.round(this.heartbeatSeconds * 1e6))) return this.closeSegment(true);
    return null;
  }

  rotateKey(newSigner: Signer): Rec {
    const rec = this.write({ kind: "key_rotation", new_key: { id: newSigner.keyId, public: newSigner.publicKey } });
    this.signer = newSigner;
    return rec;
  }

  // -- anchoring --------------------------------------------------------------------
  /**
   * Anchor every closed segment that has no receipt yet. Resolves to how many segments were
   * fully anchored. Concurrent calls share one run. Synchronous anchors complete before this
   * returns (the receipts are written immediately).
   */
  anchorPending(): Promise<number> {
    if (!this.anchors.length) return Promise.resolve(0);
    if (this.anchoring) {
      // One follow-up run covers every request made while a run is in flight (segments closed
      // meanwhile), so a burst of segment closes during a slow network call queues one run, not many.
      this.rerun ??= this.anchoring.then(
        () => this.startRun(),
        () => this.startRun(),
      );
      return this.rerun;
    }
    return this.startRun();
  }

  private startRun(): Promise<number> {
    this.rerun = null;
    const run = this.runAnchoring().finally(() => {
      if (this.anchoring === run) this.anchoring = null;
    });
    this.anchoring = run;
    return run;
  }

  /** Anchor in the background: never throws, never rejects, reports failures through the warning callback. */
  private anchorInBackground(): void {
    this.anchorPending().catch((exc) => this.warn(`gleipnir: background anchoring failed: ${exc instanceof Error ? exc.message : String(exc)}`));
  }

  private async runAnchoring(): Promise<number> {
    let done = 0;
    for (const seq of [...this.pendingAnchor.keys()].sort((a, b) => a - b)) {
      const seg = this.pendingAnchor.get(seq);
      if (!seg) continue;
      const ok = await this.anchorOne(seg);
      if (ok) done += 1;
      else break;
    }
    return done;
  }

  /** Run every configured anchor not yet done for this segment. True when all are done. */
  private async anchorOne(seg: Rec): Promise<boolean> {
    const h = recordHash(seg);
    const seq = seg["seq"] as number;
    if (!this.anchorDone.has(seq)) this.anchorDone.set(seq, new Set());
    const done = this.anchorDone.get(seq)!;
    let allOk = true;
    for (const anchor of this.anchors) {
      if (done.has(anchor.type)) continue;
      let receipt: Rec;
      try {
        const r = anchor.anchor({ segmentHash: h, chain: this.chainId, segmentSeq: seq });
        receipt = r instanceof Promise ? await r : r;
      } catch (exc) {
        this.warn(`gleipnir: ${anchor.type} anchoring of segment ${seq} failed, will retry: ${exc instanceof Error ? exc.message : String(exc)}`);
        allOk = false;
        continue;
      }
      this.write({ kind: "anchor", anchor: { segment_seq: seq, segment_hash: h, type: anchor.type, receipt } });
      done.add(anchor.type);
    }
    if (allOk) this.pendingAnchor.delete(seq);
    return allOk;
  }

  // -- background -------------------------------------------------------------------
  private startBackground(): void {
    const tick = Math.max(1, Math.min(30, this.heartbeatSeconds / 10)) * 1000;
    this.timer = setInterval(() => {
      try {
        this.maybeHeartbeat();
        this.anchorInBackground();
      } catch (exc) {
        this.warn(`gleipnir: background task failed: ${exc instanceof Error ? exc.message : String(exc)}`);
      }
    }, tick);
    this.timer.unref?.();
  }

  /** Close the open segment and anchor everything pending. */
  async flush(): Promise<void> {
    if (this.openMembers.length) this.closeSegment();
    await this.anchorPending();
  }

  async close(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    await this.flush();
  }
}
