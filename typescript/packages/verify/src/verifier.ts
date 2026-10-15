/**
 * Verification of Gleipnir record chains and bundles.
 *
 * A port of the reference verifier (python/gleipnir-verify/src/gleipnir_verify/verifier.py)
 * with the same checks, finding codes and options. It checks, in order:
 *
 * 1. Record order and sequence numbers (no gaps, duplicates or reordering).
 * 2. Signatures, against keys introduced by the genesis record or signed rotations.
 * 3. Hash chain continuity (each record commits to the previous one).
 * 4. Segments: Merkle roots, tiling (every record belongs to exactly one segment),
 *    and time continuity between segments (heartbeats).
 * 5. Anchor receipts for segments.
 * 6. Bundle-level expectations: declared range, expected key, expected coverage.
 *
 * It never throws on hostile input: problems become findings.
 */

import { verifyLocal, type AnchorOptions, type AnchorResult, type AnchorVerifier } from "./anchors.js";
import { hashToBytes, recordHash } from "./canon.js";
import { decodePublicKey, keyId, recordMessage, verifySignature } from "./crypto.js";
import { merkleRoot } from "./merkle.js";
import { readBundle } from "./bundle.js";
import { bytesEqual } from "./bytes.js";
import {
  BigIntLiteral,
  OverflowErr,
  PyError,
  TypeErr,
  ValueErr,
  caught,
  codePointCompare,
  dget,
  errorText,
  formatFixed,
  hasKey,
  isDict,
  isNone,
  isPyInt,
  num,
  pyEq,
  pyIntBig,
  pyKey,
  pyRepr,
  pyRound,
  pyStr,
  requireHashable,
  sub,
  truthy,
  type JsonDict,
} from "./py.js";
import { MICROS_PER_SECOND, microsFromDate, parseTime, pyIsoformat, pyTimedelta, type Micros } from "./time.js";
import { verifyRekor } from "./rekor.js";
import { verifyRfc3161 } from "./timestamp.js";

export const FORMAT_VERSION = 1;
export type Level = "error" | "warn" | "info";
export const ERROR: Level = "error";
export const WARN: Level = "warn";
export const INFO: Level = "info";

export interface Finding {
  level: Level;
  code: string;
  message: string;
  /** The record's seq, when the finding is about one record. */
  seq?: unknown;
}

export interface Summary {
  [key: string]: unknown;
}

export class Report {
  findings: Finding[] = [];
  summary: Summary = {};

  get errors(): Finding[] {
    return this.findings.filter((f) => f.level === ERROR);
  }

  get warnings(): Finding[] {
    return this.findings.filter((f) => f.level === WARN);
  }

  valid(strict = false): boolean {
    return this.errors.length === 0 && (!strict || this.warnings.length === 0);
  }

  add(level: Level, code: string, message: string, seq?: unknown): void {
    const f: Finding = { level, code, message };
    if (!isNone(seq)) f.seq = seq;
    this.findings.push(f);
  }

  toJSON(strict = false): { result: "VALID" | "INVALID"; summary: Summary; findings: Finding[] } {
    return {
      result: this.valid(strict) ? "VALID" : "INVALID",
      summary: this.summary,
      findings: this.findings.map((f) => ({ ...f })),
    };
  }
}

export type AnchorType = "rekor" | "rfc3161";

export interface VerifyOptions {
  /** The bundle manifest, when verifying records from a bundle. */
  manifest?: JsonDict | null;
  /** Fail unless the chain is signed with this key id. */
  expectKey?: string | null;
  /** Fail unless records cover at least until this time (detects truncation). */
  expectUntil?: Date | string | null;
  /** Fail unless this record (from an earlier bundle) is present and unchanged: {seq, hash} or "SEQ:sha256:HEX". */
  knownHead?: { seq: number; hash: string } | string | null;
  /** Fail unless every segment has a verified independent anchor of this type (or of each type). */
  requireAnchor?: AnchorType | string | readonly string[] | null;
  /** Fail if a segment was timestamped more than this many seconds after it closed. */
  maxAnchorDelay?: number | null;
  /** Fail unless the bundle starts at the beginning of the chain. */
  requireFull?: boolean;
  /** Verifiers by anchor type (defaults: local, rekor, rfc3161). */
  anchorVerifiers?: Record<string, AnchorVerifier>;
  anchorOptions?: AnchorOptions;
}

export function defaultVerifiers(): Record<string, AnchorVerifier> {
  return { local: verifyLocal, rekor: verifyRekor, rfc3161: verifyRfc3161 };
}

/** Parse a `--known-head` value ("SEQ:sha256:HEX"); returns null when it is not well formed. */
export function parseKnownHead(text: string): { seq: number; hash: string } | null {
  const i = text.indexOf(":");
  if (i < 0) return null;
  const seqText = text.slice(0, i);
  const hash = text.slice(i + 1);
  if (!/^\p{Nd}+$/u.test(seqText) || !hash.startsWith("sha256:")) return null;
  const ascii = seqText.replace(/\p{Nd}/gu, (d) => String(digitValue(d)));
  return { seq: Number(ascii), hash };
}

function digitValue(d: string): number {
  const cp = d.codePointAt(0) as number;
  // Unicode decimal digits come in contiguous runs of ten starting at a code point ending in 0.
  for (let z = cp; z >= cp - 9; z--) {
    if (/\p{Nd}/u.test(String.fromCodePoint(z)) && !/\p{Nd}/u.test(String.fromCodePoint(z - 1))) return (cp - z) % 10;
  }
  return 0;
}

interface ResolvedOptions {
  manifest: JsonDict | null;
  expectKey: string | null;
  expectUntil: Micros | null;
  knownHead: { seq: number; hash: string } | null;
  required: string[];
  maxAnchorDelay: number | null;
  requireFull: boolean;
  anchorVerifiers: Record<string, AnchorVerifier>;
  anchorOptions: AnchorOptions;
}

function resolve(opts: VerifyOptions): ResolvedOptions {
  let expectUntil: Micros | null = null;
  if (opts.expectUntil instanceof Date) {
    if (Number.isNaN(opts.expectUntil.getTime())) throw new RangeError("expectUntil is an invalid Date");
    expectUntil = microsFromDate(opts.expectUntil);
  } else if (typeof opts.expectUntil === "string") {
    try {
      expectUntil = parseTime(opts.expectUntil);
    } catch {
      throw new RangeError("expectUntil needs an ISO 8601 time with a timezone, e.g. 2026-10-14T18:00:00Z");
    }
  }
  let knownHead: { seq: number; hash: string } | null = null;
  if (typeof opts.knownHead === "string") {
    knownHead = parseKnownHead(opts.knownHead);
    if (knownHead === null) throw new RangeError("knownHead must look like 12:sha256:<64 hex>");
  } else if (opts.knownHead) knownHead = opts.knownHead;
  const ra = opts.requireAnchor;
  const required = typeof ra === "string" ? [ra] : ra ? [...ra] : [];
  return {
    manifest: opts.manifest ?? null,
    expectKey: opts.expectKey ?? null,
    expectUntil,
    knownHead,
    required,
    maxAnchorDelay: opts.maxAnchorDelay ?? null,
    requireFull: opts.requireFull ?? false,
    anchorVerifiers: opts.anchorVerifiers ?? defaultVerifiers(),
    // A fresh options object per verification: it carries a per-run cache.
    anchorOptions: { ...(opts.anchorOptions ?? {}), _localCache: undefined },
  };
}

/** Verify a list of records (parsed JSON). Never throws on malformed records; problems become findings. */
export function verifyRecords(records: unknown, options: VerifyOptions = {}): Report {
  const opts = resolve(options);
  try {
    if (!Array.isArray(records)) throw TypeErr("records must be a list");
    return verifyRecordsInner(records, opts);
  } catch (exc) {
    const report = new Report();
    report.add(ERROR, "malformed", `records could not be processed: ${errorText(exc)}`);
    return report;
  }
}

/** A seq-keyed map with Python dict key semantics (1, 1.0 and true are the same key). */
class PyMap<V> {
  private readonly m = new Map<string, V>();
  has(k: unknown): boolean {
    return this.m.has(pyKey(k));
  }
  get(k: unknown): V | undefined {
    return this.m.get(pyKey(k));
  }
  set(k: unknown, v: V): void {
    this.m.set(pyKey(k), v);
  }
}

function big(x: unknown): bigint {
  return pyIntBig(x);
}

/** Python `str(int)` for an int-like JSON value. */
function istr(x: bigint): string {
  return x.toString();
}

const MAX_TIMEDELTA_S = 999999999 * 86400 + 86399.999999;

/** Python `timedelta(seconds=x)` in microseconds. */
function timedeltaSeconds(x: number): bigint {
  if (Number.isNaN(x)) throw ValueErr("cannot convert float NaN to integer");
  if (!Number.isFinite(x) || Math.abs(x) > MAX_TIMEDELTA_S) {
    throw OverflowErr(`days=${Math.trunc(x / 86400)}; must have magnitude <= 999999999`);
  }
  const us = x * 1e6;
  const r = Math.round(us);
  const fixed = Math.abs(us - Math.trunc(us)) === 0.5 && r % 2 !== 0 ? r - 1 : r; // half to even
  return BigInt(fixed);
}

/** Python `heartbeat * 1.5 + 60` (or `(heartbeat or 0) + 60`) on a JSON value. */
function arith(x: unknown, mul: number, add: number): number {
  if (typeof x === "string" || Array.isArray(x) || isDict(x) || isNone(x)) {
    throw TypeErr(`unsupported operand type(s) for *: '${typeof x}' and 'float'`);
  }
  return num(x) * mul + add;
}

function verifyRecordsInner(records: unknown[], o: ResolvedOptions): Report {
  const report = new Report();
  const anchorVerifiers = o.anchorVerifiers;
  const anchorOptions = o.anchorOptions;

  if (records.length === 0) {
    report.add(ERROR, "empty", "bundle contains no records");
    return report;
  }

  // ---- genesis and keys ---------------------------------------------------
  const genesis = records[0];
  if (!isDict(genesis)) {
    report.add(ERROR, "malformed", "first record is not a JSON object");
    return report;
  }
  if (!pyEq(dget(genesis, "kind"), "genesis") || !pyEq(dget(genesis, "seq"), 0)) {
    report.add(ERROR, "no_genesis", "first record must be the genesis record (seq 0)");
    return report;
  }
  if (!pyEq(dget(genesis, "v"), FORMAT_VERSION)) {
    report.add(ERROR, "format_version", `unsupported format version ${pyRepr(dget(genesis, "v"))}`);
    return report;
  }
  const chainId = dget(genesis, "chain");
  const keys = new Map<string, Uint8Array>();
  try {
    const pk = sub(genesis, "public_key");
    const raw = decodePublicKey(sub(pk, "public"));
    if (!pyEq(keyId(raw), sub(pk, "id"))) {
      report.add(ERROR, "key_id_mismatch", "genesis key id does not match its public key", 0);
      return report;
    }
    keys.set(sub(pk, "id") as string, raw);
  } catch (exc) {
    if (!caught(exc, "KeyError", "TypeError", "ValueError")) throw exc;
    report.add(ERROR, "bad_genesis_key", `cannot read genesis public key: ${(exc as Error).message}`, 0);
    return report;
  }
  const genesisKey = sub(sub(genesis, "public_key"), "id") as string;
  const config = dget(genesis, "config", {});
  const heartbeat = dget(config, "heartbeat_seconds");

  if (o.expectKey && o.expectKey !== genesisKey) {
    report.add(ERROR, "unexpected_key", `chain key ${genesisKey} is not the expected key ${o.expectKey}`, 0);
  }

  // ---- per-record checks ----------------------------------------------------
  const hashes = new PyMap<string>();
  const bySeq = new PyMap<JsonDict>();
  let prevSeq: unknown = null;
  let prevHash: string | null = null;
  let firstBodySeq: unknown = null;
  let currentKey = genesisKey;

  for (let idx = 0; idx < records.length; idx++) {
    const rec = records[idx];
    if (!isDict(rec)) {
      report.add(ERROR, "malformed", `record at position ${idx} is not a JSON object`);
      return report;
    }
    const seq = dget(rec, "seq");
    if (!isPyInt(seq)) {
      report.add(ERROR, "bad_seq", `record at position ${idx} has no integer seq`);
      continue;
    }
    if (!pyEq(dget(rec, "chain"), chainId)) {
      report.add(ERROR, "wrong_chain", `record belongs to chain ${pyRepr(dget(rec, "chain"))}`, seq);
    }
    if (!pyEq(dget(rec, "v"), FORMAT_VERSION)) {
      report.add(ERROR, "format_version", `unsupported format version ${pyRepr(dget(rec, "v"))}`, seq);
    }

    let h: string;
    try {
      h = recordHash(rec);
    } catch (exc) {
      report.add(ERROR, "unencodable", `record cannot be canonicalized: ${(exc as Error).message}`, seq);
      continue;
    }
    if (bySeq.has(seq)) report.add(ERROR, "duplicate_seq", "sequence number appears twice", seq);
    hashes.set(seq, h);
    bySeq.set(seq, rec);

    // signature
    const kid = dget(rec, "key");
    requireHashable(kid);
    const known = typeof kid === "string" && keys.has(kid);
    if (!known) {
      report.add(ERROR, "unknown_key", `signed with unknown key ${pyRepr(kid)}`, seq);
    } else if (!verifySignature(keys.get(kid as string)!, recordMessage(h), dget(rec, "sig", ""))) {
      report.add(ERROR, "bad_signature", "signature does not match record content (record altered?)", seq);
    } else if (idx > 0 && kid !== currentKey) {
      report.add(ERROR, "stale_key", `signed with ${pyStr(kid)} after it was rotated out`, seq);
    }

    if (pyEq(dget(rec, "kind"), "key_rotation") && known) {
      try {
        const nk = sub(rec, "new_key");
        const raw = decodePublicKey(sub(nk, "public"));
        if (!pyEq(keyId(raw), sub(nk, "id"))) throw ValueErr("id mismatch");
        keys.set(sub(nk, "id") as string, raw);
        currentKey = sub(nk, "id") as string;
      } catch (exc) {
        if (!caught(exc, "KeyError", "TypeError", "ValueError")) throw exc;
        report.add(ERROR, "bad_rotation", `invalid key rotation: ${(exc as Error).message}`, seq);
      }
    }

    // chain continuity
    if (idx === 0) {
      if (hasKey(rec, "prev")) report.add(ERROR, "genesis_prev", "genesis record must not have prev", seq);
    } else if (idx === 1 && !pyEq(seq, 1)) {
      // Partial bundle: chain resumes after genesis. The first body record must open a segment;
      // its prev is accepted and checked through the segment's Merkle root and anchor.
      firstBodySeq = seq;
      report.add(
        o.requireFull ? ERROR : WARN,
        "partial_bundle",
        `bundle starts at seq ${pyStr(seq)}: records 1..${istr(big(seq) - 1n)} are not included, so nothing is proven about them`,
      );
    } else {
      if (prevSeq !== null && big(seq) !== big(prevSeq) + 1n) {
        if (big(seq) <= big(prevSeq)) {
          report.add(ERROR, "reordered", `seq ${pyStr(seq)} follows seq ${pyStr(prevSeq)}`, seq);
        } else {
          report.add(ERROR, "gap", `records ${istr(big(prevSeq) + 1n)}..${istr(big(seq) - 1n)} are missing`, seq);
        }
      }
      if (!pyEq(dget(rec, "prev"), prevHash)) {
        report.add(ERROR, "broken_chain", "prev does not match the hash of the preceding record", seq);
      }
    }
    if (idx === 1 && firstBodySeq === null) firstBodySeq = seq;
    prevSeq = seq;
    prevHash = h;
  }

  if (report.errors.length > 0) {
    summarize(report, records as JsonDict[], genesis, keys, [], 0);
    return report;
  }

  const recs = records as JsonDict[];

  // ---- segments ----------------------------------------------------------------
  const seqList = recs.map((r) => sub(r, "seq"));
  const lastSeq = seqList[seqList.length - 1];
  const segments = recs.filter((r) => pyEq(dget(r, "kind"), "segment"));
  // Every record was hashed without error, so every seq is a safe integer and unique.
  /** Present seqs, sorted, for counting segment members without materializing their ranges. */
  const sortedSeqs: number[] = [...new Set(recs.map((r) => Number(big(sub(r, "seq")))))].sort((a, b) => a - b);
  const lowerBound = (x: bigint): number => {
    let lo = 0;
    let hi = sortedSeqs.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (BigInt(sortedSeqs[mid]!) < x) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  };
  /** Covered seqs: segment members and segment records. */
  const covered = new Set<number>();
  let prevSegment: JsonDict | null = null;
  let expectedFrom: bigint = firstBodySeq !== null ? big(firstBodySeq) : 1n;
  for (const segRec of segments) {
    const s = dget(segRec, "segment", {});
    const sseq = sub(segRec, "seq");
    let frm: bigint;
    let count: bigint;
    let rootTag: unknown;
    let opened: Micros;
    let closed: Micros;
    try {
      frm = big(sub(s, "from"));
      count = big(sub(s, "count"));
      rootTag = sub(s, "root");
      opened = parseTime(sub(s, "opened_at"));
      closed = parseTime(sub(s, "closed_at"));
    } catch (exc) {
      if (!caught(exc, "KeyError", "TypeError", "ValueError")) throw exc;
      report.add(ERROR, "bad_segment", `malformed segment: ${(exc as Error).message}`, sseq);
      continue;
    }
    const sd = s as JsonDict;
    if (frm !== expectedFrom || frm + count !== big(sseq)) {
      report.add(
        ERROR,
        "segment_tiling",
        `segment covers ${istr(frm)}..${istr(frm + count - 1n)} but should start at ${istr(expectedFrom)} and end right before its own record`,
        sseq,
      );
    }
    const end = frm + count;
    const nMembers = count > 0n ? count : 0n;
    // The reference materializes list(range(from, from + count)); Python cannot for more than sys.maxsize items.
    if (nMembers > 2n ** 63n - 1n) throw OverflowErr("Python int too large to convert to C ssize_t");
    const firstIdx = lowerBound(frm);
    const endIdx = nMembers > 0n ? lowerBound(end) : firstIdx;
    const missing = nMembers - BigInt(endIdx - firstIdx);
    if (missing > 0n) {
      report.add(ERROR, "segment_incomplete", `${istr(missing)} records of this segment are missing`, sseq);
    } else {
      const leaves: Uint8Array[] = [];
      for (let m = frm; m < end; m++) leaves.push(hashToBytes(hashes.get(Number(m))));
      if (!bytesEqual(merkleRoot(leaves), hashToBytes(rootTag))) {
        report.add(ERROR, "merkle_mismatch", "segment Merkle root does not match its records", sseq);
      }
    }
    for (let k = firstIdx; k < endIdx; k++) covered.add(sortedSeqs[k]!);
    covered.add(Number(big(sseq)));
    if (prevSegment !== null) {
      if (!pyEq(dget(sd, "prev_segment"), hashes.get(sub(prevSegment, "seq")))) {
        report.add(ERROR, "segment_link", "prev_segment does not match the previous segment", sseq);
      }
      const prevClosedText = sub(sub(prevSegment, "segment"), "closed_at");
      if (parseTime(prevClosedText) !== opened) {
        report.add(WARN, "time_gap", `no segment between ${pyStr(prevClosedText)} and ${pyStr(sd["opened_at"])}`, sseq);
      }
    } else if (frm === 1n && opened !== parseTime(sub(genesis, "time"))) {
      report.add(WARN, "time_gap", "first segment does not start at the genesis time", sseq);
    }
    if (closed < opened) report.add(ERROR, "segment_time", "segment closes before it opens", sseq);
    if (truthy(heartbeat)) {
      const limit = timedeltaSeconds(arith(heartbeat, 1.5, 60));
      if (closed - opened > limit) {
        report.add(
          WARN,
          "missed_heartbeat",
          `segment spans ${pyTimedelta(closed - opened)} which is longer than the ${pyStr(heartbeat)}s heartbeat (process down or records withheld?)`,
          sseq,
        );
      }
    }
    prevSegment = segRec;
    expectedFrom = big(sseq) + 1n;
  }

  const body = seqList.filter((s) => !pyEq(s, 0));
  // Anchor receipts written after the last segment closed are expected in the tail; losing one only
  // makes its segment show as unanchored, so they are not counted as unprotected records.
  const tail = body.filter((s) => !covered.has(Number(big(s))) && !pyEq(dget(bySeq.get(s), "kind"), "anchor"));
  if (tail.length > 0) {
    report.add(
      WARN,
      "unsegmented_tail",
      `${tail.length} records after the last closed segment (seq ${pyStr(tail[0])}..${pyStr(tail[tail.length - 1])}) are not covered by a segment or anchor; truncation of this tail cannot be ruled out`,
    );
  }

  // ---- anchors -------------------------------------------------------------------
  const receipts = new PyMap<JsonDict[]>();
  for (const rec of recs) {
    if (pyEq(dget(rec, "kind"), "anchor")) {
      const a = dget(rec, "anchor", {});
      const key = dget(a, "segment_seq");
      requireHashable(key);
      const list = receipts.get(key) ?? [];
      list.push(rec);
      receipts.set(key, list);
    }
  }

  let anchored = 0;
  let independent = 0;
  let unchecked = 0;
  const required = o.required;
  let timestamped = 0;
  let maxDelay = 0.0;
  let trustedUntil: unknown = null;
  let lastAnchoredClose: unknown = null;
  for (const segRec of segments) {
    const sseq = sub(segRec, "seq");
    const rlist = receipts.get(sseq) ?? [];
    let okAny = false;
    let seenUnchecked = false;
    let segIndependent = false;
    const verifiedTypes = new Set<string>();
    for (const r of rlist) {
      const a = sub(r, "anchor");
      if (!pyEq(dget(a, "segment_hash"), hashes.get(sseq))) {
        report.add(ERROR, "anchor_hash", "anchor receipt is for a different segment hash", sub(r, "seq"));
        continue;
      }
      const type = dget(a, "type");
      requireHashable(type);
      const fn = typeof type === "string" && hasKey(anchorVerifiers, type) ? anchorVerifiers[type] : undefined;
      if (fn === undefined) {
        report.add(WARN, "anchor_type", `unknown anchor type ${pyRepr(type)}`, sub(r, "seq"));
        continue;
      }
      const res: AnchorResult = fn(a as JsonDict, { segmentHash: hashes.get(sseq)!, chain: chainId, options: anchorOptions });
      if (res.ok === false) {
        report.add(ERROR, "anchor_invalid", `anchor receipt invalid: ${res.detail}`, sub(r, "seq"));
      } else if (res.ok === null) {
        report.add(INFO, "anchor_unchecked", `anchor receipt not checked: ${res.detail}`, sub(r, "seq"));
        seenUnchecked = true;
      } else {
        okAny = true;
        if (res.independent) {
          segIndependent = true;
          verifiedTypes.add(type as string);
        }
        if (res.time) {
          const ts = parseTime(res.time);
          const closedText = sub(sub(segRec, "segment"), "closed_at");
          const closed = parseTime(closedText);
          const delay = Number(ts - closed) / Number(MICROS_PER_SECOND);
          if (delay < -300) {
            report.add(
              WARN,
              "timestamp_before_close",
              `trusted time ${res.time} is before the segment's claimed close ${pyStr(closedText)} (vendor clock ahead?)`,
              sseq,
            );
          }
          if (o.maxAnchorDelay !== null && delay > o.maxAnchorDelay) {
            report.add(
              ERROR,
              "late_timestamp",
              `segment timestamped ${formatFixed(delay, 0)}s after it closed (limit ${formatFixed(o.maxAnchorDelay, 0)}s): history may have been rebuilt later`,
              sseq,
            );
          } else if (delay > 86400) {
            report.add(
              WARN,
              "late_timestamp",
              `segment timestamped ${formatFixed(delay / 3600, 1)}h after it closed (history may have been rebuilt later)`,
              sseq,
            );
          }
          maxDelay = Math.max(maxDelay, delay);
        }
      }
    }
    if (okAny) {
      anchored += 1;
      lastAnchoredClose = sub(sub(segRec, "segment"), "closed_at");
    } else if (seenUnchecked) {
      unchecked += 1;
    }
    if (segIndependent) independent += 1;
    for (const req of required) {
      if (!verifiedTypes.has(req)) {
        report.add(
          ERROR,
          "anchor_required",
          `segment has no verified ${req} anchor (receipt missing, removed or not independent)`,
          sseq,
        );
      }
    }
    if (verifiedTypes.has("rfc3161")) {
      timestamped += 1;
      trustedUntil = sub(sub(segRec, "segment"), "closed_at");
    }
  }
  const unanchored = segments.length - anchored - unchecked;
  if (unanchored) {
    report.add(WARN, "unanchored_segments", `${unanchored} of ${segments.length} segments have no verified anchor receipt in this bundle`);
  }
  if (unchecked) {
    report.add(WARN, "anchors_unchecked", `${unchecked} segments have anchor receipts that could not be checked`);
  }

  // ---- bundle expectations ---------------------------------------------------------
  if (o.requireFull && body.length > 0 && !pyEq(body[0], 1)) {
    report.add(ERROR, "partial_bundle", "a full bundle was required but records are missing at the start");
  }
  const manifest = o.manifest;
  if (manifest !== null) {
    if (!isNone(dget(manifest, "key")) && !pyEq(dget(manifest, "key"), genesisKey)) {
      report.add(ERROR, "manifest_key", "manifest key does not match the genesis key");
    }
    if (!pyEq(dget(manifest, "chain"), chainId)) {
      report.add(ERROR, "manifest_chain", "manifest chain does not match records");
    }
    if (!isNone(dget(manifest, "to_seq")) && !pyEq(dget(manifest, "to_seq"), lastSeq)) {
      report.add(
        ERROR,
        "truncated",
        `manifest declares records up to seq ${pyStr(dget(manifest, "to_seq"))} but the bundle ends at seq ${pyStr(lastSeq)}`,
      );
    }
    if (!isNone(dget(manifest, "from_seq")) && body.length > 0 && !pyEq(dget(manifest, "from_seq"), body[0])) {
      report.add(
        ERROR,
        "manifest_range",
        `manifest declares records from seq ${pyStr(dget(manifest, "from_seq"))} but the bundle starts at ${pyStr(body[0])}`,
      );
    }
  }
  if (o.expectUntil !== null) {
    if (segments.length === 0) {
      report.add(ERROR, "coverage", "no closed segments, coverage cannot be established");
    } else {
      const lastClosedText = sub(sub(segments[segments.length - 1], "segment"), "closed_at");
      const lastClose = parseTime(lastClosedText);
      const slack = timedeltaSeconds(arith(truthy(heartbeat) ? heartbeat : 0, 1, 60));
      if (lastClose + slack < o.expectUntil) {
        report.add(
          ERROR,
          "coverage",
          `records end at ${pyStr(lastClosedText)}, earlier than expected ${pyIsoformat(o.expectUntil)} (truncated?)`,
        );
      }
    }
  }

  if (o.knownHead !== null) {
    const { seq: kseq, hash: khash } = o.knownHead;
    if (!hashes.has(kseq)) {
      report.add(
        ERROR,
        "known_head_missing",
        `a previously seen record (seq ${kseq}) is not in this bundle (truncated or rewritten?)`,
      );
    } else if (hashes.get(kseq) !== khash) {
      report.add(ERROR, "known_head_changed", `record seq ${kseq} differs from the one seen before (history rewritten)`, kseq);
    }
  }

  summarize(report, recs, genesis, keys, segments, anchored, independent, lastAnchoredClose);
  report.summary["segments_timestamped"] = timestamped;
  report.summary["trusted_time_until"] = trustedUntil;
  report.summary["max_timestamp_delay_s"] = timestamped ? pyRound(maxDelay, 1) : null;
  const headSeq = dget(recs[recs.length - 1], "seq");
  report.summary["head"] = { seq: headSeq, hash: hashes.get(headSeq) ?? null };
  return report;
}

function summarize(
  report: Report,
  records: JsonDict[],
  genesis: JsonDict,
  keys: Map<string, Uint8Array>,
  segments: JsonDict[],
  anchored: number,
  independent = 0,
  lastAnchoredClose: unknown = null,
): void {
  const kinds = new Map<string, [unknown, number]>();
  for (const r of records) {
    const k = dget(r, "kind", "?");
    const pk = pyKey(k);
    const cur = kinds.get(pk);
    kinds.set(pk, [cur ? cur[0] : k, (cur ? cur[1] : 0) + 1]);
  }
  const byKind: Record<string, number> = {};
  for (const [k, n] of kinds.values()) byKind[jsonKey(k)] = n;
  const first = firstBodySeqOf(records);
  report.summary = {
    chain: dget(genesis, "chain"),
    keys: [...keys.keys()].sort(codePointCompare),
    records: records.length,
    first_seq: dget(records[0], "seq"),
    last_seq: dget(records[records.length - 1], "seq"),
    by_kind: byKind,
    segments: segments.length,
    segments_anchored: anchored,
    partial: !(isNone(first) || pyEq(first, 1)),
    anchors_independent: independent,
    anchored_until: lastAnchoredClose,
    covered_from: dget(genesis, "time"),
    covered_until: segments.length > 0 ? sub(sub(segments[segments.length - 1], "segment"), "closed_at") : null,
  };
}

/** A dict key as Python's json.dumps writes it. */
function jsonKey(k: unknown): string {
  if (typeof k === "string") return k;
  if (k === true) return "true";
  if (k === false) return "false";
  if (isNone(k)) return "null";
  return pyRepr(k);
}

function firstBodySeqOf(records: unknown[]): unknown {
  if (records.length > 1 && isDict(records[1])) return dget(records[1], "seq");
  return null;
}

/** Verify a bundle (the bytes of its zip file). Never throws on malformed input; problems become findings. */
export function verifyBundle(zipBytes: Uint8Array, options: VerifyOptions = {}): Report {
  let manifest: unknown;
  let records: unknown;
  let localLog: unknown[] | null;
  try {
    [manifest, records, localLog] = readBundle(zipBytes);
  } catch (exc) {
    const msg = exc instanceof Error ? exc.message : String(exc);
    return badBundleReport(`cannot read bundle: ${errorName(exc)}: ${msg.slice(0, 300)}`);
  }
  if (!isDict(manifest) || !Array.isArray(records)) return badBundleReport("manifest.json must be a JSON object");
  if (localLog !== null && !localLog.every((e) => isDict(e))) localLog = null;
  if (!pyEq(dget(manifest, "format"), FORMAT_VERSION)) {
    const report = new Report();
    report.add(ERROR, "format_version", `unsupported bundle format ${pyRepr(dget(manifest, "format"))}`);
    return report;
  }
  const opts: VerifyOptions = { ...options };
  if (localLog !== null) {
    const ao: AnchorOptions = { ...(options.anchorOptions ?? {}) };
    if (ao.localAnchorEntries === undefined) ao.localAnchorEntries = localLog;
    opts.anchorOptions = ao;
  }
  return verifyRecords(records, { ...opts, manifest });
}

function errorName(exc: unknown): string {
  return exc instanceof Error ? exc.name : "Error";
}

/** A report with a single `bad_bundle` error (for bundles that cannot be read at all). */
export function badBundleReport(message: string): Report {
  const report = new Report();
  report.add(ERROR, "bad_bundle", message);
  return report;
}

export { BigIntLiteral, PyError };
