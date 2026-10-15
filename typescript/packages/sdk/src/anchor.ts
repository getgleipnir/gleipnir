/**
 * Anchors publish segment hashes outside the vendor's control.
 *
 * `LocalFileAnchor` is for tests and demos: it writes to a local append-only log, so it is
 * not independent of the vendor. (Publishing to Sigstore Rekor and RFC 3161 timestamping are
 * provided by the Python SDK; receipts they produce are verified by @getgleipnir/verify.)
 */

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { basename, dirname } from "node:path";
import { localLogEntryHash, parseJsonl } from "@getgleipnir/verify";
import { recordLine, type Rec } from "./store.js";
import { iso, utcnow, type Clock } from "./util.js";

export interface AnchorRequest {
  segmentHash: string;
  chain: string;
  segmentSeq: number;
}

export interface Anchor {
  /** Anchor type, as written in anchor records ("local", "rekor", "rfc3161", ...). */
  readonly type: string;
  /** Publish `segmentHash` and return a receipt (JSON object). May be async (network anchors). */
  anchor(req: AnchorRequest): Rec | Promise<Rec>;
}

export class LocalFileAnchor implements Anchor {
  readonly type = "local";
  constructor(
    readonly path: string,
    readonly clock: Clock = utcnow,
  ) {
    mkdirSync(dirname(path), { recursive: true });
  }

  private last(): Rec | null {
    if (!existsSync(this.path)) return null;
    const entries = parseJsonl(readFileSync(this.path, "utf8")) as Rec[];
    return entries.length ? entries[entries.length - 1]! : null;
  }

  anchor({ segmentHash, chain, segmentSeq }: AnchorRequest): Rec {
    const last = this.last();
    const entry: Rec = {
      v: 1,
      index: last === null ? 0 : (last["index"] as number) + 1,
      chain,
      segment_seq: segmentSeq,
      segment_hash: segmentHash,
      time: iso(this.clock()),
    };
    if (last !== null) entry["prev"] = last["hash"];
    entry["hash"] = localLogEntryHash(entry);
    const fd = openSync(this.path, "a");
    try {
      writeSync(fd, recordLine(entry));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    return { index: entry["index"], entry_hash: entry["hash"], time: entry["time"], log: basename(this.path) };
  }
}
