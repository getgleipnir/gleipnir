/**
 * Anchors publish segment hashes outside the vendor's control.
 *
 * `LocalFileAnchor` is for tests and demos: it writes to a local append-only log, so it is
 * not independent of the vendor. `RekorAnchor` publishes to Sigstore Rekor v2 and
 * `TimestampAnchor` gets an RFC 3161 timestamp; both send only a hash and write the same
 * receipts as the Python SDK's anchors of the same name.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as nodeSign, type KeyObject } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import {
  anchorMessage,
  b64encode,
  localLogEntryHash,
  parseJsonBytes,
  parseJsonl,
  pyDumps,
  timestampMessage,
  verifyRekorReceipt,
  verifyTimestampReceipt,
} from "@getgleipnir/verify";
import { writePrivateFile } from "./keys.js";
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

/** The `fetch` the network anchors use (injectable for tests and custom transports). */
export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

const USER_AGENT = "gleipnir-sdk";

async function post(fetchFn: FetchLike, url: string, body: Uint8Array | string, headers: Record<string, string>, timeoutMs: number): Promise<Uint8Array> {
  const resp = await fetchFn(url, {
    method: "POST",
    headers: { ...headers, "User-Agent": USER_AGENT },
    body: typeof body === "string" ? body : Buffer.from(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const raw = new Uint8Array(await resp.arrayBuffer());
  if (!resp.ok) {
    const text = new TextDecoder().decode(raw.subarray(0, 300)).trim();
    throw new Error(`HTTP ${resp.status} from ${url}${text ? `: ${text}` : ""}`);
  }
  return raw;
}

export const DEFAULT_REKOR_V2_URL = "https://log2025-1.rekor.sigstore.dev";

export interface RekorAnchorOptions {
  /** Rekor v2 shard (default {@link DEFAULT_REKOR_V2_URL}); Sigstore announces new shards via its TUF repository. */
  url?: string;
  timeoutMs?: number;
  clock?: Clock;
  /** The ECDSA P-256 anchor key (a KeyObject or PEM). Default: `<home>/keys/anchor-ecdsa-p256.pem`, created if missing. */
  privateKey?: KeyObject | string;
  fetch?: FetchLike;
}

/**
 * Publishes segment hashes to Sigstore Rekor v2 (public, append-only).
 *
 * Only a hash, an ECDSA P-256 signature and the anchor public key are sent. Rekor v2 does not
 * accept pure Ed25519 for `hashedrekord` entries, so anchoring uses a separate P-256 key
 * (PKCS#8 PEM, the same file the Python SDK uses); records themselves stay Ed25519-signed.
 * Every receipt is verified offline before it is returned.
 */
export class RekorAnchor implements Anchor {
  readonly type = "rekor";
  readonly url: string;
  readonly timeoutMs: number;
  readonly clock: Clock;
  /** DER SubjectPublicKeyInfo of the anchor key. */
  readonly publicDer: Uint8Array;
  readonly #key: KeyObject;
  readonly #fetch: FetchLike;

  constructor(home = ".gleipnir", opts: RekorAnchorOptions = {}) {
    this.url = (opts.url ?? DEFAULT_REKOR_V2_URL).replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 60_000;
    this.clock = opts.clock ?? utcnow;
    this.#fetch = opts.fetch ?? ((url, init) => fetch(url, init));
    let key: KeyObject;
    if (opts.privateKey !== undefined) {
      key = typeof opts.privateKey === "string" ? createPrivateKey(opts.privateKey) : opts.privateKey;
    } else {
      const path = join(home, "keys", "anchor-ecdsa-p256.pem");
      if (existsSync(path)) key = createPrivateKey(readFileSync(path, "utf8"));
      else {
        key = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
        writePrivateFile(path, key.export({ format: "pem", type: "pkcs8" }) as string);
      }
    }
    if (key.type !== "private" || key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      throw new Error("Rekor anchor key must be an ECDSA P-256 private key");
    }
    this.#key = key;
    this.publicDer = new Uint8Array(createPublicKey(key).export({ format: "der", type: "spki" }));
  }

  /** The hashedrekord v0.0.2 request body for `segmentHash` (as the Python SDK sends it). */
  requestBody(segmentHash: string): Rec {
    const message = anchorMessage(segmentHash);
    const sig = new Uint8Array(nodeSign("sha256", message, { key: this.#key, dsaEncoding: "der" }));
    return {
      hashedRekordRequestV002: {
        digest: b64encode(sha256(message)),
        signature: {
          content: b64encode(sig),
          verifier: { publicKey: { rawBytes: b64encode(this.publicDer) }, keyDetails: "PKIX_ECDSA_P256_SHA_256" },
        },
      },
    };
  }

  async anchor({ segmentHash }: AnchorRequest): Promise<Rec> {
    const raw = await post(
      this.#fetch,
      `${this.url}/api/v2/log/entries`,
      pyDumps(this.requestBody(segmentHash)), // json.dumps(body), byte-identical to the Python SDK
      { "Content-Type": "application/json", Accept: "application/json" },
      this.timeoutMs,
    );
    const entry = parseJsonBytes(raw);
    const receipt: Rec = {
      log_url: this.url,
      entry,
      anchor_key: { alg: "ecdsa-p256-sha256", public: b64encode(this.publicDer) },
      observed_at: iso(this.clock()),
    };
    const check = verifyRekorReceipt({ receipt }, segmentHash, {});
    if (check.ok !== true) throw new Error(`Rekor returned a receipt that does not verify: ${check.detail}`);
    return receipt;
  }
}

export const DEFAULT_TSA_URL = "https://timestamp.sigstore.dev/api/v1/timestamp";

export interface TimestampAnchorOptions {
  timeoutMs?: number;
  clock?: Clock;
  fetch?: FetchLike;
}

// DER pieces of a TimeStampReq (RFC 3161 section 2.4.1).
const der = (tag: number, body: Uint8Array): Uint8Array => {
  const n = body.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Uint8Array.from([tag, ...len, ...body]);
};
const cat = (...parts: Uint8Array[]): Uint8Array => Uint8Array.from(parts.flatMap((p) => [...p]));
// AlgorithmIdentifier { id-sha512, NULL }
const SHA512_ALG = Uint8Array.from([0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00]);

/** A positive, minimally encoded 64-bit INTEGER. */
function nonceInteger(): Uint8Array {
  const b = randomBytes(8);
  b[0]! &= 0x7f;
  let i = 0;
  while (i < b.length - 1 && b[i] === 0 && (b[i + 1]! & 0x80) === 0) i++;
  return der(0x02, b.subarray(i));
}

/**
 * TimeStampReq { version 1, messageImprint (SHA-512 of `message`), nonce, certReq TRUE }: the
 * same request the Python SDK sends (rfc3161-client's builder defaults).
 */
export function timestampRequest(message: Uint8Array): Uint8Array {
  const imprint = der(0x30, cat(SHA512_ALG, der(0x04, sha512(message))));
  return der(0x30, cat(Uint8Array.from([0x02, 0x01, 0x01]), imprint, nonceInteger(), Uint8Array.from([0x01, 0x01, 0xff])));
}

/**
 * Gets an RFC 3161 timestamp for each segment hash from a timestamp authority.
 *
 * Rekor v2 proves inclusion but not time; the timestamp proves the segment existed no later
 * than the TSA's signed time. The default TSA is Sigstore's public one, whose certificate chain
 * ships in the verifier's trusted root. Every token is verified offline before it is returned.
 */
export class TimestampAnchor implements Anchor {
  readonly type = "rfc3161";
  readonly url: string;
  readonly timeoutMs: number;
  readonly clock: Clock;
  readonly #fetch: FetchLike;

  constructor(url: string = DEFAULT_TSA_URL, opts: TimestampAnchorOptions = {}) {
    this.url = url;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.clock = opts.clock ?? utcnow;
    this.#fetch = opts.fetch ?? ((u, init) => fetch(u, init));
  }

  async anchor({ segmentHash }: AnchorRequest): Promise<Rec> {
    const request = timestampRequest(timestampMessage(segmentHash));
    const raw = await post(this.#fetch, this.url, request, { "Content-Type": "application/timestamp-query" }, this.timeoutMs);
    const receipt: Rec = { tsa_url: this.url, response: b64encode(raw), observed_at: iso(this.clock()) };
    const check = verifyTimestampReceipt({ receipt }, segmentHash, {});
    if (check.ok !== true) throw new Error(`timestamp authority returned a token that does not verify: ${check.detail}`);
    return receipt;
  }
}
