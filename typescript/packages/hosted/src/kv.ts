/**
 * The smallest key-value surface the hosted checker needs: read with an ETag, conditional write, delete, list.
 * BlobsKV maps it onto Netlify Blobs (strong consistency); MemoryKV is the fake the tests use.
 */

import type { Store } from "@netlify/blobs";

export interface Entry {
  data: string;
  etag: string;
}

/** null: unconditional. {ifNew}: only if the key is absent. {ifMatch}: only if the current ETag is this one. */
export type Cond = { ifNew: true } | { ifMatch: string } | null;

export class StoreError extends Error {}

export interface KV {
  get(key: string): Promise<Entry | null>;
  /**
   * true if written; false only if the condition did not hold. Throws (StoreError) on anything else,
   * including an answer the store gives that does not prove the write happened.
   */
  put(key: string, data: string, cond: Cond): Promise<boolean>;
  del(key: string): Promise<void>;
  /** Keys under a prefix (at most `max`). */
  list(prefix: string, max: number): Promise<string[]>;
}

/**
 * Netlify Blobs. Its client reports a conditional write as `{modified: false}` only on 412, and as
 * `{modified: true}` for every other status (400, 401, 403, 404, 413, and 429/5xx once its retries run out),
 * so `modified` alone is not proof of a write. A write counts only when the answer is `modified: true` with
 * the new ETag, or when reading the key back returns exactly the bytes written. Anything else throws, and
 * the caller fails closed.
 */
export class BlobsKV implements KV {
  constructor(private readonly store: Store) {}

  async get(key: string): Promise<Entry | null> {
    const r = await this.store.getWithMetadata(key, { type: "text", consistency: "strong" });
    if (r === null) return null;
    if (typeof r.etag !== "string" || !r.etag || typeof r.data !== "string") throw new StoreError("store returned no ETag");
    return { data: r.data, etag: r.etag };
  }

  async put(key: string, data: string, cond: Cond): Promise<boolean> {
    const opts = cond === null ? {} : "ifNew" in cond ? { onlyIfNew: true } : { onlyIfMatch: cond.ifMatch };
    const r = await this.store.set(key, data, opts);
    if (r.modified === false) {
      if (cond === null) throw new StoreError("unconditional write not applied");
      return false;
    }
    if (r.modified === true && typeof r.etag === "string" && r.etag.length > 0) return true;
    // No ETag: an error status, or an edge that omits it. Every value we write carries a unique op nonce
    // (state.ts), so reading back exactly these bytes proves this write landed; anything else is a failure.
    const back = await this.get(key);
    if (back !== null && back.data === data) return true;
    throw new StoreError("store did not confirm the write");
  }

  async del(key: string): Promise<void> {
    await this.store.delete(key);
  }

  async list(prefix: string, max: number): Promise<string[]> {
    const out: string[] = [];
    for await (const page of this.store.list({ prefix, paginate: true })) {
      for (const b of page.blobs) {
        out.push(b.key);
        if (out.length >= max) return out;
      }
    }
    return out;
  }
}

/**
 * In-memory KV with the same conditional-write semantics. Every call yields to the event loop first, so
 * concurrent callers interleave the way they would against a remote store.
 */
export class MemoryKV implements KV {
  readonly items = new Map<string, Entry>();
  private n = 0;
  /** Set to make every call (or the calls whose key matches) throw, to test failing closed. */
  failOn: ((op: "get" | "put" | "del" | "list", key: string) => boolean) | null = null;
  /**
   * Set to make a write land but report a lost answer: the store applies it, then the caller sees a 412
   * (what a client-side retry of a committed PUT looks like).
   */
  lostAnswer: ((key: string) => boolean) | null = null;

  private async tick(op: "get" | "put" | "del" | "list", key: string): Promise<void> {
    await new Promise((r) => setTimeout(r, Math.random() * 2));
    if (this.failOn?.(op, key)) throw new StoreError("store unavailable");
  }

  async get(key: string): Promise<Entry | null> {
    await this.tick("get", key);
    const e = this.items.get(key);
    return e ? { ...e } : null;
  }

  async put(key: string, data: string, cond: Cond): Promise<boolean> {
    await this.tick("put", key);
    const cur = this.items.get(key);
    if (cond !== null && "ifNew" in cond && cur) return false;
    if (cond !== null && "ifMatch" in cond && (!cur || cur.etag !== cond.ifMatch)) return false;
    this.items.set(key, { data, etag: `"${++this.n}"` });
    if (cond !== null && this.lostAnswer?.(key)) return false;
    return true;
  }

  async del(key: string): Promise<void> {
    await this.tick("del", key);
    this.items.delete(key);
  }

  async list(prefix: string, max: number): Promise<string[]> {
    await this.tick("list", prefix);
    return [...this.items.keys()].filter((k) => k.startsWith(prefix)).sort().slice(0, max);
  }
}
