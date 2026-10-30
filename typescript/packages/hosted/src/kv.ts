/**
 * The smallest key-value surface the hosted checker needs: read with an ETag, conditional write, delete.
 * BlobsKV maps it onto Netlify Blobs (strong consistency); MemoryKV is the fake the tests use.
 */

import type { Store } from "@netlify/blobs";

export interface Entry {
  data: string;
  etag: string;
}

/** null: unconditional. {ifNew}: only if the key is absent. {ifMatch}: only if the current ETag is this one. */
export type Cond = { ifNew: true } | { ifMatch: string } | null;

export interface KV {
  get(key: string): Promise<Entry | null>;
  /** true if written; false if the condition did not hold. Throws if the store is unreachable. */
  put(key: string, data: string, cond: Cond): Promise<boolean>;
  del(key: string): Promise<void>;
}

export class BlobsKV implements KV {
  constructor(private readonly store: Store) {}

  async get(key: string): Promise<Entry | null> {
    const r = await this.store.getWithMetadata(key, { type: "text", consistency: "strong" });
    if (r === null) return null;
    if (typeof r.etag !== "string" || !r.etag) throw new Error("store returned no ETag");
    return { data: r.data, etag: r.etag };
  }

  async put(key: string, data: string, cond: Cond): Promise<boolean> {
    const opts = cond === null ? {} : "ifNew" in cond ? { onlyIfNew: true } : { onlyIfMatch: cond.ifMatch };
    const r = await this.store.set(key, data, opts);
    return r.modified;
  }

  async del(key: string): Promise<void> {
    await this.store.delete(key);
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
  failOn: ((op: "get" | "put" | "del", key: string) => boolean) | null = null;

  private async tick(op: "get" | "put" | "del", key: string): Promise<void> {
    await new Promise((r) => setTimeout(r, Math.random() * 2));
    if (this.failOn?.(op, key)) throw new Error("store unavailable");
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
    return true;
  }

  async del(key: string): Promise<void> {
    await this.tick("del", key);
    this.items.delete(key);
  }
}
