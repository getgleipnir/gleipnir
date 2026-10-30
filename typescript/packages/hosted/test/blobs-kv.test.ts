// BlobsKV against the real @netlify/blobs client with a fake edge (fetch): a write counts only when the store
// proves it, and a committed write whose answer was lost is never applied twice.
import { getStore } from "@netlify/blobs";
import { describe, expect, it } from "vitest";
import { BlobsKV } from "../src/kv.js";
import { KVLedger, KVPaymentLog, update } from "../src/state.js";

interface Edge {
  data: Map<string, { body: string; etag: string }>;
  /** Next PUT answers with this status without storing. */
  failPut: number;
  /** Next PUT is stored, then answered with this status (the client then retries it). */
  commitThen: number;
  /** Omit the ETag header on successful PUTs. */
  noEtag: boolean;
  puts: number;
  /** Runs right after a commitThen write lands: another writer gets in before the client's retry. */
  between: ((key: string) => void) | null;
}

function fakeStore(): [BlobsKV, Edge] {
  const edge: Edge = { data: new Map(), failPut: 0, commitThen: 0, noEtag: false, puts: 0, between: null };
  let n = 0;
  const fetchFake = async (url: string, opts: { method: string; headers?: Record<string, string>; body?: unknown }) => {
    const key = decodeURIComponent(new URL(url).pathname.split("/").pop()!);
    const hd = opts.headers ?? {};
    if (opts.method === "get") {
      const e = edge.data.get(key);
      return e ? new Response(e.body, { status: 200, headers: { etag: e.etag } }) : new Response(null, { status: 404 });
    }
    if (opts.method === "put") {
      edge.puts++;
      if (edge.failPut) {
        const st = edge.failPut;
        return new Response("boom", { status: st });
      }
      const cur = edge.data.get(key);
      if (hd["if-none-match"] === "*" && cur) return new Response(null, { status: 412 });
      if (hd["if-match"] && (!cur || cur.etag !== hd["if-match"])) return new Response(null, { status: 412 });
      const etag = `"${++n}"`;
      edge.data.set(key, { body: String(opts.body), etag });
      if (edge.commitThen) {
        const st = edge.commitThen;
        edge.commitThen = 0;
        edge.between?.(key);
        return new Response(null, { status: st });
      }
      return new Response(null, { status: 200, headers: edge.noEtag ? {} : { etag } });
    }
    if (opts.method === "delete") {
      edge.data.delete(key);
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 400 });
  };
  const store = getStore({ name: "s", siteID: "site", token: "tok", edgeURL: "https://edge.example",
    uncachedEdgeURL: "https://edge.example", consistency: "strong", fetch: fetchFake as unknown as typeof fetch });
  return [new BlobsKV(store), edge];
}

const AT = BigInt(Date.UTC(2026, 9, 30)) * 1000n;
const total = (edge: Edge) => [...edge.data.values()].map((v) => JSON.parse(v.body).total).find((x) => x !== undefined);

describe("BlobsKV on the Netlify Blobs client", () => {
  it("200 with an ETag is a write; 412 is a refused condition", async () => {
    const [kv] = fakeStore();
    expect(await kv.put("k", "a", { ifNew: true })).toBe(true);
    expect(await kv.put("k", "b", { ifNew: true })).toBe(false);
    expect(await kv.put("k", "b", { ifMatch: '"nope"' })).toBe(false);
    const e = (await kv.get("k"))!;
    expect(await kv.put("k", "c", { ifMatch: e.etag })).toBe(true);
    expect((await kv.get("k"))!.data).toBe("c");
  });

  it.each([400, 401, 403, 404, 413, 429, 500, 503])("a PUT answered %i throws (the client calls it modified)", async (status) => {
    const [kv, edge] = fakeStore();
    edge.failPut = status;
    await expect(kv.put("k", "a", { ifNew: true })).rejects.toThrow();
    await expect(kv.put("k", "a", null)).rejects.toThrow();
    const ledger = new KVLedger(kv, "t"), log = new KVPaymentLog(kv, "t");
    await expect(ledger.reserve("mandate:x", "P1D", 60n, 100n, AT)).rejects.toThrow();
    await expect(log.register("p", "h")).rejects.toThrow();
    expect(edge.data.size).toBe(0);
  });

  it("the period limit holds and replays are caught when every write goes through the real client", async () => {
    const [kv] = fakeStore();
    const ledger = new KVLedger(kv, "t"), log = new KVPaymentLog(kv, "t");
    expect(await ledger.reserve("mandate:x", "P1D", 60n, 100n, AT)).toBe(true);
    expect(await ledger.reserve("mandate:x", "P1D", 60n, 100n, AT)).toBe(false);
    expect(await log.register("p", "h")).toBe(true);
    expect(await log.register("p", "h")).toBe(false);
  });

  it("a 200 without an ETag counts only if the bytes read back are ours", async () => {
    const [kv, edge] = fakeStore();
    edge.noEtag = true;
    expect(await kv.put("k", "a", { ifNew: true })).toBe(true);
  });

  it("a committed write whose answer was lost (5xx, then 412 on the client's retry) is applied once", async () => {
    const [kv, edge] = fakeStore();
    const ledger = new KVLedger(kv, "t");
    expect(await ledger.reserve("mandate:x", "P1D", 70n, 100n, AT)).toBe(true);
    edge.commitThen = 503; // the release lands, the client retries, the retry gets 412
    await ledger.release("mandate:x", "P1D", 30n, AT);
    expect(total(edge)).toBe("40"); // not 10: subtracted once
    edge.commitThen = 503;
    expect(await ledger.reserve("mandate:x", "P1D", 50n, 100n, AT)).toBe(true);
    expect(total(edge)).toBe("90"); // added once
    const log = new KVPaymentLog(kv, "t");
    edge.commitThen = 500;
    expect(await log.register("p", "h")).toBe(true); // our own claim, not a duplicate
  });

  it("update() recognises its own landed write even after someone else wrote on top", async () => {
    const [kv, edge] = fakeStore();
    await update(kv, "c", () => [{ n: 1 }, undefined]);
    edge.between = (key) => { // a concurrent writer, carrying the op history forward as update() does
      const v = JSON.parse(edge.data.get(key)!.body);
      edge.data.set(key, { body: JSON.stringify({ n: v.n + 100, ops: [...v.ops, "other"] }), etag: '"other"' });
    };
    edge.commitThen = 503;
    let calls = 0;
    const res = await update(kv, "c", (cur) => [{ n: (cur!.n as number) + 1 }, ++calls]);
    expect(res).toBe(1);
    expect(calls).toBe(1);
    expect(JSON.parse(edge.data.get("c")!.body).n).toBe(102); // 1 + 1 + 100: ours applied once
  });
});
