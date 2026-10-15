/**
 * Differential tests against the Python reference for the second review (315ae62): duplicate ids,
 * approvals over dropped fields, proofs of non-actions, no_trusted_time, record-line rules,
 * strict Rekor integers, top-level reconcile ids with --tool, CSV read errors.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { actionDigest, parseJsonl, reconcile, recordHash, verifyBundle, verifyRecords, verifyRekorReceipt } from "@getgleipnir/verify";
import { main } from "../src/cli.js";
import { Builder, P256Key, proofFiles, proofZip, resign, writeBundle, zipBundle, type Rec } from "./chainbuilder.js";
import { REPO, normalizeReport, oracle, pythonAvailable, pythonCli, stripExceptionText, toTsOptions } from "./oracle.js";

const d = pythonAvailable ? describe : describe.skip;

function cli(args: string[]) {
  let out = "";
  let err = "";
  const code = main(args, { out: (s) => (out += s), err: (s) => (err += s) });
  return { code, out, err };
}

d("differential: second review", () => {
  it("record reports match: duplicate ids, dropped-field approvals, no_trusted_time", () => {
    const cases: Array<{ name: string; records: Rec[]; options?: Record<string, unknown> }> = [];
    let b = new Builder();
    b.action(1);
    b.action(2);
    b.records[2]!["id"] = b.records[1]!["id"];
    resign(b.records, b.key, 2);
    cases.push({ name: "duplicate id", records: b.records });
    b = new Builder();
    b.action(1, { id: 7 });
    b.action(2, { id: 7 });
    b.action(3, { id: null });
    b.action(4, { id: null });
    b.action(5, { id: "x" });
    b.add({ kind: "note", id: "x", note: { text: "same id, other kind" } });
    b.add({ kind: "note", id: "x", note: { text: "third" } });
    cases.push({ name: "duplicate ids, odd types", records: b.records });
    for (const [name, args] of [
      ["dropped top", { order: "o1", amount: { redacted: "dropped" } }],
      ["dropped nested", { order: "o1", items: [{ card: { redacted: "dropped" } }] }],
      ["dropped with extra key", { order: "o1", amount: { redacted: "dropped", note: 1 } }],
      ["hmac", { order: "o1", amount: { redacted: "hmac-sha256:00" } }],
      ["deep", JSON.parse("[".repeat(102) + "1" + "]".repeat(102))],
      ["deep-ish", JSON.parse("[".repeat(99) + "1" + "]".repeat(99))],
    ] as const) {
      b = new Builder();
      b.add({ kind: "review", id: "rev1", review: { action_digest: actionDigest("refund", "pay", args), decision: "approved", reviewer: "x" } });
      b.action(1, { approval: "rev1", args });
      cases.push({ name: `approval ${name}`, records: b.records });
    }
    // dropped field without an approval is fine
    b = new Builder();
    b.action(1, { args: { card: { redacted: "dropped" } } });
    cases.push({ name: "dropped without approval", records: b.records });
    // no_trusted_time with and without timestamps / anchors
    const s = new Builder().standard();
    for (const delay of [0, 86400, 1e9]) {
      cases.push({ name: `max delay ${delay}`, records: s.records, options: { local_anchor_entries: s.anchorLog, max_anchor_delay: delay } });
    }
    cases.push({ name: "max delay, no log", records: s.records, options: { max_anchor_delay: 60 } });
    const py = oracle(cases.map((c) => ({ kind: "records", text: c.records.map((r) => JSON.stringify(r)).join("\n"), options: c.options ?? {} })));
    cases.forEach((c, i) => {
      const ts = normalizeReport(verifyRecords(parseJsonl(c.records.map((r) => JSON.stringify(r)).join("\n")), toTsOptions(c.options)).toJSON());
      expect(stripExceptionText(ts), c.name).toEqual(stripExceptionText(py[i]));
    });
  });

  it("bundle and proof reports match: line rules, proofs of non-actions, Rekor integers", () => {
    const dir = mkdtempSync(join(tmpdir(), "gleipnir-r2-"));
    const items: Array<[string, Uint8Array, Record<string, unknown>]> = [];
    const b = new Builder().standard(2, 3);
    const manifest = JSON.stringify({ format: 1, chain: b.chain, from_seq: 1, to_seq: b.records[b.records.length - 1]!["seq"] });
    const log = b.anchorLog.map((e) => JSON.stringify(e) + "\n").join("");
    const withLines = (text: string, logText = log) => zipBundle({ "manifest.json": manifest, "records.jsonl": text, "anchors/local-anchor-log.jsonl": logText });
    const lines = b.records.map((r) => JSON.stringify(r));
    for (const [name, text] of [
      ["plain", lines.join("\n")],
      ["crlf", lines.join("\r\n")],
      ["blank lines", lines.join("\n\n \t\r\n")],
      ["leading blank", "\n\r\n" + lines.join("\n")],
      ["trailing space", lines.map((l) => l + " ").join("\n")],
      ["leading tab", lines.map((l) => "\t" + l).join("\n")],
      ...["\u000b", "\u000c", "\u001c", "\u001d", "\u001e", "\u0085", " ", " ", " ", "　"].flatMap((c) => [
        [`suffix U+${c.charCodeAt(0).toString(16)}`, lines.map((l) => l + c).join("\n")],
        [`separator U+${c.charCodeAt(0).toString(16)}`, lines.join(c)],
        [`blank line of U+${c.charCodeAt(0).toString(16)}`, lines.join("\n" + c + "\n")],
      ]),
      ["two values on a line", lines[0] + " " + lines[1] + "\n" + lines.slice(2).join("\n")],
    ] as const) {
      items.push([`lines ${name}`, withLines(text), {}]);
    }
    items.push(["log with VT", withLines(lines.join("\n"), b.anchorLog.map((e) => JSON.stringify(e) + "\u000b\n").join("")), {}]);
    items.push(["log with blank lines", withLines(lines.join("\n"), "\n \r\n" + log + "\t\n"), {}]);
    // proofs of non-actions
    for (const key of [undefined, new P256Key()]) {
      const p = new Builder(key ? { key } : {});
      p.action(1);
      const note = p.add({ kind: "note", note: { text: "n" } });
      const rev = p.add({ kind: "review", review: { decision: "approved" } });
      p.anchor(p.segment());
      for (const rec of [note, rev, p.records[1]!]) {
        const f = proofFiles(p, rec["id"]);
        items.push([`proof of ${rec["kind"]} ${key ? "p256" : "ed"}`, proofZip(p, f.manifest, f.records), {}]);
      }
      const f = proofFiles(p, p.records[1]!["id"]);
      const r = structuredClone(f.records);
      delete r[1]!["kind"];
      delete r[1]!["sig"];
      r[1]!["sig"] = p.key.sign(recordHash(r[1]!));
      items.push([`proof of kindless ${key ? "p256" : "ed"}`, proofZip(p, f.manifest, r), {}]);
      items.push([`proof with max delay ${key ? "p256" : "ed"}`, proofZip(p, f.manifest, f.records), { max_anchor_delay: 10 }]);
    }
    const cases = items.map(([name, bytes, options]) => {
      const p = join(dir, name.replace(/\W/g, "_") + ".zip");
      writeFileSync(p, bytes);
      return { kind: "bundle", path: p, options };
    });
    const py = oracle(cases);
    items.forEach(([name, bytes, options], i) => {
      const ts = normalizeReport(verifyBundle(bytes, toTsOptions(options)).toJSON()) as any;
      const want = py[i];
      if (ts.findings?.[0]?.code === "bad_bundle" || want.findings?.[0]?.code === "bad_bundle") {
        expect([ts.result, ts.findings.map((f: any) => f.code)], name).toEqual([want.result, want.findings.map((f: any) => f.code)]);
      } else {
        expect(stripExceptionText(ts), name).toEqual(stripExceptionText(want));
      }
    });
  });

  it("Rekor logIndex / treeSize accept and reject the same values", () => {
    const FIX = fileURLToPath(new URL("./fixtures/", import.meta.url));
    const fx = JSON.parse(readFileSync(FIX + "rekor_v2_receipt.json", "utf8"));
    const dir = mkdtempSync(join(tmpdir(), "gleipnir-rk-"));
    const values: unknown[] = [];
    const idx = fx.anchor.receipt.entry.inclusionProof.logIndex as string;
    values.push(idx, Number(idx), "+" + idx, ` ${idx} `, idx.replace(/(\d)(\d)/, "$1_$2"), "١", Number(idx) + 0.5, true, false, -1, "", "0x10", null, [idx], "0" + idx, Number(idx) + 1);
    const results: Array<[string, any]> = [];
    for (const field of ["logIndex", "treeSize"]) {
      for (const v of values) {
        const a = structuredClone(fx.anchor);
        a.receipt.entry.inclusionProof[field] = v;
        results.push([`${field}=${JSON.stringify(v)}`, a]);
      }
    }
    // Compare with rekor.verify_rekor_receipt on each mutated anchor.
    const path = join(dir, "anchors.json");
    writeFileSync(path, JSON.stringify(results.map(([, a]) => a)));
    const res = execFileSync(
      "uv",
      [
        "run", "--quiet", "python", "-I", "-c",
        "import json,sys\nfrom gleipnir_verify.rekor import verify_rekor_receipt\n" +
          "print(json.dumps([verify_rekor_receipt(a, segment_hash=sys.argv[2], options={}).ok for a in json.load(open(sys.argv[1]))]))",
        path, fx.segment_hash,
      ],
      { encoding: "utf8", cwd: REPO },
    );
    const py = JSON.parse(res) as Array<boolean | null>;
    expect(py.filter((x) => x === true).length).toBeGreaterThan(0);
    results.forEach(([name, a], i) => {
      expect(verifyRekorReceipt(a, fx.segment_hash, {}).ok, name).toBe(py[i]);
    });
  });

  it("reconcile matches: top-level ids only, --tool, CSV read errors are usage errors", () => {
    const dir = mkdtempSync(join(tmpdir(), "gleipnir-rc2-"));
    const b = new Builder();
    b.action(0, { tool: { name: "issue_refund", system: "p" }, response: { status: "ok", body: { refund_id: "R1", nested: { refund_id: "N1" } } } });
    b.action(1, { tool: { name: "list_refunds", system: "p" }, response: { status: "ok", body: { items: [{ refund_id: "R1" }, { refund_id: "R2" }] } } });
    b.action(2, { tool: { name: "lookup", system: "p" }, response: { status: "ok", body: { refund_id: 42 } } });
    b.action(3, { tool: { name: "issue_refund", system: "p" }, response: { status: "ok", body: { refund_id: true } } });
    b.action(4, { tool: { name: "issue_refund", system: "p" }, response: { status: "ok", body: [{ refund_id: "L1" }] } });
    b.action(5, { tool: "issue_refund", response: { status: "ok", body: { refund_id: "T1" } } });
    b.action(6, { tool: { name: "issue_refund", system: "p" }, response: { status: "error", error: "x" } });
    b.action(7, { tool: { name: "issue_refund", system: "p" }, response: { status: "ok", body: { refund_id: 1.5 } } });
    b.add({ kind: "note", tool: { name: "issue_refund" }, response: { status: "ok", body: { refund_id: "NOTE" } }, note: { text: "x" } });
    b.anchor(b.segment());
    const bp = join(dir, "b.zip");
    writeFileSync(bp, writeBundle(b));
    const csv = (name: string, content: string | Uint8Array) => {
      const p = join(dir, name);
      writeFileSync(p, content);
      return p;
    };
    const good = csv("good.csv", "refund_id\nR1\nR2\n42\nT1\n");
    const argvs: string[][] = [
      ["reconcile", bp, good, "--column", "refund_id"],
      ["reconcile", bp, good, "--column", "refund_id", "--tool", "issue_refund"],
      ["reconcile", bp, good, "--column", "refund_id", "--tool", "issue_refund", "--tool", "lookup"],
      ["reconcile", bp, good, "--column", "refund_id", "--tool", "nope"],
      ["reconcile", bp, csv("other.csv", "rid\nR1\n"), "--column", "rid", "--field", "refund_id"],
      ["reconcile", bp, csv("nested.csv", "rid\nN1\n"), "--column", "rid", "--field", "refund_id"],
      ["reconcile", bp, csv("nul.csv", "refund_id\nR\u00001\n"), "--column", "refund_id"],
      ["reconcile", bp, csv("latin1.csv", new Uint8Array([0x72, 0x0a, 0xe9, 0x0a])), "--column", "r"],
      ["reconcile", bp, csv("empty.csv", ""), "--column", "refund_id"],
      ["reconcile", bp, good, "--column", "refund_id", "--tool"],
    ];
    for (const argv of argvs) {
      const py = pythonCli(argv);
      const ts = cli(argv);
      expect([ts.code, ts.out, ts.err], argv.slice(2).join(" ")).toEqual([py.code, py.out, py.err]);
    }
    const r = reconcile(readFileSync(bp), "refund_id\nR1\nR2\n", { column: "refund_id", tools: ["issue_refund"] });
    expect([...r.matched]).toEqual(["R1"]);
  });
});
