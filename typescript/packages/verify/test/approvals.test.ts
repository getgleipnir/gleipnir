/**
 * Signed approvals: spec vectors (spec/test-vectors/approvals.json), differential tests against the
 * Python reference for valid and invalid key and WebAuthn approvals, and CLI parity.
 */

import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { p256 } from "@noble/curves/nist.js";
import {
  actionDigest,
  approvalChallenge,
  approvalMessage,
  b64uDecode,
  b64uEncode,
  bytesToHex,
  checkSignature,
  ed25519PublicFromSeed,
  ed25519Sign,
  encodeP256PublicKey,
  encodeP256Signature,
  encodePublicKey,
  encodeSignature,
  hexToBytes,
  loadApprovers,
  p256Sign,
  p256SpkiFromScalar,
  parseJson,
  verifyRecords,
  type Report,
} from "@getgleipnir/verify";
import { main } from "../src/cli.js";
import { Builder, rng, writeBundle, type Rec } from "./chainbuilder.js";
import { normalizeReport, oracle, pythonAvailable, pythonCli, toTsOptions } from "./oracle.js";

const V = parseJson(readFileSync(fileURLToPath(new URL("../../../../spec/test-vectors/approvals.json", import.meta.url)), "utf8")) as any;
const pairs = (r: Report) => r.findings.map((f) => [f.level, f.code]);
const d = pythonAvailable ? describe : describe.skip;

describe("spec vectors: signed approvals", () => {
  it("reproduces the digest, approval message and WebAuthn challenge", () => {
    expect(actionDigest(V.tool, V.system, V.args)).toBe(V.action_digest);
    expect(new TextDecoder().decode(approvalMessage(V.action_digest))).toBe(V.approval_message);
    expect(b64uEncode(approvalChallenge(V.action_digest))).toBe(V.webauthn_challenge);
  });

  it("reproduces the signatures byte for byte from the fixed keys (Ed25519, RFC 6979 P-256)", () => {
    const keys = V.approver_keys;
    const anna = V.cases[0].review.signature;
    const seed = hexToBytes(keys["ops:anna"].ed25519_seed_hex);
    expect(encodePublicKey(ed25519PublicFromSeed(seed))).toBe(anna.public_key);
    expect(encodeSignature(ed25519Sign(seed, approvalMessage(V.action_digest)))).toBe(anna.sig);
    const jonas = V.cases[1].review.signature;
    const js = hexToBytes(keys["ops:jonas"].p256_scalar_hex);
    expect(encodeP256PublicKey(p256SpkiFromScalar(js))).toBe(jonas.public_key);
    expect(encodeP256Signature(p256Sign(js, approvalMessage(V.action_digest)))).toBe(jonas.sig);
    const li = V.cases[2].review.signature;
    const ls = hexToBytes(keys["ops:li"].p256_scalar_hex);
    const auth = hexToBytes(keys["ops:li"].authenticator_data_hex);
    const cdj = new TextEncoder().encode(keys["ops:li"].client_data_json);
    expect(b64uEncode(auth)).toBe(li.authenticator_data);
    expect(b64uEncode(cdj)).toBe(li.client_data_json);
    const signed = new Uint8Array([...auth, ...createHash("sha256").update(cdj).digest()]);
    expect(b64uEncode(p256Sign(ls, signed))).toBe(li.signature);
    expect(encodeP256PublicKey(p256SpkiFromScalar(ls))).toBe(li.public_key);
  });

  const reg = loadApprovers(V.registry);
  for (const c of V.cases) {
    it(`case: ${c.description}`, () => {
      const modes: Array<[string, any, boolean]> = [["no_registry", null, false], ["registry", reg, false], ["require", reg, true]];
      for (const [mode, r, req] of modes) {
        const got = checkSignature(c.review, r, V.allowed_origins, req).map(([lv, code]) => [lv, code]);
        expect(got, mode).toEqual(c.expected[mode]);
      }
    });
  }

  it("verifies the whole approval chain in every mode as the vector says", () => {
    const kw: Record<string, any> = {
      no_registry: {},
      registry: { approvers: V.registry },
      registry_other_origin: { approvers: V.registry, webauthnOrigins: ["https://other.example"] },
      require: { approvers: V.registry, requireSignedApprovals: true },
    };
    for (const [mode, exp] of Object.entries<any>(V.chain.expected)) {
      const r = verifyRecords(V.chain.records, kw[mode]);
      expect({ valid: r.valid(), findings: pairs(r) }, mode).toEqual(exp);
    }
  });

  it("rejects malformed registries before verifying anything", () => {
    for (const bad of [{}, [5], [{ id: "", name: "x", public_key: "ed25519:" + "A".repeat(43) }], [{ id: "a", name: "x" }]]) {
      expect(() => loadApprovers(bad)).toThrow();
      expect(() => verifyRecords(new Builder().records, { approvers: bad as any })).toThrow();
    }
  });
});

// ---- differential ------------------------------------------------------------------------
const ED_SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 7);
const ED_PUB = encodePublicKey(ed25519PublicFromSeed(ED_SEED));
const WA_SCALAR = p256.utils.randomSecretKey();
const WA_PUB = encodeP256PublicKey(p256SpkiFromScalar(WA_SCALAR));
const RP = "approve.example.com";
const ORIGIN = `https://${RP}`;
const REGISTRY = [
  { id: "ops:anna", name: "Anna", public_key: ED_PUB },
  { id: "ops:li", name: "Li", webauthn: { public_key: WA_PUB, rp_id: RP } },
];

function keySig(digest: string, msg?: Uint8Array): Rec {
  return { type: "key", approver_id: "ops:anna", public_key: ED_PUB, sig: encodeSignature(ed25519Sign(ED_SEED, msg ?? approvalMessage(digest))) };
}

function waSig(digest: string, o: { cd?: Rec; flags?: number; rp?: string; extra?: Uint8Array; rawCd?: string } = {}): Rec {
  const cd = { type: "webauthn.get", challenge: b64uEncode(approvalChallenge(digest)), origin: ORIGIN, ...(o.cd ?? {}) };
  const cdj = new TextEncoder().encode(o.rawCd ?? JSON.stringify(cd));
  const rpHash = createHash("sha256").update(o.rp ?? RP).digest();
  const auth = new Uint8Array([...rpHash, o.flags ?? 0x05, 0, 0, 0, 1, ...(o.extra ?? [])]);
  const msg = new Uint8Array([...auth, ...createHash("sha256").update(cdj).digest()]);
  return {
    type: "webauthn",
    approver_id: "ops:li",
    public_key: WA_PUB,
    rp_id: RP,
    credential_id: "AAEC",
    authenticator_data: b64uEncode(auth),
    client_data_json: b64uEncode(cdj),
    signature: b64uEncode(p256Sign(WA_SCALAR, msg)),
  };
}

function signedChain(sig: (digest: string) => unknown, reviewer = "ops:anna"): Builder {
  const b = new Builder();
  const args = { order: "o1", amount: 1 };
  const digest = actionDigest("refund", "pay", args);
  const body: Rec = { action_digest: digest, tool: "refund", system: "pay", reviewer, decision: "approved", before_execution: true };
  const s = sig(digest);
  if (s !== undefined) body["signature"] = s;
  const rev = b.add({ kind: "review", review: body });
  b.action(1, { approval: rev["id"], args });
  b.anchor(b.segment());
  return b;
}

d("differential: signed approvals", () => {
  const digest = actionDigest("refund", "pay", { order: "o1", amount: 1 });
  const flip = (s: string) => s.slice(0, -2) + (s.at(-2) === "A" ? "B" : "A") + s.at(-1);
  const variants: Array<[string, (dg: string) => unknown, string?]> = [
    ["unsigned", () => undefined],
    ["key ok", (dg) => keySig(dg)],
    ["key flipped", (dg) => ({ ...keySig(dg), sig: flip(keySig(dg)["sig"]) })],
    ["key wrong domain", (dg) => keySig(dg, new TextEncoder().encode("gleipnir/record/v1\n" + dg))],
    ["key, reviewer differs", (dg) => keySig(dg), "ops:boss"],
    ["key bad pubkey", (dg) => ({ ...keySig(dg), public_key: "ecdsa-p256:AAAA" })],
    ["key sig not a string", (dg) => ({ ...keySig(dg), sig: 5 })],
    ["approver_id missing", (dg) => ({ ...keySig(dg), approver_id: undefined })],
    ["not an object", () => ["x"]],
    ["unknown approver", (dg) => ({ ...keySig(dg), approver_id: "ops:eve" }), "ops:eve"],
    ["webauthn ok", (dg) => waSig(dg), "ops:li"],
    ["webauthn BE|BS", (dg) => waSig(dg, { flags: 0x1d }), "ops:li"],
    ["webauthn BS without BE", (dg) => waSig(dg, { flags: 0x15 }), "ops:li"],
    ["webauthn ED with extensions", (dg) => waSig(dg, { flags: 0x85, extra: Uint8Array.of(0xa0) }), "ops:li"],
    ["webauthn ED without data", (dg) => waSig(dg, { flags: 0x85 }), "ops:li"],
    ["webauthn trailing bytes", (dg) => waSig(dg, { extra: Uint8Array.of(0) }), "ops:li"],
    ["webauthn no UV", (dg) => waSig(dg, { flags: 0x01 }), "ops:li"],
    ["webauthn no UP", (dg) => waSig(dg, { flags: 0x04 }), "ops:li"],
    ["webauthn AT", (dg) => waSig(dg, { flags: 0x45 }), "ops:li"],
    ["webauthn other rp", (dg) => waSig(dg, { rp: "evil.example" }), "ops:li"],
    ["webauthn origin", (dg) => waSig(dg, { cd: { origin: "https://evil.example" } }), "ops:li"],
    ["webauthn origin missing", (dg) => waSig(dg, { cd: { origin: 5 } }), "ops:li"],
    ["webauthn create", (dg) => waSig(dg, { cd: { type: "webauthn.create" } }), "ops:li"],
    ["webauthn challenge", (dg) => waSig(dg, { cd: { challenge: "AAAA" } }), "ops:li"],
    ["webauthn crossOrigin", (dg) => waSig(dg, { cd: { crossOrigin: true } }), "ops:li"],
    ["webauthn topOrigin", (dg) => waSig(dg, { cd: { topOrigin: ORIGIN } }), "ops:li"],
    ["webauthn cd not JSON", (dg) => waSig(dg, { rawCd: "{nope" }), "ops:li"],
    ["webauthn cd array", (dg) => waSig(dg, { rawCd: "[1]" }), "ops:li"],
    ["webauthn cd bad utf-8", (dg) => ({ ...waSig(dg), client_data_json: b64uEncode(Uint8Array.of(0xff, 0xfe)) }), "ops:li"],
    ["webauthn short auth", (dg) => ({ ...waSig(dg), authenticator_data: "AAAA" }), "ops:li"],
    ["webauthn non-b64", (dg) => ({ ...waSig(dg), signature: "@@" }), "ops:li"],
    ["webauthn b64 len%4==1", (dg) => ({ ...waSig(dg), signature: "AAAAA" }), "ops:li"],
    ["webauthn ed25519 key", (dg) => ({ ...waSig(dg), public_key: ED_PUB }), "ops:li"],
    ["webauthn as key", (dg) => ({ ...waSig(dg), type: "key" }), "ops:li"],
    ["webauthn no rp_id (no registry)", (dg) => ({ ...waSig(dg), rp_id: "" }), "ops:li"],
    ["webauthn credential differs", (dg) => ({ ...waSig(dg), credential_id: "AAAA" }), "ops:li"],
  ];
  const modes: Array<[string, Rec]> = [
    ["none", {}],
    ["registry", { approvers: REGISTRY }],
    ["registry+cred", { approvers: [REGISTRY[0], { ...REGISTRY[1], webauthn: { ...REGISTRY[1]!["webauthn"], credential_id: "AAEC" } }] }],
    ["origins", { approvers: REGISTRY, webauthn_origins: ["https://other.example", ORIGIN] }],
    ["require", { approvers: REGISTRY, require_signed_approvals: true }],
    ["require, no registry", { require_signed_approvals: true }],
  ];

  it("check_signature: same findings and messages as the reference", () => {
    const cases: unknown[] = [];
    const local: unknown[] = [];
    for (const [, mk, reviewer] of variants) {
      const sig = mk(digest);
      const body: Rec = { action_digest: digest, reviewer: reviewer ?? "ops:anna" };
      if (sig !== undefined) body["signature"] = JSON.parse(JSON.stringify(sig));
      for (const [, m] of modes) {
        const req = Boolean(m["require_signed_approvals"]);
        cases.push({ kind: "approval_sig", body, approvers: m["approvers"] ?? null, origins: m["webauthn_origins"] ?? null, require: req });
        const reg = m["approvers"] ? loadApprovers(m["approvers"]) : null;
        local.push({ findings: checkSignature(body, reg, m["webauthn_origins"] ?? null, req) });
      }
    }
    // malformed digests in the review
    for (const dg of ["sha256:" + "A".repeat(64), "sha256:00", 5, null]) {
      const body: Rec = { action_digest: dg, reviewer: "ops:anna", signature: keySig(digest) };
      cases.push({ kind: "approval_sig", body, approvers: REGISTRY, origins: null, require: false });
      local.push({ findings: checkSignature(body, loadApprovers(REGISTRY), null, false) });
    }
    expect(local).toEqual(oracle(cases));
  });

  it("whole chains: identical reports", () => {
    const cases: unknown[] = [];
    const local: unknown[] = [];
    for (const [, mk, reviewer] of variants) {
      const b = signedChain(mk, reviewer);
      const text = b.records.map((r) => JSON.stringify(r)).join("\n");
      for (const [, m] of modes) {
        cases.push({ kind: "records", text, options: m });
        local.push(normalizeReport(verifyRecords(parseJson("[" + b.records.map((r) => JSON.stringify(r)).join(",") + "]"), toTsOptions(m)).toJSON()));
      }
    }
    expect(local).toEqual(oracle(cases).map(normalizeReport));
  });

  it("approver registries: same acceptance and messages", () => {
    const texts = [
      JSON.stringify(REGISTRY),
      "{}",
      "[5]",
      "[]",
      JSON.stringify([{ id: "a", name: "x", public_key: ED_PUB }, { id: "a", name: "y", public_key: ED_PUB }]),
      JSON.stringify([{ name: "x", public_key: ED_PUB }]),
      JSON.stringify([{ id: 5, name: "x", public_key: ED_PUB }]),
      JSON.stringify([{ id: "a", public_key: ED_PUB }]),
      JSON.stringify([{ id: "a", name: "x" }]),
      JSON.stringify([{ id: "a", name: "x", public_key: ED_PUB, webauthn: {} }]),
      JSON.stringify([{ id: "a", name: "x", public_key: "nope" }]),
      JSON.stringify([{ id: "a", name: "x", public_key: 5 }]),
      JSON.stringify([{ id: "a", name: "x", roles: ["r", 5], public_key: ED_PUB }]),
      JSON.stringify([{ id: "a", name: "x", roles: null, public_key: ED_PUB }]),
      JSON.stringify([{ id: "a", name: "x", webauthn: [] }]),
      JSON.stringify([{ id: "a", name: "x", webauthn: { public_key: ED_PUB, rp_id: "x" } }]),
      JSON.stringify([{ id: "a", name: "x", webauthn: { public_key: WA_PUB } }]),
      JSON.stringify([{ id: "a", name: "x", webauthn: { public_key: WA_PUB, rp_id: "\ud800" } }]),
      JSON.stringify([{ id: "a", name: "x", webauthn: { public_key: WA_PUB, rp_id: "x", credential_id: "" } }]),
      JSON.stringify([{ id: "a", name: "x", webauthn: { public_key: WA_PUB, rp_id: "x", credential_id: "+/" } }]),
      JSON.stringify([{ id: "a", name: "x", webauthn: { public_key: WA_PUB, rp_id: "x", credential_id: null } }]),
      JSON.stringify([{ id: "aé", name: "x", public_key: ED_PUB }]),
    ];
    const local = texts.map((t) => {
      try {
        return { ids: [...loadApprovers(parseJson(t)).keys()].sort() };
      } catch (exc: any) {
        return { error: exc.name, message: exc.message };
      }
    });
    expect(local).toEqual(oracle(texts.map((text) => ({ kind: "registry", text }))));
  });

  it("random byte flips in WebAuthn fields agree with the reference", () => {
    const rand = rng(7);
    const cases: unknown[] = [];
    const local: unknown[] = [];
    const reg = loadApprovers(REGISTRY);
    for (let i = 0; i < 60; i++) {
      const sig = waSig(digest) as Rec;
      const field = ["authenticator_data", "client_data_json", "signature"][i % 3]!;
      const bytes = b64uDecode(sig[field]);
      bytes[Math.floor(rand() * bytes.length)]! ^= 1 << Math.floor(rand() * 8);
      sig[field] = b64uEncode(bytes);
      const body = { action_digest: digest, reviewer: "ops:li", signature: sig };
      cases.push({ kind: "approval_sig", body, approvers: REGISTRY, origins: null, require: false });
      local.push({ findings: checkSignature(body, reg, null, false) });
    }
    expect(local).toEqual(oracle(cases));
  });
});

describe("gleipnir-verify CLI: approvals", () => {
  const dir = mkdtempSync(join(tmpdir(), "gleipnir-approvals-"));
  const b = signedChain((dg) => keySig(dg));
  const bundle = join(dir, "b.zip");
  writeFileSync(bundle, writeBundle(b));
  const unsigned = join(dir, "u.zip");
  const ub = signedChain(() => undefined);
  writeFileSync(unsigned, writeBundle(ub));
  const reg = join(dir, "approvers.json");
  writeFileSync(reg, JSON.stringify(REGISTRY));
  const badReg = join(dir, "bad.json");
  writeFileSync(badReg, "[{}]");
  const notJson = join(dir, "nj.json");
  writeFileSync(notJson, "nope");
  const cli = (args: string[]) => {
    let out = "";
    let err = "";
    const code = main(args, { out: (s) => (out += s), err: (s) => (err += s) });
    return { code, out, err };
  };

  it("checks approvals against --approvers", () => {
    const r = cli([bundle, "--approvers", reg, "--require-signed-approvals"]);
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain("[info] seq 2 approval_verified: approved by Anna (ops:anna), signature verified");
    expect(cli([unsigned, "--approvers", reg]).code).toBe(1);
    expect(cli([unsigned]).code).toBe(0);
    expect(cli([unsigned, "--strict"]).code).toBe(1);
    expect(cli([bundle, "--require-signed-approvals"]).code).toBe(2);
    expect(cli([bundle, "--approvers", badReg]).code).toBe(2);
    expect(cli(["--help"]).out).toContain("--approvers FILE");
  });

  it.runIf(pythonAvailable)("prints exactly what the Python CLI prints", () => {
    const argvs = [
      [bundle],
      [bundle, "--approvers", reg],
      [bundle, "--approvers", reg, "--require-signed-approvals", "--json"],
      [bundle, "--approvers", reg, "--webauthn-origin", "https://x.example", "--webauthn-origin", ORIGIN],
      [unsigned, "--approvers", reg],
      [unsigned, "--json"],
      [bundle, "--require-signed-approvals"],
      [bundle, "--approvers", badReg],
      [bundle, "--approvers", notJson],
      [bundle, "--approvers", join(dir, "missing.json")],
      [bundle, "--approvers"],
    ];
    for (const argv of argvs) {
      const py = pythonCli(argv);
      const ts = cli(argv);
      // Only the error line: argparse wraps the usage block to the terminal width (the TS CLI does not).
      const norm = (s: string) => s.split("\n").filter((l) => l.startsWith("gleipnir-verify: error:")).join("\n");
      expect([ts.code, ts.out, norm(ts.err)], argv.slice(1).join(" ")).toEqual([py.code, py.out, norm(py.err)]);
    }
  });
});

void bytesToHex;
