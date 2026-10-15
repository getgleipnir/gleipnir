import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  P256_PREFIX,
  canonicalizeString,
  decodePublicKey,
  ed25519PublicFromSeed,
  ed25519Sign,
  encodeP256PublicKey,
  encodeP256Signature,
  encodePublicKey,
  encodeSignature,
  p256Sign,
  p256SpkiFromScalar,
  verifyRecords,
  hexToBytes,
  bytesToHex,
  inclusionProof,
  keyId,
  leafHash,
  merkleRoot,
  parseJson,
  recordBody,
  recordHash,
  recordMessage,
  verifyInclusion,
  verifySignature,
} from "@getgleipnir/verify";

const VECTORS = fileURLToPath(new URL("../../../../spec/test-vectors/", import.meta.url));

const recordVectors = readdirSync(VECTORS)
  .filter((f) => /^\d+-.*\.json$/.test(f))
  .sort();

/** Parse with the verifier's own JSON parser (keeps -0.0 / big ints as the Python side reads them). */
function load(name: string): Record<string, unknown> {
  return parseJson(readFileSync(VECTORS + name, "utf8")) as Record<string, unknown>;
}

describe("spec test vectors: records", () => {
  it("has record vectors", () => {
    expect(recordVectors.length).toBeGreaterThanOrEqual(2);
  });

  for (const file of recordVectors) {
    describe(file, () => {
      const v = load(file);
      const record = v["record"] as Record<string, unknown>;

      it("reproduces the canonical bytes exactly", () => {
        expect(canonicalizeString(recordBody(record))).toBe(v["canonical"]);
      });

      it("reproduces the record hash", () => {
        expect(recordHash(record)).toBe(v["hash"]);
      });

      const p256 = typeof v["private_key_scalar_hex"] === "string";

      it("derives the public key and key id from the private key", () => {
        if (p256) {
          const spki = p256SpkiFromScalar(hexToBytes(v["private_key_scalar_hex"] as string));
          expect(encodeP256PublicKey(spki)).toBe(v["public_key"]);
        } else {
          const pub = ed25519PublicFromSeed(hexToBytes(v["private_key_seed_hex"] as string));
          expect(encodePublicKey(pub)).toBe(v["public_key"]);
          expect(keyId(pub)).toBe(v["key_id"]);
        }
        expect(keyId(decodePublicKey(v["public_key"]))).toBe(v["key_id"]);
        expect(record["key"]).toBe(v["key_id"]);
      });

      it("reproduces the signature byte for byte (Ed25519 and RFC 6979 ECDSA are deterministic) and verifies it", () => {
        const msg = recordMessage(v["hash"] as string);
        const sig = p256
          ? encodeP256Signature(p256Sign(hexToBytes(v["private_key_scalar_hex"] as string), msg))
          : encodeSignature(ed25519Sign(hexToBytes(v["private_key_seed_hex"] as string), msg));
        expect(sig).toBe(record["sig"]);
        const pub = decodePublicKey(v["public_key"]);
        expect(verifySignature(pub, msg, record["sig"])).toBe(true);
      });

      it.runIf(record["kind"] === "genesis")("verifies as a one-record chain", () => {
        const report = verifyRecords([record], { expectKey: v["key_id"] as string });
        expect(report.errors).toEqual([]);
        expect(report.summary["keys"]).toEqual([v["key_id"]]);
      });

      it("rejects a signature of the other key type", () => {
        const pub = decodePublicKey(v["public_key"]);
        const sig = record["sig"] as string;
        const swapped = p256 ? sig.replace(P256_PREFIX, "ed25519:") : sig.replace("ed25519:", P256_PREFIX);
        expect(verifySignature(pub, recordMessage(v["hash"] as string), swapped)).toBe(false);
      });

      it("rejects the signature over any other hash", () => {
        const pub = decodePublicKey(v["public_key"]);
        const other = "sha256:" + "00".repeat(32);
        expect(verifySignature(pub, recordMessage(other), record["sig"])).toBe(false);
      });

      it("canonicalizes the same when the record is parsed with JSON.parse", () => {
        // Plain JS numbers: -0.0 parses to -0, which JCS writes as 0; the hash must not change.
        const plain = JSON.parse(readFileSync(VECTORS + file, "utf8")).record;
        expect(recordHash(plain)).toBe(v["hash"]);
      });
    });
  }
});

describe("spec test vectors: Merkle", () => {
  const m = JSON.parse(readFileSync(VECTORS + "merkle.json", "utf8")) as {
    cases: Array<{ leaves: string[]; root: string; proofs?: string[][] }>;
  };

  for (const c of m.cases) {
    const leaves = c.leaves.map(hexToBytes);
    it(`root over ${leaves.length} leaves`, () => {
      expect(bytesToHex(merkleRoot(leaves))).toBe(c.root);
    });
    (c.proofs ?? []).forEach((proof, i) => {
      it(`inclusion proof for leaf ${i} of ${leaves.length}`, () => {
        expect(inclusionProof(i, leaves).map(bytesToHex)).toEqual(proof);
        const root = hexToBytes(c.root);
        const path = proof.map(hexToBytes);
        expect(verifyInclusion(i, leaves.length, leafHash(leaves[i]!), path, root)).toBe(true);
        // wrong index, out-of-range index, wrong root, tampered path
        expect(verifyInclusion(i + 1, leaves.length, leafHash(leaves[i]!), path, root)).toBe(false);
        expect(verifyInclusion(leaves.length, leaves.length, leafHash(leaves[i]!), path, root)).toBe(false);
        expect(verifyInclusion(-1, leaves.length, leafHash(leaves[i]!), path, root)).toBe(false);
        const badRoot = root.slice();
        badRoot[0]! ^= 1;
        expect(verifyInclusion(i, leaves.length, leafHash(leaves[i]!), path, badRoot)).toBe(false);
        if (path.length > 0) {
          const badPath = path.map((p) => p.slice());
          badPath[0]![0]! ^= 1;
          expect(verifyInclusion(i, leaves.length, leafHash(leaves[i]!), badPath, root)).toBe(false);
        }
      });
    });
  }
});
