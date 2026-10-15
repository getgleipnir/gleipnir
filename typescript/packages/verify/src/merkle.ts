/** RFC 6962 / RFC 9162 Merkle tree hashing and inclusion proofs. */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesEqual, concatBytes } from "./bytes.js";

const LEAF = Uint8Array.of(0);
const NODE = Uint8Array.of(1);

export function leafHash(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(LEAF, data));
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(NODE, left, right));
}

/** Largest power of two strictly smaller than n (n >= 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Merkle tree hash of the given leaf inputs (not pre-hashed). */
export function merkleRoot(entries: readonly Uint8Array[]): Uint8Array {
  const n = entries.length;
  if (n === 0) return sha256(new Uint8Array(0));
  if (n === 1) return leafHash(entries[0]!);
  const k = split(n);
  return nodeHash(merkleRoot(entries.slice(0, k)), merkleRoot(entries.slice(k)));
}

export function inclusionProof(index: number, entries: readonly Uint8Array[]): Uint8Array[] {
  const n = entries.length;
  if (!(index >= 0 && index < n)) throw new RangeError("leaf index out of range");
  if (n === 1) return [];
  const k = split(n);
  if (index < k) return [...inclusionProof(index, entries.slice(0, k)), merkleRoot(entries.slice(k))];
  return [...inclusionProof(index - k, entries.slice(k)), merkleRoot(entries.slice(0, k))];
}

/** RFC 9162 section 2.1.3.2. `leaf` is the leaf *hash*. Indexes are bigint to cover any log size. */
export function verifyInclusion(
  index: bigint | number,
  treeSize: bigint | number,
  leaf: Uint8Array,
  proof: readonly Uint8Array[],
  expectedRoot: Uint8Array,
): boolean {
  const idx = BigInt(index);
  const size = BigInt(treeSize);
  if (idx >= size || idx < 0n) return false;
  let fn = idx;
  let sn = size - 1n;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && bytesEqual(r, expectedRoot);
}
