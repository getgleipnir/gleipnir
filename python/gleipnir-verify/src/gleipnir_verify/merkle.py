"""RFC 6962 / RFC 9162 Merkle tree hashing and inclusion proofs."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(entries: Sequence[bytes]) -> bytes:
    """Merkle tree hash of the given leaf inputs (not pre-hashed)."""
    n = len(entries)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(entries[0])
    k = _split(n)
    return node_hash(root(entries[:k]), root(entries[k:]))


def inclusion_proof(index: int, entries: Sequence[bytes]) -> list[bytes]:
    n = len(entries)
    if not 0 <= index < n:
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, entries[:k]) + [root(entries[k:])]
    return inclusion_proof(index - k, entries[k:]) + [root(entries[:k])]


def verify_inclusion(index: int, tree_size: int, leaf: bytes, proof: Sequence[bytes], expected_root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2. ``leaf`` is the leaf *hash*."""
    if index >= tree_size or index < 0:
        return False
    fn, sn = index, tree_size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root
