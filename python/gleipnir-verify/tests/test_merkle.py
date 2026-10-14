import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gleipnir_verify import merkle


def naive_root(entries):
    # Independent RFC 6962 MTH using explicit recursion on bit length.
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return hashlib.sha256(b"\x00" + entries[0]).digest()
    k = 2 ** ((len(entries) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + naive_root(entries[:k]) + naive_root(entries[k:])).digest()


def leaves(n):
    return [hashlib.sha256(str(i).encode()).digest() for i in range(n)]


@pytest.mark.parametrize("n", list(range(0, 40)))
def test_root_matches_naive(n):
    assert merkle.root(leaves(n)) == naive_root(leaves(n))


def test_known_vector_rfc6962_empty():
    assert merkle.root([]).hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize("n", list(range(1, 34)))
def test_all_inclusion_proofs_verify(n):
    ls = leaves(n)
    root = merkle.root(ls)
    for i in range(n):
        proof = merkle.inclusion_proof(i, ls)
        assert merkle.verify_inclusion(i, n, merkle.leaf_hash(ls[i]), proof, root)


@given(st.integers(min_value=2, max_value=64), st.data())
def test_tampered_proofs_fail(n, data):
    ls = leaves(n)
    root = merkle.root(ls)
    i = data.draw(st.integers(min_value=0, max_value=n - 1))
    proof = merkle.inclusion_proof(i, ls)
    # wrong leaf
    assert not merkle.verify_inclusion(i, n, merkle.leaf_hash(b"x"), proof, root)
    # wrong index
    j = data.draw(st.integers(min_value=0, max_value=n - 1).filter(lambda j: j != i))
    assert not merkle.verify_inclusion(j, n, merkle.leaf_hash(ls[i]), proof, root) or ls[i] == ls[j]
    # altered proof element
    if proof:
        k = data.draw(st.integers(min_value=0, max_value=len(proof) - 1))
        bad = list(proof)
        bad[k] = hashlib.sha256(bad[k]).digest()
        assert not merkle.verify_inclusion(i, n, merkle.leaf_hash(ls[i]), bad, root)
        assert not merkle.verify_inclusion(i, n, merkle.leaf_hash(ls[i]), proof[:-1], root)


def test_out_of_range():
    with pytest.raises(IndexError):
        merkle.inclusion_proof(3, leaves(3))
    assert not merkle.verify_inclusion(3, 3, b"", [], b"")
    assert not merkle.verify_inclusion(-1, 3, b"", [], b"")
