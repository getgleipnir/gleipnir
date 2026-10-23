"""The shared conformance vectors (also run by the TypeScript port) match the Python reference."""

from __future__ import annotations

import json

import mandate_vectors as V
import pytest

from gleipnir_verify import mandate as M

DATA = json.loads(V.OUT.read_text(encoding="utf-8"))


@pytest.mark.parametrize("c", DATA["cases"], ids=[c["name"] for c in DATA["cases"]])
def test_vector(c):
    decisions = V.run(c)
    assert V.expected(decisions) == c["expect"]
    first = (c.get("mandates") or [c["mandate"]])[(c.get("which") or [0])[0]]
    receipt = M.verify_receipt(first, c["payments"][0], decisions[0], [DATA["bank"]["public_key"]],
                               webauthn=c["webauthn"])
    assert {k: v for k, v in receipt.items() if k != "checked_at"} == c["receipt"]


def test_fixture_is_current():
    """The fixture is what the generator writes today (rerun mandate_vectors.py after changing either)."""
    fresh = V.build()
    for c_old, c_new in zip(DATA["cases"], fresh["cases"], strict=True):
        assert {k: v for k, v in c_old.items()} == {k: v for k, v in c_new.items()}


def test_payment_keys_are_unambiguous():
    keys = [k for _, _, k in DATA["payment_keys"]]
    assert len(set(keys)) == len(keys)
    for co, pid, key in DATA["payment_keys"]:
        assert M.payment_key(co, pid) == key


def test_signed_decisions_verify():
    keys = [DATA["bank"]["public_key"]]
    for d in DATA["signed"]:
        assert M.verify_decision(d, keys)
        assert not M.verify_decision({**d, "outcome": "allow" if d["outcome"] != "allow" else "block"}, keys)
        assert not M.verify_decision(d, [DATA["other_public_key"]])


def test_problem_messages():
    for kind, obj, problem in DATA["problems"]:
        assert (M.mandate_problem if kind == "mandate" else M.payment_problem)(obj) == problem
