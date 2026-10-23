"""The shared conformance vectors (also run by the TypeScript port) match the Python reference."""

from __future__ import annotations

import json

import mandate_vectors as V
import pytest

from gleipnir_verify import mandate as M

DATA = json.loads(V.OUT.read_text(encoding="utf-8"))


@pytest.mark.parametrize("c", DATA["cases"], ids=[c["name"] for c in DATA["cases"]])
def test_vector(c):
    assert V.expected(V.run(c)) == c["expect"]


def test_fixture_is_current():
    """The fixture is what the generator writes today (rerun mandate_vectors.py after changing either)."""
    fresh = V.build()
    for c_old, c_new in zip(DATA["cases"], fresh["cases"], strict=True):
        assert {k: v for k, v in c_old.items()} == {k: v for k, v in c_new.items()}


def test_signed_decisions_verify():
    keys = [DATA["bank"]["public_key"]]
    for d in DATA["signed"]:
        assert M.verify_decision(d, keys)
        assert not M.verify_decision({**d, "outcome": "allow" if d["outcome"] != "allow" else "block"}, keys)
        assert not M.verify_decision(d, [DATA["other_public_key"]])
