"""Regression tests for the independent review of spec 0.4 (24.10.2026). Each test is an attack that worked."""

from __future__ import annotations

from datetime import datetime, timezone

import mandate_vectors as V
import pytest

from gleipnir_verify import iso20022 as ISO
from gleipnir_verify import mandate as M

NOW = datetime(2026, 10, 23, 9, 30, tzinfo=timezone.utc)


def _base():
    m = V.mandate()
    p = V.pay(m, "INV-1", "100.00")
    d = V.run(V.case("x", m, [p]))[0]
    return m, p, d, ISO.pain001(m, p, d)


def test_f1_extra_transaction_to_attacker_is_flagged():
    m, p, d, good = _base()
    tx = good[good.index("<CdtTrfTxInf>"):good.index("</CdtTrfTxInf>") + 14]
    evil = tx.replace(">INV-1<", ">INV-EVIL<").replace(">100.00<", ">99999.00<")
    assert ISO.pain001_problems(good.replace(tx, tx + evil), m, p, d) == ["unexpected_content"]


def test_f2_cheque_and_intermediary_are_flagged():
    m, p, d, good = _base()
    assert ISO.pain001_problems(good.replace("<PmtMtd>TRF<", "<PmtMtd>CHK<"), m, p, d) == ["unexpected_content"]
    inter = good.replace("<CdtrAgt>", "<IntrmyAgt1><FinInstnId><BICFI>EVILXXXX</BICFI></FinInstnId></IntrmyAgt1>"
                                      "<CdtrAgt>")
    assert ISO.pain001_problems(inter, m, p, d) == ["unexpected_content"]


def test_f3_retired_issuer_key_cannot_make_current_list():
    home = V.key(11)
    ks = {"v": f"gleipnir/keys/{M.V}", "checker": "bank:HOME", "issued_at": "2026-10-23T00:00:00.000Z",
          "keys": [{"public_key": M.public_key_of(home), "until": "2025-01-01T00:00:00.000Z"}]}
    doc = M.revocation_list([], issuer="bank:HOME", sk=home, issued_at="2024-06-01T00:00:00.000Z",
                            next_update="2026-10-23T10:00:00.000Z")
    with pytest.raises(ValueError, match="not trusted"):
        M.revocations_from_list(doc, ks, NOW)


def test_f3_list_is_current_for_at_most_a_day():
    home = V.key(11)
    doc = M.revocation_list([], issuer="bank:HOME", sk=home, issued_at="2026-10-23T09:00:00.000Z",
                            next_update="2099-01-01T00:00:00.000Z")
    with pytest.raises(ValueError, match="24 hours"):
        M.revocations_from_list(doc, [M.public_key_of(home)], NOW)


def test_f4_lone_surrogate_is_malformed_not_a_crash():
    m, p, d, good = _base()
    assert ISO.pain001_problems(good.replace("</Nm></Cdtr>", "\ud800</Nm></Cdtr>"), m, p, d) == ["xml_malformed"]


def test_issuer_cannot_inject_revocation():
    m = V.mandate()
    home = V.key(11)
    rev = M.revoke(m, signer={"id": "bank:HOME", "public_key": M.public_key_of(home)}, sk=home, id="r_x",
                   revoked_at="2026-10-22T00:00:00.000Z")
    doc = M.revocation_list([rev], issuer="bank:HOME", sk=home, issued_at="2026-10-23T09:00:00.000Z",
                            next_update="2026-10-23T10:00:00.000Z")
    d = V.run(V.case("inj", m, [V.pay(m, "p_1")], feed={"doc": doc, "keys": [M.public_key_of(home)]}))[0]
    assert d["outcome"] == "allow" and "revocation_list_current" in d["checks"]
