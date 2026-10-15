"""Signed approvals: key and WebAuthn signatures, the approver registry and the CLI flags."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from chainbuilder import Builder
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gleipnir_verify import cli, verify_records
from gleipnir_verify.approvals import (
    approval_challenge,
    approval_message,
    check_signature,
    load_approvers,
)
from gleipnir_verify.crypto import b64u, encode_p256_public_key, encode_public_key, encode_signature, unb64u
from gleipnir_verify.verifier import action_digest

VECTORS = json.loads((Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "approvals.json").read_text())
ARGS = {"order": "o1", "amount": 1}
DIGEST = action_digest("refund", "pay", ARGS)


def ed_key():
    sk = Ed25519PrivateKey.generate()
    pub = encode_public_key(sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return sk, pub


def key_signature(sk, pub, approver_id="ops:anna", digest=DIGEST):
    return {"type": "key", "approver_id": approver_id, "public_key": pub,
            "sig": encode_signature(sk.sign(approval_message(digest)))}


def build(signature=None, reviewer="ops:anna", digest=DIGEST, action_args=None):
    b = Builder()
    body = {"action_digest": digest, "tool": "refund", "system": "pay", "reviewer": reviewer,
            "decision": "approved", "before_execution": True}
    if signature is not None:
        body["signature"] = signature
    rev = b._add({"kind": "review", "review": body})
    b.action(1, approval=rev["id"], args=action_args or ARGS)
    b.anchor(b.segment())
    return b


def findings(report):
    return [(f.level, f.code) for f in report.findings]


def test_message_and_challenge():
    assert approval_message(DIGEST) == b"gleipnir/approval/v1\n" + DIGEST.encode()
    assert approval_challenge(DIGEST) == bytes.fromhex(DIGEST[7:])
    for bad in ("sha256:AB" + "0" * 62, "sha256:00", "md5:" + "0" * 64, 5):
        with pytest.raises(ValueError):
            approval_challenge(bad)


def test_unsigned_is_a_warning_and_an_error_with_a_registry_or_required():
    b = build()
    assert ("warn", "approval_unsigned") in findings(verify_records(b.records))
    assert verify_records(b.records).valid()
    sk, pub = ed_key()
    reg = [{"id": "ops:anna", "name": "Anna", "public_key": pub}]
    assert ("error", "approval_unsigned") in findings(verify_records(b.records, approvers=reg))
    assert ("error", "approval_unsigned") in findings(verify_records(b.records, require_signed_approvals=True))


def test_key_signature_with_registry():
    sk, pub = ed_key()
    b = build(key_signature(sk, pub))
    reg = [{"id": "ops:anna", "name": "Anna", "public_key": pub}]
    rep = verify_records(b.records, approvers=reg, require_signed_approvals=True)
    assert rep.valid(), findings(rep)
    assert ("info", "approval_verified") in findings(rep)
    verified = next(f for f in rep.findings if f.code == "approval_verified")
    assert verified.message == "approved by Anna (ops:anna), signature verified" and verified.seq == 2
    # without a registry, the signature checks out but nobody vouched for the key
    rep = verify_records(b.records)
    assert rep.valid() and ("warn", "approval_unknown_approver") in findings(rep)
    assert not verify_records(b.records, require_signed_approvals=True).valid()


def test_p256_key_signature():
    sk = ec.generate_private_key(ec.SECP256R1())
    pub = encode_p256_public_key(sk.public_key().public_bytes(serialization.Encoding.DER,
                                                              serialization.PublicFormat.SubjectPublicKeyInfo))
    sig = {"type": "key", "approver_id": "ops:anna", "public_key": pub,
           "sig": "ecdsa-p256:" + b64u(sk.sign(approval_message(DIGEST), ec.ECDSA(hashes.SHA256())))}
    rep = verify_records(build(sig).records, approvers=[{"id": "ops:anna", "name": "A", "public_key": pub}])
    assert ("info", "approval_verified") in findings(rep)


def test_signature_bound_to_the_action():
    sk, pub = ed_key()
    reg = [{"id": "ops:anna", "name": "Anna", "public_key": pub}]
    # the vendor rewrites the approved digest to match a different action: the signature no longer fits
    other = action_digest("refund", "pay", {"order": "o1", "amount": 5000})
    b = build(key_signature(sk, pub), digest=other, action_args={"order": "o1", "amount": 5000})
    assert ("error", "approval_bad_signature") in findings(verify_records(b.records, approvers=reg))
    # a signature from another key, under the registered approver's id
    sk2, pub2 = ed_key()
    b = build(key_signature(sk2, pub2))
    assert ("error", "approval_unknown_approver") in findings(verify_records(b.records, approvers=reg))
    # the reviewer field must name the signer
    b = build(key_signature(sk, pub), reviewer="ops:boss")
    assert ("error", "approval_bad_signature") in findings(verify_records(b.records, approvers=reg))


@pytest.mark.parametrize("sig", [5, {"type": "pgp", "approver_id": "x"}, {"type": "key"},
                                 {"type": "key", "approver_id": "ops:anna", "public_key": "rsa:x", "sig": ""},
                                 {"type": "webauthn", "approver_id": "ops:anna", "public_key": "ed25519:" + "A" * 43}])
def test_malformed_signatures(sig):
    reviewer = sig.get("approver_id", "ops:anna") if isinstance(sig, dict) else "ops:anna"
    rep = verify_records(build(sig, reviewer=reviewer).records)
    codes = {c for lv, c in findings(rep) if lv == "error"}
    assert codes & {"approval_bad_signature", "approval_webauthn_invalid"}, findings(rep)


@pytest.mark.parametrize("bad, msg", [
    ({}, "must be a JSON list"),
    ([5], "must be a JSON object"),
    ([{"name": "x", "public_key": "ed25519:" + "A" * 43}], "non-empty string id"),
    ([{"id": "a", "public_key": "ed25519:" + "A" * 43}], "string name"),
    ([{"id": "a", "name": "x"}], "exactly one of"),
    ([{"id": "a", "name": "x", "public_key": "nope"}], "cannot read public_key"),
    ([{"id": "a", "name": "x", "webauthn": {"public_key": "ed25519:" + "A" * 43, "rp_id": "x"}}], "P-256"),
    ([{"id": "a", "name": "x", "roles": "admin", "public_key": "ed25519:" + "A" * 43}], "roles"),
])
def test_registry_validation(bad, msg):
    with pytest.raises(ValueError, match=msg):
        load_approvers(bad)
    with pytest.raises(ValueError):
        verify_records(Builder().records, approvers=bad)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["description"])
def test_vectors(case):
    reg = load_approvers(VECTORS["registry"])
    origins = VECTORS["allowed_origins"]
    for mode, r, req in (("no_registry", None, False), ("registry", reg, False), ("require", reg, True)):
        got = [[lv, code] for lv, code, _ in check_signature(case["review"], r, origins, req)]
        assert got == case["expected"][mode], mode


def test_vector_inputs_reproduce():
    v = VECTORS
    assert action_digest(v["tool"], v["system"], v["args"]) == v["action_digest"]
    assert approval_message(v["action_digest"]).decode() == v["approval_message"]
    assert b64u(approval_challenge(v["action_digest"])) == v["webauthn_challenge"]
    li = v["approver_keys"]["ops:li"]
    good = v["cases"][2]["review"]["signature"]
    assert unb64u(good["authenticator_data"]).hex() == li["authenticator_data_hex"]
    assert unb64u(good["client_data_json"]).decode() == li["client_data_json"]
    assert unb64u(good["authenticator_data"])[:32] == hashlib.sha256(li["rp_id"].encode()).digest()
    for mode, exp in v["chain"]["expected"].items():
        kw = {"no_registry": {}, "registry": {"approvers": v["registry"]},
              "registry_other_origin": {"approvers": v["registry"], "webauthn_origins": ["https://other.example"]},
              "require": {"approvers": v["registry"], "require_signed_approvals": True}}[mode]
        rep = verify_records(v["chain"]["records"], **kw)
        assert {"valid": rep.valid(), "findings": findings_list(rep)} == exp, mode


def findings_list(rep):
    return [[f.level, f.code] for f in rep.findings]


def test_cli_flags(tmp_path, capsys):
    sk, pub = ed_key()
    b = build(key_signature(sk, pub))
    bundle = tmp_path / "b.zip"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"format": 1, "chain": b.chain, "from_seq": 1,
                                                 "to_seq": b.records[-1]["seq"]}))
        zf.writestr("records.jsonl", "".join(json.dumps(r) + "\n" for r in b.records))
        zf.writestr("anchors/local-anchor-log.jsonl", "".join(json.dumps(e) + "\n" for e in b.anchor_log))
    reg = tmp_path / "approvers.json"
    reg.write_text(json.dumps([{"id": "ops:anna", "name": "Anna", "public_key": pub}]))
    assert cli.main([str(bundle), "--approvers", str(reg), "--require-signed-approvals"]) == 0
    assert "[info] seq 2 approval_verified: approved by Anna (ops:anna)" in capsys.readouterr().out
    other = tmp_path / "other.json"
    other.write_text(json.dumps([{"id": "ops:li", "name": "Li", "public_key": ed_key()[1]}]))
    assert cli.main([str(bundle), "--approvers", str(other)]) == 1
    assert "approval_unknown_approver" in capsys.readouterr().out
    for argv in (["--require-signed-approvals"], ["--approvers", str(tmp_path / "missing.json")],
                 ["--approvers", str(bundle)]):
        with pytest.raises(SystemExit) as exc:
            cli.main([str(bundle), *argv])
        assert exc.value.code == 2
