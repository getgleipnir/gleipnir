"""Signed approvals in the SDK: ApproverKey, rec.approve(signature=...) and `gleipnir approve`."""

from __future__ import annotations

import json

import pytest

from gleipnir import ApproverKey, approval_digest, approval_message
from gleipnir.cli import main as gleipnir_main
from gleipnir_verify import verify_records


def test_signed_approval_end_to_end(rec):
    @rec.tool(system="payments", redact=["card"])
    def refund(order, amount, card):
        return {"ok": True}

    anna = ApproverKey.generate("ops:anna")
    args = {"order": "A1", "amount": 500, "card": "4111"}
    digest = rec.approval_digest(refund, args)
    # the hmac-redacted card is in the digest, so the approver never needs to see the card number
    assert digest != approval_digest("refund", args, "payments")
    approval = rec.approve(refund, args, signature=anna.sign(digest), rule="amount>100")
    with rec.context(approval=approval):
        refund("A1", 500, "4111")
    records = rec.chain.store.read_all()
    review = next(r for r in records if r["kind"] == "review")
    assert review["review"]["reviewer"] == "ops:anna"
    assert review["review"]["signature"]["type"] == "key"
    registry = [anna.registry_entry("Anna Berger", ["refunds"])]
    report = verify_records(records, approvers=registry, require_signed_approvals=True)
    assert report.valid(), [f.as_dict() for f in report.findings]
    assert "approval_verified" in {f.code for f in report.findings}


def test_p256_approver_and_json_signature(rec):
    key = ApproverKey.generate("ops:jonas", "ecdsa-p256")
    assert key.public_key.startswith("ecdsa-p256:")
    digest = approval_digest("refund", {"order": "A1"}, "payments")
    assert approval_message("refund", {"order": "A1"}, "payments") == b"gleipnir/approval/v1\n" + digest.encode()
    rid = rec.approve("refund", {"order": "A1"}, system="payments", signature=json.dumps(key.sign(digest)))
    assert rid


def test_approve_rejects_bad_or_mismatched_signatures(rec):
    anna = ApproverKey.generate("ops:anna")
    good = rec.approval_digest("refund", {"order": "A1"}, system="payments")
    other = rec.approval_digest("refund", {"order": "A2"}, system="payments")
    with pytest.raises(ValueError, match="approval_bad_signature"):
        rec.approve("refund", {"order": "A1"}, system="payments", signature=anna.sign(other))
    with pytest.raises(ValueError, match="differs"):
        rec.approve("refund", {"order": "A1"}, system="payments", approver="ops:boss", signature=anna.sign(good))
    with pytest.raises(ValueError):
        rec.approve("refund", {"order": "A1"}, system="payments", signature="not json")
    with pytest.raises(ValueError, match="approver="):
        rec.approve("refund", {"order": "A1"}, system="payments")
    with pytest.raises(ValueError):
        ApproverKey.generate("")
    with pytest.raises(ValueError):
        anna.sign("sha256:short")


def test_key_roundtrip(tmp_path):
    k = ApproverKey.generate("ops:anna", "ecdsa-p256")
    path = k.save(tmp_path / "anna.pem")
    assert (path.stat().st_mode & 0o777) == 0o600
    assert ApproverKey.load(path, "ops:anna").public_key == k.public_key
    with pytest.raises(FileExistsError):
        k.save(path)


def test_approve_cli(tmp_path, capsys):
    pem = tmp_path / "anna.pem"
    assert gleipnir_main(["approve", "keygen", "--id", "ops:anna", "--name", "Anna", "-o", str(pem)]) == 0
    entry = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert entry["id"] == "ops:anna" and entry["public_key"].startswith("ed25519:")
    assert gleipnir_main(["approve", "digest", "refund", "--system", "payments", "--args", '{"order": "A1"}']) == 0
    out = capsys.readouterr().out
    digest = approval_digest("refund", {"order": "A1"}, "payments")
    assert f"action digest:     {digest}" in out and f"#digest={digest}" in out
    assert gleipnir_main(["approve", "sign", digest, "--key", str(pem), "--id", "ops:anna"]) == 0
    sig = capsys.readouterr().out.strip()
    reg = tmp_path / "approvers.json"
    reg.write_text(json.dumps([entry]))
    assert gleipnir_main(["approve", "check", digest, "--signature", sig, "--approvers", str(reg)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == json.loads(sig) and "approval_verified" in captured.err
    other = approval_digest("refund", {"order": "A2"}, "payments")
    (tmp_path / "sig.json").write_text(sig)
    assert gleipnir_main(["approve", "check", other, "--signature", "@" + str(tmp_path / "sig.json")]) == 1
    assert "approval_bad_signature" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        gleipnir_main(["approve", "sign", "sha256:00", "--key", str(pem), "--id", "ops:anna"])
    with pytest.raises(SystemExit):
        gleipnir_main(["approve", "keygen", "--id", "ops:anna", "--name", "Anna", "-o", str(pem)])
