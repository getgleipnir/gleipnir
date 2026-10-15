import json
import zipfile

from chainbuilder import Builder

from gleipnir_verify import cli
from gleipnir_verify.reconcile import external_ids, reconcile


def bundle_with_refunds(tmp_path, refund_ids):
    b = Builder()
    for i, rid in enumerate(refund_ids):
        b.action(i, response={"status": "ok", "body": {"refund_id": rid, "nested": {"order_id": f"O{i}"}}})
    seg = b.segment()
    b.anchor(seg)
    p = tmp_path / "b.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"format": 1, "chain": b.chain, "from_seq": 1,
                                                  "to_seq": b.records[-1]["seq"]}))
        zf.writestr("records.jsonl", "".join(json.dumps(r) + "\n" for r in b.records))
        zf.writestr("anchors/local-anchor-log.jsonl", "".join(json.dumps(e) + "\n" for e in b.anchor_log))
    return p


def test_external_ids():
    body = {"id": 5, "refund_id": "R1", "x": {"customerId": "C9", "flag": True}, "items": [{"sku_id": "S"}]}
    assert external_ids(body) == {"5", "R1", "C9", "S"}
    assert external_ids(body, "refund_id") == {"R1"}


def test_reconcile_finds_both_kinds_of_difference(tmp_path, capsys):
    p = bundle_with_refunds(tmp_path, ["R1", "R2", "R3"])
    csv_path = tmp_path / "system.csv"
    csv_path.write_text("refund_id,amount\nR1,10\nR2,20\nR9,99\n")
    res = reconcile(p, csv_path, column="refund_id")
    assert res.matched == {"R1", "R2"} and res.only_in_system == {"R9"} and res.only_in_records == {"R3"}
    assert cli.main(["reconcile", str(p), str(csv_path), "--column", "refund_id"]) == 1
    out = capsys.readouterr().out
    assert "R9" in out and "DIFFERENCES FOUND" in out
    csv_path.write_text("refund_id\nR1\nR2\nR3\n")
    assert cli.main(["reconcile", str(p), str(csv_path), "--column", "refund_id"]) == 0
    assert "RECONCILED" in capsys.readouterr().out


def test_reconcile_tolerates_short_rows_and_odd_responses(tmp_path):
    p = bundle_with_refunds(tmp_path, ["R1"])
    csv_path = tmp_path / "s.csv"
    csv_path.write_text("amount,refund_id\n10,R1\n5\n")
    res = reconcile(p, csv_path, column="refund_id")
    assert res.ok


def test_list_calls_do_not_mask_missing_records(tmp_path):
    b = Builder()
    b.action(0, response={"status": "ok", "body": {"refund_id": "R1"}}, tool={"name": "issue_refund", "system": "p"})
    b.action(1, response={"status": "ok", "body": {"items": [{"refund_id": "R1"}, {"refund_id": "R2"}]}},
             tool={"name": "list_refunds", "system": "p"})
    b.anchor(b.segment())
    p = tmp_path / "b.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"format": 1, "chain": b.chain, "from_seq": 1,
                                                  "to_seq": b.records[-1]["seq"]}))
        zf.writestr("records.jsonl", "".join(json.dumps(r) + "\n" for r in b.records))
        zf.writestr("anchors/local-anchor-log.jsonl", "".join(json.dumps(e) + "\n" for e in b.anchor_log))
    csv_path = tmp_path / "s.csv"
    csv_path.write_text("refund_id\nR1\nR2\n")
    res = reconcile(p, csv_path, column="refund_id")
    assert res.only_in_system == {"R2"}
    res2 = reconcile(p, csv_path, column="refund_id", tools=["issue_refund"])
    assert res2.only_in_system == {"R2"} and res2.matched == {"R1"}


def test_nul_in_csv_is_a_usage_error(tmp_path, capsys):
    import pytest
    p = bundle_with_refunds(tmp_path, ["R1"])
    csv_path = tmp_path / "n.csv"
    csv_path.write_bytes(b"refund_id\nR\x001\n")
    # Older Pythons' csv module rejects NUL; either way the result is a clean exit, never a traceback.
    try:
        code = cli.main(["reconcile", str(p), str(csv_path), "--column", "refund_id"])
    except SystemExit as exc:
        code = exc.code
    assert code in (1, 2)
    del pytest
    capsys.readouterr()
