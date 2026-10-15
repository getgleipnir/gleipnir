"""`gleipnir demo` runs offline, produces the evidence report, and its tamper test fails verification."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from gleipnir.cli import main
from gleipnir.demo import FakePayments, run, tamper


def test_demo_produces_valid_bundle_and_report(tmp_path: Path) -> None:
    lines: list[str] = []
    res = run(tmp_path / "demo", echo=lines.append)
    assert res["valid"] is True
    assert res["tampered_valid"] is False
    assert {"bad_signature", "broken_chain"} <= set(res["tampered_codes"])
    page = res["summary"].read_text()
    assert "VALID" in page and "Refunded 180.00 on order A-1002" in page and "amount_cents = 17950" in page
    assert "4111111111111111" not in page  # card number is redacted everywhere
    with zipfile.ZipFile(res["bundle"]) as z:
        assert "4111111111111111" not in z.read("records.jsonl").decode()
    text = "\n".join(lines)
    assert text.count("outcome mismatch") == 2 and "INVALID" in text


def test_demo_refuses_to_overwrite_a_foreign_folder(tmp_path: Path) -> None:
    (tmp_path / "mine").mkdir()
    (tmp_path / "mine" / "notes.txt").write_text("keep me")
    with pytest.raises(FileExistsError):
        run(tmp_path / "mine", echo=lambda *_: None)
    assert (tmp_path / "mine" / "notes.txt").read_text() == "keep me"


def test_demo_rerun_replaces_its_own_folder(tmp_path: Path) -> None:
    first = run(tmp_path / "d", echo=lambda *_: None)
    second = run(tmp_path / "d", echo=lambda *_: None)
    assert first["key"] != second["key"]  # fresh key and chain each run
    assert second["valid"]


def test_cli_demo_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "-o", str(tmp_path / "cli-demo")]) == 0
    assert "Verify as the buyer would" in capsys.readouterr().out
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "f").write_text("")
    assert main(["demo", "-o", str(tmp_path / "x")]) == 2


def test_tamper_without_mismatch_changes_nothing(tmp_path: Path) -> None:
    res = run(tmp_path / "d", echo=lambda *_: None)
    # a bundle whose mismatches were already flipped has none left to flip
    once, twice = tmp_path / "once.zip", tmp_path / "twice.zip"
    assert tamper(res["bundle"], once) is not None
    assert tamper(once, twice) is not None  # second mismatch
    assert tamper(twice, tmp_path / "thrice.zip") is None


def test_fake_payments_bug_only_on_large_refunds() -> None:
    p = FakePayments()
    small = p.refund("A", 10_000, "x")
    large = p.refund("B", 10_001, "x")
    assert p.get_refund(small["refund_id"])["amount_cents"] == 10_000
    assert p.get_refund(large["refund_id"])["amount_cents"] == 9_951
    with pytest.raises(ValueError):
        p.refund("C", 0, "x")
