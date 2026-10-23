"""End-to-end tests of ``gleipnir mandate``: the README quickstart, run through main()."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gleipnir.cli import main

IBAN = "AT611904300234573201"
PAYEE = f"Brenner Stahl AG={IBAN}"
DEBTOR = "AT48 3200 0000 1234 5864"
ISSUE = ["mandate", "issue", "--from-account", DEBTOR]


@pytest.fixture()
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    for name in ("berger", "agent", "bank"):
        assert main(["mandate", "keygen", "-o", f"{name}.pem"]) == 0
    assert main([*ISSUE, "--id", "m_ap", "--company", "Nordhafen Logistik GmbH", "--country", "AT",
                 "--signer-id", "kberger@nordhafen.at", "--signer-key", "berger.pem",
                 "--agent-id", "ap-agent", "--agent-key", "agent.pem", "--currency", "EUR",
                 "--max-per-payment", "25000.00", "--max-per-period", "40000.00/P1M",
                 "--payee", PAYEE, "-o", "mandate.json"]) == 0
    assert main(["mandate", "sign", "mandate.json", "--key", "berger.pem"]) == 0
    assert main(["mandate", "kyb", "mandate.json", "-o", "kyb.json"]) == 0
    return tmp_path


def pay(pid: str, amount: str, payee: str = PAYEE) -> str:
    assert main(["mandate", "pay", "mandate.json", "--id", pid, "--amount", amount, "--payee", payee,
                 "--agent-key", "agent.pem", "-o", f"{pid}.json"]) == 0
    return f"{pid}.json"


def check(payment: str, *extra: str) -> tuple[int, dict]:
    out = payment.replace(".json", ".decision.json")
    code = main(["mandate", "check", "mandate.json", payment, "--authority", "kyb.json", "--bank-key", "bank.pem",
                 "-o", out, *extra])
    return code, json.loads(Path(out).read_text())


def test_allow_block_escalate(setup: Path) -> None:
    assert check(pay("p_1", "18400.00"))[0] == 0
    code, d = check(pay("p_2", "18400.00", "Brenner Stahl AG=LT121000011101001000"))
    assert (code, d["reasons"]) == (1, ["payee_not_on_mandate"])
    code, d = check(pay("p_3", "26000.00"))
    assert (code, d["outcome"]) == (3, "escalate")


def test_state_persists_between_runs(setup: Path) -> None:
    _, first = check(pay("p_1", "18400.00"))
    _, again = check("p_1.json")
    assert again == first  # idempotent retry across processes
    assert check(pay("p_2", "18400.00"))[0] == 0
    code, d = check(pay("p_3", "18400.00"))  # 55 200 > 40 000 period limit
    assert (code, d["reasons"]) == (3, ["over_period_limit"])
    state = json.loads((setup / ".gleipnir" / "mandate-state" / "state.json").read_text())
    mh = json.loads(Path("p_1.json").read_text())["mandate"]["hash"]
    assert state["totals"] == {f"mandate:{mh}|{d['checked_at'][:7]}": "36800.00"}


def test_verify(setup: Path, capsys: pytest.CaptureFixture[str]) -> None:
    check(pay("p_1", "100.00"))
    assert main(["mandate", "verify", "p_1.decision.json", "--bank-pub", "bank.pem"]) == 0
    assert main(["mandate", "verify", "p_1.decision.json", "--bank-pub", "agent.pem"]) == 1
    d = json.loads(Path("p_1.decision.json").read_text())
    d["outcome"] = "escalate"
    Path("edited.json").write_text(json.dumps(d))
    assert main(["mandate", "verify", "edited.json", "--bank-pub", "bank.pem"]) == 1
    assert capsys.readouterr().out.splitlines()[-1] == "INVALID"


def test_revoke(setup: Path) -> None:
    assert main(["mandate", "revoke", "mandate.json", "--key", "berger.pem", "--id", "r_1", "-o", "rev.json"]) == 0
    code, d = check(pay("p_1", "100.00"), "--revocation", "rev.json")
    assert (code, d["reasons"]) == (1, ["mandate_revoked"])


def test_unknown_signer_escalates(setup: Path) -> None:
    Path("kyb.json").write_text(json.dumps({"signers": []}))
    code, d = check(pay("p_1", "100.00"))
    assert (code, d["reasons"]) == (3, ["signer_unknown"])


def test_usage_errors(setup: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["mandate", "sign", "mandate.json", "--key", "agent.pem"]) == 2
    assert main(["mandate", "keygen", "-o", "bank.pem"]) == 2
    assert main(["mandate", "pay", "mandate.json", "--id", "p", "--amount", "1.5", "--payee", PAYEE]) == 2
    assert main(["mandate", "pay", "mandate.json", "--id", "p", "--amount", "1.00", "--payee", "no-iban"]) == 2
    for bad in ("X=AT62190430023457320", "X=telex:1", "X=us_aba:1"):
        assert main(["mandate", "pay", "mandate.json", "--id", "p", "--amount", "1.00", "--payee", bad]) == 2
    Path("dupe.json").write_text('{"id": "a", "id": "b"}')
    assert main(["mandate", "sign", "dupe.json", "--key", "berger.pem"]) == 2
    Path("nan.json").write_text('{"x": NaN}')
    assert main(["mandate", "sign", "nan.json", "--key", "berger.pem"]) == 2
    err = capsys.readouterr().err
    assert "not the signer key" in err and "duplicate JSON key" in err and "NaN is not allowed" in err


def test_joint_signing_via_cli(setup: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["mandate", "keygen", "-o", "hofer.pem"]) == 0
    hofer_pub = capsys.readouterr().out.strip()
    assert main([*ISSUE, "--id", "m_joint", "--company", "Nordhafen Logistik GmbH", "--country", "AT",
                 "--signer-id", "kberger@nordhafen.at", "--signer-key", "berger.pem",
                 "--cosigner", f"mhofer@nordhafen.at={hofer_pub}", "--agent-id", "ap-agent", "--agent-key", "agent.pem",
                 "--currency", "EUR", "--max-per-payment", "25000.00", "--payee", PAYEE, "-o", "joint.json"]) == 0
    assert main(["mandate", "sign", "joint.json", "--key", "berger.pem"]) == 0
    assert "1 of 2 needed" in capsys.readouterr().err
    assert main(["mandate", "kyb", "joint.json", "-o", "kyb.json"]) == 0
    assert main(["mandate", "pay", "joint.json", "--id", "p_j1", "--amount", "100.00", "--payee", PAYEE,
                 "--agent-key", "agent.pem", "-o", "p_j1.json"]) == 0
    code = main(["mandate", "check", "joint.json", "p_j1.json", "--authority", "kyb.json", "--bank-key", "bank.pem",
                 "-o", "d1.json"])
    assert (code, json.loads(Path("d1.json").read_text())["reasons"]) == (1, ["signature_threshold_not_met"])
    assert main(["mandate", "sign", "joint.json", "--key", "hofer.pem"]) == 0
    assert main(["mandate", "sign", "joint.json", "--key", "agent.pem"]) == 2
    assert main(["mandate", "pay", "joint.json", "--id", "p_j2", "--amount", "100.00", "--payee", PAYEE,
                 "--agent-key", "agent.pem", "-o", "p_j2.json"]) == 0
    assert main(["mandate", "check", "joint.json", "p_j2.json", "--authority", "kyb.json", "--bank-key", "bank.pem",
                 "-o", "d2.json"]) == 0
    assert "signatures:2/2" in json.loads(Path("d2.json").read_text())["checks"]


def test_delegation_via_cli(setup: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for name in ("ceo", "cfo"):
        assert main(["mandate", "keygen", "-o", f"{name}.pem"]) == 0
    assert main(["mandate", "delegate", "--id", "g_ceo_cfo", "--company", "Nordhafen Logistik GmbH",
                 "--from-id", "ceo@nordhafen.at", "--key", "ceo.pem", "--to", "cfo@nordhafen.at=cfo.pem",
                 "--to-role", "CFO", "--currency", "EUR", "--max-per-payment", "50000.00", "-o", "g1.json"]) == 0
    assert main([*ISSUE, "--id", "m_cfo", "--company", "Nordhafen Logistik GmbH", "--country", "AT",
                 "--signer-id", "cfo@nordhafen.at", "--signer-key", "cfo.pem", "--delegation", "g1.json",
                 "--agent-id", "ap-agent", "--agent-key", "agent.pem", "--currency", "EUR",
                 "--max-per-payment", "25000.00", "--payee", PAYEE, "-o", "cfo.json"]) == 0
    assert main(["mandate", "sign", "cfo.json", "--key", "cfo.pem"]) == 0
    assert main(["mandate", "kyb", "cfo.json", "-o", "kyb.json"]) == 0
    kyb = json.loads(Path("kyb.json").read_text())["signers"]
    assert [(r["signer"], r["may_sign"]) for r in kyb] == [("ceo@nordhafen.at", True), ("cfo@nordhafen.at", False)]
    assert main(["mandate", "pay", "cfo.json", "--id", "p_c1", "--amount", "100.00", "--payee", PAYEE,
                 "--agent-key", "agent.pem", "-o", "p_c1.json"]) == 0
    code = main(["mandate", "check", "cfo.json", "p_c1.json", "--authority", "kyb.json", "--bank-key", "bank.pem",
                 "-o", "dc1.json"])
    assert code == 0 and "delegation:1" in json.loads(Path("dc1.json").read_text())["checks"]
    assert main(["mandate", "revoke", "g1.json", "--key", "ceo.pem", "--id", "r_g1", "-o", "rev_g1.json"]) == 0
    assert json.loads(Path("rev_g1.json").read_text())["signer"]["id"] == "ceo@nordhafen.at"
    assert main(["mandate", "pay", "cfo.json", "--id", "p_c2", "--amount", "100.00", "--payee", PAYEE,
                 "--agent-key", "agent.pem", "-o", "p_c2.json"]) == 0
    code = main(["mandate", "check", "cfo.json", "p_c2.json", "--authority", "kyb.json", "--bank-key", "bank.pem",
                 "--revocation", "rev_g1.json", "-o", "dc2.json"])
    assert (code, json.loads(Path("dc2.json").read_text())["reasons"]) == (1, ["delegation_revoked"])
    # A wider mandate than the delegation is refused by the bank, not by the CLI.
    assert main([*ISSUE, "--id", "m_wide", "--company", "Nordhafen Logistik GmbH", "--country", "AT",
                 "--signer-id", "cfo@nordhafen.at", "--signer-key", "cfo.pem", "--delegation", "g1.json",
                 "--agent-id", "ap-agent", "--currency", "EUR", "--max-per-payment", "90000.00", "--payee", PAYEE,
                 "-o", "wide.json"]) == 0


def test_cli_multisig_usage_errors(setup: Path) -> None:
    assert main([*ISSUE, "--id", "m", "--company", "X", "--country", "AT", "--signer-id", "a",
                 "--signer-key", "berger.pem", "--threshold", "2", "--agent-id", "x", "--currency", "EUR",
                 "--max-per-payment", "1.00", "--payee", PAYEE]) == 2
    assert main([*ISSUE, "--id", "m", "--company", "X", "--country", "AT", "--signer-id", "a",
                 "--signer-key", "berger.pem", "--cosigner", "nokey", "--agent-id", "x", "--currency", "EUR",
                 "--max-per-payment", "1.00", "--payee", PAYEE]) == 2
    assert main(["mandate", "delegate", "--id", "g", "--company", "X", "--from-id", "a", "--key", "berger.pem",
                 "--to", "b=agent.pem", "--currency", "EUR", "--max-per-payment", "1"]) == 2
    assert main(["mandate", "delegate", "--id", "g", "--company", "X", "--from-id", "a", "--key", "berger.pem",
                 "--to", "b=agent.pem", "--currency", "EUR", "--max-per-payment", "1.00",
                 "--max-per-period", "5.00"]) == 2


def test_override_and_resolve_via_cli(setup: Path) -> None:
    code, d = check(pay("p_big", "26000.00"))
    assert (code, d["reasons"]) == (3, ["over_payment_limit"])
    assert main(["mandate", "override", "p_big.decision.json", "--key", "berger.pem", "--signer-id",
                 "kberger@nordhafen.at", "--reason", "Annual contract", "-o", "o.json"]) == 0
    code = main(["mandate", "resolve", "mandate.json", "p_big.json", "p_big.decision.json", "o.json",
                 "--authority", "kyb.json", "--bank-key", "bank.pem", "-o", "final.json"])
    final = json.loads(Path("final.json").read_text())
    assert code == 0 and "override:company:1/1" in final["checks"]
    assert check("p_big.json")[1] == final  # the agent's retry gets the final answer
    # An override signed with a key the bank does not know for that person does not count.
    code, d2 = check(pay("p_big2", "26000.00"))
    assert main(["mandate", "override", "p_big2.decision.json", "--key", "agent.pem", "--signer-id",
                 "kberger@nordhafen.at", "-o", "o2.json"]) == 0
    assert main(["mandate", "resolve", "mandate.json", "p_big2.json", "p_big2.decision.json", "o2.json",
                 "--authority", "kyb.json", "--bank-key", "bank.pem", "-o", "f2.json"]) == 3
    assert json.loads(Path("f2.json").read_text())["reasons"] == ["override_not_authorized"]
    # A bank officer may resolve it.
    assert main(["mandate", "keygen", "-o", "ops.pem"]) == 0
    assert main(["mandate", "override", "p_big2.decision.json", "--key", "ops.pem", "--signer-id", "ops@bank",
                 "--outcome", "block", "-o", "o3.json"]) == 0
    assert main(["mandate", "resolve", "mandate.json", "p_big2.json", "p_big2.decision.json", "o3.json",
                 "--authority", "kyb.json", "--bank-key", "bank.pem", "--officer", "ops.pem", "-o", "f3.json"]) == 1
    assert json.loads(Path("f3.json").read_text())["reasons"] == ["blocked_by_override"]
    assert main(["mandate", "override", "p_1.decision.json", "--key", "berger.pem", "--signer-id", "x"]) == 2


def test_override_cosign_via_cli(setup: Path) -> None:
    check(pay("p_big", "26000.00"))
    assert main(["mandate", "keygen", "-o", "hofer.pem"]) == 0
    assert main(["mandate", "override", "p_big.decision.json", "--key", "berger.pem", "--signer-id", "a",
                 "-o", "o.json"]) == 0
    assert main(["mandate", "override", "--add", "o.json", "--key", "hofer.pem", "--signer-id", "b",
                 "-o", "o.json"]) == 0
    assert [s["signer"]["id"] for s in json.loads(Path("o.json").read_text())["sigs"]] == ["a", "b"]


def test_status_answer_via_cli(setup: Path) -> None:
    assert main(["mandate", "status", "mandate.json", "--key", "berger.pem", "--signer-id", "kberger@nordhafen.at",
                 "--status", "revoked", "-o", "status.json"]) == 0
    s = json.loads(Path("status.json").read_text())
    assert s["status"] == "revoked" and s["mandate"]["id"] == "m_ap" and s["v"] == "gleipnir/status/0.3"


def test_accounts_worldwide_via_cli(setup: Path) -> None:
    from gleipnir.mandate_cli import parse_account

    assert parse_account("at61 1904 3002 3457 3201") == {"scheme": "iban", "iban": IBAN}
    assert parse_account("us_aba:021000021/1234 5678") == {"scheme": "us_aba", "routing": "021000021",
                                                           "account": "12345678"}
    assert parse_account("uk_sort_code:60-16-13/31926819")["sort_code"] == "601613"
    assert parse_account("swift:mhcbjpjt/1234567") == {"scheme": "swift", "bic": "MHCBJPJT", "account": "1234567"}
    assert main(["mandate", "issue", "--from-account", "us_aba:011000015/000123456789", "--id", "m_us",
                 "--company", "Acme Inc", "--country", "US", "--signer-id", "cfo@acme", "--signer-key", "berger.pem",
                 "--agent-id", "ap", "--agent-key", "agent.pem", "--rail", "ach", "--currency", "USD",
                 "--max-per-payment", "500.00", "--payee", "Supplier=us_aba:021000021/123456789",
                 "-o", "us.json"]) == 0
    assert main(["mandate", "sign", "us.json", "--key", "berger.pem"]) == 0
    assert main(["mandate", "kyb", "us.json", "-o", "kyb_us.json"]) == 0
    assert json.loads(Path("kyb_us.json").read_text())["accounts"][0]["account"]["scheme"] == "us_aba"
    assert main(["mandate", "pay", "us.json", "--id", "p_us", "--amount", "10.00", "--payee",
                 "Supplier=us_aba:021000021/123456789", "--agent-key", "agent.pem", "-o", "p_us.json"]) == 0
    assert main(["mandate", "check", "us.json", "p_us.json", "--authority", "kyb_us.json", "--bank-key", "bank.pem",
                 "-o", "d_us.json"]) == 0


def test_status_fetcher_refuses_internal_hosts() -> None:
    from gleipnir.mandate_cli import CliError, make_status_fetcher

    fetch = make_status_fetcher()
    for url in ("http://example.com/s", "https://127.0.0.1/s", "https://localhost/s", "https://10.0.0.1/s",
                "https://169.254.169.254/latest/meta-data", "https://[::1]/s"):
        with pytest.raises(CliError):
            fetch(url)
    with pytest.raises(CliError, match="not allowed"):
        make_status_fetcher(["status.bank.example"])("https://evil.example/s")


def test_status_fetcher_reads_a_public_https_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import socket
    import urllib.request

    from gleipnir import mandate_cli
    from gleipnir.mandate_cli import CliError

    seen = {}

    class Opener:
        def open(self, req, timeout):
            seen["url"], seen["timeout"] = req.full_url, timeout
            return io.BytesIO(seen.get("body", b'{"status": "active"}'))

    monkeypatch.setattr(urllib.request, "build_opener", lambda *h: Opener())
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("93.184.216.34", 443))])
    fetch = mandate_cli.make_status_fetcher()
    assert fetch("https://status.example/m_1") == {"status": "active"} and seen["timeout"] == 5
    seen["body"] = b'{"a": 1, "a": 2}'
    with pytest.raises(CliError, match="duplicate"):
        fetch("https://status.example/m_1")
    seen["body"] = b"x" * (mandate_cli.MAX_STATUS + 1)
    with pytest.raises(CliError, match="too large"):
        fetch("https://status.example/m_1")
    seen["body"] = b'{"ok": true}'
    assert mandate_cli.make_status_fetcher(["status.example"])("https://status.example/s") == {"ok": True}
    assert mandate_cli._NoRedirect().redirect_request() is None
