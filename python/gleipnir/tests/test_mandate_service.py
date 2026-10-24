"""The reference bank checker (HTTP) and the agent MCP server, end to end."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from argparse import Namespace
from pathlib import Path

import pytest

from gleipnir.cli import main
from gleipnir.mandate_service import Bank, MandateTools, handle, make_mcp_http, make_server, serve_stdio
from gleipnir_verify import mandate as M

IBAN = "AT611904300234573201"
PAYEE = f"Brenner Stahl AG={IBAN}"
DEBTOR = "AT483200000012345864"
ISSUE = ["mandate", "issue", "--from-account", DEBTOR]


@pytest.fixture()
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    for name in ("signer", "agent", "bank"):
        assert main(["mandate", "keygen", "-o", f"{name}.pem"]) == 0
    assert main([*ISSUE, "--id", "m_ap", "--company", "Nordhafen Logistik GmbH", "--country", "AT",
                 "--signer-id", "kberger@nordhafen.at", "--signer-key", "signer.pem", "--agent-id", "ap-agent",
                 "--agent-key", "agent.pem", "--currency", "EUR", "--max-per-payment", "25000.00",
                 "--max-per-period", "40000.00/P1M", "--payee", PAYEE, "-o", "mandate.json"]) == 0
    assert main(["mandate", "sign", "mandate.json", "--key", "signer.pem"]) == 0
    assert main(["mandate", "kyb", "mandate.json", "-o", "kyb.json"]) == 0
    return tmp_path


@pytest.fixture()
def server(world: Path):
    bank = Bank(bank_id="bank:test", bank_key="bank.pem", authority="kyb.json", state=world / "state.json")
    srv = make_server(bank, port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", bank
    srv.shutdown()
    srv.server_close()


def post(url: str, body: bytes | dict, path: str = "/check") -> tuple[int, dict]:
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(url + path, data=data, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def revoke_via(url: str, mandate: dict) -> tuple[int, dict]:
    return post(url, {"revocation": json.loads(Path("rev.json").read_text()), "mandate": mandate}, "/revoke")


def tools(world: Path, **kw) -> MandateTools:
    args = Namespace(mandate="mandate.json", agent_key="agent.pem", drafts=str(world / "drafts"), bank_url=None,
                     bank_key=None, authority=None, state=str(world / "agent-state.json"), revocation=None,
                     home=str(world / ".gleipnir"))
    for k, v in kw.items():
        setattr(args, k, v)
    return MandateTools(args)


def call(t: MandateTools, name: str, args: dict, rid: int = 1) -> dict:
    resp = handle(t, {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": name, "arguments": args}})
    return resp["result"]


def test_http_check_keys_revoke(server, world):
    url, bank = server
    mandate = json.loads(Path("mandate.json").read_text())
    t = tools(world)
    p_ok = call(t, "attach_mandate", {"payment_id": "INV-1", "amount": "18400.00", "payee": PAYEE})["structuredContent"]
    code, d = post(url, {"mandate": mandate, "payment": p_ok["payment"]})
    assert code == 200 and d["outcome"] == "allow"
    with urllib.request.urlopen(url + "/keys") as r:
        keys = json.loads(r.read())
    assert keys == {"checker": "bank:test", "keys": [bank.public_key]}
    assert M.verify_decision(d, keys["keys"])
    code, again = post(url, {"mandate": mandate, "payment": p_ok["payment"]})
    assert again == d  # idempotent over HTTP too
    assert main(["mandate", "revoke", "mandate.json", "--key", "signer.pem", "--id", "r_1", "-o", "rev.json"]) == 0
    assert revoke_via(url, mandate) == (200, {"ok": True})
    p2 = call(t, "attach_mandate", {"payment_id": "INV-2", "amount": "1.00", "payee": PAYEE})["structuredContent"]
    assert post(url, {"mandate": mandate, "payment": p2["payment"]})[1]["reasons"] == ["mandate_revoked"]


@pytest.mark.parametrize("body, path, code", [
    (b'{"mandate": {}, "mandate": {}, "payment": {}}', "/check", 400),
    (b'{"mandate": NaN, "payment": {}}', "/check", 400),
    (b'{"payment": {}}', "/check", 400),
    (b"\xff\xfe", "/check", 400),
    (b"[" * 100000, "/check", 400),
    (b'{"v": "x"}', "/revoke", 400),
    (b"{}", "/nope", 404),
])
def test_http_rejects_bad_requests(server, body, path, code):
    url, _ = server
    assert post(url, body, path)[0] == code


def test_http_junk_mandate_still_signed_block(server):
    url, bank = server
    code, d = post(url, {"mandate": {"v": "x"}, "payment": {"v": "y"}})
    assert code == 200 and d["outcome"] == "block" and M.verify_decision(d, [bank.public_key])
    req = urllib.request.Request(url + "/check", data=b"", method="POST")
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(req, timeout=5)
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(url + "/other", timeout=5)


def test_mcp_demo_script_via_bank_url(server, world):
    """The 60-second demo: allow, 'we changed our bank details' blocked, too much escalated."""
    url, _ = server
    t = tools(world, bank_url=url)
    outcomes = []
    swapped = "Brenner Stahl AG=LT121000011101001000"
    for pid, amount, payee in [("INV-1", "18400.00", PAYEE), ("INV-2", "18400.00", swapped),
                               ("INV-3", "26000.00", PAYEE)]:
        p = call(t, "attach_mandate", {"payment_id": pid, "amount": amount, "payee": payee})["structuredContent"]
        r = call(t, "check_payment", p)["structuredContent"]
        outcomes.append((r["outcome"], r["reasons"]))
        assert r["advice"]
    assert outcomes == [("allow", []), ("block", ["payee_not_on_mandate"]), ("escalate", ["over_payment_limit"])]


def test_mcp_local_demo_checker(world):
    t = tools(world, bank_key="bank.pem", authority="kyb.json")
    p = call(t, "attach_mandate", {"payment_id": "INV-9", "amount": "100.00", "payee": PAYEE})["structuredContent"]
    assert call(t, "check_payment", p)["structuredContent"]["outcome"] == "allow"


def test_mcp_protocol(world):
    t = tools(world)
    init = handle(t, {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
    assert init["result"]["protocolVersion"] == "2025-03-26" and "tools" in init["result"]["capabilities"]
    odd = handle(t, {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "1999"}})
    assert odd["result"]["protocolVersion"] == "2025-06-18"
    assert handle(t, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    names = [x["name"] for x in handle(t, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]]
    assert names == ["mandate_scope", "request_mandate", "attach_mandate", "check_payment"]
    assert handle(t, {"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"] == {}
    assert handle(t, {"jsonrpc": "2.0", "id": 3, "method": "nope"})["error"]["code"] == -32601
    assert handle(t, {"id": 4})["error"]["code"] == -32600
    assert handle(t, "x")["error"]["code"] == -32600
    bad = handle(t, {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "pay_everything"}})
    assert bad["error"]["code"] == -32602


def test_mcp_tool_errors_are_results_not_crashes(world):
    t = tools(world)
    assert call(t, "attach_mandate", {"amount": "1.00"})["isError"]
    assert "bad amount" in call(t, "attach_mandate", {"payment_id": "x", "amount": "1.5", "payee": PAYEE})[
        "content"][0]["text"]
    assert "no checker configured" in call(t, "check_payment", {"payment": {}})["content"][0]["text"]
    assert "unreachable" in call(tools(world, bank_url="http://127.0.0.1:9"), "check_payment",
                                 {"payment": {}})["content"][0]["text"]
    assert "no mandate loaded" in call(tools(world, mandate=None), "attach_mandate",
                                       {"payment_id": "x", "amount": "1.00", "payee": PAYEE})["content"][0]["text"]
    assert "--agent-key" in call(tools(world, agent_key=None), "attach_mandate",
                                 {"payment_id": "x", "amount": "1.00", "payee": PAYEE})["content"][0]["text"]


def test_mcp_request_mandate_writes_unsigned_draft(world):
    t = tools(world)
    pub = M.public_key_of(M.new_key()[0])
    args = {"company": "Nordhafen Logistik GmbH", "country": "AT", "signer_id": "kberger@nordhafen.at",
            "signer_public_key": pub, "currency": "EUR", "max_per_payment": "5000.00", "max_per_month": "20000.00",
            "payees": [PAYEE], "from_accounts": [DEBTOR], "valid_until": "2026-12-31T23:59:59.000Z",
            "purpose": "Freight invoices"}
    out = call(t, "request_mandate", args)["structuredContent"]
    assert out["status"] == "awaiting_signature"
    draft = json.loads(Path(out["draft"]).read_text())
    assert "sig" not in draft and draft["scope"]["max_per_period"] == {"amount": "20000.00", "period": "P1M"}
    assert draft["scope"]["from_accounts"] == [{"scheme": "iban", "iban": DEBTOR}]
    assert M.mandate_hash(draft) == out["mandate_hash"]
    second = call(t, "request_mandate", args)["structuredContent"]
    assert second["draft"] != out["draft"]
    assert call(t, "request_mandate", {**args, "max_per_payment": "5000"})["isError"]


def test_mcp_stdio_loop(world):
    t = tools(world)
    stdin = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n\nnot json\n'
                        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    out = io.StringIO()
    serve_stdio(t, stdin, out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert len(lines) == 2 and lines[0]["id"] == 1 and lines[1]["error"]["code"] == -32700


def test_mcp_as_a_real_process(world):
    """What Claude Desktop runs: `gleipnir mandate mcp ...` on stdio."""
    proc = subprocess.run(
        [sys.executable, "-m", "gleipnir.cli", "mandate", "mcp", "--mandate", "mandate.json", "--agent-key",
         "agent.pem", "--bank-key", "bank.pem", "--authority", "kyb.json", "--state", "s.json"],
        input='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
              '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"attach_mandate","arguments":'
              '{"payment_id":"INV-1","amount":"100.00","payee":"' + PAYEE + '"}}}\n',
        capture_output=True, text=True, timeout=60, cwd=world)
    lines = [json.loads(x) for x in proc.stdout.splitlines()]
    assert lines[0]["result"]["serverInfo"]["name"] == "gleipnir-mandate"
    assert lines[1]["result"]["structuredContent"]["payment"]["id"] == "INV-1"


def test_mcp_scope_and_resource(world):
    t = tools(world)
    scope = call(t, "mandate_scope", {})["structuredContent"]
    assert scope["max_per_payment"] == "25000.00" and scope["payees"][0]["account"]["iban"] == IBAN
    assert scope["signed_by"] == ["kberger@nordhafen.at"] and scope["problem"] is None
    res = handle(t, {"jsonrpc": "2.0", "id": 1, "method": "resources/list"})["result"]["resources"]
    assert res[0]["uri"] == "gleipnir://mandate/current"
    body = handle(t, {"jsonrpc": "2.0", "id": 2, "method": "resources/read",
                      "params": {"uri": "gleipnir://mandate/current"}})["result"]["contents"][0]["text"]
    assert json.loads(body)["id"] == "m_ap"
    assert handle(t, {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "file:///etc/passwd"}})[
        "error"]["code"] == -32002
    none = tools(world, mandate=None)
    assert handle(none, {"jsonrpc": "2.0", "id": 4, "method": "resources/list"})["result"]["resources"] == []


@pytest.mark.parametrize("name, args, text", [
    ("attach_mandate", {"payment_id": "x", "amount": 100, "payee": PAYEE}, "amount must be a string"),
    ("attach_mandate", {"payment_id": "x", "amount": "1.00", "payee": PAYEE, "agent_key": "/etc/x"}, "unknown"),
    ("attach_mandate", {"payment_id": "x" * 3000, "amount": "1.00", "payee": PAYEE}, "too long"),
    ("check_payment", {"payment": "p"}, "payment must be a object"),
    ("request_mandate", {"company": "X", "country": "AT", "signer_id": "a", "signer_public_key": "k",
                         "currency": "EUR", "max_per_payment": "1.00", "payees": [1], "from_accounts": [DEBTOR],
                         "valid_until": "x"},
     "list of strings"),
    ("mandate_scope", [], "arguments must be an object"),
])
def test_mcp_rejects_bad_arguments(world, name, args, text):
    out = handle(tools(world), {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"name": name, "arguments": args}})["result"]
    assert out["isError"] and text in out["content"][0]["text"]


def rpc(url: str, msg, headers: dict | None = None) -> tuple[int, dict | None]:
    data = msg if isinstance(msg, bytes) else json.dumps(msg).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, json.loads(raw) if raw else None


@pytest.fixture()
def mcp_http(world):
    srv = make_mcp_http(tools(world, bank_key="bank.pem", authority="kyb.json"), port=0, token="s3cret",
                        origins=["https://claude.example"])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    srv.shutdown()
    srv.server_close()


def test_mcp_over_http(mcp_http):
    auth = {"Authorization": "Bearer s3cret"}
    code, init = rpc(mcp_http, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, auth)
    assert code == 200 and init["result"]["capabilities"]["resources"] == {}
    assert rpc(mcp_http, {"jsonrpc": "2.0", "method": "notifications/initialized"}, auth) == (202, None)
    code, p = rpc(mcp_http, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "attach_mandate", "arguments": {"payment_id": "INV-H", "amount": "100.00", "payee": PAYEE}}}, auth)
    payment = p["result"]["structuredContent"]["payment"]
    code, d = rpc(mcp_http, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
        "name": "check_payment", "arguments": {"payment": payment}}},
        {**auth, "Origin": "https://claude.example"})
    assert d["result"]["structuredContent"]["outcome"] == "allow"


@pytest.mark.parametrize("headers, body, path, code", [
    ({}, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, "/mcp", 401),
    ({"Authorization": "Bearer nope"}, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, "/mcp", 401),
    ({"Authorization": "Bearer s3cret", "Origin": "https://evil.example"}, {"jsonrpc": "2.0", "id": 1,
                                                                            "method": "ping"}, "/mcp", 403),
    ({"Authorization": "Bearer s3cret"}, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, "/other", 404),
    ({"Authorization": "Bearer s3cret"}, [{"jsonrpc": "2.0", "id": 1, "method": "ping"}], "/mcp", 400),
    ({"Authorization": "Bearer s3cret"}, b'{"jsonrpc": "2.0", "id": 1, "id": 2, "method": "ping"}', "/mcp", 400),
    ({"Authorization": "Bearer s3cret"}, b"\xff", "/mcp", 400),
])
def test_mcp_http_guards(mcp_http, headers, body, path, code):
    assert rpc(mcp_http.replace("/mcp", path), body, headers)[0] == code


def test_mcp_http_no_streams(mcp_http):
    for method in ("GET", "DELETE"):
        req = urllib.request.Request(mcp_http, method=method, headers={"Authorization": "Bearer s3cret"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=5)
        assert e.value.code == 405
    req = urllib.request.Request(mcp_http, data=b"", method="POST", headers={"Authorization": "Bearer s3cret"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=5)
    assert e.value.code == 400


TS_MCP = Path(__file__).resolve().parents[3] / "typescript/packages/sdk/dist/mandate-mcp.js"


@pytest.mark.skipif(not TS_MCP.exists() or not __import__("shutil").which("node"), reason="TS MCP not built")
def test_ts_mcp_against_python_bank(server, world):
    """Interop: the npx MCP server (TypeScript) asks the reference bank checker (Python) over HTTP."""
    url, bank = server
    calls = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "attach_mandate", "arguments": {
        "payment_id": "INV-TS", "amount": "18400.00", "payee": PAYEE}}}]
    first = subprocess.run(["node", str(TS_MCP), "--mandate", "mandate.json", "--agent-key", "agent.pem"],
                           input=json.dumps(calls[0]) + "\n", capture_output=True, text=True, timeout=60, cwd=world)
    payment = json.loads(first.stdout)["result"]["structuredContent"]["payment"]
    check = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "check_payment", "arguments": {"payment": payment}}}
    second = subprocess.run(["node", str(TS_MCP), "--mandate", "mandate.json", "--bank-url", url],
                            input=json.dumps(check) + "\n", capture_output=True, text=True, timeout=60, cwd=world)
    out = json.loads(second.stdout)["result"]["structuredContent"]
    assert out["outcome"] == "allow"
    assert M.verify_decision(out["decision"], [bank.public_key])


def test_audit_F8_revocations_survive_restart(server, world):
    url, bank = server
    mandate = json.loads(Path("mandate.json").read_text())
    assert main(["mandate", "revoke", "mandate.json", "--key", "signer.pem", "--id", "r_x", "-o", "rev.json"]) == 0
    assert revoke_via(url, mandate) == (200, {"ok": True})
    restarted = Bank(bank_id="bank:test", bank_key="bank.pem", authority="kyb.json", state=bank.state)
    t = tools(world)
    p = call(t, "attach_mandate", {"payment_id": "INV-R", "amount": "1.00", "payee": PAYEE})["structuredContent"]
    assert restarted.check(mandate, p["payment"])["reasons"] == ["mandate_revoked"]


def test_audit_F15_checker_refuses_cross_site_posts(server):
    url, _ = server
    for headers, code in [({"Content-Type": "text/plain"}, 415), ({}, 415),
                          ({"Content-Type": "application/json", "Origin": "https://evil.example"}, 403)]:
        req = urllib.request.Request(url + "/check", data=b'{"mandate": {}, "payment": {}}', method="POST",
                                     headers=headers)
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=5)
        assert e.value.code == code


def test_audit_F9_hostile_json_gets_an_answer(server, world):
    url, _ = server
    assert post(url, b'{"mandate": ' + b"9" * 5000 + b', "payment": {}}')[0] == 400
    t = tools(world)
    bad_name = handle(t, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": {"x": 1}}})
    assert bad_name["error"]["code"] == -32602
    weird = handle(t, {"jsonrpc": "2.0", "id": [1], "method": "tools/call", "params": {"name": "mandate_scope",
                                                                                       "arguments": None}})
    assert "result" in weird or "error" in weird
    out = io.StringIO()
    serve_stdio(t, io.StringIO('{"x": ' + "9" * 5000 + '}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n'), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32700 and lines[1]["result"] == {}
    Path("huge.json").write_text('{"v": ' + "9" * 5000 + "}")
    assert main(["mandate", "sign", "huge.json", "--key", "signer.pem"]) == 2  # an error message, not a traceback


def test_audit_R6_revoke_needs_a_valid_signature(server, world):
    url, _ = server
    assert main(["mandate", "revoke", "mandate.json", "--key", "signer.pem", "--id", "r_y", "-o", "rev.json"]) == 0
    r = json.loads(Path("rev.json").read_text())
    mandate = json.loads(Path("mandate.json").read_text())
    assert post(url, {"revocation": {**r, "reason": "edited after signing"}, "mandate": mandate}, "/revoke")[0] == 400
    assert post(url, r, "/revoke")[0] == 400  # the mandate it revokes must come with it
    assert post(url, {"revocation": r, "mandate": mandate}, "/revoke") == (200, {"ok": True})
    assert post(url, {"revocation": r, "mandate": mandate}, "/revoke") == (200, {"ok": True})  # stored once


def test_audit3_F1_junk_revocations_are_refused(server, world):
    """Self-signed revocations by strangers, or huge ones, never reach the store (audit 24.10.2026, F1)."""
    url, bank = server
    mandate = json.loads(Path("mandate.json").read_text())
    evil_sk, evil_pk = M.new_key()
    junk = M.revoke(mandate, signer={"id": "evil@x", "public_key": evil_pk}, sk=evil_sk, id="r_evil")
    assert post(url, {"revocation": junk, "mandate": mandate}, "/revoke")[0] == 400
    from gleipnir.mandate_cli import load_key

    sk = load_key("signer.pem")
    big = M.revoke(mandate, signer={"id": "kberger@nordhafen.at", "public_key": M.public_key_of(sk)}, sk=sk,
                   id="r_big", reason="x" * 5000)
    assert post(url, {"revocation": big, "mandate": mandate}, "/revoke")[0] == 400
    other = {**mandate, "id": "m_other"}
    real = M.revoke(mandate, signer={"id": "kberger@nordhafen.at", "public_key": M.public_key_of(sk)}, sk=sk,
                    id="r_1")
    assert post(url, {"revocation": real, "mandate": other}, "/revoke")[0] == 400  # not aimed at that mandate
    state = json.loads(Path(bank.state).read_text()) if Path(bank.state).exists() else {"revocations": []}
    assert state["revocations"] == []


def test_http_resolve_override(server, world):
    url, bank = server
    mandate = json.loads(Path("mandate.json").read_text())
    t = tools(world)
    p = call(t, "attach_mandate", {"payment_id": "INV-BIG", "amount": "26000.00", "payee": PAYEE})[
        "structuredContent"]["payment"]
    code, d = post(url, {"mandate": mandate, "payment": p})
    assert (code, d["reasons"]) == (200, ["over_payment_limit"])
    from gleipnir.mandate_cli import load_key

    sk = load_key("signer.pem")
    o = M.sign_override(M.make_override(d, outcome="allow", id="o_1"), sk,
                        {"id": "kberger@nordhafen.at", "public_key": M.public_key_of(sk)})
    code, final = post(url, {"mandate": mandate, "payment": p, "decision": d, "override": o}, "/resolve")
    assert code == 200 and final["outcome"] == "allow" and final["override"]["id"] == "o_1"
    assert post(url, {"mandate": mandate, "payment": p}, "/resolve")[0] == 400
    assert post(url, {"mandate": mandate, "payment": p})[1] == final


def test_http_keyset_and_revocation_list(server, world):
    url, bank = server
    mandate = json.loads(Path("mandate.json").read_text())
    with urllib.request.urlopen(url + "/.well-known/gleipnir-checker.json") as r:
        ks = json.loads(r.read())
    assert M.keyset_problem(ks) is None and ks["checker"] == "bank:test"
    t = tools(world)
    p = call(t, "attach_mandate", {"payment_id": "INV-K", "amount": "1.00", "payee": PAYEE})["structuredContent"]
    _, d = post(url, {"mandate": mandate, "payment": p["payment"]})
    assert M.verify_decision(d, ks)
    assert main(["mandate", "revoke", "mandate.json", "--key", "signer.pem", "--id", "r_k", "-o", "rev.json"]) == 0
    assert revoke_via(url, mandate) == (200, {"ok": True})
    with urllib.request.urlopen(url + "/revocations") as r:
        doc = json.loads(r.read())
    from datetime import datetime, timezone

    revs = M.revocations_from_list(doc, ks, datetime.now(timezone.utc))
    assert [r["id"] for r in revs] == ["r_k"]
