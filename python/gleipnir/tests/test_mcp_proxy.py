"""gleipnir-mcp: a recording stdio proxy in front of a real MCP server process."""

import json
import os
import signal
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

from gleipnir import cli, mcp_proxy
from gleipnir.store import JsonlStore
from gleipnir_verify import verify_bundle
from gleipnir_verify.cli import main as verify_main

HERE = Path(__file__).parent
FAKE = HERE / "mcp_servers" / "fake_server.py"
SDK = HERE / "mcp_servers" / "sdk_server.py"


def jl(*msgs):
    return b"".join(json.dumps(m).encode() + b"\n" for m in msgs)


def call(i, name, args=None):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args or {}}}


SESSION = [
    {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "9.1"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    call(2, "refund", {"order": "o1", "amount": 5, "card": "4111111111111111"}),
    call("s-3", "fails", {"order": "o2"}),
    call(4, "boom", {"x": 1}),
    {"jsonrpc": "2.0", "id": 5, "method": "ping"},
    [call(6, "refund", {"order": "b1", "amount": 1}), call(7, "refund", {"order": "b2", "amount": 2})],
    call(8, "big", {"size": 3_000_000}),
]


def proxy_cmd(home, *extra):
    return [sys.executable, "-m", "gleipnir.mcp_proxy", "--home", str(home), *extra, "--",
            sys.executable, str(FAKE)]


def run(cmd, data, env=None, timeout=60):
    env = {**os.environ, **(env or {})}
    return subprocess.run(cmd, input=data, capture_output=True, timeout=timeout, env=env)


def actions(home, chain="mcp-fake_server"):
    return [r for r in JsonlStore(Path(home) / "chains" / chain, fsync=False).read_all() if r["kind"] == "action"]


def test_forwarding_is_byte_identical_and_calls_are_recorded(tmp_path):
    data = jl(*SESSION)
    direct_log, proxied_log = tmp_path / "direct.log", tmp_path / "proxied.log"
    direct = run([sys.executable, str(FAKE)], data, {"FAKE_MCP_LOG": str(direct_log)})
    home = tmp_path / "g"
    proxied = run(proxy_cmd(home, "--redact", "card"), data, {"FAKE_MCP_LOG": str(proxied_log)})
    assert proxied.returncode == 0, proxied.stderr.decode()
    # server -> client: exactly the bytes the server wrote, same order (incl. a notification and a batch)
    assert proxied.stdout == direct.stdout
    # client -> server: exactly the bytes the client wrote
    assert proxied_log.read_bytes() == data == direct_log.read_bytes()
    out = [json.loads(x) for x in proxied.stdout.splitlines()]
    assert out[1]["method"] == "notifications/message"
    assert [m["id"] for m in out if isinstance(m, dict) and "id" in m] == [0, 1, 2, "s-3", 4, 5, 8]
    assert b"recording tool calls to" in proxied.stderr

    acts = actions(home)
    assert [a["tool"]["name"] for a in acts] == ["refund", "fails", "boom", "refund", "refund", "big"]
    refund, fails, boom = acts[0], acts[1], acts[2]
    assert all(a["tool"]["system"] == "fake-payments" for a in acts)  # from serverInfo
    assert all(a["agent"] == {"id": "test-client", "version": "9.1"} for a in acts)
    assert refund["context"]["session"] == "test-client 9.1" and refund["context"]["tool_call_id"] == "2"
    assert refund["args"]["order"] == "o1" and refund["args"]["card"]["redacted"].startswith("hmac-sha256:")
    assert refund["response"] == {"status": "ok", "body": {
        "content": [{"type": "text", "text": json.dumps({"refund_id": "R-o1", "amount": 5})}],
        "structuredContent": {"refund_id": "R-o1", "amount": 5}, "isError": False}}
    assert fails["response"] == {"status": "error", "error": "tool returned isError: refund not allowed"}
    assert boom["response"]["status"] == "error" and "-32602" in boom["response"]["error"]
    assert "unknown tool boom" in boom["response"]["error"]
    assert len(acts[5]["response"]["body"]["content"][0]["text"]) == 3_000_000
    assert all(a["t"]["start"] <= a["t"]["end"] for a in acts)

    # EOF closed the segment: a full export verifies with gleipnir-verify
    assert cli.main(["--home", str(home), "--chain", "mcp-fake_server", "export", "-o",
                     str(tmp_path / "b.zip")]) == 0
    assert verify_bundle(tmp_path / "b.zip", require_full=True).valid()
    key = JsonlStore(home / "chains" / "mcp-fake_server").read_all()[0]["public_key"]["id"]
    assert verify_main([str(tmp_path / "b.zip"), "--expect-key", key, "--require-full",
                        "--local-anchor-log", str(home / "anchors" / "local-anchor-log.jsonl")]) == 0
    records = JsonlStore(home / "chains" / "mcp-fake_server").read_all()
    assert records[-1]["kind"] in ("segment", "anchor") or any(r["kind"] == "segment" for r in records)


def test_split_writes_and_cancellation(tmp_path):
    home = tmp_path / "g"
    p = subprocess.Popen(proxy_cmd(home, "--system", "payments"), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    msg = jl(SESSION[0], call(1, "refund", {"order": "o9", "amount": 3}))
    for i in range(0, len(msg), 7):  # a message split over many small writes
        p.stdin.write(msg[i:i + 7])
        p.stdin.flush()
        time.sleep(0.002)
    out, err = p.communicate(jl(call(2, "slow", {"delay": 0.5}),
                                {"jsonrpc": "2.0", "method": "notifications/cancelled",
                                 "params": {"requestId": 2, "reason": "user stopped"}}), timeout=30)
    assert p.returncode == 0, err.decode()
    ids = [json.loads(x).get("id") for x in out.splitlines()]
    assert ids == [0, 1, 2]  # the late response is still forwarded
    acts = sorted(actions(home, "mcp-payments"), key=lambda a: a["context"]["tool_call_id"])  # completion order
    assert [a["tool"]["name"] for a in acts] == ["refund", "slow"]
    assert acts[0]["tool"]["system"] == "payments"
    assert acts[1]["response"] == {"status": "error", "error": "cancelled by the client: user stopped"}


def test_sigterm_flushes_and_records_unanswered_calls(tmp_path):
    home = tmp_path / "g"
    p = subprocess.Popen(proxy_cmd(home), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(jl(SESSION[0], call(1, "refund", {"order": "o1", "amount": 1}), call(2, "slow", {"delay": 60})))
    p.stdin.flush()
    deadline = time.time() + 20
    seen = b""
    while seen.count(b"\n") < 2 and time.time() < deadline:
        seen += p.stdout.read1(65536)
    time.sleep(0.3)
    p.send_signal(signal.SIGTERM)
    p.communicate(timeout=30)
    acts = actions(home)
    assert [a["tool"]["name"] for a in acts] == ["refund", "slow"]
    assert acts[1]["response"]["error"] == "no response before the proxy shut down"
    out = tmp_path / "b.zip"
    assert cli.main(["--home", str(home), "--chain", "mcp-fake_server", "export", "-o", str(out)]) == 0
    report = verify_bundle(out, require_full=True)
    assert report.valid(), report.as_dict()
    assert report.summary["segments"] >= 1


def test_recording_failure_does_not_break_the_session(tmp_path):
    home = tmp_path / "not-a-dir"
    home.write_text("x")
    data = jl(*SESSION[:5])
    direct = run([sys.executable, str(FAKE)], data)
    proxied = run(proxy_cmd(home), data)
    assert proxied.returncode == 0
    assert proxied.stdout == direct.stdout
    assert b"recording disabled" in proxied.stderr


def test_server_exit_code_and_missing_server(tmp_path):
    r = run([sys.executable, "-m", "gleipnir.mcp_proxy", "--home", str(tmp_path / "g"), "--",
             sys.executable, "-c", "import sys; sys.exit(3)"], b"")
    assert r.returncode == 3
    r = run([sys.executable, "-m", "gleipnir.mcp_proxy", "--home", str(tmp_path / "g"), "--",
             "definitely-not-a-command-xyz"], b"")
    assert r.returncode == 127 and b"cannot start MCP server" in r.stderr
    r = run([sys.executable, "-m", "gleipnir.mcp_proxy"], b"")
    assert r.returncode == 2


def test_second_proxy_for_same_server_uses_its_own_chain(tmp_path):
    home = tmp_path / "g"
    first = subprocess.Popen(proxy_cmd(home), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    first.stdin.write(jl(SESSION[0], call(1, "refund", {"order": "a", "amount": 1})))
    first.stdin.flush()
    first.stdout.readline()
    first.stdout.readline()
    second = run(proxy_cmd(home), jl(SESSION[0], call(1, "refund", {"order": "b", "amount": 1})))
    assert second.returncode == 0
    first.communicate(b"", timeout=30)
    assert [a["args"]["order"] for a in actions(home)] == ["a"]
    assert [a["args"]["order"] for a in actions(home, "mcp-fake_server-2")] == ["b"]


def test_observer_reassembles_chunks(tmp_path, clock):
    import gleipnir

    rec = gleipnir.Recorder("x", "1", home=tmp_path / "g", background=False, clock=clock, quiet=True, fsync=False)
    obs = mcp_proxy.Observer(home=tmp_path / "g", chain=None, system=None, default_system="srv", anchor=None,
                             redact=None, recorder=rec)
    req = jl(call(1, "t", {"a": "é "}))
    resp = jl({"jsonrpc": "2.0", "id": 1, "result": {"content": []}})
    obs.start()
    for i in range(len(req)):  # byte by byte, splitting a multi-byte UTF-8 character
        obs.feed("c2s", req[i:i + 1])
    obs.feed("s2c", b"not json at all\n" + resp[:5])
    obs.feed("s2c", resp[5:])
    obs.close()
    acts = [r for r in rec.chain.store.read_all() if r["kind"] == "action"]
    assert len(acts) == 1 and acts[0]["args"] == {"a": "é "} and acts[0]["tool"]["system"] == "srv"


def test_oversized_message_is_forwarded_but_not_recorded(tmp_path, clock, monkeypatch):
    import gleipnir

    monkeypatch.setattr(mcp_proxy, "MAX_LINE", 100)
    rec = gleipnir.Recorder("x", "1", home=tmp_path / "g", background=False, clock=clock, quiet=True, fsync=False)
    obs = mcp_proxy.Observer(home=tmp_path / "g", chain=None, system=None, default_system="srv", anchor=None,
                             redact=None, recorder=rec)
    obs.start()
    obs.feed("c2s", jl(call(1, "t", {"a": "x" * 200}))[:150])
    obs.feed("c2s", b"x" * 100 + b"\n" + jl(call(2, "t")))
    obs.feed("s2c", jl({"jsonrpc": "2.0", "id": 1, "result": {}}, {"jsonrpc": "2.0", "id": 2, "result": {}}))
    obs.close()
    records = rec.chain.store.read_all()
    assert [r["context"]["tool_call_id"] for r in records if r["kind"] == "action"] == ["2"]
    assert any(r["kind"] == "note" and "not observed" in r["note"]["text"] for r in records)


@pytest.mark.parametrize("cmd,name", [
    (["npx", "-y", "@modelcontextprotocol/server-github"], "server-github"),
    (["uvx", "mcp-server-fetch"], "mcp-server-fetch"),
    (["python", "-m", "my_server"], "my_server"),
    (["python3.12", "/srv/tools/server.py"], "server"),
    (["docker", "run", "-i", "--rm", "ghcr.io/x/y-mcp:latest"], "y-mcp:latest"),
    (["/usr/local/bin/my-mcp"], "my-mcp"),
])
def test_server_name(cmd, name):
    assert mcp_proxy.server_name(cmd) == name


def test_print_config(tmp_path, capsys):
    home = tmp_path / "g"
    assert mcp_proxy.main(["--home", str(home), "--print-config", "claude-desktop", "--redact", "token",
                           "--", "npx", "-y", "@modelcontextprotocol/server-github"]) == 0
    cfg = json.loads(capsys.readouterr().out)
    entry = cfg["mcpServers"]["server-github"]
    assert entry["args"][-4:] == ["--", "npx", "-y", "@modelcontextprotocol/server-github"]
    assert "--redact" in entry["args"] and str(home.resolve()) in entry["args"]
    assert "type" not in entry
    assert cli.main(["mcp-proxy", "--print-config", "cursor", "--name", "gh", "--", "uvx", "x"]) == 0
    cur = json.loads(capsys.readouterr().out)["mcpServers"]["gh"]
    assert cur["type"] == "stdio" and cur["args"][-3:] == ["--", "uvx", "x"]
    assert cli.main(["mcp-proxy", "--print-config", "claude-code", "--", "uvx", "mcp-x"]) == 0
    line = capsys.readouterr().out.strip()
    assert line.startswith("claude mcp add --transport stdio mcp-x -- ") and line.endswith("-- uvx mcp-x")


def test_cli_mcp_proxy_and_report(tmp_path):
    home = tmp_path / "g"
    data = jl(*SESSION[:6])
    r = run([sys.executable, "-m", "gleipnir.cli", "--home", str(home), "mcp-proxy", "--", sys.executable,
             str(FAKE)], data)
    assert r.returncode == 0, r.stderr.decode()
    assert len(r.stdout.splitlines()) == 6
    out = tmp_path / "report.html"
    assert cli.main(["--home", str(home), "report", "-o", str(out)]) == 0
    page = out.read_text()
    assert "What my agent did" in page and "fake-payments" in page and "refund not allowed" in page
    assert "VALID" in page and "test-client" in page and "mcp-fake_server" in page


def test_report_empty_home(tmp_path):
    out = tmp_path / "r.html"
    assert cli.main(["--home", str(tmp_path / "none"), "report", "-o", str(out)]) == 0
    assert "No tool calls recorded yet" in out.read_text()


# ---- against the official MCP Python SDK -----------------------------------------------------------
def _mcp():
    try:
        import mcp  # noqa: F401
        from mcp import ClientSession, StdioServerParameters, stdio_client
    except Exception:  # noqa: BLE001
        pytest.skip("mcp SDK not installed (uv pip install mcp)")
    return ClientSession, StdioServerParameters, stdio_client


async def test_real_mcp_sdk_client_and_server(tmp_path):
    ClientSession, StdioServerParameters, stdio_client = _mcp()
    home = tmp_path / "g"
    params = StdioServerParameters(command=sys.executable, args=[
        "-m", "gleipnir.mcp_proxy", "--home", str(home), "--redact", "card", "--", sys.executable, str(SDK)])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "sdk-payments"
        tools = await session.list_tools()
        assert {t.name for t in tools.tools} >= {"refund", "explode"}
        ok = await session.call_tool("refund", {"order": "o1", "amount": 7, "card": "4111"})
        assert not ok.is_error and "R-o1" in json.dumps(ok.model_dump(mode="json"))
        bad = await session.call_tool("explode", {"reason": "nope"})
        assert bad.is_error
    deadline = time.time() + 15
    while time.time() < deadline:  # the proxy seals the segment after the client closes the pipe
        recs = JsonlStore(home / "chains" / "mcp-sdk_server", fsync=False).read_all()
        if recs and recs[-1]["kind"] in ("segment", "anchor"):
            break
        time.sleep(0.1)
    acts = actions(home, "mcp-sdk_server")
    assert [a["tool"]["name"] for a in acts] == ["refund", "explode"]
    assert acts[0]["tool"]["system"] == "sdk-payments"
    assert acts[0]["args"]["card"]["redacted"].startswith("hmac")
    assert "R-o1" in json.dumps(acts[0]["response"]["body"])
    assert acts[1]["response"]["status"] == "error" and "explode" in acts[1]["response"]["error"]
    assert acts[0]["agent"]["id"]  # the SDK's clientInfo name
    out = tmp_path / "pack.zip"
    assert cli.main(["--home", str(home), "--chain", "mcp-sdk_server", "pack", "-o", str(out)]) == 0
    with zipfile.ZipFile(out) as zf:
        assert json.loads(zf.read("verification.json"))["result"] == "VALID"
