"""Transparent stdio MCP proxy that records every ``tools/call`` going through it.

    gleipnir-mcp [--home DIR] [--system NAME] [--anchor local|rekor] [--redact f1,f2] -- <server command...>

The proxy launches the real MCP server as a subprocess and copies bytes in both directions
exactly as they arrive: nothing is parsed, buffered or re-encoded on the forwarding path. A
copy of each chunk goes to a background observer thread that splits it into newline-delimited
JSON-RPC messages (the MCP stdio transport), pairs each ``tools/call`` request with its response,
and writes one signed action record per call. Recording runs off the forwarding path, so a slow
disk, a full queue or a crash in the observer never delays, alters or drops a message.

Records go to ``<home>/chains/<chain>``; one chain per MCP server (``mcp-<name>``). If another
proxy process already writes that chain, a numbered sibling (``mcp-<name>-2``) is used, because a
chain has a single writer.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import queue
import re
import shlex
import shutil
import signal
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .util import new_id, utcnow

CHUNK = 64 * 1024
MAX_LINE = 64 * 1024 * 1024  # longer messages are forwarded but not recorded
MAX_BACKLOG = 20_000  # observer queue items; beyond this, chunks are forwarded but not observed
MAX_PENDING = 10_000  # open tools/call requests tracked at once
SHUTDOWN_GRACE = 5.0  # seconds the server gets to exit after its stdin closes

_LAUNCHERS = {"python", "python3", "py", "node", "npx", "uvx", "uv", "bun", "bunx", "deno", "pnpm", "pnpx",
              "yarn", "docker", "podman", "pipx", "java", "dotnet", "ruby", "go", "cargo"}
_SUBCOMMANDS = {"run", "dlx", "exec", "x", "tool", "-m"}


def _log(msg: str) -> None:
    try:
        sys.stderr.write(f"gleipnir-mcp: {msg}\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001 - stderr may be closed
        pass


def default_home() -> Path:
    return Path(os.environ.get("GLEIPNIR_HOME") or Path.home() / ".gleipnir")


def server_name(cmd: list[str]) -> str:
    """A readable name for an MCP server command (``npx -y @x/server-github`` -> ``server-github``)."""
    if not cmd:
        return "mcp-server"
    base = re.sub(r"\.(exe|cmd|bat|py|js|mjs|ts)$", "", Path(cmd[0]).name.lower())
    if re.match(r"^python\d", base):
        base = "python"
    if base in _LAUNCHERS:
        for arg in cmd[1:]:
            if arg.startswith("-") and arg != "-m" or arg in _SUBCOMMANDS:
                continue
            name = arg.rstrip("/\\").replace("\\", "/").split("/")[-1].split("@")[0] or arg
            return re.sub(r"\.(py|js|mjs|ts|jar)$", "", name)
    return Path(cmd[0]).name


def slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")
    return s[:80] or "server"


# ---- chain locking ----------------------------------------------------------------------
class _ChainLock:
    """Exclusive, non-blocking lock on ``<home>/locks/<chain>.lock`` (released when the process ends)."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(path, "a+b")  # noqa: SIM115 - held for the life of the proxy
        try:
            if os.name == "nt":
                import msvcrt

                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.fh.close()
            raise

    def release(self) -> None:
        try:
            self.fh.close()
        except Exception:  # noqa: BLE001
            pass


def acquire_chain(home: Path, base: str) -> tuple[str, _ChainLock]:
    for i in range(1, 100):
        chain = base if i == 1 else f"{base}-{i}"
        try:
            return chain, _ChainLock(home / "locks" / f"{chain}.lock")
        except OSError:
            continue
    raise RuntimeError(f"no free chain name for {base}")


# ---- observer -----------------------------------------------------------------------------
def _key(request_id: Any) -> str:
    return json.dumps(request_id, sort_keys=True)


def _content_text(result: dict[str, Any]) -> str:
    parts = []
    for c in result.get("content") or []:
        if isinstance(c, dict) and isinstance(c.get("text"), str):
            parts.append(c["text"])
    return " ".join(parts)


class Observer:
    """Reassembles messages from forwarded chunks and records tool calls, on its own thread."""

    def __init__(self, *, home: Path, chain: str | None, system: str | None, default_system: str,
                 anchor: str | None, redact: list[str] | None, recorder: Any = None):
        self.home = home
        self.chain_base = chain
        self.system = system
        self.default_system = default_system
        self.anchor = anchor
        self.redact = redact or None
        self.rec = recorder
        self.lock: _ChainLock | None = None
        self.q: queue.Queue[tuple[str, datetime, bytes] | None] = queue.Queue()
        self.buffers = {"c2s": bytearray(), "s2c": bytearray()}
        self.skipping = {"c2s": False, "s2c": False}
        self.pending: dict[str, dict[str, Any]] = {}
        self.init_ids: set[str] = set()
        self.client: dict[str, Any] | None = None
        self.server: dict[str, Any] | None = None
        self.run_id = new_id("run")
        self.dropped = 0
        self.failures = 0
        self.recorded = 0
        self._thread = threading.Thread(target=self._run, name="gleipnir-mcp-observer", daemon=True)

    # -- called from the event loop (must be cheap and never raise) --------------------------
    def feed(self, direction: str, data: bytes) -> None:
        try:
            if self.q.qsize() >= MAX_BACKLOG:
                self.dropped += 1
                return
            self.q.put_nowait((direction, utcnow(), data))
        except Exception:  # noqa: BLE001
            self.dropped += 1

    def start(self) -> None:
        self._thread.start()

    def close(self, timeout: float = 30.0) -> None:
        self.q.put(None)
        self._thread.join(timeout)

    # -- observer thread ------------------------------------------------------------------------
    def _open(self) -> None:
        if self.rec is not None:
            return
        from . import __version__
        from .recorder import Recorder

        base = self.chain_base or "mcp-" + slug(self.system or self.default_system)
        chain, self.lock = acquire_chain(self.home, base)
        self.rec = Recorder("mcp-client", "unknown", home=self.home, chain=chain, anchor=self.anchor)
        _log(f"recording tool calls to {self.home / 'chains' / chain} (key {self.rec.key_id}, "
             f"gleipnir-sdk {__version__})")

    def _run(self) -> None:
        try:
            self._open()
        except Exception as exc:  # noqa: BLE001 - recording must never break the session
            _log(f"recording disabled: {type(exc).__name__}: {exc}")
            self.rec = None
        while True:
            item = self.q.get()
            if item is None:
                break
            if self.rec is None:
                continue
            try:
                self._chunk(*item)
            except Exception as exc:  # noqa: BLE001
                self._fail(exc)
        self._finish()

    def _fail(self, exc: BaseException) -> None:
        self.failures += 1
        if self.failures <= 5:
            _log(f"recording error (session unaffected): {type(exc).__name__}: {exc}")

    def _chunk(self, direction: str, t: datetime, data: bytes) -> None:
        buf = self.buffers[direction]
        start = 0
        while True:
            nl = data.find(b"\n", start)
            if nl < 0:
                break
            piece = data[start:nl]
            if self.skipping[direction]:
                self.skipping[direction] = False
            else:
                buf += piece
                line = bytes(buf)
                buf.clear()
                self._line(direction, t, line)
            start = nl + 1
        if not self.skipping[direction]:
            buf += data[start:]
            if len(buf) > MAX_LINE:
                buf.clear()
                self.skipping[direction] = True
                self.dropped += 1

    def _line(self, direction: str, t: datetime, line: bytes) -> None:
        line = line.strip()
        if not line:
            return
        try:
            msg = json.loads(line)
        except ValueError:
            return  # not JSON (a misbehaving server's log line); forwarded anyway
        for m in msg if isinstance(msg, list) else [msg]:
            if isinstance(m, dict):
                try:
                    self._message(direction, t, m)
                except Exception as exc:  # noqa: BLE001
                    self._fail(exc)

    def _message(self, direction: str, t: datetime, m: dict[str, Any]) -> None:
        method = m.get("method")
        params = m.get("params") if isinstance(m.get("params"), dict) else {}
        if direction == "c2s":
            meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
            info = meta.get("io.modelcontextprotocol/clientInfo")
            if isinstance(info, dict) and self.client is None:
                self._set_client(info)
            if method is not None and "id" in m:
                if method == "initialize":
                    self.init_ids.add(_key(m["id"]))
                    if isinstance(params.get("clientInfo"), dict):
                        self._set_client(params["clientInfo"])
                elif method == "server/discover":
                    self.init_ids.add(_key(m["id"]))
                elif method == "tools/call" and len(self.pending) < MAX_PENDING:
                    args = params.get("arguments")
                    self.pending[_key(m["id"])] = {
                        "id": m["id"], "name": str(params.get("name", "")), "start": t,
                        "args": args if isinstance(args, dict) else ({} if args is None else {"input": args}),
                    }
            elif method == "notifications/cancelled":
                call = self.pending.pop(_key(params.get("requestId")), None)
                if call is not None:
                    reason = params.get("reason")
                    self._record(call, t, error="cancelled by the client" + (f": {reason}" if reason else ""))
            return
        # server -> client: only responses to the client's own requests matter
        if method is not None or "id" not in m:
            return
        k = _key(m["id"])
        if k in self.init_ids:
            self.init_ids.discard(k)
            result = m.get("result") if isinstance(m.get("result"), dict) else {}
            info = result.get("serverInfo") or (result.get("_meta") or {}).get("io.modelcontextprotocol/serverInfo")
            if isinstance(info, dict):
                self.server = info
            return
        call = self.pending.pop(k, None)
        if call is None:
            return
        if "error" in m:
            err = m["error"] if isinstance(m["error"], dict) else {"message": str(m["error"])}
            text = f"JSON-RPC error {err.get('code')}: {err.get('message')}"
            if err.get("data") is not None:
                text += f" {json.dumps(err['data'], default=str)[:1000]}"
            self._record(call, t, error=text)
            return
        result = m.get("result")
        if isinstance(result, dict) and result.get("isError"):
            self._record(call, t, error=f"tool returned isError: {_content_text(result)}")
        else:
            self._record(call, t, response=result)

    def _set_client(self, info: dict[str, Any]) -> None:
        self.client = info
        if self.rec is not None:
            self.rec.agent = {"id": str(info.get("name") or "mcp-client"), "version": str(info.get("version") or "")}

    def _system(self) -> str:
        if self.system:
            return self.system
        if self.server and self.server.get("name"):
            return str(self.server["name"])
        return self.default_system

    def _record(self, call: dict[str, Any], end: datetime, *, response: Any = None, error: str | None = None) -> None:
        assert self.rec is not None
        ctx: dict[str, Any] = {"run_id": self.run_id, "tool_call_id": str(call["id"])}
        if self.client:
            ctx["session"] = f"{self.client.get('name', '')} {self.client.get('version', '')}".strip()
        with self.rec.context(**ctx):
            self.rec.record_action(tool=call["name"], system=self._system(), args=call["args"], response=response,
                                   error=error, start=call["start"], end=end, redact=self.redact)
        self.recorded += 1

    def _finish(self) -> None:
        if self.rec is None:
            return
        try:
            now = utcnow()
            for call in list(self.pending.values()):
                self._record(call, now, error="no response before the proxy shut down")
            self.pending.clear()
            if self.dropped:
                self.rec.note(f"{self.dropped} message chunks were forwarded but not observed "
                              "(recording backlog or oversized message); tool calls in them may be missing")
        except Exception as exc:  # noqa: BLE001
            self._fail(exc)
        try:
            self.rec.close()
        except Exception as exc:  # noqa: BLE001
            self._fail(exc)
        if self.lock is not None:
            self.lock.release()


# ---- byte pumps ---------------------------------------------------------------------------------
def _stdin_reader(loop: asyncio.AbstractEventLoop, q: asyncio.Queue[bytes]) -> None:
    fd = sys.stdin.fileno()
    while True:
        try:
            data = os.read(fd, CHUNK)
        except OSError:
            data = b""
        try:
            loop.call_soon_threadsafe(q.put_nowait, data)
        except RuntimeError:  # loop closed
            return
        if not data:
            return


class _StdoutWriter:
    """Writes to our stdout on a thread so a slow client never stalls the other direction."""

    def __init__(self, on_broken: Any):
        self.q: queue.SimpleQueue[bytes | None] = queue.SimpleQueue()
        self.on_broken = on_broken
        self.t = threading.Thread(target=self._run, name="gleipnir-mcp-stdout", daemon=True)
        self.t.start()

    def write(self, data: bytes) -> None:
        self.q.put(data)

    def _run(self) -> None:
        out = sys.stdout.buffer
        while True:
            data = self.q.get()
            if data is None:
                return
            try:
                out.write(data)
                out.flush()
            except (OSError, ValueError):
                self.on_broken()
                return

    def close(self, timeout: float = 10.0) -> None:
        self.q.put(None)
        self.t.join(timeout)


async def _terminate(proc: asyncio.subprocess.Process, grace: float) -> None:
    try:
        await asyncio.wait_for(proc.wait(), grace)
        return
    except asyncio.TimeoutError:
        pass
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), 3)
        return
    except (ProcessLookupError, asyncio.TimeoutError):
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    await proc.wait()


async def run_proxy(cmd: list[str], observer: Observer, *, grace: float = SHUTDOWN_GRACE) -> int:
    loop = asyncio.get_running_loop()
    exe = shutil.which(cmd[0]) or cmd[0]
    try:
        proc = await asyncio.create_subprocess_exec(exe, *cmd[1:], stdin=asyncio.subprocess.PIPE,
                                                    stdout=asyncio.subprocess.PIPE, stderr=None)
    except OSError as exc:
        _log(f"cannot start MCP server {cmd[0]!r}: {exc}")
        return 127
    assert proc.stdin is not None and proc.stdout is not None
    stop = asyncio.Event()
    observer.start()
    writer = _StdoutWriter(lambda: loop.call_soon_threadsafe(stop.set))
    inq: asyncio.Queue[bytes] = asyncio.Queue()
    threading.Thread(target=_stdin_reader, args=(loop, inq), name="gleipnir-mcp-stdin", daemon=True).start()

    if os.name != "nt":
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError, ValueError):
                pass
    else:  # pragma: no cover - Windows
        try:
            signal.signal(signal.SIGTERM, lambda *_: loop.call_soon_threadsafe(stop.set))
        except (ValueError, OSError):
            pass

    async def client_to_server() -> None:
        try:
            while True:
                data = await inq.get()
                if not data:
                    break
                proc.stdin.write(data)
                observer.feed("c2s", data)
                await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:  # noqa: BLE001
                pass

    async def server_to_client() -> None:
        while True:
            try:
                data = await proc.stdout.read(CHUNK)
            except (ConnectionResetError, OSError):
                data = b""
            if not data:
                return
            writer.write(data)
            observer.feed("s2c", data)

    c2s = asyncio.ensure_future(client_to_server())
    s2c = asyncio.ensure_future(server_to_client())
    stopper = asyncio.ensure_future(stop.wait())
    await asyncio.wait({c2s, s2c, stopper}, return_when=asyncio.FIRST_COMPLETED)

    if not c2s.done():  # server ended or a signal arrived: stop feeding the server
        c2s.cancel()
        try:
            await c2s
        except asyncio.CancelledError:
            pass
    # On EOF the server gets `grace` seconds to exit by itself (the MCP stdio shutdown sequence);
    # on a signal the client wants us gone now, so the server is terminated right away.
    await _terminate(proc, 0.0 if stop.is_set() else grace)
    try:
        await asyncio.wait_for(s2c, 5)  # drain what the server wrote before exiting
    except asyncio.TimeoutError:
        s2c.cancel()
    stopper.cancel()
    writer.close()
    observer.close()
    code = proc.returncode or 0
    return code if code >= 0 else 128 - code


# ---- client config snippets -------------------------------------------------------------------
def proxy_command() -> list[str]:
    """How a client should launch the proxy: the console script if on PATH, else this Python."""
    exe = shutil.which("gleipnir-mcp")
    if exe:
        return [str(Path(exe).absolute())]  # absolute: GUI clients do not see the shell PATH
    return [sys.executable, "-m", "gleipnir.mcp_proxy"]


def proxy_args(cmd: list[str], *, name: str, home: Path | None, system: str | None, anchor: str | None,
               redact: list[str] | None) -> list[str]:
    args = ["--home", str(home or default_home()), "--chain", "mcp-" + slug(name)]
    if system:
        args += ["--system", system]
    if anchor and anchor != "local":
        args += ["--anchor", anchor]
    if redact:
        args += ["--redact", ",".join(redact)]
    return args + ["--", *cmd]


def print_config(client: str, cmd: list[str], *, name: str | None, home: Path | None, system: str | None,
                 anchor: str | None, redact: list[str] | None) -> str:
    name = name or slug(server_name(cmd))
    launcher = proxy_command()
    args = launcher[1:] + proxy_args(cmd, name=name, home=home, system=system, anchor=anchor, redact=redact)
    entry: dict[str, Any] = {"command": launcher[0], "args": args}
    if client == "cursor":
        entry = {"type": "stdio", **entry}
    if client == "claude-code":
        line = ["claude", "mcp", "add", "--transport", "stdio", name, "--", launcher[0], *args]
        return " ".join(shlex.quote(x) for x in line)
    return json.dumps({"mcpServers": {name: entry}}, indent=2)


# ---- entry point ----------------------------------------------------------------------------------
def add_arguments(p: argparse.ArgumentParser, *, home_dest: str = "home") -> None:
    p.add_argument("--home", dest=home_dest, default=None,
                   help="data directory (default: $GLEIPNIR_HOME or ~/.gleipnir)")
    p.add_argument("--system", help="name recorded as the system (default: the server's own serverInfo.name)")
    p.add_argument("--chain", dest="proxy_chain", help="chain name (default: mcp-<system>)")
    p.add_argument("--anchor", choices=["local", "rekor", "none"], default="local",
                   help="where segment hashes are anchored (default: local)")
    p.add_argument("--redact", default="", help="comma-separated argument/result fields to redact (HMAC)")
    p.add_argument("--print-config", choices=["claude-desktop", "cursor", "claude-code"],
                   help="print the snippet for this client's config instead of running")
    p.add_argument("--name", help="server name in the printed config (default: derived from the command)")


def run_from_args(args: argparse.Namespace, cmd: list[str], home: Path | None) -> int:
    if not cmd:
        _log("no server command; usage: gleipnir-mcp [options] -- <server command...>")
        return 2
    redact = [f.strip() for f in (args.redact or "").split(",") if f.strip()]
    anchor = None if args.anchor == "none" else args.anchor
    if args.print_config:
        print(print_config(args.print_config, cmd, name=args.name, home=home.resolve() if home else None,
                           system=args.system, anchor=anchor, redact=redact))
        return 0
    observer = Observer(home=home or default_home(), chain=args.proxy_chain, system=args.system,
                        default_system=server_name(cmd), anchor=anchor, redact=redact)
    return asyncio.run(run_proxy(cmd, observer))


def split_command(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    own, cmd = split_command(argv)
    p = argparse.ArgumentParser(prog="gleipnir-mcp",
                                description="Record every MCP tools/call as a verifiable Gleipnir action record",
                                usage="gleipnir-mcp [options] -- <server command...>")
    add_arguments(p)
    args = p.parse_args(own)
    return run_from_args(args, cmd, Path(args.home).expanduser() if args.home else None)


if __name__ == "__main__":
    sys.exit(main())
