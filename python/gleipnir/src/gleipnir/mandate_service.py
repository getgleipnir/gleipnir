"""A reference bank checker over HTTP, and an MCP server for agents that pay under a mandate.

``gleipnir mandate serve`` (bank side, reference only):

    POST /check   {"mandate": {...}, "payment": {...}}  -> the signed decision (200), or {"error": ...} (400)
    GET  /keys    -> {"checker": id, "keys": [public key]}: what companies and auditors verify decisions with
    POST /revoke  a signed revocation; the checker still verifies it on every payment before it counts

Binds to 127.0.0.1 by default. Bodies are strict JSON (no duplicate keys, no NaN), at most 1 MiB. There is
no authentication: put it behind the bank's own API gateway. State (period ledger, payment log) is the dev
file store from ``gleipnir mandate check``.

``gleipnir mandate mcp`` (agent side): a stdio MCP server with three tools.

- ``request_mandate``: draft an unsigned mandate for a person to review and sign in their bank's app (or with
  ``gleipnir mandate sign``). The agent never signs a mandate itself.
- ``attach_mandate``: build a payment under the loaded mandate, signed with the agent's key.
- ``check_payment``: ask the bank's checker (``--bank-url``) whether a payment would pass, before submitting it;
  with ``--bank-key`` and ``--authority`` instead, a local demo checker answers.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from gleipnir_verify import mandate as m

from .mandate_cli import CliError, FileState, load_authority, load_key, loads_strict, parse_payee, read_json

MAX_BODY = 1 << 20
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")


# ---------- the bank side ----------

class Bank:
    """A Checker wired to the dev file state, safe to call from several HTTP threads."""

    def __init__(self, *, bank_id: str, bank_key: str, authority: str, state: Path,
                 revocations: list[str] | None = None) -> None:
        self.id = bank_id
        self.sk = load_key(bank_key)
        self.public_key = m.public_key_of(self.sk)
        self.authority = load_authority(authority)
        self.state = state
        self.revocations: list[dict] = [read_json(r) for r in revocations or []]
        self._lock = threading.Lock()

    def check(self, mandate: Any, payment: Any) -> dict[str, Any]:
        with self._lock, FileState(self.state) as st:
            checker = m.Checker(id=self.id, sk=self.sk, authority=self.authority, ledger=st, payments=st,
                                revocations=list(self.revocations))
            return checker.check(mandate, payment)

    def add_revocation(self, r: Any) -> None:
        problem = m.revocation_problem(r)
        if problem:
            raise CliError(f"revocation rejected: {problem}")
        with self._lock:
            self.revocations.append(r)


def make_handler(bank: Bank) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "gleipnir-checker/0.2"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            pass

        def _send(self, code: int, obj: Any) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> Any:
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise CliError("bad Content-Length") from exc
            if n <= 0 or n > MAX_BODY:
                raise CliError(f"body must be 1 byte to {MAX_BODY} bytes")
            try:
                text = self.rfile.read(n).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CliError("body is not UTF-8") from exc
            return loads_strict(text, "body")

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/keys":
                self._send(200, {"checker": bank.id, "keys": [bank.public_key]})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            try:
                if self.path == "/check":
                    body = self._body()
                    if not isinstance(body, dict) or set(body) != {"mandate", "payment"}:
                        raise CliError('expected {"mandate": ..., "payment": ...}')
                    self._send(200, bank.check(body["mandate"], body["payment"]))
                elif self.path == "/revoke":
                    bank.add_revocation(self._body())
                    self._send(200, {"ok": True})
                else:
                    self._send(404, {"error": "not found"})
            except CliError as exc:
                self._send(400, {"error": str(exc)})

    return Handler


def make_server(bank: Bank, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(bank))


def cmd_serve(args: argparse.Namespace) -> int:
    state = Path(args.state) if args.state else Path(args.home) / "mandate-state" / "state.json"
    bank = Bank(bank_id=args.bank_id, bank_key=args.bank_key, authority=args.authority, state=state,
                revocations=args.revocation)
    srv = make_server(bank, args.host, args.port)
    print(f"gleipnir: checker {bank.id} on http://{args.host}:{srv.server_address[1]} "
          f"(POST /check, GET /keys, POST /revoke). Reference server, no auth: keep it behind your gateway.",
          file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


# ---------- the agent side: MCP over stdio ----------

def _schema(props: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


TOOLS = [
    {"name": "request_mandate",
     "description": "Draft an unsigned mandate for a company signatory to review and sign in their bank's app. "
                    "You cannot sign it yourself; until a person signs, you cannot pay under it.",
     "inputSchema": _schema({
         "company": {"type": "string"}, "country": {"type": "string", "description": "ISO 3166 code"},
         "signer_id": {"type": "string", "description": "the signatory who will sign, as the bank knows them"},
         "signer_public_key": {"type": "string"},
         "currency": {"type": "string"}, "max_per_payment": {"type": "string", "description": "e.g. 25000.00"},
         "max_per_month": {"type": "string"},
         "payees": {"type": "array", "items": {"type": "string", "description": "NAME=IBAN"}},
         "valid_until": {"type": "string", "description": "RFC 3339 UTC"}, "purpose": {"type": "string"},
     }, ["company", "country", "signer_id", "signer_public_key", "currency", "max_per_payment", "payees",
         "valid_until"])},
    {"name": "attach_mandate",
     "description": "Build a payment under the loaded mandate, signed with your agent key. Submit the result "
                    "to the bank together with the mandate. Check it first with check_payment.",
     "inputSchema": _schema({
         "payment_id": {"type": "string", "description": "unique per payer, e.g. the invoice number"},
         "amount": {"type": "string", "description": "e.g. 18400.00"},
         "payee": {"type": "string", "description": "NAME=IBAN, exactly as on the invoice"},
         "reference": {"type": "string"}, "rail": {"type": "string"},
     }, ["payment_id", "amount", "payee"])},
    {"name": "check_payment",
     "description": "Ask the bank's checker whether a payment built by attach_mandate is covered by the mandate. "
                    "Returns allow, block or escalate with a reason. Never pay on block; on escalate, ask a "
                    "person. Note: the bank records this payment id; resubmit the same payment, not a new one.",
     "inputSchema": _schema({"payment": {"type": "object"}}, ["payment"])},
]


class MandateTools:
    def __init__(self, args: argparse.Namespace) -> None:
        self.mandate_path = args.mandate
        self.agent_sk = load_key(args.agent_key) if args.agent_key else None
        self.drafts = Path(args.drafts)
        self.bank_url = args.bank_url
        self.local: Bank | None = None
        if not self.bank_url and args.bank_key and args.authority:
            state = Path(args.state) if args.state else Path(args.home) / "mandate-state" / "state.json"
            self.local = Bank(bank_id="bank:local-demo", bank_key=args.bank_key, authority=args.authority,
                              state=state, revocations=args.revocation)

    def _mandate(self) -> dict:
        if not self.mandate_path:
            raise CliError("no mandate loaded: start the server with --mandate, or use request_mandate first")
        return read_json(self.mandate_path)

    def request_mandate(self, a: dict) -> dict:
        scope: dict[str, Any] = {"rails": ["sepa", "sepa_instant"], "currency": a["currency"],
                                 "max_per_payment": a["max_per_payment"],
                                 "payees": [parse_payee(p) for p in a["payees"]]}
        if a.get("max_per_month"):
            scope["max_per_period"] = {"amount": a["max_per_month"], "period": "P1M"}
        if a.get("purpose"):
            scope["purpose"] = a["purpose"]
        agent = {"id": "agent"}
        if self.agent_sk is not None:
            agent["public_key"] = m.public_key_of(self.agent_sk)
        try:
            draft = m.issue(id=f"m_draft_{len(list(self.drafts.glob('*.json'))) + 1}" if self.drafts.exists()
                            else "m_draft_1", company={"name": a["company"], "country": a["country"]}, agent=agent,
                            signer={"id": a["signer_id"], "public_key": a["signer_public_key"]}, scope=scope,
                            valid_until=a["valid_until"])
        except ValueError as exc:
            raise CliError(f"mandate rejected: {exc}") from exc
        self.drafts.mkdir(parents=True, exist_ok=True)
        path = self.drafts / f"{draft['id']}.json"
        path.write_text(json.dumps(draft, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return {"status": "awaiting_signature", "draft": str(path), "mandate_hash": m.mandate_hash(draft),
                "next": "A signatory reviews and signs it (bank app, passkey, or `gleipnir mandate sign`). "
                        "You cannot pay under it until then."}

    def attach_mandate(self, a: dict) -> dict:
        mandate = self._mandate()
        if self.agent_sk is None and "public_key" in mandate.get("agent", {}):
            raise CliError("the mandate requires an agent signature: start the server with --agent-key")
        try:
            p = m.attach(mandate, id=a["payment_id"], rail=a.get("rail") or mandate["scope"]["rails"][0],
                         amount=a["amount"], currency=mandate["scope"]["currency"], payee=parse_payee(a["payee"]),
                         reference=a.get("reference", ""), agent_sk=self.agent_sk)
        except (KeyError, IndexError, TypeError) as exc:
            raise CliError(f"cannot use the loaded mandate: {exc}") from exc
        problem = m.payment_problem(p)
        if problem:
            raise CliError(f"payment rejected: {problem}")
        return {"payment": p}

    def check_payment(self, a: dict) -> dict:
        mandate, payment = self._mandate(), a["payment"]
        if self.bank_url:
            body = json.dumps({"mandate": mandate, "payment": payment}).encode()
            req = urllib.request.Request(self.bank_url.rstrip("/") + "/check", data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - URL is operator config
                    decision = loads_strict(resp.read().decode("utf-8"), "bank response")
            except (urllib.error.URLError, TimeoutError, UnicodeDecodeError) as exc:
                raise CliError(f"bank checker unreachable: {exc}") from exc
        elif self.local is not None:
            decision = self.local.check(mandate, payment)
        else:
            raise CliError("no checker configured: start the server with --bank-url (or --bank-key and --authority)")
        reasons = decision.get("reasons") or []
        advice = {"allow": "Covered. Submit this exact payment with the mandate.",
                  "block": "Not covered. Do not pay. Tell the person why.",
                  "escalate": "Needs a person before it can be paid. Do not retry with a new id."}
        return {"outcome": decision.get("outcome"), "reasons": reasons,
                "advice": advice.get(decision.get("outcome"), "Unknown answer. Do not pay."), "decision": decision}


def _result(rid: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _error(rid: Any, code: int, text: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": text}}


def handle(tools: MandateTools, msg: Any) -> dict | None:
    """One JSON-RPC message in, one response out (None for notifications)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request")
    rid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
    if "id" not in msg:
        return None
    if method == "initialize":
        asked = params.get("protocolVersion") if isinstance(params, dict) else None
        return _result(rid, {"protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                             "capabilities": {"tools": {}},
                             "serverInfo": {"name": "gleipnir-mandate", "version": m.V},
                             "instructions": "Pay only under a mandate a person signed. Check every payment "
                                             "with check_payment first; never pay on block."})
    if method == "ping":
        return _result(rid, {})
    if method == "tools/list":
        return _result(rid, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name") if isinstance(params, dict) else None
        args = params.get("arguments") or {} if isinstance(params, dict) else {}
        fn = {"request_mandate": tools.request_mandate, "attach_mandate": tools.attach_mandate,
              "check_payment": tools.check_payment}.get(name)
        if fn is None:
            return _error(rid, -32602, f"unknown tool {name!r}")
        spec = next(t for t in TOOLS if t["name"] == name)["inputSchema"]
        missing = [k for k in spec["required"] if k not in args] if isinstance(args, dict) else spec["required"]
        if missing:
            return _result(rid, {"content": [{"type": "text", "text": f"missing arguments: {missing}"}],
                                 "isError": True})
        try:
            out = fn(args)
            return _result(rid, {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}],
                                 "structuredContent": out, "isError": False})
        except (CliError, ValueError, KeyError, TypeError, AttributeError) as exc:
            return _result(rid, {"content": [{"type": "text", "text": str(exc)}], "isError": True})
    return _error(rid, -32601, f"method not found: {method}")


def serve_stdio(tools: MandateTools, stdin: Any = None, stdout: Any = None) -> None:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = loads_strict(line, "message")
        except CliError as exc:
            resp: dict | None = _error(None, -32700, str(exc))
        else:
            resp = handle(tools, msg)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()


def cmd_mcp(args: argparse.Namespace) -> int:
    serve_stdio(MandateTools(args))
    return 0


def add_arguments(sub: argparse._SubParsersAction) -> None:
    s = sub.add_parser("serve", help="reference bank checker over HTTP: POST /check, GET /keys, POST /revoke")
    s.add_argument("--authority", required=True, help="KYB file (see `gleipnir mandate kyb`)")
    s.add_argument("--bank-key", required=True)
    s.add_argument("--bank-id", default="bank:local")
    s.add_argument("--revocation", action="append")
    s.add_argument("--state")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(mandate_fn=cmd_serve)

    c = sub.add_parser("mcp", help="MCP server (stdio) for an agent: request_mandate, attach_mandate, check_payment")
    c.add_argument("--mandate", help="the signed mandate the agent pays under")
    c.add_argument("--agent-key", help="the agent's private key PEM")
    c.add_argument("--bank-url", help="the bank's checker, e.g. http://127.0.0.1:8787")
    c.add_argument("--bank-key", help="demo only: run a local checker with this bank key")
    c.add_argument("--authority", help="demo only: KYB file for the local checker")
    c.add_argument("--revocation", action="append")
    c.add_argument("--state")
    c.add_argument("--drafts", default="mandate-drafts", help="where request_mandate writes drafts")
    c.set_defaults(mandate_fn=cmd_mcp)
