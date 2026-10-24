"""A reference bank checker over HTTP, and an MCP server for agents that pay under a mandate.

``gleipnir mandate serve`` (bank side, reference only):

    POST /check    {"mandate": {...}, "payment": {...}}  -> the signed decision (200), or {"error": ...} (400)
    POST /resolve  {"mandate", "payment", "decision", "override"} -> the decision after a signed override
    GET  /keys     -> {"checker": id, "keys": [public key]}: what companies and auditors verify decisions with
    GET  /.well-known/gleipnir-checker.json -> the bank's key set with validity windows (spec 10.1)
    GET  /revocations -> a signed list of the revocations this checker holds, current for an hour (spec 9.2)
    POST /revoke   {"revocation": {...}, "mandate": {...}}: stored only if it counts for that mandate now (signed,
                   aimed at it or a link of its chain, by someone who may revoke it); verified again per payment

Binds to 127.0.0.1 by default. Bodies are strict JSON (no duplicate keys, no NaN), at most 1 MiB. There is
no authentication: put it behind the bank's own API gateway. State (period ledger, payment log) is the dev
file store from ``gleipnir mandate check``.

``gleipnir mandate mcp`` (agent side): an MCP server (stdio, or Streamable HTTP with ``--http PORT``) with four
tools and the current mandate as a resource (``gleipnir://mandate/current``).

- ``mandate_scope``: what the agent may pay under the loaded mandate.
- ``request_mandate``: draft an unsigned mandate for a person to review and sign in their bank's app (or with
  ``gleipnir mandate sign``). The agent never signs a mandate itself.
- ``attach_mandate``: build a payment under the loaded mandate, from one of its accounts, signed with the agent's key.
- ``check_payment``: ask the bank's checker (``--bank-url``) whether a payment would pass, before submitting it;
  with ``--bank-key`` and ``--authority`` instead, a local demo checker answers.
"""

from __future__ import annotations

import argparse
import hmac
import json
import secrets
import sys
import threading
import urllib.error
import urllib.request
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from gleipnir_verify import mandate as m

from .mandate_cli import (
    CliError,
    FileState,
    load_authority,
    load_holds,
    load_key,
    loads_strict,
    make_status_fetcher,
    parse_account,
    parse_payee,
    public_key,
    read_json,
    webauthn_of,
)

MAX_BODY = 1 << 20
MAX_REVOCATIONS = 10_000
MAX_REVOCATION = 4096
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")


# ---------- the bank side ----------

class Bank:
    """A Checker wired to the dev file state, safe to call from several HTTP threads."""

    def __init__(self, *, bank_id: str, bank_key: str, authority: str, state: Path,
                 revocations: list[str] | None = None, webauthn: dict | None = None, officers: list[str] | None = None,
                 require_payees: bool = False, status_hosts: list[str] | None = None) -> None:
        self.webauthn = webauthn or {}
        self.id = bank_id
        self.sk = load_key(bank_key)
        self.public_key = m.public_key_of(self.sk)
        self.authority = load_authority(authority)
        self.holds = load_holds(authority)
        self.officers = officers or []
        self.require_payees = require_payees
        self.status = make_status_fetcher(status_hosts)
        self.state = state
        self.revocations: list[dict] = [read_json(r) for r in revocations or []]
        self.keyset_doc: dict | None = None
        self._lock = threading.Lock()

    def _checker(self, st: FileState | None, status: Any = None) -> m.Checker:
        return m.Checker(id=self.id, sk=self.sk, authority=self.authority, holds=self.holds, ledger=st,
                         payments=st if st is not None else m.InMemoryPaymentLog(),
                         revocations=[*self.revocations, *(st.revocations if st is not None else [])],
                         webauthn=self.webauthn, status=status, officers=self.officers,
                         require_payees=self.require_payees)

    def _prefetch(self, mandate: Any) -> Any:
        """Fetch the mandate's status before taking any lock, so a slow status server delays only its own
        payment. The checker then reads the answer (or the failure) from here."""
        url = mandate.get("status_url") if isinstance(mandate, dict) else None
        if not isinstance(url, str):
            return None
        try:
            answer: Any = self.status(url)
        except Exception as exc:  # noqa: BLE001 - the checker turns any failure into status_unavailable
            answer = exc

        def status(_url: str) -> Any:
            if isinstance(answer, Exception):
                raise answer
            return answer
        return status

    def check(self, mandate: Any, payment: Any) -> dict[str, Any]:
        status = self._prefetch(mandate)
        with self._lock, FileState(self.state) as st:
            return self._checker(st, status).check(mandate, payment)

    def resolve(self, mandate: Any, payment: Any, decision: Any, override: Any) -> dict[str, Any]:
        status = self._prefetch(mandate)
        with self._lock, FileState(self.state) as st:
            return self._checker(st, status).resolve(mandate, payment, decision, override)

    def keyset(self) -> dict[str, Any]:
        """The published key set: the configured one (with key history), or just the current key."""
        if self.keyset_doc is not None:
            return self.keyset_doc
        return m.keyset(self.id, [{"public_key": self.public_key}])

    def revocation_list(self) -> dict[str, Any]:
        with self._lock, FileState(self.state) as st:
            revs = [*self.revocations, *st.revocations]
        return m.revocation_list(revs, issuer=self.id, sk=self.sk,
                                 next_update=m.fmt_ts(m.utcnow() + timedelta(hours=1)))

    def add_revocation(self, r: Any, mandate: Any) -> None:
        """Store a revocation that counts for this mandate now; the checker verifies it again on every payment.
        Junk, and revocations by people who may not revoke, are refused, so the store holds only real ones."""
        problem = m.revocation_problem(r)
        if problem:
            raise CliError(f"revocation rejected: {problem}")
        if len(m.canonicalize(r)) > MAX_REVOCATION:
            raise CliError(f"revocation rejected: larger than {MAX_REVOCATION} bytes")
        if not self._checker(None).revocation_counts(mandate, r):
            raise CliError("revocation rejected: not a valid revocation of this mandate by someone who may revoke it")
        with self._lock, FileState(self.state) as st:
            if r in st.revocations:
                return
            if len(st.revocations) >= MAX_REVOCATIONS:
                raise CliError("revocation store is full: this reference server keeps at most "
                               f"{MAX_REVOCATIONS}; use your own revocation store")
            st.revocations.append(r)


def make_handler(bank: Bank, allow_origins: frozenset[str] = frozenset()) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"gleipnir-checker/{m.V}"

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
            elif self.path == "/.well-known/gleipnir-checker.json":
                self._send(200, bank.keyset())
            elif self.path == "/revocations":
                self._send(200, bank.revocation_list())
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                self._send(415, {"error": "Content-Type must be application/json"})
                return
            origin = self.headers.get("Origin")
            if origin is not None and origin not in allow_origins:
                self._send(403, {"error": "origin not allowed"})
                return
            try:
                if self.path == "/check":
                    body = self._body()
                    if not isinstance(body, dict) or set(body) != {"mandate", "payment"}:
                        raise CliError('expected {"mandate": ..., "payment": ...}')
                    self._send(200, bank.check(body["mandate"], body["payment"]))
                elif self.path == "/resolve":
                    body = self._body()
                    if not isinstance(body, dict) or set(body) != {"mandate", "payment", "decision", "override"}:
                        raise CliError('expected {"mandate", "payment", "decision", "override"}')
                    self._send(200, bank.resolve(body["mandate"], body["payment"], body["decision"],
                                                 body["override"]))
                elif self.path == "/revoke":
                    body = self._body()
                    if not isinstance(body, dict) or set(body) != {"revocation", "mandate"}:
                        raise CliError('expected {"revocation": ..., "mandate": ...}')
                    bank.add_revocation(body["revocation"], body["mandate"])
                    self._send(200, {"ok": True})
                else:
                    self._send(404, {"error": "not found"})
            except CliError as exc:
                self._send(400, {"error": str(exc)})
            except Exception:  # noqa: BLE001 - never drop the connection without an answer
                self._send(500, {"error": "internal error"})

    return Handler


def make_server(bank: Bank, host: str = "127.0.0.1", port: int = 8787,
                allow_origins: list[str] | None = None) -> ThreadingHTTPServer:
    """Browsers may only call it from ``allow_origins``; servers (no Origin header) always can."""
    return ThreadingHTTPServer((host, port), make_handler(bank, frozenset(allow_origins or [])))


def cmd_serve(args: argparse.Namespace) -> int:
    state = Path(args.state) if args.state else Path(args.home) / "mandate-state" / "state.json"
    bank = Bank(bank_id=args.bank_id, bank_key=args.bank_key, authority=args.authority, state=state,
                revocations=args.revocation, webauthn=webauthn_of(args),
                officers=[public_key(k) for k in args.officer or []], require_payees=args.require_payees,
                status_hosts=args.status_host)
    if args.keyset:
        ks = read_json(args.keyset)
        if m.keyset_problem(ks) or not any(k["public_key"] == bank.public_key for k in ks["keys"]):
            raise CliError(f"{args.keyset}: not a key set that lists this bank key")
        bank.keyset_doc = ks
    srv = make_server(bank, args.host, args.port, args.allow_origin)
    print(f"gleipnir: checker {bank.id} on http://{args.host}:{srv.server_address[1]} "
          "(POST /check, POST /resolve, GET /keys, POST /revoke). Reference server, no auth: keep it behind your "
          "gateway.",
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
    {"name": "mandate_scope",
     "description": "What you may pay under the loaded mandate: company, payees (name and account), limits, rails, "
                    "validity, who signed. Read this before paying; anything outside it will be refused.",
     "inputSchema": _schema({}, []),
     "annotations": {"title": "What may I pay?", "readOnlyHint": True, "openWorldHint": False}},
    {"name": "request_mandate",
     "description": "Draft an unsigned mandate for a company signatory to review and sign in their bank's app. "
                    "You cannot sign it yourself; until a person signs, you cannot pay under it.",
     "inputSchema": _schema({
         "company": {"type": "string"}, "country": {"type": "string", "description": "ISO 3166 code"},
         "signer_id": {"type": "string", "description": "the signatory who will sign, as the bank knows them"},
         "signer_public_key": {"type": "string"},
         "currency": {"type": "string"}, "max_per_payment": {"type": "string", "description": "e.g. 25000.00"},
         "max_per_month": {"type": "string"},
         "payees": {"type": "array", "items": {"type": "string", "description": "NAME=ACCOUNT"}},
         "from_accounts": {"type": "array", "items": {"type": "string"},
                           "description": "the company's accounts to pay from: IBAN, or SCHEME:FIELD/FIELD"},
         "valid_until": {"type": "string", "description": "RFC 3339 UTC"}, "purpose": {"type": "string"},
     }, ["company", "country", "signer_id", "signer_public_key", "currency", "max_per_payment", "payees",
         "from_accounts", "valid_until"]),
     "annotations": {"title": "Ask a person for a mandate", "readOnlyHint": False, "destructiveHint": False,
                     "openWorldHint": False}},
    {"name": "attach_mandate",
     "description": "Build a payment under the loaded mandate, signed with your agent key. Submit the result "
                    "to the bank together with the mandate. Check it first with check_payment.",
     "inputSchema": _schema({
         "payment_id": {"type": "string", "description": "unique per payer, e.g. the invoice number"},
         "amount": {"type": "string", "description": "e.g. 18400.00"},
         "payee": {"type": "string", "description": "NAME=ACCOUNT exactly as on the invoice: an IBAN, or "
                                                    "SCHEME:FIELD/FIELD (us_aba:ROUTING/ACCOUNT, "
                                                    "uk_sort_code:SORT_CODE/ACCOUNT, ...)"},
         "from_account": {"type": "string", "description": "which mandate account to pay from (default: the "
                                                           "only one)"},
         "reference": {"type": "string"}, "rail": {"type": "string"},
     }, ["payment_id", "amount", "payee"]),
     "annotations": {"title": "Prepare a payment", "readOnlyHint": True, "openWorldHint": False}},
    {"name": "check_payment",
     "description": "Submit a payment built by attach_mandate to the bank's check. This is the real check, not a "
                    "dry run: an allowed payment is recorded under its id and counts against the limits, so "
                    "call it only for a payment you intend to make. Returns allow, block or escalate with a "
                    "reason. Never pay on block; on escalate, ask a person (they sign an override at the bank). "
                    "To retry, resubmit the same payment; after a block you may correct it and reuse the id.",
     "inputSchema": _schema({"payment": {"type": "object"}}, ["payment"]),
     "annotations": {"title": "Ask the bank", "readOnlyHint": False, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": True}},
]

RESOURCE_URI = "gleipnir://mandate/current"
_TYPES = {"string": str, "object": dict, "array": list}


def arguments_problem(spec: dict, args: Any) -> str | None:
    """Check tool arguments against the tool's schema: required keys, no extra keys, types."""
    if not isinstance(args, dict):
        return "arguments must be an object"
    missing = [k for k in spec["required"] if k not in args]
    if missing:
        return f"missing arguments: {missing}"
    extra = sorted(set(args) - set(spec["properties"]))
    if extra:
        return f"unknown arguments: {extra}"
    for k, v in args.items():
        want = spec["properties"][k]
        if not isinstance(v, _TYPES[want["type"]]):
            return f"{k} must be a {want['type']}"
        if want["type"] == "array" and not all(isinstance(x, str) for x in v):
            return f"{k} must be a list of strings"
        if want["type"] == "string" and len(v) > 2000:
            return f"{k} is too long"
    return None


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
                              state=state, revocations=args.revocation, webauthn=webauthn_of(args))

    def _mandate(self) -> dict:
        if not self.mandate_path:
            raise CliError("no mandate loaded: start the server with --mandate, or use request_mandate first")
        return read_json(self.mandate_path)

    def mandate_scope(self, a: dict) -> dict:
        md = self._mandate()
        sc = md.get("scope", {})
        signed_by = [md["signer"]["id"]] if "signer" in md else [s.get("signer") for s in md.get("sigs", [])]
        return {"mandate": md.get("id"), "company": md.get("company", {}).get("name"),
                "agent": md.get("agent", {}).get("id"), "currency": sc.get("currency"),
                "max_per_payment": sc.get("max_per_payment"), "max_per_period": sc.get("max_per_period"),
                "rails": sc.get("rails", "any"), "payees": sc.get("payees", "any payee"),
                "from_accounts": sc.get("from_accounts"),
                "valid_from": md.get("valid_from"), "valid_until": md.get("valid_until"), "signed_by": signed_by,
                "delegation": [f"{d['from']['id']} -> {d['to']['id']}" for d in md.get("delegation", [])],
                "problem": m.mandate_problem(md)}

    def request_mandate(self, a: dict) -> dict:
        scope: dict[str, Any] = {"rails": ["sepa", "sepa_instant"], "currency": a["currency"],
                                 "max_per_payment": a["max_per_payment"],
                                 "payees": [parse_payee(p) for p in a["payees"]],
                                 "from_accounts": [parse_account(x) for x in a["from_accounts"]]}
        if a.get("max_per_month"):
            scope["max_per_period"] = {"amount": a["max_per_month"], "period": "P1M"}
        if a.get("purpose"):
            scope["purpose"] = a["purpose"]
        agent = {"id": "agent"}
        if self.agent_sk is not None:
            agent["public_key"] = m.public_key_of(self.agent_sk)
        try:
            draft = m.issue(id="m_" + secrets.token_hex(8), company={"name": a["company"], "country": a["country"]},
                            agent=agent,
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
            rails = mandate["scope"].get("rails") or ["sepa"]
            p = m.attach(mandate, id=a["payment_id"], rail=a.get("rail") or rails[0],
                         amount=a["amount"], currency=mandate["scope"]["currency"], payee=parse_payee(a["payee"]),
                         from_account=parse_account(a["from_account"]) if a.get("from_account") else None,
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
    """One JSON-RPC message in, one response out (None for notifications). Never raises."""
    try:
        return _handle(tools, msg)
    except Exception as exc:  # noqa: BLE001 - a hostile message must not take the server down
        rid = msg.get("id") if isinstance(msg, dict) and isinstance(msg.get("id"), (str, int)) else None
        return _error(rid, -32603, f"internal error: {type(exc).__name__}")


def _handle(tools: MandateTools, msg: Any) -> dict | None:
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request")
    rid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
    if "id" not in msg:
        return None
    if method == "initialize":
        asked = params.get("protocolVersion") if isinstance(params, dict) else None
        return _result(rid, {"protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                             "capabilities": {"tools": {}, "resources": {}},
                             "serverInfo": {"name": "gleipnir-mandate", "version": m.V},
                             "instructions": "Pay only under a mandate a person signed. Check every payment "
                                             "with check_payment first; never pay on block."})
    if method == "ping":
        return _result(rid, {})
    if method == "tools/list":
        return _result(rid, {"tools": TOOLS})
    if method == "resources/list":
        return _result(rid, {"resources": [{"uri": RESOURCE_URI, "name": "Current mandate",
                                            "description": "The signed mandate this agent pays under",
                                            "mimeType": "application/json"}] if tools.mandate_path else []})
    if method == "resources/read":
        if not isinstance(params, dict) or params.get("uri") != RESOURCE_URI or not tools.mandate_path:
            return _error(rid, -32002, "resource not found")
        try:
            text = json.dumps(tools._mandate(), indent=2, ensure_ascii=False)
        except CliError as exc:
            return _error(rid, -32603, str(exc))
        return _result(rid, {"contents": [{"uri": RESOURCE_URI, "mimeType": "application/json", "text": text}]})
    if method == "tools/call":
        name = params.get("name") if isinstance(params, dict) else None
        args = params.get("arguments") if isinstance(params, dict) else None
        if args is None:
            args = {}
        if not isinstance(name, str):
            return _error(rid, -32602, "tool name must be a string")
        fn = {"mandate_scope": tools.mandate_scope, "request_mandate": tools.request_mandate,
              "attach_mandate": tools.attach_mandate, "check_payment": tools.check_payment}.get(name)
        if fn is None:
            return _error(rid, -32602, f"unknown tool {name!r}")
        bad = arguments_problem(next(t for t in TOOLS if t["name"] == name)["inputSchema"], args)
        if bad:
            return _result(rid, {"content": [{"type": "text", "text": bad}], "isError": True})
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


def make_mcp_http(tools: MandateTools, host: str = "127.0.0.1", port: int = 8788, token: str | None = None,
                  origins: list[str] | None = None) -> ThreadingHTTPServer:
    """MCP Streamable HTTP, JSON responses only (no server-initiated streams): POST /mcp.

    Rejects browser requests from other origins (DNS-rebinding protection) and, with ``token``, requests
    without ``Authorization: Bearer <token>``.
    """
    allowed = set(origins or []) | {f"http://{host}:{port}", f"http://localhost:{port}", f"http://127.0.0.1:{port}"}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = f"gleipnir-mandate-mcp/{m.V}"

        def log_message(self, fmt: str, *args: Any) -> None:
            pass

        def _send(self, code: int, obj: Any = None) -> None:
            body = b"" if obj is None else json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            if obj is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _guard(self) -> bool:
            origin = self.headers.get("Origin")
            if origin is not None and origin not in allowed:
                self._send(403, {"error": "origin not allowed"})
                return False
            if token is not None:
                got = self.headers.get("Authorization", "")
                if not hmac.compare_digest(got.encode(), f"Bearer {token}".encode()):
                    self._send(401, {"error": "missing or wrong bearer token"})
                    return False
            if self.path != "/mcp":
                self._send(404, {"error": "not found"})
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802 - no server-initiated stream
            if self._guard():
                self._send(405, {"error": "this server only answers POST /mcp"})

        def do_DELETE(self) -> None:  # noqa: N802
            if self._guard():
                self._send(405, {"error": "no sessions"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._guard():
                return
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if n <= 0 or n > MAX_BODY:
                self._send(400, _error(None, -32600, f"body must be 1 byte to {MAX_BODY} bytes"))
                return
            try:
                msg = loads_strict(self.rfile.read(n).decode("utf-8"), "message")
            except (CliError, UnicodeDecodeError) as exc:
                self._send(400, _error(None, -32700, str(exc)))
                return
            if isinstance(msg, list):
                self._send(400, _error(None, -32600, "batches are not supported"))
                return
            with lock:
                resp = handle(tools, msg)
            if resp is None:
                self._send(202)
            else:
                self._send(200, resp)

    return ThreadingHTTPServer((host, port), Handler)


def cmd_mcp(args: argparse.Namespace) -> int:
    tools = MandateTools(args)
    if args.http is None:
        serve_stdio(tools)
        return 0
    token = args.token or (secrets.token_urlsafe(24) if args.host not in ("127.0.0.1", "localhost") else None)
    srv = make_mcp_http(tools, args.host, args.http, token, args.allow_origin)
    print(f"gleipnir: MCP on http://{args.host}:{srv.server_address[1]}/mcp"
          + (f" (Authorization: Bearer {token})" if token else ""), file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def add_arguments(sub: argparse._SubParsersAction) -> None:
    from .mandate_cli import add_checker_arguments

    s = sub.add_parser("serve", help="reference bank checker over HTTP: POST /check, /resolve, /revoke; GET /keys")
    add_checker_arguments(s)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--allow-origin", action="append", help="browser origin allowed to call the checker")
    s.add_argument("--keyset", help="key set to publish (with earlier keys); default: just this key")
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
    c.add_argument("--http", type=int, metavar="PORT", help="serve MCP over HTTP on this port instead of stdio")
    c.add_argument("--host", default="127.0.0.1")
    c.add_argument("--token", help="bearer token for HTTP (generated when binding beyond localhost)")
    c.add_argument("--allow-origin", action="append", help="browser origin allowed to call the HTTP server")
    c.add_argument("--rp-id", help="passkey relying party id (local demo checker)")
    c.add_argument("--origin", action="append", help="allowed passkey origin (local demo checker)")
    c.set_defaults(mandate_fn=cmd_mcp)
