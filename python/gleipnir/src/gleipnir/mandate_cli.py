"""``gleipnir mandate``: issue, sign and revoke agent mandates, attach payments, check them as a bank would.

    gleipnir mandate keygen -o berger.pem                       # company signatory
    gleipnir mandate keygen -o agent.pem                        # the AI agent
    gleipnir mandate keygen -o bank.pem                         # the bank (checker)
    gleipnir mandate issue --id m_ap --company "Nordhafen Logistik GmbH" --country AT \\
        --signer-id kberger@nordhafen.at --signer-name "K. Berger" --signer-key berger.pem \\
        --agent-id ap-agent --agent-key agent.pem --rail sepa --currency EUR \\
        --max-per-payment 25000.00 --max-per-period 100000.00/P1M \\
        --from-account AT483200000012345864 \\
        --payee "Brenner Stahl AG=AT611904300234573201" -o mandate.json
    gleipnir mandate sign mandate.json --key berger.pem
    gleipnir mandate pay mandate.json --id p_1 --amount 18400.00 \\
        --payee "Brenner Stahl AG=AT611904300234573201" --agent-key agent.pem -o payment.json
    gleipnir mandate kyb mandate.json -o kyb.json               # dev only: trust the mandate's signer
    gleipnir mandate check mandate.json payment.json --authority kyb.json --bank-key bank.pem
    gleipnir mandate override decision.json --key berger.pem --signer-id kberger@nordhafen.at -o override.json
    gleipnir mandate resolve mandate.json payment.json decision.json override.json --authority kyb.json \\
        --bank-key bank.pem
    gleipnir mandate revoke mandate.json --key berger.pem --id r_1 -o revocation.json
    gleipnir mandate verify decision.json --bank-pub ed25519:...

Accounts are an IBAN (spaces allowed), or SCHEME:FIELD/FIELD/... in the scheme's field order:
us_aba:ROUTING/ACCOUNT, uk_sort_code:SORT_CODE/ACCOUNT, ca_eft:INSTITUTION/TRANSIT/ACCOUNT,
au_bsb:BSB/ACCOUNT, in_ifsc:IFSC/ACCOUNT, mx_clabe:CLABE, swift:BIC/ACCOUNT.

``check`` prints the signed decision and exits 0 for allow, 1 for block, 3 for escalate (2 is a usage
error). Period totals and seen payment ids are kept in ``<home>/mandate-state`` so repeated runs
behave like one bank. That store is a single-process file for development, not a production ledger.
"""

from __future__ import annotations

import argparse
import fcntl
import http.client
import ipaddress
import json
import os
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gleipnir_verify import mandate as m

from .keys import write_private_file

EXIT = {"allow": 0, "block": 1, "escalate": 3}


class CliError(Exception):
    pass


# ---------- files ----------

def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise CliError(f"duplicate JSON key {k!r}")
        out[k] = v
    return out


def _bad_constant(name: str) -> Any:
    raise CliError(f"{name} is not allowed in JSON")


def loads_strict(text: str, what: str = "input") -> Any:
    """JSON with no duplicate keys and no NaN or Infinity (spec section 13)."""
    try:
        return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_bad_constant)
    except ValueError as exc:  # JSONDecodeError, and integers beyond Python's digit limit
        raise CliError(f"{what} is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        raise CliError(f"{what} is nested too deeply") from exc


def read_json(path: str) -> Any:
    try:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc.strerror}") from exc
    return loads_strict(text, path)


def write_json(obj: Any, path: str | None) -> None:
    text = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
    if path is None or path == "-":
        sys.stdout.write(text)
    else:
        Path(path).write_text(text, encoding="utf-8")


def load_key(path: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise CliError(f"cannot load private key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise CliError(f"{path} is not an Ed25519 private key")
    return key


def public_key(text: str) -> str:
    """A public key given as text (ed25519:...) or as the path of a private key PEM."""
    if Path(text).is_file():
        return m.public_key_of(load_key(text))
    return text


def parse_account(text: str) -> dict[str, str]:
    """An IBAN ("AT61 1904 ..."), or SCHEME:FIELD/FIELD in the scheme's field order ("us_aba:021000021/1234")."""
    scheme, sep, rest = text.strip().partition(":")
    if not sep:
        scheme, rest = "iban", text
    scheme = scheme.strip().lower()
    if scheme not in m.SCHEMES:
        raise CliError(f"unknown account scheme {scheme!r}: one of {', '.join(m.SCHEMES)}")
    names = list(m.SCHEMES[scheme])
    parts = rest.split("/")
    if len(parts) != len(names):
        raise CliError(f"a {scheme} account is {scheme}:{'/'.join(n.upper() for n in names)}, got {text!r}")
    try:
        return m.account(scheme, **dict(zip(names, parts, strict=True)))
    except ValueError as exc:
        raise CliError(f"bad account {text!r}: {exc}") from exc


def parse_payee(text: str) -> dict[str, Any]:
    name, sep, acc = text.rpartition("=")
    if not sep or not name or not acc:
        raise CliError(f"payee must be NAME=ACCOUNT, got {text!r}")
    return {"name": name.strip(), "account": parse_account(acc)}


# ---------- file-backed state for repeated local runs ----------

class FileState:
    """Payment log and period ledger in one JSON file, locked for the length of a check."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {"payments": {}, "totals": {}, "revocations": []}

    def __enter__(self) -> FileState:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # The lock lives in a file of its own, so the state file can be replaced atomically.
        self._lock = open(self.path.with_name(self.path.name + ".lock"), "a")  # noqa: SIM115
        fcntl.flock(self._lock, fcntl.LOCK_EX)
        try:
            text = self.path.read_text(encoding="utf-8") if self.path.exists() else ""
            if text.strip():
                self.data = json.loads(text)
                for k in ("payments", "totals", "revocations"):
                    self.data.setdefault(k, {} if k != "revocations" else [])
        except BaseException:
            self._unlock()
            raise
        return self

    def __exit__(self, exc_type: object, *exc: object) -> None:
        try:
            if exc_type is None:  # a failed block writes nothing: the previous state stays intact
                tmp = self.path.with_name(self.path.name + ".tmp")
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(self.data, fh, indent=1, sort_keys=True)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
        finally:
            self._unlock()

    def _unlock(self) -> None:
        fcntl.flock(self._lock, fcntl.LOCK_UN)
        self._lock.close()

    # PaymentLog (spec 7): keyed by payer and payment id
    def lookup(self, key: str, payment_hash: str) -> dict | None:
        entry = self.data["payments"].get(key)
        return entry["decision"] if entry and entry["hash"] == payment_hash else None

    def register(self, key: str, payment_hash: str) -> bool:
        if key in self.data["payments"]:
            return False
        self.data["payments"][key] = {"hash": payment_hash, "decision": None}
        return True

    def remember(self, key: str, decision: dict) -> None:
        self.data["payments"][key]["decision"] = decision

    def forget(self, key: str) -> None:
        self.data["payments"].pop(key, None)

    def take(self, key: str, payment_hash: str, decision_id: str) -> bool:
        entry = self.data["payments"].get(key)
        if not entry or entry["hash"] != payment_hash or not isinstance(entry["decision"], dict) \
                or entry["decision"].get("id") != decision_id:
            return False
        entry["decision"] = None
        return True

    # Ledger: keyed by "mandate:<hash>" or "delegation:<hash>" and the calendar period
    def reserve(self, key: str, period: str, amount: Decimal, limit: Decimal | None, at: Any) -> bool:
        k = f"{key}|{m.period_key(period, at)}"
        total = Decimal(self.data["totals"].get(k, "0")) + amount
        if limit is not None and total > limit:
            return False
        self.data["totals"][k] = str(total)
        return True

    def release(self, key: str, period: str, amount: Decimal, at: Any) -> None:
        k = f"{key}|{m.period_key(period, at)}"
        self.data["totals"][k] = str(max(Decimal(0), Decimal(self.data["totals"].get(k, "0")) - amount))

    # Revocations received by a running checker survive restarts
    @property
    def revocations(self) -> list[dict]:
        return self.data.setdefault("revocations", [])


def load_authority(path: str) -> m.Authority:
    """A KYB file: {"source": "bank_kyb", "signers": [{"company", "signer", "keys", "may_sign", "joint",
    "retired"}], "accounts": [{"company", "account"}]}."""
    doc = read_json(path)
    try:
        source = doc.get("source", "bank_kyb")
        table = {(s["company"], s["signer"]): m.AuthorityResult(source, tuple(s["keys"]), s.get("may_sign", True),
                                                                s.get("joint", 1), s.get("retired", {}))
                 for s in doc["signers"]}
    except (AttributeError, KeyError, TypeError) as exc:
        raise CliError(f"{path}: expected {{'signers': [{{'company', 'signer', 'keys'}}]}}") from exc

    def authority(company: dict, signer_id: str) -> m.AuthorityResult | None:
        return table.get((company.get("name"), signer_id))

    return authority


def load_holds(path: str) -> Any:
    """The accounts the bank holds, from the KYB file's "accounts": [{"company", "account", "customer"}]; the
    customer id (default: the company name) keys the payment log."""
    doc = read_json(path)
    try:
        held = {(a["company"], m.canonicalize(a["account"])): str(a.get("customer", a["company"]))
                for a in doc.get("accounts", [])}
    except (AttributeError, KeyError, TypeError) as exc:
        raise CliError(f"{path}: expected \"accounts\": [{{'company', 'account'}}]") from exc

    def holds(company: dict, account: dict) -> str | None:
        return held.get((company.get("name"), m.canonicalize(account)))

    return holds


MAX_STATUS = 64 * 1024
STATUS_DEADLINE = 5.0  # seconds for the whole fetch: connect, TLS, headers and body


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to one vetted IP address, with SNI and certificate checks for the URL's host name."""

    def __init__(self, host: str, ip: str, timeout: float, context: ssl.SSLContext, port: int = 443) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip
        self.raw: socket.socket | None = None

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # type: ignore[attr-defined]
        self.raw = self.sock  # kept: http.client drops self.sock once the response owns the connection


def make_status_fetcher(allow_hosts: list[str] | None = None, deadline: float = STATUS_DEADLINE, *,
                        context: ssl.SSLContext | None = None, _port: int = 443) -> Any:
    """status(url) for the Checker: GET over https on port 443 only, no redirects, one deadline for the whole
    fetch, 64 KiB, strict JSON.

    The URL comes from the company, so this is a request the bank makes on a customer's behalf: with
    ``allow_hosts`` only those hosts are fetched; without, the host is resolved once, every address must be
    public (not loopback, private, link-local or reserved), and the connection goes to that vetted address,
    so a second DNS answer cannot point the bank at its own network.
    """
    allowed = set(allow_hosts or [])
    context = context or ssl.create_default_context()

    def status(url: str) -> Any:
        end = time.monotonic() + deadline
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or not u.hostname or u.port not in (None, 443) or u.username or u.password:
            raise CliError("status_url must be https on port 443")
        if allowed and u.hostname not in allowed:
            raise CliError(f"status host {u.hostname} is not allowed")
        infos = socket.getaddrinfo(u.hostname, 443, proto=socket.IPPROTO_TCP)
        ips = [info[4][0] for info in infos]
        if not ips:
            raise CliError(f"status host {u.hostname} does not resolve")
        if not allowed and not all(ipaddress.ip_address(ip.split("%")[0]).is_global for ip in ips):
            raise CliError(f"status host {u.hostname} resolves to a non-public address")
        conn = _PinnedHTTPS(u.hostname, ips[0], deadline, context, _port)

        def kill() -> None:  # the deadline covers a server that drips bytes, not just one that stalls
            try:
                if conn.raw is not None:
                    conn.raw.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(deadline, kill)
        timer.daemon = True
        timer.start()
        try:
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            conn.request("GET", path, headers={"Accept": "application/json", "Host": u.hostname})
            resp = conn.getresponse()
            if resp.status != 200:  # redirects included: a status URL that redirects is not an answer
                raise CliError(f"status answered HTTP {resp.status}")
            body = b""
            while len(body) <= MAX_STATUS:
                if time.monotonic() >= end:
                    raise CliError("status fetch took too long")
                chunk = resp.read1(MAX_STATUS + 1 - len(body))
                if not chunk:
                    break
                body += chunk
            if time.monotonic() >= end:  # the watchdog cut the connection: what arrived is not an answer
                raise CliError("status fetch took too long")
        except (OSError, http.client.HTTPException) as exc:
            if time.monotonic() >= end:
                raise CliError("status fetch took too long") from exc
            raise
        finally:
            timer.cancel()
            conn.close()
        if len(body) > MAX_STATUS:
            raise CliError("status response too large")
        return loads_strict(body.decode("utf-8"), "status response")

    return status


# ---------- commands ----------

def cmd_keygen(args: argparse.Namespace) -> int:
    sk, pk = m.new_key()
    pem = sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())
    try:
        write_private_file(Path(args.output), pem)
    except FileExistsError as exc:
        raise CliError(f"{args.output} already exists") from exc
    print(pk)
    return 0


def build_scope(args: argparse.Namespace) -> dict[str, Any]:
    scope: dict[str, Any] = {"rails": args.rail or ["sepa"], "currency": args.currency,
                             "max_per_payment": args.max_per_payment}
    if args.payee:
        scope["payees"] = [parse_payee(p) for p in args.payee]
    if getattr(args, "from_account", None):
        scope["from_accounts"] = [parse_account(a) for a in args.from_account]
    if args.max_per_period:
        amount, sep, period = args.max_per_period.partition("/")
        if not sep:
            raise CliError("--max-per-period must be AMOUNT/PERIOD, e.g. 100000.00/P1M")
        scope["max_per_period"] = {"amount": amount, "period": period}
    if getattr(args, "purpose", None):
        scope["purpose"] = args.purpose
    return scope


def parse_person(text: str) -> dict[str, Any]:
    """ID=KEY, where KEY is a public key or a private key PEM path."""
    pid, sep, key = text.partition("=")
    if not sep or not pid or not key:
        raise CliError(f"expected ID=KEY, got {text!r}")
    return {"id": pid.strip(), "public_key": public_key(key.strip())}


def cmd_issue(args: argparse.Namespace) -> int:
    scope = build_scope(args)
    signer = {"id": args.signer_id, "name": args.signer_name or args.signer_id,
              "public_key": public_key(args.signer_key)}
    if args.signer_role:
        signer["role"] = args.signer_role
    signers = None
    if args.cosigner:
        of = [signer, *(parse_person(c) for c in args.cosigner)]
        signers = {"threshold": args.threshold or len(of), "of": of}
    elif args.threshold:
        raise CliError("--threshold needs at least one --cosigner")
    chain = [read_json(d) for d in args.delegation or []]
    agent = {"id": args.agent_id, "name": args.agent_name or args.agent_id}
    if args.agent_key:
        agent["public_key"] = public_key(args.agent_key)
    company = {"name": args.company}
    if args.country:
        company["country"] = args.country
    if args.lei:
        company["lei"] = args.lei
    valid_until = args.valid_until or m.fmt_ts(m.utcnow() + timedelta(days=args.days))
    try:
        mandate = m.issue(id=args.id, company=company, agent=agent, scope=scope, valid_until=valid_until,
                          signer=None if signers else signer, signers=signers, delegation=chain or None,
                          valid_from=args.valid_from, status_url=args.status_url)
    except ValueError as exc:
        raise CliError(f"mandate rejected: {exc}") from exc
    write_json(mandate, args.output)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign a single-signer mandate, or add this key's co-signature to a multi-signature one."""
    mandate = read_json(args.mandate)
    sk = load_key(args.key)
    pub = m.public_key_of(sk)
    problem = m.mandate_problem({k: v for k, v in mandate.items() if k not in ("sig", "sigs")})
    if problem:
        raise CliError(f"mandate rejected: {problem}")
    if "signers" in mandate:
        mine = [p for p in mandate["signers"]["of"] if p["public_key"] == pub]
        if not mine:
            raise CliError("this key is not one of the signers named in the mandate")
        signed = m.cosign(mandate, sk, mine[0]["id"])
        have, need = len(signed["sigs"]), mandate["signers"]["threshold"]
        print(f"gleipnir: signed as {mine[0]['id']} ({have} of {need} needed)", file=sys.stderr)
    else:
        if mandate["signer"]["public_key"] != pub:
            raise CliError("this key is not the signer key named in the mandate")
        signed = m.sign_mandate(mandate, sk)
    write_json(signed, args.output or args.mandate)
    return 0


def cmd_delegate(args: argparse.Namespace) -> int:
    sk = load_key(args.key)
    parent = read_json(args.parent) if args.parent else None
    company = {"name": args.company, **({"country": args.country} if args.country else {})}
    to = parse_person(args.to)
    if args.to_role:
        to["role"] = args.to_role
    valid_until = args.valid_until or m.fmt_ts(m.utcnow() + timedelta(days=args.days))
    try:
        d = m.delegate(id=args.id, company=company, from_={"id": args.from_id, "public_key": m.public_key_of(sk)},
                       to=to, scope=build_scope(args), valid_until=valid_until, sk=sk, parent=parent,
                       valid_from=args.valid_from)
    except ValueError as exc:
        raise CliError(f"delegation rejected: {exc}") from exc
    write_json(d, args.output)
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    mandate = read_json(args.mandate)
    sk = load_key(args.key)
    if args.signer_id:
        sid = args.signer_id
    elif "signer" in mandate:
        sid = mandate["signer"]["id"]
    elif "from" in mandate:
        sid = mandate["from"]["id"]
    else:
        raise CliError("--signer-id is required for this target")
    signer = {"id": sid, "public_key": m.public_key_of(sk)}
    write_json(m.revoke(mandate, signer=signer, sk=sk, id=args.id, reason=args.reason or ""), args.output)
    return 0


def cmd_pay(args: argparse.Namespace) -> int:
    mandate = read_json(args.mandate)
    agent_sk = load_key(args.agent_key) if args.agent_key else None
    try:
        payment = m.attach(mandate, id=args.id, rail=args.rail or mandate["scope"]["rails"][0], amount=args.amount,
                           currency=args.currency or mandate["scope"]["currency"], payee=parse_payee(args.payee),
                           from_account=parse_account(args.from_account) if args.from_account else None,
                           reference=args.reference or "", agent_sk=agent_sk)
    except ValueError as exc:
        raise CliError(str(exc)) from exc
    problem = m.payment_problem(payment)
    if problem:
        raise CliError(f"payment rejected: {problem}")
    write_json(payment, args.output)
    return 0


def cmd_kyb(args: argparse.Namespace) -> int:
    mandate = read_json(args.mandate)
    print("gleipnir: dev KYB file trusts the mandate's own signer key. A bank fills this from its KYB records.",
          file=sys.stderr)
    company = mandate["company"]["name"]
    chain = mandate.get("delegation", [])
    if chain:  # root may sign; everyone below is enrolled but signs only on the strength of the chain
        rows = [(chain[0]["from"], True)] + [(d["to"], False) for d in chain]
    else:
        rows = [(p, True) for p in ([mandate["signer"]] if "signer" in mandate else mandate["signers"]["of"])]
    doc = {"source": "bank_kyb", "signers": [{"company": company, "signer": p["id"], "keys": [p["public_key"]],
                                              "may_sign": may} for p, may in rows],
           "accounts": [{"company": company, "account": a} for a in mandate["scope"].get("from_accounts", [])]}
    write_json(doc, args.output)
    return 0


def checker_of(args: argparse.Namespace, state: FileState) -> m.Checker:
    revocations = [read_json(r) for r in args.revocation or []]
    return m.Checker(id=args.bank_id, sk=load_key(args.bank_key), authority=load_authority(args.authority),
                     holds=load_holds(args.authority), ledger=state, payments=state,
                     revocations=[*revocations, *state.revocations], webauthn=webauthn_of(args),
                     status=make_status_fetcher(args.status_host), officers=[public_key(k) for k in args.officer or []],
                     require_payees=args.require_payees)


def _decided(decision: dict, output: str | None) -> int:
    write_json(decision, output)
    if output and output != "-":
        print(f"{decision['outcome']} {','.join(decision['reasons']) or '-'}", file=sys.stderr)
    return EXIT[decision["outcome"]]


def state_of(args: argparse.Namespace) -> Path:
    return Path(args.state) if args.state else Path(args.home) / "mandate-state" / "state.json"


def cmd_check(args: argparse.Namespace) -> int:
    mandate, payment = read_json(args.mandate), read_json(args.payment)
    with FileState(state_of(args)) as state:
        decision = checker_of(args, state).check(mandate, payment)
    return _decided(decision, args.output)


def cmd_resolve(args: argparse.Namespace) -> int:
    """The bank applies a signed override to one of its escalate decisions."""
    mandate, payment = read_json(args.mandate), read_json(args.payment)
    decision, override = read_json(args.decision), read_json(args.override)
    with FileState(state_of(args)) as state:
        final = checker_of(args, state).resolve(mandate, payment, decision, override)
    return _decided(final, args.output)


def cmd_override(args: argparse.Namespace) -> int:
    """A person signs an override of an escalate decision; with --add, co-signs an existing override."""
    sk = load_key(args.key)
    me = {"id": args.signer_id, "public_key": m.public_key_of(sk)}
    if args.add:
        o = read_json(args.add)
    else:
        decision = read_json(args.decision)
        if not isinstance(decision, dict) or decision.get("outcome") != "escalate":
            raise CliError("only an escalate decision can be overridden")
        o = m.make_override(decision, outcome=args.outcome, id=args.id or "o_" + secrets.token_hex(8),
                            reason=args.reason or "")
    write_json(m.sign_override(o, sk, me), args.output)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """What a status_url serves: a signed, timed statement that this mandate is active or revoked."""
    mandate = read_json(args.mandate)
    sk = load_key(args.key)
    write_json(m.status_response(mandate, status=args.status, signer={"id": args.signer_id,
                                                                      "public_key": m.public_key_of(sk)}, sk=sk),
               args.output)
    return 0


def webauthn_of(args: argparse.Namespace) -> dict[str, Any]:
    """Passkey settings for mandates signed in a browser or bank app: --rp-id and --origin."""
    if not getattr(args, "rp_id", None):
        return {}
    return {"rp_id": args.rp_id, "origins": args.origin or [f"https://{args.rp_id}"]}


def cmd_verify(args: argparse.Namespace) -> int:
    decision = read_json(args.decision)
    keys = [public_key(k) for k in args.bank_pub]
    ok = m.verify_decision(decision, keys)
    print(f"{'VALID' if ok else 'INVALID'} {decision.get('outcome', '?') if ok else ''}".strip())
    return 0 if ok else 1


def add_checker_arguments(c: argparse.ArgumentParser) -> None:
    """The bank's checker settings, shared by check, resolve and serve."""
    c.add_argument("--authority", required=True, help="KYB file: who may sign, with which keys; accounts held")
    c.add_argument("--bank-key", required=True, help="the bank's (checker's) private key PEM")
    c.add_argument("--bank-id", default="bank:local")
    c.add_argument("--revocation", action="append", help="revocation file (repeatable)")
    c.add_argument("--state", help="state file (default: <home>/mandate-state/state.json)")
    c.add_argument("--rp-id", help="passkey relying party id, for mandates signed with a passkey")
    c.add_argument("--origin", action="append", help="allowed passkey origin (default https://<rp-id>)")
    c.add_argument("--officer", action="append", metavar="KEY", help="bank officer key allowed to sign overrides")
    c.add_argument("--require-payees", action="store_true", help="policy: block mandates without a payee list")
    c.add_argument("--status-host", action="append", metavar="HOST",
                   help="only fetch status_url on these hosts (default: any public host)")


def add_subcommands(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="mandate_cmd", required=True)

    k = sub.add_parser("keygen", help="create an Ed25519 key (PEM, mode 0600) and print its public key")
    k.add_argument("-o", "--output", required=True)
    k.set_defaults(mandate_fn=cmd_keygen)

    i = sub.add_parser("issue", help="write an unsigned mandate")
    i.add_argument("--id", required=True)
    i.add_argument("--company", required=True, help="legal name, as in the bank's KYB")
    i.add_argument("--country", required=True, help="ISO 3166 country code, e.g. AT")
    i.add_argument("--lei", help="optional LEI; extra proof, not required")
    i.add_argument("--signer-id", required=True)
    i.add_argument("--signer-name")
    i.add_argument("--signer-role")
    i.add_argument("--signer-key", required=True, help="signer public key, or the signer's private key PEM")
    i.add_argument("--agent-id", required=True)
    i.add_argument("--agent-name")
    i.add_argument("--agent-key", help="agent public key or PEM; then payments must carry the agent's signature")
    i.add_argument("--rail", action="append", choices=sorted(m.RAILS), help="allowed rail (repeatable; default sepa)")
    i.add_argument("--currency", required=True)
    i.add_argument("--max-per-payment", required=True, help="e.g. 25000.00")
    i.add_argument("--max-per-period", help="AMOUNT/PERIOD, period one of P1D, P7D, P1M")
    i.add_argument("--payee", action="append", help="NAME=ACCOUNT (repeatable); recommended")
    i.add_argument("--from-account", action="append", required=True, metavar="ACCOUNT",
                   help="the company's account the agent may pay from (repeatable)")
    i.add_argument("--purpose")
    i.add_argument("--cosigner", action="append", metavar="ID=KEY",
                   help="another signatory (repeatable): makes a multi-signature (joint signing) mandate")
    i.add_argument("--threshold", type=int, help="signatures needed (default: all signers)")
    i.add_argument("--delegation", action="append", metavar="FILE",
                   help="delegation link the signer's authority comes from (repeatable, root first)")
    i.add_argument("--valid-from")
    i.add_argument("--valid-until", help="RFC 3339 UTC; default now + --days")
    i.add_argument("--days", type=int, default=30)
    i.add_argument("--status-url")
    i.add_argument("-o", "--output")
    i.set_defaults(mandate_fn=cmd_issue)

    s = sub.add_parser("sign", help="sign a mandate, or co-sign a multi-signature one (writes in place unless -o)")
    s.add_argument("mandate")
    s.add_argument("--key", required=True)
    s.add_argument("-o", "--output")
    s.set_defaults(mandate_fn=cmd_sign)

    g = sub.add_parser("delegate", help="write a signed delegation: a bounded part of your authority to someone")
    g.add_argument("--id", required=True)
    g.add_argument("--company", required=True)
    g.add_argument("--country")
    g.add_argument("--from-id", required=True, help="you, as the bank knows you")
    g.add_argument("--key", required=True, help="your private key PEM")
    g.add_argument("--to", required=True, metavar="ID=KEY", help="the delegate and their enrolled key")
    g.add_argument("--to-role")
    g.add_argument("--parent", help="the delegation link your own authority comes from")
    g.add_argument("--rail", action="append", choices=sorted(m.RAILS))
    g.add_argument("--currency", required=True)
    g.add_argument("--max-per-payment", required=True)
    g.add_argument("--max-per-period")
    g.add_argument("--payee", action="append", help="NAME=ACCOUNT (repeatable); omit for any payee")
    g.add_argument("--from-account", action="append", metavar="ACCOUNT",
                   help="accounts the delegate may pay from (required with --max-per-period)")
    g.add_argument("--valid-from")
    g.add_argument("--valid-until")
    g.add_argument("--days", type=int, default=90)
    g.add_argument("-o", "--output")
    g.set_defaults(mandate_fn=cmd_delegate)

    r = sub.add_parser("revoke", help="write a signed revocation of a mandate or a delegation")
    r.add_argument("mandate")
    r.add_argument("--key", required=True, help="key of a signatory of the company")
    r.add_argument("--id", required=True)
    r.add_argument("--signer-id", help="default: the mandate's signer")
    r.add_argument("--reason")
    r.add_argument("-o", "--output")
    r.set_defaults(mandate_fn=cmd_revoke)

    y = sub.add_parser("pay", help="write a payment that relies on a mandate, signed by the agent")
    y.add_argument("mandate")
    y.add_argument("--id", required=True, help="payment id, unique per payer")
    y.add_argument("--amount", required=True)
    y.add_argument("--payee", required=True, help="NAME=ACCOUNT")
    y.add_argument("--from-account", metavar="ACCOUNT", help="default: the mandate's only from_account")
    y.add_argument("--rail", choices=sorted(m.RAILS), help="default: first rail on the mandate")
    y.add_argument("--currency", help="default: the mandate's currency")
    y.add_argument("--reference")
    y.add_argument("--agent-key")
    y.add_argument("-o", "--output")
    y.set_defaults(mandate_fn=cmd_pay)

    b = sub.add_parser("kyb", help="dev only: write a KYB file that trusts the mandate's signer")
    b.add_argument("mandate")
    b.add_argument("-o", "--output")
    b.set_defaults(mandate_fn=cmd_kyb)

    c = sub.add_parser("check", help="check a payment against its mandate as the bank; prints the signed decision")
    c.add_argument("mandate")
    c.add_argument("payment")
    add_checker_arguments(c)
    c.add_argument("-o", "--output")
    c.set_defaults(mandate_fn=cmd_check)

    rs = sub.add_parser("resolve", help="the bank applies a signed override to an escalate decision")
    for name in ("mandate", "payment", "decision", "override"):
        rs.add_argument(name)
    add_checker_arguments(rs)
    rs.add_argument("-o", "--output")
    rs.set_defaults(mandate_fn=cmd_resolve)

    o = sub.add_parser("override", help="sign an override of an escalate decision (allow or block)")
    o.add_argument("decision", nargs="?", help="the escalate decision (not needed with --add)")
    o.add_argument("--key", required=True)
    o.add_argument("--signer-id", required=True, help="you, as the bank knows you")
    o.add_argument("--outcome", choices=["allow", "block"], default="allow")
    o.add_argument("--id")
    o.add_argument("--reason")
    o.add_argument("--add", metavar="OVERRIDE", help="co-sign this existing override instead")
    o.add_argument("-o", "--output")
    o.set_defaults(mandate_fn=cmd_override)

    st = sub.add_parser("status", help="write the signed answer a status_url serves (active or revoked)")
    st.add_argument("mandate")
    st.add_argument("--key", required=True)
    st.add_argument("--signer-id", required=True)
    st.add_argument("--status", choices=["active", "revoked"], default="active")
    st.add_argument("-o", "--output")
    st.set_defaults(mandate_fn=cmd_status)

    from .mandate_service import add_arguments as add_service

    add_service(sub)

    v = sub.add_parser("verify", help="verify a decision against the bank's published keys")
    v.add_argument("decision")
    v.add_argument("--bank-pub", action="append", required=True, help="bank public key or PEM (repeatable)")
    v.set_defaults(mandate_fn=cmd_verify)


def run(args: argparse.Namespace) -> int:
    try:
        return args.mandate_fn(args)
    except CliError as exc:
        print(f"gleipnir mandate: {exc}", file=sys.stderr)
        return 2
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        print(f"gleipnir mandate: malformed input ({type(exc).__name__}: {exc})", file=sys.stderr)
        return 2
