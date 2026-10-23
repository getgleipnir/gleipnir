"""``gleipnir mandate``: issue, sign and revoke agent mandates, attach payments, check them as a bank would.

    gleipnir mandate keygen -o berger.pem                       # company signatory
    gleipnir mandate keygen -o agent.pem                        # the AI agent
    gleipnir mandate keygen -o bank.pem                         # the bank (checker)
    gleipnir mandate issue --id m_ap --company "Nordhafen Logistik GmbH" --country AT \\
        --signer-id kberger@nordhafen.at --signer-name "K. Berger" --signer-key berger.pem \\
        --agent-id ap-agent --agent-key agent.pem --rail sepa --currency EUR \\
        --max-per-payment 25000.00 --max-per-period 100000.00/P1M \\
        --payee "Brenner Stahl AG=AT611904300234573201" -o mandate.json
    gleipnir mandate sign mandate.json --key berger.pem
    gleipnir mandate pay mandate.json --id p_1 --amount 18400.00 \\
        --payee "Brenner Stahl AG=AT611904300234573201" --agent-key agent.pem -o payment.json
    gleipnir mandate kyb mandate.json -o kyb.json               # dev only: trust the mandate's signer
    gleipnir mandate check mandate.json payment.json --authority kyb.json --bank-key bank.pem
    gleipnir mandate revoke mandate.json --key berger.pem --id r_1 -o revocation.json
    gleipnir mandate verify decision.json --bank-pub ed25519:...

``check`` prints the signed decision and exits 0 for allow, 1 for block, 3 for escalate (2 is a usage
error). Period totals and seen payment ids are kept in ``<home>/mandate-state`` so repeated runs
behave like one bank. That store is a single-process file for development, not a production ledger.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import sys
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


def read_json(path: str) -> Any:
    try:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_bad_constant)
    except json.JSONDecodeError as exc:
        raise CliError(f"{path} is not valid JSON: {exc}") from exc


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


def parse_payee(text: str) -> dict[str, Any]:
    name, sep, iban = text.rpartition("=")
    if not sep or not name or not iban:
        raise CliError(f"payee must be NAME=IBAN, got {text!r}")
    return {"name": name.strip(), "account": {"iban": iban.strip()}}


# ---------- file-backed state for repeated local runs ----------

class FileState:
    """Payment log and period ledger in one JSON file, locked for the length of a check."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {"payments": {}, "totals": {}}

    def __enter__(self) -> FileState:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a+", encoding="utf-8")  # noqa: SIM115
        fcntl.flock(self._fh, fcntl.LOCK_EX)
        self._fh.seek(0)
        text = self._fh.read()
        if text.strip():
            self.data = json.loads(text)
        return self

    def __exit__(self, *exc: object) -> None:
        self._fh.seek(0)
        self._fh.truncate()
        json.dump(self.data, self._fh, indent=1, sort_keys=True)
        self._fh.flush()
        fcntl.flock(self._fh, fcntl.LOCK_UN)
        self._fh.close()

    # PaymentLog
    def seen(self, payment_id: str, payment_hash: str) -> dict | str | None:
        entry = self.data["payments"].get(payment_id)
        if entry is None:
            self.data["payments"][payment_id] = {"hash": payment_hash, "decision": None}
            return None
        if entry["hash"] != payment_hash:
            return "duplicate"
        return entry["decision"] or "duplicate"

    def remember(self, payment_id: str, decision: dict) -> None:
        self.data["payments"][payment_id]["decision"] = decision

    # Ledger
    def reserve(self, mandate_id: str, period: str, amount: Decimal, limit: Decimal, at: Any) -> bool:
        key = f"{mandate_id}|{m.period_key(period, at)}"
        total = Decimal(self.data["totals"].get(key, "0")) + amount
        if total > limit:
            return False
        self.data["totals"][key] = str(total)
        return True


def load_authority(path: str) -> m.Authority:
    """A KYB file: {"source": "bank_kyb", "signers": [{"company", "signer", "keys", "may_sign"}]}."""
    doc = read_json(path)
    try:
        source = doc.get("source", "bank_kyb")
        table = {(s["company"], s["signer"]): m.AuthorityResult(source, tuple(s["keys"]), s.get("may_sign", True))
                 for s in doc["signers"]}
    except (AttributeError, KeyError, TypeError) as exc:
        raise CliError(f"{path}: expected {{'signers': [{{'company', 'signer', 'keys'}}]}}") from exc

    def authority(company: dict, signer_id: str) -> m.AuthorityResult | None:
        return table.get((company.get("name"), signer_id))

    return authority


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


def cmd_issue(args: argparse.Namespace) -> int:
    scope: dict[str, Any] = {"rails": args.rail or ["sepa"], "currency": args.currency,
                             "max_per_payment": args.max_per_payment, "payees": [parse_payee(p) for p in args.payee]}
    if args.max_per_period:
        amount, sep, period = args.max_per_period.partition("/")
        if not sep:
            raise CliError("--max-per-period must be AMOUNT/PERIOD, e.g. 100000.00/P1M")
        scope["max_per_period"] = {"amount": amount, "period": period}
    if args.purpose:
        scope["purpose"] = args.purpose
    signer = {"id": args.signer_id, "name": args.signer_name or args.signer_id,
              "public_key": public_key(args.signer_key)}
    if args.signer_role:
        signer["role"] = args.signer_role
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
        mandate = m.issue(id=args.id, company=company, agent=agent, signer=signer, scope=scope,
                          valid_until=valid_until, valid_from=args.valid_from, status_url=args.status_url)
    except ValueError as exc:
        raise CliError(f"mandate rejected: {exc}") from exc
    write_json(mandate, args.output)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    mandate = read_json(args.mandate)
    sk = load_key(args.key)
    if mandate.get("signer", {}).get("public_key") != m.public_key_of(sk):
        raise CliError("this key is not the signer key named in the mandate")
    unsigned = {k: v for k, v in mandate.items() if k != "sig"}
    problem = m.mandate_problem(unsigned)
    if problem:
        raise CliError(f"mandate rejected: {problem}")
    write_json(m.sign_mandate(unsigned, sk), args.output or args.mandate)
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    mandate = read_json(args.mandate)
    sk = load_key(args.key)
    signer = {"id": args.signer_id or mandate["signer"]["id"], "public_key": m.public_key_of(sk)}
    write_json(m.revoke(mandate, signer=signer, sk=sk, id=args.id, reason=args.reason or ""), args.output)
    return 0


def cmd_pay(args: argparse.Namespace) -> int:
    mandate = read_json(args.mandate)
    agent_sk = load_key(args.agent_key) if args.agent_key else None
    payment = m.attach(mandate, id=args.id, rail=args.rail or mandate["scope"]["rails"][0], amount=args.amount,
                       currency=args.currency or mandate["scope"]["currency"], payee=parse_payee(args.payee),
                       reference=args.reference or "", agent_sk=agent_sk)
    problem = m.payment_problem(payment)
    if problem:
        raise CliError(f"payment rejected: {problem}")
    write_json(payment, args.output)
    return 0


def cmd_kyb(args: argparse.Namespace) -> int:
    mandate = read_json(args.mandate)
    print("gleipnir: dev KYB file trusts the mandate's own signer key. A bank fills this from its KYB records.",
          file=sys.stderr)
    people = [mandate["signer"]] if "signer" in mandate else mandate["signers"]["of"]
    doc = {"source": "bank_kyb", "signers": [{"company": mandate["company"]["name"], "signer": p["id"],
                                              "keys": [p["public_key"]], "may_sign": True} for p in people]}
    write_json(doc, args.output)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    mandate, payment = read_json(args.mandate), read_json(args.payment)
    revocations = [read_json(r) for r in args.revocation or []]
    state_path = Path(args.state) if args.state else Path(args.home) / "mandate-state" / "state.json"
    with FileState(state_path) as state:
        checker = m.Checker(id=args.bank_id, sk=load_key(args.bank_key), authority=load_authority(args.authority),
                            ledger=state, payments=state, revocations=revocations)
        decision = checker.check(mandate, payment)
    write_json(decision, args.output)
    if args.output and args.output != "-":
        print(f"{decision['outcome']} {','.join(decision['reasons']) or '-'}", file=sys.stderr)
    return EXIT[decision["outcome"]]


def cmd_verify(args: argparse.Namespace) -> int:
    decision = read_json(args.decision)
    keys = [public_key(k) for k in args.bank_pub]
    ok = m.verify_decision(decision, keys)
    print(f"{'VALID' if ok else 'INVALID'} {decision.get('outcome', '?') if ok else ''}".strip())
    return 0 if ok else 1


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
    i.add_argument("--payee", action="append", required=True, help="NAME=IBAN (repeatable)")
    i.add_argument("--purpose")
    i.add_argument("--valid-from")
    i.add_argument("--valid-until", help="RFC 3339 UTC; default now + --days")
    i.add_argument("--days", type=int, default=30)
    i.add_argument("--status-url")
    i.add_argument("-o", "--output")
    i.set_defaults(mandate_fn=cmd_issue)

    s = sub.add_parser("sign", help="sign a mandate with the signatory's key (writes in place unless -o)")
    s.add_argument("mandate")
    s.add_argument("--key", required=True)
    s.add_argument("-o", "--output")
    s.set_defaults(mandate_fn=cmd_sign)

    r = sub.add_parser("revoke", help="write a signed revocation of a mandate")
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
    y.add_argument("--payee", required=True, help="NAME=IBAN")
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
    c.add_argument("--authority", required=True, help="KYB file: who may sign for which company, with which keys")
    c.add_argument("--bank-key", required=True, help="the bank's (checker's) private key PEM")
    c.add_argument("--bank-id", default="bank:local")
    c.add_argument("--revocation", action="append", help="revocation file (repeatable)")
    c.add_argument("--state", help="state file (default: <home>/mandate-state/state.json)")
    c.add_argument("-o", "--output")
    c.set_defaults(mandate_fn=cmd_check)

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
