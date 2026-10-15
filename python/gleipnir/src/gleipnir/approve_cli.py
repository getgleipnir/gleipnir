"""``gleipnir approve``: compute what an approver signs, sign it with an approver key, check a signature.

    gleipnir approve digest refund --system payments --args '{"order": "A1", "amount": 500}'
    gleipnir approve keygen --id ops:anna --name "Anna Berger" -o anna.pem     # on the approver's machine
    gleipnir approve sign sha256:... --key anna.pem --id ops:anna              # on the approver's machine
    gleipnir approve check sha256:... --signature '{"type": "key", ...}' [--approvers approvers.json]

``digest`` prints the action digest, the WebAuthn challenge and a link fragment for the passkey page
(site/approve/index.html). ``check`` accepts a signature (JSON text, ``@file`` or ``-`` for stdin) and
prints it on one line, ready for ``rec.approve(..., signature=...)``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from gleipnir_verify.approvals import approval_challenge, check_signature, load_approvers
from gleipnir_verify.crypto import b64u

from .approvals import ApproverKey, parse_signature


def _read_arg(text: str) -> str:
    if text == "-":
        return sys.stdin.read()
    if text.startswith("@"):
        return Path(text[1:]).read_text(encoding="utf-8")
    return text


def _digest_of(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    try:
        approval_challenge(args.digest)
    except ValueError as exc:
        parser.error(str(exc))
    return args.digest


def cmd_digest(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from .recorder import Redactor

    try:
        tool_args = json.loads(_read_arg(args.args))
    except (OSError, ValueError) as exc:
        parser.error(f"--args must be a JSON object: {exc}")
    if not isinstance(tool_args, dict):
        parser.error("--args must be a JSON object")
    key = None
    if args.redact:
        path = Path(args.home) / "keys" / "redaction-hmac.key"
        if not path.exists():
            parser.error(f"--redact needs the recorder's redaction key at {path}")
        key = path.read_bytes()
    redactor = Redactor(key)
    from gleipnir_verify.verifier import _has_dropped, action_digest

    from .util import to_jsonable

    bound = redactor.apply(to_jsonable(tool_args), redactor.rules(args.redact))
    if _has_dropped(bound):
        parser.error("an approved argument would be dropped by redaction")
    digest = action_digest(args.tool, args.system, bound)
    challenge = b64u(approval_challenge(digest))
    print(f"action digest:     {digest}")
    print(f"webauthn challenge: {challenge}")
    print(f"passkey page:      approve/index.html#digest={digest}&tool={args.tool}&system={args.system}")
    print("The approver signs this digest on their own device (gleipnir approve sign, or the passkey page);")
    print("pass the signature to rec.approve(..., signature=...).")
    return 0


def cmd_keygen(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    key = ApproverKey.generate(args.id, args.type)
    try:
        key.save(args.output)
    except FileExistsError:
        parser.error(f"{args.output} exists; not overwriting an approver key")
    print(f"wrote {args.output} (keep it on this device; the agent must never see it)")
    print("registry entry for the buyer's approvers file:")
    print(json.dumps(key.registry_entry(args.name, args.role), ensure_ascii=False))
    return 0


def cmd_sign(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    digest = _digest_of(args, parser)
    try:
        key = ApproverKey.load(args.key, args.id)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(f"cannot load approver key {args.key}: {exc}")
    print(json.dumps(key.sign(digest), separators=(",", ":")))
    return 0


def cmd_check(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    digest = _digest_of(args, parser)
    try:
        sig = parse_signature(_read_arg(args.signature))
    except (OSError, ValueError) as exc:
        parser.error(f"--signature: {exc}")
    approvers = None
    if args.approvers:
        try:
            approvers = load_approvers(json.loads(Path(args.approvers).read_bytes()))
        except (OSError, ValueError) as exc:
            parser.error(f"--approvers: {exc}")
    findings = check_signature({"action_digest": digest, "signature": sig}, approvers, args.webauthn_origin, False)
    ok = not any(level == "error" for level, _, _ in findings)
    for level, code, message in findings:
        print(f"[{'FAIL' if level == 'error' else level.upper()}] {code}: {message}", file=sys.stderr)
    if not ok:
        return 1
    print(json.dumps(sig, separators=(",", ":"), ensure_ascii=False))
    return 0


def add_subcommands(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="approve_cmd", required=True)
    d = sub.add_parser("digest", help="print the action digest an approver signs")
    d.add_argument("tool")
    d.add_argument("--system", required=True)
    d.add_argument("--args", required=True, help="tool arguments as JSON (or @file, or - for stdin)")
    d.add_argument("--redact", action="append", help="argument redacted with hmac by the tool (repeatable)")
    d.set_defaults(approve_fn=cmd_digest)
    k = sub.add_parser("keygen", help="create an approver key and print its registry entry")
    k.add_argument("--id", required=True, help="approver id, e.g. ops:anna")
    k.add_argument("--name", required=True)
    k.add_argument("--role", action="append")
    k.add_argument("--type", choices=["ed25519", "ecdsa-p256"], default="ed25519")
    k.add_argument("-o", "--output", required=True)
    k.set_defaults(approve_fn=cmd_keygen)
    s = sub.add_parser("sign", help="sign an approval with an approver key")
    s.add_argument("digest")
    s.add_argument("--key", required=True, help="approver private key (PEM)")
    s.add_argument("--id", required=True, help="approver id, as in the buyer's registry")
    s.set_defaults(approve_fn=cmd_sign)
    c = sub.add_parser("check", help="check an approver signature and print it for rec.approve")
    c.add_argument("digest")
    c.add_argument("--signature", required=True, help="signature JSON (or @file, or - for stdin)")
    c.add_argument("--approvers", help="buyer's approver registry to check the key against")
    c.add_argument("--webauthn-origin", action="append", help="allowed passkey origin (repeatable)")
    c.set_defaults(approve_fn=cmd_check)


def run(args: argparse.Namespace, parser: Any) -> int:
    return args.approve_fn(args, parser)
