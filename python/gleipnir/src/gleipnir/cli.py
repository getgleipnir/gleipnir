"""gleipnir command line: init, status, export, check, pack."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from gleipnir_verify.canon import record_hash
from gleipnir_verify.verifier import parse_time

from . import __version__
from .anchor import LocalFileAnchor
from .export import export_bundle
from .keys import load_or_create_signer
from .store import JsonlStore


def _store(args: argparse.Namespace) -> JsonlStore:
    return JsonlStore(Path(args.home) / "chains" / args.chain, fsync=False)


def cmd_init(args: argparse.Namespace) -> int:
    signer = load_or_create_signer(Path(args.home))
    print(f"key id:     {signer.key_id}")
    print(f"public key: {signer.public_key}")
    print("Publish the key id where buyers can see it; they pass it to gleipnir-verify --expect-key.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    records = _store(args).read_all()
    if not records:
        print(f"no records in {Path(args.home) / 'chains' / args.chain}")
        return 1
    segs = [r for r in records if r.get("kind") == "segment"]
    anchored = {r["anchor"]["segment_seq"] for r in records if r.get("kind") == "anchor"}
    actions = sum(1 for r in records if r.get("kind") == "action")
    print(f"chain:     {records[0]['chain']}")
    print(f"key:       {records[0]['public_key']['id']}")
    print(f"records:   {len(records)} ({actions} actions)")
    print(f"segments:  {len(segs)} closed, {sum(1 for s in segs if s['seq'] in anchored)} anchored")
    print(f"head:      {records[-1]['seq']}:{record_hash(records[-1])}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    records = _store(args).read_all()
    if not records:
        print("no records to export", file=sys.stderr)
        return 1
    since = parse_time(args.since) if args.since else None
    until = parse_time(args.until) if args.until else None
    log = Path(args.home) / "anchors" / "local-anchor-log.jsonl"
    out = export_bundle(records, args.output, since=since, until=until,
                        local_anchor_log=log if log.exists() else None)
    print(f"wrote {out}")
    print(f"verify with: pipx run gleipnir-verify {out.name} --expect-key {records[0]['public_key']['id']}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    import json as _json

    from .check import capabilities_from_records, evaluate, load_checklist, render_text

    records = _store(args).read_all()
    caps, why = capabilities_from_records(records)
    results = evaluate(load_checklist(args.checklist), caps)
    if args.json:
        print(_json.dumps({"capabilities": sorted(caps), "evidence": why,
                           "items": [r.__dict__ for r in results]}, indent=2))
    else:
        print(render_text(results, why))
    return 0


def cmd_pack(args: argparse.Namespace) -> int:
    from .pack import build_pack

    records = _store(args).read_all()
    if not records:
        print("no records", file=sys.stderr)
        return 1
    since = parse_time(args.since) if args.since else None
    until = parse_time(args.until) if args.until else None
    log = Path(args.home) / "anchors" / "local-anchor-log.jsonl"
    out = build_pack(records, args.output, since=since, until=until,
                     local_anchor_log=log if log.exists() else None, checklist=args.checklist)
    print(f"wrote {out} (summary.html, actions.csv, bundle.zip, VERIFY.md)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gleipnir", description="Verifiable action records for AI agents")
    p.add_argument("--home", default=".gleipnir", help="data directory (default: .gleipnir)")
    p.add_argument("--chain", default="default", help="chain name (default: default)")
    p.add_argument("--version", action="version", version=f"gleipnir-sdk {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create the signing key and print its id").set_defaults(fn=cmd_init)
    sub.add_parser("status", help="show chain status").set_defaults(fn=cmd_status)
    e = sub.add_parser("export", help="write a bundle for gleipnir-verify")
    e.add_argument("-o", "--output", default="bundle.zip")
    e.add_argument("--since", help="ISO 8601 start time")
    e.add_argument("--until", help="ISO 8601 end time")
    e.set_defaults(fn=cmd_export)
    c = sub.add_parser("check", help="show which security review checklist items your records evidence")
    c.add_argument("--checklist", help="path to a checklist.yaml (default: the pinned copy shipped with the SDK)")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_check)
    k = sub.add_parser("pack", help="build a Security Review Pack for a period")
    k.add_argument("-o", "--output", default="security-review-pack.zip")
    k.add_argument("--since", help="ISO 8601 start time")
    k.add_argument("--until", help="ISO 8601 end time")
    k.add_argument("--checklist", help="path to a checklist.yaml")
    k.set_defaults(fn=cmd_pack)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

__all__ = ["main", "LocalFileAnchor"]
