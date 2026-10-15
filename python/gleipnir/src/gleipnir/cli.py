"""gleipnir command line: init, status, export, check, pack, prove, report, mcp-proxy."""

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
    if args.format == "ocsf":
        from .sinks import to_ndjson

        out_path = Path(args.output if args.output != "bundle.zip" else "actions.ocsf.ndjson")
        out_path.write_bytes(to_ndjson(records, "ocsf"))
        print(f"wrote {out_path} (OCSF API Activity events, one per action)")
        return 0
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


def cmd_prove(args: argparse.Namespace) -> int:
    from .export import export_proof

    records = _store(args).read_all()
    log = Path(args.home) / "anchors" / "local-anchor-log.jsonl"
    out = export_proof(records, args.action_id, args.output, local_anchor_log=log if log.exists() else None)
    print(f"wrote {out}; verify with: pipx run gleipnir-verify {out.name} --expect-key "
          f"{records[0]['public_key']['id']}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    import webbrowser

    from .report import build_report

    home = Path(args.home) if args.home_given else _report_home()
    chain = args.chain if args.chain_given else None
    out, n = build_report(home, Path(args.output), chain=chain, limit=args.limit)
    print(f"wrote {out} ({n} tool calls from {home / 'chains'})")
    if args.open:
        webbrowser.open(out.resolve().as_uri())
    return 0


def _report_home() -> Path:
    from .mcp_proxy import default_home

    local = Path(".gleipnir")
    return local if (local / "chains").exists() else default_home()


def cmd_mcp_proxy(args: argparse.Namespace) -> int:
    from .mcp_proxy import run_from_args

    home = args.proxy_home or (args.home if args.home_given else None)
    return run_from_args(args, args.server_cmd, Path(home).expanduser() if home else None)


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
    e.add_argument("--format", choices=["bundle", "ocsf"], default="bundle",
                   help="bundle (verifiable zip) or ocsf (NDJSON events for a SIEM)")
    e.set_defaults(fn=cmd_export)
    pr = sub.add_parser("prove", help="write a proof for a single action")
    pr.add_argument("action_id")
    pr.add_argument("-o", "--output", default="proof.zip")
    pr.set_defaults(fn=cmd_prove)
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
    rp = sub.add_parser("report", help="write an HTML page of what your agent did (all chains in --home)")
    rp.add_argument("-o", "--output", default="gleipnir-report.html")
    rp.add_argument("--limit", type=int, default=1000, help="most recent tool calls to list (default 1000)")
    rp.add_argument("--open", action="store_true", help="open the page in a browser")
    rp.set_defaults(fn=cmd_report)
    from .mcp_proxy import add_arguments

    m = sub.add_parser("mcp-proxy", help="run an MCP server behind a recording stdio proxy",
                       usage="gleipnir mcp-proxy [options] -- <server command...>")
    add_arguments(m, home_dest="proxy_home")
    m.set_defaults(fn=cmd_mcp_proxy)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    server_cmd: list[str] = []
    if "mcp-proxy" in argv and "--" in argv[argv.index("mcp-proxy"):]:
        cut = argv.index("--", argv.index("mcp-proxy"))
        argv, server_cmd = argv[:cut], argv[cut + 1:]
    args = build_parser().parse_args(argv)
    args.server_cmd = server_cmd
    args.home_given = any(a == "--home" or a.startswith("--home=") for a in argv[: argv.index(args.cmd)])
    args.chain_given = any(a == "--chain" or a.startswith("--chain=") for a in argv[: argv.index(args.cmd)])
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

__all__ = ["main", "LocalFileAnchor"]
