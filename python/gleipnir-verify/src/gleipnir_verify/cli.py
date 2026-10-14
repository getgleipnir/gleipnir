"""gleipnir-verify: check a Gleipnir record bundle offline."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .verifier import ERROR, INFO, WARN, parse_time, verify_bundle

_MARK = {ERROR: "FAIL", WARN: "WARN", INFO: "info"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gleipnir-verify",
        description="Verify a Gleipnir agent action record bundle. Works offline; needs no access to the vendor.",
    )
    p.add_argument("bundle", help="path to bundle .zip")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--expect-key", metavar="KEY_ID", help="fail unless the chain is signed with this key id")
    p.add_argument("--expect-until", metavar="TIME",
                   help="fail unless records cover at least until this ISO 8601 time (detects truncation)")
    p.add_argument("--known-head", metavar="SEQ:HASH",
                   help="fail unless the record with this seq and hash is present (from an earlier bundle); "
                        "detects truncation and rewritten history")
    p.add_argument("--local-anchor-log", metavar="PATH", help="local anchor log to check local receipts against")
    p.add_argument("--strict", action="store_true", help="treat warnings as failures")
    p.add_argument("--version", action="version", version=f"gleipnir-verify {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    expect_until = parse_time(args.expect_until) if args.expect_until else None
    options = {}
    if args.local_anchor_log:
        options["local_anchor_log"] = args.local_anchor_log
    known_head = None
    if args.known_head:
        seq_text, _, hash_text = args.known_head.partition(":")
        known_head = (int(seq_text), hash_text)
    report = verify_bundle(args.bundle, expect_key=args.expect_key, expect_until=expect_until,
                           known_head=known_head, anchor_options=options)
    valid = report.valid(strict=args.strict)

    if args.json:
        print(json.dumps(report.as_dict(strict=args.strict), indent=2, sort_keys=True))
        return 0 if valid else 1

    s = report.summary
    out = sys.stdout
    if s:
        out.write(f"chain:        {s.get('chain')}\n")
        out.write(f"signing keys: {', '.join(s.get('keys', []))}\n")
        out.write(f"records:      {s.get('records')} (seq {s.get('first_seq')}..{s.get('last_seq')})\n")
        kinds = ", ".join(f"{k} {v}" for k, v in sorted(s.get("by_kind", {}).items()))
        out.write(f"by kind:      {kinds}\n")
        out.write(f"segments:     {s.get('segments')}, anchored {s.get('segments_anchored')} "
                  f"(independent anchors: {s.get('anchors_independent')})\n")
        out.write(f"covers:       {s.get('covered_from')} .. {s.get('covered_until')}\n")
        if s.get("head"):
            out.write(f"head:         {s['head']['seq']}:{s['head']['hash']}\n")
            out.write("              (keep this; pass it as --known-head next time to detect truncation)\n")
        if s.get("anchored_until"):
            out.write(f"anchored to:  {s.get('anchored_until')}\n")
    if report.findings:
        out.write("\n")
        for f in report.findings:
            where = f" seq {f.seq}" if f.seq is not None else ""
            out.write(f"[{_MARK[f.level]}]{where} {f.code}: {f.message}\n")
    out.write("\n")
    if valid:
        out.write("result: VALID\n")
    else:
        n = len(report.errors) + (len(report.warnings) if args.strict else 0)
        out.write(f"result: INVALID ({n} problem{'s' if n != 1 else ''})\n")
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
