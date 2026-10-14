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
    p.add_argument("--require-anchor", choices=["rekor"],
                   help="fail unless every segment has a verified anchor in this independent log")
    p.add_argument("--require-full", action="store_true",
                   help="fail unless the bundle starts at the beginning of the chain")
    p.add_argument("--trusted-root", metavar="PATH",
                   help="Sigstore trusted_root.json to use instead of the embedded one (for newer log shards)")
    p.add_argument("--local-anchor-log", metavar="PATH", help="local anchor log to check local receipts against")
    p.add_argument("--strict", action="store_true", help="treat warnings as failures")
    p.add_argument("--version", action="version", version=f"gleipnir-verify {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    expect_until = None
    if args.expect_until:
        try:
            expect_until = parse_time(args.expect_until)
        except ValueError:
            parser.error("--expect-until needs an ISO 8601 time with a timezone, e.g. 2026-10-14T18:00:00Z")
    options: dict[str, object] = {}
    if args.local_anchor_log:
        options["local_anchor_log"] = args.local_anchor_log
    if args.trusted_root:
        options["trusted_root"] = args.trusted_root
    known_head = None
    if args.known_head:
        seq_text, sep, hash_text = args.known_head.partition(":")
        if not sep or not seq_text.isdigit() or not hash_text.startswith("sha256:"):
            parser.error("--known-head must look like 12:sha256:<64 hex>")
        known_head = (int(seq_text), hash_text)
    report = verify_bundle(args.bundle, expect_key=args.expect_key, expect_until=expect_until,
                           known_head=known_head, require_anchor=args.require_anchor,
                           require_full=args.require_full, anchor_options=options)
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
