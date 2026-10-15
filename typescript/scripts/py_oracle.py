"""Reference oracle for the TypeScript differential tests.

Reads a JSON list of cases from stdin. Each case is {"kind": ..., ...}:
  - {"kind": "canon", "text": <JSON text>}                -> {"canonical": str} or {"error": name}
  - {"kind": "hash", "text": <JSON text of a record>}     -> {"hash": str} or {"error": name}
  - {"kind": "time", "text": str}                         -> {"micros": int} or {"error": name}
  - {"kind": "records", "text": <JSONL>, "options": {...}} -> report dict
  - {"kind": "bundle", "path": str, "options": {...}}      -> report dict
Writes a JSON list of results to stdout. Run with: uv run python typescript/scripts/py_oracle.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

from gleipnir_verify.canon import canonicalize, record_hash
from gleipnir_verify.verifier import parse_time, verify_bundle, verify_records

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def opts(o: dict) -> dict:
    kw: dict = {}
    if o.get("expect_key") is not None:
        kw["expect_key"] = o["expect_key"]
    if o.get("expect_until") is not None:
        kw["expect_until"] = parse_time(o["expect_until"])
    if o.get("known_head") is not None:
        kw["known_head"] = (o["known_head"][0], o["known_head"][1])
    if o.get("require_anchor") is not None:
        kw["require_anchor"] = o["require_anchor"]
    if o.get("max_anchor_delay") is not None:
        kw["max_anchor_delay"] = o["max_anchor_delay"]
    if o.get("require_full"):
        kw["require_full"] = True
    if o.get("manifest") is not None:
        kw["manifest"] = o["manifest"]
    if o.get("local_anchor_entries") is not None:
        kw["anchor_options"] = {"local_anchor_entries": o["local_anchor_entries"]}
    return kw


def one(case: dict) -> dict:
    k = case["kind"]
    try:
        if k == "canon":
            return {"canonical": canonicalize(json.loads(case["text"])).decode("utf-8")}
        if k == "hash":
            return {"hash": record_hash(json.loads(case["text"]))}
        if k == "time":
            dt = parse_time(case["text"])
            delta = dt - EPOCH
            return {"micros": (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds}
    except Exception as exc:  # noqa: BLE001
        return {"error": type(exc).__name__}
    if k == "records":
        try:
            records = [json.loads(line) for line in case["text"].splitlines() if line.strip()]
        except Exception as exc:  # noqa: BLE001
            return {"parse_error": type(exc).__name__}
        return verify_records(records, **opts(case.get("options", {}))).as_dict()
    if k == "bundle":
        return verify_bundle(case["path"], **opts(case.get("options", {}))).as_dict()
    if k == "version":
        return {"version": list(sys.version_info[:2])}
    raise ValueError(k)


def main() -> None:
    sys.setrecursionlimit(1000)
    cases = json.load(sys.stdin)
    out = [one(c) for c in cases]
    # No sort_keys: a record whose "kind" is not a string puts a non-string key into
    # summary["by_kind"], which json.dumps(sort_keys=True) (as the Python CLI uses) cannot sort.
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
