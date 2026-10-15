"""Reference oracle for the TypeScript differential tests.

Reads a JSON list of cases from stdin. Each case is {"kind": ..., ...}:
  - {"kind": "canon", "text": <JSON text>}                -> {"canonical": str} or {"error": name}
  - {"kind": "hash", "text": <JSON text of a record>}     -> {"hash": str} or {"error": name}
  - {"kind": "time", "text": str}                         -> {"micros": int} or {"error": name}
  - {"kind": "records", "text": <JSONL>, "options": {...}} -> report dict
  - {"kind": "bundle", "path": str, "options": {...}}      -> report dict (bundles and proofs)
  - {"kind": "pubkey", "text": str}                       -> {"key_id": str} or {"error": name}
  - {"kind": "sig", "public": str, "message": str, "sig": str} -> {"ok": bool}
  - {"kind": "digest", "text": <JSON [tool, system, args]>} -> {"digest": str} or {"error": name}
  - {"kind": "ids", "text": <JSON>, "wanted": str|None}   -> {"ids": [...]}
  - {"kind": "csv", "text": str}                          -> {"rows": [[...]]} or {"error": name}
  - {"kind": "reconcile", "bundle": path, "csv": path, "column": str, "field": str|None} -> sets
  - {"kind": "approval_sig", "body": {...}, "approvers": [...]|None, "origins": [...]|None, "require": bool}
                                                          -> {"findings": [[level, code, message]]} or {"error": name}
  - {"kind": "registry", "text": <JSON>}                  -> {"ids": [...]} or {"error": name, "message": str}
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
    if o.get("approvers") is not None:
        kw["approvers"] = o["approvers"]
    if o.get("webauthn_origins") is not None:
        kw["webauthn_origins"] = o["webauthn_origins"]
    if o.get("require_signed_approvals"):
        kw["require_signed_approvals"] = True
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
    if k == "pubkey":
        from gleipnir_verify.crypto import decode_public_key, key_id
        try:
            return {"key_id": key_id(decode_public_key(case["text"]))}
        except Exception as exc:  # noqa: BLE001
            return {"error": type(exc).__name__}
    if k == "sig":
        from gleipnir_verify.crypto import decode_public_key, verify_signature
        return {"ok": verify_signature(decode_public_key(case["public"]), case["message"].encode("utf-8"), case["sig"])}
    if k == "digest":
        from gleipnir_verify.verifier import action_digest
        try:
            return {"digest": action_digest(*json.loads(case["text"]))}
        except Exception as exc:  # noqa: BLE001
            return {"error": type(exc).__name__}
    if k == "ids":
        from gleipnir_verify.reconcile import external_ids
        return {"ids": sorted(external_ids(json.loads(case["text"]), case.get("wanted")))}
    if k == "csv":
        import csv as _csv
        import io
        try:
            return {"rows": list(_csv.reader(io.StringIO(case["text"], newline="")))}
        except Exception as exc:  # noqa: BLE001
            return {"error": type(exc).__name__}
    if k == "reconcile":
        from gleipnir_verify.reconcile import reconcile
        try:
            res = reconcile(case["bundle"], case["csv"], column=case["column"], field_name=case.get("field"),
                            **opts(case.get("options", {})))
        except Exception as exc:  # noqa: BLE001
            return {"error": type(exc).__name__}
        return {"valid": res.report.valid(), "matched": sorted(res.matched), "only_in_system": sorted(res.only_in_system),
                "only_in_records": sorted(res.only_in_records), "ok": res.ok}
    if k == "approval_sig":
        from gleipnir_verify.approvals import check_signature, load_approvers
        try:
            reg = load_approvers(case["approvers"]) if case.get("approvers") is not None else None
            return {"findings": [list(f) for f in check_signature(case["body"], reg, case.get("origins"),
                                                                   bool(case.get("require")))]}
        except Exception as exc:  # noqa: BLE001
            return {"error": type(exc).__name__, "message": str(exc)}
    if k == "registry":
        from gleipnir_verify.approvals import load_approvers
        try:
            return {"ids": sorted(load_approvers(json.loads(case["text"])))}
        except Exception as exc:  # noqa: BLE001
            return {"error": type(exc).__name__, "message": str(exc)}
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
