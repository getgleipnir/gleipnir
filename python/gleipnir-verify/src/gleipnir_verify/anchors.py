"""Verification of anchor receipts.

An anchor receipt proves that a segment hash was published outside the vendor's
control at some point in time. Each anchor type registers a verifier function.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canon import canonicalize, sha256_tagged


@dataclass
class AnchorResult:
    ok: bool | None  # True = verified, False = invalid, None = present but not checked
    detail: str = ""
    independent: bool = False  # True if the anchor is outside the vendor's control
    time: str | None = None  # trusted time attested by the anchor, if any (RFC 3339, UTC)


def local_log_entry_hash(entry: dict[str, Any]) -> str:
    return sha256_tagged(canonicalize({k: v for k, v in entry.items() if k != "hash"}))


def read_local_log(path: str | Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip(" \t\r\n")]


def check_local_log(entries: list[dict[str, Any]]) -> str | None:
    """Return None if the local anchor log is internally consistent, else a reason."""
    prev = None
    for i, e in enumerate(entries):
        if e.get("index") != i:
            return f"entry {i} has index {e.get('index')}"
        if e.get("prev") != prev:
            return f"entry {i} does not link to entry {i - 1}"
        h = local_log_entry_hash(e)
        if e.get("hash") != h:
            return f"entry {i} hash mismatch"
        prev = h
    return None


def _local_entries(options: dict[str, Any]) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Load the local anchor log once (from --local-anchor-log, else from the bundle)."""
    cache = options.setdefault("_local_cache", {})
    if "entries" in cache:
        return cache["entries"], cache["error"]
    entries, error = None, None
    if options.get("local_anchor_log"):
        try:
            entries = read_local_log(options["local_anchor_log"])
        except (OSError, json.JSONDecodeError) as exc:
            error = f"cannot read local anchor log: {exc}"
    elif options.get("local_anchor_entries") is not None:
        entries = options["local_anchor_entries"]
    if entries is not None and error is None:
        problem = check_local_log(entries)
        if problem:
            error = f"local anchor log is inconsistent: {problem}"
    cache["entries"], cache["error"] = entries, error
    return entries, error


def verify_local(receipt: dict[str, Any], *, segment_hash: str, chain: str, options: dict[str, Any]) -> AnchorResult:
    entries, error = _local_entries(options)
    if error:
        return AnchorResult(False, error)
    if entries is None:
        return AnchorResult(None, "local anchor log not provided (use --local-anchor-log); local anchors are "
                                  "for testing and are not independent of the vendor")
    r = receipt.get("receipt", {})
    idx = r.get("index")
    if not isinstance(idx, int) or not 0 <= idx < len(entries):
        return AnchorResult(False, f"receipt index {idx!r} not in local anchor log")
    entry = entries[idx]
    if entry.get("hash") != r.get("entry_hash"):
        return AnchorResult(False, "receipt does not match the log entry")
    if entry.get("segment_hash") != segment_hash or entry.get("chain") != chain:
        return AnchorResult(False, "log entry is for a different segment")
    return AnchorResult(True, "local anchor log entry found (not independent of the vendor)", independent=False)


def verify_rekor(receipt: dict[str, Any], *, segment_hash: str, chain: str, options: dict[str, Any]) -> AnchorResult:
    from .rekor import verify_rekor_receipt

    return verify_rekor_receipt(receipt, segment_hash=segment_hash, options=options)


def verify_rfc3161(receipt: dict[str, Any], *, segment_hash: str, chain: str, options: dict[str, Any]) -> AnchorResult:
    from .timestamp import verify_timestamp_receipt

    return verify_timestamp_receipt(receipt, segment_hash=segment_hash, options=options)


def default_verifiers() -> dict[str, Callable[..., AnchorResult]]:
    return {"local": verify_local, "rekor": verify_rekor, "rfc3161": verify_rfc3161}
