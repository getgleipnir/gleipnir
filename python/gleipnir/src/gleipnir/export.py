"""Export bundles that buyers verify with gleipnir-verify."""

from __future__ import annotations

import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from gleipnir_verify.verifier import FORMAT_VERSION, parse_time

from . import __version__
from .util import iso, utcnow

VERIFY_README = """\
# How to verify this bundle

This bundle contains signed, hash-chained records of actions taken by an AI agent.
You can check it yourself, offline, without access to the vendor's systems:

    pipx run gleipnir-verify {name}

Useful options:

    --expect-key {key}     fail unless the chain is signed with this key
                           (compare with the key id the vendor publishes)
    --expect-until <ISO time>   fail if the records stop earlier than this (detects truncation)
    --json                 machine-readable result

A VALID result means: no record was edited, removed, reordered or inserted after it was
written, every segment's Merkle root matches, and anchor receipts check out. It does not
mean the agent's decisions were correct, and it cannot show actions the vendor never
recorded: reconcile the external object IDs in the records with your own systems.
"""


def select_records(records: list[dict[str, Any]], since: datetime | None = None,
                   until: datetime | None = None) -> list[dict[str, Any]]:
    """Genesis plus the complete segments overlapping [since, until].

    A partial bundle always starts at a segment boundary, so the verifier can check its first
    record through the segment's Merkle root. It is extended to include the anchor receipts of
    the chosen segments (which are written into later segments).
    """
    if not records:
        return []
    if since is None and until is None:
        return records
    genesis, body = records[0], records[1:]
    if any(r.get("kind") == "key_rotation" for r in body):
        raise NotImplementedError("date-range export of a chain with key rotations is not supported yet; "
                                  "export the whole chain")
    seg_pos = [i for i, r in enumerate(body) if r.get("kind") == "segment"]
    starts = [0] + [i + 1 for i in seg_pos[:-1]]
    chosen = []
    for start, end in zip(starts, seg_pos, strict=True):
        seg = body[end]["segment"]
        opened, closed = parse_time(seg["opened_at"]), parse_time(seg["closed_at"])
        if (since is None or closed >= since) and (until is None or opened <= until):
            chosen.append((start, end))
    tail_start = seg_pos[-1] + 1 if seg_pos else 0
    include_tail = until is None
    if not chosen:
        if include_tail and tail_start < len(body):
            return [genesis] + body[tail_start:]
        return [genesis]
    first, last = chosen[0][0], chosen[-1][1]
    wanted = {body[end]["seq"] for _, end in chosen}
    receipt_pos = [i for i, r in enumerate(body) if r.get("kind") == "anchor"
                   and r["anchor"]["segment_seq"] in wanted]
    if receipt_pos and max(receipt_pos) > last:
        need = max(receipt_pos)
        later = [i for i in seg_pos if i >= need]
        last = later[0] if later else len(body) - 1
    if include_tail:
        last = len(body) - 1
    return [genesis] + body[first : last + 1]


def export_bundle(records: list[dict[str, Any]], out: str | Path, *, since: datetime | None = None,
                  until: datetime | None = None, local_anchor_log: str | Path | None = None) -> Path:
    out = Path(out)
    picked = select_records(records, since, until)
    if not picked:
        raise ValueError("no records to export")
    body = [r for r in picked if r["seq"] != 0]
    manifest = {
        "format": FORMAT_VERSION,
        "chain": picked[0]["chain"],
        "from_seq": body[0]["seq"] if body else None,
        "to_seq": picked[-1]["seq"],
        "exported_at": iso(utcnow()),
        "key": picked[0]["public_key"]["id"],
        "tool": f"gleipnir-sdk {__version__}",
    }
    if since:
        manifest["since"] = iso(since)
    if until:
        manifest["until"] = iso(until)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        zf.writestr("records.jsonl", "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n"
                                             for r in picked))
        zf.writestr("VERIFY.md", VERIFY_README.format(name=out.name, key=manifest["key"]))
        if local_anchor_log and Path(local_anchor_log).exists():
            zf.write(local_anchor_log, "anchors/local-anchor-log.jsonl")
    return out

