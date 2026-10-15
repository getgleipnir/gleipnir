"""Verification of Gleipnir record chains and bundles.

The verifier answers one question: can these records be trusted not to have been
changed after they were written and anchored? It checks, in order:

1. Record order and sequence numbers (no gaps, duplicates or reordering).
2. Signatures, against keys introduced by the genesis record or signed rotations.
3. Hash chain continuity (each record commits to the previous one).
4. Segments: Merkle roots, tiling (every record belongs to exactly one segment),
   and time continuity between segments (heartbeats).
5. Anchor receipts for segments.
6. Bundle-level expectations: declared range, expected key, expected coverage.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import anchors as anchor_mod
from . import merkle
from .canon import hash_to_bytes, record_hash
from .crypto import decode_public_key, key_id, record_message, verify_signature

FORMAT_VERSION = 1
ERROR, WARN, INFO = "error", "warn", "info"


@dataclass
class Finding:
    level: str
    code: str
    message: str
    seq: int | None = None

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"level": self.level, "code": self.code, "message": self.message}
        if self.seq is not None:
            d["seq"] = self.seq
        return d


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.level == ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.level == WARN]

    def valid(self, strict: bool = False) -> bool:
        return not self.errors and (not strict or not self.warnings)

    def add(self, level: str, code: str, message: str, seq: int | None = None) -> None:
        self.findings.append(Finding(level, code, message, seq))

    def as_dict(self, strict: bool = False) -> dict[str, Any]:
        return {
            "result": "VALID" if self.valid(strict) else "INVALID",
            "summary": self.summary,
            "findings": [f.as_dict() for f in self.findings],
        }


_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})",
                      re.ASCII)


def parse_time(text: str) -> datetime:
    """Parse a strict RFC 3339 timestamp (``YYYY-MM-DDTHH:MM:SS[.ffffff](Z|+HH:MM)``) to UTC.

    The grammar is deliberately narrow and identical in every implementation, so a bundle's
    validity never depends on the language or Python version that checks it.
    """
    if not isinstance(text, str):
        raise ValueError("timestamp must be a string")
    m = _RFC3339.fullmatch(text)
    if m is None:
        raise ValueError(f"Invalid RFC 3339 timestamp: {text!r}")
    year, month, day, hour, minute, second = (int(x) for x in m.groups()[:6])
    micro = int((m.group(7) or "").ljust(6, "0") or "0")
    tz = m.group(8)
    if tz == "Z":
        tzinfo = timezone.utc
    else:
        sign = 1 if tz[0] == "+" else -1
        tzinfo = timezone(sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6])))
    return datetime(year, month, day, hour, minute, second, micro, tzinfo=tzinfo).astimezone(timezone.utc)


def verify_records(records: list[dict[str, Any]], **kwargs: Any) -> Report:
    """Verify a list of records. Never raises on malformed input; problems become findings."""
    try:
        return _verify_records(records, **kwargs)
    except Exception as exc:  # noqa: BLE001 - adversarial input must not crash the verifier
        report = Report()
        report.add(ERROR, "malformed", f"records could not be processed: {type(exc).__name__}: {exc}")
        return report


def _verify_records(
    records: list[dict[str, Any]],
    *,
    manifest: dict[str, Any] | None = None,
    expect_key: str | None = None,
    expect_until: datetime | None = None,
    known_head: tuple[int, str] | None = None,
    require_anchor: str | list[str] | None = None,
    max_anchor_delay: float | None = None,
    require_full: bool = False,
    anchor_verifiers: dict[str, Callable[..., anchor_mod.AnchorResult]] | None = None,
    anchor_options: dict[str, Any] | None = None,
) -> Report:
    report = Report()
    anchor_verifiers = anchor_verifiers or anchor_mod.default_verifiers()
    anchor_options = anchor_options or {}

    if not records:
        report.add(ERROR, "empty", "bundle contains no records")
        return report

    # ---- genesis and keys ---------------------------------------------------
    genesis = records[0]
    if not isinstance(genesis, dict):
        report.add(ERROR, "malformed", "first record is not a JSON object")
        return report
    if genesis.get("kind") != "genesis" or genesis.get("seq") != 0:
        report.add(ERROR, "no_genesis", "first record must be the genesis record (seq 0)")
        return report
    if genesis.get("v") != FORMAT_VERSION:
        report.add(ERROR, "format_version", f"unsupported format version {genesis.get('v')!r}")
        return report
    chain_id = genesis.get("chain")
    keys: dict[str, bytes] = {}
    try:
        pk = genesis["public_key"]
        raw = decode_public_key(pk["public"])
        if key_id(raw) != pk["id"]:
            report.add(ERROR, "key_id_mismatch", "genesis key id does not match its public key", 0)
            return report
        keys[pk["id"]] = raw
    except (KeyError, TypeError, ValueError) as exc:
        report.add(ERROR, "bad_genesis_key", f"cannot read genesis public key: {exc}", 0)
        return report
    genesis_key = genesis["public_key"]["id"]
    config = genesis.get("config", {})
    heartbeat = config.get("heartbeat_seconds")

    if expect_key and expect_key != genesis_key:
        report.add(ERROR, "unexpected_key", f"chain key {genesis_key} is not the expected key {expect_key}", 0)

    # ---- per-record checks ----------------------------------------------------
    hashes: dict[int, str] = {}
    by_seq: dict[int, dict[str, Any]] = {}
    prev_seq: int | None = None
    prev_hash: str | None = None
    first_body_seq: int | None = None
    current_key = genesis_key

    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            report.add(ERROR, "malformed", f"record at position {idx} is not a JSON object")
            return report
        seq = rec.get("seq")
        if not isinstance(seq, int):
            report.add(ERROR, "bad_seq", f"record at position {idx} has no integer seq")
            continue
        if rec.get("chain") != chain_id:
            report.add(ERROR, "wrong_chain", f"record belongs to chain {rec.get('chain')!r}", seq)
        if rec.get("v") != FORMAT_VERSION:
            report.add(ERROR, "format_version", f"unsupported format version {rec.get('v')!r}", seq)

        try:
            h = record_hash(rec)
        except Exception as exc:  # noqa: BLE001 - e.g. integers outside the JSON-safe range
            report.add(ERROR, "unencodable", f"record cannot be canonicalized: {exc}", seq)
            continue
        if seq in by_seq:
            report.add(ERROR, "duplicate_seq", "sequence number appears twice", seq)
        hashes[seq] = h
        by_seq[seq] = rec

        # signature
        kid = rec.get("key")
        if kid not in keys:
            report.add(ERROR, "unknown_key", f"signed with unknown key {kid!r}", seq)
        elif not verify_signature(keys[kid], record_message(h), rec.get("sig", "")):
            report.add(ERROR, "bad_signature", "signature does not match record content (record altered?)", seq)
        elif idx > 0 and kid != current_key:
            report.add(ERROR, "stale_key", f"signed with {kid} after it was rotated out", seq)

        if rec.get("kind") == "key_rotation" and kid in keys:
            try:
                nk = rec["new_key"]
                raw = decode_public_key(nk["public"])
                if key_id(raw) != nk["id"]:
                    raise ValueError("id mismatch")
                keys[nk["id"]] = raw
                current_key = nk["id"]
            except (KeyError, TypeError, ValueError) as exc:
                report.add(ERROR, "bad_rotation", f"invalid key rotation: {exc}", seq)

        # chain continuity
        if idx == 0:
            if "prev" in rec:
                report.add(ERROR, "genesis_prev", "genesis record must not have prev", seq)
        elif idx == 1 and seq != 1:
            # Partial bundle: chain resumes after genesis. The first body record must open a segment;
            # its prev is accepted and checked through the segment's Merkle root and anchor.
            first_body_seq = seq
            report.add(ERROR if require_full else WARN, "partial_bundle",
                       f"bundle starts at seq {seq}: records 1..{seq - 1} are not included, so nothing is proven "
                       "about them")
        else:
            if prev_seq is not None and seq != prev_seq + 1:
                if seq <= prev_seq:
                    report.add(ERROR, "reordered", f"seq {seq} follows seq {prev_seq}", seq)
                else:
                    report.add(ERROR, "gap", f"records {prev_seq + 1}..{seq - 1} are missing", seq)
            if rec.get("prev") != prev_hash:
                report.add(ERROR, "broken_chain", "prev does not match the hash of the preceding record", seq)
        if idx == 1 and first_body_seq is None:
            first_body_seq = seq
        prev_seq, prev_hash = seq, h

    if report.errors:
        _summarize(report, records, genesis, keys, [], 0)
        return report

    # ---- segments ----------------------------------------------------------------
    seq_list = [r["seq"] for r in records]
    last_seq = seq_list[-1]
    segments = [r for r in records if r.get("kind") == "segment"]
    covered: set[int] = set()
    prev_segment: dict[str, Any] | None = None
    expected_from = first_body_seq if first_body_seq is not None else 1
    for seg_rec in segments:
        s = seg_rec.get("segment", {})
        sseq = seg_rec["seq"]
        try:
            frm, count, root_tag = int(s["from"]), int(s["count"]), s["root"]
            opened, closed = parse_time(s["opened_at"]), parse_time(s["closed_at"])
        except (KeyError, TypeError, ValueError) as exc:
            report.add(ERROR, "bad_segment", f"malformed segment: {exc}", sseq)
            continue
        if frm != expected_from or frm + count != sseq:
            report.add(ERROR, "segment_tiling", f"segment covers {frm}..{frm + count - 1} but should start at "
                       f"{expected_from} and end right before its own record", sseq)
        members = list(range(frm, frm + count))
        missing = [m for m in members if m not in hashes]
        if missing:
            report.add(ERROR, "segment_incomplete", f"{len(missing)} records of this segment are missing", sseq)
        else:
            leaves = [hash_to_bytes(hashes[m]) for m in members]
            if merkle.root(leaves) != hash_to_bytes(root_tag):
                report.add(ERROR, "merkle_mismatch", "segment Merkle root does not match its records", sseq)
        covered.update(members)
        covered.add(sseq)
        if prev_segment is not None:
            if s.get("prev_segment") != hashes[prev_segment["seq"]]:
                report.add(ERROR, "segment_link", "prev_segment does not match the previous segment", sseq)
            if parse_time(prev_segment["segment"]["closed_at"]) != opened:
                report.add(WARN, "time_gap", f"no segment between {prev_segment['segment']['closed_at']} and "
                           f"{s['opened_at']}", sseq)
        elif frm == 1 and opened != parse_time(genesis["time"]):
            report.add(WARN, "time_gap", "first segment does not start at the genesis time", sseq)
        if closed < opened:
            report.add(ERROR, "segment_time", "segment closes before it opens", sseq)
        if heartbeat and (closed - opened) > timedelta(seconds=heartbeat * 1.5 + 60):
            report.add(WARN, "missed_heartbeat", f"segment spans {(closed - opened)} which is longer than the "
                       f"{heartbeat}s heartbeat (process down or records withheld?)", sseq)
        prev_segment = seg_rec
        expected_from = sseq + 1

    body = [s for s in seq_list if s != 0]
    # Anchor receipts written after the last segment closed are expected in the tail; losing one only
    # makes its segment show as unanchored, so they are not counted as unprotected records.
    tail = [s for s in body if s not in covered and by_seq[s].get("kind") != "anchor"]
    if tail:
        report.add(WARN, "unsegmented_tail", f"{len(tail)} records after the last closed segment "
                   f"(seq {tail[0]}..{tail[-1]}) are not covered by a segment or anchor; "
                   "truncation of this tail cannot be ruled out")

    # ---- anchors -------------------------------------------------------------------
    receipts: dict[int, list[dict[str, Any]]] = {}
    for rec in records:
        if rec.get("kind") == "anchor":
            a = rec.get("anchor", {})
            receipts.setdefault(a.get("segment_seq"), []).append(rec)

    anchored = 0
    independent = 0
    unchecked = 0
    required = [require_anchor] if isinstance(require_anchor, str) else list(require_anchor or [])
    timestamped = 0
    max_delay = 0.0
    trusted_until: str | None = None
    last_anchored_close: str | None = None
    for seg_rec in segments:
        sseq = seg_rec["seq"]
        recs = receipts.get(sseq, [])
        ok_any = False
        seen_unchecked = False
        seg_independent = False
        verified_types: set[str] = set()
        for r in recs:
            a = r["anchor"]
            if a.get("segment_hash") != hashes[sseq]:
                report.add(ERROR, "anchor_hash", "anchor receipt is for a different segment hash", r["seq"])
                continue
            fn = anchor_verifiers.get(a.get("type"))
            if fn is None:
                report.add(WARN, "anchor_type", f"unknown anchor type {a.get('type')!r}", r["seq"])
                continue
            res = fn(a, segment_hash=hashes[sseq], chain=chain_id, options=anchor_options)
            if res.ok is False:
                report.add(ERROR, "anchor_invalid", f"anchor receipt invalid: {res.detail}", r["seq"])
            elif res.ok is None:
                report.add(INFO, "anchor_unchecked", f"anchor receipt not checked: {res.detail}", r["seq"])
                seen_unchecked = True
            else:
                ok_any = True
                if res.independent:
                    seg_independent = True
                    verified_types.add(a.get("type"))
                if res.time:
                    ts = parse_time(res.time)
                    closed = parse_time(seg_rec["segment"]["closed_at"])
                    delay = (ts - closed).total_seconds()
                    if delay < -300:
                        report.add(WARN, "timestamp_before_close", f"trusted time {res.time} is before the segment's "
                                   f"claimed close {seg_rec['segment']['closed_at']} (vendor clock ahead?)", sseq)
                    if max_anchor_delay is not None and delay > max_anchor_delay:
                        report.add(ERROR, "late_timestamp", f"segment timestamped {delay:.0f}s after it closed "
                                   f"(limit {max_anchor_delay:.0f}s): history may have been rebuilt later", sseq)
                    elif delay > 86400:
                        report.add(WARN, "late_timestamp", f"segment timestamped {delay / 3600:.1f}h after it closed "
                                   "(history may have been rebuilt later)", sseq)
                    max_delay = max(max_delay, delay)
        if ok_any:
            anchored += 1
            last_anchored_close = seg_rec["segment"]["closed_at"]
        elif seen_unchecked:
            unchecked += 1
        if seg_independent:
            independent += 1
        for req in required:
            if req not in verified_types:
                report.add(ERROR, "anchor_required", f"segment has no verified {req} anchor (receipt missing, "
                           "removed or not independent)", sseq)
        if "rfc3161" in verified_types:
            timestamped += 1
            trusted_until = seg_rec["segment"]["closed_at"]
    unanchored = len(segments) - anchored - unchecked
    if unanchored:
        report.add(WARN, "unanchored_segments", f"{unanchored} of {len(segments)} segments have no verified anchor "
                   "receipt in this bundle")
    if unchecked:
        report.add(WARN, "anchors_unchecked", f"{unchecked} segments have anchor receipts that could not be checked")

    # ---- bundle expectations ---------------------------------------------------------
    if require_full and body and body[0] != 1:
        report.add(ERROR, "partial_bundle", "a full bundle was required but records are missing at the start")
    if manifest is not None:
        if manifest.get("key") is not None and manifest.get("key") != genesis_key:
            report.add(ERROR, "manifest_key", "manifest key does not match the genesis key")
        if manifest.get("chain") != chain_id:
            report.add(ERROR, "manifest_chain", "manifest chain does not match records")
        if manifest.get("to_seq") is not None and manifest.get("to_seq") != last_seq:
            report.add(ERROR, "truncated", f"manifest declares records up to seq {manifest.get('to_seq')} but the "
                       f"bundle ends at seq {last_seq}")
        if manifest.get("from_seq") is not None and body and manifest.get("from_seq") != body[0]:
            report.add(ERROR, "manifest_range", f"manifest declares records from seq {manifest.get('from_seq')} but "
                       f"the bundle starts at {body[0]}")
    if expect_until is not None:
        if not segments:
            report.add(ERROR, "coverage", "no closed segments, coverage cannot be established")
        else:
            last_close = parse_time(segments[-1]["segment"]["closed_at"])
            slack = timedelta(seconds=(heartbeat or 0) + 60)
            if last_close + slack < expect_until:
                report.add(ERROR, "coverage", f"records end at {segments[-1]['segment']['closed_at']}, earlier than "
                           f"expected {expect_until.isoformat()} (truncated?)")

    if known_head is not None:
        kseq, khash = known_head
        if kseq not in hashes:
            report.add(ERROR, "known_head_missing", f"a previously seen record (seq {kseq}) is not in this bundle "
                       "(truncated or rewritten?)")
        elif hashes[kseq] != khash:
            report.add(ERROR, "known_head_changed", f"record seq {kseq} differs from the one seen before "
                       "(history rewritten)", kseq)

    _summarize(report, records, genesis, keys, segments, anchored, independent, last_anchored_close)
    report.summary["segments_timestamped"] = timestamped
    report.summary["trusted_time_until"] = trusted_until
    report.summary["max_timestamp_delay_s"] = round(max_delay, 1) if timestamped else None
    report.summary["head"] = {"seq": records[-1].get("seq"), "hash": hashes.get(records[-1].get("seq"))}
    return report


def _summarize(report: Report, records: list[dict[str, Any]], genesis: dict[str, Any], keys: dict[str, bytes],
               segments: list[dict[str, Any]], anchored: int, independent: int = 0,
               last_anchored_close: str | None = None) -> None:
    kinds: dict[str, int] = {}
    for r in records:
        k = r.get("kind", "?") if isinstance(r, dict) else "?"
        k = k if isinstance(k, str) else "?"  # non-string kinds are counted as "?" in every implementation
        kinds[k] = kinds.get(k, 0) + 1
    report.summary = {
        "chain": genesis.get("chain"),
        "keys": sorted(keys),
        "records": len(records),
        "first_seq": records[0].get("seq"),
        "last_seq": records[-1].get("seq"),
        "by_kind": kinds,
        "segments": len(segments),
        "segments_anchored": anchored,
        "partial": _first_body_seq(records) not in (None, 1),
        "anchors_independent": independent,
        "anchored_until": last_anchored_close,
        "covered_from": genesis.get("time"),
        "covered_until": segments[-1]["segment"]["closed_at"] if segments else None,
    }


def _first_body_seq(records: list[Any]) -> Any:
    if len(records) > 1 and isinstance(records[1], dict):
        return records[1].get("seq")
    return None


def read_bundle(path: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]] | None]:
    with zipfile.ZipFile(path) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        lines = zf.read("records.jsonl").decode("utf-8").split("\n")
        local_log = None
        if "anchors/local-anchor-log.jsonl" in zf.namelist():
            raw = zf.read("anchors/local-anchor-log.jsonl").decode("utf-8").split("\n")
            local_log = [json.loads(line) for line in raw if line.strip()]
    records = [json.loads(line) for line in lines if line.strip()]
    return manifest, records, local_log


def verify_bundle(path: str | Path, **kwargs: Any) -> Report:
    """Verify a bundle file. Never raises on malformed input; problems become findings."""
    try:
        manifest, records, local_log = read_bundle(path)
    except Exception as exc:  # noqa: BLE001 - zip, UTF-8, JSON, recursion and int-size errors alike
        report = Report()
        report.add(ERROR, "bad_bundle", f"cannot read bundle: {type(exc).__name__}: {str(exc)[:300]}")
        return report
    if not isinstance(manifest, dict) or not isinstance(records, list):
        report = Report()
        report.add(ERROR, "bad_bundle", "manifest.json must be a JSON object")
        return report
    if local_log is not None and not all(isinstance(e, dict) for e in local_log):
        local_log = None
    if manifest.get("format") != FORMAT_VERSION:
        report = Report()
        report.add(ERROR, "format_version", f"unsupported bundle format {manifest.get('format')!r}")
        return report
    if local_log is not None:
        opts = dict(kwargs.get("anchor_options") or {})
        opts.setdefault("local_anchor_entries", local_log)
        kwargs["anchor_options"] = opts
    return verify_records(records, manifest=manifest, **kwargs)


def iter_jsonl(path: str | Path) -> Iterable[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)
