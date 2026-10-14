"""An independent, minimal chain writer used only by the verifier's tests.

It is written from the spec, separately from the SDK, so the verifier is not only
tested against the code that produces its input.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from gleipnir_verify import merkle
from gleipnir_verify.anchors import local_log_entry_hash
from gleipnir_verify.canon import hash_to_bytes, record_hash
from gleipnir_verify.crypto import encode_public_key, encode_signature, key_id, record_message

T0 = datetime(2026, 10, 1, 9, 0, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class Key:
    def __init__(self, seed: bytes | None = None):
        self.sk = Ed25519PrivateKey.from_private_bytes(seed) if seed else Ed25519PrivateKey.generate()
        raw = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.id = key_id(raw)
        self.public = encode_public_key(raw)

    def sign(self, h: str) -> str:
        return encode_signature(self.sk.sign(record_message(h)))


class Builder:
    def __init__(self, key: Key | None = None, heartbeat: int = 600, chain: str = "ch_test"):
        self.key = key or Key()
        self.chain = chain
        self.records: list[dict[str, Any]] = []
        self.now = T0
        self.open: list[str] = []
        self.last_seg: str | None = None
        self.opened = T0
        self.anchor_log: list[dict[str, Any]] = []
        self.heartbeat = heartbeat
        self._add({"kind": "genesis", "public_key": {"id": self.key.id, "public": self.key.public},
                   "config": {"heartbeat_seconds": heartbeat, "segment_max_records": 1000}})

    def tick(self, seconds: float = 1) -> None:
        self.now += timedelta(seconds=seconds)

    def _add(self, fields: dict[str, Any], key: Key | None = None) -> dict[str, Any]:
        rec = {"v": 1, "chain": self.chain, "seq": len(self.records), "id": f"r{len(self.records)}",
               "time": iso(self.now), "key": (key or self.key).id, **fields}
        if self.records:
            rec["prev"] = record_hash(self.records[-1])
        h = record_hash(rec)
        rec["sig"] = (key or self.key).sign(h)
        self.records.append(rec)
        if rec["kind"] not in ("genesis", "segment"):
            self.open.append(h)
        return rec

    def action(self, n: int = 0, **extra: Any) -> dict[str, Any]:
        self.tick()
        return self._add({"kind": "action", "tool": {"name": "refund", "system": "pay"},
                          "args": {"order": f"o{n}", "amount": n}, "response": {"status": "ok"},
                          "t": {"start": iso(self.now), "end": iso(self.now)}, **extra})

    def segment(self) -> dict[str, Any]:
        self.tick()
        count = len(self.open)
        seg = {"from": len(self.records) - count, "count": count,
               "root": "sha256:" + merkle.root([hash_to_bytes(h) for h in self.open]).hex(),
               "opened_at": iso(self.opened), "closed_at": iso(self.now), "heartbeat": False}
        if self.last_seg:
            seg["prev_segment"] = self.last_seg
        rec = self._add({"kind": "segment", "segment": seg})
        self.open = []
        self.last_seg = record_hash(rec)
        self.opened = self.now
        return rec

    def anchor(self, seg: dict[str, Any]) -> dict[str, Any]:
        h = record_hash(seg)
        entry = {"v": 1, "index": len(self.anchor_log), "chain": self.chain, "segment_seq": seg["seq"],
                 "segment_hash": h, "time": iso(self.now)}
        if self.anchor_log:
            entry["prev"] = self.anchor_log[-1]["hash"]
        entry["hash"] = local_log_entry_hash(entry)
        self.anchor_log.append(entry)
        return self._add({"kind": "anchor", "anchor": {"segment_seq": seg["seq"], "segment_hash": h,
                                                       "type": "local", "receipt": {
                                                           "index": entry["index"], "entry_hash": entry["hash"],
                                                           "time": entry["time"]}}})

    def standard(self, segments: int = 3, per: int = 4) -> Builder:
        prev = None
        for s in range(segments):
            if prev is not None:
                self.anchor(prev)
            for i in range(per):
                self.action(s * 100 + i)
            prev = self.segment()
        self.anchor(prev)
        return self

    def copy(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self.records)


def resign(records: list[dict[str, Any]], key: Key, start: int = 0) -> list[dict[str, Any]]:
    """Recompute prev/sig from ``start`` on, as an attacker holding ``key`` would."""
    for i in range(start, len(records)):
        rec = records[i]
        rec.pop("sig", None)
        if i > 0:
            rec["prev"] = record_hash(records[i - 1])
        rec["key"] = key.id
        rec["sig"] = key.sign(record_hash(rec))
    return records
