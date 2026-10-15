"""Chain writer: signs, hash-chains and segments records, and anchors segments."""

from __future__ import annotations

import json
import logging
import queue
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any

from gleipnir_verify import merkle
from gleipnir_verify.canon import hash_to_bytes, record_hash
from gleipnir_verify.crypto import record_message
from gleipnir_verify.verifier import FORMAT_VERSION, parse_time

from .anchor import Anchor
from .keys import Signer
from .store import Store
from .util import Clock, iso, new_id, utcnow

log = logging.getLogger("gleipnir")


class ChainWriter:
    """Appends signed, hash-chained records to a store and closes segments.

    Thread-safe. One writer per chain: do not point two processes at the same store.
    """

    def __init__(
        self,
        store: Store,
        signer: Signer,
        *,
        clock: Clock = utcnow,
        anchor: Anchor | list[Anchor] | None = None,
        segment_max_records: int = 1000,
        heartbeat_seconds: int = 600,
        background: bool = True,
        genesis_extra: dict[str, Any] | None = None,
        sinks: list[Any] | None = None,
        state_dir: Any = None,
    ):
        if segment_max_records < 1:
            raise ValueError("segment_max_records must be >= 1")
        self.store = store
        self.signer = signer
        self.clock = clock
        if anchor is None:
            self.anchors: list[Anchor] = []
        elif isinstance(anchor, (list, tuple)):
            self.anchors = list(anchor)
        else:
            self.anchors = [anchor]
        if len({a.type for a in self.anchors}) != len(self.anchors):
            raise ValueError("at most one anchor per type")
        self.segment_max_records = segment_max_records
        self.heartbeat_seconds = heartbeat_seconds
        self._lock = threading.RLock()
        self._anchor_queue: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.background = background
        self.sinks = list(sinks or [])
        self._state_path = (Path(state_dir) / "sinks-state.json") if state_dir else None
        self._sink_lock = threading.Lock()
        self._recent: list[dict[str, Any]] = []
        self._delivered: dict[str, int] = {}
        self._recover(genesis_extra or {})
        self._init_sinks()
        if background:
            self._start_background()

    # -- state ------------------------------------------------------------------------
    def _recover(self, genesis_extra: dict[str, Any]) -> None:
        records = self.store.read_all()
        self.open_members: list[str] = []
        self.pending_anchor: dict[int, dict[str, Any]] = {}
        self.anchor_done = {}
        if not records:
            self.chain_id = new_id("ch")
            self.seq = -1
            self.last_hash: str | None = None
            self.last_segment_hash: str | None = None
            now = self.clock()
            genesis = {
                "kind": "genesis",
                "public_key": {"id": self.signer.key_id, "public": self.signer.public_key},
                "config": {"heartbeat_seconds": self.heartbeat_seconds,
                           "segment_max_records": self.segment_max_records},
                **genesis_extra,
            }
            self._write(genesis, now=now)
            self.segment_opened_at = iso(now)
            return

        genesis = records[0]
        self.chain_id = genesis["chain"]
        if genesis["public_key"]["id"] != self.signer.key_id:
            rotated = [r for r in records if r.get("kind") == "key_rotation"]
            current = rotated[-1]["new_key"]["id"] if rotated else genesis["public_key"]["id"]
            if current != self.signer.key_id:
                raise ValueError(f"chain {self.chain_id} is signed with {current}, not {self.signer.key_id}")
        self.seq = records[-1]["seq"]
        self.last_hash = record_hash(records[-1])
        self.last_segment_hash = None
        self.segment_opened_at = genesis["time"]
        self.anchor_done: dict[int, set[str]] = {}
        for r in records:
            if r.get("kind") == "anchor":
                self.anchor_done.setdefault(r["anchor"]["segment_seq"], set()).add(r["anchor"]["type"])
        wanted = {a.type for a in self.anchors}
        for r in records[1:]:
            if r.get("kind") == "segment":
                self.open_members = []
                self.last_segment_hash = record_hash(r)
                self.segment_opened_at = r["segment"]["closed_at"]
                if not wanted <= self.anchor_done.get(r["seq"], set()):
                    self.pending_anchor[r["seq"]] = r
            else:
                self.open_members.append(record_hash(r))
        for seg in list(self.pending_anchor.values()):
            self._anchor_queue.put(seg)

    # -- writing ----------------------------------------------------------------------
    def _write(self, fields: dict[str, Any], now=None) -> dict[str, Any]:
        with self._lock:
            now = now or self.clock()
            rec: dict[str, Any] = {
                "v": FORMAT_VERSION,
                "chain": self.chain_id,
                "seq": self.seq + 1,
                "id": fields.pop("id", None) or new_id(fields.get("kind", "rec")[:3]),
                "time": iso(now),
                "key": self.signer.key_id,
                **fields,
            }
            if self.last_hash is not None:
                rec["prev"] = self.last_hash
            rec = json.loads(json.dumps(rec))  # normalize to plain JSON types before hashing
            h = record_hash(rec)
            rec["sig"] = self.signer.sign(record_message(h))
            self.store.append(rec)
            if self.sinks:
                self._recent.append(rec)
            self.seq = rec["seq"]
            self.last_hash = h
            if rec["kind"] not in ("genesis", "segment"):
                self.open_members.append(h)
            return rec

    def append(self, kind: str, fields: dict[str, Any]) -> dict[str, Any]:
        if kind in ("genesis", "segment"):
            raise ValueError(f"{kind} records are written by the chain itself")
        with self._lock:
            rec = self._write({"kind": kind, **fields})
            if len(self.open_members) >= self.segment_max_records:
                self.close_segment()
                if not self.background:
                    self.anchor_pending()
                    self.deliver()
            return rec

    def close_segment(self, heartbeat: bool = False) -> dict[str, Any]:
        """Close the open segment (even if empty) and queue it for anchoring."""
        with self._lock:
            now = self.clock()
            count = len(self.open_members)
            root = merkle.root([hash_to_bytes(h) for h in self.open_members])
            seg: dict[str, Any] = {
                "from": self.seq + 1 - count,
                "count": count,
                "root": "sha256:" + root.hex(),
                "opened_at": self.segment_opened_at,
                "closed_at": iso(now),
                "heartbeat": heartbeat,
            }
            if self.last_segment_hash is not None:
                seg["prev_segment"] = self.last_segment_hash
            rec = self._write({"kind": "segment", "segment": seg}, now=now)
            self.open_members = []
            self.last_segment_hash = self.last_hash
            self.segment_opened_at = seg["closed_at"]
            if self.anchors:
                self.pending_anchor[rec["seq"]] = rec
                self._anchor_queue.put(rec)
            return rec

    def maybe_heartbeat(self) -> dict[str, Any] | None:
        with self._lock:
            opened = parse_time(self.segment_opened_at)
            if self.clock() - opened >= timedelta(seconds=self.heartbeat_seconds):
                return self.close_segment(heartbeat=True)
        return None

    def rotate_key(self, new_signer: Signer) -> dict[str, Any]:
        with self._lock:
            rec = self._write({"kind": "key_rotation",
                               "new_key": {"id": new_signer.key_id, "public": new_signer.public_key}})
            self.signer = new_signer
            return rec

    # -- anchoring --------------------------------------------------------------------
    def anchor_pending(self) -> int:
        """Anchor every closed segment that has no receipt yet. Returns how many were anchored."""
        if not self.anchors:
            return 0
        done = 0
        while True:
            try:
                seg = self._anchor_queue.get_nowait()
            except queue.Empty:
                break
            if seg is None or seg["seq"] not in self.pending_anchor:
                continue
            if self._anchor_one(seg):
                done += 1
            else:
                self._anchor_queue.put(seg)
                break
        return done

    def _anchor_one(self, seg: dict[str, Any]) -> bool:
        """Run every configured anchor not yet done for this segment. True when all are done."""
        h = record_hash(seg)
        done = self.anchor_done.setdefault(seg["seq"], set())
        all_ok = True
        for anchor in self.anchors:
            if anchor.type in done:
                continue
            try:
                receipt = anchor.anchor(segment_hash=h, chain=self.chain_id, segment_seq=seg["seq"])
            except Exception as exc:  # noqa: BLE001 - anchoring must never break the agent
                log.warning("gleipnir: %s anchoring of segment %s failed, will retry: %s", anchor.type, seg["seq"], exc)
                all_ok = False
                continue
            with self._lock:
                self._write({"kind": "anchor", "anchor": {"segment_seq": seg["seq"], "segment_hash": h,
                                                          "type": anchor.type, "receipt": receipt}})
                done.add(anchor.type)
        if all_ok:
            self.pending_anchor.pop(seg["seq"], None)
        return all_ok

    # -- sinks ------------------------------------------------------------------------
    @staticmethod
    def sink_key(sink: Any) -> str:
        d = sink.describe()
        return f"{d.get('type')}:{d.get('target')}"

    def _init_sinks(self) -> None:
        if not self.sinks:
            return
        state: dict[str, int] = {}
        if self._state_path is not None and self._state_path.exists():
            try:
                state = json.loads(self._state_path.read_text())
            except (OSError, ValueError):
                state = {}
        for sink in self.sinks:
            self._delivered[self.sink_key(sink)] = int(state.get(self.sink_key(sink), -1))
        lowest = min(self._delivered.values())
        self._recent = [r for r in self.store.read_all() if r["seq"] > lowest] if lowest < self.seq else []

    def deliver(self) -> int:
        """Send records not yet delivered to each sink. Returns how many sinks are fully up to date."""
        if not self.sinks:
            return 0
        with self._sink_lock:
            with self._lock:
                recent = list(self._recent)
            current = 0
            for sink in self.sinks:
                key = self.sink_key(sink)
                batch = [r for r in recent if r["seq"] > self._delivered[key]]
                if not batch:
                    current += 1
                    continue
                try:
                    sink.write(self.chain_id, batch)
                except Exception as exc:  # noqa: BLE001 - delivery must never break the agent
                    log.warning("gleipnir: delivery to %s failed, will retry: %s", key, exc)
                    continue
                self._delivered[key] = batch[-1]["seq"]
                current += 1
            lowest = min(self._delivered.values())
            with self._lock:
                self._recent = [r for r in self._recent if r["seq"] > lowest]
            if self._state_path is not None:
                tmp = self._state_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(self._delivered, sort_keys=True))
                tmp.replace(self._state_path)
            return current

    # -- background -------------------------------------------------------------------
    def _start_background(self) -> None:
        def loop() -> None:
            tick = max(1.0, min(30.0, self.heartbeat_seconds / 10))
            while not self._stop.wait(tick):
                try:
                    self.maybe_heartbeat()
                    self.anchor_pending()
                    self.deliver()
                except Exception as exc:  # noqa: BLE001
                    log.warning("gleipnir: background task failed: %s", exc)

        t = threading.Thread(target=loop, name="gleipnir-chain", daemon=True)
        t.start()
        self._threads.append(t)

    def flush(self) -> None:
        """Close the open segment and anchor everything pending (blocking)."""
        with self._lock:
            if self.open_members:
                self.close_segment()
        self.anchor_pending()
        self.deliver()

    def close(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        self.flush()
