"""Anchors publish segment hashes outside the vendor's control.

``LocalFileAnchor`` is for tests and demos: it writes to a local append-only log, so it
is not independent of the vendor. ``RekorAnchor`` publishes to Sigstore Rekor.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Protocol

from gleipnir_verify.anchors import local_log_entry_hash

from .util import Clock, iso, utcnow


class Anchor(Protocol):
    type: str

    def anchor(self, *, segment_hash: str, chain: str, segment_seq: int) -> dict[str, Any]:
        """Publish ``segment_hash`` and return a receipt (JSON object)."""
        ...


class LocalFileAnchor:
    type = "local"

    def __init__(self, path: str | Path, clock: Clock = utcnow):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self._lock = threading.Lock()

    def _last(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        last = None
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        return json.loads(last) if last else None

    def anchor(self, *, segment_hash: str, chain: str, segment_seq: int) -> dict[str, Any]:
        with self._lock:
            last = self._last()
            entry: dict[str, Any] = {
                "v": 1,
                "index": 0 if last is None else last["index"] + 1,
                "chain": chain,
                "segment_seq": segment_seq,
                "segment_hash": segment_hash,
                "time": iso(self.clock()),
            }
            if last is not None:
                entry["prev"] = last["hash"]
            entry["hash"] = local_log_entry_hash(entry)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return {"index": entry["index"], "entry_hash": entry["hash"], "time": entry["time"],
                    "log": self.path.name}
