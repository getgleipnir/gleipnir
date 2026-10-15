"""Record storage. The default store is an append-only JSON Lines file per chain."""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

_LINE_SEPARATORS = {"\u2028": "\\u2028", "\u2029": "\\u2029", "\u0085": "\\u0085"}


def _dumps_line(record: dict[str, Any]) -> str:
    """One JSON line. Unicode line separators are escaped so no tool splits a record in two."""
    text = json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    for ch, esc in _LINE_SEPARATORS.items():
        text = text.replace(ch, esc)
    return text + "\n"


class Store(Protocol):
    def append(self, record: dict[str, Any]) -> None: ...

    def read_all(self) -> list[dict[str, Any]]: ...


class JsonlStore:
    def __init__(self, directory: str | Path, fsync: bool = True):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "records.jsonl"
        self.fsync = fsync
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> None:
        line = _dumps_line(record)
        with self._lock, open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            if self.fsync:
                os.fsync(fh.fileno())

    def __iter__(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return iter(())
        return (json.loads(line) for line in self.path.read_text(encoding="utf-8").split("\n") if line.strip())

    def read_all(self) -> list[dict[str, Any]]:
        return list(iter(self))


class MemoryStore:
    """In-memory store for tests."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def append(self, record: dict[str, Any]) -> None:
        self.records.append(json.loads(json.dumps(record)))

    def read_all(self) -> list[dict[str, Any]]:
        return [json.loads(json.dumps(r)) for r in self.records]
