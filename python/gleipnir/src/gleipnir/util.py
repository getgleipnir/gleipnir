"""Small helpers: ids, clocks, JSON conversion."""

from __future__ import annotations

import dataclasses
import math
import os
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """RFC 3339 UTC with millisecond precision and a Z suffix."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def new_id(prefix: str) -> str:
    """Time-ordered unique id: <prefix>_<ms since epoch, hex><80 random bits, hex>."""
    return f"{prefix}_{int(time.time() * 1000):012x}{os.urandom(10).hex()}"


def to_jsonable(value: Any, _depth: int = 0) -> Any:
    """Convert a tool argument or response into a JSON value that JCS can encode."""
    if _depth > 50:
        return {"repr": "<max depth>"}
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return {"float": repr(value)}
        return value
    if isinstance(value, dict):
        return {str(k): to_jsonable(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=repr) if isinstance(value, (set, frozenset)) else value
        return [to_jsonable(v, _depth + 1) for v in items]
    if isinstance(value, (bytes, bytearray)):
        return {"bytes_len": len(value)}
    if isinstance(value, datetime):
        return iso(value) if value.tzinfo else value.isoformat()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return to_jsonable(dataclasses.asdict(value), _depth + 1)
    dump = getattr(value, "model_dump", None)  # pydantic v2
    if callable(dump):
        try:
            return to_jsonable(dump(mode="json"), _depth + 1)
        except Exception:  # noqa: BLE001
            pass
    as_dict = getattr(value, "dict", None)  # pydantic v1 / similar
    if callable(as_dict):
        try:
            return to_jsonable(as_dict(), _depth + 1)
        except Exception:  # noqa: BLE001
            pass
    return {"repr": repr(value)[:2000]}
