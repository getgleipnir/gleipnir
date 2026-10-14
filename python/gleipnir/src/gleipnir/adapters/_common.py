"""Helpers shared by the framework adapters."""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Mapping
from typing import Any

from ..recorder import Call, Outcome, _coerce_outcome, _error_text

logger = logging.getLogger("gleipnir.adapters")


def parse_args(raw: Any) -> dict[str, Any]:
    """Tool arguments as a dict: JSON objects are decoded, anything else is kept under ``"input"``."""
    if raw is None:
        return {}
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, (str, bytes, bytearray)):
        try:
            value = json.loads(raw)
        except ValueError:
            return {"input": raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "replace")}
        return dict(value) if isinstance(value, dict) else {"input": value}
    return {"input": raw}


def parse_json(raw: Any) -> Any:
    """Decode a JSON string if it is one, otherwise return the value unchanged."""
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return raw
    return raw


def check_outcome(checks: Mapping[str, Any], call: Call, result: Any) -> Outcome | None:
    """Run a sync ``verify_outcome`` callback for ``call.tool`` if one is registered."""
    fn = checks.get(call.tool)
    if fn is None:
        return None
    try:
        value = fn(call, result)
        if inspect.isawaitable(value):
            close = getattr(value, "close", None)
            if close is not None:
                close()
            return Outcome("error", detail="async verify_outcome is not supported by this adapter")
        return _coerce_outcome(value)
    except Exception as exc:  # noqa: BLE001 - a failing check must not break the agent
        return Outcome("error", detail=_error_text(exc))


async def acheck_outcome(checks: Mapping[str, Any], call: Call, result: Any) -> Outcome | None:
    """Run a sync or async ``verify_outcome`` callback for ``call.tool`` if one is registered."""
    fn = checks.get(call.tool)
    if fn is None:
        return None
    try:
        value = fn(call, result)
        if inspect.isawaitable(value):
            value = await value
        return _coerce_outcome(value)
    except Exception as exc:  # noqa: BLE001
        return Outcome("error", detail=_error_text(exc))
