"""MCP client middleware: record every ``call_tool`` on an MCP ClientSession.

Works with the official ``mcp`` Python SDK and any object with a compatible
``async call_tool(name, arguments=None, ...)`` method; ``mcp`` itself is not imported.

    from gleipnir.adapters.mcp import instrument_session

    async with ClientSession(read, write) as session:
        instrument_session(session, rec, system="payments-mcp",
                           verify_outcome={"refund": check_refund})
"""

from __future__ import annotations

import functools
from collections.abc import Mapping
from typing import Any

from ..recorder import Call, Outcome, Recorder, RedactSpec, _coerce_outcome, _error_text
from ..util import new_id


def instrument_session(
    session: Any,
    recorder: Recorder,
    *,
    system: str,
    redact: RedactSpec = None,
    verify_outcome: Mapping[str, Any] | None = None,
) -> Any:
    """Wrap ``session.call_tool`` in place and return the session.

    ``verify_outcome`` maps tool names to sync or async callbacks ``(Call, result) -> Outcome``.
    A result with ``isError`` set is recorded as an error response.
    """
    if getattr(session, "_gleipnir_instrumented", False):
        return session
    original = session.call_tool
    checks = dict(verify_outcome or {})

    @functools.wraps(original)
    async def call_tool(name: str, arguments: dict[str, Any] | None = None, *args: Any, **kwargs: Any) -> Any:
        action_id = new_id("act")
        start = recorder.clock()
        call_args = dict(arguments or {})
        try:
            result = await original(name, arguments, *args, **kwargs)
        except BaseException as exc:
            recorder.record_action(tool=name, system=system, args=call_args, error=exc, start=start,
                                   redact=redact, action_id=action_id)
            raise
        end = recorder.clock()
        outcome = None
        is_error = bool(getattr(result, "isError", False))
        fn = checks.get(name)
        if fn is not None and not is_error:
            try:
                value = fn(Call(action_id, name, system, call_args), result)
                if hasattr(value, "__await__"):
                    value = await value
                outcome = _coerce_outcome(value)
            except Exception as exc:  # noqa: BLE001
                outcome = Outcome("error", detail=_error_text(exc))
        if is_error:
            recorder.record_action(tool=name, system=system, args=call_args,
                                   error=f"tool returned isError: {_content_text(result)}", start=start, end=end,
                                   redact=redact, action_id=action_id)
        else:
            recorder.record_action(tool=name, system=system, args=call_args, response=result, outcome=outcome,
                                   start=start, end=end, redact=redact, action_id=action_id)
        return result

    session.call_tool = call_tool
    session._gleipnir_instrumented = True
    return session


def _content_text(result: Any) -> str:
    parts = []
    for c in getattr(result, "content", None) or []:
        text = getattr(c, "text", None)
        if text:
            parts.append(text)
    return " ".join(parts)[:500]
