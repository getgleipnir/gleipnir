"""OpenAI Agents SDK adapter: record every function tool invocation.

Works with ``openai-agents`` (import name ``agents``); it is imported only when wrapping.

    from agents import Agent, Runner, function_tool
    from gleipnir.adapters.openai_agents import wrap_tools

    @function_tool
    def issue_refund(order_id: str, amount: int) -> dict: ...

    agent = Agent(name="support", model="gpt-5",
                  tools=wrap_tools([issue_refund, lookup_order], rec, system="payments-api",
                                   systems={"lookup_order": "orders-db"},
                                   verify_outcome={"issue_refund": check_refund}))
    await Runner.run(agent, "Refund order A-1")

``wrap_tools`` returns copies of the ``FunctionTool`` objects (other tool types, such as hosted
tools, are returned unchanged). Each record carries the parsed JSON arguments the model sent, the
tool's return value before the SDK turns it into model text, and as context the tool call id and the
Agents SDK trace and span ids (``trace_...``/``span_...``) when tracing is on. If the agent's
``model`` is a string and no ``model`` was set with ``rec.context``, it is recorded as
``model={"name": ...}``.

For tools made with ``@function_tool``, the wrapper sits inside the SDK's failure handling: an
exception is recorded as an error response and then handled exactly as before (by default the model
receives an error message; with ``failure_error_function=None`` the run fails). Validation of
malformed arguments happens inside the wrapper too, so it is recorded as an error. For a
hand-built ``FunctionTool`` the whole ``on_invoke_tool`` is wrapped; a returned error string is then
recorded as an ok response.
"""

from __future__ import annotations

import copy
import dataclasses
import functools
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any

from ..recorder import _CONTEXT, Call, Recorder, RedactSpec
from ..util import new_id
from ._common import acheck_outcome, parse_args


def wrap_tools(
    tools: Iterable[Any],
    recorder: Recorder,
    *,
    system: str,
    systems: Mapping[str, str] | None = None,
    redact: RedactSpec = None,
    verify_outcome: Mapping[str, Callable[[Call, Any], Any]] | None = None,
) -> list[Any]:
    """Return ``tools`` with every ``FunctionTool`` recorded through ``recorder``.

    ``systems`` overrides ``system`` per tool name. ``verify_outcome`` maps tool names to sync or
    async callbacks ``(Call, result) -> Outcome``.
    """
    return [wrap_tool(t, recorder, system=(systems or {}).get(getattr(t, "name", ""), system), redact=redact,
                      verify_outcome=verify_outcome) for t in tools]


def wrap_tool(
    tool: Any,
    recorder: Recorder,
    *,
    system: str,
    redact: RedactSpec = None,
    verify_outcome: Mapping[str, Callable[[Call, Any], Any]] | None = None,
) -> Any:
    """Return a recorded copy of one ``FunctionTool``; any other object is returned unchanged."""
    from agents import FunctionTool

    if not isinstance(tool, FunctionTool):
        return tool
    checks = dict(verify_outcome or {})
    invoker = tool.on_invoke_tool
    inner = getattr(invoker, "_invoke_tool_impl", None)
    if inner is not None:
        if getattr(inner, "gleipnir_tool", None):
            return tool
        new_invoker = copy.copy(invoker)
        new_invoker._invoke_tool_impl = _recording(inner, recorder, tool.name, system, redact, checks)
        new_invoker._function_tool = None  # rebound to the copy in FunctionTool.__post_init__
        return dataclasses.replace(tool, on_invoke_tool=new_invoker)
    if getattr(invoker, "gleipnir_tool", None):
        return tool
    return dataclasses.replace(tool, on_invoke_tool=_recording(invoker, recorder, tool.name, system, redact, checks))


def _recording(
    fn: Callable[[Any, str], Awaitable[Any]],
    recorder: Recorder,
    default_name: str,
    system: str,
    redact: RedactSpec,
    checks: Mapping[str, Any],
) -> Callable[[Any, str], Awaitable[Any]]:
    @functools.wraps(fn)  # also copies the SDK's marker attributes in fn.__dict__
    async def invoke(ctx: Any, input: str) -> Any:
        name = getattr(ctx, "tool_name", None) or default_name
        args = parse_args(input)
        action_id = new_id("act")
        start = recorder.clock()
        with recorder.context(**_context(ctx)):
            try:
                result = await fn(ctx, input)
            except BaseException as exc:
                recorder.record_action(tool=name, system=system, args=args, error=exc, start=start,
                                       redact=redact, action_id=action_id)
                raise
            end = recorder.clock()
            outcome = await acheck_outcome(checks, Call(action_id, name, system, args), result)
            recorder.record_action(tool=name, system=system, args=args, response=result, outcome=outcome,
                                   start=start, end=end, redact=redact, action_id=action_id)
        return result

    invoke.gleipnir_tool = default_name  # type: ignore[attr-defined]
    return invoke


def _context(ctx: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    call_id = getattr(ctx, "tool_call_id", None)
    if call_id:
        out["tool_call_id"] = str(call_id)
    try:
        from agents.tracing import get_current_span, get_current_trace

        trace = get_current_trace()
        span = get_current_span()
        if trace is not None and getattr(trace, "trace_id", None):
            out["trace_id"] = str(trace.trace_id)
            if span is not None and getattr(span, "span_id", None):
                out["span_id"] = str(span.span_id)
    except Exception:  # noqa: BLE001 - context is best effort
        pass
    model = getattr(getattr(ctx, "agent", None), "model", None)
    if isinstance(model, str) and model and "model" not in (_CONTEXT.get() or {}):
        out["model"] = {"name": model}
    return out
