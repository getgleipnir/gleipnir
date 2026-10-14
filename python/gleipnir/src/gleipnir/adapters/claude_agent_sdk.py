"""Claude Agent SDK adapter: record tool calls with PreToolUse / PostToolUse hooks.

Works with ``claude-agent-sdk``; it is imported only to build the ``HookMatcher`` objects.

    from claude_agent_sdk import ClaudeAgentOptions, query
    from gleipnir.adapters.claude_agent_sdk import gleipnir_hooks

    options = ClaudeAgentOptions(
        allowed_tools=["Bash", "mcp__payments__issue_refund"],
        hooks=gleipnir_hooks(rec, system="claude-code", redact=["card_number"],
                             verify_outcome={"mcp__payments__issue_refund": check_refund}),
    )
    async for message in query(prompt="Refund order A-1", options=options):
        ...

To combine with your own hooks, extend the lists: ``hooks = gleipnir_hooks(...)`` then
``hooks["PreToolUse"].append(HookMatcher(matcher="Bash", hooks=[my_guard]))``.

Mapping:

- ``PreToolUse`` notes the start time per ``tool_use_id``; ``PostToolUse`` records an ok response
  with ``tool_response``; ``PostToolUseFailure`` records an error response with ``error``.
  Without a matching ``PreToolUse`` (for example a hook added mid-run) the start time is derived
  from ``duration_ms``.
- System: ``systems[tool_name]``, then for MCP tools (``mcp__<server>__<tool>``) the server name,
  then ``system``.
- Context: ``session`` from ``session_id``, ``tool_call_id`` from ``tool_use_id`` and, inside a
  sub-agent, ``run_id`` is set to ``subagent:<agent_id>``.

The hooks only observe: they always return ``{}``, so they never allow, deny or modify a tool call.
A failure inside recording is logged and swallowed; the agent continues. The hooks run in the SDK
process, which sees the tool's input and output as the CLI reports them, not the external system's
own state: use ``verify_outcome`` to read back from the system of record.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping
from datetime import timedelta
from typing import Any

from ..recorder import Call, Recorder, RedactSpec
from ..util import new_id
from ._common import acheck_outcome, logger

_MAX_PENDING = 4096


def gleipnir_hooks(
    recorder: Recorder,
    *,
    system: str = "claude-agent",
    systems: Mapping[str, str] | None = None,
    matcher: str | None = None,
    redact: RedactSpec = None,
    verify_outcome: Mapping[str, Callable[[Call, Any], Any]] | None = None,
) -> dict[str, list[Any]]:
    """Return a ``hooks`` dict for ``ClaudeAgentOptions`` that records every tool call.

    ``matcher`` limits recording to matching tool names (the SDK's matcher syntax, e.g.
    ``"Bash|mcp__payments__.*"``); ``None`` records all tools. ``verify_outcome`` maps tool names to
    sync or async callbacks ``(Call, tool_response) -> Outcome``.
    """
    from claude_agent_sdk import HookMatcher

    h = GleipnirHooks(recorder, system=system, systems=systems, redact=redact, verify_outcome=verify_outcome)
    return {
        "PreToolUse": [HookMatcher(matcher=matcher, hooks=[h.pre_tool_use])],
        "PostToolUse": [HookMatcher(matcher=matcher, hooks=[h.post_tool_use])],
        "PostToolUseFailure": [HookMatcher(matcher=matcher, hooks=[h.post_tool_use_failure])],
    }


class GleipnirHooks:
    """The hook callbacks behind ``gleipnir_hooks``; usable directly with your own matchers.

    Each callback has the SDK's ``HookCallback`` signature ``(input, tool_use_id, context)``.
    """

    def __init__(
        self,
        recorder: Recorder,
        *,
        system: str = "claude-agent",
        systems: Mapping[str, str] | None = None,
        redact: RedactSpec = None,
        verify_outcome: Mapping[str, Callable[[Call, Any], Any]] | None = None,
    ):
        self.recorder = recorder
        self.system = system
        self.systems = dict(systems or {})
        self.redact = redact
        self.checks = dict(verify_outcome or {})
        self._pending: OrderedDict[str, tuple[Any, str]] = OrderedDict()
        self._lock = threading.Lock()

    def system_for(self, tool: str) -> str:
        if tool in self.systems:
            return self.systems[tool]
        if tool.startswith("mcp__"):
            parts = tool.split("__")
            if len(parts) >= 3 and parts[1]:
                return parts[1]
        return self.system

    async def pre_tool_use(self, input: Mapping[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
        try:
            key = tool_use_id or input.get("tool_use_id")
            if key:
                with self._lock:
                    self._pending[str(key)] = (self.recorder.clock(), new_id("act"))
                    while len(self._pending) > _MAX_PENDING:
                        self._pending.popitem(last=False)
        except Exception:  # noqa: BLE001 - never break the agent
            logger.exception("gleipnir: PreToolUse hook failed")
        return {}

    async def post_tool_use(self, input: Mapping[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
        await self._record(input, tool_use_id, error=None)
        return {}

    async def post_tool_use_failure(self, input: Mapping[str, Any], tool_use_id: str | None,
                                    context: Any) -> dict[str, Any]:
        error = str(input.get("error") or "tool failed")
        if input.get("is_interrupt"):
            error = "interrupted: " + error
        await self._record(input, tool_use_id, error=error)
        return {}

    async def _record(self, input: Mapping[str, Any], tool_use_id: str | None, error: str | None) -> None:
        try:
            key = str(tool_use_id or input.get("tool_use_id") or "")
            with self._lock:
                pending = self._pending.pop(key, None) if key else None
            end = self.recorder.clock()
            if pending is not None:
                start, action_id = pending
            else:
                ms = input.get("duration_ms")
                start = end - timedelta(milliseconds=ms) if isinstance(ms, (int, float)) else end
                action_id = new_id("act")
            tool = str(input.get("tool_name") or "unknown")
            system = self.system_for(tool)
            args = dict(input.get("tool_input") or {})
            response = input.get("tool_response")
            outcome = None
            if error is None:
                outcome = await acheck_outcome(self.checks, Call(action_id, tool, system, args), response)
            ctx: dict[str, Any] = {}
            if input.get("session_id"):
                ctx["session"] = str(input["session_id"])
            if key:
                ctx["tool_call_id"] = key
            if input.get("agent_id"):
                ctx["run_id"] = f"subagent:{input['agent_id']}"
            with self.recorder.context(**ctx):
                self.recorder.record_action(tool=tool, system=system, args=args, response=response, error=error,
                                            outcome=outcome, start=start, end=end, redact=self.redact,
                                            action_id=action_id)
        except Exception:  # noqa: BLE001 - never break the agent
            logger.exception("gleipnir: PostToolUse hook failed")
