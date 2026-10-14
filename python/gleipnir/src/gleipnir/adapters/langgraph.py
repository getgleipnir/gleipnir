"""LangChain / LangGraph adapter: a callback handler that records every tool run.

Works with ``langchain-core`` (``BaseCallbackHandler``), so it covers LangChain agents, LangGraph's
``ToolNode`` / ``create_react_agent`` and any tool invoked through ``BaseTool.invoke``.

    from gleipnir.adapters.langgraph import GleipnirCallbackHandler

    handler = GleipnirCallbackHandler(rec, system="payments-api", redact=["card_number"],
                                      verify_outcome={"issue_refund": check_refund})
    graph.invoke({"messages": [("user", "Refund order A-1")]}, config={"callbacks": [handler]})

Mapping:

- ``on_tool_start`` notes the start time, tool name (``serialized["name"]`` or the run ``name``) and
  arguments (``inputs`` when LangChain passes them, else ``input_str`` parsed as JSON) per ``run_id``.
- ``on_tool_end`` records an ok response. A ``ToolMessage`` output is recorded as its ``content``
  (plus ``artifact`` when set); one with ``status="error"`` (a tool error handled by
  ``handle_tool_error`` or ``ToolNode``) is recorded as an error response.
- ``on_tool_error`` records an error response. LangChain re-raises the exception itself; the
  handler never raises.
- System: ``metadata["gleipnir_system"]`` on the tool or run, then ``systems[tool_name]``, then
  ``system``.
- Context: ``run_id`` (LangChain's run UUID), ``tool_call_id`` (the model's tool call id),
  ``session`` from ``metadata["thread_id"]`` (LangGraph's checkpointer thread).

Callbacks run synchronously in the tool's thread (``run_inline``) so the record is written before the
tool result goes back to the agent. ``verify_outcome`` callbacks must be synchronous.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping
from typing import Any
from uuid import UUID

from ..recorder import Call, Recorder, RedactSpec
from ..util import new_id
from ._common import check_outcome, logger, parse_args

try:
    from langchain_core.callbacks import BaseCallbackHandler as _HandlerBase
except ImportError:  # pragma: no cover - exercised only without the extra
    _HandlerBase = object  # type: ignore[assignment,misc]

_MAX_PENDING = 4096


class GleipnirCallbackHandler(_HandlerBase):  # type: ignore[misc,valid-type]
    """LangChain callback handler that records tool runs through ``recorder``."""

    run_inline = True
    raise_error = False

    def __init__(
        self,
        recorder: Recorder,
        *,
        system: str = "unknown",
        systems: Mapping[str, str] | None = None,
        redact: RedactSpec = None,
        verify_outcome: Mapping[str, Callable[[Call, Any], Any]] | None = None,
    ):
        if _HandlerBase is object:
            raise ImportError("GleipnirCallbackHandler needs langchain-core: pip install 'gleipnir-sdk[langchain]'")
        super().__init__()
        self.recorder = recorder
        self.system = system
        self.systems = dict(systems or {})
        self.redact = redact
        self.checks = dict(verify_outcome or {})
        self._runs: OrderedDict[UUID, dict[str, Any]] = OrderedDict()
        self._lock = threading.Lock()

    # -- callbacks ---------------------------------------------------------------------------
    def on_tool_start(
        self,
        serialized: dict[str, Any] | None,
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            serialized = serialized or {}
            metadata = metadata or {}
            tool = str(serialized.get("name") or kwargs.get("name") or "unknown")
            system = str(metadata.get("gleipnir_system") or self.systems.get(tool) or self.system)
            args = dict(inputs) if isinstance(inputs, Mapping) else parse_args(input_str)
            ctx: dict[str, Any] = {"run_id": str(run_id)}
            if kwargs.get("tool_call_id"):
                ctx["tool_call_id"] = str(kwargs["tool_call_id"])
            if metadata.get("thread_id"):
                ctx["session"] = str(metadata["thread_id"])
            run = {"tool": tool, "system": system, "args": args, "ctx": ctx, "start": self.recorder.clock(),
                   "action_id": new_id("act")}
            with self._lock:
                self._runs[run_id] = run
                while len(self._runs) > _MAX_PENDING:
                    self._runs.popitem(last=False)
        except Exception:  # noqa: BLE001 - never break the agent
            logger.exception("gleipnir: on_tool_start failed")

    def on_tool_end(self, output: Any, *, run_id: UUID, parent_run_id: UUID | None = None, **kwargs: Any) -> None:
        body, error = _tool_output(output)
        self._finish(run_id, body, error, kwargs)

    def on_tool_error(self, error: BaseException, *, run_id: UUID, parent_run_id: UUID | None = None,
                      **kwargs: Any) -> None:
        self._finish(run_id, None, error, kwargs)

    # -- recording -----------------------------------------------------------------------------
    def _finish(self, run_id: UUID, body: Any, error: BaseException | str | None, kwargs: Mapping[str, Any]) -> None:
        try:
            with self._lock:
                run = self._runs.pop(run_id, None)
            if run is None:  # handler attached after the tool started
                tool = str(kwargs.get("name") or "unknown")
                run = {"tool": tool, "system": self.systems.get(tool, self.system), "args": {},
                       "ctx": {"run_id": str(run_id)}, "start": None, "action_id": new_id("act")}
                if kwargs.get("tool_call_id"):
                    run["ctx"]["tool_call_id"] = str(kwargs["tool_call_id"])
            outcome = None
            if error is None:
                outcome = check_outcome(self.checks, Call(run["action_id"], run["tool"], run["system"], run["args"]),
                                        body)
            with self.recorder.context(**run["ctx"]):
                self.recorder.record_action(tool=run["tool"], system=run["system"], args=run["args"], response=body,
                                            error=error, outcome=outcome, start=run["start"], redact=self.redact,
                                            action_id=run["action_id"])
        except Exception:  # noqa: BLE001 - never break the agent
            logger.exception("gleipnir: tool callback failed")


def _tool_output(output: Any) -> tuple[Any, str | None]:
    """Unwrap a ``ToolMessage`` / ``Command``; return (body, error text if the tool reported an error)."""
    from langchain_core.messages import ToolMessage

    if isinstance(output, ToolMessage):
        content = output.content
        if getattr(output, "status", "success") == "error":
            return None, f"tool returned error: {content}"[:2000]
        artifact = getattr(output, "artifact", None)
        if artifact is not None:
            return {"content": content, "artifact": artifact}, None
        return content, None
    return output, None
