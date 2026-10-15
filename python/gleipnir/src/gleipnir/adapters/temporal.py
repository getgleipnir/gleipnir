"""Temporal adapter: a worker interceptor that records every activity execution.

Temporal workflows must be deterministic, so this adapter never runs in workflow code: it only
intercepts activities, which is where side effects (API calls, payments, emails) happen anyway.
Workflow replay never re-executes activities, so replaying history writes no records. Requires
``temporalio``; it is imported only for the interceptor base classes and ``activity.info()``.

    from temporalio.worker import Worker
    from gleipnir.adapters.temporal import GleipnirInterceptor

    worker = Worker(client, task_queue="refunds", workflows=[RefundWorkflow],
                    activities=[issue_refund, notify_customer],
                    interceptors=[GleipnirInterceptor(
                        rec, system_for_activity={"issue_refund": "payments-api"},
                        redact=["card_number"], verify_outcome={"issue_refund": check_refund})])

Mapping:

- One action per activity *attempt*, so retries are visible: ``tool.name`` is the activity type,
  ``tool.system`` comes from ``system_for_activity`` (a mapping, or a callable taking the activity
  type and returning a system or ``None``), then ``system``.
- ``args``: the activity's arguments bound to its parameter names (``{"args": [...]}`` when they
  cannot be bound, for example dynamic activities); dataclasses and pydantic models become objects.
- Response: the return value; or an error with the exception, its ``ApplicationError`` type, and
  whether Temporal will retry, e.g. ``"ApplicationError: card declined [type=Declined,
  non_retryable] [attempt 1/3, final]"``. Cancellation is recorded as an error and re-raised. An
  activity that completes asynchronously (``activity.raise_complete_async()``) is recorded as ok
  with body ``{"completion": "async"}``; the later completion happens outside the worker.
- Context: ``session`` = workflow id, ``run_id`` = workflow run id and ``tool_call_id`` =
  ``"<activity id>#<attempt>"`` (the activity id is the same across retries). Other context set with
  ``rec.context(...)`` around the worker (identity, versions, model) is kept; these three keys are
  overwritten per attempt. Local activities are recorded the same way.
- ``verify_outcome`` maps activity types to sync or async callbacks ``(Call, result) -> Outcome``,
  run after a successful attempt, on the activity's event loop.

Recording never changes the activity's result or exception; a failure inside recording is logged.
Only ``intercept_activity`` is implemented: ``workflow_interceptor_class`` returns ``None``.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from typing import Any

from ..recorder import Call, Recorder, RedactSpec, _error_text
from ..util import new_id
from ._common import acheck_outcome, logger

try:  # the base classes are only needed when temporalio is installed
    from temporalio.worker import ActivityInboundInterceptor as _InboundBase
    from temporalio.worker import Interceptor as _InterceptorBase
except ImportError:  # pragma: no cover - exercised only without the extra
    _InterceptorBase = object  # type: ignore[assignment,misc]
    _InboundBase = object  # type: ignore[assignment,misc]

SystemFor = Callable[[str], Any] | Mapping[str, str]


class GleipnirInterceptor(_InterceptorBase):  # type: ignore[misc,valid-type]
    """Temporal worker interceptor that records each activity attempt through ``recorder``."""

    def __init__(
        self,
        recorder: Recorder,
        *,
        system: str = "temporal",
        system_for_activity: SystemFor | None = None,
        redact: RedactSpec = None,
        verify_outcome: Mapping[str, Callable[[Call, Any], Any]] | None = None,
    ):
        if _InterceptorBase is object:
            raise ImportError("GleipnirInterceptor needs temporalio: pip install 'gleipnir-sdk[temporal]'")
        self.recorder = recorder
        self.system = system
        self.system_for_activity = system_for_activity
        self.redact = redact
        self.checks = dict(verify_outcome or {})

    def intercept_activity(self, next: Any) -> Any:  # noqa: A002 - Temporal's parameter name
        return _ActivityInbound(next, self)

    def system_for(self, activity_type: str) -> str:
        chooser = self.system_for_activity
        try:
            if isinstance(chooser, Mapping):
                found = chooser.get(activity_type)
            elif callable(chooser):
                found = chooser(activity_type)
            else:
                found = None
        except Exception:  # noqa: BLE001 - a bad chooser must not break the activity
            logger.exception("gleipnir: system_for_activity failed for %r", activity_type)
            found = None
        return str(found) if found else self.system


class _ActivityInbound(_InboundBase):  # type: ignore[misc,valid-type]
    def __init__(self, next: Any, owner: GleipnirInterceptor):  # noqa: A002
        super().__init__(next)
        self.owner = owner

    async def execute_activity(self, input: Any) -> Any:  # noqa: A002
        from temporalio import activity

        rec = self.owner.recorder
        prepared = None
        try:
            prepared = _prepare(self.owner, activity.info(), input)
        except Exception:  # noqa: BLE001 - never break the activity
            logger.exception("gleipnir: could not read activity info")
        start = rec.clock()
        try:
            result = await self.next.execute_activity(input)
        except BaseException as exc:
            if prepared is not None:
                if type(exc).__name__ == "CompleteAsyncError":
                    self._record(prepared, start, {"completion": "async"}, None)
                else:
                    self._record(prepared, start, None, _failure_text(exc, prepared["info"]))
            raise
        if prepared is not None:
            outcome = None
            if self.owner.checks:
                outcome = await acheck_outcome(self.owner.checks, Call(prepared["action_id"], prepared["tool"],
                                                                       prepared["system"], prepared["args"]), result)
            self._record(prepared, start, result, None, outcome)
        return result

    def _record(self, p: dict[str, Any], start: Any, result: Any, error: str | None, outcome: Any = None) -> None:
        rec = self.owner.recorder
        try:
            with rec.context(**p["ctx"]):
                rec.record_action(tool=p["tool"], system=p["system"], args=p["args"], response=result, error=error,
                                  outcome=outcome, start=start, redact=self.owner.redact, action_id=p["action_id"])
        except Exception:  # noqa: BLE001
            logger.exception("gleipnir: failed to record activity %r", p.get("tool"))


def _prepare(owner: GleipnirInterceptor, info: Any, input: Any) -> dict[str, Any]:  # noqa: A002
    tool = str(info.activity_type)
    ctx: dict[str, Any] = {"tool_call_id": f"{info.activity_id}#{info.attempt}"}
    if info.workflow_id:
        ctx["session"] = str(info.workflow_id)
    if info.workflow_run_id:
        ctx["run_id"] = str(info.workflow_run_id)
    return {"tool": tool, "system": owner.system_for(tool), "args": _bind_args(input.fn, input.args), "ctx": ctx,
            "info": info, "action_id": new_id("act")}


def _bind_args(fn: Any, args: Any) -> dict[str, Any]:
    values = list(args or ())
    try:
        bound = inspect.signature(fn).bind(*values)
    except (TypeError, ValueError):
        return {"args": values} if values else {}
    out = dict(bound.arguments)
    out.pop("self", None)
    for name, param in inspect.signature(fn).parameters.items():
        if param.kind is inspect.Parameter.VAR_POSITIONAL and name in out:
            out[name] = list(out[name])
    return out


def _failure_text(exc: BaseException, info: Any) -> str:
    is_app = type(exc).__name__ == "ApplicationError"
    message = getattr(exc, "message", None) if is_app else None
    text = f"ApplicationError: {message}" if isinstance(message, str) else _error_text(exc)
    tags = []
    # Temporal matches non_retryable_error_types against ApplicationError.type, or the class name
    etype = getattr(exc, "type", None) if is_app else type(exc).__name__
    non_retryable = is_app and bool(getattr(exc, "non_retryable", False))
    if is_app and etype:
        tags.append(f"type={etype}")
    if non_retryable:
        tags.append("non_retryable")
    if tags:
        text += " [" + ", ".join(tags) + "]"
    retry = getattr(info, "retry_policy", None)
    maximum = getattr(retry, "maximum_attempts", 0) or 0
    attempt = int(getattr(info, "attempt", 1) or 1)
    cancelled = type(exc).__name__ == "CancelledError"
    non_retryable_types = set(getattr(retry, "non_retryable_error_types", None) or ())
    if cancelled:
        state = "cancelled"
    elif non_retryable or (etype and etype in non_retryable_types) or (maximum and attempt >= maximum):
        state = "final"
    elif retry is None:
        state = "retry per server policy"
    else:
        state = "will retry"
    of = f"/{maximum}" if maximum else ""
    return f"{text} [attempt {attempt}{of}, {state}]"[:2000]
