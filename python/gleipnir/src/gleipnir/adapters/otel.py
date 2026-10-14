"""OpenTelemetry span exporter: turn GenAI tool-call spans into Gleipnir records.

For vendors with their own harness that already emit OpenTelemetry spans following the GenAI
semantic conventions (https://github.com/open-telemetry/semantic-conventions-genai). Requires
``opentelemetry-sdk``; it is imported only for the base class and the export result.

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from gleipnir.adapters.otel import GleipnirSpanExporter

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(
        GleipnirSpanExporter(rec, system="payments-api", redact=["card_number"])))

    with tracer.start_as_current_span("execute_tool issue_refund", attributes={
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "issue_refund",
        "gen_ai.tool.call.id": call_id,
        "gen_ai.tool.call.arguments": json.dumps(args),   # opt-in attribute; recorded as args
        "gleipnir.system": "payments-api",                # optional per-span system
    }) as span:
        result = issue_refund(**args)
        span.set_attribute("gen_ai.tool.call.result", json.dumps(result))

Mapping:

- Spans with ``gen_ai.operation.name == "execute_tool"`` become one action each. Tool name from
  ``gen_ai.tool.name`` (falling back to the span name), args from ``gen_ai.tool.call.arguments``
  (a JSON string or mapping; ``{}`` when the attribute is not captured), response body from
  ``gen_ai.tool.call.result``, times from the span's start and end.
- The system is the span attribute named by ``system_attr`` (default ``gleipnir.system``), then
  ``systems[tool_name]``, then ``system``.
- Span status ERROR becomes an error response, using the status description, ``error.type`` or the
  recorded ``exception`` event.
- Context: ``trace_id`` and ``span_id`` (hex, as in W3C trace context), ``tool_call_id`` from
  ``gen_ai.tool.call.id`` and ``session`` from ``gen_ai.conversation.id``.
- Model spans (``chat``, ``generate_content``, ``text_completion``) are not records on their own.
  The latest one that ended in the same trace before a tool span started is attached to that tool's
  record, as ``calls=[{"service": provider, "endpoint": operation, "model": ..., "span_id": ...}]``
  and as ``model={"provider", "name"}``. Provider comes from ``gen_ai.provider.name`` (or the
  deprecated ``gen_ai.system``).

Exporting never raises into the tracing pipeline; a failed record is logged and the batch reports
``FAILURE``. If you also use the MCP middleware or ``Recorder.tool`` on the same calls, each call is
recorded twice: pick one hook point per tool.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ..recorder import Call, Recorder, RedactSpec
from ..util import new_id
from ._common import check_outcome, logger, parse_args, parse_json

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan

try:  # the base class is only needed when opentelemetry-sdk is installed
    from opentelemetry.sdk.trace.export import SpanExporter as _SpanExporterBase
except ImportError:  # pragma: no cover - exercised only without the extra
    _SpanExporterBase = object  # type: ignore[assignment,misc]

MODEL_OPERATIONS = frozenset({"chat", "generate_content", "text_completion"})
_MAX_TRACES = 1024
_MAX_MODEL_SPANS_PER_TRACE = 32


class GleipnirSpanExporter(_SpanExporterBase):  # type: ignore[misc,valid-type]
    """SpanExporter that records GenAI ``execute_tool`` spans through ``recorder``.

    ``verify_outcome`` maps tool names to sync callbacks ``(Call, result) -> Outcome``; ``result``
    is the decoded ``gen_ai.tool.call.result``. Export runs in the span processor's thread, so
    callbacks must be synchronous.
    """

    def __init__(
        self,
        recorder: Recorder,
        *,
        system: str = "unknown",
        system_attr: str = "gleipnir.system",
        systems: Mapping[str, str] | None = None,
        redact: RedactSpec = None,
        verify_outcome: Mapping[str, Callable[[Call, Any], Any]] | None = None,
    ):
        if _SpanExporterBase is object:
            raise ImportError("GleipnirSpanExporter needs opentelemetry-sdk: pip install 'gleipnir-sdk[otel]'")
        self.recorder = recorder
        self.system = system
        self.system_attr = system_attr
        self.systems = dict(systems or {})
        self.redact = redact
        self.checks = dict(verify_outcome or {})
        self._models: OrderedDict[int, list[tuple[int, dict[str, Any], dict[str, Any]]]] = OrderedDict()
        self._lock = threading.Lock()
        self._shutdown = False

    # -- SpanExporter ------------------------------------------------------------------------
    def export(self, spans: Sequence[ReadableSpan]) -> Any:
        from opentelemetry.sdk.trace.export import SpanExportResult

        if self._shutdown:
            return SpanExportResult.FAILURE
        ok = True
        for span in spans:
            try:
                attrs = span.attributes or {}
                op = attrs.get("gen_ai.operation.name")
                if op in MODEL_OPERATIONS:
                    self._remember_model(span, attrs, str(op))
                elif op == "execute_tool":
                    self._record_tool(span, attrs)
            except Exception:  # noqa: BLE001 - never break the tracing pipeline
                logger.exception("gleipnir: failed to record span %r", getattr(span, "name", None))
                ok = False
        return SpanExportResult.SUCCESS if ok else SpanExportResult.FAILURE

    def shutdown(self) -> None:
        self._shutdown = True
        self.recorder.flush()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        self.recorder.flush()
        return True

    # -- mapping ------------------------------------------------------------------------------
    def _remember_model(self, span: ReadableSpan, attrs: Mapping[str, Any], op: str) -> None:
        ctx = span.get_span_context()
        if ctx is None:
            return
        provider = attrs.get("gen_ai.provider.name") or attrs.get("gen_ai.system")
        request_model = attrs.get("gen_ai.request.model")
        response_model = attrs.get("gen_ai.response.model")
        call: dict[str, Any] = {"service": str(provider or "unknown"), "endpoint": op,
                                "span_id": format(ctx.span_id, "016x")}
        if request_model:
            call["model"] = str(request_model)
        if response_model and response_model != request_model:
            call["response_model"] = str(response_model)
        model: dict[str, Any] = {}
        if provider:
            model["provider"] = str(provider)
        if response_model or request_model:
            model["name"] = str(response_model or request_model)
        with self._lock:
            entries = self._models.setdefault(ctx.trace_id, [])
            self._models.move_to_end(ctx.trace_id)
            entries.append((span.end_time or 0, call, model))
            del entries[:-_MAX_MODEL_SPANS_PER_TRACE]
            while len(self._models) > _MAX_TRACES:
                self._models.popitem(last=False)

    def _model_before(self, trace_id: int, start_ns: int) -> tuple[dict[str, Any], dict[str, Any]] | None:
        with self._lock:
            entries = self._models.get(trace_id) or []
            before = [e for e in entries if e[0] <= start_ns]
        if not before:
            return None
        _, call, model = max(before, key=lambda e: e[0])
        return call, model

    def _record_tool(self, span: ReadableSpan, attrs: Mapping[str, Any]) -> None:
        from opentelemetry.trace import StatusCode

        tool = str(attrs.get("gen_ai.tool.name") or _strip_prefix(span.name))
        system = str(attrs.get(self.system_attr) or self.systems.get(tool) or self.system)
        args = parse_args(attrs.get("gen_ai.tool.call.arguments"))
        result = parse_json(attrs.get("gen_ai.tool.call.result"))
        start, end = _dt(span.start_time), _dt(span.end_time)

        error = None
        status = span.status
        if status is not None and status.status_code == StatusCode.ERROR:
            error = _span_error(span, attrs)

        ctx_values: dict[str, Any] = {}
        sctx = span.get_span_context()
        calls = None
        if sctx is not None and sctx.is_valid:
            ctx_values["trace_id"] = format(sctx.trace_id, "032x")
            ctx_values["span_id"] = format(sctx.span_id, "016x")
            found = self._model_before(sctx.trace_id, span.start_time or 0)
            if found:
                call, model = found
                calls = [call]
                if model:
                    ctx_values["model"] = model
        if attrs.get("gen_ai.tool.call.id"):
            ctx_values["tool_call_id"] = str(attrs["gen_ai.tool.call.id"])
        if attrs.get("gen_ai.conversation.id"):
            ctx_values["session"] = str(attrs["gen_ai.conversation.id"])

        action_id = new_id("act")
        outcome = None
        if error is None:
            outcome = check_outcome(self.checks, Call(action_id, tool, system, args), result)
        with self.recorder.context(**ctx_values):
            self.recorder.record_action(tool=tool, system=system, args=args, response=result, error=error,
                                        outcome=outcome, start=start, end=end, redact=self.redact,
                                        action_id=action_id, calls=calls)


def _strip_prefix(name: str) -> str:
    return name[len("execute_tool "):] if name.startswith("execute_tool ") else name


def _dt(ns: int | None) -> datetime | None:
    if ns is None:
        return None
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)


def _span_error(span: ReadableSpan, attrs: Mapping[str, Any]) -> str:
    for event in span.events or ():
        if event.name == "exception":
            ea = event.attributes or {}
            etype, msg = ea.get("exception.type"), ea.get("exception.message")
            if etype or msg:
                return f"{etype or 'Exception'}: {msg or ''}".rstrip(": ")
    desc = span.status.description if span.status is not None else None
    etype = attrs.get("error.type")
    if etype and desc:
        return f"{etype}: {desc}"
    return str(desc or etype or "span status ERROR")
