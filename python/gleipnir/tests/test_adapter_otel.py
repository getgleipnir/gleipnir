import json

import pytest

pytest.importorskip("opentelemetry.sdk.trace")

from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExportResult  # noqa: E402
from opentelemetry.trace import Status, StatusCode  # noqa: E402

import gleipnir  # noqa: E402
from gleipnir.adapters.otel import GleipnirSpanExporter  # noqa: E402


def actions(rec):
    return [r for r in rec.chain.store.read_all() if r["kind"] == "action"]


def setup(rec, **kw):
    exporter = GleipnirSpanExporter(rec, **kw)
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return exporter, provider.get_tracer("test-agent")


def test_tool_span_becomes_record_with_model_call(rec):
    def check(call, result):
        return gleipnir.Outcome.compare({"amount": call.args["amount"]}, {"amount": result["amount"]})

    _, tracer = setup(rec, system="payments-api", redact=["card_number"], verify_outcome={"issue_refund": check})
    with tracer.start_as_current_span("invoke_agent support") as root:
        with tracer.start_as_current_span("chat gpt-5", attributes={
            "gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
            "gen_ai.request.model": "gpt-5", "gen_ai.response.model": "gpt-5-2026-08-01"}):
            pass
        with tracer.start_as_current_span("execute_tool issue_refund", attributes={
            "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "issue_refund",
            "gen_ai.tool.call.id": "call_abc", "gen_ai.conversation.id": "conv-1",
            "gen_ai.tool.call.arguments": json.dumps({"order_id": "A-1", "amount": 4210, "card_number": "4111"}),
        }) as span:
            span.set_attribute("gen_ai.tool.call.result", json.dumps({"refund_id": "R-9", "amount": 4210}))
        trace_id = format(root.get_span_context().trace_id, "032x")
        tool_span_id = format(span.get_span_context().span_id, "016x")

    [a] = actions(rec)
    assert a["tool"] == {"name": "issue_refund", "system": "payments-api"}
    assert a["args"]["order_id"] == "A-1" and a["args"]["card_number"]["redacted"].startswith("hmac-sha256:")
    assert a["response"] == {"status": "ok", "body": {"refund_id": "R-9", "amount": 4210}}
    assert a["outcome"]["check"] == "match"
    assert a["context"] == {"trace_id": trace_id, "span_id": tool_span_id, "tool_call_id": "call_abc",
                            "session": "conv-1"}
    assert a["model"] == {"provider": "openai", "name": "gpt-5-2026-08-01"}
    assert a["calls"][0]["service"] == "openai" and a["calls"][0]["endpoint"] == "chat"
    assert a["calls"][0]["model"] == "gpt-5"
    assert a["t"]["start"] <= a["t"]["end"]


def test_error_status_and_exception(rec):
    _, tracer = setup(rec, system_attr="app.system")
    with pytest.raises(TimeoutError):
        with tracer.start_as_current_span("execute_tool lookup", attributes={
            "gen_ai.operation.name": "execute_tool", "app.system": "crm"}):
            raise TimeoutError("gateway timed out")
    with tracer.start_as_current_span("execute_tool lookup", attributes={
            "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "lookup",
            "error.type": "500"}) as span:
        span.set_status(Status(StatusCode.ERROR, "upstream failed"))
    a, b = actions(rec)
    assert a["tool"] == {"name": "lookup", "system": "crm"}  # name from span name, system from custom attr
    assert a["args"] == {}  # arguments are opt-in in the conventions
    assert a["response"] == {"status": "error", "error": "TimeoutError: gateway timed out"}
    assert b["tool"]["system"] == "unknown"
    assert b["response"] == {"status": "error", "error": "500: upstream failed"}
    assert "calls" not in b and "model" not in b


def test_other_spans_ignored_and_systems_map(rec):
    exporter, tracer = setup(rec, systems={"search": "kb"})
    with tracer.start_as_current_span("GET /health"):
        pass
    with tracer.start_as_current_span("x", attributes={"gen_ai.operation.name": "execute_tool",
                                                       "gen_ai.tool.name": "search",
                                                       "gen_ai.tool.call.arguments": "not json"}):
        pass
    [a] = actions(rec)
    assert a["tool"] == {"name": "search", "system": "kb"}
    assert a["args"] == {"input": "not json"}
    assert exporter.force_flush() is True
    exporter.shutdown()
    assert exporter.export([]) == SpanExportResult.FAILURE


def test_record_failure_does_not_raise(rec, monkeypatch):
    exporter, tracer = setup(rec)

    def boom(**kw):
        raise RuntimeError("disk full")

    monkeypatch.setattr(rec, "record_action", boom)
    with tracer.start_as_current_span("execute_tool t", attributes={"gen_ai.operation.name": "execute_tool"}) as s:
        pass
    assert exporter.export([s]) == SpanExportResult.FAILURE
