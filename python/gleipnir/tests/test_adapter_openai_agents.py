import json

import pytest

pytest.importorskip("agents")

from agents import Agent, FunctionTool, Model, ModelResponse, RunConfig, Runner, Usage, function_tool  # noqa: E402
from agents.tool_context import ToolContext  # noqa: E402
from agents.tracing import get_trace_provider, set_trace_processors  # noqa: E402
from openai.types.responses import (  # noqa: E402
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

import gleipnir  # noqa: E402
from gleipnir.adapters.openai_agents import wrap_tool, wrap_tools  # noqa: E402


def actions(rec):
    return [r for r in rec.chain.store.read_all() if r["kind"] == "action"]


@pytest.fixture(autouse=True)
def no_trace_export():
    """Keep the SDK's default processor (which uploads to OpenAI) out of the tests."""
    multi = get_trace_provider()._multi_processor
    saved = multi._processors
    set_trace_processors([])
    yield
    multi._processors = saved


class ScriptedModel(Model):
    """A Model that replays fixed tool calls, then answers; no network."""

    def __init__(self, calls):
        self.calls = list(calls)
        self.turn = 0

    async def get_response(self, *a, **kw):
        self.turn += 1
        if self.turn == 1:
            out = [ResponseFunctionToolCall(type="function_call", call_id=cid, name=name, arguments=args, id=f"fc_{i}")
                   for i, (cid, name, args) in enumerate(self.calls)]
        else:
            out = [ResponseOutputMessage(id="msg_1", type="message", role="assistant", status="completed",
                                         content=[ResponseOutputText(type="output_text", text="done",
                                                                     annotations=[])])]
        return ModelResponse(output=out, usage=Usage(), response_id=None)

    def stream_response(self, *a, **kw):  # pragma: no cover
        raise NotImplementedError


@function_tool
def issue_refund(order_id: str, amount: int, card_number: str) -> dict:
    """Refund an order."""
    return {"refund_id": f"R-{order_id}", "amount": amount}


@function_tool
def lookup(order_id: str) -> str:
    """Look up an order."""
    raise TimeoutError("orders-db timed out")


async def test_runner_records_function_tools(rec):
    def check(call, result):
        return gleipnir.Outcome.compare({"amount": call.args["amount"]}, {"amount": result["amount"]})

    tools = wrap_tools([issue_refund, lookup], rec, system="payments-api", systems={"lookup": "orders-db"},
                       redact=["card_number"], verify_outcome={"issue_refund": check})
    assert tools[0] is not issue_refund and isinstance(tools[0], FunctionTool)
    assert tools[0].name == "issue_refund" and tools[0].params_json_schema == issue_refund.params_json_schema
    model = ScriptedModel([
        ("call_1", "issue_refund", json.dumps({"order_id": "A-1", "amount": 4210, "card_number": "4111"})),
        ("call_2", "lookup", json.dumps({"order_id": "A-1"})),
    ])
    agent = Agent(name="support", instructions="help", model=model, tools=tools)
    result = await Runner.run(agent, "refund A-1", run_config=RunConfig(tracing_disabled=False))
    assert result.final_output == "done"

    by_tool = {a["tool"]["name"]: a for a in actions(rec)}
    r = by_tool["issue_refund"]
    assert r["tool"]["system"] == "payments-api"
    assert r["args"]["order_id"] == "A-1" and r["args"]["card_number"]["redacted"].startswith("hmac-sha256:")
    assert r["response"] == {"status": "ok", "body": {"refund_id": "R-A-1", "amount": 4210}}
    assert r["outcome"]["check"] == "match"
    assert r["context"]["tool_call_id"] == "call_1"
    assert r["context"]["trace_id"].startswith("trace_") and r["context"]["span_id"].startswith("span_")
    l_ = by_tool["lookup"]
    assert l_["tool"]["system"] == "orders-db"
    assert l_["response"] == {"status": "error", "error": "TimeoutError: orders-db timed out"}
    # the SDK's own failure handling still turned the exception into a model-visible message
    outputs = [i.output for i in result.new_items if getattr(i, "type", "") == "tool_call_output_item"]
    assert any("error occurred" in str(o).lower() for o in outputs)


async def test_direct_invoke_unchanged_and_raises_when_unhandled(rec):
    @function_tool(failure_error_function=None)
    def charge(amount: int) -> int:
        """Charge."""
        if amount < 0:
            raise ValueError("negative")
        return amount * 2

    wrapped = wrap_tool(charge, rec, system="billing")
    assert wrap_tool(wrapped, rec, system="billing") is wrapped  # idempotent
    agent = Agent(name="a", model="gpt-5")
    ctx = ToolContext(context=None, tool_name="charge", tool_call_id="c1", tool_arguments='{"amount": 3}', agent=agent)
    assert await wrapped.on_invoke_tool(ctx, '{"amount": 3}') == await charge.on_invoke_tool(ctx, '{"amount": 3}')
    with pytest.raises(ValueError):
        await wrapped.on_invoke_tool(ctx, '{"amount": -1}')
    ok, err = actions(rec)
    assert ok["response"]["body"] == 6 and ok["model"] == {"name": "gpt-5"}
    assert ok["context"] == {"tool_call_id": "c1"}  # no trace active
    assert err["response"]["error"] == "ValueError: negative"


async def test_hand_built_function_tool_and_other_tools(rec):
    async def on_invoke(ctx, input):
        return "pong:" + json.loads(input)["x"]

    tool = FunctionTool(name="ping", description="ping", params_json_schema={
        "type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"], "additionalProperties": False},
        on_invoke_tool=on_invoke)
    hosted = object()
    wrapped, same = wrap_tools([tool, hosted], rec, system="net")
    assert same is hosted
    ctx = ToolContext(context=None, tool_name="ping", tool_call_id="c9", tool_arguments='{"x": "a"}')
    with rec.context(model={"provider": "openai", "name": "gpt-5"}):
        assert await wrapped.on_invoke_tool(ctx, '{"x": "a"}') == "pong:a"
    [a] = actions(rec)
    assert a["tool"] == {"name": "ping", "system": "net"} and a["args"] == {"x": "a"}
    assert a["response"]["body"] == "pong:a" and a["model"]["provider"] == "openai"
