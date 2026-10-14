import pytest

pytest.importorskip("langchain_core")

from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langchain_core.tools import ToolException, tool  # noqa: E402

import gleipnir  # noqa: E402
from gleipnir.adapters.langgraph import GleipnirCallbackHandler  # noqa: E402


def actions(rec):
    return [r for r in rec.chain.store.read_all() if r["kind"] == "action"]


@tool
def issue_refund(order_id: str, amount: int, card_number: str) -> dict:
    """Refund an order."""
    return {"refund_id": f"R-{order_id}", "amount": amount}


@tool
def lookup(order_id: str) -> str:
    """Look up an order."""
    raise TimeoutError("orders-db timed out")


@tool
def close_ticket(ticket: str) -> str:
    """Close a ticket."""
    raise ToolException(f"ticket {ticket} is locked")


close_ticket.handle_tool_error = True
close_ticket.metadata = {"gleipnir_system": "crm"}


def test_tool_call_records_and_result_unchanged(rec):
    def check(call, result):
        return gleipnir.Outcome.compare({"amount": call.args["amount"]}, {"amount": result["amount"]})

    h = GleipnirCallbackHandler(rec, system="payments-api", redact=["card_number"],
                                verify_outcome={"issue_refund": check})
    args = {"order_id": "A-1", "amount": 4210, "card_number": "4111"}
    plain = issue_refund.invoke(args)
    out = issue_refund.invoke(args, config={"callbacks": [h], "metadata": {"thread_id": "th-1"}})
    assert out == plain
    msg = issue_refund.invoke({"type": "tool_call", "id": "call_1", "name": "issue_refund", "args": args},
                              config={"callbacks": [h]})
    assert isinstance(msg, ToolMessage) and msg.tool_call_id == "call_1"
    a, b = actions(rec)
    assert a["tool"] == {"name": "issue_refund", "system": "payments-api"}
    assert a["args"]["order_id"] == "A-1" and a["args"]["card_number"]["redacted"].startswith("hmac-sha256:")
    assert a["response"]["body"] == {"refund_id": "R-A-1", "amount": 4210}
    assert a["outcome"]["check"] == "match"
    assert a["context"]["session"] == "th-1" and len(a["context"]["run_id"]) == 36
    assert b["context"]["tool_call_id"] == "call_1"
    assert b["response"]["status"] == "ok"  # ToolMessage content (stringified by LangChain)
    assert a["context"]["run_id"] != b["context"]["run_id"]


def test_errors_recorded_and_reraised(rec):
    h = GleipnirCallbackHandler(rec, systems={"lookup": "orders-db"})
    with pytest.raises(TimeoutError):
        lookup.invoke({"order_id": "A-1"}, config={"callbacks": [h]})
    handled = close_ticket.invoke({"ticket": "T-7"}, config={"callbacks": [h]})
    assert handled == "ticket T-7 is locked"  # handle_tool_error still turns it into a result
    a, b = actions(rec)
    assert a["tool"] == {"name": "lookup", "system": "orders-db"}
    assert a["response"] == {"status": "error", "error": "TimeoutError: orders-db timed out"}
    assert b["tool"] == {"name": "close_ticket", "system": "crm"}
    assert b["response"]["status"] == "ok" and b["response"]["body"] == "ticket T-7 is locked"


async def test_async_invoke(rec):
    h = GleipnirCallbackHandler(rec, system="payments-api")
    out = await issue_refund.ainvoke({"order_id": "B", "amount": 1, "card_number": "x"}, config={"callbacks": [h]})
    assert out["refund_id"] == "R-B"
    [a] = actions(rec)
    assert a["response"]["body"]["refund_id"] == "R-B"


def test_langgraph_tool_node(rec):
    """A real StateGraph with a ToolNode; no model involved."""
    prebuilt = pytest.importorskip("langgraph.prebuilt")
    from langgraph.graph import END, START, MessagesState, StateGraph

    h = GleipnirCallbackHandler(rec, system="payments-api")
    g = StateGraph(MessagesState)
    g.add_node("tools", prebuilt.ToolNode([issue_refund, lookup], handle_tool_errors=True))
    g.add_edge(START, "tools")
    g.add_edge("tools", END)
    node = g.compile()
    ai = AIMessage(content="", tool_calls=[
        {"id": "call_a", "name": "issue_refund", "args": {"order_id": "C", "amount": 5, "card_number": "x"}},
        {"id": "call_b", "name": "lookup", "args": {"order_id": "C"}},
    ])
    result = node.invoke({"messages": [ai]}, config={"callbacks": [h]})
    statuses = {m.tool_call_id: m.status for m in result["messages"] if isinstance(m, ToolMessage)}
    assert statuses == {"call_a": "success", "call_b": "error"}  # ToolNode handled the TimeoutError
    by_call = {a["context"]["tool_call_id"]: a for a in actions(rec)}
    assert by_call["call_a"]["response"]["status"] == "ok"
    assert by_call["call_b"]["response"]["status"] == "error"
    assert "orders-db timed out" in by_call["call_b"]["response"]["error"]


def test_end_without_start_and_failure_swallowed(rec, monkeypatch):
    import uuid

    h = GleipnirCallbackHandler(rec, system="s")
    h.on_tool_end(ToolMessage(content="x", tool_call_id="c", status="error"), run_id=uuid.uuid4(), name="t")
    [a] = actions(rec)
    assert a["tool"] == {"name": "t", "system": "s"} and a["response"]["status"] == "error"

    def boom(**kw):
        raise RuntimeError("disk full")

    monkeypatch.setattr(rec, "record_action", boom)
    assert issue_refund.invoke({"order_id": "D", "amount": 1, "card_number": "x"},
                               config={"callbacks": [h]})["refund_id"] == "R-D"
