import pytest

pytest.importorskip("claude_agent_sdk")

from claude_agent_sdk import ClaudeAgentOptions, HookMatcher  # noqa: E402
from claude_agent_sdk._internal.query import _convert_hook_output_for_cli  # noqa: E402
from claude_agent_sdk.types import _hooks_to_internal_format  # noqa: E402

import gleipnir  # noqa: E402
from gleipnir.adapters.claude_agent_sdk import GleipnirHooks, gleipnir_hooks  # noqa: E402

BASE = {"session_id": "sess-1", "transcript_path": "/tmp/t.jsonl", "cwd": "/work", "permission_mode": "default"}
CTX = {"signal": None}


def actions(rec):
    return [r for r in rec.chain.store.read_all() if r["kind"] == "action"]


def callbacks(hooks, event):
    return [cb for m in hooks[event] for cb in m.hooks]


async def fire(hooks, event, payload, tool_use_id):
    """Call every hook for ``event`` the way the SDK's control protocol does."""
    outs = []
    for cb in callbacks(hooks, event):
        out = await cb({**BASE, "hook_event_name": event, **payload}, tool_use_id, CTX)
        outs.append(_convert_hook_output_for_cli(out))
    return outs


def test_hooks_dict_is_valid_options(rec):
    hooks = gleipnir_hooks(rec, matcher="Bash|mcp__.*")
    assert set(hooks) == {"PreToolUse", "PostToolUse", "PostToolUseFailure"}
    assert all(isinstance(m, HookMatcher) and m.matcher == "Bash|mcp__.*" for ms in hooks.values() for m in ms)
    opts = ClaudeAgentOptions(hooks=hooks)
    internal = _hooks_to_internal_format(opts.hooks)
    assert len(internal["PostToolUse"][0]["hooks"]) == 1


async def test_mcp_tool_success_and_outcome(rec, clock):
    def check(call, response):
        return gleipnir.Outcome.compare({"amount": call.args["amount"]}, {"amount": response["amount"]})

    hooks = gleipnir_hooks(rec, redact=["card_number"], verify_outcome={"mcp__payments__issue_refund": check})
    tool_input = {"order_id": "A-1", "amount": 4210, "card_number": "4111"}
    pre = await fire(hooks, "PreToolUse", {"tool_name": "mcp__payments__issue_refund", "tool_input": tool_input,
                                           "tool_use_id": "toolu_01"}, "toolu_01")
    assert pre == [{}]  # observe only: no permission decision
    clock.advance(2)
    post = await fire(hooks, "PostToolUse", {
        "tool_name": "mcp__payments__issue_refund", "tool_input": tool_input, "tool_use_id": "toolu_01",
        "tool_response": {"refund_id": "R-9", "amount": 4200}, "duration_ms": 1900}, "toolu_01")
    assert post == [{}]
    [a] = actions(rec)
    assert a["tool"] == {"name": "mcp__payments__issue_refund", "system": "payments"}
    assert a["args"]["card_number"]["redacted"].startswith("hmac-sha256:")
    assert a["response"]["body"] == {"refund_id": "R-9", "amount": 4200}
    assert a["outcome"]["check"] == "mismatch" and a["outcome"]["fields"] == ["amount"]
    assert a["context"] == {"session": "sess-1", "tool_call_id": "toolu_01"}
    assert a["t"] == {"start": "2026-10-01T09:00:00.000Z", "end": "2026-10-01T09:00:02.000Z"}


async def test_builtin_failure_subagent_and_missing_pre(rec, clock):
    h = GleipnirHooks(rec, system="claude-code", systems={"WebFetch": "internet"})
    await h.pre_tool_use({**BASE, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "false"}, "tool_use_id": "toolu_02"}, "toolu_02", CTX)
    clock.advance(1)
    out = await h.post_tool_use_failure({**BASE, "hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                         "tool_input": {"command": "false"}, "tool_use_id": "toolu_02",
                                         "error": "Exit code 1", "agent_id": "sub-7"}, "toolu_02", CTX)
    assert out == {}
    # PostToolUse without a PreToolUse: start time comes from duration_ms
    await h.post_tool_use({**BASE, "hook_event_name": "PostToolUse", "tool_name": "WebFetch",
                           "tool_input": {"url": "https://example.com"}, "tool_use_id": "toolu_03",
                           "tool_response": "<html>", "duration_ms": 500}, None, CTX)
    a, b = actions(rec)
    assert a["tool"] == {"name": "Bash", "system": "claude-code"}
    assert a["response"] == {"status": "error", "error": "Exit code 1"}
    assert a["context"]["run_id"] == "subagent:sub-7"
    assert b["tool"]["system"] == "internet" and b["response"]["body"] == "<html>"
    assert b["t"] == {"start": "2026-10-01T09:00:00.500Z", "end": "2026-10-01T09:00:01.000Z"}
    assert b["context"]["tool_call_id"] == "toolu_03"


async def test_recording_failure_is_swallowed(rec, monkeypatch):
    def boom(**kw):
        raise RuntimeError("disk full")

    monkeypatch.setattr(rec, "record_action", boom)
    h = GleipnirHooks(rec)
    out = await h.post_tool_use({**BASE, "hook_event_name": "PostToolUse", "tool_name": "Read",
                                 "tool_input": {}, "tool_use_id": "t", "tool_response": "x"}, "t", CTX)
    assert out == {}
