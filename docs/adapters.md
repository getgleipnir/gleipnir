# Adapters

Every adapter calls the same `Recorder`, so records look the same whichever one you use: `tool`, `system`, `args`, `response`, `t`, optional `outcome`, and context ids. Each adapter imports its framework lazily, never changes what the agent sees, and logs and swallows its own failures, so recording cannot break the agent.

Pick one hook point per tool. If two adapters see the same call (say, the MCP middleware and an OpenTelemetry exporter), it is recorded twice.

Install the framework with the matching extra, e.g. `pip install 'gleipnir-sdk[playwright]'`.

| Adapter | Extra | Hook point |
|---|---|---|
| [`Recorder.tool`](#recordertool-no-framework) | none | decorator on your own tool functions |
| [MCP client middleware](#mcp-client-middleware) | `mcp` | `ClientSession.call_tool` |
| [`gleipnir-mcp` proxy](mcp-proxy.md) | none | stdio between any MCP client and server |
| [OpenTelemetry](#opentelemetry) | `otel` | span exporter for GenAI `execute_tool` spans |
| [OpenAI Agents SDK](#openai-agents-sdk) | `openai-agents` | `FunctionTool` wrapper |
| [Claude Agent SDK](#claude-agent-sdk) | `claude-agent-sdk` | `PreToolUse` / `PostToolUse` hooks |
| [LangChain / LangGraph](#langchain--langgraph) | `langchain`, `langgraph` | callback handler |
| [Playwright](#playwright-browser-and-computer-use-agents) | `playwright` | page instrumentation (sync and async) |
| [Temporal](#temporal) | `temporal` | worker activity interceptor |

All snippets assume:

```python
import gleipnir

rec = gleipnir.Recorder(agent_id="support-agent", agent_version="3.2.4")

def check_refund(call, result):                  # read back from the system of record
    r = payments.get_refund(result["refund_id"])
    return gleipnir.Outcome.compare({"amount": call.args["amount"]}, {"amount": r.amount})
```

## `Recorder.tool` (no framework)

```python
@rec.tool(system="payments-api", redact=["card_number"], verify_outcome=check_refund)
def issue_refund(order_id: str, amount: int, card_number: str) -> dict:
    return payments.refund(order_id, amount, card_number)
```

When a decorator does not fit, call `rec.record_action(tool=..., system=..., args=..., response=...)` directly.

## MCP client middleware

```python
from gleipnir.adapters.mcp import instrument_session

async with ClientSession(read, write) as session:
    instrument_session(session, rec, system="payments-mcp", verify_outcome={"refund": check_refund})
    await session.call_tool("refund", {"order_id": "A-1", "amount": 4210})
```

A result with `isError` is recorded as an error response. For zero-code recording in Claude Desktop, Cursor or Claude Code, use the [`gleipnir-mcp` proxy](mcp-proxy.md) instead.

## OpenTelemetry

```python
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from gleipnir.adapters.otel import GleipnirSpanExporter

provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(
    GleipnirSpanExporter(rec, system="payments-api", redact=["card_number"])))
```

Spans with `gen_ai.operation.name == "execute_tool"` become one action each; the latest model span before the tool span is attached as `calls` and `model`. Arguments come from the opt-in `gen_ai.tool.call.arguments` attribute.

## OpenAI Agents SDK

```python
from agents import Agent, Runner
from gleipnir.adapters.openai_agents import wrap_tools

agent = Agent(name="support", model="gpt-5",
              tools=wrap_tools([issue_refund, lookup_order], rec, system="payments-api",
                               systems={"lookup_order": "orders-db"},
                               verify_outcome={"issue_refund": check_refund}))
await Runner.run(agent, "Refund order A-1")
```

## Claude Agent SDK

```python
from claude_agent_sdk import ClaudeAgentOptions, query
from gleipnir.adapters.claude_agent_sdk import gleipnir_hooks

options = ClaudeAgentOptions(
    allowed_tools=["Bash", "mcp__payments__issue_refund"],
    hooks=gleipnir_hooks(rec, system="claude-code",
                         verify_outcome={"mcp__payments__issue_refund": check_refund}))
async for message in query(prompt="Refund order A-1", options=options):
    ...
```

The hooks only observe; they never allow, deny or modify a tool call. MCP tools get their server name as system.

## LangChain / LangGraph

```python
from gleipnir.adapters.langgraph import GleipnirCallbackHandler

handler = GleipnirCallbackHandler(rec, system="payments-api", redact=["card_number"],
                                  verify_outcome={"issue_refund": check_refund})
graph.invoke({"messages": [("user", "Refund order A-1")]}, config={"callbacks": [handler]})
```

## Playwright (browser and computer-use agents)

Browser agents act through human-style logins, so a vendor's own "clicked Submit" log is usually the only trail. `instrument_page` records what happened on the page itself:

```python
from playwright.sync_api import sync_playwright        # or playwright.async_api
from gleipnir.adapters.playwright import instrument_page

def payout_booked(call, result):                       # runs when the URL matches the pattern
    return bank.latest_payout(account="agent-7").status == "booked"

page = browser.new_page()
instrument_page(page, rec, system="bank-portal",
                screenshots="store",                   # "hash" (default) | "none" | "store"
                redact_selectors=["#iban", ".account-number"],
                record_values=["#search", "country"],  # fill values recorded in clear
                verify_outcome={"*/payouts/confirm*": payout_booked})
page.goto("https://portal.example/login")
page.get_by_label("User").fill("agent-7")
page.get_by_role("button", name="Sign in").click()
```

- **Actions**: `browser.navigate` (goto, reload, back, forward, and navigations the page caused), `browser.click`, `browser.fill` / `browser.type`, `browser.select`, `browser.check`, `browser.upload` (name, size, SHA-256), `browser.press` (submitting keys: Enter), `browser.submit` (form action, method and field names, reported by the page) and `browser.download` (URL, file name, SHA-256, size).
- **Where**: every record has `args.page_url`, `args.frame` (main frame, or the iframe's name and URL) and `args.target`: the Playwright selector plus the element's tag, ARIA role, accessible name, label, id, `name` attribute and test id. Never the element's value.
- **Grouping**: records after a main-frame navigation carry `context.parent_action` = that navigation's id. Page-caused navigations, submits and downloads carry `cause` (the action in flight) or `after` (the latest action).
- **Redaction**: typed values are HMAC-redacted by default (the vendor can later prove what was typed without showing it). Values for password fields, credential and card `autocomplete` fields and `redact_selectors` are dropped even when allowlisted. Secret URL parameters (`password`, `token`, `code`, ...), parameters in `redact_query`, and parameters named after fields whose values were not recorded are replaced with `[redacted]` in every recorded URL.
- **Screenshots**: a PNG before and after each action. Only its SHA-256 goes in the record (`sources: [{"type": "screenshot", "phase": "before", "sha256": ...}]`). With `"store"` the PNG is written to `<chain dir>/screenshots/<sha256>.png`, so you can hand over a screenshot later and anyone can check it against the signed hash. Password fields and `redact_selectors` are masked before hashing. Everything else on screen is visible in a stored PNG.
- **Limits**: actions through `ElementHandle` (`page.query_selector(...).click()`) and raw `mouse.down`/`up` are not recorded; use locators. A `browser.submit` record comes from page JavaScript, so a hostile page could fake one. It shows what the page reported, not what the server received. Use `verify_outcome` to check the system of record.

## Temporal

Temporal workflows must be deterministic, so the interceptor only hooks activities, which is where side effects happen. Replaying history never re-executes activities, so it writes no records.

```python
from temporalio.worker import Worker
from gleipnir.adapters.temporal import GleipnirInterceptor

worker = Worker(client, task_queue="refunds", workflows=[RefundWorkflow],
                activities=[issue_refund, notify_customer],
                interceptors=[GleipnirInterceptor(
                    rec, system="refund-worker",
                    system_for_activity={"issue_refund": "payments-api"},   # or a callable
                    redact=["card_number"],
                    verify_outcome={"issue_refund": check_refund})])
```

- One action per activity **attempt**, so retries are visible. Failures read like `RuntimeError: gateway timeout [attempt 1/5, will retry]` or `ApplicationError: declined [type=Declined, non_retryable] [attempt 1/3, final]`.
- `args` are the activity arguments bound to parameter names (dataclasses become objects, then redaction applies). `verify_outcome` callbacks receive the original argument objects.
- Context: `session` = workflow id, `run_id` = workflow run id, `tool_call_id` = `<activity id>#<attempt>`.
- Sync, async and local activities are covered. An activity that completes asynchronously is recorded with body `{"completion": "async"}`.
