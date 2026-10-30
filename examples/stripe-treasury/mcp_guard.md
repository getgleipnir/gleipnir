# Putting the mandate check in front of Stripe's `send_money` MCP tool

`agent.py` calls Stripe's REST API itself. Most agents will use Stripe's MCP server instead
(`https://mcp.stripe.com`, tools `send_money`, `setup_recipient`, `transfer_money`, `convert_currency`,
`get_balance_summary`; see [Treasury for agents][agents]). This note shows how to make sure a `send_money`
call only reaches Stripe after a Gleipnir `allow`.

## The rule that makes it work

**The agent must not hold any credential that can move money at Stripe.** A check the agent can route around
isn't a control. In practice:

- Give the agent's own Stripe connection (OAuth grant or [agent API key][keys]) **read-only** permissions,
  for example `Balance: Read` and `Money Management Financial Accounts: Read`. Without
  `Money Management Outbound Payments: Write`, `send_money` fails at Stripe. Without
  `Recipient Configuration: Write`, `setup_recipient` does too.
- Only the **guard** holds an agent API key with `Money Management Outbound Payments: Write`.
- Keep Stripe's own [approval rule][approvals] for "Outbound payment is created" on the guard's agent key as a
  second layer: amount thresholds and a human click, on top of the signed mandate.
- `stripe_api_write` can call any POST endpoint, including outbound payments. Stripe asks a person to confirm
  outbound payments made that way ([MCP: confirm actions][mcp-confirm]), but the agent's own connection
  shouldn't have the write permission in the first place.

## Can `gleipnir-mcp` (python/gleipnir/src/gleipnir/mcp_proxy.py) do this?

Not on its own. `gleipnir-mcp` is a **recording** proxy. It launches a stdio MCP server, copies bytes in both
directions unchanged, and writes a signed action record for every `tools/call` off the forwarding path. By
design it never parses, delays, alters or drops a message, so it can't block a call. It also speaks stdio,
while Stripe's server is remote (Streamable HTTP).

It is still useful here as the **audit layer around the guard**: wrap the guard with it, and every tool call
the agent made, allowed or not, lands in a signed, append-only chain next to the signed Gleipnir decisions.

## Pattern A (recommended): a guard that owns `send_money`

The agent talks to two MCP servers:

1. `gleipnir mandate mcp`: `mandate_scope`, `attach_mandate` (build and sign the payment under the mandate),
   `check_payment`.
2. A small **guard** server whose one money tool is `send_money(payment)`. It takes the payment that
   `attach_mandate` built, asks the checker, verifies the signed decision, and only on `allow` calls
   `POST /v2/money_management/outbound_payments` with its own key. The request body is built from the checked
   payment, exactly like `pay_out` in `agent.py`.

Read-only Stripe tools (`get_balance_summary`, `stripe_api_read`) can go straight to `mcp.stripe.com` on the
agent's read-only connection.

Claude Code `.mcp.json`:

```json
{
  "mcpServers": {
    "gleipnir": {
      "command": "uv",
      "args": ["run", "gleipnir", "mandate", "mcp",
               "--mandate", "nordwind-ap.mandate.json",
               "--agent-key", "agent.pem",
               "--bank-url", "https://checker.platform.example"]
    },
    "stripe-guard": {
      "command": "uv",
      "args": ["run", "gleipnir-mcp", "--system", "stripe-guard", "--",
               "uv", "run", "python", "stripe_guard.py"],
      "env": { "STRIPE_GUARD_KEY_FILE": "/run/secrets/stripe_guard_agent_key" }
    },
    "stripe": {
      "type": "http",
      "url": "https://mcp.stripe.com",
      "headers": { "Authorization": "Bearer ${STRIPE_READONLY_AGENT_KEY}" }
    }
  }
}
```

`gleipnir-mcp ... -- <command>` is the existing recording proxy wrapped around the guard.
Records go to the chain `mcp-stripe-guard` under `$GLEIPNIR_HOME`. Running
`gleipnir-mcp --print-config claude-code --name stripe-guard --system stripe-guard -- uv run python stripe_guard.py`
prints the equivalent `claude mcp add` line. In production the guard runs on a machine the agent can't read: the key file and the
checker are out of the agent's reach.

The guard's `send_money` handler, as a sketch (`stripe_guard.py` isn't shipped; the functions it uses are
the ones in `agent.py`):

```python
def send_money(args: dict) -> dict:
    payment = args["payment"]                         # built by attach_mandate, signed by the agent
    decision = checker_check(MANDATE, payment)        # POST {bank_url}/check, or an in-process m.Checker
    log_decision(decision)                            # decisions.jsonl / your store
    if not (decision["outcome"] == "allow"
            and m.verify_decision(decision, CHECKER_KEYS)          # keys from the platform, not the decision
            and decision["payment"] == {"id": payment["id"], "hash": m.obj_hash(payment, "agent_sig")}):
        return tool_error(f"{decision['outcome']}: {decision['reasons']} - not sent")   # isError: true
    body = outbound_payment_body(payment)             # amount, payee route, rail: all from the checked payment
    body["metadata"]["gleipnir_decision"] = decision["id"]
    obp = stripe.call("POST", "/v2/money_management/outbound_payments", body, idempotency_key=payment["id"])
    return tool_result({"outbound_payment": obp["id"], "status": obp["status"], "decision": decision["id"]})
```

On `escalate`, the guard returns the decision and the agent asks a person. The CFO signs an override
(`gleipnir mandate override` or the bank's app), the guard calls the checker's `/resolve`, and the same
`send_money` path sends the escalated payment unchanged.

## Pattern B: a transparent proxy in front of `mcp.stripe.com`

If the agent must keep calling Stripe's own `send_money`, put a proxy between the agent and
`https://mcp.stripe.com` that works from an **allowlist**, not a denylist:

| Tool call | Proxy does |
| --- | --- |
| `tools/list` | forward; keep only the allowlisted read-only tools and `send_money` in the result |
| `tools/call` of an allowlisted read-only tool | forward, using a **read-only** Stripe key |
| `send_money` | map arguments to a Gleipnir payment, check, then call with the write key and **arguments rebuilt from the checked payment** on `allow`; return an MCP tool error otherwise |
| any other `tools/call` (incl. `stripe_api_write`, `setup_recipient`, `transfer_money`, unknown names) | reject. Hiding a tool from `tools/list` doesn't stop an agent from calling it by name |

Two caveats, which is why Pattern A is recommended:

- **`send_money`'s input schema is not published.** Stripe documents the tool's name, description and
  required permission, but not its arguments. The mapping from `send_money` arguments (financial account,
  recipient, payout method, amount, currency) to a Gleipnir payment must be written against the schema the
  server returns in `tools/list`, and checked again whenever Stripe changes it. Keep that mapping in one
  clearly marked adapter function, and fail closed (block) on any argument it doesn't understand.
- **Human approval in the MCP flow.** Per Stripe's docs, with user (OAuth) credentials Stripe can answer a
  money-moving call with an approval URL, and the agent retries with an approval token after a person approves
  ([MCP][mcp-confirm]); with agent API keys, approval rules apply instead ([approvals][approvals]). The proxy must treat the retry as the same payment: same Gleipnir payment id, which the
  checker's payment log answers idempotently. It must not run a fresh check that could count against the
  monthly limit twice.

A proxy like this needs an MCP Streamable HTTP client toward Stripe, with the guard's agent key as the bearer
token. The repository doesn't ship one yet.

[agents]: https://docs.stripe.com/treasury/agents
[mcp-confirm]: https://docs.stripe.com/mcp#confirm-actions-by-agents-acting-on-your-behalf
[approvals]: https://docs.stripe.com/account/approvals
[keys]: https://docs.stripe.com/keys#agent-keys
