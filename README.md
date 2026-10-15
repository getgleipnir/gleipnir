# Gleipnir

Verifiable action records for AI agents.

AI agent vendors get stuck in their buyers' security reviews because they can't prove what their agent did: their logs are self-written, so the buyer can't verify them. Gleipnir records each agent action together with the real outcome in the external system, signs it, anchors it outside the vendor, and lets the buyer, auditor or insurer verify it independently.

```python
import gleipnir

rec = gleipnir.Recorder(agent_id="support-agent", agent_version="3.2.4", anchor="rekor")

def refund_booked(call, response):
    r = payments.get_refund(response["refund_id"])          # read back from the system of record
    return gleipnir.Outcome.compare({"amount": call.args["amount"]}, {"amount": r.amount})

@rec.tool(system="payments-api", redact=["card_number"], verify_outcome=refund_booked)
def issue_refund(order_id: str, amount: int, card_number: str) -> dict:
    return payments.refund(order_id, amount, card_number)

rec.pack("security-review-pack.zip")   # summary.html, actions.csv, bundle.zip
```

The buyer checks the bundle offline, with no account and no access to the vendor:

```bash
pipx run gleipnir-verify bundle.zip --expect-key k_ed25519_... --require-anchor rekor --require-full
```

## Zero-code: any MCP client

Put `gleipnir-mcp` in front of a local MCP server in Claude Desktop, Cursor or Claude Code and every tool call through it gets a signed record, with no code changes:

```bash
gleipnir-mcp --print-config claude-desktop -- npx -y @modelcontextprotocol/server-filesystem ~/Desktop
gleipnir report --open      # what my agent did
```

See [docs/mcp-proxy.md](docs/mcp-proxy.md).

## Try it in five minutes

[examples/refund-agent](examples/refund-agent): a toy refund agent, a fake payments API with a hidden bug, verification, and a tamper demo.

## What's in the box

**Recording (vendor side)**

| | |
|---|---|
| `gleipnir-sdk` (`import gleipnir`) | `Recorder.tool` decorator (sync and async), outcome read-back checks, field redaction, context (identity, scope, model, prompt versions) |
| Outcome checks | `gleipnir.outcomes`: ready-made read-backs from the system of record for Stripe, Zendesk, Salesforce, Intercom, HubSpot, Jira, ServiceNow, Shopify and any HTTP/JSON API; inject your own client, money in minor units, bounded retries. See [docs/outcome-checks.md](docs/outcome-checks.md) |
| Adapters | MCP client middleware, OpenTelemetry span exporter (GenAI semantic conventions), OpenAI Agents SDK, Claude Agent SDK hooks, LangChain/LangGraph callback handler, Playwright (browser and computer-use agents: navigations, clicks, fills with values redacted, submits, downloads, screenshot hashes), Temporal activity interceptor (every attempt, retries visible, replay-safe). See [docs/adapters.md](docs/adapters.md) |
| `gleipnir-mcp` | Zero-code stdio MCP proxy that records every `tools/call`, plus `gleipnir report` |
| Approvals | `rec.approve(...)` binds a human approval to one exact action; the verifier checks it came first and matches |
| Keys | Ed25519 by default; AWS KMS, Google Cloud KMS and Azure Key Vault signers (Ed25519 or ECDSA P-256), so the key never sits in the agent process |
| Anchoring | Segment hashes in Sigstore Rekor v2 plus RFC 3161 trusted timestamps; only hashes leave your infrastructure |
| Copies and retention | Sinks for a buyer-held copy, S3 Object Lock (WORM), webhooks and Splunk HEC; OCSF export for SIEMs; retention declared in a signed config record |

**Checking (buyer, auditor, insurer side)**

| | |
|---|---|
| `gleipnir-verify` | Small offline verifier: signatures, hash chain, Merkle roots, Rekor inclusion proofs and checkpoints, trusted timestamps, truncation and late re-anchoring checks, approvals |
| Browser verifier | [site/verify](site/verify): drop a bundle, verified entirely in the page; nothing is uploaded |
| `pack` | Security Review Pack: summary.html with checklist coverage and control references, actions.csv, bundle |
| `prove` | A single action with its Merkle proof and anchors, for disputes, without sharing the whole bundle |
| `reconcile` | `gleipnir-verify reconcile bundle.zip your_export.csv --column refund_id` finds actions in your system with no record, and claims with no object |
| `check` | Which items of the open [agent security review checklist](https://github.com/getgleipnir/agent-security-review) your records evidence |

Python and TypeScript (`@getgleipnir/verify`, `@getgleipnir/sdk`) produce and accept the same bytes; CI checks it on every commit. Format: [spec/format.md](spec/format.md).

Docs: [design](docs/design.md), [adapters](docs/adapters.md), [threat model](docs/threat-model.md) (what a valid result proves, and what it doesn't).

## Status

Pre-release (0.1.0.dev0), not yet on PyPI or npm.

```bash
git clone https://github.com/getgleipnir/gleipnir && cd gleipnir
uv sync --all-packages
uv run pytest python
```

## License

Apache-2.0
