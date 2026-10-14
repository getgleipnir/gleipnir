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
pipx run gleipnir-verify bundle.zip --expect-key k_ed25519_...
```

## Try it in five minutes

[examples/refund-agent](examples/refund-agent): a toy refund agent, a fake payments API with a hidden bug, verification, and a tamper demo.

## What's in the box

| | |
|---|---|
| `gleipnir-sdk` (`import gleipnir`) | `Recorder.tool` decorator (sync and async), outcome checks, field redaction, context (identity, scope, model, prompt versions), review records, MCP client middleware, `export`, `pack`, `check` |
| `gleipnir-verify` | Small offline verifier the buyer runs: signatures, hash chain, Merkle roots, Rekor inclusion proofs and checkpoints, truncation checks |
| Records | RFC 8785 canonical JSON, Ed25519 signatures, hash chain, segments with RFC 6962 Merkle roots, anchored in Sigstore Rekor v2. See [spec/format.md](spec/format.md) |
| `gleipnir check` | Which items of the open [agent security review checklist](https://github.com/getgleipnir/agent-security-review) your records evidence |

Docs: [design](docs/design.md), [threat model](docs/threat-model.md) (what a valid result proves, and what it doesn't).

## Status

Pre-release (0.1.0.dev0), not yet on PyPI. Python first; TypeScript and adapters for the OpenAI Agents SDK, Claude Agent SDK, LangGraph and OpenTelemetry are next.

```bash
git clone https://github.com/getgleipnir/gleipnir && cd gleipnir
uv sync --all-packages
uv run pytest python
```

## License

Apache-2.0
