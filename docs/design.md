# Gleipnir SDK: design

Status: draft for review, 2026-10-14. Nothing here is implemented yet.

## 1. What this is

AI agent vendors get stuck in their buyers' security reviews because they cannot prove what their agent did. Their logs are written, stored and attested by themselves, so the buyer has nothing it can check.

The SDK lets a vendor add verifiable action records in a few lines:

1. **Record** each agent action together with the real response from the external system.
2. **Sign and chain** the records so any later edit, deletion, reordering or truncation is detectable.
3. **Anchor** periodic digests outside the vendor, in a public append-only transparency log. Only hashes leave the vendor.
4. **Verify**: the buyer, auditor or insurer runs an offline verifier on an exported bundle, with zero setup.
5. **Pack**: export a Security Review Pack for a date range.
6. **Check**: report which items of the [agent-security-review checklist](https://github.com/getgleipnir/agent-security-review) the current setup covers.

### Non-goals

- Deciding or approving actions. The SDK records; it does not gate.
- Proving the agent's intent or that its decision was correct.
- Replacing the vendor's observability or eval stack.
- Hosting. Everything runs in the vendor's environment; the only external call is to the transparency log (and a timestamp authority).

## 2. Repository layout

```
spec/                       Record and bundle format (normative), JSON schemas, test vectors
  test-vectors/             Shared by Python and TypeScript; both must produce identical bytes
python/
  gleipnir-verify/          Distribution "gleipnir-verify". Format, canonicalization, hashing,
                            Merkle proofs, signature and anchor verification, the verify CLI.
                            Small on purpose, so buyers can audit it. Deps: cryptography, rfc8785.
  gleipnir/                 Distribution "gleipnir-sdk", import name "gleipnir". Recorder, wrap,
                            signers, stores, anchors, pack, check, adapters. Depends on gleipnir-verify.
typescript/                 Later: @getgleipnir/sdk and @getgleipnir/verify, same format
examples/refund-agent/      5-minute quickstart and tamper demo
docs/                       design.md, threat-model.md, quickstart.md
```

One `uv` workspace for the Python packages. The verifier being a separate, minimal package is a feature: the buyer installs only the part that checks, not the part that writes.

**Package names.** `gleipnir` is taken on PyPI (an AWS helper, last release 2021) and on npm (an AMQP wrapper, last release 2022). Free as of 2026-10-14: `gleipnir-sdk`, `gleipnir-verify` on PyPI; `@getgleipnir/*` scope on npm. Proposal: `pip install gleipnir-sdk`, `import gleipnir`, `pipx run gleipnir-verify bundle.zip`. A PEP 541 request for `gleipnir` is possible later but takes months.

## 3. Developer experience

```python
import gleipnir

rec = gleipnir.Recorder(agent_id="support-agent", agent_version="3.2.4")

def refund_exists(call, response):
    r = payments.get_refund(response["refund_id"])
    return gleipnir.Outcome.compare(
        expected={"amount": call.args["amount"], "order_id": call.args["order_id"]},
        observed={"amount": r.amount, "order_id": r.order_id},
    )

@rec.tool(system="payments-api", redact=["card_number"], verify_outcome=refund_exists)
def issue_refund(order_id: str, amount: float, card_number: str) -> dict:
    return payments.refund(order_id, amount)
```

- Sync and async functions both work. Exceptions are recorded as `failed` and re-raised unchanged.
- The decorator never changes the tool's return value or signature.
- Context (trace ID, session, on-behalf-of, model, prompt/config versions) is set once per run with `rec.context(...)` (a `contextvars` scope), and the OpenTelemetry trace/span ID is picked up automatically if present.
- The agent's claim: by default the intended call (tool + redacted args). A framework adapter, or the vendor, can attach the agent's natural-language claim with `rec.claim(action_id, text)`.
- First run with no key: an Ed25519 key is generated in `./.gleipnir/keys/`, with a loud warning that it is a local development key and how to configure a real one.

Defaults are local-first: records go to `./.gleipnir/records/`, anchoring uses the local file anchor until Rekor is configured explicitly.

## 4. Record format (v1)

All records are JSON objects canonicalized with RFC 8785 (JCS). The record hash is `sha256(JCS(record without "sig"))`.

```json
{
  "v": 1,
  "kind": "action",
  "chain": "ch_01J…",
  "seq": 2291,
  "id": "act_01J…",
  "prev": "sha256:…",
  "agent": { "id": "support-agent", "version": "3.2.4" },
  "tool": { "name": "issue_refund", "system": "payments-api" },
  "args": { "order_id": "A-1001", "amount": 42.1, "card_number": { "redacted": "hmac-sha256:…" } },
  "claim": { "text": "Refunded $42.10 on order A-1001" },
  "response": { "status": "ok", "body": { "refund_id": "R-9", "amount": 42.1 } },
  "outcome": { "check": "match", "method": "verify_outcome", "observed": { "amount": 42.1 } },
  "context": { "trace_id": "…", "span_id": "…", "session": "…", "on_behalf_of": "ticket:T-77" },
  "model": { "provider": "…", "name": "…", "version": "…" },
  "versions": { "prompt": "pr-31", "config": "cfg-9" },
  "identity": { "principal": "svc-agent-prod", "credential_id": "…", "scope": "refunds:write" },
  "t": { "start": "2026-10-14T09:14:05.112Z", "end": "2026-10-14T09:14:05.871Z" },
  "key": "k_ed25519_…",
  "sig": "ed25519:…"
}
```

- `kind`: `genesis` (first record: chain ID, public key, created time), `action`, `segment` (see 6), `key_rotation`, `note`.
- `prev` is the hash of the previous record in the same chain. `seq` is gapless and starts at 0 with the genesis record.
- `sig` is Ed25519 over the domain-separated message `"gleipnir/record/v1\n" || record_hash`.
- `outcome.check`: `match`, `mismatch`, `not_checked`, `error`.
- Optional fields are omitted, never `null`. Unknown fields must be preserved by verifiers and covered by the hash.
- Floats: JCS serializes numbers as IEEE 754 doubles. Money should be passed as strings or integer minor units; `check` warns when a float is used for an amount-like field.

### Redaction

Redaction happens before hashing, so a record is never signed over a value it does not contain. Per field: `drop`, `hmac-sha256` (keyed, so the buyer can match a value it knows without the record revealing it), or a custom callable. The redaction policy version is stored on the record.

## 5. Storage

Pluggable `Store` interface. Default: append-only JSONL, one file per segment, in `./.gleipnir/records/<chain>/`. Writes are fsync'd before the tool's result is returned (configurable to async for latency-sensitive paths, with the trade-off documented). Optional `Sink`s replicate records to storage the buyer controls (S3/GCS bucket) for buyer-held copies.

Concurrency: one chain per process by default; multiple workers either use one chain each (simplest, recommended) or a shared writer. Multi-writer ordering is out of scope for v0.

## 6. Segments and Merkle roots

Records are grouped into segments. A segment closes after N records or T seconds (defaults: 1,000 records or 10 minutes), and **also on a fixed heartbeat even when empty**, so that a bundle can prove there is no hidden gap in time.

On close, the recorder appends a `segment` record containing the sequence range, the Merkle root over the record hashes in that range (RFC 6962 tree hashing with 0x00/0x01 leaf/node prefixes), and the previous segment's hash. The segment record is itself signed and chained.

## 7. Anchoring

Pluggable `Anchor` interface:

- `LocalFileAnchor`: append-only file, for tests and demos.
- `RekorAnchor`: posts the segment record hash to Sigstore Rekor as a `hashedrekord` entry and stores the returned transparency log entry (inclusion proof and signed checkpoint) in the chain as an `anchor` receipt.
- Later: an RFC 3161 timestamp authority, the buyer's own log, or a Gleipnir-hosted witness.

What leaves the vendor: the segment hash, a signature over it and the anchor public key. No record content.

Notes from checking Rekor (2026-10-14):

- Rekor v2 is GA (October 2025) and accepts only `hashedrekord` and `dsse`. Shard URLs come from Sigstore's TUF root and must not be hardcoded.
- v2 returns an inclusion proof with a checkpoint and blocks until the checkpoint is published (seconds). It no longer returns signed timestamps; a separate RFC 3161 timestamp is needed for trusted time.
- v2 has **no search by key or hash**. So the verifier cannot ask the log "which entries exist for this vendor". Gap detection therefore relies on the heartbeat segments in 6, not on log search.
- The documented examples use ECDSA P-256. Whether pure Ed25519 is accepted for `hashedrekord` is not confirmed. Plan: test Ed25519 first; if rejected, use a separate ECDSA P-256 anchor key. Record signing stays Ed25519 either way.

Anchoring is asynchronous and never blocks a tool call. If the log is unreachable, segments queue and are anchored later; the delay is visible in the pack.

## 8. Bundle and verify

A bundle is a zip:

```
manifest.json      chain ID, range (seq and time), public keys, format version, tool version
records/*.jsonl    records in the range, plus the genesis and key records needed to verify them
anchors/*.json     anchor receipts (inclusion proofs, checkpoints, timestamps)
trust/             pinned trust material for the logs used (Rekor public keys / TUF snapshot)
```

`gleipnir-verify bundle.zip` checks, fully offline:

1. Every signature, against keys introduced by the genesis or a signed `key_rotation`.
2. Hash chain: every `prev` matches, `seq` has no gaps, no duplicates, no reordering.
3. Every segment's Merkle root matches its records.
4. Every segment is anchored: inclusion proof valid against a checkpoint signed by a pinned log key.
5. Time coverage: heartbeat segments cover the declared range with no gap longer than the configured interval.
6. Reports: VALID, or each failure with the record or segment where it happens. Also reports the unanchored tail (records after the last anchored segment) explicitly, because truncation of that tail cannot be excluded.

Output: human-readable by default, `--json` for tooling. Exit code 0 only when fully valid.

An optional `--online` mode refreshes trust material and checks consistency against newer log checkpoints.

## 9. Pack

`gleipnir pack --from 2026-07-01 --to 2026-09-30` produces:

- `summary.html` (and `summary.pdf` with the optional `pdf` extra): actions by tool and system, identities and scopes used, failures, outcome mismatches, model and config versions seen, anchoring delays, verification result.
- The bundle for the same range, and `verify.md` with buyer instructions.
- Optional: a checklist coverage page (see 10).

## 10. Check

`gleipnir check` loads `checklist.yaml` (a pinned copy ships with the package; `--checklist PATH|URL` to use another), inspects the current configuration, and reports per item:

- **covered**: every capability the item lists is active (for example `signed_records` and `hash_chain` for TMP-01);
- **partial**: some are active;
- **not covered**: none;
- **process item**: the item has no capabilities; the SDK cannot evidence it, so it lists it as a reminder.

Capabilities are derived from configuration, not claimed: `outcome_check` is active only if at least one wrapped tool has `verify_outcome`; `external_anchor` only if a non-local anchor is configured and has succeeded recently; `buyer_copy` only if a sink is configured; and so on.

## 11. Adapters

All adapters call the same core `Recorder`. Order follows the plan: one adapter after `check`, the rest after the quickstart.

| Adapter | Hook point |
|---|---|
| OpenAI Agents SDK | function tool wrapper and tracing processor |
| Claude Agent SDK | tool hooks (pre/post tool use) |
| LangGraph | tool node wrapper / callback handler |
| MCP client middleware | wraps `call_tool` on the client session |
| OpenTelemetry span exporter | turns tool-call spans into records, for vendors with their own harness |
| Stretch: Playwright/CDP | records navigations, clicks and submits with a DOM target and screenshot hash |

Research on 27 target vendors showed custom harnesses (often on Temporal) rather than these frameworks, so the plain decorator and the OTel exporter are expected to matter most for real pilots.

## 12. Engineering

- `uv`, `pytest`, `hypothesis` for property tests, `ruff`, `mypy --strict` on `gleipnir-verify`.
- Coverage gate: 90% on canonicalization, crypto, chain, Merkle, anchor verification and the verify CLI.
- Property tests on generated chains: editing any field of any record, deleting any record, swapping any two records, truncating at any point, and dropping any segment must all fail verification (truncation after the last anchor must be reported as an unanchored tail).
- Cross-language test vectors in `spec/test-vectors/` from day one, so TypeScript can be checked byte for byte.
- CI on GitHub Actions: Python 3.10 to 3.13, Linux and macOS.

## 13. Threat model (summary; full version in docs/threat-model.md)

**What a valid bundle proves**

- The records were not changed, removed, reordered or truncated after their segment was anchored (up to the unanchored tail, which is reported).
- They were signed by the holder of the vendor's key.
- Each segment existed no later than its anchor time.
- For checked actions: the recorded system response matched what the vendor's read-back of the external system returned.

**What it does not prove**

- The agent's intent, or that a decision was right.
- That every action was recorded. A vendor who skips the wrapper produces no record. Mitigation: the buyer reconciles the pack's action IDs against its own system logs (the pack lists external object IDs for that purpose).
- That a recorded response is genuine if the vendor process itself is compromised before signing. Mitigations: outcome read-back, buyer reconciliation, keys in an HSM or KMS.
- Anything about records made before the genesis or after the last anchor.

## 14. Build order

1. Design doc (this file): review.
2. Core: format, JCS, hashing, signatures, chain, segments, Merkle, local store, `verify` CLI, with tests and test vectors.
3. Anchor: local file, then Rekor.
4. `check`.
5. One adapter.
6. `pack`.
7. Quickstart: toy refund agent against a fake payments API, then the tamper demo.
8. Remaining adapters, then TypeScript.

## 15. Open questions for review

1. Package names: `gleipnir-sdk` and `gleipnir-verify` on PyPI, `@getgleipnir/*` on npm (needs an npm organization named `getgleipnir`)?
2. Which adapter goes first in step 5? Proposal: MCP client middleware, because it covers MCP tool calls in any framework, then OpenAI Agents SDK.
3. Default anchor cadence: 10-minute heartbeat including empty segments, up to about 144 Rekor entries per day per chain. Acceptable, or start at 30 minutes?
4. Public Rekor only for v0, or also a private log option early (some buyers will not want vendor key fingerprints in a public log)?
