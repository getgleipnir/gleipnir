# Gleipnir for TypeScript

Two packages that produce and check the [Gleipnir record format](../spec/format.md), byte for byte compatible with the Python SDK and verifier:

| Package | What it is | Runs in |
|---|---|---|
| [`@getgleipnir/verify`](packages/verify) | Offline verifier for record bundles, plus the `gleipnir-verify` CLI | Node 20+ and browsers (pure JS: `@noble/curves`, `@noble/hashes`, `fflate`) |
| [`@getgleipnir/sdk`](packages/sdk) | Recorder that wraps agent tool calls into signed, hash-chained, segmented, anchored records | Node 20+ |

A bundle written by the TypeScript SDK verifies with the Python `gleipnir-verify`, and a bundle written by the Python SDK verifies with the TypeScript one. Both verifiers return the same report (result, finding codes, messages, summary) for the same bundle.

## Install

```bash
npm install @getgleipnir/verify     # verifier (Node or browser)
npm install @getgleipnir/sdk        # recorder (Node)
```

## Verify a bundle

From the command line, offline, with the same flags as the Python CLI:

```bash
npx -p @getgleipnir/verify gleipnir-verify bundle.zip \
  --expect-key k_ed25519_56475aa75463474c --require-anchor rekor --require-anchor rfc3161 --require-full
```

| Flag | Meaning |
|---|---|
| `--expect-key KEY_ID` | fail unless the chain is signed with this key id |
| `--expect-until TIME` | fail unless records cover at least until this ISO 8601 time (detects truncation) |
| `--known-head SEQ:HASH` | fail unless this record from an earlier bundle is present and unchanged |
| `--require-anchor rekor\|rfc3161` | fail unless every segment has a verified independent anchor of this type; repeatable |
| `--max-anchor-delay SECONDS` | fail if a segment was timestamped more than this long after it closed |
| `--require-full` | fail unless the bundle starts at the beginning of the chain |
| `--trusted-root PATH` | Sigstore `trusted_root.json` to use instead of the embedded one |
| `--local-anchor-log PATH` | local anchor log to check `local` receipts against |
| `--strict` | treat warnings as failures |
| `--json` | machine-readable output |

Exit code 0 means VALID, 1 INVALID, 2 bad arguments.

From code (Node or browser):

```ts
import { verifyBundle, verifyRecords } from "@getgleipnir/verify";

const zip = new Uint8Array(await (await fetch("/bundle.zip")).arrayBuffer());
const report = verifyBundle(zip, {
  expectKey: "k_ed25519_56475aa75463474c",
  requireAnchor: ["rekor", "rfc3161"],
  requireFull: true,
  maxAnchorDelay: 3600,
});
report.valid();          // no errors (report.valid(true): no warnings either)
report.findings;         // [{ level: "error" | "warn" | "info", code, message, seq? }]
report.summary;          // chain, keys, records, segments, anchors, coverage, head
JSON.stringify(report);  // { result: "VALID" | "INVALID", summary, findings }
```

`verifyRecords(records, options)` takes already-parsed records (for example from `parseJsonl(text)`); options also accept `manifest`, `knownHead` (`{ seq, hash }` or `"SEQ:sha256:HEX"`), `expectUntil` (`Date` or ISO string), `anchorOptions` (`{ localAnchorEntries, trustedRoot }`) and custom `anchorVerifiers`. Neither function throws on hostile input; every problem is a finding. Use the library's own `parseJson`/`parseJsonl` when you parse records yourself: `JSON.parse` turns `1.0` into `1` and rounds integers beyond 2^53, which changes what a record says.

### What is verified

| Check | Status |
|---|---|
| JCS (RFC 8785) canonical bytes, SHA-256 record hashes, Ed25519 and ECDSA P-256 signatures, key ids, key rotation (also between key types) | verified |
| Approvals bound to actions (`approval_missing`, `approval_after_action`, `approval_not_approved`, `approval_mismatch`) | verified |
| Signed approvals: key (Ed25519 / P-256) and WebAuthn (ES256) signatures against the buyer's approver registry (`approvers`, `webauthnOrigins`, `requireSignedApprovals`; CLI `--approvers`, `--webauthn-origin`, `--require-signed-approvals`) | verified, differential against Python |
| Single-action proofs (`proof.zip`, manifest `type: "proof"`): signatures, Merkle inclusion, position, anchors | verified |
| Sequence, `prev` chaining, segment tiling, RFC 6962 Merkle roots, segment links, heartbeats, manifest range, expected key, coverage, known head | verified |
| `local` anchors | verified against the bundle's (or a given) local anchor log; reported as not independent |
| `rekor` anchors (Sigstore Rekor v2) | verified offline: hashedrekord digest and ECDSA P-256 signature over the anchor message, RFC 6962 inclusion proof, checkpoint signed note with the log's Ed25519 key pinned in the embedded Sigstore trusted root |
| `rfc3161` anchors | verified offline in pure JS: TimeStampResp status, CMS SignedData signature (ECDSA/Ed25519/RSA) over the signed attributes, message digest and content type, TSA certificate pinned in the Sigstore trusted root, chain to its root valid at `genTime`, critical `id-kp-timeStamping` EKU, message imprint (SHA-256/384/512) over `"gleipnir/timestamp/v1\n" || segment_hash` |

The verifier follows the Python reference's parsing rules exactly, including Python 3.10's `datetime.fromisoformat` grammar for timestamps (3 or 6 fractional digits, `+HH:MM` offsets) and its base64 rules; see `test/differential.test.ts`, which compares canonical bytes, hashes, timestamps and full reports with the Python verifier.

### Single-action proofs and reconcile

`verifyBundle` also checks a `proof.zip` (one action, its segment, a Merkle inclusion proof and the segment's anchors), with the same findings and options. To close the gap that signed records cannot show unrecorded actions, compare the ids in a verified bundle with an export from your own system:

```bash
npx -p @getgleipnir/verify gleipnir-verify reconcile bundle.zip refunds_by_agent.csv --column refund_id [--field refund_id] [--expect-key KEY]
```

`reconcile(bundleBytes, csvText, { column, field })` does the same from code.

### In the browser

[`site/verify/index.html`](../site/verify/index.html) is a single static page that verifies a dropped `bundle.zip` or `proof.zip` entirely in the browser (nothing is uploaded; its Content-Security-Policy forbids network requests), with fields for the expected key, a known head and required anchors. Build it with `npm run build:site` from `site/verify/src/`.

## Record agent actions

```ts
import { Outcome, Recorder } from "@getgleipnir/sdk";

const rec = new Recorder({ agentId: "support-agent", agentVersion: "3.2.4" }); // keys and chain in ./.gleipnir

const issueRefund = rec.tool(
  async (orderId: string, amountCents: number, cardNumber: string) => payments.refund(orderId, amountCents, cardNumber),
  {
    system: "payments-api",
    name: "issue_refund",
    params: ["order_id", "amount_cents", "card_number"], // record arguments by name
    redact: ["card_number"],                             // HMAC-SHA256 by default; or { card_number: "drop" | "hmac" | fn }
    verifyOutcome: async (call, res) => {                // read back from the system of record
      const booked = await payments.getRefund(res.refund_id);
      return Outcome.compare({ amount_cents: call.args.amount_cents }, { amount_cents: booked.amount_cents });
    },
    claim: (args) => `Refunded ${args.amount_cents} on ${args.order_id}`,
  },
);

await rec.context({ on_behalf_of: "ticket:T-101", identity: { principal: "svc-support", scope: "refunds:write" } }, () =>
  issueRefund("A-1001", 4210, "4111111111111111"),
);

await rec.export("bundle.zip"); // closes the open segment, anchors it, writes the bundle and VERIFY.md
```

- `tool()` wraps sync and async functions; the wrapper returns what the function returns and re-throws its errors after recording them. A `verifyOutcome` returning `true`/`false`/`null` means match/mismatch/not checked; a throwing check is recorded as `error`.
- `context(values, fn)` attaches `trace_id`, `span_id`, `session`, `run_id`, `on_behalf_of`, `parent_action`, `model`, `versions` and `identity` to every record made inside `fn`, across `await`s (AsyncLocalStorage).
- `recordAction`, `claim`, `review` and `note` write records directly.
- `approve(tool, args, { approver, rule })` records an approval of one exact action before it runs; run the action in `rec.context({ approval: id }, ...)` and the verifier checks the approval came first and the tool, system and (redacted) arguments match. With `{ signature }` (the approver's own signature over `rec.approvalDigest(tool, args)`, from `ApproverKey.sign`, `gleipnir approve sign` or the passkey page `site/approve/`), the approval is bound to the approver's key; the reviewer defaults to its `approver_id`.
- `prove(actionId, "proof.zip")` writes a single-action proof for a dispute about one action.
- The chain writer closes a segment every `segmentMaxRecords` records and after `heartbeatSeconds` (also when empty), with a background timer that never keeps the process alive. Anchoring may be asynchronous and is retried; it never breaks recording.
- Anchors: `"local"` (default, a local append-only log for tests and demos, not independent), `"rekor"` (Sigstore Rekor v2 public log plus an RFC 3161 timestamp from Sigstore's TSA: `[new RekorAnchor(home), new TimestampAnchor()]`), or any object implementing `Anchor` (`{ type, anchor({ segmentHash, chain, segmentSeq }) }`, sync or async).
  - `RekorAnchor(home, { url, timeoutMs, privateKey, fetch })` sends only a `hashedrekord` v0.0.2 entry (SHA-256 digest of the anchor message, an ECDSA P-256 signature and the anchor public key). The anchor key is `<home>/keys/anchor-ecdsa-p256.pem` (PKCS#8, created on first use, the same file the Python SDK uses). `TimestampAnchor(url, { timeoutMs, fetch })` sends an RFC 3161 request (SHA-512 imprint, nonce, certReq). Both write the same receipts as the Python SDK and verify every receipt offline before storing it.
  - Network anchoring runs off the tool-call path: closing a segment queues it, one anchoring run is in flight at a time, failures are reported through `onWarning` and retried on the next run (timer, next segment, `flush()` or `export()`). Tool calls never wait for Rekor or the TSA. Both use the global `fetch` (Node 20+); behind an HTTPS proxy, pass a `fetch` that uses it (or run Node 22.21+ with `NODE_USE_ENV_PROXY=1`).
- Signing keys are PKCS#8 PEM files (`.gleipnir/keys/signing-ed25519.pem`), the same format the Python SDK uses. For production, pass a `Signer` backed by a KMS or HSM: `new SpkiSigner({ spki, signMessage })` wraps an external Ed25519 or ECDSA P-256 key (DER or raw r||s signatures); `EcdsaP256Signer` is a local P-256 key. Ed25519 stays the default.
- Storage: `JsonlStore` (default, append-only, fsync) or `MemoryStore`, or your own `Store`.

## Develop

```bash
cd typescript
npm ci
npm run build
npm test            # spec vectors, Rekor/RFC 3161 fixtures, tamper tests; differential tests run if `uv` is available
npm run interop     # Python SDK bundle -> TS verifier and TS SDK bundle -> Python verifier (needs `uv sync --all-packages`)
npm run build:site  # site/verify/index.html (a test fails if it is stale)
GLEIPNIR_LIVE_REKOR=1 npx vitest run packages/sdk/test/anchors.test.ts  # publishes test hashes to public Rekor + Sigstore TSA
node scripts/record-anchor-fixtures.mjs  # re-record the Rekor/TSA responses the anchor unit tests replay
```
