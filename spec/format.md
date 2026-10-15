# Gleipnir record format, version 1

Normative. Implementations in any language must produce and accept exactly this. The test vectors in [test-vectors/](test-vectors/) are part of the spec.

## Encoding

- A record is a JSON object. Bytes for hashing are its **RFC 8785 (JCS)** canonical form, UTF-8.
- Integers must be in the IEEE 754 safe range (|n| ≤ 2^53 − 1). Producers record larger integers as `{"int": "<decimal>"}` instead of failing. Money should be strings or integer minor units.
- `record_hash = "sha256:" || hex(SHA-256(JCS(record minus "sig")))`.
- Optional fields are omitted, never `null`. Unknown fields are allowed and are covered by the hash.
- Timestamps are strict RFC 3339: `YYYY-MM-DDTHH:MM:SS[.f{1,6}](Z|+HH:MM|-HH:MM)`, uppercase `T` and `Z`. Producers write UTC with milliseconds and `Z`, for example `2026-10-14T09:14:05.112Z`. Verifiers reject anything else, so validity never depends on the implementation.
- JSON Lines files split on `\n` only. Producers escape U+2028, U+2029 and U+0085 inside strings (this does not change the canonical bytes).

## Common fields

| Field | Type | Meaning |
|---|---|---|
| `v` | int | Format version, `1`. |
| `kind` | string | `genesis`, `action`, `claim`, `note`, `segment`, `anchor`, `key_rotation`. |
| `chain` | string | Chain id, set by the genesis record. |
| `seq` | int | 0 for genesis, then +1 per record, no gaps. |
| `id` | string | Unique record id. Action ids are referenced by claims and by `verify_outcome`. |
| `time` | string | When the record was written. |
| `prev` | string | `record_hash` of the record with `seq - 1`. Absent only on genesis. |
| `key` | string | Id of the signing key. |
| `sig` | string | `"ed25519:" || base64url-nopad(Ed25519(sk, "gleipnir/record/v1\n" || record_hash))`. |

Key ids: `"k_ed25519_" || first 16 hex chars of SHA-256(raw 32-byte public key)`. Public keys: `"ed25519:" || base64url-nopad(raw)`.

ECDSA P-256 keys are also allowed, for KMS/HSM setups without Ed25519 (Azure Key Vault, Cloud KMS HSM): public key `"ecdsa-p256:" || base64url-nopad(DER SubjectPublicKeyInfo)`, key id `"k_p256_" || first 16 hex chars of SHA-256(DER SPKI)`, signature `"ecdsa-p256:" || base64url-nopad(DER ECDSA-SHA256 signature)` over the same message. A chain may rotate between key types.

## Kinds

**genesis**: `public_key: {id, public}`, `config: {heartbeat_seconds, segment_max_records}`. Signed by that key.

**action**: `agent: {id, version}`, `tool: {name, system}`, `args`, `response: {status: "ok", body} | {status: "error", error}`, `t: {start, end}`. Optional: `claim: {text}`, `outcome: {check, method, observed?, fields?, detail?}` with `check` in `match | mismatch | error | not_checked`, `context: {trace_id, span_id, session, run_id, on_behalf_of, parent_action, tool_call_id}`, `model`, `versions`, `identity`, `redaction: {fields, default}`.

Redacted values are replaced before hashing by `{"redacted": "dropped"}` or `{"redacted": "hmac-sha256:<hex>"}` (HMAC-SHA256 with a vendor-held key over the JCS encoding of the original value).

**claim**: `claim: {action, text}`. The agent's own statement about an earlier action.

**note**: `note: {text, ...}`.

**review**: `review: {reviewer, decision, rule?, before_execution?, reason?, changes?, action?}` for reviews, overrides and reversals. An *approval* of one exact action is a review with `decision: "approved"`, `tool`, `system` and `action_digest = sha256:hex(SHA-256(JCS({"tool", "system", "args"})))` over the action's (redacted) arguments. The approved action carries `approval: <review id>`. Verifiers require the review to come earlier in the chain, to match the digest, to be used by only one action, and the action's arguments to contain no dropped fields. `reviewer` is asserted by the vendor; a signed approval (below) binds the approval to the approver's own key.

### Signed approvals

An approval may carry `review.signature`, made by the approver outside the agent's process. It covers the approval message

    approval_message = "gleipnir/approval/v1\n" || action_digest      (ASCII, action_digest as written in the review)

Two signature types:

- **`type: "key"`**: `{type, approver_id, public_key, sig}`. `public_key` is an Ed25519 or ECDSA P-256 public key in the record key format (`"ed25519:"…` or `"ecdsa-p256:"…` DER SPKI); `sig` is a signature over `approval_message` in the record signature format (`"ed25519:"…`, or `"ecdsa-p256:"…` DER ECDSA-SHA256).
- **`type: "webauthn"`**: a passkey assertion (ES256), so a person approves on a phone or laptop. `{type, approver_id, public_key, rp_id, credential_id, authenticator_data, client_data_json, signature}`. `public_key` is the credential public key as `"ecdsa-p256:"…` DER SPKI; `authenticator_data`, `client_data_json` and `signature` (DER ECDSA) are base64url-nopad of the bytes the authenticator returned; `credential_id` is base64url-nopad of the credential's raw id; `rp_id` is informational (the registry's value is used). The WebAuthn challenge is the 32 raw bytes of the action digest (the hex after `sha256:`), so `clientDataJSON.challenge = base64url-nopad(those bytes)`. WebAuthn's own structure (`type`, rpId hash) separates these signatures from other uses of the credential.

**Approver registry.** Who may approve is the buyer's decision, not the vendor's. The buyer gives the verifier a registry, a JSON list of approvers:

```json
[{"id": "ops:anna", "name": "Anna Berger", "public_key": "ed25519:…", "roles": ["refunds"]},
 {"id": "ops:li", "name": "Li Wei", "webauthn": {"public_key": "ecdsa-p256:…", "rp_id": "approve.example.com",
  "credential_id": "…"}}]
```

Each entry has a unique non-empty string `id`, a string `name`, exactly one of `public_key` (for `key` signatures) or `webauthn` (`public_key` P-256, non-empty `rp_id`, optional base64url `credential_id`), and optional `roles` (list of strings, informational). Anything else is a usage error.

**Verification** of each action's approval, after the checks above, in this order:

1. No `signature`: `approval_unsigned`, a warning without a registry; an error with a registry (the buyer named who may approve) or with `--require-signed-approvals`.
2. `signature` is not an object, has an unknown `type`, no non-empty string `approver_id`, or the review's `reviewer` differs from `approver_id`: `approval_bad_signature`.
3. `public_key` cannot be decoded (or is not P-256 for `webauthn`): `approval_bad_signature` (`approval_webauthn_invalid` for `webauthn`).
4. With a registry: `approver_id` not in it, registered for the other type, or registered with a different key (compared by key id): `approval_unknown_approver`, an error. The registry's key, `rp_id` and `credential_id` are used from here on.
5. The review's `action_digest` must be `sha256:` + 64 lowercase hex, else the signature check fails.
6. `key`: the signature must verify over `approval_message` with the key: else `approval_bad_signature`.
7. `webauthn` (WebAuthn Level 3 §7.2 assertion checks; any failure is `approval_webauthn_invalid`): the three byte fields are base64url; `authenticator_data` is at least 37 bytes; `client_data_json` is UTF-8 JSON object with `type = "webauthn.get"`, `challenge` as above, `origin` in the verifier's allowed origins (`--webauthn-origin`, repeatable; default `https://<rp_id>`), no `crossOrigin: true` and no `topOrigin`; `rpIdHash` (bytes 0..31) = SHA-256(rp_id); flags (byte 32) have UP (0x01) and UV (0x04) set, AT (0x40) clear, BS (0x10) only with BE (0x08), and the data is exactly 37 bytes unless ED (0x80) is set (then longer); `credential_id` equals the registry's when it names one; the signature verifies with ECDSA P-256/SHA-256 over `authenticator_data || SHA-256(client_data_json)`.
8. Valid: with a registry, `approval_verified` (info) naming the approver; without one, `approval_unknown_approver` as a warning (an error with `--require-signed-approvals`): the signature is consistent, but nothing says whose key it is.

The signature counter is not checked (a stateless verifier has no previous value).

**config**: `config: {sinks: [{type, role, target, ...}], retention?: {days, note?}}`. The data-handling setup, written when it changes. `role: "buyer"` marks a copy the buyer controls.

**key_rotation**: `new_key: {id, public}`. Signed by the current key; every later record is signed by the new key.

**segment**: `segment: {from, count, root, opened_at, closed_at, heartbeat, prev_segment?}`.

- Covers every record with `from ≤ seq < from + count`, and `from + count` equals the segment record's own `seq`. Segments tile the chain: the first starts at seq 1, each next one starts right after the previous segment record.
- `root` is the RFC 6962 Merkle tree hash over the members' raw 32-byte record hashes, in seq order (leaf = SHA-256(0x00 || h), node = SHA-256(0x01 || l || r), empty tree = SHA-256("")).
- `opened_at` equals the previous segment's `closed_at` (or the genesis `time`). A segment closes after `segment_max_records` members or after `heartbeat_seconds`, also when empty.
- `prev_segment` is the previous segment record's hash.

**anchor**: `anchor: {segment_seq, segment_hash, type, receipt}`. Proof that `segment_hash` (the segment record's `record_hash`) was published outside the vendor. Receipts are written after the segment closes, so they live in a later segment.

- `type: "local"`: `receipt: {index, entry_hash, time, log}`, pointing into a local append-only log whose entries are `{v, index, chain, segment_seq, segment_hash, time, prev?, hash}` with `hash = sha256(JCS(entry minus "hash"))`. For tests only; not independent of the vendor.
- `type: "rekor"`: `receipt: {log_url, entry, anchor_key: {alg: "ecdsa-p256-sha256", public}, observed_at}`. `entry` is the Sigstore Rekor v2 `TransparencyLogEntry` exactly as returned. The log entry is a `hashedrekord` (v0.0.2) whose digest is SHA-256 of `"gleipnir/anchor/v1\n" || segment_hash`, signed with ECDSA P-256 by the anchor key (Rekor v2 does not accept pure Ed25519 entries). Verification: the body's digest and signature match the segment and anchor key; the RFC 6962 inclusion proof for SHA-256(0x00 || canonicalizedBody) verifies against the proof root; the checkpoint (signed note) has the log's origin, the same size and root, and a signature by the log key pinned in the Sigstore trusted root. `observed_at` is the vendor's clock, not trusted time.
- `type: "rfc3161"`: `receipt: {tsa_url, response, observed_at}`. `response` is the base64 DER RFC 3161 `TimeStampResp` for SHA-256 of `"gleipnir/timestamp/v1\n" || segment_hash`, verified against a timestamp authority in the Sigstore trusted root. Its `genTime` is trusted time: the segment existed no later than that. Verifiers compare it with the segment's `closed_at` and can fail segments timestamped too long after they closed (`--max-anchor-delay`).

Record ids are unique within a chain.

## Proof bundle

A single-action proof is a zip with `manifest.json` = `{format: 1, type: "proof", chain, key, action, action_seq, segment_seq, leaf_index, tree_size, proof: [hex, ...]}` and `records.jsonl` = genesis, the action, its segment, and the segment's anchor records. It verifies when every record is signed by the genesis key, the proven record is an action, it sits at `leaf_index` of a segment of `tree_size` members, the RFC 6962 inclusion proof leads to the segment's root, and the anchor receipts match the segment.

## Bundle

A zip file containing:

- `manifest.json`: `{format: 1, chain, from_seq, to_seq, exported_at, key, tool, since?, until?}`.
- `records.jsonl`: the genesis record, then records in seq order, one JSON value per line. Lines are split on `\n`; a line that is empty or holds only JSON whitespace (space, tab, CR) is skipped, and any other line must be exactly one JSON value with only JSON whitespace around it. A bundle that does not start at seq 1 must start at the first member of a segment.
- `anchors/local-anchor-log.jsonl` (optional).
- `VERIFY.md`: instructions for the recipient.

## Verification

A bundle is valid when, for every record: it is a JSON object with `v = 1` and the genesis chain id; its signature verifies with a key introduced by the genesis or a signed rotation that is current at that point; seqs are consecutive; `prev` matches; every segment's members are present and its root matches; segments link and tile; anchor receipts match their segment hash and verify for their type; the manifest range matches; and, when given, the expected key, expected coverage time and known head match.

Warnings (valid, but reported): records after the last segment, segments without receipts, time gaps longer than the heartbeat, receipts that could not be checked, approvals not signed by a registered approver.

Signed approvals are checked as described under **review**. Test vectors: [test-vectors/approvals.json](test-vectors/approvals.json) (`key` signatures with Ed25519 and P-256, a WebAuthn assertion from a fixed P-256 key with fixed authenticator data and client data, and invalid variants with their finding codes).
