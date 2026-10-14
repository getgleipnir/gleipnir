# Gleipnir record format, version 1

Normative. Implementations in any language must produce and accept exactly this. The test vectors in [test-vectors/](test-vectors/) are part of the spec.

## Encoding

- A record is a JSON object. Bytes for hashing are its **RFC 8785 (JCS)** canonical form, UTF-8.
- Integers must be in the IEEE 754 safe range (|n| ≤ 2^53 − 1). Money should be strings or integer minor units.
- `record_hash = "sha256:" || hex(SHA-256(JCS(record minus "sig")))`.
- Optional fields are omitted, never `null`. Unknown fields are allowed and are covered by the hash.
- Timestamps are RFC 3339 UTC with a `Z` suffix, for example `2026-10-14T09:14:05.112Z`.

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

## Kinds

**genesis**: `public_key: {id, public}`, `config: {heartbeat_seconds, segment_max_records}`. Signed by that key.

**action**: `agent: {id, version}`, `tool: {name, system}`, `args`, `response: {status: "ok", body} | {status: "error", error}`, `t: {start, end}`. Optional: `claim: {text}`, `outcome: {check, method, observed?, fields?, detail?}` with `check` in `match | mismatch | error | not_checked`, `context: {trace_id, span_id, session, run_id, on_behalf_of, parent_action}`, `model`, `versions`, `identity`, `redaction: {fields, default}`.

Redacted values are replaced before hashing by `{"redacted": "dropped"}` or `{"redacted": "hmac-sha256:<hex>"}` (HMAC-SHA256 with a vendor-held key over the JCS encoding of the original value).

**claim**: `claim: {action, text}`. The agent's own statement about an earlier action.

**note**: `note: {text, ...}`.

**key_rotation**: `new_key: {id, public}`. Signed by the current key; every later record is signed by the new key.

**segment**: `segment: {from, count, root, opened_at, closed_at, heartbeat, prev_segment?}`.

- Covers every record with `from ≤ seq < from + count`, and `from + count` equals the segment record's own `seq`. Segments tile the chain: the first starts at seq 1, each next one starts right after the previous segment record.
- `root` is the RFC 6962 Merkle tree hash over the members' raw 32-byte record hashes, in seq order (leaf = SHA-256(0x00 || h), node = SHA-256(0x01 || l || r), empty tree = SHA-256("")).
- `opened_at` equals the previous segment's `closed_at` (or the genesis `time`). A segment closes after `segment_max_records` members or after `heartbeat_seconds`, also when empty.
- `prev_segment` is the previous segment record's hash.

**anchor**: `anchor: {segment_seq, segment_hash, type, receipt}`. Proof that `segment_hash` (the segment record's `record_hash`) was published outside the vendor. Receipts are written after the segment closes, so they live in a later segment.

- `type: "local"`: `receipt: {index, entry_hash, time, log}`, pointing into a local append-only log whose entries are `{v, index, chain, segment_seq, segment_hash, time, prev?, hash}` with `hash = sha256(JCS(entry minus "hash"))`. For tests only; not independent of the vendor.
- `type: "rekor"`: defined in the anchor stage.

## Bundle

A zip file containing:

- `manifest.json`: `{format: 1, chain, from_seq, to_seq, exported_at, key, tool, since?, until?}`.
- `records.jsonl`: the genesis record, then records in seq order. A bundle that does not start at seq 1 must start at the first member of a segment.
- `anchors/local-anchor-log.jsonl` (optional).
- `VERIFY.md`: instructions for the recipient.

## Verification

A bundle is valid when, for every record: it is a JSON object with `v = 1` and the genesis chain id; its signature verifies with a key introduced by the genesis or a signed rotation that is current at that point; seqs are consecutive; `prev` matches; every segment's members are present and its root matches; segments link and tile; anchor receipts match their segment hash and verify for their type; the manifest range matches; and, when given, the expected key, expected coverage time and known head match.

Warnings (valid, but reported): records after the last segment, segments without receipts, time gaps longer than the heartbeat, receipts that could not be checked.
