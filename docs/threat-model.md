# Threat model

Who relies on Gleipnir records: the **buyer** of an AI agent (security, risk, audit), their **auditor**, **regulator** or **insurer**. Who produces them: the **vendor** running the agent. The records are useful only if the buyer does not have to trust the vendor's word.

## What a VALID verification proves

1. **Integrity.** No record in the bundle was edited, deleted, reordered or inserted after it was signed. Every record is Ed25519-signed and commits to the previous one (hash chain); segments commit to their records (Merkle root) and to the previous segment.
2. **Origin.** The records were signed by the holder of the vendor's key. With `--expect-key`, it is the key the vendor publishes (for example in its trust center).
3. **Existence no later than anchoring.** For a segment with a Rekor receipt, the segment hash was included in Sigstore's public append-only log, outside the vendor's control. Rewriting such a segment afterwards would require a different hash, which the existing receipt does not match.
4. **Outcome agreement, where checked.** For actions with `verify_outcome`, the vendor read the external system back after the action and recorded whether it matched (`match` / `mismatch`), together with the raw response.
5. **No silent truncation, given an expectation.** With `--known-head` (the head from an earlier pack) or `--expect-until`, a bundle that drops recent records fails.

## What it does not prove

- **Intent or correctness.** Records show what the agent did, not whether it should have.
- **Completeness.** An action the vendor never wrapped produces no record. Mitigation: the buyer reconciles `actions.csv` (external object ids) against its own system logs. A gap shows up as an object in the buyer's system with no matching record.
- **Truth of what was signed at the moment of signing.** A vendor (or attacker) controlling the process before signing can record a false response. Mitigations: outcome read-back from the system of record, buyer reconciliation, signing keys in a KMS/HSM outside the agent process.
- **Trusted time.** Record and anchor times come from the vendor's clock. Rekor v2 returns inclusion proofs but no signed timestamps; an RFC 3161 timestamp from an independent authority is planned. Until then, a vendor holding the key could rebuild history and re-anchor it later; the new log entries would carry later log positions, but the verifier does not yet turn that into wall-clock evidence.
- **Records after the last anchor.** The unanchored tail is reported explicitly. Truncation inside the last heartbeat interval is detectable only with `--known-head`.
- **Records before genesis or outside the bundle.** A partial bundle proves its own range.

## Attacker capabilities considered

| Attacker | Can | Detected by |
|---|---|---|
| Anyone handling the bundle (email, storage) | Edit, delete, reorder, insert records | Signatures, hash chain, Merkle roots |
| Vendor staff without the signing key | Same | Same |
| Vendor with the signing key, after anchoring | Rewrite and re-sign anchored segments | Anchor receipts no longer match; `--known-head` |
| Vendor with the signing key, rewriting everything including anchors | Re-anchor rewritten history with new receipts | `--known-head`, `--expect-key` against a previously published key, log positions; trusted timestamps (planned) |
| Vendor dropping recent records | Truncate the tail | Manifest range, `--expect-until`, `--known-head` |
| Vendor not recording some actions | Omit | Buyer reconciliation against its own systems |
| Malicious bundle aimed at the verifier | Malformed JSON, huge numbers, bad zip | Verifier reports findings and never crashes (tested) |

## Keys

- **Record signing key** (Ed25519): auto-generated locally for development, with a warning. Production should use a KMS/HSM-backed `Signer`. Rotation is supported with a signed `key_rotation` record.
- **Anchor key** (ECDSA P-256): only signs anchor entries in Rekor. Its compromise lets someone publish entries but not forge records.
- **Redaction HMAC key**: lets the vendor (and a buyer who is given the value) match redacted fields without storing the value. Losing it does not affect verification.

## Privacy

Only segment hashes, an anchor signature and the anchor public key leave the vendor. Record content stays local unless the vendor exports a bundle. Redaction happens before hashing. Note that the anchor public key is visible in a public log, which links a vendor's anchors to each other (not to their content).
