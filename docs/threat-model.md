# Threat model

Who relies on Gleipnir records: the **buyer** of an AI agent (security, risk, audit), their **auditor**, **regulator** or **insurer**. Who produces them: the **vendor** running the agent. The records are useful only if the buyer does not have to trust the vendor's word.

## What a VALID verification proves

1. **Integrity.** No record in the bundle was edited, deleted, reordered or inserted after it was signed. Every record is signed (Ed25519, or ECDSA P-256 for KMS/HSM keys without Ed25519) and commits to the previous one (hash chain); segments commit to their records (Merkle root) and to the previous segment.
2. **Origin.** The records were signed by the holder of the vendor's key. With `--expect-key`, it is the key the vendor publishes (for example in its trust center).
3. **Existence no later than anchoring.** For a segment with a Rekor receipt, the segment hash was included in Sigstore's public append-only log, outside the vendor's control. Rewriting such a segment afterwards would require a different hash, which the existing receipt does not match.
4. **Outcome agreement, where checked.** For actions with `verify_outcome`, the vendor read the external system back after the action and recorded whether it matched (`match` / `mismatch`), together with the raw response.
5. **No silent truncation or omission, given an expectation.** With `--known-head` (the head from an earlier pack) a bundle that drops recent records fails; with `--require-full` one that drops early records fails; with `--require-anchor rekor` one whose anchor receipts were removed fails. Without these flags those cases are warnings, not failures, so buyers should always pass them (the generated VERIFY.md does).

## What it does not prove

- **Intent or correctness.** Records show what the agent did, not whether it should have.
- **Completeness.** An action the vendor never wrapped produces no record. Mitigation: the buyer reconciles `actions.csv` (external object ids) against its own system logs. A gap shows up as an object in the buyer's system with no matching record.
- **Truth of what was signed at the moment of signing.** A vendor (or attacker) controlling the process before signing can record a false response. Mitigations: outcome read-back from the system of record, buyer reconciliation, signing keys in a KMS/HSM outside the agent process.
- **Trusted time is bounded, not exact.** With `anchor="rekor"` each segment also gets an RFC 3161 timestamp from an independent authority, so the segment provably existed no later than that time. Record times inside a segment are still the vendor's clock; the timestamp only bounds them from above.
- **Records after the last anchor.** The unanchored tail is reported explicitly. Truncation inside the last heartbeat interval is detectable only with `--known-head`.
- **Records before genesis or outside the bundle.** A partial bundle proves its own range.

- **Who approved, without a registry.** An approval proves that a review naming this exact action was written before the action. Unsigned, `reviewer` is the vendor's statement (`approval_unsigned`). Signed but checked without `--approvers`, it proves that *some* key approved this action, not whose key it is (`approval_unknown_approver`, a warning). The buyer's approver registry is what turns a signature into a person.
- **Signed approvals bound a person to the action, not to the moment.** With `--approvers` (and `--require-signed-approvals`), every approval must carry a signature by a key or passkey the buyer registered, over `"gleipnir/approval/v1\n" || action_digest`: the vendor cannot forge one or move it to a different action. It does not prove *when* the approver signed (the review's position in the chain bounds it, the vendor's clock dates it), that the approver read what they signed (the passkey page recomputes the digest from the arguments it shows; a CLI user signs a digest), or that a stolen approver key or passkey was not used. The WebAuthn signature counter is not checked (a stateless verifier has nothing to compare it with). Approvals over redacted arguments bind the HMAC of the value, so the approver needs to see the value elsewhere.
- **`--max-anchor-delay` needs timestamps.** It only works on segments with an RFC 3161 receipt, and fails segments that have none.

## Attacker capabilities considered

| Attacker | Can | Detected by |
|---|---|---|
| Anyone handling the bundle (email, storage) | Edit, delete, reorder, insert records | Signatures, hash chain, Merkle roots |
| Vendor staff without the signing key | Same | Same |
| Vendor with the signing key, after anchoring | Rewrite and re-sign anchored segments, keeping the old receipts | Receipts no longer match the segment hash |
| Same, removing the receipts | Rewrite and drop every anchor receipt | `--require-anchor rekor` (without it: only a warning) |
| Vendor with the signing key and the anchor key, rewriting everything | Rebuild history and anchor and timestamp it again | New timestamps are later than the segments claim: `--max-anchor-delay` fails them; `--known-head` too. A rewrite done within the allowed delay is not detected |
| Vendor dropping early records | Export a bundle that starts later in the chain | `--require-full` (without it: a warning, and the summary marks the bundle partial) |
| Vendor dropping recent records | Truncate the tail | Manifest range, `--known-head`; `--expect-until` only beyond one heartbeat |
| Vendor not recording some actions | Omit | `gleipnir-verify reconcile` against the buyer's own system export |
| Vendor claiming an approval that did not happen first | Write the approval after the action, or reuse one approval | `approval_after_action`, `approval_reused`, `approval_mismatch` |
| Vendor (or the agent) inventing an approval | Write a review naming an approver who never approved | `--approvers` with `--require-signed-approvals`: `approval_unsigned`, `approval_unknown_approver` (without them: a warning) |
| Vendor reusing a real approver's signature | Copy a signature onto another action, or edit the approved digest | The signature covers the digest: `approval_bad_signature` / `approval_webauthn_invalid`, and `approval_mismatch` |
| Vendor registering its own key as an approver | Sign approvals itself | Not by the verifier: the registry is the buyer's file, so the buyer must collect keys from the approvers (not from the vendor) |
| Phishing page collecting passkey approvals | Get a real passkey assertion for an action through another site | rpIdHash (passkeys are bound to their domain), allowed origins (`--webauthn-origin`), no cross-origin frames |
| Someone stealing the signing key from the agent host | Sign forged records | Use a KMS/HSM signer (AWS, Google Cloud, Azure): the key cannot be copied |
| Malicious bundle aimed at the verifier | Invalid UTF-8, malformed or deeply nested JSON, huge numbers, bad zip, bad arguments | Verifier reports findings or a usage error instead of a traceback (regression-tested) |

## Keys

- **Record signing key** (Ed25519 by default, ECDSA P-256 allowed): auto-generated locally for development, with a warning. Production should use a KMS/HSM-backed `Signer`. Rotation is supported with a signed `key_rotation` record.
- **Anchor key** (ECDSA P-256): only signs anchor entries in Rekor. Its compromise lets someone publish entries but not forge records.
- **Approver keys** (Ed25519 or ECDSA P-256, or a passkey): held by each approver on their own device, never by the agent. `gleipnir approve keygen` / `sign`, or the passkey page site/approve/, which needs no backend. The buyer lists them in its approvers file; compromise of one lets someone approve as that person until the buyer removes the entry.
- **Redaction HMAC key**: lets the vendor (and a buyer who is given the value) match redacted fields without storing the value. Losing it does not affect verification.

## Privacy

Only segment hashes, an anchor signature and the anchor public key leave the vendor. Record content stays local unless the vendor exports a bundle. Redaction happens before hashing. Note that the anchor public key is visible in a public log, which links a vendor's anchors to each other (not to their content).
