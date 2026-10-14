# gleipnir-verify

Offline verifier for Gleipnir action record bundles. This is the part the buyer, auditor or insurer runs.

```bash
pipx run gleipnir-verify bundle.zip
```

It checks every signature, the hash chain (no edits, deletions, reordering or gaps), every segment's Merkle root, anchor receipts, and time coverage. It needs no account, no network and no access to the vendor's systems.

Format: see `spec/` in https://github.com/getgleipnir/gleipnir.
