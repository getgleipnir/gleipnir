# gleipnir-verify

Offline verifier for Gleipnir action record bundles. This is the part the buyer, auditor or insurer runs.

```bash
pipx run gleipnir-verify bundle.zip
```

It checks every signature, the hash chain (no edits, deletions, reordering or gaps), every segment's Merkle root, anchor receipts, and time coverage. It needs no account, no network and no access to the vendor's systems.

Format: see `spec/` in https://github.com/getgleipnir/gleipnir.

It also holds the reference checker for Gleipnir mandates (Know Your Agent for bank transfers): `gleipnir_verify.mandate`
checks a payment an AI agent started against the mandate a company signatory signed, and returns a signed allow, block
or escalate decision. It implements spec 0.5 (draft) and still accepts 0.4 objects with 0.4 behaviour; the package
version is 0.4.0, the last release. See `spec/mandate.md`.
