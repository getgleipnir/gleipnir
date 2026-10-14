# Quickstart: a refund agent with verifiable records

Five minutes, no API keys. A toy support agent issues refunds against a fake payments API. Every refund is recorded with the payments system's real response, checked by reading the refund back, signed, chained and anchored. Then you verify the records as a buyer would, tamper with them, and watch verification fail.

```bash
git clone https://github.com/getgleipnir/gleipnir
cd gleipnir
uv sync --all-packages
cd examples/refund-agent

uv run python agent.py
```

The fake payments API has a bug: on refunds over $100 it books 50 cents less than it reports. The agent's own messages say everything went fine. The records show two **outcome mismatches**, because the wrapper read each refund back from the system of record.

**Verify, as the buyer would** (offline, no access to the vendor):

```bash
uv run gleipnir-verify bundle.zip --expect-key <key id printed by agent.py>
```

**Tamper and verify again.** `tamper.py` flips one mismatch to "match", the kind of edit someone might make before a review:

```bash
uv run python tamper.py bundle.zip tampered.zip
uv run gleipnir-verify tampered.zip
# [FAIL] seq 2 bad_signature: signature does not match record content (record altered?)
# [FAIL] seq 3 broken_chain: prev does not match the hash of the preceding record
# result: INVALID (2 problems)
```

**Open the Security Review Pack.** `security-review-pack.zip` contains `summary.html` (systems touched, identities and scopes, failures, mismatches, checklist coverage), `actions.csv` for reconciliation with the buyer's own logs, and the bundle.

**Anchor in a public log.** By default the demo uses a local test anchor. To publish segment hashes to the public Sigstore Rekor log (only hashes leave your machine):

```bash
uv run python agent.py --rekor
uv run gleipnir-verify bundle.zip
# segments: 4, anchored 4 (independent anchors: 4)
```

**See what your setup covers** in the open [security review checklist](https://github.com/getgleipnir/agent-security-review):

```bash
uv run gleipnir --home .gleipnir check
```
