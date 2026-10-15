# Gleipnir verify action

A GitHub Action that verifies Gleipnir agent action record bundles (`bundle.zip`, `proof.zip`) offline, writes a job summary (VALID/INVALID, a table per bundle, every finding) and fails the step if any bundle is INVALID.

It needs no network access and no install step. By default it runs the TypeScript verifier (`@getgleipnir/verify`), bundled into [`dist/gleipnir-verify.mjs`](dist/gleipnir-verify.mjs) as one dependency-free file. It can also run the reference Python verifier (`gleipnir-verify`). Both give the same verdicts and reports.

## Usage

Until the action is published as its own repository, use it from this repository's path:

```yaml
- uses: actions/checkout@v4
- uses: getgleipnir/gleipnir/action@main   # or `uses: ./action` inside this repo
  with:
    bundle: evidence/**/*.zip
    expect-key: k_ed25519_56475aa75463474c
    require-anchor: rekor, rfc3161
    require-full: true
    max-anchor-delay: 86400
```

Pin a commit SHA instead of `@main` for anything that matters. Once it is published as `getgleipnir/verify-action`, the inputs stay the same:

```yaml
- uses: getgleipnir/verify-action@v1
  with:
    bundle: bundle.zip
```

### Detecting truncation across runs

A bundle's `head` (the last record's `SEQ:HASH`) is an output. Store it, then pass it as `known-head` when you check the next bundle from the same chain. Verification fails if that record is missing or changed, which catches history that was cut off or rewritten:

```yaml
- id: verify
  uses: getgleipnir/gleipnir/action@main
  with:
    bundle: bundle.zip
    expect-key: ${{ vars.GLEIPNIR_KEY }}
    known-head: ${{ vars.GLEIPNIR_LAST_HEAD }}
- run: echo "new head ${{ steps.verify.outputs.head }}"
```

### Checking a bundle you expect to fail

```yaml
- id: verify
  continue-on-error: true
  uses: getgleipnir/gleipnir/action@main
  with:
    bundle: tampered.zip
- run: test "${{ steps.verify.outcome }}" = failure && test "${{ steps.verify.outputs.result }}" = INVALID
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `bundle` | (required) | Path or glob (`*`, `**`, `?`, `[...]`, `{a,b}`), one per line. A line starting with `!` excludes. Relative to the workspace. No match is an error. |
| `expect-key` | | Fail unless the chain is signed with this key id. Without it, a valid bundle only shows that some key signed it consistently. |
| `require-anchor` | | Fail unless every segment has a verified independent anchor of each listed type: `rekor` (Sigstore Rekor public log), `rfc3161` (trusted timestamp). Comma or space separated. |
| `require-full` | `false` | Fail unless the bundle starts at the beginning of the chain (genesis). |
| `max-anchor-delay` | | Fail if a segment was timestamped more than this many seconds after it closed. |
| `known-head` | | `SEQ:sha256:HEX` from an earlier bundle. Fail unless that record is present and unchanged. |
| `expect-until` | | Fail unless records cover at least until this ISO 8601 time. |
| `trusted-root` | | A Sigstore `trusted_root.json` to use instead of the embedded one, for newer Rekor shards. |
| `strict` | `false` | Treat warnings as failures. |
| `verifier` | `typescript` | `typescript` (bundled) or `python`. |
| `python-command` | `pipx run gleipnir-verify` | Command for the Python verifier, e.g. `uv run gleipnir-verify`. |

The inputs map one to one to the `gleipnir-verify` CLI flags.

## Outputs

| Output | Value |
|---|---|
| `result` | `VALID`, `INVALID`, or `ERROR` (bad input, no bundle matched, verifier did not run) |
| `bundles` | number of bundles verified |
| `invalid` | the INVALID bundles, one per line |
| `head` | `SEQ:HASH` of the bundle when exactly one was verified |
| `report` | JSON array of the verifier reports (`bundle`, `valid`, `result`, `summary`, `findings`) |

The step fails (exit 1) on `INVALID` and on `ERROR`. Each error and warning finding is also emitted as a workflow annotation.

## Develop

- `run.mjs` is the action. It has no dependencies and reads inputs from `INPUT_*` environment variables, so you can run it locally:
  `INPUT_BUNDLE='action/test/fixtures/*.zip' node action/run.mjs`
- `dist/gleipnir-verify.mjs` is generated from `typescript/packages/verify/src` by `npm run build:action` in `typescript/`. A test fails if it is stale.
- `test/fixtures/valid.zip` is a TypeScript SDK bundle whose segments are anchored on public Rekor v2 and timestamped by Sigstore's TSA. `tampered.zip` is the same bundle with one refund amount changed afterwards. `fixtures.json` holds the key id and head used by the tests. `node scripts/make-action-fixtures.mjs` (in `typescript/`) regenerates all three; update the key and head in `.github/workflows/action-test.yml` if you do.
- Tests: `typescript/packages/verify/test/action.test.ts` (in `npm test`) and `.github/workflows/action-test.yml`, which runs the action itself on a valid bundle and on a tampered one (`continue-on-error` plus assertions on `outcome` and outputs), with both verifiers.
