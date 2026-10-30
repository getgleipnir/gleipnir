# Gleipnir hosted checker (SANDBOX)

> **SANDBOX. Not for real money.** Decisions are signed by sandbox keys (checker id `sandbox:<tenant>`).
> Use it to integrate and test. Do not let a real transfer depend on it.

A hosted version of the reference bank checker (`gleipnir mandate serve`) for pilot partners. Before a
platform, PSP or bank sends a transfer an AI agent started, it posts the agent's mandate and payment here and gets
back a signed **allow / block / escalate** decision (spec/mandate.md v0.4, checked by `@getgleipnir/verify`, the
same library and the same conformance vectors as the Python reference).

It runs as **its own Netlify site** (Functions v2 + Netlify Blobs), e.g. `https://gleipnir-check.netlify.app`. It
has nothing to do with the getgleipnir.com site.

## Tenants

Each pilot partner is a tenant with:

- a tenant id (`acme-psp`) and checker id `sandbox:acme-psp`;
- its own Ed25519 checker key, generated on creation and stored only encrypted (AES-256-GCM under a key derived
  from `MASTER_KEY`, bound to the tenant id). It is never returned; only the public key is published;
- an API key (`gks_<tenant>_<random>`), shown once on creation. Only an HMAC of it is stored;
- an **authority table**: what the partner's KYB knows. Who may sign for which company, with which public keys,
  and which accounts each company holds. Same shape as the `--authority` file of `gleipnir mandate serve`:

```json
{
  "source": "bank_kyb",
  "signers":  [{"company": "Nordhafen Logistik GmbH", "signer": "kberger@nordhafen.at",
                "keys": ["ed25519:..."], "may_sign": true, "joint": 1}],
  "accounts": [{"company": "Nordhafen Logistik GmbH", "account": {"scheme": "iban", "iban": "AT483200000012345864"}}],
  "officers": [],
  "require_payees": false
}
```

Optional per row: `retired` (rotated-out key → RFC 3339 time), `person` (one person under several ids), and per
account `customer` (the payment log key; default the company name). Optional at top level: `officers` (public keys
of the partner's staff who may sign bank overrides), `require_payees`, `webauthn` (`{"rp_id", "origins"}` for
passkey-signed mandates).

## API

Same contract as `gleipnir mandate serve`, under `/v1`, with a bearer key:

| Method and path | Auth | Body → answer |
|---|---|---|
| `POST /v1/check` | tenant | `{"mandate", "payment"}` → the signed decision |
| `POST /v1/resolve` | tenant | `{"mandate", "payment", "decision", "override"}` → the decision after a signed override |
| `POST /v1/revoke` | tenant | `{"revocation", "mandate"}` → `{"ok": true, "checker"}`; stored only if it counts for that mandate |
| `GET /v1/revocations` | tenant | signed list of the stored revocations, current for an hour |
| `GET /v1/keys` | tenant | `{"checker", "keys"}` |
| `GET /t/<tenant>/keys` | public | `{"checker", "keys"}` |
| `GET /t/<tenant>/.well-known/gleipnir-checker.json` | public | the key set (spec 10.1) to verify decisions with |
| `POST /v1/admin/tenants` | `ADMIN_TOKEN` | `{"id"[, "authority"]}` → `201` with `api_key` (once) |
| `POST /v1/admin/tenants/<id>/api-key` | `ADMIN_TOKEN` | → a new `api_key`; the old one stops working |
| `PUT /v1/admin/tenants/<id>/authority` | `ADMIN_TOKEN` or that tenant's key | the authority table (replaces it) |
| `GET /v1/admin/tenants/<id>/authority` | `ADMIN_TOKEN` or that tenant's key | the authority table |

Rules, as the reference server: POST/PUT need `Content-Type: application/json`; bodies are 1 byte to 1 MiB of strict
JSON (duplicate keys, floats, NaN refused with `400`); `/check`, `/resolve` and `/revoke` take exactly the listed
fields. Requests with an `Origin` header (browsers) are refused with `403` unless the origin is in
`ALLOW_ORIGINS`: API keys belong on servers. Errors are `{"error": "..."}`: `400` bad input, `401` auth,
`404`, `405`, `409` tenant exists, `415`, `429` rate limit, `503` store or configuration unavailable. Every
response carries `Gleipnir-Environment: sandbox`; decisions carry `checker.id = "sandbox:<tenant>"`.

## Pilot partner quickstart (curl)

```sh
BASE=https://gleipnir-check.netlify.app

# 1. (Gleipnir) create the tenant; the api_key is shown once: send it to the partner over a secure channel
curl -sS -X POST $BASE/v1/admin/tenants -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"id": "acme-psp"}'
KEY=gks_acme-psp_...

# 2. (partner or Gleipnir) set the authority table: who may sign, and which accounts the company holds
curl -sS -X PUT $BASE/v1/admin/tenants/acme-psp/authority -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -d @authority.json

# 3. check a payment the agent started (mandate signed by the signatory, payment signed by the agent)
curl -sS -X POST $BASE/v1/check -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -d '{"mandate": '"$(cat mandate.json)"', "payment": '"$(cat payment.json)"'}'
# -> {"v": "gleipnir/decision/0.4", "outcome": "allow", "reasons": [], "checker": {"id": "sandbox:acme-psp", ...}, "sig": ...}

# 4. verify decisions offline against the published key set
curl -sS $BASE/t/acme-psp/.well-known/gleipnir-checker.json
```

Mandates and payments are made with the SDKs (`gleipnir mandate sign` / `attach` in Python, `issue`, `signMandate`,
`attach` from `@getgleipnir/verify/mandate`). `scripts/hosted-smoke.mjs` shows the whole flow in about 100 lines.

**Smoke test** (the three demo cases: allow, tricked-agent payee block, over-limit escalate then signatory override):

```sh
cd typescript && npm ci && npm run build -w @getgleipnir/verify
node packages/hosted/scripts/hosted-smoke.mjs https://gleipnir-check.netlify.app gks_acme-psp_...
```

It adds a throwaway "Gleipnir Smoke ..." company with a fresh key to that tenant's authority table (other rows are
kept, earlier smoke rows replaced). Prefer a dedicated `smoke` tenant.

## Deploy

One-time, from this directory (`typescript/packages/hosted`), with the Netlify CLI logged in:

```sh
cd typescript/packages/hosted
netlify sites:create --name gleipnir-check          # a NEW site; do not link getgleipnir.com
netlify env:set MASTER_KEY  "$(openssl rand -base64 48)" --secret
netlify env:set ADMIN_TOKEN "$(openssl rand -base64 48)" --secret
netlify deploy --build            # draft URL: run the smoke test against it
netlify deploy --build --prod
```

Environment variables:

| Name | Required | What |
|---|---|---|
| `MASTER_KEY` | yes (≥ 32 chars) | encrypts tenant checker keys, keys the API key hashes. **Changing or losing it makes every tenant key unusable** (`503`) and invalidates every API key. Keep a copy in the password manager. |
| `ADMIN_TOKEN` | yes for admin (≥ 32 chars) | bearer token for `/v1/admin/*`. Without it admin is closed. |
| `RATE_LIMIT_PER_MIN` | no (120) | requests per minute per API key |
| `ALLOW_ORIGINS` | no | comma-separated browser origins allowed to call authenticated endpoints |

The build runs `npm ci` at `typescript/` and builds `@getgleipnir/verify`, which the function imports; Netlify
bundles the function with esbuild (Node 20). State lives in the site-wide Blobs store `gleipnir-sandbox-checker`
(survives deploys). If the CLI does not pick up the monorepo layout, run it with `--filter @getgleipnir/hosted-checker`
or set Base directory `typescript/packages/hosted` in the site settings.

## State and atomicity

- **Payment log** (idempotency, replay protection, spec 7): one blob per (tenant, payer, payment id), keyed by
  SHA-256 of the library's `paymentKey`. `register` is a create-only write (`onlyIfNew`), so of two concurrent
  checks of one payment id exactly one claims it. `remember` and `take` are compare-and-swap on the ETag
  (`onlyIfMatch`), so two concurrent overrides of one escalation cannot both re-check.
- **Period ledger**: one blob per (tenant, limited object, calendar period). `reserve` reads the total with its
  ETag, refuses if it would pass the limit, writes with `onlyIfMatch` (or `onlyIfNew`) and retries on conflict
  (8 tries, jittered backoff). Concurrent checks cannot both fit into the last of a limit (tested).
- **Revocations**: one blob per tenant, appended with compare-and-swap; at most 1000 per tenant, 4 KiB each.
- All reads use strong consistency.

**Fail closed.** If the ledger or payment log cannot be read or written (or the retries run out), the library
answers a signed **escalate `checker_unavailable`**. If the revocations cannot be read, the checker is built so
that every payment gets the same signed `checker_unavailable`. If the tenant record itself cannot be read, the
answer is `503`. Nothing is ever allowed on a guess.

Remaining races and gaps (acceptable for a sandbox, to fix before production):

1. A mandate with a period limit plus delegation links reserves each limit in its own blob. The library does this
   all-or-nothing by giving back earlier reservations if a later one fails; a function crash in between leaves an
   over-count. That errs strict (later payments may escalate too early), never lenient.
2. If the function dies after claiming a payment id but before storing the decision (or the store fails exactly
   then), the id stays claimed with no decision: retries get `block duplicate_payment`. Strict again; the agent
   uses a new payment id. There is deliberately no automatic takeover of stale claims, because after a lost
   `remember` it would allow a replay.
3. `forget` is an unconditional delete. Only the request that holds the claim calls it, so it cannot race with
   another writer of that key.
4. Correctness relies on Netlify Blobs honouring `onlyIfNew` / `onlyIfMatch` atomically with strong consistency,
   as documented. Under heavy contention on one key, checks escalate `checker_unavailable` rather than waiting.

## Limits

- Sandbox only: shared Netlify infrastructure, no SLA, no HSM. Tenant keys are protected by `MASTER_KEY` in
  Netlify env, not by hardware.
- Rate limits are per function instance and best effort (in memory): 120/min per key by default, 120/min per IP on
  public endpoints, 20 failed auth attempts per IP per minute (then `429` for that IP for the rest of the minute).
- Mandates with a `status_url` are not fetched (no outbound requests from the sandbox): they escalate
  `status_unavailable`. Use `/v1/revoke` instead. No revocation feed (`revocationFeed`).
- Authority and holds come only from the tenant's table (no vLEI or register lookup).
- The key set lists only the current key; there is no key rotation for checker keys yet.
- Paths are versioned (`/v1/check`) and need a bearer key, so the Python MCP tool `check_payment --bank-url`
  (which posts to `<url>/check` without auth) does not talk to this server directly.

## Development

```sh
cd typescript
npm ci
npx vitest run packages/hosted     # handlers with an in-memory Blobs fake, plus the shared conformance vectors
npm run typecheck
```
