# Gleipnir hosted checker (SANDBOX)

> **SANDBOX. Not for real money.** Decisions are signed by sandbox keys (checker id `sandbox:<tenant>`).
> Use it to integrate and test. Do not let a real transfer depend on it.

A hosted version of the reference bank checker (`gleipnir mandate serve`) for pilot partners. Before a
platform, PSP or bank sends a transfer an AI agent started, it posts the agent's mandate and payment here and gets
back a signed **allow / block / escalate** decision (spec/mandate.md v0.4, checked by `@getgleipnir/verify`, the
same library and the same conformance vectors as the Python reference).

It runs as **its own Netlify site** (Functions v2 + Netlify Blobs), e.g. `https://gleipnir-check.netlify.app`. It
has nothing to do with the getgleipnir.com site.

## Tenants and keys

Each pilot partner is a tenant with:

- a tenant id and checker id `sandbox:<id>`. **Tenant ids are public**: they appear in the key URLs
  (`/t/<id>/keys`) and in every decision. Omit `id` on creation to get an opaque one (`t-<16 hex>`);
- its own Ed25519 checker key, generated on creation and stored only encrypted (AES-256-GCM under a key derived
  from `MASTER_KEY`, bound to the tenant id). It is never returned; only the public key is published (from a
  separate small blob, so the public endpoints never read the record that holds the sealed key and key hashes);
- two bearer keys, each shown once, only an HMAC of each stored:
  - the **check key** (`gks_<id>_...`): check, resolve, revoke, revocations, keys. It cannot change who may sign;
  - the **KYB key** (`gkk_<id>_...`): only reads and replaces the authority table. Keep it with whoever runs
    the partner's KYB, not in the payment path;
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

Every authority change gets a version number and is first written to an append-only log
(`t/<id>/authority-log/<version>-<nonce>` in the store: time, who (admin or KYB key), hash, previous hash, the
full table); the table is then switched only if no other change came in meanwhile and the KYB key used was not
rotated in between (`409` otherwise). A log entry whose version never became current is an attempt that lost.

## API

Same contract as `gleipnir mandate serve`, under `/v1`, with a bearer key:

| Method and path | Auth | Body → answer |
|---|---|---|
| `POST /v1/check` | check key | `{"mandate", "payment"[, "payee_approvals"]}` → the signed decision |
| `POST /v1/resolve` | check key | `{"mandate", "payment", "decision", "override"[, "payee_approvals"]}` → the decision after a signed override |
| `POST /v1/revoke` | check key | `{"revocation", "mandate"[, "payee_approval"]}` → `{"ok": true, "checker"}` |
| `POST /v1/release` | check key | `{"mandate", "payment", "decision"}` → `{"released": true, ...}`: the bank did not execute this allowed payment; its reservations come back once, within `RELEASE_WINDOW_HOURS` and the same limit period; the payment id stays used |
| `GET /v1/revocations` | check key | signed list of the stored revocations, current for an hour |
| `GET /v1/keys` | check key | `{"checker", "keys"}` |
| `GET /t/<tenant>/keys` | public | `{"checker", "keys"}` |
| `GET /t/<tenant>/.well-known/gleipnir-checker.json` | public | the key set (spec 10.1) to verify decisions with |
| `POST /v1/admin/tenants` | `ADMIN_TOKEN` | `{["id"][, "authority"]}` → `201` with `api_key` and `kyb_key` (once) |
| `DELETE /v1/admin/tenants/<id>` | `ADMIN_TOKEN` | the tenant and **all** its data → `{"deleted": true, "keys": n}`; `404` if nothing is there |
| `POST /v1/admin/tenants/<id>/api-key` | `ADMIN_TOKEN` | → a new check key; the old one stops working |
| `POST /v1/admin/tenants/<id>/kyb-key` | `ADMIN_TOKEN` | → a new KYB key; the old one stops working |
| `PUT /v1/admin/tenants/<id>/authority` | `ADMIN_TOKEN` or that tenant's KYB key | the authority table (replaces it) → `{"ok", "version", "hash"}` |
| `GET /v1/admin/tenants/<id>/authority` | `ADMIN_TOKEN` or that tenant's KYB key | the authority table |

`/v1/revoke` answers `ok` once the revocation is **verified and stored**: well formed, at most 4 KiB, validly
signed, aimed at this mandate or a link of its chain, by someone the authority table says may revoke it, every
link of the chain for the mandate's company. It is checked again on every payment (a revocation stops counting if
the authority table no longer backs its signer). A revocation with a future `revoked_at` is stored but switches
the mandate off only from then.

Rules, as the reference server: POST/PUT need `Content-Type: application/json`; bodies are 1 byte to 1 MiB of strict
JSON (duplicate keys, floats, NaN refused with `400`); `/check`, `/resolve` and `/revoke` take exactly the listed
fields. Requests with an `Origin` header (browsers) are refused with `403` unless the origin is in
`ALLOW_ORIGINS`: keys belong on servers. Errors are `{"error": "..."}`: `400` bad input, `401` auth, `404`,
`405`, `409` conflict, `415`, `429` rate limit, `503` store or configuration unavailable. Every response carries
`Gleipnir-Environment: sandbox` and HSTS/CSP headers; decisions carry `checker.id = "sandbox:<tenant>"`.

**Payee approvals** (spec 0.5, section 7.2) travel with a payment as `payee_approvals`, a list of at most 16; they
count for 0.5 mandates only. Their revocations are stored per approval hash, and `/v1/revoke` needs the approval
itself (`payee_approval`) to verify that the revocation is aimed at an approval of this mandate by someone who may
revoke it.

**Release** (`/v1/release`): when the bank does not execute a payment the checker allowed (the payment failed,
was cancelled, or the bank's own controls stopped it), it hands back the mandate, the payment and the allow decision.
The decision must be signed by this tenant's checker key, be an `allow` naming exactly this payment and mandate,
and be the decision the payment log holds for that payment now. Then:

- **Reservations come back, the payment id does not.** The period reservations the allow made (the mandate's and
  every delegation link's with a period limit) are released. The payment id stays used: the payment log keeps the
  key claimed and records the release. If the same payment (or any other payment under its id) is sent again, the
  answer is a signed **block `duplicate_payment`**, never the old allow and never a fresh check. A payment the bank
  wants to try again needs a **new payment id**, which is checked against the limits like any other. We chose the
  existing code over a new one (`payment_released`) so every 0.5 verifier and receipt already understands it; the
  release answer and this page say why the id is used.
- **Only soon after the decision, and in the same period.** The release must come within `RELEASE_WINDOW_HOURS`
  (default 24) of the decision's `checked_at`, and while each limit period the allow reserved in is still the
  current one (an allow of 31 October cannot be released on 1 November). Otherwise `409`, and the reservation
  stands. `RELEASE_WINDOW_HOURS=0` turns release off (`403`); a value that is not a whole number from 0 to 744 is
  `503`.
- **Once.** The answer is stored in a release marker keyed by the decision hash, written before anything is
  released. A repeated call (also concurrent, and also after the window has closed) is a no-op that returns exactly
  the same answer:
  `{"released": true, "checker", "decision": {"id", "hash"}, "payment": {"id", "hash"}, "reservations": [...], "payment_id": "held", "released_at"}`.
- A decision the checker does not hold for the payment (never allowed here, or superseded) is `409`; an escalate
  or block, an edited decision, another payment or another tenant's decision is `400`.
- If the store fails half way (`503`), what is left is stricter, never looser: reservations stay reserved and the
  payment log keeps either the allow or the released claim. A repeat then returns the stored answer and does not
  release again.

**What release still trusts.** The check key holder says the bank did not execute the payment; the checker cannot
see the bank's books. With the window, the period rule and the id kept used, the most a check key holder can do is
claim that an allowed payment was not executed: once per allow, within its window and its period. It can no longer
reset limits with old decisions or get the same payment allowed twice. If the party
holding the check key is not the one executing payments, set `RELEASE_WINDOW_HOURS=0`.

**Deleting a tenant** (`DELETE /v1/admin/tenants/<id>`) removes the tenant record first, so its check and KYB keys
stop working at once, then every key under `t/<id>/`: its public key, the authority table log, the payment log, the
period ledger, stored revocations and release markers. If the store fails half way it answers `503`; calling it
again finishes the job. A tenant id cannot be created again while any of its old data is still in the store. A
check that was already running when the tenant was deleted can still write its payment log entry afterwards;
delete once more after a minute to be sure. Decisions the tenant signed can no longer be verified against
`/t/<id>/keys`: keep the key set with the receipts.

## Pilot partner quickstart (curl)

```sh
BASE=https://gleipnir-check.netlify.app

# 1. (Gleipnir) create the tenant; both keys are shown once: send them over a secure channel
curl -sS -X POST $BASE/v1/admin/tenants -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"id": "acme-psp"}'
# -> {"id": "acme-psp", "checker": "sandbox:acme-psp", "api_key": "gks_acme-psp_...", "kyb_key": "gkk_acme-psp_...", ...}

# 2. (partner's KYB side, or Gleipnir with ADMIN_TOKEN) set the authority table
curl -sS -X PUT $BASE/v1/admin/tenants/acme-psp/authority -H "Authorization: Bearer $GLEIPNIR_KYB_KEY" \
  -H "Content-Type: application/json" -d @authority.json

# 3. check a payment the agent started (mandate signed by the signatory, payment signed by the agent)
curl -sS -X POST $BASE/v1/check -H "Authorization: Bearer $GLEIPNIR_API_KEY" \
  -H "Content-Type: application/json" -d '{"mandate": '"$(cat mandate.json)"', "payment": '"$(cat payment.json)"'}'
# -> {"v": "gleipnir/decision/0.4", "outcome": "allow", "reasons": [], "checker": {"id": "sandbox:acme-psp", ...}, "sig": ...}

# 4. verify decisions offline against the published key set
curl -sS $BASE/t/acme-psp/.well-known/gleipnir-checker.json
```

Mandates and payments are made with the SDKs (`gleipnir mandate sign` / `attach` in Python, `issue`, `signMandate`,
`attach` from `@getgleipnir/verify/mandate`). `scripts/hosted-smoke.mjs` shows the whole flow in about 100 lines.

**Smoke test** (the three demo cases: allow, tricked-agent payee block, over-limit escalate then signatory override).
Keys come from the environment only:

```sh
cd typescript && npm ci && npm run build -w @getgleipnir/verify
export GLEIPNIR_API_KEY=gks_smoke_...  GLEIPNIR_KYB_KEY=gkk_smoke_...   # e.g. from your password manager
node packages/hosted/scripts/hosted-smoke.mjs https://gleipnir-check.netlify.app
```

It adds a throwaway "Gleipnir Smoke ..." company with a fresh key to that tenant's authority table (other rows are
kept, earlier smoke rows replaced). Use a dedicated `smoke` tenant.

## Deploy

One-time, from this directory (`typescript/packages/hosted`), with the Netlify CLI logged in:

```sh
cd typescript/packages/hosted
netlify sites:create --name gleipnir-check          # a NEW site; do not link getgleipnir.com
netlify env:set MASTER_KEY  "$(openssl rand -base64 48)" --secret
netlify env:set ADMIN_TOKEN "$(openssl rand -base64 48)" --secret
netlify deploy --build            # draft URL: create a smoke tenant, run the smoke test against it
netlify deploy --build --prod
```

Environment variables:

| Name | Required | What |
|---|---|---|
| `MASTER_KEY` | yes (≥ 32 chars) | encrypts tenant checker keys, keys the API key hashes. **Changing or losing it makes every tenant key unusable** (`503`) and invalidates every API key. Keep a copy in the password manager. |
| `ADMIN_TOKEN` | yes for admin (≥ 32 chars) | bearer token for `/v1/admin/*`. Without it admin is closed. |
| `RATE_LIMIT_PER_MIN` | no (120) | requests per minute per key, per function instance |
| `ALLOW_ORIGINS` | no | comma-separated browser origins allowed to call authenticated endpoints |
| `RELEASE_WINDOW_HOURS` | no (24) | hours after an allow during which `/v1/release` may give its reservations back; `0` turns release off, max 744 |

The build runs `npm ci` at `typescript/` and builds `@getgleipnir/verify`, which the function imports; Netlify
bundles the function with esbuild (Node 20). State lives in the site-wide Blobs store `gleipnir-sandbox-checker`
(survives deploys). If the CLI does not pick up the monorepo layout, run it with `--filter @getgleipnir/hosted-checker`
or set Base directory `typescript/packages/hosted` in the site settings. After the first deploy, check in the
Netlify UI that the function's rate limit rule (from `config.rateLimit`) is active on your plan.

## State and atomicity

- **What counts as a write.** The `@netlify/blobs` client reports a conditional write as `modified: false` only
  on HTTP 412; for every other status (400/401/403/404/413, and 429/5xx after its own retries) it says
  `modified: true`. `BlobsKV` therefore counts a write only when the answer carries the new ETag, or when reading
  the key back returns exactly the bytes written. Anything else throws, and the request fails closed.
- **Lost answers.** The client retries 429/5xx itself, so a write can land and its retry then get 412. Every value
  carries the random ids of its last 16 writes; after a refused write the next read shows whether it was ours,
  and it is never applied twice (e.g. a `release` does not subtract twice, a `register` is not mistaken for a
  duplicate).
- **Payment log** (idempotency, replay protection, spec 7): one blob per (tenant, payer, payment id). `register` is
  create-only; `remember` and `take` are compare-and-swap on the ETag, so two concurrent overrides of one
  escalation cannot both re-check.
- **Period ledger**: one blob per (tenant, limited object, calendar period); compare-and-swap with 8 tries.
- **Revocations**: one small blob per revoked object (mandate hash or delegation link hash). A check reads only
  the blobs of its mandate and its chain. Revocations of expired objects are dropped. There is no tenant-wide cap;
  per object the 32 earliest are kept (one valid revocation already switches it off); revocations are rate-limited
  per signer (10 per minute per instance).
- All reads use strong consistency.

**Failing closed.** In the sandbox code paths: if the ledger, the payment log or the revocations of the mandate
cannot be read or written (or the retries run out), the answer is a signed **escalate `checker_unavailable`**; if
the tenant record cannot be read, `503`. This is tested against an in-memory store and against the real Blobs
client with a fake edge (`test/blobs-kv.test.ts`), not against Netlify's production Blobs service.

**Concurrency** (period limit under parallel checks, lost answers, writers in between) is tested on the in-memory
store and on the fake edge only. Correctness on Netlify relies on Blobs honouring `onlyIfNew` / `onlyIfMatch`
atomically with strong consistency, as documented.

Remaining gaps (acceptable for a sandbox, to fix before production):

1. A mandate with a period limit plus delegation links reserves each limit in its own blob. The library does this
   all-or-nothing by giving back earlier reservations if a later one fails; a function crash in between leaves an
   over-count. That errs strict, never lenient.
2. If the function dies after claiming a payment id but before storing the decision, the id stays claimed with no
   decision: retries get `block duplicate_payment`, and the agent uses a new payment id. There is deliberately no
   automatic takeover of stale claims, because after a lost `remember` it would allow a replay.
3. The library swallows a failed `remember`/`forget` after deciding; the decision still stands. A failed `forget`
   leaves the id claimed (strict, as in 2).
4. The Blobs client waits about 5 s per retry on 429/5xx (up to 5 retries), so a degraded store can make a check
   take long enough to hit the function timeout; the caller then gets an error, not a decision.
5. Under heavy contention on one key, checks escalate `checker_unavailable` rather than waiting.

## Limits

- Sandbox only: shared Netlify infrastructure, no SLA, no HSM. Tenant keys are protected by `MASTER_KEY` in
  Netlify env, not by hardware.
- **Rate limits are weak.** In-function limits are in memory per function instance (each cold instance starts
  fresh): 120/min per key by default, 120/min per IP on public endpoints, 20 failed auth attempts per IP per minute
  (then `429` for that IP for the rest of the minute). Without a client IP from the platform there are no per-IP
  limits. The platform rule in `config.rateLimit` (300/min per IP and domain) applies only where the Netlify plan
  supports it. API keys carry 256 random bits, so guessing them is not the risk; cost and load are.
- Mandates with a `status_url` are not fetched (no outbound requests from the sandbox): they escalate
  `status_unavailable`. Use `/v1/revoke` instead. No revocation feed (`revocationFeed`).
- Authority and holds come only from the tenant's table (no vLEI or register lookup).
- **Checker signing keys are not rotated**: the key set lists only the current key. Only the bearer keys
  (check key, KYB key) can be rotated.
- `GET /v1/revocations` lists at most 500 revoked objects, and uses the Blobs listing, which may lag a fresh
  revocation briefly. Checks never depend on it: they read the mandate's own revocation blobs directly.
- Paths are versioned (`/v1/check`) and need a bearer key, so the Python MCP tool `check_payment --bank-url`
  (which posts to `<url>/check` without auth) does not talk to this server directly.

## Development

```sh
cd typescript
npm ci
npx vitest run packages/hosted     # handlers on an in-memory store, BlobsKV on a fake edge, the shared vectors
npm run typecheck
```
