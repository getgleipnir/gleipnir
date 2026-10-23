# Gleipnir mandate format, version 0.1 (draft)

Normative draft. A **mandate** is a power of attorney for an AI agent: a person who may sign for a company states what one agent may pay, to whom, how much and until when. A bank or payment service provider (PSP) checks the mandate before it executes a transfer the agent started, and records a signed **decision**.

Gleipnir does not move money. The bank executes the transfer as it does today; the mandate check is one extra step before execution.

Encoding, key formats and signature formats are the same as in [format.md](format.md): RFC 8785 (JCS) canonical JSON, SHA-256, Ed25519 or ECDSA P-256, `base64url-nopad`, strict RFC 3339 timestamps, optional fields omitted rather than `null`.

## 1. Objects

| Object | Signed by | Purpose |
|---|---|---|
| `mandate` | the company's signatory | What the agent may pay. |
| `revocation` | a signatory of the same company | Switches a mandate off. |
| `payment` | nobody (it is the bank's own payment order) | The transfer the agent asks the bank to execute, plus the mandate it relies on. |
| `decision` | the checker (bank, PSP or a hosted checker) | The result of checking one payment against one mandate. |

Every object has `v: "gleipnir/<object>/0.1"` and an `id`.

## 2. Mandate

```json
{
  "v": "gleipnir/mandate/0.1",
  "id": "m_01JB7K3Q8Z4W2N6F",
  "company": {
    "name": "Nordhafen Logistik GmbH",
    "country": "AT",
    "ids": {"lei": "529900T8BM49AURSDO55", "register": "FN 123456a"}
  },
  "agent": {
    "id": "ap-agent",
    "name": "Accounts payable agent",
    "public_key": "ed25519:…"
  },
  "signer": {
    "id": "kberger@nordhafen.at",
    "name": "K. Berger",
    "role": "Prokurist",
    "public_key": "ed25519:…"
  },
  "scope": {
    "rails": ["sepa", "sepa_instant"],
    "currency": "EUR",
    "max_per_payment": "25000.00",
    "max_per_period": {"amount": "100000.00", "period": "P1M"},
    "payees": [
      {"name": "Brenner Stahl AG", "account": {"iban": "AT611904300234573201"}}
    ],
    "purpose": "Supplier invoices"
  },
  "valid_from": "2026-10-23T00:00:00.000Z",
  "valid_until": "2026-12-31T23:59:59.000Z",
  "issued_at": "2026-10-23T09:00:00.000Z",
  "status_url": "https://checker.example.com/v0/mandates/m_01JB7K3Q8Z4W2N6F/status",
  "sig": "ed25519:…"
}
```

Rules:

- `company.name` and `company.country` (ISO 3166-1 alpha-2) are required. `company.ids` is optional and open: `lei`, `vlei` (a vLEI credential reference), `register`, `vat`, or the bank's own customer id under `bank:<bic>`.
- `agent.id` is required. `agent.public_key` is optional; when present, the payment must carry an agent signature (section 4) so a stolen mandate alone is not enough.
- `signer.id`, `signer.public_key` are required. `signer.role` is informational. **Whether this person may sign for this company is not decided by the mandate.** The checker decides it from its own source: the bank's KYB records of authorized signatories, a company register, or a vLEI role credential. See section 6.
- `scope.currency` is required and applies to every amount in the scope. Amounts are decimal strings with exactly the currency's ISO 4217 minor units, no sign, no exponent, no leading zeros, no whitespace: `^(0|[1-9][0-9]*)\.[0-9]{2}$` for EUR, USD, GBP, CHF, SEK, NOK, DKK, PLN, CZK, HUF; `^(0|[1-9][0-9]*)$` for JPY. Other currencies are not supported in 0.1. Every amount must be greater than zero. Never floats.
- `scope.max_per_payment` is required. `scope.max_per_period` is optional; `period` is one of `P1D` (UTC calendar day), `P7D` (ISO week, Monday to Sunday, UTC) or `P1M` (UTC calendar month).
- `scope.payees` is optional; every entry must have an `account` object. If present, a payment is covered only if its payee account matches one entry exactly (after normalization: IBAN uppercase without spaces; US accounts as `{"aba": "...", "account": "..."}`). If absent, any payee is allowed within the limits. A changed account is a different payee.
- `scope.rails` is optional; values: `sepa`, `sepa_instant`, `ach`, `wire`, `faster_payments`, `fednow`, `rtp`. If absent, any rail.
- `valid_until` is required. Producers should keep mandates short (weeks or months, not years).
- `status_url` is optional. If present, the checker must fetch the mandate status from it (section 5).

**Signature.** `mandate_hash = "sha256:" || hex(SHA-256(JCS(mandate minus "sig")))`. `sig` is a signature by `signer.public_key` over

    "gleipnir/mandate/v0.1\n" || mandate_hash

in the record signature format of format.md. A signer may also sign with a passkey: `sig` is then an object `{"type": "webauthn", …}` exactly as in format.md "Signed approvals", with the WebAuthn challenge set to the 32 raw bytes of `mandate_hash`. This lets a signatory sign on a phone without managing keys.

## 3. Revocation

```json
{
  "v": "gleipnir/revocation/0.1",
  "id": "r_01JB8…",
  "mandate": "m_01JB7K3Q8Z4W2N6F",
  "mandate_hash": "sha256:…",
  "revoked_at": "2026-11-02T10:42:00.000Z",
  "signer": {"id": "mhofer@nordhafen.at", "public_key": "ed25519:…"},
  "reason": "Agent replaced",
  "sig": "ed25519:…"
}
```

Signed like a mandate with the prefix `"gleipnir/revocation/v0.1\n"`. Any signatory of the same company may revoke (the checker applies the same authority check as for issuing). A revocation takes effect at `revoked_at`; a payment checked at or after that time is blocked.

## 4. Payment

What the agent submits to the bank, or what the bank's API layer builds from the agent's request:

```json
{
  "v": "gleipnir/payment/0.1",
  "id": "p_7Q-20418",
  "mandate": {"id": "m_01JB7K3Q8Z4W2N6F", "hash": "sha256:…"},
  "rail": "sepa",
  "amount": "18400.00",
  "currency": "EUR",
  "payee": {"name": "Brenner Stahl AG", "account": {"iban": "AT611904300234573201"}},
  "reference": "INV-2026-0912",
  "requested_at": "2026-10-23T09:14:02.000Z",
  "agent_sig": "ed25519:…"
}
```

`id` must be unique per payer: the checker treats a second payment with the same `id` as a duplicate (section 5, step 3). `requested_at` is the agent's own clock and is informational; the checker uses its own clock (section 5).

`agent_sig` is required when the mandate names `agent.public_key`: a signature over `"gleipnir/payment/v0.1\n" || payment_hash`, where `payment_hash` is computed over the payment minus `agent_sig`.

The full mandate travels with the payment (as a separate field of the API call or a header) or is fetched by id from the issuer; the payment itself only references it by id and hash.

## 5. Check

**Whose clock.** All time-based checks use the checker's own clock ("now"), never a time supplied by the agent. `payment.requested_at` must lie within `max_skew` of now (default 60 seconds), otherwise the payment is blocked with `clock_skew`. Validity, revocation and period limits are evaluated at now.

The checker runs these steps in order and stops at the first failure. Each step yields a reason code.

| # | Check | Fails with | Outcome |
|---|---|---|---|
| 1 | Mandate parses: `v` known, required fields present and well-typed, amounts in strict format, known `period`, every payee has an `account` | `mandate_malformed` | block |
| 2 | Payment parses: `v` known, `id`, `mandate.id`, `mandate.hash`, `rail`, `currency`, `payee.account`, `requested_at` present and well-typed, amount in strict format and > 0, whole object encodable as I-JSON | `payment_malformed` | block |
| 3 | Payment `id` not seen before. Same `id` and same payment hash: the checker returns the earlier decision unchanged (idempotent retry). Same `id`, different hash: | `duplicate_payment` | block |
| 4 | `payment.mandate.hash` equals the mandate's hash | `mandate_mismatch` | block |
| 5 | `requested_at` within `max_skew` of the checker's clock | `clock_skew` | block |
| 6 | Mandate signature valid for `signer.public_key` | `mandate_bad_signature` | block |
| 7 | Authority source (section 6) knows `signer.id` | `signer_unknown` | escalate |
| 8 | Source says the person may sign, and `signer.public_key` is one of the keys the source binds to that person | `signer_not_authorized` | block |
| 9 | `valid_from ≤ now ≤ valid_until` | `mandate_not_yet_valid` / `mandate_expired` | block |
| 10 | Not revoked: a valid revocation (step 6–8 rules applied to its signer) with `revoked_at ≤ now`, or `status_url` answering `revoked` | `mandate_revoked` | block |
| 11 | `status_url`, if present, answers exactly `active` | `status_unavailable` | escalate |
| 12 | Agent signature valid, if the mandate names an agent key | `agent_bad_signature` | block |
| 13 | Rail allowed | `rail_not_allowed` | block |
| 14 | Currency matches | `currency_mismatch` | block |
| 15 | Payee account covered (normalized, exact) | `payee_not_on_mandate` | block |
| 16 | `amount ≤ max_per_payment` | `over_payment_limit` | escalate |
| 17 | If `max_per_period` is set: the amount is atomically reserved in the period ledger | `over_period_limit` / `ledger_missing` | escalate |

A dependency the checker cannot reach (authority source, payment log, ledger) gives `checker_unavailable` (escalate). Any input the checker cannot process gives a signed `block`; a checker never raises on input and never allows a payment it could not fully check.

Outcomes:

- **allow**: every check passed. The bank executes.
- **block**: the payment is not covered and must not be executed on the strength of this mandate.
- **escalate**: the payment may be legitimate but needs a person (the company or the bank's operations team) before execution.

**Idempotency.** The checker keeps a payment log keyed by payment `id` with the payment hash and the decision. Registering a new `id` must be atomic, so two concurrent submissions of one `id` cannot both pass step 3.

**Period ledger.** Step 17 is a single atomic operation `reserve(mandate_id, period, amount, limit, now) → bool`: it adds the amount to the running total of the current period only if the result stays within the limit. A checker without a ledger must not allow payments under a mandate with `max_per_period` (`ledger_missing`). If the bank later does not execute an allowed payment it releases the reservation.

## 6. Who may sign

The mandate states who signed. The checker decides whether that person may sign for the company, using one or more **authority sources**, in this order of preference:

1. **Bank KYB.** The bank's own onboarding records list the company's authorized signatories and their keys or passkeys. This is the default and needs nothing new from the company.
2. **Company register.** Signing powers from a commercial register extract (for example Firmenbuch, Handelsregister, Companies House), mapped to the signer.
3. **vLEI.** A GLEIF vLEI Official Organizational Role or Engagement Context Role credential for the signer, chained to the company's LEI. Optional, useful across banks and borders.

Contract: the source is asked about a **person**, never about a key taken from the mandate:

    authority(company, signer_id) → {source, keys, may_sign} | unknown

`keys` are the public keys (or passkey keys) the source itself binds to that person. The mandate's `signer.public_key` is accepted only if it is one of them; a mandate signed with any other key is `signer_not_authorized`, even if the signature is valid. The same rule applies to the signer of a revocation. The decision records which source was used. A signer the checker cannot place in any source yields `signer_unknown` (escalate), not allow.

## 7. Decision

```json
{
  "v": "gleipnir/decision/0.1",
  "id": "d_01JB7…",
  "payment": {"id": "p_7Q-20418", "hash": "sha256:…"},
  "mandate": {"id": "m_01JB7K3Q8Z4W2N6F", "hash": "sha256:…"},
  "outcome": "allow",
  "reasons": [],
  "checks": ["mandate_valid", "signer_authorized:bank_kyb", "not_revoked", "payee_on_mandate", "within_payment_limit", "within_period_limit"],
  "checked_at": "2026-10-23T09:14:02.312Z",
  "checker": {"id": "bank:RZBAATWW", "public_key": "ed25519:…"},
  "sig": "ed25519:…"
}
```

Signed by the checker with the prefix `"gleipnir/decision/v0.1\n"`. `checked_at` is the checker's clock. A decision is verified against the bank's **known** checker keys, obtained out of band (for example from the bank's published key list); the `checker.public_key` inside the decision only says which of those keys signed it and is never trusted on its own. `id` is random. Decisions may be appended to a hash-chained log in the record format of format.md (`kind: "note"` with `note.decision`), so the company, the bank and an auditor can later show what was checked and when.

## 8. What this does and does not prove

Proves: a named person signed this scope for this agent; the checker found that person authorized by a stated source; this payment was inside the scope at the time it was checked; the decision was not changed afterwards.

Does not prove: that the agent understood the invoice, that the invoice is genuine, or that the signer chose wisely. A mandate narrows what can go wrong; it does not replace the bank's fraud and AML controls.

## 9. Encoding rules

Objects are I-JSON (RFC 7493): no duplicate keys, no floats, integers within ±2^53. A checker parsing JSON from the wire must reject duplicate keys before hashing. Strings should be NFC.

## 10. Open questions for 0.2

- Mandate delegation (agent A gives agent B a narrower sub-mandate).
- Multi-signature mandates ("two of: Berger, Hofer") for amounts above a threshold.
- A standard `status_url` response and a revocation list format for offline checkers.
- Mapping to ISO 20022 `pain.001` fields so the mandate reference travels inside the payment message.
