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
- `scope.currency` is required and applies to every amount in the scope. Amounts are decimal strings with the currency's minor units (`"25000.00"`), never floats.
- `scope.max_per_payment` is required. `scope.max_per_period` is optional; `period` is an ISO 8601 duration (`P1D`, `P7D`, `P1M`).
- `scope.payees` is optional. If present, a payment is covered only if its payee account matches one entry exactly (after normalization: IBAN uppercase without spaces; US accounts as `{"aba": "...", "account": "..."}`). If absent, any payee is allowed within the limits. A changed account is a different payee.
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

`agent_sig` is required when the mandate names `agent.public_key`: a signature over `"gleipnir/payment/v0.1\n" || payment_hash`, where `payment_hash` is computed over the payment minus `agent_sig`.

The full mandate travels with the payment (as a separate field of the API call or a header) or is fetched by id from the issuer; the payment itself only references it by id and hash.

## 5. Check

The checker runs these steps in order and stops at the first failure. Each step yields a reason code.

| # | Check | Fails with | Outcome |
|---|---|---|---|
| 1 | Mandate parses, `v` known, required fields present | `mandate_malformed` | block |
| 2 | `payment.mandate.hash` equals the mandate's hash | `mandate_mismatch` | block |
| 3 | Mandate signature valid for `signer.public_key` | `mandate_bad_signature` | block |
| 4 | Signer is authorized for `company` (section 6) | `signer_not_authorized` / `signer_unknown` | block / escalate |
| 5 | `valid_from ≤ requested_at ≤ valid_until` | `mandate_expired` / `mandate_not_yet_valid` | block |
| 6 | Not revoked (revocations known to the checker, and `status_url` if present) | `mandate_revoked` / `status_unavailable` | block / escalate |
| 7 | Agent signature valid, if required | `agent_bad_signature` | block |
| 8 | Rail allowed | `rail_not_allowed` | block |
| 9 | Currency matches | `currency_mismatch` | block |
| 10 | Payee covered | `payee_not_on_mandate` | block |
| 11 | `amount ≤ max_per_payment` | `over_payment_limit` | escalate |
| 12 | Period total including this payment `≤ max_per_period.amount` | `over_period_limit` | escalate |

Outcomes:

- **allow**: every check passed. The bank executes.
- **block**: the payment is not covered and must not be executed on the strength of this mandate.
- **escalate**: the payment may be legitimate but needs a person (the company or the bank's operations team) before execution.

The checker keeps the running period totals it needs for step 12. `status_unavailable` escalates rather than allows: a checker never allows a payment it could not check.

## 6. Who may sign

The mandate states who signed. The checker decides whether that person may sign for the company, using one or more **authority sources**, in this order of preference:

1. **Bank KYB.** The bank's own onboarding records list the company's authorized signatories and their keys or passkeys. This is the default and needs nothing new from the company.
2. **Company register.** Signing powers from a commercial register extract (for example Firmenbuch, Handelsregister, Companies House), mapped to the signer.
3. **vLEI.** A GLEIF vLEI Official Organizational Role or Engagement Context Role credential for the signer, chained to the company's LEI. Optional, useful across banks and borders.

The decision records which source was used. A signer the checker cannot place in any source yields `signer_unknown` (escalate), not allow.

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

Signed by the checker with the prefix `"gleipnir/decision/v0.1\n"`. Decisions may be appended to a hash-chained log in the record format of format.md (`kind: "note"` with `note.decision`), so the company, the bank and an auditor can later show what was checked and when.

## 8. What this does and does not prove

Proves: a named person signed this scope for this agent; the checker found that person authorized by a stated source; this payment was inside the scope at the time it was checked; the decision was not changed afterwards.

Does not prove: that the agent understood the invoice, that the invoice is genuine, or that the signer chose wisely. A mandate narrows what can go wrong; it does not replace the bank's fraud and AML controls.

## 9. Open questions for 0.2

- Mandate delegation (agent A gives agent B a narrower sub-mandate).
- Multi-signature mandates ("two of: Berger, Hofer") for amounts above a threshold.
- A standard `status_url` response and a revocation list format for offline checkers.
- Mapping to ISO 20022 `pain.001` fields so the mandate reference travels inside the payment message.
