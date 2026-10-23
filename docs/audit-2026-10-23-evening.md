# Second external audit: mandate v0.2 (23.10.2026, evening)

Scope: spec/mandate.md 0.2, the Python reference, the TypeScript port, CLI, reference HTTP checker, both MCP servers and the passkey signing page. The auditor ran every suite and wrote each attack as a test (an independent agent that had not seen the code being written). Verdict before fixes: core design sound; not yet fit to show a bank because of F1, F2 and F4–F6.

| id | sev | Finding | Fix | Regression test |
|---|---|---|---|---|
| F1 | high | A delegate could multiply a delegated monthly limit by signing many mandates (ledger per mandate). | A link's period limit is an aggregate: step 17 reserves against the mandate and every link, all or nothing. Spec §5.6, §7. | `test_F1_*`, vector `F1_delegated_period_limit_is_shared` |
| F2 | high | TS: a `__proto__` key was dropped from hashes (accept after edit) or made `check` throw. | Own-property copies (`put`), hashes computed inside the never-throw guard. | TS `F2: a __proto__ key ...`, vectors `F2_*` |
| F3 | medium | Python and TS disagreed on `2.0`, integers beyond 2^53, non-string account fields. | No floats, integers within 2^53 − 1 (both); `parseStrict` refuses float and large-integer literals; account fields must be strings. Spec §13. | `test_F3_*`, TS `F3:*`, vector `F3_account_value_not_a_string` |
| F4 | medium | Unsigned junk could burn a payment id (log written before signature checks, keyed by id only). | Log keyed by payer and id; read-only lookup first; the key is claimed only after mandate, authority and agent signatures verify (step 7c). | `test_F4_*`, vector `F4_*` |
| F5 | medium | An unsigned copy, or a transient outage, was cached as the answer. | Agent signature verified before claiming; transient outcomes released, not cached. | `test_F5_*`, vector `F5_unsigned_copy_first` |
| F6 | medium | Ledger keyed by mandate id: another company's same id ate the limit. | Ledger keys `mandate:<hash>`, `delegation:<hash>`. | `test_F6_*`, vector `F6_*` |
| F7 | medium | One key under two signer ids met a 2-of-2 threshold. | Duplicate keys in `signers.of` malformed; keys counted once. | `test_F7_*`, vector `F7_*` |
| F8 | medium | Reference server lost `/revoke` revocations on restart. | Stored in the state file. | `test_audit_F8_*` |
| F9 | medium | Hostile JSON-RPC (unhashable tool name, 5000-digit integers) crashed the Python MCP server; HTTP dropped connections. | Catch-all in `handle`, `loads_strict` catches `ValueError`, HTTP answers 500 instead of dropping. | `test_audit_F9_*` |
| F10 | medium | TS MCP KYB loader coerced `"joint": "2"` to 1 and `may_sign: null` to true. | Values passed through; both checkers refuse non-boolean `may_sign`, non-integer `joint`, non-string keys. | `test_F10_*`, TS `F10:*` |
| F11 | low | Unknown payment rail accepted when the mandate lists none. | `payment_malformed`. | `test_F11_*`, vector `F11_*` |
| F12 | low | MCP `check_payment` read like a dry run but is binding. | Description says it is the real check. | — |
| F13 | low | Link company matched by name only; `parent.id` unchecked; `country` unchecked. | Name plus country and ids where given; parent id checked; ISO alpha-2. | `test_F13_*`, vector `F13_*` |
| F14 | low | A leaf delegate could revoke the root link. | Revokers per target: that link and the links above it. Spec §9. | `test_F14_*`, vector `F14_*` |
| F15 | low | HTTP checker accepted `text/plain` cross-site POSTs. | `application/json` required (415); foreign `Origin` refused (403) unless allowed. | `test_audit_F15_*` |
| F16 | low | IBAN uppercasing differs between Python and Node for some non-ASCII letters. | IBANs ASCII only. | `test_F3_F16_*`, vector `F16_non_ascii_iban` |
| F17 | low | Page did not show agent key or `status_url`; "from issued_at" wording; Python MCP crashed on a mandate without rails; receipts need passkey settings. | Page shows both and "from the moment it is signed"; rails default `sepa`; documented in `verify_receipt`. | page test, `test_mcp_*` |

After fixes: Python 716 passed, TS 395 passed, 76 shared vectors (12 from this audit), typecheck, ruff and the browser passkey test green. Still open from the first audit: M5 (IBAN normalization beyond spaces), M6 (revocation distribution), L4 (IBAN checksum), L6 (NFC).

## Re-verification (same auditor, commit 64be48c)

19 of 21 original attack tests no longer reproduce; the other two only checked a pass-through value and a wording change. All F1–F17 confirmed closed. New items, fixed in the next commit:

| id | sev | Finding | Fix |
|---|---|---|---|
| N1 | low | Payment log key `country|name|id` could be crafted to collide across companies ("Alpha" + "Beta|INV-1" vs "Alpha|Beta" + "INV-1"). | Key is JCS of `[country, name, ids, id]` in both implementations; byte-identical keys pinned in the shared vectors. |
| N2 | low | TS accepts `2.0` if the integrator uses `JSON.parse` instead of `parseStrict`. | Documented on `parseStrict` and in the README (JavaScript cannot tell 2.0 from 2 after parsing). |
| R1 | info | A resend returns the earlier decision even after a revocation or outside the skew window. | By design (execute at most once); spec §7 now says so explicitly. |
| R2 | low | `mandate_not_yet_valid` and `over_period_limit` were cached, so a retry once valid / in a new period stayed blocked. | Both released instead of cached. |
| R6 | low | `/revoke` stored any well-formed revocation. | Signature must verify; deduplicated; capped at 10 000 in the reference server. |

Auditor's verdict after re-verification: fit to show bank engineers as a reference implementation once N1 and R1/R2 are handled (done).
