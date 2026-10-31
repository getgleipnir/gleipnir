# Changelog

## Unreleased: mandate spec 0.5

Additive: only objects that use something new are `0.5`. A 0.5 checker accepts every 0.4 object and checks it
exactly as before (every 0.4 conformance vector is unchanged).

### Added

- **Payees that are not on the mandate** (spec 4.1, 7 step 21). A 0.5 mandate may set
  `scope.unlisted_payees`: `"block"` (default, as in 0.4) or `"escalate"`: a payment to an unlisted payee waits
  for a person (`new_payee`, escalate, holds the payment id). `scope.max_per_unlisted_payee` blocks larger
  payments to an unlisted payee outright (`over_unlisted_payee_limit`).
- **Changed bank details stay blocked**: a payee name that matches a listed payee (by a fixed name key: NFKD,
  lowercase, letters and digits only, look-alikes folded) with another account is `payee_account_changed`
  (block), whatever the policy, and is never escalated.
- **Payee approvals** (spec 7.2): `gleipnir/payee_approval/0.5`, signed by the company's signatories (as many as
  the mandate needed), bound to one mandate by hash, optional `valid_until`, revocable by hash with the existing
  revocation (0.5 revocations may target a payee approval). They travel with the payment; an approved account
  counts as listed, which is also the one way to pay a listed payee at a new account. Decisions name the approval
  they relied on and whom they counted; receipts check it. New code `payee_approval_invalid` (block).
- **Overrides of `new_payee`** by the company's signatories or a bank officer (spec 7.1).
- Python: `approve_payee`, `sign_payee_approval`, `payee_approval_problem`, `payee_approval_hash`,
  `payee_approval_digest`, `payee_name_key`, `version_of`; `Checker.check/resolve(..., payee_approvals)`,
  `Checker.revocation_counts(..., payee_approval)`, `verify_receipt(..., payee_approvals=)`. TypeScript: the same
  as `approvePayee`, `signPayeeApproval`, `payeeApprovalProblem`, `payeeApprovalHash`, `payeeApprovalDigest`,
  `payeeNameKey`, `versionOf`, `MANDATE_VERSION_05`, `SPEC_VERSION`, `MAX_APPROVALS`.
- CLI: `gleipnir mandate issue --unlisted-payees block|escalate [--max-per-unlisted-payee AMOUNT]`,
  `gleipnir mandate approve-payee`, `--payee-approval FILE` on `check` and `resolve`; `revoke` takes an approval.
  Reference server: `payee_approvals` on `/check` and `/resolve`, `payee_approval` on `/revoke`.
- MCP (Python and TypeScript): `mandate_scope` shows the unlisted-payee policy, the cap and approved payees;
  `check_payment` returns `new_payee: true` and specific advice for the new reason codes. Approvals come from the
  operator (`--payee-approval`), never from the agent.
- Hosted sandbox checker (merged from `hosted-checker`): `DELETE /v1/admin/tenants/<id>` deletes a tenant and
  all its data; `POST /v1/release` gives back the period reservations of an allowed payment the bank did
  not execute, once (a repeat returns the same answer), bound to the decision, only within `RELEASE_WINDOW_HOURS`
  (off by default; turn on only where the check key holder executes the payments) and the same limit period; the payment id stays used, so the same payment sent again is blocked
  `duplicate_payment`; `payee_approvals` on `/v1/check` and `/v1/resolve`,
  `payee_approval` on `/v1/revoke`.
- The signing page (site/mandate) shows what happens to payees that are not on the list before a person signs.

### Changed

- Decisions about a 0.5 mandate are `gleipnir/decision/0.5`, signed with the `v0.5` prefix; `verify_decision`
  reads the prefix from the decision's `v`. Signature prefixes name each object's own version.
- `mandateMessage(kind, hash, version?)` / `message(kind, h, v=)` take the version (default `0.4`).
- `payees_required` is satisfied by `unlisted_payees` as well as by a payee list.

### API

- No breaking change for 0.4 users: existing calls, objects, decisions and receipts are unchanged. Receipts of
  0.5 decisions carry an extra `payee_approved_by` list.
- Integrators who adopt 0.5 must pass payee approvals next to the mandate (they are not part of the payment), may
  see the new reason codes, and must keep `new_payee` escalations (they hold the payment id) like
  `over_payment_limit`.

## mandate spec 0.4.1

Wire format unchanged: every `v` string and signature prefix stays `0.4`, so 0.4 mandates, payments,
decisions and signatures stay valid.

### Fixed

- Checker (Python `gleipnir_verify.mandate.Checker`, TypeScript `Checker` in `@getgleipnir/verify/mandate`):
  a payment log or period ledger that answers anything but exactly `true`/`false` (for example a string,
  a number or `None`/`undefined` from a buggy adapter) now gives `checker_unavailable` (escalate). Before, a
  truthy non-boolean from `ledger.reserve` allowed the payment as if the amount was reserved, and one from
  `payments.register` / `payments.take` counted as a claimed payment id. Spec section 7.

### Added

- Conformance vectors for each attack of the 23.10.2026 audit, run by both implementations
  (`attack_*` cases in `mandate-vectors.json`): mandate signed with a self-asserted key for a known
  signatory and for an invented one (C1); payments back-dated past expiry and before a revocation, and
  forward-dated (C2); replayed payments, including that a replay never reserves twice (H1); a ledger and a
  payment log that raise or answer a non-boolean, and no ledger wired (H2). Key-set vectors now include a
  decision forged with a non-bank key, an edited decision, an unsigned decision, and the plain key-list
  form of `verify_decision` (C3).

### API

- No signature changes. Integrators whose `Ledger.reserve`, `PaymentLog.register` or `PaymentLog.take`
  return truthy non-booleans must return real booleans; otherwise payments escalate with
  `checker_unavailable`.
