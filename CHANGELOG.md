# Changelog

## Unreleased: mandate spec 0.4.1

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
