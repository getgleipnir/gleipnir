# Gleipnir + Stripe Treasury for agents: an AI agent pays a supplier, only within its mandate

An accounts payable agent pays supplier invoices from a Stripe [financial account][fa] through Stripe's
[Outbound Payments API][obp], which is what Stripe's MCP tool `send_money` does
([Treasury for agents][agents], public preview since 21 Oct 2026). Before every payment the agent asks a
checker whether the company's signatory allowed it. Only an `allow` for exactly that payment reaches
`POST /v2/money_management/outbound_payments`.

```
a. $1,250 to Acme, account on the mandate      allow     reason=-                      -> outbound payment created
b. $1,250 to 'Acme', injected bank details     block     reason=payee_not_on_mandate   -> not sent
c. $7,500 to Acme (over $5,000 limit)          escalate  reason=over_payment_limit     -> not sent
   approved by Dana Ruiz (signed override)     allow                                   -> outbound payment created
```

Case b is the one that matters. Invoice INV-1002 contains a hidden line aimed at the agent ("our bank details
changed, use account ...") and the agent takes it. The Stripe key could pay that account once someone ran
`setup_recipient` for it. The mandate can't, because Dana never approved that payee.

## What Stripe already gives you, and what this adds

Stripe already has real controls, and you should keep them on:

- **Human approval for agent money movement.** By default, any live money movement an agent starts through
  the MCP server needs a person to approve it at a Stripe URL. The agent then gets an approval token and
  retries ([Treasury for agents][agents], [MCP: confirm actions][mcp-confirm]).
- **Approval rules** ([two-party approvals][approvals]). For agent-tagged API keys you can require approval
  for, or block, "Outbound payment is created", with conditions on amount, actor or rate. The API then
  returns `403 approval_required`. Stripe ships default rules for agent keys.
- **Scoped credentials**: per-tool permissions on the MCP OAuth grant, and [agent API keys][keys] with only
  the permissions they need. The MCP server stops accepting non-agent secret keys after 30 Nov 2026
  ([MCP][mcp]).
- **Agent spending limits** are announced for "the coming weeks" and are not live yet ([Treasury for
  agents][agents]).

All of these live inside one Stripe account, and they answer "did someone with a role in this Stripe account
click approve?" or "is this under a number?". Gleipnir adds three things:

1. **Who approved, and whether they may.** The mandate is signed by the company's signatory (here Dana Ruiz,
   CFO). The checker confirms she may sign for Nordwind Trading LLC from the platform's onboarding (KYB),
   not from a Dashboard role anyone could be given.
2. **Approved payees, not just amounts.** The mandate lists payees by bank account. A Stripe approval rule
   has conditions on amount, actor and rate, but none on whether this recipient is one the company agreed to
   pay. A $1,250 payment to an attacker's account would pass any amount rule. Here it is blocked.
3. **A signed decision record that someone else can verify.** Every check returns a decision signed by the
   checker, naming the mandate and the exact payment (by hash). The bank, the platform, an auditor or the
   company's own finance team can verify it later with the checker's public key. A changed byte breaks it.
   Overrides (case c) are signed by the CFO too, not just clicked.

Gleipnir never moves or holds money. Stripe moves it; the checker only says whether this agent may.

## Run it

```bash
uv run python examples/stripe-treasury/agent.py --dry-run   # offline, in-memory fake of the Stripe calls
```

### Run it against your sandbox

Sandbox keys only. The script refuses `sk_live_` and `rk_live_` keys, refuses a financial account whose
`livemode` isn't `false`, and never prints the key.

You need a Stripe [sandbox][sandboxes] with Treasury / Global Payouts enabled, and:

1. A USD **financial account**, funded. In a sandbox you can fund it with the
   [Credit a Financial Address test helper][testing]:
   `POST /v2/money_management/test_helpers/financial_addresses/{id}/credit`.
2. A **recipient** for the supplier: a v2 Account with `configuration.recipient.capabilities.bank_accounts.ach`
   requested ([create recipients][recipients]).
3. A **US bank account payout method** for that recipient, made with
   `POST /v2/money_management/outbound_setup_intents` and `Stripe-Context: <recipient id>`. Use Stripe's test
   routing `110000000` and account `000123456789`, where payouts succeed ([testing][testing]).

Then:

```bash
export STRIPE_SECRET_KEY=sk_test_...            # or a restricted rk_test_... key
export STRIPE_FINANCIAL_ACCOUNT=fa_test_...
export STRIPE_RECIPIENT=acct_...
export STRIPE_PAYOUT_METHOD=usba_test_...
# optional: SUPPLIER_ROUTING / SUPPLIER_ACCOUNT if the payout method isn't 110000000 / 000123456789
# optional: FA_ROUTING / FA_ACCOUNT if your financial address list doesn't return the full account number
uv run python examples/stripe-treasury/agent.py
```

A restricted key needs `Money Management Financial Accounts: Read`, access to `Money Management Payout Methods`
(Stripe's send-payouts guide lists `Write`; the script only reads one) and
`Money Management Outbound Payments: Write`. If you use an agent-tagged
key and Stripe's default approval rule holds the payment, the script prints that it is held. That's
Stripe's layer working on top of Gleipnir's.

## The Stripe calls

All requests send `Stripe-Version: 2026-10-28.preview` (override with `STRIPE_VERSION`). Python stdlib only.

| Call | Why | Docs |
| --- | --- | --- |
| `GET /v2/money_management/financial_accounts/{id}` | open, sandbox, balance | [Financial Accounts][fa-api] |
| `GET /v2/money_management/financial_addresses?financial_account={id}` | the company's own ABA routing and account number, for the mandate's `from_accounts` | [Financial Addresses][faddr] |
| `GET /v2/money_management/payout_methods/{id}` with `Stripe-Context: {recipient}` | confirm the supplier's payout method has the mandate's routing number and last4 | [Payout Methods][pm], [recipients][recipients] |
| `POST /v2/money_management/outbound_payments` with `Idempotency-Key: {payment id}` | the payment, only after a verified `allow` | [Create an Outbound Payment][obp-create], [send payouts][send] |

The outbound payment body is built from the checked payment and nothing else. `amount.value` is the payment's
amount in cents, `to` is the payout method the gateway registered for the payment's payee account,
`to.payout_method_options.bank_account.preferred_networks` is the payment's rail (`ach`), and `metadata`
carries the mandate, payment, payment hash and decision ids. After the CFO's override in case c, the same
function sends the escalated payment itself, so the amount and payee can't differ from what was checked.
The dry run's fake Stripe fails if anything is sent that no `allow` covered.

## What is uncertain (read before relying on it)

- **Public preview.** The v2 money management APIs and the MCP Treasury tools are in public preview. Field
  names can change. The script pins the API version the docs use today.
- **`send_money`'s own arguments are not published.** Stripe documents the tool's name and its permission
  (`Money Management Outbound Payments: Write`), but not its input schema. This example calls the documented
  REST endpoint directly. It does not claim to replicate the tool's arguments. See
  [`mcp_guard.md`](mcp_guard.md) for putting the check in front of the MCP tool itself.
- **Payee binding is ours (adapter `payee_route`).** Stripe identifies a payee by recipient and payout method
  ids and shows only the routing number and last4 of the bank account. The gateway keeps the table from the
  full account number (known when the payout method was set up) to the payout method id, and fails closed
  for any account not in it.
- **Own account (adapter `own_account`).** Taken from the financial address list. Stripe's documented example
  includes the full `account_number`. If your sandbox masks it, set `FA_ROUTING` and `FA_ACCOUNT`.
- **Payout Intents.** Stripe recommends the [Payout Intents API][send] (`POST /v2/money_management/payout_intents`)
  for most payout integrations, and requires it for UK cross-border payouts. This example uses Outbound
  Payments because that is the permission `send_money` needs. The same gate fits in front of a PayoutIntent.
- **Not run live by the author.** The live path follows the docs above but has not been run against a
  sandbox yet. `--dry-run` is tested.

**Demo shortcut, not the production setup.** To run on its own, this script holds the Stripe key, the CFO's
key, the agent's key and the checker's key in one process. In production the CFO signs with their own
passkey, and the checker runs at the platform or in a gateway that alone holds a Stripe key with
`Outbound Payments: Write`. The agent holds none of them. Otherwise a compromised agent could skip the check
and call Stripe directly.

Spec: [`spec/mandate.md`](../../spec/mandate.md) · Increase version of this example: `examples/increase-ach`

[agents]: https://docs.stripe.com/treasury/agents
[mcp]: https://docs.stripe.com/mcp
[mcp-confirm]: https://docs.stripe.com/mcp#confirm-actions-by-agents-acting-on-your-behalf
[approvals]: https://docs.stripe.com/account/approvals
[keys]: https://docs.stripe.com/keys#agent-keys
[fa]: https://docs.stripe.com/treasury
[obp]: https://docs.stripe.com/api/v2/money-management/outbound-payments?api-version=preview
[obp-create]: https://docs.stripe.com/api/v2/money-management/outbound-payments/create?api-version=preview
[fa-api]: https://docs.stripe.com/api/v2/money-management/financial-accounts?api-version=preview
[faddr]: https://docs.stripe.com/api/v2/money-management/financial-addresses/list?api-version=preview
[pm]: https://docs.stripe.com/api/v2/money-management/payout-methods?api-version=preview
[send]: https://docs.stripe.com/global-payouts/send-money
[recipients]: https://docs.stripe.com/global-payouts/recipient-creation
[testing]: https://docs.stripe.com/global-payouts/testing
[sandboxes]: https://docs.stripe.com/sandboxes
