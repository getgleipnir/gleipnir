# Gleipnir + Increase: an AI agent pays suppliers by ACH, only within its mandate

An accounts payable agent sends ACH transfers through [Increase](https://increase.com). Before every
transfer it asks a checker whether the company's signatory allowed this payment. Only an `allow` reaches
`POST /ach_transfers`.

```
a. $1,250 to Acme, account on the mandate      allow     reason=-                     -> ACH transfer created
b. $1,250 to 'Acme', new account number        block     reason=payee_not_on_mandate  -> not sent
c. $7,500 to Acme (over $5,000 limit)          escalate  reason=over_payment_limit    -> not sent
   approved by Dana Ruiz (signed override)     allow                                  -> ACH transfer created
```

Case b is the one that matters: the agent was tricked into paying "Acme" at a new account number. The
API key could pay anyone. The mandate could not.

## Run it

```bash
uv run python examples/increase-ach/agent.py --dry-run   # offline, in-memory fake of Increase
uv run python examples/increase-ach/agent.py             # live Increase sandbox, no Increase account needed
```

The live run creates a fresh sandbox group with one unauthenticated `POST /groups`, then an entity (the
sample body from Increase's API reference), an account, an account number and $50,000 of simulated incoming
wire. Set `INCREASE_API_KEY` (and `INCREASE_ENTITY_ID`) to use your own sandbox instead.

## What the pieces are

- **Mandate**: signed by the company's CFO with an Ed25519 key (a passkey in production). ACH only, one
  payee, $5,000 per payment, $20,000 per month, from one account, until 31 Dec 2026.
- **Checker**: in this example it runs in-process as the platform's checker. It knows from onboarding who
  may sign for the business. Run it as a service with `gleipnir mandate serve`.
- **Decisions**: every check returns a signed decision, written to `decisions.jsonl`. Anyone with the
  checker's public key can verify it later; a changed byte breaks the signature.

Gleipnir never moves or holds money. Increase moves it; the checker only says whether this agent may.

Spec: [`spec/mandate.md`](../../spec/mandate.md)
