# Outcome checks

An agent's log says what the agent *thinks* happened. An outcome check reads the object back from the system of record after the write and records whether it matches what the agent asked for. That's what lets a buyer tell "the agent called refund(1000)" apart from "a refund of 1000 exists". The second one is what they care about.

`gleipnir.outcomes` ships ready-made checks for common systems. Each factory returns a `verify_outcome` callback for `@rec.tool(...)`:

- **Injected client.** Pass the official SDK client you already use, or a callable `path -> JSON` (`gleipnir.outcomes.json_get(base_url, headers=...)`). Gleipnir doesn't depend on any vendor SDK.
- **Exact fields.** Only the fields you check are compared and stored in `outcome.observed`. A mismatch lists them in `outcome.fields`.
- **Money in minor units.** Expected amounts are integers (cents). Shopify's decimal strings are converted exactly using the currency's ISO 4217 exponent. A float amount is a configuration error, never a silent pass.
- **Missing object** = `mismatch` with `fields: ["exists"]`. A deleted Stripe customer, an archived HubSpot object or an `IsDeleted` Salesforce record counts as missing too.
- **Errors never reach the agent.** Network, auth and configuration problems give `Outcome("error", detail=...)`.
- **Eventual consistency.** `retries=N` (default `0`, max 10) reads again with exponential backoff (`backoff=0.5`, `max_backoff=4.0` seconds) after a transient error (timeouts, connection errors, 408/409/425/429/5xx), not-found or a mismatch. Auth and other 4xx errors are not retried. When retries happened, `detail` says how many attempts it took.

`outcome.method` names the check (`stripe.refund_matches`, ...), so the Security Review Pack shows which read-back was used.

## Expected values

Keyword arguments that take a value accept:

| | |
|---|---|
| `"amount"` | the tool argument named `amount` (an error if the call has none) |
| `opt_arg("amount")` | that argument if present, else the field is skipped (most defaults) |
| `resp("refund.id")` | a dotted path into the tool's response |
| `lambda call, resp: ...` | computed; return `SKIP` to skip, `None` means "empty / unassigned" |
| `None` | don't check |

`fields=` / `properties=` take a list of names (each one equals the argument of the same name), a mapping `{field: value or arg("x")}`, or a callable that returns a mapping. Comparisons account for how APIs serialize values: `1500 == "1500.00"`, `123 == "123"`, `True == "true"`, `None ==` missing/empty, and a dict is a subset match.

## Stripe

[Refund](https://docs.stripe.com/api/refunds/object), [PaymentIntent](https://docs.stripe.com/api/payment_intents/object), [Customer](https://docs.stripe.com/api/customers/object)

```python
import stripe
from gleipnir.outcomes import stripe as stripe_checks

client = stripe.StripeClient("sk_live_...")

@rec.tool(system="stripe", verify_outcome=stripe_checks.refund_matches(client, retries=2))
def refund(payment_intent: str, amount: int, currency: str = "eur"):
    return client.v1.refunds.create(params={"payment_intent": payment_intent, "amount": amount})
```

`refund_matches` re-fetches the refund by `response.id` and checks `amount`, `currency`, `charge` / `payment_intent`, and that `status` isn't `failed` or `canceled` (set `allowed_status=("succeeded",)` to reject `pending` as well). `payment_intent_matches` checks `amount`, `amount_received`, `currency`, `customer` and `status`. `customer_updated(client, fields=["email", "name"])` checks the listed fields.

## Zendesk

[Tickets](https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/), [Ticket comments](https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_comments/)

```python
from gleipnir.outcomes import json_get, zendesk

zd = json_get("https://acme.zendesk.com", headers={"Authorization": "Basic ..."})   # or a Zenpy client

@rec.tool(system="zendesk", verify_outcome=zendesk.ticket_updated(zd, comment="reply",
                                                                  comment_public=lambda c, r: True))
def solve_ticket(ticket_id: int, status: str, reply: str): ...
```

`ticket_updated` checks `status`, `priority`, `assignee_id`, `group_id`, `tags` (all expected tags present, or `tags_exact=True`), `custom_fields`, and that a comment with the given text (and visibility or author) is among the latest comments. `ticket_created` reads the ticket id from the create response and checks `subject`, `requester_id`, `type` and the first comment as well.

## Salesforce

[Retrieve a record](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_retrieve_get.htm)

```python
from simple_salesforce import Salesforce
from gleipnir.outcomes import arg, salesforce

sf = Salesforce(instance_url=..., session_id=...)

@rec.tool(system="salesforce", verify_outcome=salesforce.record_matches(
    sf, "Case", fields={"Status": "Closed", "OwnerId": arg("owner_id")}))
def close_case(record_id: str, owner_id: str): ...
```

Field API names are matched case-insensitively. `attributes.type` must equal the sObject. Currency fields are numbers in major units, so compare them as numbers.

## Intercom

[Retrieve a conversation](https://developers.intercom.com/docs/references/rest-api/api.intercom.io/conversations/retrieveconversation)

```python
from gleipnir.outcomes import intercom, json_get

ic = json_get("https://api.intercom.io", headers={"Authorization": "Bearer ...", "Intercom-Version": "2.11"})

@rec.tool(system="intercom", verify_outcome=intercom.conversation_replied(ic, author_type=lambda c, r: "admin"))
def reply(conversation_id: str, admin_id: str, body: str): ...
```

`conversation_replied` looks for a `conversation_parts` entry whose body contains the reply (HTML stripped), optionally with a given `part_type`, `author.id` and `author.type`. `conversation_state` checks `state`, `open`, `read`, `priority`, `admin_assignee_id`, `team_assignee_id` (unassigned `0` equals `None`) and tag names.

## HubSpot

[Read a CRM object](https://developers.hubspot.com/docs/api-reference/crm-objects-v3/basic/get-crm-v3-objects-objectType-objectId)

```python
from hubspot import HubSpot
from gleipnir.outcomes import hubspot

hs = HubSpot(access_token="...")

@rec.tool(system="hubspot", verify_outcome=hubspot.object_matches(hs, "deals", properties=["dealstage", "amount"]))
def update_deal(object_id: str, dealstage: str, amount: int): ...
```

Property values come back as strings, and the comparison accounts for that. An archived object counts as missing.

## Jira

[Get issue](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-issueidorkey-get)

```python
from gleipnir.outcomes import jira, json_get

jr = json_get("https://acme.atlassian.net", headers={"Authorization": "Basic ..."})   # or jira.JIRA

@rec.tool(system="jira", verify_outcome=jira.issue_matches(jr, status_category=lambda c, r: "done"))
def resolve_issue(issue_key: str, status: str, assignee_account_id: str): ...
```

Checks `fields.status.name` (case-insensitive), `status.statusCategory.key`, `assignee.accountId` (`None` = unassigned), `priority.name`, `labels`, `summary`, `resolution.name`, plus any `fields={"customfield_10016": 3}`.

## ServiceNow

[Table API](https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html)

```python
from gleipnir.outcomes import json_get, servicenow

sn = json_get("https://acme.service-now.com", headers={"Authorization": "Basic ..."})

@rec.tool(system="servicenow", verify_outcome=servicenow.record_matches(
    sn, "incident", fields={"state": "6", "close_code": "Solved (Permanently)"}))
def resolve_incident(sys_id: str): ...
```

By default it compares raw values (`sysparm_display_value=false`, so `state` is `"6"`, not `"Resolved"`). Reference fields compare by `sys_id`.

## Shopify

[Refund (REST)](https://shopify.dev/docs/api/admin-rest/latest/resources/refund), [Order (REST)](https://shopify.dev/docs/api/admin-rest/latest/resources/order), [Refund (GraphQL)](https://shopify.dev/docs/api/admin-graphql/latest/objects/Refund), [Order (GraphQL)](https://shopify.dev/docs/api/admin-graphql/latest/objects/Order)

```python
from gleipnir.outcomes import json_get, shopify

shop = json_get("https://acme.myshopify.com", headers={"X-Shopify-Access-Token": "..."})

@rec.tool(system="shopify", verify_outcome=shopify.refund_matches(shop))
def refund_order(order_id: int, amount: int, currency: str): ...   # amount in cents

# GraphQL Admin API (the REST Admin API is legacy):
check = shopify.order_cancelled(graphql=lambda query, variables: gql_client.execute(query, variables))
```

`refund_matches` sums the refund's `kind=refund, status=success` transactions in minor units and compares the total with `amount`. It also checks `currency` and `order_id`, and any `failure` or `error` transaction makes it a mismatch. `order_cancelled` checks that `cancelled_at` is set, plus the `cancel_reason` and the financial status.

## Anything else: generic HTTP

```python
from gleipnir.outcomes import http_json_matches, json_get

api = json_get("https://billing.internal", headers={"Authorization": "Bearer ..."})

check = http_json_matches(
    get_url=lambda call, resp: f"/v2/credits/{resp['credit_id']}",
    fetch=api,
    expected=lambda call, resp: {"amount_cents": call.args["amount_cents"], "account.id": call.args["account"]},
    root="data", retries=3,
)
```

## TypeScript

`@getgleipnir/sdk` exports the Stripe, Zendesk and generic HTTP checks with the same semantics. They're async, so wrap an async tool, and pass `params` so arguments are recorded by name:

```ts
import Stripe from "stripe";
import { Recorder, outcomes } from "@getgleipnir/sdk";

const stripe = new Stripe(process.env.STRIPE_KEY!);
const refund = rec.tool(
  async (payment_intent: string, amount: number) => stripe.refunds.create({ payment_intent, amount }),
  { name: "refund", system: "stripe", params: ["payment_intent", "amount"],
    verifyOutcome: outcomes.stripe.refundMatches(stripe, { retries: 2 }) },
);

const zd = outcomes.jsonGet("https://acme.zendesk.com", { headers: { Authorization: "Basic ..." } });
const solve = rec.tool(solveTicket, { system: "zendesk", params: ["ticket_id", "status", "reply"],
  verifyOutcome: outcomes.zendesk.ticketUpdated(zd, { comment: "reply" }) });
```

## What gets recorded

`outcome.observed` holds only the compared fields, as read from the system. It isn't run through the tool's `redact` rules, so don't compare secrets. A check is evidence that the read-back matched at the moment it ran. It doesn't stop a compromised vendor process from faking the read (see the [threat model](threat-model.md)). For that, the buyer runs `gleipnir-verify reconcile` against their own export.
