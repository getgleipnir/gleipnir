"""Ready-made outcome read-back checks for common systems of record.

After the agent writes, read the object back from the system and compare it with what the agent
asked for. Each factory returns a ``verify_outcome`` callback for :meth:`gleipnir.Recorder.tool`::

    import stripe
    from gleipnir.outcomes import stripe as stripe_checks

    client = stripe.StripeClient("sk_...")

    @rec.tool(system="stripe", verify_outcome=stripe_checks.refund_matches(client, retries=3))
    def refund(payment_intent: str, amount: int, currency: str = "eur"):
        return client.v1.refunds.create(params={"payment_intent": payment_intent, "amount": amount})

Modules: :mod:`.stripe`, :mod:`.zendesk`, :mod:`.salesforce`, :mod:`.intercom`, :mod:`.hubspot`,
:mod:`.jira`, :mod:`.servicenow`, :mod:`.shopify`, :mod:`.http`. Clients are injected (an official
SDK client or a callable ``path -> JSON`` such as :func:`json_get`), so no SDK is a dependency.

Every check returns ``match``, ``mismatch`` (``fields`` lists what differs; a missing object is
``fields=["exists"]``) or ``error`` (could not check: network, auth, configuration); none raises.
``retries=N`` (default 0) re-reads up to N times with exponential backoff (``backoff=0.5``,
``max_backoff=4.0`` seconds) on transient errors, not-found and mismatches, for eventually
consistent systems.

Note: ``observed`` is recorded as-is (it is not run through the tool's ``redact`` rules), and it
holds only the compared fields; don't compare secrets.
"""

from __future__ import annotations

from ._core import ABSENT, SKIP, ConfigError, NotFound, arg, const, first_of, opt_arg, resp, to_minor_units
from ._http import HttpError, json_get
from .http import http_json_matches

__all__ = [
    "ABSENT",
    "SKIP",
    "ConfigError",
    "HttpError",
    "NotFound",
    "arg",
    "const",
    "first_of",
    "http_json_matches",
    "json_get",
    "opt_arg",
    "resp",
    "to_minor_units",
]
