"""Stripe read-back checks: refunds, PaymentIntents, customers.

Field names and status values are from the Stripe API reference:

* Refund object: https://docs.stripe.com/api/refunds/object
  (``amount`` integer in the smallest currency unit, ``currency`` lowercase ISO code, ``charge``,
  ``payment_intent``, ``status`` one of ``pending``, ``requires_action``, ``succeeded``, ``failed``,
  ``canceled``; ``failure_reason``; ``metadata``)
* PaymentIntent object: https://docs.stripe.com/api/payment_intents/object
  (``amount``, ``amount_received``, ``currency``, ``customer``, ``status``, ``metadata``)
* Customer object: https://docs.stripe.com/api/customers/object (a deleted customer is returned
  as ``{"id": ..., "deleted": true}``)
* Errors: https://docs.stripe.com/error-handling (``InvalidRequestError`` with code
  ``resource_missing`` / HTTP 404 for a missing object, ``APIConnectionError``, ``RateLimitError``)

``client`` may be a ``stripe.StripeClient`` (``client.v1.refunds.retrieve``), the ``stripe``
module itself (``stripe.Refund.retrieve``), or a callable ``path -> JSON`` such as
``json_get("https://api.stripe.com", headers={"Authorization": "Bearer sk_..."})``.

Money is compared in minor units: the expected ``amount`` must be an integer (cents).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..recorder import Call, Outcome
from ._core import (
    ABSENT,
    SKIP,
    Check,
    ConfigError,
    Fields,
    NotFound,
    Spec,
    check_fn,
    ci_equal,
    expect_minor,
    first_of,
    get_path,
    object_id,
    one_of,
    opt_arg,
    plain,
    resolve,
    resolve_fields,
    resolve_id,
    resp,
)

DOCS = "https://docs.stripe.com/api"
REFUND_OK_STATUSES = ("pending", "requires_action", "succeeded")
_CLASS = {"refunds": "Refund", "payment_intents": "PaymentIntent", "customers": "Customer"}


def retrieve(client: Any, resource: str, object_id_: str) -> Any:
    """Fetch one Stripe object by id through whichever client shape was injected."""
    v1 = getattr(client, "v1", None)
    if v1 is not None and hasattr(getattr(v1, resource, None), "retrieve"):
        return getattr(v1, resource).retrieve(object_id_)
    svc = getattr(client, resource, None)
    if svc is not None and hasattr(svc, "retrieve"):
        return svc.retrieve(object_id_)
    cls = getattr(client, _CLASS[resource], None)
    if cls is not None and hasattr(cls, "retrieve"):
        return cls.retrieve(object_id_)
    if callable(client):
        return client(f"/v1/{resource}/{object_id_}")
    raise ConfigError(f"unsupported Stripe client {type(client).__name__}")


def _fetch(client: Any, resource: str, oid: str) -> Any:
    obj = plain(retrieve(client, resource, oid))
    if obj is None:
        raise NotFound(f"{resource}/{oid}")
    if get_path(obj, "deleted") is True:
        raise NotFound(f"{resource}/{oid} is deleted")
    return obj


def refund_matches(
    client: Any,
    *,
    refund_id: Spec = resp("id"),
    amount: Spec = opt_arg("amount"),
    currency: Spec = opt_arg("currency"),
    charge: Spec = opt_arg("charge"),
    payment_intent: Spec = opt_arg("payment_intent"),
    metadata: Spec = None,
    allowed_status: Iterable[str] = REFUND_OK_STATUSES,
    **retry: Any,
) -> Any:
    """Re-fetch the refund by id and check amount, currency, charge / PaymentIntent and status.

    Defaults follow Stripe's own create-refund parameter names (``amount``, ``currency``,
    ``charge``, ``payment_intent``), taken from the tool's arguments when present; the refund id
    comes from the tool's response (``response["id"]``). A ``failed`` or ``canceled`` refund is a
    mismatch on ``status``; pass ``allowed_status=("succeeded",)`` to also reject ``pending``.
    """
    allowed = tuple(allowed_status)

    def read(call: Call, response: Any) -> Outcome:
        rid = resolve_id(refund_id, call, response, "refund id")
        obj = _fetch(client, "refunds", rid)
        c = Check("stripe.refund_matches")
        c.note("id", get_path(obj, "id"))
        c.field("amount", expect_minor(resolve(amount, call, response)), get_path(obj, "amount"))
        c.field("currency", resolve(currency, call, response), get_path(obj, "currency"), ci_equal)
        c.field("charge", object_id(resolve(charge, call, response)), object_id(get_path(obj, "charge")))
        c.field("payment_intent", object_id(resolve(payment_intent, call, response)),
                object_id(get_path(obj, "payment_intent")))
        c.field("metadata", resolve(metadata, call, response), get_path(obj, "metadata"))
        status = get_path(obj, "status")
        c.require("status", status in allowed, status)
        reason = get_path(obj, "failure_reason")
        if reason not in (None, ABSENT):
            c.note("failure_reason", reason)
        return c.outcome()

    return check_fn("stripe.refund_matches", read, retry)


def payment_intent_matches(
    client: Any,
    *,
    payment_intent_id: Spec = first_of(opt_arg("payment_intent_id"), resp("id")),
    amount: Spec = opt_arg("amount"),
    amount_received: Spec = None,
    currency: Spec = opt_arg("currency"),
    customer: Spec = opt_arg("customer"),
    status: Spec = None,
    metadata: Spec = None,
    **retry: Any,
) -> Any:
    """Re-fetch a PaymentIntent and check amount, amount_received, currency, customer, status.

    ``status`` may be one value or a tuple of acceptable values, e.g.
    ``status=lambda call, resp: ("succeeded", "processing")``.
    """

    def read(call: Call, response: Any) -> Outcome:
        pid = resolve_id(payment_intent_id, call, response, "PaymentIntent id")
        obj = _fetch(client, "payment_intents", pid)
        c = Check("stripe.payment_intent_matches")
        c.note("id", get_path(obj, "id"))
        c.field("amount", expect_minor(resolve(amount, call, response)), get_path(obj, "amount"))
        c.field("amount_received", expect_minor(resolve(amount_received, call, response), "amount_received"),
                get_path(obj, "amount_received"))
        c.field("currency", resolve(currency, call, response), get_path(obj, "currency"), ci_equal)
        c.field("customer", object_id(resolve(customer, call, response)), object_id(get_path(obj, "customer")))
        c.field("status", resolve(status, call, response), get_path(obj, "status"), one_of)
        c.field("metadata", resolve(metadata, call, response), get_path(obj, "metadata"))
        return c.outcome()

    return check_fn("stripe.payment_intent_matches", read, retry)


def customer_updated(
    client: Any,
    *,
    fields: Fields,
    customer_id: Spec = first_of(opt_arg("customer_id"), opt_arg("customer"), resp("id")),
    **retry: Any,
) -> Any:
    """Re-fetch a customer and check that the listed fields hold the values the agent wrote.

    ``fields=["email", "name"]`` compares each against the tool argument of the same name;
    ``fields={"metadata": {"tier": "gold"}, "address.city": "Vienna"}`` gives explicit values
    (dotted paths reach nested fields; a dict is a subset match). A deleted customer is a
    mismatch on ``exists``.
    """

    def read(call: Call, response: Any) -> Outcome:
        cid = resolve_id(customer_id, call, response, "customer id")
        expected = resolve_fields(fields, call, response)
        obj = _fetch(client, "customers", cid)
        c = Check("stripe.customer_updated")
        c.note("id", get_path(obj, "id"))
        for name, value in expected.items():
            c.field(name, value, get_path(obj, name))
        return c.outcome()

    if fields is None:
        raise TypeError("customer_updated needs fields=")
    return check_fn("stripe.customer_updated", read, retry)


__all__ = ["DOCS", "REFUND_OK_STATUSES", "SKIP", "customer_updated", "payment_intent_matches", "refund_matches",
           "retrieve"]
