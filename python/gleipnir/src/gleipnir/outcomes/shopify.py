"""Shopify read-back checks: a refund was booked, an order was cancelled.

From the Shopify Admin API reference:

* REST Refund: https://shopify.dev/docs/api/admin-rest/latest/resources/refund
  (``GET /admin/api/{version}/orders/{order_id}/refunds/{refund_id}.json`` returns
  ``{"refund": {id, order_id, created_at, transactions: [{amount: "209.00", currency, kind:
  "refund", status: "success"}], refund_line_items}}``)
* REST Order: https://shopify.dev/docs/api/admin-rest/latest/resources/order
  (``GET /admin/api/{version}/orders/{order_id}.json``; ``cancelled_at`` null unless cancelled,
  ``cancel_reason`` one of ``customer``, ``fraud``, ``inventory``, ``declined``, ``other``;
  ``financial_status`` e.g. ``refunded``, ``voided``)
* GraphQL Refund: https://shopify.dev/docs/api/admin-graphql/latest/objects/Refund
  (``totalRefundedSet.shopMoney {amount, currencyCode}``, ``transactions`` with ``kind``
  (``REFUND``...) and ``status`` (``SUCCESS``, ``PENDING``, ``FAILURE``, ``ERROR``,
  ``AWAITING_RESPONSE``, ``UNKNOWN``), ``order.id``)
* GraphQL Order: https://shopify.dev/docs/api/admin-graphql/latest/objects/Order
  (``cancelledAt``, ``cancelReason`` (``CUSTOMER``, ``DECLINED``, ``FRAUD``, ``INVENTORY``,
  ``OTHER``, ``STAFF``), ``displayFinancialStatus``)

The REST Admin API is legacy since 2024-10-01 (new public apps must use GraphQL), so both are
supported: ``client`` is a callable ``path -> JSON`` for REST (``json_get("https://shop.myshopify.com",
headers={"X-Shopify-Access-Token": ...})``), or pass ``graphql=`` a callable
``(query, variables) -> data`` for the GraphQL Admin API.

Money: Shopify returns decimal strings in major units; they are converted exactly to minor units
using the currency's ISO 4217 exponent and compared with the expected integer ``amount``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..recorder import Call, Outcome
from ._core import (
    ABSENT,
    Check,
    ConfigError,
    NotFound,
    Spec,
    check_fn,
    ci_equal,
    expect_minor,
    first_of,
    get_path,
    http_get,
    opt_arg,
    plain,
    resolve,
    resolve_id,
    resp,
    to_minor_units,
)

DOCS = "https://shopify.dev/docs/api/admin-rest/latest/resources/refund"
API_VERSION = "2025-10"
_BAD_TX = {"failure", "error"}

_REFUND_QUERY = """query GleipnirRefund($id: ID!) { refund(id: $id) { id order { id }
  totalRefundedSet { shopMoney { amount currencyCode } }
  transactions(first: 50) { nodes { kind status amountSet { shopMoney { amount currencyCode } } } } } }"""
_ORDER_QUERY = """query GleipnirOrder($id: ID!) { order(id: $id) { id cancelledAt cancelReason
  displayFinancialStatus currencyCode } }"""


def _gid(kind: str, v: str) -> str:
    return v if v.startswith("gid://") else f"gid://shopify/{kind}/{v}"


def _legacy(v: Any) -> str:
    s = str(v)
    return s.rsplit("/", 1)[-1] if s.startswith("gid://") else s


def _gql(graphql: Callable[..., Any], query: str, variables: dict[str, Any], key: str, what: str) -> Any:
    data = plain(graphql(query, variables))
    if isinstance(data, dict) and "data" in data and key not in data:
        errs = data.get("errors")
        if errs:
            raise ConfigError(f"Shopify GraphQL errors: {str(errs)[:300]}")
        data = data["data"]
    obj = get_path(data, key)
    if obj is ABSENT or obj is None:
        raise NotFound(what)
    return obj


def _sum_minor(txs: list[Any], currency: str | None) -> tuple[int, str | None]:
    total, cur = 0, currency
    for t in txs:
        kind = str(get_path(t, "kind")).lower()
        status = str(get_path(t, "status")).lower()
        if kind != "refund" or status != "success":
            continue
        amt = get_path(t, "amount")
        tcur = get_path(t, "currency")
        if amt is ABSENT:  # GraphQL shape
            amt = get_path(t, "amountSet.shopMoney.amount")
            tcur = get_path(t, "amountSet.shopMoney.currencyCode")
        cur = cur or (None if tcur is ABSENT else str(tcur))
        if cur is None:
            raise ConfigError("transaction has no currency")
        total += to_minor_units(amt, cur)
    return total, cur


def refund_matches(
    client: Any = None,
    *,
    graphql: Callable[..., Any] | None = None,
    order_id: Spec = first_of(opt_arg("order_id"), resp("refund.order_id"), resp("order_id")),
    refund_id: Spec = first_of(resp("refund.id"), resp("id")),
    amount: Spec = opt_arg("amount"),
    currency: Spec = opt_arg("currency"),
    api_version: str = API_VERSION,
    **retry: Any,
) -> Any:
    """Re-fetch the refund and check its successful refund transactions add up to ``amount``
    (integer minor units), in ``currency``, on ``order_id``; any ``failure``/``error``
    transaction is a mismatch on ``transactions``.
    """
    if (client is None) == (graphql is None):
        raise TypeError("pass a REST client or graphql=, not both")

    def read(call: Call, response: Any) -> Outcome:
        rid = resolve_id(refund_id, call, response, "refund id")
        want_amount = expect_minor(resolve(amount, call, response))
        want_cur = resolve(currency, call, response)
        want_order = resolve(order_id, call, response)
        c = Check("shopify.refund_matches")
        if graphql is not None:
            r = _gql(graphql, _REFUND_QUERY, {"id": _gid("Refund", rid)}, "refund", f"refund {rid}")
            txs = get_path(r, "transactions.nodes")
            txs = txs if isinstance(txs, list) else []
            got_order = get_path(r, "order.id")
            shop_cur = get_path(r, "totalRefundedSet.shopMoney.currencyCode")
            shop_cur = None if shop_cur is ABSENT else str(shop_cur)
        else:
            oid = resolve_id(order_id, call, response, "order id")
            path = f"/admin/api/{api_version}/orders/{_legacy(oid)}/refunds/{_legacy(rid)}.json"
            body = plain(http_get(client, path))
            r = get_path(body, "refund")
            if r is ABSENT or not r:
                raise NotFound(f"refund {rid}")
            txs = get_path(r, "transactions")
            txs = txs if isinstance(txs, list) else []
            got_order = get_path(r, "order_id")
            shop_cur = None
        c.note("id", get_path(r, "id"))
        total, cur = _sum_minor(txs, shop_cur)
        c.field("order_id", want_order, got_order, lambda a, b: b is not ABSENT and _legacy(a) == _legacy(b))
        c.field("amount", want_amount, total)
        c.field("currency", want_cur, cur if cur is not None else ABSENT, ci_equal)
        bad = [get_path(t, "status") for t in txs if str(get_path(t, "status")).lower() in _BAD_TX]
        c.require("transactions", not bad, {"count": len(txs), "failed": bad} if bad else {"count": len(txs)})
        return c.outcome()

    return check_fn("shopify.refund_matches", read, retry)


def order_cancelled(
    client: Any = None,
    *,
    graphql: Callable[..., Any] | None = None,
    order_id: Spec = first_of(opt_arg("order_id"), resp("order.id"), resp("id")),
    reason: Spec = opt_arg("reason"),
    financial_status: Spec = None,
    api_version: str = API_VERSION,
    **retry: Any,
) -> Any:
    """Re-fetch the order and check it is cancelled (``cancelled_at`` set), with ``reason``
    (case-insensitive: REST ``customer`` == GraphQL ``CUSTOMER``) and optional
    ``financial_status`` (REST ``financial_status`` / GraphQL ``displayFinancialStatus``).
    """
    if (client is None) == (graphql is None):
        raise TypeError("pass a REST client or graphql=, not both")

    def read(call: Call, response: Any) -> Outcome:
        oid = resolve_id(order_id, call, response, "order id")
        c = Check("shopify.order_cancelled")
        if graphql is not None:
            o = _gql(graphql, _ORDER_QUERY, {"id": _gid("Order", oid)}, "order", f"order {oid}")
            at, why, fin = (get_path(o, k) for k in ("cancelledAt", "cancelReason", "displayFinancialStatus"))
        else:
            body = plain(http_get(client, f"/admin/api/{api_version}/orders/{_legacy(oid)}.json"))
            o = get_path(body, "order")
            if o is ABSENT or not o:
                raise NotFound(f"order {oid}")
            at, why, fin = (get_path(o, k) for k in ("cancelled_at", "cancel_reason", "financial_status"))
        c.note("id", get_path(o, "id"))
        c.require("cancelled_at", at not in (None, ABSENT, ""), at)
        c.field("cancel_reason", resolve(reason, call, response), why, ci_equal)
        c.field("financial_status", resolve(financial_status, call, response), fin, ci_equal)
        return c.outcome()

    return check_fn("shopify.order_cancelled", read, retry)


__all__ = ["API_VERSION", "DOCS", "order_cancelled", "refund_matches"]
