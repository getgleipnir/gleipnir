"""Shopify refund / order-cancel read-back checks (REST and GraphQL shapes)."""

import pytest

from gleipnir import Call
from gleipnir.outcomes import HttpError, to_minor_units
from gleipnir.outcomes import shopify as sh

# GET /admin/api/2025-10/orders/450789469/refunds/509562969.json
REFUND = {
    "refund": {
        "id": 509562969, "order_id": 450789469, "created_at": "2026-10-01T09:00:00-04:00", "note": "it broke",
        "refund_line_items": [{"id": 104689539, "quantity": 1, "line_item_id": 703073504, "restock_type": "no_restock",
                               "subtotal": 195.67, "total_tax": 3.98}],
        "transactions": [
            {"id": 179259969, "order_id": 450789469, "kind": "refund", "gateway": "bogus", "status": "success",
             "amount": "209.00", "currency": "USD", "parent_id": 801038806},
        ],
    }
}
ORDER = {
    "order": {"id": 450789469, "cancelled_at": "2026-10-01T10:00:00-04:00", "cancel_reason": "customer",
              "financial_status": "refunded", "currency": "USD", "total_price": "409.94"}
}


class FakeRest:
    def __init__(self, routes, failures=None):
        self.routes, self.failures, self.paths = routes, failures or [], []

    def __call__(self, path):
        self.paths.append(path)
        if self.failures:
            raise self.failures.pop(0)
        if path not in self.routes:
            raise HttpError(404, path, '{"errors":"Not Found"}')
        return self.routes[path]


RPATH = "/admin/api/2025-10/orders/450789469/refunds/509562969.json"
OPATH = "/admin/api/2025-10/orders/450789469.json"


def call(**args):
    return Call("act_1", "refund", "shopify", args)


def test_minor_units():
    assert to_minor_units("209.00", "USD") == 20900
    assert to_minor_units("500", "JPY") == 500
    assert to_minor_units("1.234", "KWD") == 1234
    with pytest.raises(ValueError):
        to_minor_units("1.005", "USD")


def test_rest_refund_match_and_mismatch():
    client = FakeRest({RPATH: REFUND})
    chk = sh.refund_matches(client)
    o = chk(call(order_id=450789469, amount=20900, currency="usd"), {"refund": {"id": 509562969}})
    assert o.check == "match", o
    assert o.observed["amount"] == 20900
    o = chk(call(order_id=450789469, amount=21000), {"refund": {"id": 509562969}})
    assert o.check == "mismatch" and o.fields == ["amount"]


def test_failed_transaction_and_split_transactions():
    txs = [{"kind": "refund", "status": "success", "amount": "100.00", "currency": "USD"},
           {"kind": "refund", "status": "failure", "amount": "109.00", "currency": "USD"}]
    client = FakeRest({RPATH: {"refund": {**REFUND["refund"], "transactions": txs}}})
    o = sh.refund_matches(client)(call(order_id=450789469, amount=20900), {"refund": {"id": 509562969}})
    assert o.fields == ["amount", "transactions"]
    assert o.observed["amount"] == 10000


def test_refund_missing_and_retry():
    o = sh.refund_matches(FakeRest({}))(call(order_id=450789469, amount=1), {"refund": {"id": 509562969}})
    assert o.fields == ["exists"]
    client = FakeRest({RPATH: REFUND}, failures=[HttpError(429, "/x"), HttpError(503, "/x")])
    o = sh.refund_matches(client, retries=2, sleep=lambda s: None)(
        call(order_id=450789469, amount=20900), {"refund": {"id": 509562969}})
    assert o.check == "match" and len(client.paths) == 3


def test_graphql_refund():
    seen = []

    def graphql(query, variables):
        seen.append(variables)
        if variables["id"] != "gid://shopify/Refund/509562969":
            return {"data": {"refund": None}}
        return {"data": {"refund": {
            "id": "gid://shopify/Refund/509562969", "order": {"id": "gid://shopify/Order/450789469"},
            "totalRefundedSet": {"shopMoney": {"amount": "209.0", "currencyCode": "USD"}},
            "transactions": {"nodes": [{"kind": "REFUND", "status": "SUCCESS",
                                        "amountSet": {"shopMoney": {"amount": "209.0", "currencyCode": "USD"}}}]},
        }}}

    chk = sh.refund_matches(graphql=graphql)
    o = chk(call(order_id="450789469", amount=20900, currency="USD"), {"refund": {"id": "509562969"}})
    assert o.check == "match", o
    assert chk(call(amount=20900), {"refund": {"id": "1"}}).fields == ["exists"]

    def errors(query, variables):
        return {"data": None, "errors": [{"message": "Access denied for refund field."}]}

    o = sh.refund_matches(graphql=errors)(call(amount=1), {"id": "1"})
    assert o.check == "error" and "Access denied" in o.detail


def test_order_cancelled_rest_and_graphql():
    client = FakeRest({OPATH: ORDER})
    o = sh.order_cancelled(client, financial_status=lambda c, r: "refunded")(
        call(order_id=450789469, reason="CUSTOMER"), {})
    assert o.check == "match", o
    open_order = {"order": {**ORDER["order"], "cancelled_at": None, "cancel_reason": None}}
    o = sh.order_cancelled(FakeRest({OPATH: open_order}))(call(order_id=450789469, reason="customer"), {})
    assert o.fields == ["cancel_reason", "cancelled_at"]

    def graphql(query, variables):
        return {"order": {"id": variables["id"], "cancelledAt": "2026-10-01T14:00:00Z", "cancelReason": "FRAUD",
                          "displayFinancialStatus": "VOIDED", "currencyCode": "USD"}}

    assert sh.order_cancelled(graphql=graphql)(call(order_id=1, reason="fraud"), {}).check == "match"
    with pytest.raises(TypeError):
        sh.order_cancelled()
