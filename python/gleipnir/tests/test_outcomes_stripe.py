"""Stripe read-back checks against fake clients shaped like https://docs.stripe.com/api."""

import copy

import pytest

from gleipnir import Call
from gleipnir.outcomes import json_get
from gleipnir.outcomes import stripe as st

# Shapes copied from https://docs.stripe.com/api/refunds/object and friends.
REFUND = {
    "id": "re_1Nispe2eZvKYlo2Cd31jOCgZ", "object": "refund", "amount": 1000,
    "balance_transaction": "txn_1Nispe2eZvKYlo2CYezqFhEx", "charge": "ch_1NirD82eZvKYlo2CIvbtLWuY",
    "created": 1692942318, "currency": "usd", "metadata": {"ticket": "T-101"},
    "payment_intent": "pi_1GszsK2eZvKYlo2CfhZyoZLp", "reason": None, "receipt_number": None,
    "source_transfer_reversal": None, "status": "succeeded", "transfer_reversal": None,
}
PI = {
    "id": "pi_3MtwBwLkdIwHu7ix28a3tqPa", "object": "payment_intent", "amount": 2000, "amount_capturable": 0,
    "amount_received": 2000, "currency": "usd", "customer": "cus_NffrFeUfNV2Hib", "metadata": {},
    "status": "succeeded", "latest_charge": "ch_3MtwBwLkdIwHu7ix28a3tqPa",
}
CUSTOMER = {
    "id": "cus_NffrFeUfNV2Hib", "object": "customer", "address": {"city": "Vienna", "country": "AT"},
    "balance": 0, "email": "jennyrosen@example.com", "name": "Jenny Rosen", "metadata": {"tier": "gold"},
    "phone": None, "preferred_locales": ["de-AT"],
}


class InvalidRequestError(Exception):
    """Like stripe.InvalidRequestError: http_status + code."""

    def __init__(self, msg, http_status, code):
        super().__init__(msg)
        self.http_status = http_status
        self.code = code


class APIConnectionError(Exception):
    pass


class AuthenticationError(Exception):
    def __init__(self, msg):
        super().__init__(msg)
        self.http_status = 401


class Service:
    def __init__(self, objects, failures):
        self.objects, self.failures, self.calls = objects, failures, 0

    def retrieve(self, oid):
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        if oid not in self.objects:
            raise InvalidRequestError(f"No such object: '{oid}'", 404, "resource_missing")
        return copy.deepcopy(self.objects[oid])


class FakeStripeClient:
    """Mimics stripe.StripeClient: client.v1.refunds.retrieve(id)."""

    def __init__(self, *objs, failures=None):
        by_res = {"refund": {}, "payment_intent": {}, "customer": {}}
        for o in objs:
            by_res[o["object"]][o["id"]] = o
        failures = failures if failures is not None else []

        class V1:
            pass

        self.v1 = V1()
        self.v1.refunds = Service(by_res["refund"], failures)
        self.v1.payment_intents = Service(by_res["payment_intent"], failures)
        self.v1.customers = Service(by_res["customer"], failures)


def call(**args):
    return Call("act_1", "refund", "stripe", args)


def no_sleep(_):
    pass


def test_refund_match():
    check = st.refund_matches(FakeStripeClient(REFUND))
    o = check(call(payment_intent="pi_1GszsK2eZvKYlo2CfhZyoZLp", amount=1000, currency="USD"), {"id": REFUND["id"]})
    assert o.check == "match", o
    assert o.method == "stripe.refund_matches"
    assert o.observed == {"id": REFUND["id"], "amount": 1000, "currency": "usd",
                          "payment_intent": "pi_1GszsK2eZvKYlo2CfhZyoZLp", "status": "succeeded"}
    assert o.as_record()["check"] == "match"


def test_refund_amount_mismatch_in_minor_units():
    booked = {**REFUND, "amount": 950}
    o = st.refund_matches(FakeStripeClient(booked))(call(charge="ch_1NirD82eZvKYlo2CIvbtLWuY", amount=1000),
                                                     {"id": REFUND["id"]})
    assert o.check == "mismatch"
    assert o.fields == ["amount"]
    assert o.observed["amount"] == 950
    assert "amount" in o.detail


@pytest.mark.parametrize("status", ["failed", "canceled"])
def test_refund_failed_or_canceled_is_mismatch(status):
    obj = {**REFUND, "status": status, "failure_reason": "expired_or_canceled_card" if status == "failed" else None}
    o = st.refund_matches(FakeStripeClient(obj))(call(amount=1000), {"id": REFUND["id"]})
    assert o.check == "mismatch" and o.fields == ["status"]
    assert o.observed["status"] == status
    if status == "failed":
        assert o.observed["failure_reason"] == "expired_or_canceled_card"


def test_refund_pending_allowed_by_default_but_can_be_strict():
    obj = {**REFUND, "status": "pending"}
    assert st.refund_matches(FakeStripeClient(obj))(call(amount=1000), {"id": REFUND["id"]}).check == "match"
    strict = st.refund_matches(FakeStripeClient(obj), allowed_status=("succeeded",))
    assert strict(call(amount=1000), {"id": REFUND["id"]}).fields == ["status"]


def test_refund_wrong_payment_intent_and_expanded_charge():
    obj = {**REFUND, "charge": {"id": "ch_other", "object": "charge"}}
    o = st.refund_matches(FakeStripeClient(obj))(
        call(charge="ch_1NirD82eZvKYlo2CIvbtLWuY", payment_intent="pi_wrong", amount=1000), {"id": REFUND["id"]})
    assert o.check == "mismatch" and o.fields == ["charge", "payment_intent"]
    assert o.observed["charge"] == "ch_other"


def test_refund_metadata_subset():
    chk = st.refund_matches(FakeStripeClient(REFUND), metadata=lambda c, r: {"ticket": c.args["ticket"]})
    assert chk(call(amount=1000, ticket="T-101"), {"id": REFUND["id"]}).check == "match"
    assert chk(call(amount=1000, ticket="T-999"), {"id": REFUND["id"]}).fields == ["metadata"]


def test_refund_missing_object():
    o = st.refund_matches(FakeStripeClient())(call(amount=1000), {"id": "re_missing"})
    assert o.check == "mismatch" and o.fields == ["exists"]
    assert o.observed == {"exists": False}
    assert "not found" in o.detail


def test_refund_float_amount_is_configuration_error():
    o = st.refund_matches(FakeStripeClient(REFUND))(call(amount=10.00), {"id": REFUND["id"]})
    assert o.check == "error" and "minor units" in o.detail


def test_transient_error_then_retry_succeeds():
    client = FakeStripeClient(REFUND, failures=[APIConnectionError("connection reset"),
                                                InvalidRequestError("rate", 429, "rate_limit")])
    sleeps = []
    o = st.refund_matches(client, retries=3, backoff=0.1, sleep=sleeps.append)(call(amount=1000), {"id": REFUND["id"]})
    assert o.check == "match"
    assert client.v1.refunds.calls == 3
    assert sleeps == [0.1, 0.2]
    assert "after 3 attempts" in o.detail


def test_transient_error_without_retry_is_error_not_raise():
    client = FakeStripeClient(REFUND, failures=[APIConnectionError("connection reset")])
    o = st.refund_matches(client)(call(amount=1000), {"id": REFUND["id"]})
    assert o.check == "error" and "APIConnectionError" in o.detail
    assert client.v1.refunds.calls == 1


def test_auth_error_is_not_retried():
    client = FakeStripeClient(REFUND, failures=[AuthenticationError("Invalid API Key")])
    o = st.refund_matches(client, retries=5, sleep=no_sleep)(call(amount=1000), {"id": REFUND["id"]})
    assert o.check == "error" and "HTTP 401" in o.detail
    assert client.v1.refunds.calls == 1


def test_stale_read_retried_until_consistent():
    class Eventually(Service):
        def retrieve(self, oid):
            self.calls += 1
            return {**REFUND, "status": "pending", "amount": 0} if self.calls < 3 else dict(REFUND)

    client = FakeStripeClient()
    client.v1.refunds = Eventually({}, [])
    o = st.refund_matches(client, retries=2, sleep=no_sleep)(call(amount=1000), {"id": REFUND["id"]})
    assert o.check == "match" and client.v1.refunds.calls == 3


def test_retries_are_bounded():
    client = FakeStripeClient(failures=[APIConnectionError("x")] * 20)
    o = st.refund_matches(client, retries=2, sleep=no_sleep)(call(amount=1000), {"id": REFUND["id"]})
    assert o.check == "error" and client.v1.refunds.calls == 3
    with pytest.raises(ValueError):
        st.refund_matches(client, retries=100)
    with pytest.raises(TypeError):
        st.refund_matches(client, retry=1)


def test_no_refund_id_is_error():
    o = st.refund_matches(FakeStripeClient(REFUND))(call(amount=1000), {"status": "ok"})
    assert o.check == "error" and "refund id" in o.detail


def test_legacy_module_client_and_http_callable():
    class Refund:
        @staticmethod
        def retrieve(oid):
            return dict(REFUND)

    class StripeModule:
        pass

    mod = StripeModule()
    mod.Refund = Refund
    assert st.refund_matches(mod)(call(amount=1000), {"id": REFUND["id"]}).check == "match"

    seen = []

    def fetch(path):
        seen.append(path)
        return dict(REFUND)

    assert st.refund_matches(fetch)(call(amount=1000), {"id": REFUND["id"]}).check == "match"
    assert seen == [f"/v1/refunds/{REFUND['id']}"]


def test_http_404_via_json_get_session():
    class Resp:
        status_code = 404
        text = '{"error": {"code": "resource_missing", "type": "invalid_request_error"}}'

        def json(self):
            return {}

    class Session:
        def get(self, url, headers, timeout):
            assert url == "https://api.stripe.com/v1/refunds/re_x"
            assert headers["Authorization"] == "Bearer sk_test"
            return Resp()

    fetch = json_get("https://api.stripe.com", headers={"Authorization": "Bearer sk_test"}, session=Session())
    o = st.refund_matches(fetch)(call(amount=1000), {"id": "re_x"})
    assert o.check == "mismatch" and o.fields == ["exists"]


def test_sdk_objects_are_read_through_to_dict():
    class StripeObject(dict):
        def to_dict(self):
            return dict(self)

    class Svc:
        def retrieve(self, oid):
            return StripeObject(REFUND)

    class Client:
        pass

    c = Client()
    c.refunds = Svc()
    assert st.refund_matches(c)(call(amount=1000), {"id": REFUND["id"]}).check == "match"


def test_payment_intent_matches():
    client = FakeStripeClient(PI)
    chk = st.payment_intent_matches(client, amount_received=lambda c, r: c.args["amount"],
                                    status=lambda c, r: ("succeeded", "processing"))
    args = dict(amount=2000, currency="usd", customer="cus_NffrFeUfNV2Hib")
    assert chk(call(**args), {"id": PI["id"]}).check == "match"
    o = st.payment_intent_matches(FakeStripeClient({**PI, "amount_received": 0, "status": "requires_action"}),
                                  amount_received="amount", status=lambda c, r: "succeeded")(
        call(**args), {"id": PI["id"]})
    assert o.check == "mismatch" and o.fields == ["amount_received", "status"]
    o = st.payment_intent_matches(client)(call(payment_intent_id="pi_nope", amount=1), None)
    assert o.fields == ["exists"]


def test_customer_updated():
    client = FakeStripeClient(CUSTOMER)
    chk = st.customer_updated(client, fields=["email", "name"])
    ok = call(customer_id=CUSTOMER["id"], email="jennyrosen@example.com", name="Jenny Rosen")
    assert chk(ok, {}).check == "match"
    o = chk(call(customer_id=CUSTOMER["id"], email="new@example.com", name="Jenny Rosen"), {})
    assert o.check == "mismatch" and o.fields == ["email"]
    assert o.observed == {"id": CUSTOMER["id"], "email": "jennyrosen@example.com", "name": "Jenny Rosen"}
    nested = st.customer_updated(client, fields={"address.city": "Vienna", "metadata": {"tier": "gold"},
                                                 "phone": None})
    assert nested(call(customer_id=CUSTOMER["id"]), {}).check == "match"


def test_deleted_customer_is_missing():
    deleted = {"id": "cus_gone", "object": "customer", "deleted": True}
    o = st.customer_updated(FakeStripeClient(deleted), fields={"email": "x@example.com"})(
        call(customer_id="cus_gone"), {})
    assert o.check == "mismatch" and o.fields == ["exists"]


def test_customer_updated_requires_fields():
    with pytest.raises(TypeError):
        st.customer_updated(FakeStripeClient(), fields=None)
    o = st.customer_updated(FakeStripeClient(CUSTOMER), fields=["email"])(call(customer_id=CUSTOMER["id"]), {})
    assert o.check == "error" and "no fields" in o.detail


def test_end_to_end_with_recorder(rec):
    client = FakeStripeClient({**REFUND, "amount": 950})

    @rec.tool(system="stripe", verify_outcome=st.refund_matches(client))
    def refund(payment_intent: str, amount: int):
        return {"id": REFUND["id"], "amount": amount, "status": "succeeded"}

    refund("pi_1GszsK2eZvKYlo2CfhZyoZLp", 1000)
    a = [r for r in rec.chain.store.read_all() if r["kind"] == "action"][0]
    assert a["outcome"]["check"] == "mismatch"
    assert a["outcome"]["method"] == "stripe.refund_matches"
    assert a["outcome"]["fields"] == ["amount"]
    assert a["outcome"]["observed"]["amount"] == 950
