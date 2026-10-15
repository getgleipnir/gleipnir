"""HubSpot read-back check against CRM v3 object payloads."""

from gleipnir import Call
from gleipnir.outcomes import HttpError, arg
from gleipnir.outcomes import hubspot as hs

# GET /crm/v3/objects/deals/{id}?properties=...
DEAL = {
    "id": "512", "properties": {
        "amount": "1500.00", "dealname": "Acme renewal", "dealstage": "closedwon", "pipeline": "default",
        "hs_object_id": "512", "createdate": "2026-09-01T10:00:00.000Z", "hs_is_closed": "true",
    },
    "createdAt": "2026-09-01T10:00:00.000Z", "updatedAt": "2026-10-01T09:00:00.000Z", "archived": False,
}


class FakeHubSpot:
    def __init__(self, objs, failures=None):
        self.objs, self.failures, self.paths = objs, failures or [], []

    def __call__(self, path):
        self.paths.append(path)
        if self.failures:
            raise self.failures.pop(0)
        oid = path.split("?")[0].rsplit("/", 1)[-1]
        if oid not in self.objs:
            raise HttpError(404, path, '{"status":"error","category":"OBJECT_NOT_FOUND"}')
        return {**self.objs[oid], "properties": dict(self.objs[oid]["properties"])}


def call(**args):
    return Call("act_1", "close_deal", "hubspot", args)


def test_match_with_string_encoded_values():
    client = FakeHubSpot({"512": DEAL})
    chk = hs.object_matches(client, "deals", properties={"dealstage": arg("stage"), "amount": arg("amount"),
                                                         "hs_is_closed": True})
    o = chk(call(object_id="512", stage="closedwon", amount=1500), {})
    assert o.check == "match", o
    assert client.paths == ["/crm/v3/objects/deals/512?properties=amount,dealstage,hs_is_closed"]


def test_mismatch_and_absent_property():
    client = FakeHubSpot({"512": DEAL})
    o = hs.object_matches(client, "deals", properties=["dealstage", "closed_lost_reason"])(
        call(object_id="512", dealstage="closedlost", closed_lost_reason="price"), {})
    assert o.check == "mismatch" and o.fields == ["closed_lost_reason", "dealstage"]
    assert o.observed["closed_lost_reason"] is None
    o = hs.object_matches(client, "deals", properties={"closed_lost_reason": None})(call(object_id="512"), {})
    assert o.check == "match"


def test_missing_and_archived():
    assert hs.object_matches(FakeHubSpot({}), "deals", properties={"a": 1})(call(), {"id": "9"}).fields == ["exists"]
    archived = {**DEAL, "archived": True}
    assert hs.object_matches(FakeHubSpot({"512": archived}), "deals", properties={"a": 1})(
        call(object_id="512"), {}).fields == ["exists"]


def test_rate_limit_retry():
    client = FakeHubSpot({"512": DEAL}, failures=[HttpError(429, "/x", "TEN_SECONDLY_ROLLING")])
    o = hs.object_matches(client, "deals", properties={"dealstage": "closedwon"}, retries=1, sleep=lambda s: None)(
        call(object_id="512"), {})
    assert o.check == "match" and len(client.paths) == 2


def test_official_sdk_shape():
    class ApiException(Exception):
        def __init__(self, status):
            super().__init__(f"({status})")
            self.status = status

    class SimplePublicObject:
        def __init__(self, d):
            self.d = d

        def to_dict(self):
            return dict(self.d)

    class BasicApi:
        def __init__(self):
            self.calls = []

        def get_by_id(self, object_type, object_id, properties=None):
            self.calls.append((object_type, object_id, properties))
            if object_id != "512":
                raise ApiException(404)
            return SimplePublicObject(DEAL)

    class Objects:
        basic_api = BasicApi()

    class Crm:
        objects = Objects()

    class HubSpot:
        crm = Crm()

    client = HubSpot()
    chk = hs.object_matches(client, "deals", properties={"dealstage": "closedwon"})
    assert chk(call(), {"id": "512"}).check == "match"
    assert client.crm.objects.basic_api.calls[0] == ("deals", "512", ["dealstage"])
    assert chk(call(), {"id": "513"}).fields == ["exists"]
