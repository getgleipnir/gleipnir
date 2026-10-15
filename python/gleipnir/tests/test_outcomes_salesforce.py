"""Salesforce read-back check against REST and simple-salesforce-shaped fakes."""

import pytest

from gleipnir import Call
from gleipnir.outcomes import HttpError, arg
from gleipnir.outcomes import salesforce as sf

# GET /services/data/v62.0/sobjects/Case/500xx...  (REST API Developer Guide, sObject Rows)
CASE = {
    "attributes": {"type": "Case", "url": "/services/data/v62.0/sobjects/Case/5003000000D8cuIAAR"},
    "Id": "5003000000D8cuIAAR", "CaseNumber": "00001026", "Status": "Closed", "Priority": "High",
    "OwnerId": "0053000000A1B2CAAV", "Subject": "Refund request", "IsDeleted": False, "Refund_Amount__c": 1500.0,
    "Account": {"attributes": {"type": "Account"}, "Name": "Acme"},
}


def call(**args):
    return Call("act_1", "close_case", "salesforce", args)


class Rest:
    def __init__(self, records, failures=None):
        self.records, self.failures, self.paths = records, failures or [], []

    def __call__(self, path):
        self.paths.append(path)
        if self.failures:
            raise self.failures.pop(0)
        rid = path.split("?")[0].rsplit("/", 1)[-1]
        if rid not in self.records:
            raise HttpError(404, path, '[{"errorCode":"NOT_FOUND","message":"The requested resource does not exist"}]')
        return dict(self.records[rid])


def test_rest_match_and_fields_param():
    client = Rest({CASE["Id"]: CASE})
    chk = sf.record_matches(client, "Case", fields={"Status": "Closed", "priority": arg("priority"),
                                                    "Refund_Amount__c": arg("amount"), "Account.Name": "Acme"})
    o = chk(call(record_id=CASE["Id"], priority="High", amount="1500.00"), {})
    assert o.check == "match", o
    assert o.observed["Status"] == "Closed" and o.observed["Id"] == CASE["Id"]
    assert client.paths == [f"/services/data/v62.0/sobjects/Case/{CASE['Id']}?fields=Account,Refund_Amount__c,"
                            "Status,priority"]


def test_mismatch():
    o = sf.record_matches(Rest({CASE["Id"]: {**CASE, "Status": "Escalated"}}), "Case", fields=["Status", "OwnerId"])(
        call(record_id=CASE["Id"], Status="Closed", OwnerId="0053000000A1B2CAAV"), {})
    assert o.check == "mismatch" and o.fields == ["Status"]


def test_wrong_sobject_type():
    o = sf.record_matches(Rest({CASE["Id"]: CASE}), "Account", fields={"Status": "Closed"})(
        call(record_id=CASE["Id"]), {})
    assert o.fields == ["sobject"]


def test_missing_and_deleted():
    o = sf.record_matches(Rest({}), "Case", fields={"Status": "Closed"})(call(), {"id": "500missing", "success": True})
    assert o.check == "mismatch" and o.fields == ["exists"]
    o = sf.record_matches(Rest({CASE["Id"]: {**CASE, "IsDeleted": True}}), "Case", fields={"Status": "Closed"})(
        call(record_id=CASE["Id"]), {})
    assert o.fields == ["exists"]


def test_error_array_from_non_raising_callable():
    def fetch(path):
        return [{"message": "The requested resource does not exist", "errorCode": "NOT_FOUND"}]

    assert sf.record_matches(fetch, "Case", fields={"Status": "Closed"})(call(record_id="x"), {}).fields == ["exists"]

    def bad(path):
        return [{"message": "Session expired or invalid", "errorCode": "INVALID_SESSION_ID"}]

    o = sf.record_matches(bad, "Case", fields={"Status": "Closed"})(call(record_id="x"), {})
    assert o.check == "error" and "INVALID_SESSION_ID" in o.detail


def test_transient_then_retry():
    client = Rest({CASE["Id"]: CASE}, failures=[HttpError(503, "/x"), TimeoutError("read timed out")])
    o = sf.record_matches(client, "Case", fields={"Status": "Closed"}, retries=2, sleep=lambda s: None)(
        call(record_id=CASE["Id"]), {})
    assert o.check == "match" and len(client.paths) == 3


def test_simple_salesforce_client():
    class SalesforceResourceNotFound(Exception):
        def __init__(self):
            super().__init__("Resource Case Not Found")
            self.status = 404

    class SFType:
        def get(self, record_id):
            if record_id != CASE["Id"]:
                raise SalesforceResourceNotFound()
            return dict(CASE)

    class Salesforce:
        sf_instance = "acme.my.salesforce.com"
        Case = SFType()

    chk = sf.record_matches(Salesforce(), "Case", fields={"Status": "Closed"})
    assert chk(call(), {"id": CASE["Id"], "success": True, "errors": []}).check == "match"
    assert chk(call(), {"id": "500other", "success": True}).fields == ["exists"]


def test_bad_config():
    with pytest.raises(TypeError):
        sf.record_matches(Rest({}), "Case", fields=None)
    with pytest.raises(ValueError):
        sf.record_matches(Rest({}), "Case/../x", fields={"a": 1})
