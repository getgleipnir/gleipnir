"""ServiceNow Table API read-back check."""

from gleipnir import Call
from gleipnir.outcomes import HttpError, arg
from gleipnir.outcomes import servicenow as sn

# GET /api/now/table/incident/{sys_id}: values are strings, references are {link, value}
INCIDENT = {
    "result": {
        "sys_id": "9d385017c611228701d22104cc95c371", "number": "INC0000003", "state": "6", "priority": "3",
        "active": "false", "close_code": "Solved (Permanently)", "short_description": "Wireless access is down",
        "assigned_to": {"link": "https://instance.service-now.com/api/now/table/sys_user/46d44a5d",
                        "value": "46d44a5d"},
        "assignment_group": "",
    }
}


class FakeSN:
    def __init__(self, recs, failures=None):
        self.recs, self.failures, self.paths = recs, failures or [], []

    def __call__(self, path):
        self.paths.append(path)
        if self.failures:
            raise self.failures.pop(0)
        sid = path.split("?")[0].rsplit("/", 1)[-1]
        if sid not in self.recs:
            raise HttpError(404, path, '{"error":{"message":"No Record found","detail":""},"status":"failure"}')
        return self.recs[sid]


def call(**args):
    return Call("act_1", "resolve_incident", "servicenow", args)


SID = INCIDENT["result"]["sys_id"]


def test_match_with_string_values_and_reference():
    client = FakeSN({SID: INCIDENT})
    chk = sn.record_matches(client, "incident", fields={"state": 6, "active": False, "assigned_to": arg("user"),
                                                        "close_code": arg("close_code"), "assignment_group": None})
    o = chk(call(sys_id=SID, user="46d44a5d", close_code="Solved (Permanently)"), {})
    assert o.check == "match", o
    p = client.paths[0]
    assert p.startswith(f"/api/now/table/incident/{SID}?sysparm_display_value=false"
                        "&sysparm_exclude_reference_link=true")
    assert "sysparm_fields=active,assigned_to,assignment_group,close_code,state,sys_id" in p


def test_mismatch_missing_retry():
    client = FakeSN({SID: INCIDENT})
    o = sn.record_matches(client, "incident", fields=["state", "priority"])(call(sys_id=SID, state="7", priority=3), {})
    assert o.check == "mismatch" and o.fields == ["state"]
    o = sn.record_matches(client, "incident", fields={"state": "6"})(call(), {"result": {"sys_id": "nope"}})
    assert o.fields == ["exists"]
    flaky = FakeSN({SID: INCIDENT}, failures=[HttpError(503, "/x")])
    o = sn.record_matches(flaky, "incident", fields={"state": "6"}, retries=1, sleep=lambda s: None)(
        call(sys_id=SID), {})
    assert o.check == "match" and len(flaky.paths) == 2


def test_auth_error():
    client = FakeSN({}, failures=[HttpError(401, "/x", '{"error":{"message":"User Not Authenticated"}}')])
    o = sn.record_matches(client, "incident", fields={"state": "6"}, retries=2, sleep=lambda s: None)(
        call(sys_id=SID), {})
    assert o.check == "error" and "401" in o.detail and len(client.paths) == 1
