"""Jira read-back check against IssueBean payloads (Jira Cloud REST API v3)."""

from gleipnir import Call
from gleipnir.outcomes import HttpError
from gleipnir.outcomes import jira as jr

ISSUE = {
    "expand": "renderedFields,names,schema", "id": "10002", "key": "ED-1",
    "self": "https://your-domain.atlassian.net/rest/api/3/issue/10002",
    "fields": {
        "summary": "Refund customer for order A-1002",
        "status": {"name": "Done", "id": "10001", "statusCategory": {"id": 3, "key": "done", "name": "Done"}},
        "assignee": {"accountId": "5b10a2844c20165700ede21g", "displayName": "Mia Krystof", "active": True},
        "priority": {"name": "High", "id": "2"},
        "labels": ["refund", "agent"],
        "resolution": {"name": "Fixed", "id": "10000"},
        "customfield_10016": 3.0,
        "components": [{"name": "Billing"}],
    },
}


class FakeJira:
    def __init__(self, issues, failures=None):
        self.issues, self.failures, self.paths = issues, failures or [], []

    def __call__(self, path):
        self.paths.append(path)
        if self.failures:
            raise self.failures.pop(0)
        key = path.split("?")[0].rsplit("/", 1)[-1]
        if key not in self.issues:
            raise HttpError(404, path, '{"errorMessages":["Issue does not exist or you do not have permission."]}')
        return self.issues[key]


def call(**args):
    return Call("act_1", "transition_issue", "jira", args)


def test_match():
    client = FakeJira({"ED-1": ISSUE})
    chk = jr.issue_matches(client, status_category=lambda c, r: "done", resolution=lambda c, r: "Fixed",
                           fields={"customfield_10016": 3, "components.0.name": "Billing"})
    o = chk(call(issue_key="ED-1", status="done", priority="High", assignee_account_id="5b10a2844c20165700ede21g",
                 labels=["refund"]), {})
    assert o.check == "match", o
    assert client.paths[0].startswith("/rest/api/3/issue/ED-1?fields=")
    assert "customfield_10016" in client.paths[0]


def test_mismatch_and_unassigned():
    in_progress = {"name": "In Progress", "statusCategory": {"key": "indeterminate"}}
    unassigned = {**ISSUE, "fields": {**ISSUE["fields"], "assignee": None, "status": in_progress}}
    o = jr.issue_matches(FakeJira({"ED-1": unassigned}))(
        call(issue_key="ED-1", status="Done", assignee_account_id="5b10a2844c20165700ede21g"), {})
    assert o.check == "mismatch" and o.fields == ["assignee_account_id", "status"]
    assert o.observed["assignee_account_id"] is None
    o = jr.issue_matches(FakeJira({"ED-1": unassigned}), assignee_account_id=lambda c, r: None)(
        call(issue_key="ED-1"), {})
    assert o.check == "match"


def test_labels_exact():
    o = jr.issue_matches(FakeJira({"ED-1": ISSUE}), labels_exact=True)(call(issue_key="ED-1", labels=["refund"]), {})
    assert o.fields == ["labels"]


def test_missing_and_retry_and_create_response():
    assert jr.issue_matches(FakeJira({}))(call(issue_key="ED-9", status="Done"), {}).fields == ["exists"]
    client = FakeJira({"ED-1": ISSUE}, failures=[HttpError(502, "/x")])
    o = jr.issue_matches(client, retries=1, sleep=lambda s: None)(
        call(summary="Refund customer for order A-1002"), {"id": "10002", "key": "ED-1", "self": "..."})
    assert o.check == "match" and len(client.paths) == 2


def test_pycontribs_client():
    class Resource:
        raw = ISSUE

    class JIRAError(Exception):
        def __init__(self, status_code):
            super().__init__("Issue Does Not Exist")
            self.status_code = status_code

    class JIRA:
        def issue(self, key, fields=None):
            if key != "ED-1":
                raise JIRAError(404)
            return Resource()

    chk = jr.issue_matches(JIRA())
    assert chk(call(issue_key="ED-1", status="Done"), {}).check == "match"
    assert chk(call(issue_key="ED-2", status="Done"), {}).fields == ["exists"]
