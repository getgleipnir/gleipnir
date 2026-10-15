"""Zendesk read-back checks against payloads shaped like the Zendesk Support API reference."""

import copy

from gleipnir import Call
from gleipnir.outcomes import HttpError
from gleipnir.outcomes import zendesk as zd

# https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/ (Show Ticket)
TICKET = {
    "ticket": {
        "id": 35436, "url": "https://company.zendesk.com/api/v2/tickets/35436.json",
        "assignee_id": 235323, "group_id": 98738, "requester_id": 20978392, "submitter_id": 76872,
        "organization_id": 509974, "collaborator_ids": [35334, 234], "follower_ids": [35334, 234],
        "custom_fields": [{"id": 27642, "value": "745"}, {"id": 27648, "value": "yes"}],
        "description": "The fire is very colorful.", "subject": "Help, my printer is on fire!",
        "priority": "high", "status": "open", "type": "incident", "tags": ["enterprise", "other_tag"],
        "created_at": "2009-07-20T22:55:29Z", "updated_at": "2011-05-05T10:38:52Z",
    }
}
# https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_comments/ (List Comments)
COMMENTS = {
    "comments": [
        {"id": 1274, "type": "Comment", "author_id": 235323, "public": True,
         "body": "Thanks for your help!", "html_body": "<p>Thanks for your help!</p>",
         "plain_body": "Thanks for your help!", "created_at": "2009-07-20T22:55:29Z"},
        {"id": 1275, "type": "Comment", "author_id": 235323, "public": False,
         "body": "Internal: refund approved", "html_body": "<p>Internal: refund approved</p>",
         "plain_body": "Internal: refund approved", "created_at": "2009-07-20T22:56:29Z"},
    ],
    "next_page": None, "previous_page": None, "count": 2,
}


class FakeZendesk:
    """A callable path -> JSON, like json_get("https://company.zendesk.com")."""

    def __init__(self, tickets, comments=None, failures=None):
        self.tickets = {str(t["ticket"]["id"]): t for t in tickets}
        self.comments = comments or {}
        self.failures = failures or []
        self.paths = []

    def __call__(self, path):
        self.paths.append(path)
        if self.failures:
            raise self.failures.pop(0)
        parts = path.split("?")[0].split("/")
        tid = parts[4].removesuffix(".json")
        if tid not in self.tickets:
            raise HttpError(404, path, '{"error":"RecordNotFound","description":"Not found"}')
        if len(parts) > 5 and parts[5].startswith("comments"):
            body = copy.deepcopy(self.comments.get(tid, {"comments": []}))
            if "sort_order=desc" in path:
                body["comments"].reverse()
            return body
        return copy.deepcopy(self.tickets[tid])


def call(**args):
    return Call("act_1", "update_ticket", "zendesk", args)


def no_sleep(_):
    pass


def test_ticket_updated_match_with_comment():
    client = FakeZendesk([TICKET], {"35436": COMMENTS})
    chk = zd.ticket_updated(client, comment="reply", comment_public=lambda c, r: True)
    o = chk(call(ticket_id=35436, status="open", priority="high", assignee_id="235323", tags=["enterprise"],
                 reply="Thanks for your help!"), {})
    assert o.check == "match", o
    assert o.observed["status"] == "open"
    assert o.observed["comment"]["id"] == 1274
    assert client.paths == ["/api/v2/tickets/35436.json", "/api/v2/tickets/35436/comments.json?sort_order=desc"]


def test_ticket_updated_mismatch_fields():
    client = FakeZendesk([TICKET], {"35436": COMMENTS})
    o = zd.ticket_updated(client)(call(ticket_id=35436, status="solved", priority="high", assignee_id=999,
                                       tags=["vip"]), {})
    assert o.check == "mismatch"
    assert o.fields == ["assignee_id", "status", "tags"]
    assert o.observed["tags"] == ["enterprise", "other_tag"]


def test_tags_exact_and_custom_fields():
    client = FakeZendesk([TICKET])
    exact = zd.ticket_updated(client, tags_exact=True, custom_fields={27642: "745", 27648: "no"})
    o = exact(call(ticket_id=35436, tags=["enterprise"]), {})
    assert o.fields == ["custom_fields.27648", "tags"]


def test_comment_missing_or_wrong_visibility():
    client = FakeZendesk([TICKET], {"35436": COMMENTS})
    o = zd.ticket_updated(client, comment="reply")(call(ticket_id=35436, reply="We have refunded you"), {})
    assert o.check == "mismatch" and o.fields == ["comment"]
    # the internal note exists, but the agent claimed a public reply
    o = zd.ticket_updated(client, comment="reply", comment_public=lambda c, r: True)(
        call(ticket_id=35436, reply="refund approved"), {})
    assert o.fields == ["comment"]
    o = zd.ticket_updated(client, comment="reply", comment_public=lambda c, r: False)(
        call(ticket_id=35436, reply="refund   approved"), {})
    assert o.check == "match"


def test_ticket_missing():
    o = zd.ticket_updated(FakeZendesk([]))(call(ticket_id=1, status="open"), {})
    assert o.check == "mismatch" and o.fields == ["exists"]


def test_transient_then_retry():
    client = FakeZendesk([TICKET], failures=[HttpError(503, "/x"), HttpError(429, "/x")])
    o = zd.ticket_updated(client, retries=2, sleep=no_sleep)(call(ticket_id=35436, status="open"), {})
    assert o.check == "match" and len(client.paths) == 3


def test_forbidden_is_error_and_not_retried():
    client = FakeZendesk([TICKET], failures=[HttpError(403, "/x", "Forbidden")])
    o = zd.ticket_updated(client, retries=3, sleep=no_sleep)(call(ticket_id=35436, status="open"), {})
    assert o.check == "error" and "HTTP 403" in o.detail and len(client.paths) == 1


def test_ticket_created():
    client = FakeZendesk([TICKET], {"35436": COMMENTS})
    chk = zd.ticket_created(client)
    args = dict(subject="Help, my printer is on fire!", requester_id=20978392, priority="high", type="incident",
                comment={"body": "The fire is very colorful."})
    o = chk(call(**args), {"ticket": {"id": 35436, "status": "new"}})
    assert o.check == "match", o
    o = chk(call(**{**args, "subject": "Something else"}), {"ticket": {"id": 35436}})
    assert o.fields == ["subject"]
    o = chk(call(**args), {"ticket": {"id": 99}})
    assert o.fields == ["exists"]


def test_zenpy_style_client():
    class Obj:
        def __init__(self, d):
            self._d = d

        def to_dict(self):
            return dict(self._d)

    class Tickets:
        def __call__(self, id):
            if id != 35436:
                from types import SimpleNamespace

                raise type("RecordNotFoundException", (Exception,), {})(SimpleNamespace())
            return Obj(TICKET["ticket"])

        def comments(self, ticket):
            return [Obj(c) for c in COMMENTS["comments"]]

    class Zenpy:
        tickets = Tickets()

    chk = zd.ticket_updated(Zenpy(), comment="reply")
    assert chk(call(ticket_id=35436, status="open", reply="refund approved"), {}).check == "match"
    assert chk(call(ticket_id=1, status="open", reply="x"), {}).fields == ["exists"]
