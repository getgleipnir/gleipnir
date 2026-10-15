"""Intercom read-back checks against conversation payloads shaped like the REST API reference."""

import copy

from gleipnir import Call
from gleipnir.outcomes import HttpError
from gleipnir.outcomes import intercom as ic

# GET /conversations/{id}, trimmed
CONV = {
    "type": "conversation", "id": "1295", "created_at": 1663597223, "updated_at": 1663597260,
    "state": "closed", "open": False, "read": True, "priority": "not_priority",
    "admin_assignee_id": 991267, "team_assignee_id": 0,
    "tags": {"type": "tag.list", "tags": [{"type": "tag", "id": "123456", "name": "refund"}]},
    "conversation_parts": {
        "type": "conversation_part.list",
        "conversation_parts": [
            {"type": "conversation_part", "id": "3", "part_type": "comment", "body": "<p>Where is my order?</p>",
             "author": {"type": "user", "id": "6762f0dd1bb69f9f2193bb83", "name": "Jane", "email": "j@x.com"}},
            {"type": "conversation_part", "id": "4", "part_type": "comment",
             "body": "<p>We&#39;ve refunded <b>EUR 42.10</b> to your card.</p>",
             "author": {"type": "admin", "id": "991267", "name": "Support Bot", "email": "bot@x.com"}},
            {"type": "conversation_part", "id": "5", "part_type": "close", "body": None,
             "author": {"type": "admin", "id": "991267"}},
        ],
        "total_count": 3,
    },
}


class FakeIntercom:
    def __init__(self, convs, failures=None):
        self.convs = {c["id"]: c for c in convs}
        self.failures = failures or []
        self.paths = []

    def __call__(self, path):
        self.paths.append(path)
        if self.failures:
            raise self.failures.pop(0)
        cid = path.rsplit("/", 1)[-1]
        if cid not in self.convs:
            raise HttpError(404, path, '{"type":"error.list","errors":[{"code":"not_found"}]}')
        return copy.deepcopy(self.convs[cid])


def call(**args):
    return Call("act_1", "reply", "intercom", args)


def test_replied_match():
    client = FakeIntercom([CONV])
    chk = ic.conversation_replied(client, author_type=lambda c, r: "admin")
    o = chk(call(conversation_id="1295", body="We've refunded EUR 42.10 to your card.", message_type="comment",
                 admin_id=991267), {})
    assert o.check == "match", o
    assert o.observed["reply"]["part_id"] == "4"
    assert client.paths == ["/conversations/1295"]


def test_replied_missing_or_wrong_author():
    client = FakeIntercom([CONV])
    o = ic.conversation_replied(client)(call(conversation_id="1295", body="Your refund is on the way"), {})
    assert o.check == "mismatch" and o.fields == ["reply"]
    o = ic.conversation_replied(client)(call(conversation_id="1295", body="refunded", admin_id="12"), {})
    assert o.fields == ["reply"]
    o = ic.conversation_replied(client)(call(conversation_id="1295", body="refunded", message_type="note"), {})
    assert o.fields == ["reply"]


def test_conversation_missing_and_retry():
    o = ic.conversation_state(FakeIntercom([]))(call(conversation_id="1", state="closed"), {})
    assert o.fields == ["exists"]
    client = FakeIntercom([CONV], failures=[HttpError(500, "/x"), ConnectionResetError("reset")])
    o = ic.conversation_state(client, retries=2, sleep=lambda s: None)(call(conversation_id="1295", state="closed"), {})
    assert o.check == "match" and len(client.paths) == 3


def test_state():
    client = FakeIntercom([CONV])
    chk = ic.conversation_state(client, open=lambda c, r: False)
    o = chk(call(conversation_id="1295", state="closed", admin_assignee_id="991267", team_assignee_id=None,
                 tags=["refund"]), {})
    assert o.check == "match", o
    o = chk(call(conversation_id="1295", state="snoozed", tags=["refund", "vip"]), {})
    assert o.fields == ["state", "tags"]


def test_error_list_body_and_sdk_client():
    class Convs:
        def find(self, conversation_id):
            return {"type": "error.list", "errors": [{"code": "not_found", "message": "Resource Not Found"}]}

    class Client:
        conversations = Convs()

    assert ic.conversation_state(Client())(call(conversation_id="9", state="open"), {}).fields == ["exists"]

    class Convs2:
        def find(self, conversation_id):
            return copy.deepcopy(CONV)

    class Client2:
        conversations = Convs2()

    assert ic.conversation_state(Client2())(call(conversation_id="1295", state="closed"), {}).check == "match"


def test_unauthorized_is_error():
    client = FakeIntercom([CONV], failures=[HttpError(401, "/x", '{"type":"error.list"}')])
    o = ic.conversation_state(client, retries=3, sleep=lambda s: None)(call(conversation_id="1295", state="closed"), {})
    assert o.check == "error" and len(client.paths) == 1
