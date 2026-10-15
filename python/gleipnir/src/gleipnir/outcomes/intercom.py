"""Intercom read-back checks: a reply landed on a conversation, a conversation's state.

From the Intercom REST API reference:

* Retrieve a conversation: https://developers.intercom.com/docs/references/rest-api/api.intercom.io/conversations/retrieveconversation
  (``GET /conversations/{conversation_id}``; ``state`` one of ``open``, ``closed``, ``snoozed``;
  ``open``, ``read`` booleans; ``priority`` (``none``, ``low``, ``medium``, ``high``, ``urgent``;
  older API versions: ``priority`` / ``not_priority``); ``admin_assignee_id`` and
  ``team_assignee_id`` (``0`` or null when unassigned); ``tags: {type: "tag.list", tags: [{id,
  name}]}``; ``conversation_parts: {conversation_parts: [{id, part_type, body, author: {type, id}}]}``,
  the 500 most recent parts)
* Reply to a conversation: https://developers.intercom.com/docs/references/rest-api/api.intercom.io/conversations/replyconversation
  (``message_type`` ``comment`` or ``note``, ``type`` ``admin`` or ``user``, ``admin_id``, ``body``;
  the response is the conversation)

``client`` may be the official ``intercom`` Python client (``client.conversations.find(
conversation_id=...)``) or a callable ``path -> JSON`` such as
``json_get("https://api.intercom.io", headers={"Authorization": "Bearer ...",
"Intercom-Version": "2.11"})``.
"""

from __future__ import annotations

from typing import Any

from ..recorder import Call, Outcome
from ._core import (
    ABSENT,
    SKIP,
    Check,
    ConfigError,
    NotFound,
    Spec,
    check_fn,
    first_of,
    get_path,
    http_get,
    includes_all,
    norm_text,
    opt_arg,
    plain,
    resolve,
    resolve_id,
    resp,
    same_set,
    values_equal,
)

DOCS = "https://developers.intercom.com/docs/references/rest-api/api.intercom.io/conversations/retrieveconversation"
_CONV_ID = first_of(opt_arg("conversation_id"), resp("id"))


def get_conversation(client: Any, conversation_id: str) -> Any:
    svc = getattr(client, "conversations", None)
    if svc is not None and hasattr(svc, "find"):
        conv = svc.find(conversation_id=conversation_id)
    else:
        conv = http_get(client, f"/conversations/{conversation_id}")
    conv = plain(conv)
    if not conv:
        raise NotFound(f"conversation {conversation_id}")
    if get_path(conv, "type") == "error.list":
        errs = get_path(conv, "errors")
        codes = [get_path(e, "code") for e in errs] if isinstance(errs, list) else []
        if "not_found" in codes:
            raise NotFound(f"conversation {conversation_id}")
        raise ConfigError(f"Intercom error: {codes}")
    return conv


def _parts(conv: Any) -> list[Any]:
    parts = get_path(conv, "conversation_parts.conversation_parts")
    return list(parts) if isinstance(parts, list) else []


def _tag_names(conv: Any) -> list[str]:
    tags = get_path(conv, "tags.tags")
    if not isinstance(tags, list):
        return []
    return [str(get_path(t, "name")) for t in tags if get_path(t, "name") is not ABSENT]


def _assignee(v: Any) -> Any:
    return None if v in (0, "0", None, ABSENT) else v


def conversation_replied(
    client: Any,
    *,
    conversation_id: Spec = _CONV_ID,
    body: Spec = first_of(opt_arg("body"), opt_arg("reply"), opt_arg("message")),
    message_type: Spec = opt_arg("message_type"),
    admin_id: Spec = opt_arg("admin_id"),
    author_type: Spec = None,
    **retry: Any,
) -> Any:
    """Re-fetch the conversation and check a part with the reply text is there.

    A part matches when its ``body`` (HTML stripped) contains ``body``; when given,
    ``message_type`` must equal its ``part_type`` (``comment``/``note``), ``admin_id`` its
    ``author.id`` and ``author_type`` its ``author.type`` (``admin``, ``user``, ``bot``...).
    The newest matching part is recorded.
    """

    def read(call: Call, response: Any) -> Outcome:
        cid = resolve_id(conversation_id, call, response, "conversation id")
        want = norm_text(resolve(body, call, response))
        if not want:
            raise ConfigError("reply body to look for is empty")
        mtype, aid, atype = (resolve(s, call, response) for s in (message_type, admin_id, author_type))
        conv = get_conversation(client, cid)
        c = Check("intercom.conversation_replied")
        c.note("id", get_path(conv, "id"))
        found = None
        for part in reversed(_parts(conv)):
            if want not in norm_text(get_path(part, "body")):
                continue
            if mtype is not SKIP and not values_equal(mtype, get_path(part, "part_type")):
                continue
            if aid is not SKIP and not values_equal(aid, get_path(part, "author.id")):
                continue
            if atype is not SKIP and not values_equal(atype, get_path(part, "author.type")):
                continue
            found = part
            break
        if found is None:
            c.fail("reply", {"present": False, "parts_seen": len(_parts(conv))})
        else:
            c.require("reply", True, {"present": True, "part_id": get_path(found, "id"),
                                      "part_type": get_path(found, "part_type"),
                                      "author": {"type": get_path(found, "author.type"),
                                                 "id": get_path(found, "author.id")}})
        return c.outcome()

    return check_fn("intercom.conversation_replied", read, retry)


def conversation_state(
    client: Any,
    *,
    conversation_id: Spec = _CONV_ID,
    state: Spec = opt_arg("state"),
    open: Spec = None,  # noqa: A002 - Intercom's field name
    read: Spec = None,
    priority: Spec = opt_arg("priority"),
    admin_assignee_id: Spec = opt_arg("admin_assignee_id"),
    team_assignee_id: Spec = opt_arg("team_assignee_id"),
    tags: Spec = opt_arg("tags"),
    tags_exact: bool = False,
    **retry: Any,
) -> Any:
    """Re-fetch the conversation and check state, priority, assignees and tags.

    Unassigned (``0`` or null) assignee ids compare equal to ``None``. ``tags`` are tag names;
    every expected tag must be applied (``tags_exact=True``: the same set).
    """

    def read_(call: Call, response: Any) -> Outcome:
        cid = resolve_id(conversation_id, call, response, "conversation id")
        conv = get_conversation(client, cid)
        c = Check("intercom.conversation_state")
        c.note("id", get_path(conv, "id"))
        c.field("state", resolve(state, call, response), get_path(conv, "state"))
        c.field("open", resolve(open, call, response), get_path(conv, "open"))
        c.field("read", resolve(read, call, response), get_path(conv, "read"))
        c.field("priority", resolve(priority, call, response), get_path(conv, "priority"))
        for name, spec in (("admin_assignee_id", admin_assignee_id), ("team_assignee_id", team_assignee_id)):
            exp = resolve(spec, call, response)
            c.field(name, exp if exp is SKIP else _assignee(exp), _assignee(get_path(conv, name)))
        c.field("tags", resolve(tags, call, response), _tag_names(conv), same_set if tags_exact else includes_all)
        return c.outcome()

    return check_fn("intercom.conversation_state", read_, retry)


__all__ = ["DOCS", "conversation_replied", "conversation_state", "get_conversation"]
