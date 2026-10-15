"""Zendesk Support read-back checks: ticket updated, ticket created.

Field names are from the Zendesk Support API reference:

* Tickets: https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/
  (``GET /api/v2/tickets/{ticket_id}`` returns ``{"ticket": {...}}``; ``status`` one of
  ``new``, ``open``, ``pending``, ``hold``, ``solved``, ``closed``; ``priority`` one of ``urgent``,
  ``high``, ``normal``, ``low``; ``assignee_id``, ``group_id``, ``requester_id``, ``tags``,
  ``subject``, ``type``, ``custom_fields`` as ``[{"id", "value"}]``)
* Ticket comments: https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_comments/
  (``GET /api/v2/tickets/{ticket_id}/comments?sort_order=desc`` returns ``{"comments": [...]}``,
  each with ``id``, ``body``, ``html_body``, ``plain_body``, ``public``, ``author_id``)

``client`` may be a Zenpy client (``zenpy.tickets(id=...)``, ``zenpy.tickets.comments(ticket=...)``)
or a callable ``path -> JSON``, e.g. ``json_get("https://acme.zendesk.com", headers=...)``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..recorder import Call, Outcome
from ._core import (
    ABSENT,
    SKIP,
    Check,
    ConfigError,
    Fields,
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
    resolve_fields,
    resolve_id,
    resp,
    same_set,
    values_equal,
)

DOCS = "https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/"
_TICKET_ID = first_of(opt_arg("ticket_id"), resp("ticket.id"), resp("id"))


def _is_zenpy(client: Any) -> bool:
    return not callable(client) and hasattr(client, "tickets")


def get_ticket(client: Any, ticket_id: str) -> Any:
    if _is_zenpy(client):
        t = plain(client.tickets(id=int(ticket_id) if ticket_id.isdigit() else ticket_id))
    else:
        body = plain(http_get(client, f"/api/v2/tickets/{ticket_id}.json"))
        t = get_path(body, "ticket")
        t = None if t is ABSENT else t
    if not t:
        raise NotFound(f"ticket {ticket_id}")
    return t


def get_comments(client: Any, ticket_id: str) -> list[Any]:
    """Newest comments first (one page: up to 100)."""
    if _is_zenpy(client):
        items = [plain(c) for c in client.tickets.comments(ticket=int(ticket_id) if ticket_id.isdigit()
                                                           else ticket_id)]
        return list(reversed(items))  # Zenpy pages ascending
    body = plain(http_get(client, f"/api/v2/tickets/{ticket_id}/comments.json?sort_order=desc"))
    items = get_path(body, "comments")
    if items is ABSENT or not isinstance(items, list):
        raise ConfigError("unexpected comments payload (no 'comments' list)")
    return [plain(c) for c in items]


def _custom_fields(ticket: Any) -> dict[str, Any]:
    out = {}
    cf = get_path(ticket, "custom_fields")
    if isinstance(cf, list):
        for f in cf:
            fid = get_path(f, "id")
            if fid is not ABSENT:
                out[str(fid)] = get_path(f, "value")
    return out


def _compare_ticket(c: Check, t: Any, call: Call, response: Any, *, status: Spec, priority: Spec,
                    assignee_id: Spec, group_id: Spec, tags: Spec, tags_exact: bool,
                    fields: Fields, custom_fields: Mapping[Any, Any] | None) -> None:
    c.note("id", get_path(t, "id"))
    c.field("status", resolve(status, call, response), get_path(t, "status"))
    c.field("priority", resolve(priority, call, response), get_path(t, "priority"))
    c.field("assignee_id", resolve(assignee_id, call, response), get_path(t, "assignee_id"))
    c.field("group_id", resolve(group_id, call, response), get_path(t, "group_id"))
    c.field("tags", resolve(tags, call, response), get_path(t, "tags"), same_set if tags_exact else includes_all)
    for name, value in resolve_fields(fields, call, response).items():
        c.field(name, value, get_path(t, name))
    if custom_fields:
        have = _custom_fields(t)
        for fid, value in custom_fields.items():
            v = value(call, response) if callable(value) else value
            if v is not SKIP:
                c.field(f"custom_fields.{fid}", v, have.get(str(fid), ABSENT))


def _check_comment(c: Check, client: Any, tid: str, body: Any, public: Any, author_id: Any) -> None:
    want = norm_text(body)
    if not want:
        raise ConfigError("comment body to look for is empty")
    found = None
    for cm in get_comments(client, tid):
        text = " ".join(norm_text(get_path(cm, k)) for k in ("plain_body", "body", "html_body"))
        if want not in text:
            continue
        if public is not SKIP and not values_equal(public, get_path(cm, "public")):
            continue
        if author_id is not SKIP and not values_equal(author_id, get_path(cm, "author_id")):
            continue
        found = cm
        break
    if found is None:
        c.fail("comment", {"present": False})
    else:
        c.require("comment", True, {"present": True, "id": get_path(found, "id"),
                                    "public": get_path(found, "public"), "author_id": get_path(found, "author_id")})


def ticket_updated(
    client: Any,
    *,
    ticket_id: Spec = _TICKET_ID,
    status: Spec = opt_arg("status"),
    priority: Spec = opt_arg("priority"),
    assignee_id: Spec = opt_arg("assignee_id"),
    group_id: Spec = opt_arg("group_id"),
    tags: Spec = opt_arg("tags"),
    tags_exact: bool = False,
    comment: Spec = None,
    comment_public: Spec = None,
    comment_author_id: Spec = None,
    fields: Fields = None,
    custom_fields: Mapping[Any, Any] | None = None,
    **retry: Any,
) -> Any:
    """Re-fetch the ticket and check the fields the agent changed.

    Each of ``status``, ``priority``, ``assignee_id``, ``group_id`` and ``tags`` defaults to the
    tool argument of the same name when the call has it. ``tags`` checks that every expected tag
    is on the ticket (``tags_exact=True``: the same set). ``comment`` (e.g. ``"reply"`` for the
    tool's ``reply`` argument) checks that a comment containing that text is among the latest
    comments, optionally with ``comment_public`` / ``comment_author_id``. ``custom_fields`` maps
    a custom field id to its expected value.
    """

    def read(call: Call, response: Any) -> Outcome:
        tid = resolve_id(ticket_id, call, response, "ticket id")
        t = get_ticket(client, tid)
        c = Check("zendesk.ticket_updated")
        _compare_ticket(c, t, call, response, status=status, priority=priority, assignee_id=assignee_id,
                        group_id=group_id, tags=tags, tags_exact=tags_exact, fields=fields,
                        custom_fields=custom_fields)
        body = resolve(comment, call, response)
        if body is not SKIP:
            _check_comment(c, client, tid, body, resolve(comment_public, call, response),
                           resolve(comment_author_id, call, response))
        return c.outcome()

    return check_fn("zendesk.ticket_updated", read, retry)


def ticket_created(
    client: Any,
    *,
    ticket_id: Spec = first_of(resp("ticket.id"), resp("id")),
    subject: Spec = opt_arg("subject"),
    requester_id: Spec = opt_arg("requester_id"),
    status: Spec = opt_arg("status"),
    priority: Spec = opt_arg("priority"),
    assignee_id: Spec = opt_arg("assignee_id"),
    group_id: Spec = opt_arg("group_id"),
    type: Spec = opt_arg("type"),  # noqa: A002 - Zendesk's field name
    tags: Spec = opt_arg("tags"),
    tags_exact: bool = False,
    comment: Spec = first_of(opt_arg("comment"), opt_arg("description"), opt_arg("body")),
    fields: Fields = None,
    custom_fields: Mapping[Any, Any] | None = None,
    **retry: Any,
) -> Any:
    """Re-fetch a ticket the agent created (id from the create response) and check its fields.

    The first comment is the description; ``comment`` (default: the ``comment``, ``description``
    or ``body`` argument) must appear in the ticket's ``description`` or a comment.
    """

    def read(call: Call, response: Any) -> Outcome:
        tid = resolve_id(ticket_id, call, response, "ticket id")
        t = get_ticket(client, tid)
        c = Check("zendesk.ticket_created")
        c.field("subject", resolve(subject, call, response), get_path(t, "subject"))
        c.field("requester_id", resolve(requester_id, call, response), get_path(t, "requester_id"))
        c.field("type", resolve(type, call, response), get_path(t, "type"))
        _compare_ticket(c, t, call, response, status=status, priority=priority, assignee_id=assignee_id,
                        group_id=group_id, tags=tags, tags_exact=tags_exact, fields=fields,
                        custom_fields=custom_fields)
        body = resolve(comment, call, response)
        if isinstance(body, Mapping):  # Zendesk create payload: {"comment": {"body": ...}}
            body = body.get("body") or body.get("html_body") or SKIP
        if body is not SKIP:
            if norm_text(body) and norm_text(body) in norm_text(get_path(t, "description")):
                c.require("comment", True, {"present": True, "in": "description"})
            else:
                _check_comment(c, client, tid, body, SKIP, SKIP)
        return c.outcome()

    return check_fn("zendesk.ticket_created", read, retry)


__all__ = ["DOCS", "get_comments", "get_ticket", "ticket_created", "ticket_updated"]
