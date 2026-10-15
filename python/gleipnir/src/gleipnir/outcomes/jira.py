"""Jira Cloud read-back check: an issue holds the fields the agent set.

From the Jira Cloud platform REST API v3 (OpenAPI: https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json):

* Get issue: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-issueidorkey-get
  (``GET /rest/api/3/issue/{issueIdOrKey}?fields=...``; the body (``IssueBean``) is
  ``{id, key, self, fields: {...}}``; ``fields.status.name`` and ``fields.status.statusCategory.key``
  (``new``, ``indeterminate``, ``done``), ``fields.assignee.accountId`` (null when unassigned),
  ``fields.priority.name``, ``fields.labels`` (strings), ``fields.summary``, ``fields.resolution.name``;
  404 "if the issue is not found or the user does not have permission to view it")

``client`` may be a ``jira.JIRA`` (pycontribs) instance (``client.issue(key)``; ``JIRAError``
carries ``status_code``) or a callable ``path -> JSON`` such as
``json_get("https://acme.atlassian.net", headers={"Authorization": "Basic ..."})``.

``fields`` keys are paths inside ``fields`` (``"customfield_10016"``, ``"components.0.name"``).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ..recorder import Call, Outcome
from ._core import (
    ABSENT,
    Check,
    Fields,
    NotFound,
    Spec,
    check_fn,
    first_of,
    get_path,
    http_get,
    includes_all,
    opt_arg,
    plain,
    resolve,
    resolve_fields,
    resolve_id,
    resp,
    same_set,
)

DOCS = "https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-issueidorkey-get"


def get_issue(client: Any, key: str, field_names: list[str]) -> Any:
    if not callable(client) and hasattr(client, "issue"):
        issue = client.issue(key, fields=",".join(field_names) if field_names else None)
    else:
        q = ("?fields=" + ",".join(sorted(field_names))) if field_names else ""
        issue = http_get(client, f"/rest/api/3/issue/{quote(key, safe='')}{q}")
    issue = plain(issue)
    if not issue or get_path(issue, "fields") is ABSENT:
        raise NotFound(f"issue {key}")
    return issue


def _ci(a: Any, b: Any) -> bool:
    return isinstance(b, str) and str(a).casefold() == b.casefold()


def issue_matches(
    client: Any,
    *,
    issue_key: Spec = first_of(opt_arg("issue_key"), opt_arg("issue_id"), resp("key"), resp("id")),
    status: Spec = opt_arg("status"),
    status_category: Spec = None,
    assignee_account_id: Spec = opt_arg("assignee_account_id"),
    priority: Spec = opt_arg("priority"),
    labels: Spec = opt_arg("labels"),
    labels_exact: bool = False,
    summary: Spec = opt_arg("summary"),
    resolution: Spec = None,
    fields: Fields = None,
    **retry: Any,
) -> Any:
    """Re-fetch the issue and compare status (name, case-insensitive), status category, assignee
    accountId (``None`` = unassigned), priority name, labels (expected ones present;
    ``labels_exact=True`` for the same set), summary, resolution name and any extra ``fields``.
    """

    def read(call: Call, response: Any) -> Outcome:
        key = resolve_id(issue_key, call, response, "issue key")
        expected_extra = resolve_fields(fields, call, response)
        wanted = {"status", "assignee", "priority", "labels", "summary", "resolution"}
        wanted |= {k.split(".")[0] for k in expected_extra}
        issue = get_issue(client, key, sorted(wanted))
        f = get_path(issue, "fields")
        c = Check("jira.issue_matches")
        c.note("key", get_path(issue, "key"))
        c.field("status", resolve(status, call, response), get_path(f, "status.name"), _ci)
        c.field("status_category", resolve(status_category, call, response),
                get_path(f, "status.statusCategory.key"), _ci)
        assignee = get_path(f, "assignee")
        c.field("assignee_account_id", resolve(assignee_account_id, call, response),
                None if assignee in (None, ABSENT) else get_path(assignee, "accountId"))
        c.field("priority", resolve(priority, call, response), get_path(f, "priority.name"), _ci)
        c.field("labels", resolve(labels, call, response), get_path(f, "labels"),
                same_set if labels_exact else includes_all)
        c.field("summary", resolve(summary, call, response), get_path(f, "summary"))
        res = get_path(f, "resolution")
        c.field("resolution", resolve(resolution, call, response),
                None if res in (None, ABSENT) else get_path(res, "name"))
        for name, value in expected_extra.items():
            c.field(name, value, get_path(f, name))
        return c.outcome()

    return check_fn("jira.issue_matches", read, retry)


__all__ = ["DOCS", "get_issue", "issue_matches"]
