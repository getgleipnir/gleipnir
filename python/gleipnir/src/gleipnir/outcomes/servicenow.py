"""ServiceNow read-back check: a table record holds the fields the agent wrote (Table API).

From the ServiceNow Table API reference:

* Table API: https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html
  (``GET /api/now/table/{tableName}/{sys_id}?sysparm_fields=a,b&sysparm_display_value=false``;
  the body is ``{"result": {...}}``; values are strings (``"priority": "3"``, ``"active": "true"``);
  reference fields are ``{"link": ..., "value": sys_id}`` unless ``sysparm_exclude_reference_link``;
  404 when the record is not found)

``client`` is a callable ``path -> JSON``, e.g. ``json_get("https://acme.service-now.com",
headers={"Authorization": "Basic ..."})``, or a ``pysnow``/other client wrapped in one.

Comparisons use raw database values by default (``display_value=False``): ``state`` is
``"6"``, not ``"Resolved"``. Pass ``display_value=True`` to compare display values instead.
Reference fields compare by ``sys_id``.
"""

from __future__ import annotations

from collections.abc import Mapping
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
    opt_arg,
    plain,
    resolve_fields,
    resolve_id,
    resp,
)

DOCS = "https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html"


def get_record(client: Any, table: str, sys_id: str, field_names: list[str], display_value: bool) -> Any:
    params = [f"sysparm_display_value={'true' if display_value else 'false'}",
              "sysparm_exclude_reference_link=true"]
    if field_names:
        params.append("sysparm_fields=" + ",".join(sorted({"sys_id", *(f.split(".")[0] for f in field_names)})))
    body = plain(http_get(client, f"/api/now/table/{quote(table, safe='')}/{quote(sys_id, safe='')}?"
                          + "&".join(params)))
    rec = get_path(body, "result")
    if rec is ABSENT or not rec:
        raise NotFound(f"{table}/{sys_id}")
    return plain(rec)


def _value(rec: Mapping[str, Any], name: str) -> Any:
    v = get_path(rec, name)
    if isinstance(v, Mapping) and "value" in v and set(v) <= {"value", "link", "display_value"}:
        return v["value"]
    return v


def record_matches(
    client: Any,
    table: str,
    *,
    fields: Fields,
    sys_id: Spec = first_of(opt_arg("sys_id"), resp("result.sys_id"), resp("sys_id")),
    display_value: bool = False,
    **retry: Any,
) -> Any:
    """Re-fetch ``table`` (e.g. ``"incident"``) record ``sys_id`` and compare ``fields``.

    ``sys_id`` defaults to the ``sys_id`` argument or the create/update response's
    ``result.sys_id``. ``2 == "2"`` and ``True == "true"`` compare equal (the API returns strings).
    """
    if fields is None:
        raise TypeError("record_matches needs fields=")
    if not table or not table.replace("_", "").isalnum():
        raise ValueError(f"not a table name: {table!r}")

    def read(call: Call, response: Any) -> Outcome:
        sid = resolve_id(sys_id, call, response, "sys_id")
        expected = resolve_fields(fields, call, response)
        rec = get_record(client, table, sid, list(expected), display_value)
        c = Check("servicenow.record_matches")
        c.note("sys_id", get_path(rec, "sys_id"))
        for name, value in expected.items():
            c.field(name, value, _value(rec, name))
        return c.outcome()

    return check_fn("servicenow.record_matches", read, retry)


__all__ = ["DOCS", "get_record", "record_matches"]
