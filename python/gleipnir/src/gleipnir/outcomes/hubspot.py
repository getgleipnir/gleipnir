"""HubSpot read-back check: a CRM object holds the properties the agent wrote.

From the HubSpot CRM API reference:

* Read an object: https://developers.hubspot.com/docs/api-reference/crm-objects-v3/basic/get-crm-v3-objects-objectType-objectId
  (``GET /crm/v3/objects/{objectType}/{objectId}?properties=a,b``; the body is
  ``{id, properties: {...}, createdAt, updatedAt, archived}``; a requested property with no value
  is left out of ``properties``; property values are strings, e.g. ``"amount": "1500.00"``)

``client`` may be ``hubspot.HubSpot`` (``client.crm.objects.basic_api.get_by_id(object_type,
object_id, properties=[...])``; its ``ApiException`` with ``status == 404`` counts as not found)
or a callable ``path -> JSON`` such as ``json_get("https://api.hubapi.com",
headers={"Authorization": "Bearer ..."})``.

Values compare with HubSpot's string encoding in mind: ``1500`` equals ``"1500.00"``, ``True``
equals ``"true"``, and ``None`` equals an absent or empty property.
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
    opt_arg,
    plain,
    resolve_fields,
    resolve_id,
    resp,
)

DOCS = "https://developers.hubspot.com/docs/api-reference/crm-objects-v3/basic/get-crm-v3-objects-objectType-objectId"


def get_object(client: Any, object_type: str, object_id: str, properties: list[str]) -> Any:
    crm = getattr(client, "crm", None)
    if crm is not None and not callable(client):
        obj = crm.objects.basic_api.get_by_id(object_type, object_id, properties=properties or None)
    else:
        q = ("?properties=" + ",".join(quote(p, safe="") for p in sorted(properties))) if properties else ""
        obj = http_get(client, f"/crm/v3/objects/{quote(object_type, safe='')}/{quote(object_id, safe='')}{q}")
    obj = plain(obj)
    if not obj:
        raise NotFound(f"{object_type}/{object_id}")
    return obj


def object_matches(
    client: Any,
    object_type: str,
    *,
    properties: Fields,
    object_id: Spec = first_of(opt_arg("object_id"), resp("id")),
    **retry: Any,
) -> Any:
    """Re-fetch a CRM object (``"contacts"``, ``"deals"``, ``"tickets"``, ``"0-3"``, ``"p_custom"``...)
    and compare ``properties`` (names are HubSpot internal property names, e.g. ``dealstage``).

    An archived object is a mismatch on ``exists``.
    """
    if properties is None:
        raise TypeError("object_matches needs properties=")
    if not object_type:
        raise ValueError("object_type is required")

    def read(call: Call, response: Any) -> Outcome:
        oid = resolve_id(object_id, call, response, "object id")
        expected = resolve_fields(properties, call, response)
        obj = get_object(client, object_type, oid, list(expected))
        if get_path(obj, "archived") is True:
            raise NotFound(f"{object_type}/{oid} is archived")
        props = get_path(obj, "properties")
        props = {} if props is ABSENT or props is None else plain(props)
        c = Check("hubspot.object_matches")
        c.note("id", get_path(obj, "id"))
        for name, value in expected.items():
            c.field(name, value, props.get(name, ABSENT) if hasattr(props, "get") else ABSENT)
        return c.outcome()

    return check_fn("hubspot.object_matches", read, retry)


__all__ = ["DOCS", "get_object", "object_matches"]
