"""Salesforce read-back check: an sObject record holds the fields the agent wrote.

From the Salesforce REST API Developer Guide:

* Retrieve a record: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_retrieve_get.htm
  (``GET /services/data/vXX.X/sobjects/{sObject}/{id}?fields=...``; the body holds the record's
  fields by API name, plus ``attributes: {type, url}``)
* Status codes and errors: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/errorcodes.htm
  (404 with ``errorCode: NOT_FOUND`` when the record does not exist or is not visible)

``client`` may be a ``simple_salesforce.Salesforce`` instance (``sf.Case.get(id)``; its
``SalesforceResourceNotFound`` counts as not found), or a callable ``path -> JSON`` such as
``json_get(instance_url, headers={"Authorization": "Bearer ..."})`` together with
``api_version``.

Field names are API names (``Status``, ``OwnerId``, ``Amount__c``) and are matched case-
insensitively, as Salesforce does. Currency fields come back as JSON numbers in major units
(``1500.0``); compare them as numbers or decimal strings, not cents.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..recorder import Call, Outcome
from ._core import (
    ABSENT,
    Check,
    ConfigError,
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

DOCS = "https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_retrieve_get.htm"


def _field(rec: Mapping[str, Any], name: str) -> Any:
    head, _, rest = name.partition(".")
    if head in rec:
        v = rec[head]
    else:
        low = head.lower()
        key = next((k for k in rec if isinstance(k, str) and k.lower() == low), None)
        if key is None:
            return ABSENT
        v = rec[key]
    if not rest:
        return v
    v = plain(v)
    return _field(v, rest) if isinstance(v, Mapping) else ABSENT


def get_record(client: Any, sobject: str, record_id: str, field_names: list[str], api_version: str) -> Any:
    if not callable(client) and hasattr(client, "sf_instance"):  # simple-salesforce
        rec = getattr(client, sobject).get(record_id)
    else:
        q = "?fields=" + ",".join(sorted({f.split(".")[0] for f in field_names})) if field_names else ""
        rec = http_get(client, f"/services/data/v{api_version.lstrip('v')}/sobjects/{sobject}/{record_id}{q}")
    rec = plain(rec)
    if isinstance(rec, list):  # an error array on a callable that doesn't raise
        codes = [get_path(e, "errorCode") for e in rec]
        if "NOT_FOUND" in codes:
            raise NotFound(f"{sobject}/{record_id}")
        raise ConfigError(f"Salesforce error: {rec[:3]}")
    if not isinstance(rec, Mapping) or not rec:
        raise NotFound(f"{sobject}/{record_id}")
    return rec


def record_matches(
    client: Any,
    sobject: str,
    *,
    fields: Fields,
    record_id: Spec = first_of(opt_arg("record_id"), resp("id"), resp("Id")),
    api_version: str = "62.0",
    **retry: Any,
) -> Any:
    """Re-fetch ``sobject`` (e.g. ``"Case"``) by id and compare ``fields``.

    ``record_id`` defaults to the ``record_id`` argument or the create response's ``id``
    (simple-salesforce's ``sf.Case.create`` returns ``{"id": ..., "success": true}``). The record's
    ``attributes.type`` must be ``sobject``; a deleted record (``IsDeleted``) is not found.
    """
    if fields is None:
        raise TypeError("record_matches needs fields=")
    if not sobject or not sobject.replace("_", "").isalnum():
        raise ValueError(f"not an sObject API name: {sobject!r}")

    def read(call: Call, response: Any) -> Outcome:
        rid = resolve_id(record_id, call, response, "record id")
        expected = resolve_fields(fields, call, response)
        rec = get_record(client, sobject, rid, list(expected), api_version)
        if _field(rec, "IsDeleted") is True:
            raise NotFound(f"{sobject}/{rid} is deleted")
        c = Check("salesforce.record_matches")
        c.note("Id", _field(rec, "Id"))
        typ = get_path(rec, "attributes.type")
        if typ is not ABSENT:
            c.field("sobject", sobject, typ, lambda a, b: str(a).lower() == str(b).lower())
        for name, value in expected.items():
            c.field(name, value, _field(rec, name))
        return c.outcome()

    return check_fn("salesforce.record_matches", read, retry)


__all__ = ["DOCS", "get_record", "record_matches"]
