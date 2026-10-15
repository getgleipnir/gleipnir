"""Map action records to OCSF API Activity events (class 6003) for SIEMs.

OCSF lets Splunk, Sentinel, Security Lake and others ingest agent actions without custom
parsing. The full signed record stays referenced by ``metadata.uid`` and ``unmapped.gleipnir``.
"""

from __future__ import annotations

from typing import Any

from gleipnir_verify.canon import record_hash
from gleipnir_verify.verifier import parse_time

OCSF_VERSION = "1.3.0"
_ACTIVITY = {"create": 1, "read": 2, "update": 3, "delete": 4}


def _activity(tool: str) -> tuple[int, str]:
    name = tool.lower()
    for verb, ids in (("create", ("create", "issue", "add", "open", "post", "send")),
                      ("read", ("get", "read", "list", "search", "fetch", "lookup")),
                      ("update", ("update", "set", "edit", "change", "patch", "close")),
                      ("delete", ("delete", "remove", "cancel", "revoke"))):
        if any(name.startswith(i) for i in ids):
            return _ACTIVITY[verb], verb.capitalize()
    return 99, "Other"


def to_ocsf(record: dict[str, Any]) -> dict[str, Any] | None:
    """OCSF API Activity event for an action record; None for other record kinds."""
    if record.get("kind") != "action":
        return None
    tool = record.get("tool", {})
    activity_id, activity_name = _activity(str(tool.get("name", "")))
    ok = record.get("response", {}).get("status") == "ok"
    identity = record.get("identity", {})
    event: dict[str, Any] = {
        "class_uid": 6003, "class_name": "API Activity", "category_uid": 6, "category_name": "Application Activity",
        "activity_id": activity_id, "activity_name": activity_name, "type_uid": 6003 * 100 + activity_id,
        "time": int(parse_time(record["t"]["start"]).timestamp() * 1000),
        "severity_id": 1 if ok else 3, "status_id": 1 if ok else 2, "status": "Success" if ok else "Failure",
        "api": {"operation": tool.get("name"), "service": {"name": tool.get("system")}},
        "actor": {"user": {"name": identity.get("principal") or record.get("agent", {}).get("id"),
                           "type": "Service"},
                  "app_name": f"{record.get('agent', {}).get('id')} {record.get('agent', {}).get('version')}"},
        "metadata": {"version": OCSF_VERSION, "uid": record.get("id"), "log_name": record.get("chain"),
                     "product": {"name": "Gleipnir", "vendor_name": "Gleipnir"},
                     "original_time": record.get("time")},
        "unmapped": {"gleipnir": {"seq": record.get("seq"), "record_hash": record_hash(record),
                                  "outcome": record.get("outcome", {}).get("check", "not_checked"),
                                  "scope": identity.get("scope")}},
    }
    if not ok:
        event["status_detail"] = record.get("response", {}).get("error")
    if record.get("context", {}).get("trace_id"):
        event["metadata"]["correlation_uid"] = record["context"]["trace_id"]
    return event
