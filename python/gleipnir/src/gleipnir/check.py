"""Coverage of the agent-security-review checklist by the current setup.

Capabilities are derived from evidence in the chain (what the records actually contain),
not from configuration claims. Items the checklist marks with no capabilities are process
items: the SDK cannot evidence them and lists them as reminders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from gleipnir_verify import verify_records

# Capabilities the SDK provides to every user as tooling (not evidence in the chain).
TOOLING = {"offline_verifier", "export", "pack", "report"}


def load_checklist(path: str | Path | None = None) -> dict[str, Any]:
    if path:
        text = Path(path).read_text(encoding="utf-8")
    else:
        text = resources.files("gleipnir").joinpath("data/checklist.yaml").read_text("utf-8")
    return yaml.safe_load(text)


def capabilities_from_records(records: list[dict[str, Any]], anchor_options: dict[str, Any] | None = None
                              ) -> tuple[set[str], dict[str, str]]:
    """Return (active capabilities, evidence notes)."""
    caps: set[str] = set(TOOLING)
    why: dict[str, str] = {c: "provided by the SDK" for c in TOOLING}
    actions = [r for r in records if r.get("kind") == "action"]
    if not records:
        return caps, why

    report = verify_records(records, anchor_options=anchor_options or {})
    if not report.errors:
        caps |= {"signed_records", "hash_chain"}
        why["signed_records"] = why["hash_chain"] = "chain verifies"
    if report.summary.get("anchors_independent"):
        caps.add("external_anchor")
        why["external_anchor"] = f"{report.summary['anchors_independent']} segments anchored in a public log"

    def any_action(pred: Any) -> int:
        return sum(1 for a in actions if pred(a))

    checks = [
        ("action_record", lambda a: True, "actions recorded"),
        ("identity_binding", lambda a: bool(a.get("identity", {}).get("principal")), "actions carry identity"),
        ("scope_record", lambda a: bool(a.get("identity", {}).get("scope")), "actions carry scope"),
        ("model_version", lambda a: bool(a.get("model")), "actions carry model info"),
        ("config_version", lambda a: bool(a.get("versions")), "actions carry prompt/config versions"),
        ("outcome_check", lambda a: a.get("outcome", {}).get("check") in ("match", "mismatch"),
         "actions with outcome checks"),
        ("redaction", lambda a: bool(a.get("redaction")), "actions with redaction"),
        ("source_record", lambda a: bool(a.get("sources")), "actions with source records"),
        ("endpoint_record", lambda a: bool(a.get("calls")), "actions with outbound call records"),
    ]
    for cap, pred, label in checks:
        n = any_action(pred)
        if n:
            caps.add(cap)
            why[cap] = f"{n} of {len(actions)} {label}"
    configs = [r.get("config", {}) for r in records if r.get("kind") == "config"]
    if configs:
        latest = configs[-1]
        if latest.get("retention", {}).get("days"):
            caps.add("retention_policy")
            why["retention_policy"] = f"retention {latest['retention']['days']} days declared in the chain"
        buyer = [s for s in latest.get("sinks", []) if s.get("role") == "buyer"]
        if buyer:
            caps.add("buyer_copy")
            why["buyer_copy"] = "buyer copy: " + ", ".join(f"{s.get('type')} {s.get('target')}" for s in buyer)
    reviews = sum(1 for r in records if r.get("kind") == "review")
    if reviews:
        caps.add("review_record")
        why["review_record"] = f"{reviews} review records"
    return caps, why


@dataclass
class ItemResult:
    id: str
    group: str
    question: str
    status: str  # covered | partial | missing | process
    have: list[str] = field(default_factory=list)
    need: list[str] = field(default_factory=list)


def evaluate(checklist: dict[str, Any], caps: set[str]) -> list[ItemResult]:
    out = []
    for item in checklist["items"]:
        if item.get("deprecated"):
            continue
        wanted = list(item.get("capabilities", []))
        have = [c for c in wanted if c in caps]
        need = [c for c in wanted if c not in caps]
        if not wanted:
            status = "process"
        elif not need:
            status = "covered"
        elif have:
            status = "partial"
        else:
            status = "missing"
        out.append(ItemResult(item["id"], item["group"], item["question"], status, have, need))
    return out


HINTS = {
    "identity_binding": "pass identity={'principal': ..., 'credential_id': ...} in rec.context()",
    "scope_record": "add 'scope' to identity in rec.context()",
    "model_version": "pass model={'provider', 'name', 'version'} in rec.context()",
    "config_version": "pass versions={'prompt': ..., 'config': ...} in rec.context()",
    "outcome_check": "add verify_outcome= to tools that write to external systems",
    "redaction": "add redact= to tools that handle personal or card data",
    "external_anchor": "use anchor='rekor' (public Sigstore log) instead of the local test anchor",
    "review_record": "call rec.review(action_id, reviewer=..., decision=...) where your buyer's oversight rules apply",
    "buyer_copy": "add a sink with role='buyer' (S3ObjectLockSink, DirectorySink or WebhookSink)",
    "retention_policy": "pass retention_days= to the Recorder",
    "signed_records": "chain does not verify; run gleipnir-verify on an export",
    "hash_chain": "chain does not verify; run gleipnir-verify on an export",
    "action_record": "wrap tools with @rec.tool",
    "source_record": "pass sources=[...] to rec.record_action for retrieval-based actions",
    "endpoint_record": "pass calls=[...] (model endpoints, APIs) to rec.record_action",
}


def render_text(results: list[ItemResult], why: dict[str, str]) -> str:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    lines = [f"checklist coverage: {counts.get('covered', 0)} covered, {counts.get('partial', 0)} partial, "
             f"{counts.get('missing', 0)} missing, {counts.get('process', 0)} process items (not evidenced by "
             "the SDK)", ""]
    for r in results:
        mark = {"covered": "[x]", "partial": "[~]", "missing": "[ ]", "process": "[-]"}[r.status]
        lines.append(f"{mark} {r.id}  {r.question}")
        for c in r.need:
            lines.append(f"       missing {c}: {HINTS.get(c, '')}")
    lines.append("")
    lines.append("evidence found:")
    for c, w in sorted(why.items()):
        lines.append(f"  {c}: {w}")
    return "\n".join(lines)
