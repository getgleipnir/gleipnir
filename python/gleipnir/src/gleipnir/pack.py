"""Security Review Pack: a human-readable summary plus the verifiable bundle.

The pack is what a vendor hands to a buyer's security, risk or audit team for a period:

- summary.html: actions, systems touched, identities and scopes used, failures, outcome
  mismatches, reviews, models and versions, anchoring, verification result, checklist coverage
- actions.csv: one row per action with external object ids, for reconciliation against
  the buyer's own systems
- bundle.zip and VERIFY.md: the records, verifiable offline with gleipnir-verify

HTML prints cleanly to PDF from any browser.
"""

from __future__ import annotations

import csv
import html
import io
import json
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from gleipnir_verify.canon import record_hash
from gleipnir_verify.verifier import parse_time, verify_bundle

from . import __version__
from .check import capabilities_from_records, evaluate, load_checklist
from .export import VERIFY_README, export_bundle
from .util import iso, utcnow


def _in_range(rec: dict[str, Any], since: datetime | None, until: datetime | None) -> bool:
    t = parse_time(rec["time"])
    return (since is None or t >= since) and (until is None or t <= until)


def _external_ids(value: Any, prefix: str = "") -> list[str]:
    """Collect id-like fields (``id``, ``*_id``, ``*Id``) from a response body."""
    out: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            key = f"{prefix}{k}"
            if isinstance(v, (str, int)) and (k == "id" or k.endswith("_id") or k.endswith("Id")):
                out.append(f"{key}={v}")
            elif isinstance(v, (dict, list)):
                out.extend(_external_ids(v, key + "."))
    elif isinstance(value, list):
        for i, v in enumerate(value[:20]):
            out.extend(_external_ids(v, f"{prefix}{i}."))
    return out


def summarize(records: list[dict[str, Any]], since: datetime | None, until: datetime | None) -> dict[str, Any]:
    actions = [r for r in records if r.get("kind") == "action" and _in_range(r, since, until)]
    by_tool = Counter((a["tool"]["system"], a["tool"]["name"]) for a in actions)
    status = Counter(a["response"]["status"] for a in actions)
    outcomes = Counter(a.get("outcome", {}).get("check", "not_checked") for a in actions)
    identities = Counter(
        (a.get("identity", {}).get("principal", "(not recorded)"), a.get("identity", {}).get("scope", ""))
        for a in actions)
    models = Counter(json.dumps(a.get("model", {}), sort_keys=True) for a in actions if a.get("model"))
    versions = Counter(json.dumps(a.get("versions", {}), sort_keys=True) for a in actions if a.get("versions"))
    agents = Counter(f"{a['agent']['id']} {a['agent']['version']}" for a in actions)
    reviews = [r for r in records if r.get("kind") == "review" and _in_range(r, since, until)]
    problems = [a for a in actions if a["response"]["status"] != "ok"
                or a.get("outcome", {}).get("check") in ("mismatch", "error")]
    segs = {r["seq"]: r for r in records if r.get("kind") == "segment"}
    delays = []
    for r in records:
        if r.get("kind") == "anchor" and r["anchor"]["segment_seq"] in segs:
            closed = parse_time(segs[r["anchor"]["segment_seq"]]["segment"]["closed_at"])
            delays.append((parse_time(r["time"]) - closed).total_seconds())
    return {
        "actions": actions, "by_tool": by_tool, "status": status, "outcomes": outcomes, "identities": identities,
        "models": models, "versions": versions, "agents": agents, "reviews": reviews, "problems": problems,
        "anchor_delay_max_s": max(delays) if delays else None,
    }


def actions_csv(actions: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["action_id", "seq", "start", "end", "agent", "system", "tool", "status", "outcome",
                "principal", "scope", "on_behalf_of", "external_ids", "record_hash"])
    for a in actions:
        w.writerow([
            a["id"], a["seq"], a["t"]["start"], a["t"]["end"], f"{a['agent']['id']} {a['agent']['version']}",
            a["tool"]["system"], a["tool"]["name"], a["response"]["status"],
            a.get("outcome", {}).get("check", "not_checked"), a.get("identity", {}).get("principal", ""),
            a.get("identity", {}).get("scope", ""), a.get("context", {}).get("on_behalf_of", ""),
            " ".join(_external_ids(a["response"].get("body"))), record_hash(a),
        ])
    return buf.getvalue()


_CSS = """
:root{--fg:#1b1f24;--muted:#5b6470;--line:#d8dde3;--ok:#1a7f37;--bad:#b42318;--warn:#9a6700;--bg:#fff}
@media (prefers-color-scheme:dark){:root{--fg:#e6e8eb;--muted:#9aa4af;--line:#2d333b;--ok:#3fb950;
--bad:#f85149;--warn:#d29922;--bg:#0d1117}}
body{font:15px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:var(--fg);background:var(--bg);
max-width:980px;margin:32px auto;padding:0 16px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px;border-bottom:1px solid var(--line);
padding-bottom:4px}.muted{color:var(--muted)}table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600}td.n{text-align:right;font-variant-numeric:tabular-nums}code{font-size:13px;
word-break:break-all}.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}
.warn{color:var(--warn)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{border:1px solid var(--line);border-radius:8px;padding:12px}.card b{display:block;font-size:22px}
@media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _table(headers: list[str], rows: list[list[Any]], numeric: set[int] | None = None) -> str:
    numeric = numeric or set()
    h = "".join(f"<th>{html.escape(x)}</th>" for x in headers)
    body = "".join(
        "<tr>" + "".join(f"<td{' class=n' if i in numeric else ''}>{html.escape(str(c))}</td>"
                         for i, c in enumerate(row)) + "</tr>" for row in rows)
    return f"<table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>"


def render_html(s: dict[str, Any], *, verify: dict[str, Any], coverage: list[Any], period: str, key: str,
                chain: str, head: str, bundle_name: str) -> str:
    e = html.escape
    a = s["actions"]
    v_ok = verify["result"] == "VALID"
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
             f"<meta name=viewport content='width=device-width,initial-scale=1'>"
             f"<title>Security Review Pack</title><style>{_CSS}</style></head><body>"]
    parts.append("<h1>Security Review Pack</h1>")
    parts.append(f"<p class=muted>Agent action records for {e(period)}. Generated {e(iso(utcnow()))} by "
                 f"gleipnir-sdk {e(__version__)}.</p>")
    parts.append("<div class=grid>")
    for label, value in [("Actions", len(a)), ("Failed", s["status"].get("error", 0)),
                         ("Outcome mismatches", s["outcomes"].get("mismatch", 0)),
                         ("Outcome checked", s["outcomes"].get("match", 0) + s["outcomes"].get("mismatch", 0)),
                         ("Human reviews", len(s["reviews"]))]:
        parts.append(f"<div class=card><b>{value}</b><span class=muted>{e(label)}</span></div>")
    parts.append("</div>")

    parts.append("<h2>Verification</h2>")
    parts.append(f"<p>Result: <span class={'ok' if v_ok else 'bad'}>{e(verify['result'])}</span>. "
                 f"Signing key <code>{e(key)}</code>, chain <code>{e(chain)}</code>.</p>")
    sm = verify.get("summary", {})
    parts.append(f"<p>{sm.get('segments', 0)} segments, {sm.get('segments_anchored', 0)} anchored, "
                 f"{sm.get('anchors_independent', 0)} in an independent public log. Max delay from segment close "
                 f"to anchor: {s['anchor_delay_max_s'] if s['anchor_delay_max_s'] is not None else 'n/a'} s.</p>")
    parts.append(f"<p>Chain head: <code>{e(head)}</code>. Keep this value: passing it to "
                 "<code>--known-head</code> on the next pack detects truncated or rewritten history.</p>")
    findings = [f for f in verify.get("findings", []) if f["level"] in ("error", "warn")]
    if findings:
        parts.append(_table(["Level", "Code", "Detail"], [[f["level"], f["code"], f["message"]] for f in findings]))
    parts.append(f"<p>To check it yourself, offline: <code>pipx run gleipnir-verify {e(bundle_name)} "
                 f"--expect-key {e(key)}</code></p>")

    parts.append("<h2>Systems and tools used</h2>")
    parts.append(_table(["System", "Tool", "Actions"],
                        [[sy, t, n] for (sy, t), n in s["by_tool"].most_common()], {2}))
    parts.append("<h2>Identities and scopes</h2>")
    parts.append(_table(["Principal", "Scope", "Actions"],
                        [[p, sc or "-", n] for (p, sc), n in s["identities"].most_common()], {2}))
    parts.append("<h2>Agents, models and versions</h2>")
    parts.append(_table(["Agent", "Actions"], [[k, n] for k, n in s["agents"].most_common()], {1}))
    if s["models"]:
        parts.append(_table(["Model", "Actions"], [[k, n] for k, n in s["models"].most_common()], {1}))
    if s["versions"]:
        parts.append(_table(["Prompt/config versions", "Actions"],
                            [[k, n] for k, n in s["versions"].most_common()], {1}))
    parts.append("<h2>Outcome checks</h2>")
    parts.append("<p class=muted>Whether the external system, read back after the action, matched what the agent "
                 "did.</p>")
    parts.append(_table(["Result", "Actions"], [[k, n] for k, n in s["outcomes"].most_common()], {1}))
    parts.append("<h2>Failures and mismatches</h2>")
    if s["problems"]:
        rows = []
        for p in s["problems"][:200]:
            detail = p["response"].get("error") or ", ".join(p.get("outcome", {}).get("fields", [])) or ""
            rows.append([p["t"]["start"], p["tool"]["system"], p["tool"]["name"], p["response"]["status"],
                         p.get("outcome", {}).get("check", "-"), detail, p["id"]])
        parts.append(_table(["Time", "System", "Tool", "Status", "Outcome", "Detail", "Action id"], rows))
        if len(s["problems"]) > 200:
            parts.append(f"<p class=muted>{len(s['problems']) - 200} more in actions.csv.</p>")
    else:
        parts.append("<p>None in this period.</p>")
    if s["reviews"]:
        parts.append("<h2>Human reviews</h2>")
        parts.append(_table(["Time", "Action", "Reviewer", "Decision", "Rule", "Before execution"], [
            [r["time"], r["review"]["action"], r["review"]["reviewer"], r["review"]["decision"],
             r["review"].get("rule", "-"), r["review"].get("before_execution", "-")] for r in s["reviews"][:200]]))
    parts.append("<h2>Security review checklist coverage</h2>")
    parts.append("<p class=muted>Items from the open <a href='https://github.com/getgleipnir/agent-security-review'>"
                 "agent-security-review</a> checklist that these records evidence. Process items need documents, "
                 "not records.</p>")
    parts.append(_table(["Item", "Question", "Status"], [[c.id, c.question, c.status] for c in coverage]))
    parts.append("<h2>What this pack proves and what it does not</h2><p>A VALID result shows the records were not "
                 "edited, removed, reordered or inserted after they were written, and (for anchored segments) "
                 "after they were published to the log. It does not show that the agent's decisions were correct, "
                 "and it cannot show actions that were never recorded: reconcile <code>actions.csv</code> against "
                 "your own system logs using the external ids.</p>")
    parts.append("</body></html>")
    return "".join(parts)


def build_pack(records: list[dict[str, Any]], out: str | Path, *, since: datetime | None = None,
               until: datetime | None = None, local_anchor_log: str | Path | None = None,
               checklist: str | Path | None = None) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    work = out.with_suffix("")
    bundle_path = work.parent / (work.name + "-bundle.zip")
    export_bundle(records, bundle_path, since=since, until=until, local_anchor_log=local_anchor_log)
    report = verify_bundle(bundle_path)
    verify = report.as_dict()
    s = summarize(records, since, until)
    caps, _ = capabilities_from_records(records)
    coverage = evaluate(load_checklist(checklist), caps)
    period = f"{iso(since) if since else 'start'} to {iso(until) if until else 'now'}"
    head_seq = report.summary.get("head", {}).get("seq")
    head = f"{head_seq}:{report.summary.get('head', {}).get('hash')}"
    key = records[0]["public_key"]["id"]
    page = render_html(s, verify=verify, coverage=coverage, period=period, key=key, chain=records[0]["chain"],
                       head=head, bundle_name="bundle.zip")
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("summary.html", page)
        zf.writestr("actions.csv", actions_csv(s["actions"]))
        zf.write(bundle_path, "bundle.zip")
        zf.writestr("VERIFY.md", VERIFY_README.format(name="bundle.zip", key=key))
        zf.writestr("verification.json", json.dumps(verify, indent=2, sort_keys=True))
    bundle_path.unlink()
    return out
