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
from .export import VERIFY_README, export_bundle, verify_command
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
:root{--fg:#17191f;--muted:#5d6068;--line:#dcd8cf;--soft:#f6f3ec;--gold:#a07a2c;--ok:#1d6a4d;--ok-bg:#e6f2ea;
--bad:#a1271e;--bad-bg:#f8e5e1;--warn:#8a5a00}
*{box-sizing:border-box}
body{font:15px/1.55 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif;color:var(--fg);background:#fff;
max-width:1000px;margin:36px auto;padding:0 20px}
.brand{display:flex;align-items:center;gap:10px;font-family:Georgia,"Times New Roman",serif;letter-spacing:.3em;
font-size:13px;color:var(--fg)}.brand svg{width:26px;height:22px}
h1{font-family:Georgia,"Times New Roman",serif;font-weight:400;font-size:34px;line-height:1.1;margin:22px 0 6px}
h2{font-family:Georgia,"Times New Roman",serif;font-weight:400;font-size:22px;margin:36px 0 10px;
padding-bottom:6px;border-bottom:1px solid var(--line)}
.muted{color:var(--muted)}p{margin:6px 0}a{color:var(--gold)}
.verdict{display:flex;gap:16px;align-items:flex-start;border-radius:10px;padding:16px 18px;margin:22px 0}
.verdict.ok{background:var(--ok-bg);border:1px solid #b9dcc6}
.verdict.bad{background:var(--bad-bg);border:1px solid #ecc0b8}
.verdict b{font-size:20px;letter-spacing:.02em}.verdict.ok b{color:var(--ok)}.verdict.bad b{color:var(--bad)}
.verdict ul{margin:6px 0 0;padding-left:18px}.verdict p,.verdict ul{font-weight:400;color:var(--fg)}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;font-size:13px;color:var(--muted)}td.n{text-align:right;font-variant-numeric:tabular-nums}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all;background:var(--soft);
padding:1px 4px;border-radius:3px}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:18px}
.card{border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-family:Georgia,serif;font-weight:400;font-size:30px;line-height:1.1}
.card.alert b{color:var(--bad)}
td.id{white-space:nowrap;font-family:ui-monospace,Menlo,monospace;font-size:13px;color:var(--gold)}
.s-covered{color:var(--ok);font-weight:600}.s-partial{color:var(--warn);font-weight:600}
.s-missing{color:var(--bad);font-weight:600}.s-process{color:var(--muted)}td.refs{font-size:12px;color:var(--muted)}
.said{color:var(--muted)}.shows{color:var(--bad);font-weight:600}
.foot{margin-top:40px;padding-top:12px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}
@media print{body{margin:0;max-width:none}h2{break-after:avoid}tr,.verdict,.card{break-inside:avoid}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""

_BRAND = ('<svg viewBox="0 0 34 30" aria-hidden="true"><g fill="none" stroke="#C9A45C" stroke-linecap="round">'
          '<path d="M3 23 C 9 5, 16 30, 21 13 S 31 8, 31 8" stroke-width="3"/>'
          '<path d="M3 27 C 9 11, 16 34, 21 18 S 31 13, 31 13" stroke-opacity=".5" stroke-width="1.8"/></g></svg>')


def _table(headers: list[str], rows: list[list[Any]], numeric: set[int] | None = None) -> str:
    numeric = numeric or set()
    h = "".join(f"<th>{html.escape(x)}</th>" for x in headers)
    body = "".join(
        "<tr>" + "".join(f"<td{' class=n' if i in numeric else ''}>{html.escape(str(c))}</td>"
                         for i, c in enumerate(row)) + "</tr>" for row in rows)
    return f"<table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>"


def _flat(obj_json: str) -> str:
    """Render a small JSON object as 'k: v, k: v' for people, not parsers."""
    try:
        obj = json.loads(obj_json)
    except ValueError:
        return obj_json
    if isinstance(obj, dict) and set(obj) <= {"provider", "name", "version"}:
        return " ".join(str(obj[k]) for k in ("provider", "name", "version") if k in obj)
    if isinstance(obj, dict):
        return ", ".join(f"{k}: {v}" for k, v in obj.items())
    return obj_json


def _shows(p: dict[str, Any]) -> str:
    """What the system of record showed for the fields that differed."""
    if p["response"]["status"] != "ok":
        return p["response"].get("error") or p["response"]["status"]
    out = p.get("outcome", {})
    observed = out.get("observed") or {}
    fields = out.get("fields") or list(observed)
    shown = [f"{f} = {observed[f]}" for f in fields if f in observed]
    return ", ".join(shown) or out.get("detail") or out.get("check", "")


def render_html(s: dict[str, Any], *, verify: dict[str, Any], coverage: list[Any], period: str, key: str,
                chain: str, head: str, command: str, refs: dict[str, str] | None = None) -> str:
    refs = refs or {}
    e = html.escape
    a = s["actions"]
    v_ok = verify["result"] == "VALID"
    sm = verify.get("summary", {})
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
             f"<meta name=viewport content='width=device-width,initial-scale=1'>"
             f"<title>Security Review Pack</title><style>{_CSS}</style></head><body>"]
    parts.append(f"<div class=brand>{_BRAND}GLEIPNIR</div>")
    parts.append("<h1>Security Review Pack</h1>")
    parts.append(f"<p class=muted>Agent action records covering {e(period)}. Generated {e(iso(utcnow()))} by "
                 f"gleipnir-sdk {e(__version__)}.</p>")

    independent = sm.get("anchors_independent", 0)
    if v_ok:
        checks = [f"Every record is signed with key <code>{e(key)}</code> and the signatures match.",
                  "Each record links to the one before it, so nothing was removed, reordered or inserted.",
                  f"{sm.get('segments_anchored', 0)} of {sm.get('segments', 0)} segments are anchored"
                  + (f", {independent} in an independent public log." if independent else
                     " (local test anchor in this pack; production packs anchor in a public log).")]
        parts.append("<div class='verdict ok'><div><b>VALID</b><p>These records have not been changed since they "
                     "were written.</p><ul>" + "".join(f"<li>{c}</li>" for c in checks) + "</ul></div></div>")
    else:
        parts.append(f"<div class='verdict bad'><div><b>{e(verify['result'])}</b><p>Verification found problems; "
                     "see the findings below. Do not rely on these records until they are explained.</p></div></div>")

    parts.append("<div class=grid>")
    mism = s["outcomes"].get("mismatch", 0)
    for label, value, alert in [("Actions", len(a), False), ("Failed", s["status"].get("error", 0), False),
                                ("Outcome checked", s["outcomes"].get("match", 0) + mism, False),
                                ("Outcome mismatches", mism, mism > 0),
                                ("Human reviews", len(s["reviews"]), False)]:
        parts.append(f"<div class='card{' alert' if alert and value else ''}'><b>{value}</b>"
                     f"<span class=muted>{e(label)}</span></div>")
    parts.append("</div>")

    parts.append("<h2>Where the agent's word and the system disagree</h2>")
    parts.append("<p class=muted>Each action was read back from the system it touched. These are the actions that "
                 "failed, or where the system of record shows something different from what the agent did.</p>")
    if s["problems"]:
        rows = []
        for p in s["problems"][:200]:
            said = p.get("claim", {}).get("text") or f"{p['tool']['name']} succeeded"
            rows.append(f"<tr><td>{e(p['t']['start'])}</td><td>{e(p['tool']['system'])}<br>"
                        f"<span class=muted>{e(p['tool']['name'])}</span></td>"
                        f"<td class=said>{e(said)}</td><td class=shows>{e(_shows(p))}</td>"
                        f"<td class=id>{e(p['id'])}</td></tr>")
        parts.append("<table><thead><tr><th>Time</th><th>System and tool</th><th>Agent said</th>"
                     "<th>System of record shows</th><th>Action id</th></tr></thead><tbody>"
                     + "".join(rows) + "</tbody></table>")
        if len(s["problems"]) > 200:
            parts.append(f"<p class=muted>{len(s['problems']) - 200} more in actions.csv.</p>")
    else:
        parts.append("<p>None in this period.</p>")

    parts.append("<h2>Systems, identities and versions</h2>")
    parts.append(_table(["System", "Tool", "Actions"],
                        [[sy, t, n] for (sy, t), n in s["by_tool"].most_common()], {2}))
    parts.append(_table(["Acting identity", "Scope", "Actions"],
                        [[p, sc or "-", n] for (p, sc), n in s["identities"].most_common()], {2}))
    parts.append(_table(["Agent", "Actions"], [[k, n] for k, n in s["agents"].most_common()], {1}))
    if s["models"]:
        parts.append(_table(["Model", "Actions"], [[_flat(k), n] for k, n in s["models"].most_common()], {1}))
    if s["versions"]:
        parts.append(_table(["Prompt and config versions", "Actions"],
                            [[_flat(k), n] for k, n in s["versions"].most_common()], {1}))
    if s["reviews"]:
        parts.append("<h2>Human reviews</h2>")
        parts.append(_table(["Time", "Action", "Reviewer", "Decision", "Rule", "Before execution"], [
            [r["time"], r["review"]["action"], r["review"]["reviewer"], r["review"]["decision"],
             r["review"].get("rule", "-"), r["review"].get("before_execution", "-")] for r in s["reviews"][:200]]))

    parts.append("<h2>Check it yourself</h2>")
    parts.append("<p>Anyone can verify the bundle in this pack offline, with no account and no access to the "
                 f"vendor:</p><p><code>{e(command)}</code></p>")
    delay = s["anchor_delay_max_s"] if s["anchor_delay_max_s"] is not None else "n/a"
    parts.append(f"<p class=muted>Chain <code>{e(chain)}</code>. Chain head <code>{e(head)}</code>: keep it and pass "
                 "it as <code>--known-head</code> next time to detect truncated or rewritten history. Longest delay "
                 f"from segment close to anchor: {delay} s.</p>")
    if sm.get("segments_timestamped"):
        parts.append(f"<p class=muted>Trusted time: {sm['segments_timestamped']} segments carry an RFC 3161 timestamp "
                     f"from an independent authority; the longest delay after a segment closed was "
                     f"{sm.get('max_timestamp_delay_s')} s.</p>")
    findings = [f for f in verify.get("findings", []) if f["level"] in ("error", "warn")]
    if findings:
        parts.append(_table(["Level", "Code", "Detail"], [[f["level"], f["code"], f["message"]] for f in findings]))

    counts = Counter(c.status for c in coverage)
    parts.append("<h2>Security review checklist coverage</h2>")
    parts.append(f"<p class=muted>Questions from the open <a href='https://github.com/getgleipnir/agent-security-review'>"
                 f"Agent Security Review Kit</a>: {counts.get('covered', 0)} evidenced by these records, "
                 f"{counts.get('partial', 0)} partly, {counts.get('missing', 0)} missing; {counts.get('process', 0)} "
                 "need documents rather than records.</p>")
    cov_rows = "".join(
        f"<tr><td class=id>{e(c.id)}</td><td>{e(c.question)}</td><td class=s-{e(c.status)}>{e(c.status)}</td>"
        f"<td class=refs>{e(refs.get(c.id, ''))}</td></tr>"
        for c in coverage)
    parts.append(f"<table><thead><tr><th>Item</th><th>Question</th><th>Status</th><th>Controls</th></tr></thead>"
                 f"<tbody>{cov_rows}</tbody></table>")
    parts.append("<h2>What this pack proves and what it does not</h2><p>A VALID result shows the records were not "
                 "edited, removed, reordered or inserted after they were written, and (for anchored segments) "
                 "after they were published to the log. It does not show that the agent's decisions were correct, "
                 "and it cannot show actions that were never recorded: reconcile <code>actions.csv</code> against "
                 "your own system logs using the external ids.</p>")
    parts.append("<p class=foot>Made with Gleipnir, open source under Apache-2.0: "
                 "<a href='https://github.com/getgleipnir/gleipnir'>github.com/getgleipnir/gleipnir</a></p>")
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
    checklist_data = load_checklist(checklist)
    coverage = evaluate(checklist_data, caps)
    fws = checklist_data.get("frameworks", {})
    refs = {item["id"]: "; ".join(f"{fws.get(r['fw'], {}).get('short', r['fw'])} {r['ref']}"
                                  for r in item.get("references", []))
            for item in checklist_data.get("items", [])}
    if since or until:
        period = f"{iso(since) if since else 'the start of the chain'} to {iso(until) if until else 'now'}"
    else:
        period = "the whole chain"
    head_seq = report.summary.get("head", {}).get("seq")
    head = f"{head_seq}:{report.summary.get('head', {}).get('hash')}"
    key = records[0]["public_key"]["id"]
    with zipfile.ZipFile(bundle_path) as bz:
        picked = [json.loads(x) for x in bz.read("records.jsonl").decode().split("\n") if x.strip()]
    command = verify_command(picked, "bundle.zip", full=not report.summary.get("partial"))
    page = render_html(s, verify=verify, coverage=coverage, period=period, key=key, chain=records[0]["chain"],
                       head=head, command=command, refs=refs)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("summary.html", page)
        zf.writestr("actions.csv", actions_csv(s["actions"]))
        zf.write(bundle_path, "bundle.zip")
        zf.writestr("VERIFY.md", VERIFY_README.format(command=command))
        zf.writestr("verification.json", json.dumps(verify, indent=2, sort_keys=True))
    bundle_path.unlink()
    return out
