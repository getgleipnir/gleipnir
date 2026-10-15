"""``gleipnir report``: a single HTML page showing what an agent did, from the local chains.

Meant for the person running the agent (for example through ``gleipnir-mcp``): every recorded
tool call with its arguments, result or error, grouped by chain, plus the verification result of
each chain. For a buyer or auditor, ``gleipnir pack`` is the hand-off format.
"""

from __future__ import annotations

import html
import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from gleipnir_verify.verifier import verify_bundle

from . import __version__
from .export import export_bundle
from .pack import _CSS
from .store import JsonlStore
from .util import iso, utcnow

_EXTRA_CSS = """
details{margin:0}summary{cursor:pointer;list-style:none}summary::-webkit-details-marker{display:none}
summary:before{content:'\\25B8  ';color:var(--muted)}details[open] summary:before{content:'\\25BE  '}
pre{white-space:pre-wrap;word-break:break-word;font-size:12px;margin:6px 0;max-height:420px;overflow:auto;
border:1px solid var(--line);border-radius:6px;padding:8px}td.t{white-space:nowrap;font-size:13px}
.tablewrap{overflow-x:auto}
"""


def load_chains(home: Path, chain: str | None = None) -> dict[str, list[dict[str, Any]]]:
    base = home / "chains"
    names = [chain] if chain else sorted(p.name for p in base.iterdir() if p.is_dir()) if base.exists() else []
    out = {}
    for name in names:
        records = JsonlStore(base / name, fsync=False).read_all()
        if records:
            out[name] = records
    return out


def _verify(records: list[dict[str, Any]], home: Path) -> dict[str, Any]:
    log = home / "anchors" / "local-anchor-log.jsonl"
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "bundle.zip"
        try:
            export_bundle(records, path, local_anchor_log=log if log.exists() else None)
        except Exception as exc:  # noqa: BLE001
            return {"result": "ERROR", "findings": [{"level": "error", "code": "export", "message": str(exc)}]}
        return verify_bundle(path).as_dict()


def _short(value: Any, limit: int = 160) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _result_preview(action: dict[str, Any]) -> str:
    resp = action.get("response", {})
    if resp.get("status") != "ok":
        return resp.get("error", "")
    body = resp.get("body")
    if isinstance(body, dict):
        if body.get("structuredContent") is not None:
            return _short(body["structuredContent"])
        texts = [c.get("text") for c in body.get("content") or [] if isinstance(c, dict) and c.get("text")]
        if texts:
            return _short(" ".join(texts))
    return _short(body)


def render_report(chains: dict[str, list[dict[str, Any]]], verifications: dict[str, dict[str, Any]],
                  *, home: Path, limit: int = 1000) -> str:
    e = html.escape
    actions = [(name, r) for name, recs in chains.items() for r in recs if r.get("kind") == "action"]
    actions.sort(key=lambda x: x[1]["t"]["start"], reverse=True)
    failed = sum(1 for _, a in actions if a["response"]["status"] != "ok")
    systems = Counter(a["tool"]["system"] for _, a in actions)
    clients = Counter(f"{a['agent']['id']} {a['agent']['version']}".strip() for _, a in actions)
    tools = Counter((a["tool"]["system"], a["tool"]["name"]) for _, a in actions)
    p = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
         f"<meta name=viewport content='width=device-width,initial-scale=1'><title>Agent Activity</title>"
         f"<style>{_CSS}{_EXTRA_CSS}</style></head><body>"]
    p.append("<h1>What my agent did</h1>")
    span = ""
    if actions:
        span = f" from {e(actions[-1][1]['t']['start'])} to {e(actions[0][1]['t']['end'])}"
    p.append(f"<p class=muted>Tool calls recorded in <code>{e(str(home))}</code>{span}. Generated "
             f"{e(iso(utcnow()))} by gleipnir-sdk {e(__version__)}.</p>")
    p.append("<div class=grid>")
    for label, value in [("Tool calls", len(actions)), ("Failed", failed), ("Systems", len(systems)),
                         ("Clients", len(clients)), ("Chains", len(chains))]:
        p.append(f"<div class=card><b>{value}</b><span class=muted>{e(label)}</span></div>")
    p.append("</div>")

    p.append("<h2>Integrity</h2>")
    rows = []
    for name, recs in chains.items():
        v = verifications.get(name, {})
        n = sum(1 for r in recs if r.get("kind") == "action")
        issues = [f for f in v.get("findings", []) if f.get("level") in ("error", "warn")]
        note = "; ".join(f"{f['code']}: {f['message']}" for f in issues[:3])
        rows.append(f"<tr><td><code>{e(name)}</code></td><td class=n>{n}</td>"
                    f"<td class={'ok' if v.get('result') == 'VALID' else 'bad'}>{e(str(v.get('result', '?')))}</td>"
                    f"<td><code>{e(recs[0]['public_key']['id'])}</code></td><td class=refs>{e(note)}</td></tr>")
    p.append("<div class=tablewrap><table><thead><tr><th>Chain</th><th>Tool calls</th><th>Verification</th>"
             f"<th>Signing key</th><th>Notes</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>")
    p.append("<p class=muted>VALID means the records were not edited, removed, reordered or inserted after they "
             "were written. Records still in the open segment are sealed when the proxy exits. To hand records "
             "to someone else, run <code>gleipnir --home ... --chain NAME pack</code> and send the zip; they "
             "check it with <code>gleipnir-verify</code>.</p>")

    p.append("<h2>Tools used</h2>")
    p.append("<div class=tablewrap><table><thead><tr><th>System</th><th>Tool</th><th>Calls</th></tr></thead><tbody>"
             + "".join(f"<tr><td>{e(s)}</td><td>{e(t)}</td><td class=n>{n}</td></tr>"
                       for (s, t), n in tools.most_common()) + "</tbody></table></div>")

    p.append("<h2>Tool calls, newest first</h2>")
    if not actions:
        p.append("<p>No tool calls recorded yet.</p>")
    body = []
    for _name, a in actions[:limit]:
        ok = a["response"]["status"] == "ok"
        detail = json.dumps({"args": a.get("args"), "response": a.get("response"), "context": a.get("context"),
                             "id": a["id"], "seq": a["seq"]}, indent=2, ensure_ascii=False, sort_keys=True)
        body.append(
            f"<tr><td class=t>{e(a['t']['start'])}</td><td>{e(a['agent']['id'])}</td>"
            f"<td>{e(a['tool']['system'])}</td><td><b>{e(a['tool']['name'])}</b></td>"
            f"<td class={'ok' if ok else 'bad'}>{'ok' if ok else 'error'}</td>"
            f"<td><details><summary>{e(_short(a.get('args'), 100))}<br><span class=muted>"
            f"{e(_result_preview(a))}</span></summary><pre>{e(detail)}</pre></details></td></tr>")
    if body:
        p.append("<div class=tablewrap><table><thead><tr><th>Time (UTC)</th><th>Client</th><th>System</th>"
                 "<th>Tool</th><th>Status</th><th>Arguments / result</th></tr></thead><tbody>"
                 + "".join(body) + "</tbody></table></div>")
    if len(actions) > limit:
        p.append(f"<p class=muted>{len(actions) - limit} older calls not shown.</p>")
    p.append("<h2>What this shows and what it does not</h2><p>These are records of the tool calls that went "
             "through Gleipnir (for MCP: through <code>gleipnir-mcp</code>), with the arguments sent and the "
             "result the server returned. They do not show calls made any other way, and a successful result is "
             "the server's word: whether the change really happened in the external system is only checked when "
             "an outcome check is configured.</p></body></html>")
    return "".join(p)


def build_report(home: Path, out: Path, *, chain: str | None = None, limit: int = 1000) -> tuple[Path, int]:
    chains = load_chains(home, chain)
    verifications = {name: _verify(recs, home) for name, recs in chains.items()}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(chains, verifications, home=home, limit=limit), encoding="utf-8")
    return out, sum(1 for recs in chains.values() for r in recs if r.get("kind") == "action")
