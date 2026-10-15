"""Reconcile a verified bundle against the buyer's own system of record.

Signed records cannot show actions the vendor never recorded. The buyer closes that gap by
comparing object ids in the records (refund ids, ticket ids, ...) with an export from its own
system, filtered to what the agent's identity touched:

    gleipnir-verify reconcile bundle.zip refunds_by_agent.csv --column refund_id

- in your system, not in the records: the agent may have acted without recording it
- in the records, not in your system: an action was claimed that your system does not show

Only the id field at the top level of each action's response counts (``--field``, default the
column name), and ``--tool`` limits it to the tools that create or change those objects.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .verifier import Report, read_bundle, verify_bundle


def top_level_ids(value: Any, wanted: str) -> set[str]:
    """``wanted`` at the top level of a response body only (not inside lists), so a list or search
    call that returns many objects does not count as having created them."""
    if isinstance(value, dict):
        x = value.get(wanted)
        if isinstance(x, (str, int)) and not isinstance(x, bool):
            return {str(x)}
    return set()


def external_ids(value: Any, wanted: str | None = None) -> set[str]:
    """Id-like values (keys ``id``, ``*_id``, ``*Id``) in a response body, optionally only key ``wanted``."""
    out: set[str] = set()
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            for k, x in v.items():
                if isinstance(x, (str, int)) and not isinstance(x, bool):
                    id_like = k == "id" or k.endswith("_id") or k.endswith("Id")
                    if (wanted and k == wanted) or (not wanted and id_like):
                        out.add(str(x))
                elif isinstance(x, (dict, list)):
                    stack.append(x)
        elif isinstance(v, list):
            stack.extend(v[:1000])
    return out


@dataclass
class Reconciliation:
    report: Report
    matched: set[str] = field(default_factory=set)
    only_in_system: set[str] = field(default_factory=set)
    only_in_records: set[str] = field(default_factory=set)

    @property
    def ok(self) -> bool:
        return self.report.valid() and not self.only_in_system and not self.only_in_records


def reconcile(bundle: str | Path, system_csv: str | Path, *, column: str, field_name: str | None = None,
              tools: list[str] | None = None, **verify_kwargs: Any) -> Reconciliation:
    report = verify_bundle(bundle, **verify_kwargs)
    result = Reconciliation(report)
    if not report.valid():
        return result
    _, records, _ = read_bundle(bundle)
    ids: set[str] = set()
    for r in records:
        resp = r.get("response") if isinstance(r, dict) else None
        tool = r.get("tool", {}).get("name") if isinstance(r.get("tool"), dict) else None
        if tools and tool not in tools:
            continue
        if r.get("kind") == "action" and isinstance(resp, dict) and resp.get("status") == "ok":
            ids |= top_level_ids(resp.get("body"), field_name or column)
    try:
        with open(system_csv, newline="", encoding="utf-8-sig") as fh:
            text = fh.read()
            if "\x00" in text:  # rejected on every Python version, so all implementations agree
                raise csv.Error("line contains NUL")
            reader = csv.DictReader(io.StringIO(text, newline=""))
            if reader.fieldnames is None or column not in reader.fieldnames:
                raise ValueError(f"column {column!r} not found in {system_csv}")
            system = {(row.get(column) or "").strip() for row in reader} - {""}  # short rows are skipped
    except (csv.Error, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read {system_csv}: {exc}") from exc
    result.matched = ids & system
    result.only_in_system = system - ids
    result.only_in_records = ids - system
    return result
