"""Reconcile a verified bundle against the buyer's own system of record.

Signed records cannot show actions the vendor never recorded. The buyer closes that gap by
comparing object ids in the records (refund ids, ticket ids, ...) with an export from its own
system, filtered to what the agent's identity touched:

    gleipnir-verify reconcile bundle.zip refunds_by_agent.csv --column refund_id

- in your system, not in the records: the agent may have acted without recording it
- in the records, not in your system: an action was claimed that your system does not show
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .verifier import Report, read_bundle, verify_bundle


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
              **verify_kwargs: Any) -> Reconciliation:
    report = verify_bundle(bundle, **verify_kwargs)
    result = Reconciliation(report)
    if not report.valid():
        return result
    _, records, _ = read_bundle(bundle)
    ids: set[str] = set()
    for r in records:
        if r.get("kind") == "action" and r.get("response", {}).get("status") == "ok":
            ids |= external_ids(r["response"].get("body"), field_name or column)
    with open(system_csv, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or column not in reader.fieldnames:
            raise ValueError(f"column {column!r} not found in {system_csv}")
        system = {row[column].strip() for row in reader if row.get(column, "").strip()}
    result.matched = ids & system
    result.only_in_system = system - ids
    result.only_in_records = ids - system
    return result
