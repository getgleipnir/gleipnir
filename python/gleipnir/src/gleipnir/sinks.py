"""Sinks deliver copies of records outside the vendor's primary store.

Typical uses: a buyer-held copy of the agent's records (EU AI Act deployer logs, bank record
keeping), WORM storage with a retention lock, or a SIEM feed. Delivery happens after each
segment closes and never blocks or breaks the agent; failures are retried.

    from gleipnir.sinks import S3ObjectLockSink, WebhookSink

    rec = gleipnir.Recorder(
        "support-agent", "3.2.4", anchor="rekor",
        retention_days=2555,                      # 7 years, recorded in the chain
        sinks=[S3ObjectLockSink("bank-a-agent-records", client=boto3.client("s3"), role="buyer",
                                retention_days=2555),
               WebhookSink("https://siem.example/ingest", role="siem", fmt="ocsf")],
    )

``role="buyer"`` marks a copy the buyer controls; it is declared in a signed ``config`` record
so the buyer and the checklist report can see it.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol

from .store import _dumps_line
from .util import utcnow


class Sink(Protocol):
    type: str
    role: str  # "buyer" | "worm" | "siem" | "backup"

    def describe(self) -> dict[str, Any]:
        """Public description (no secrets) recorded in the chain's config record."""
        ...

    def write(self, chain: str, records: list[dict[str, Any]]) -> None: ...


def to_ndjson(records: list[dict[str, Any]], fmt: str = "records") -> bytes:
    if fmt == "ocsf":
        from .ocsf import to_ocsf

        return "".join(json.dumps(e, separators=(",", ":"), sort_keys=True) + "\n"
                       for e in (to_ocsf(r) for r in records) if e is not None).encode()
    return "".join(_dumps_line(r) for r in records).encode()


class DirectorySink:
    """Appends records to ``<path>/<chain>/records.jsonl`` (for example a buyer-mounted bucket)."""

    type = "directory"

    def __init__(self, path: str | Path, *, role: str = "backup"):
        self.path = Path(path)
        self.role = role
        self._lock = threading.Lock()

    def describe(self) -> dict[str, Any]:
        return {"type": self.type, "role": self.role, "target": str(self.path)}

    def write(self, chain: str, records: list[dict[str, Any]]) -> None:
        d = self.path / chain
        d.mkdir(parents=True, exist_ok=True)
        with self._lock, open(d / "records.jsonl", "ab") as fh:
            fh.write(to_ndjson(records))
            fh.flush()
            os.fsync(fh.fileno())


class S3ObjectLockSink:
    """Writes each batch as one object with S3 Object Lock (WORM) retention.

    The bucket must have Object Lock enabled. ``mode`` is ``COMPLIANCE`` (nobody, including the
    root account, can shorten it) or ``GOVERNANCE``.
    """

    type = "s3-object-lock"

    def __init__(self, bucket: str, *, client: Any = None, prefix: str = "gleipnir", retention_days: int,
                 mode: str = "COMPLIANCE", role: str = "worm"):
        if client is None:
            import boto3  # type: ignore[import-not-found]

            client = boto3.client("s3")
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise ValueError("mode must be COMPLIANCE or GOVERNANCE")
        self.client, self.bucket, self.prefix = client, bucket, prefix.strip("/")
        self.retention_days, self.mode, self.role = retention_days, mode, role

    def describe(self) -> dict[str, Any]:
        return {"type": self.type, "role": self.role, "target": f"s3://{self.bucket}/{self.prefix}",
                "retention_days": self.retention_days, "mode": self.mode}

    def write(self, chain: str, records: list[dict[str, Any]]) -> None:
        first, last = records[0]["seq"], records[-1]["seq"]
        self.client.put_object(
            Bucket=self.bucket, Key=f"{self.prefix}/{chain}/{first:012d}-{last:012d}.jsonl",
            Body=to_ndjson(records), ContentType="application/x-ndjson",
            ObjectLockMode=self.mode, ObjectLockRetainUntilDate=utcnow() + timedelta(days=self.retention_days),
        )


class WebhookSink:
    """POSTs batches as NDJSON (raw records, or OCSF events with ``fmt="ocsf"``) to an HTTPS endpoint."""

    type = "webhook"

    def __init__(self, url: str, *, headers: dict[str, str] | None = None, fmt: str = "records",
                 role: str = "siem", timeout: float = 30.0):
        if not url.startswith("https://") and not url.startswith("http://localhost"):
            raise ValueError("webhook URL must be https")
        self.url, self.headers, self.fmt, self.role, self.timeout = url, dict(headers or {}), fmt, role, timeout

    def describe(self) -> dict[str, Any]:
        return {"type": self.type, "role": self.role, "target": self.url.split("?", 1)[0], "format": self.fmt}

    def write(self, chain: str, records: list[dict[str, Any]]) -> None:
        import urllib.request

        req = urllib.request.Request(self.url, data=to_ndjson(records, self.fmt), method="POST",
                                     headers={"Content-Type": "application/x-ndjson", "X-Gleipnir-Chain": chain,
                                              **self.headers})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - https enforced
            if resp.status >= 300:
                raise RuntimeError(f"webhook returned {resp.status}")


class SplunkHecSink:
    """Sends OCSF events to a Splunk HTTP Event Collector."""

    type = "splunk-hec"

    def __init__(self, url: str, token: str, *, index: str | None = None, role: str = "siem",
                 timeout: float = 30.0):
        self.url, self.token, self.index, self.role, self.timeout = url, token, index, role, timeout

    def describe(self) -> dict[str, Any]:
        return {"type": self.type, "role": self.role, "target": self.url, "format": "ocsf"}

    def write(self, chain: str, records: list[dict[str, Any]]) -> None:
        import urllib.request

        from .ocsf import to_ocsf

        events = []
        for r in records:
            e = to_ocsf(r)
            if e is not None:
                ev: dict[str, Any] = {"time": e["time"] / 1000, "sourcetype": "ocsf:api_activity",
                                      "source": f"gleipnir:{chain}", "event": e}
                if self.index:
                    ev["index"] = self.index
                events.append(json.dumps(ev, separators=(",", ":")))
        if not events:
            return
        req = urllib.request.Request(self.url, data="\n".join(events).encode(), method="POST",
                                     headers={"Authorization": f"Splunk {self.token}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            if resp.status >= 300:
                raise RuntimeError(f"Splunk HEC returned {resp.status}")
