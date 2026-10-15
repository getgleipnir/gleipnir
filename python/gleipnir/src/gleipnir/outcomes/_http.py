"""A minimal JSON-over-HTTPS fetcher, for systems where you don't want an SDK."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any


class HttpError(Exception):
    """A non-2xx response. ``status`` drives the retry / not-found classification."""

    def __init__(self, status: int, url: str, body: str = "") -> None:
        super().__init__(f"HTTP {status} from {url}" + (f": {body[:200]}" if body else ""))
        self.status = status
        self.url = url
        self.body = body


def json_get(base_url: str, *, headers: Mapping[str, str] | None = None, session: Any = None,
             timeout: float = 10.0) -> Callable[[str], Any]:
    """Return ``fetch(path) -> parsed JSON`` for ``base_url + path``.

    ``session`` may be a ``requests.Session`` or ``httpx.Client`` (anything with
    ``.get(url, headers=, timeout=)`` returning an object with ``status_code`` and ``.json()``);
    without one, the standard library is used. Non-2xx responses raise :class:`HttpError`.

    Example::

        zd = json_get("https://acme.zendesk.com", headers={"Authorization": "Basic ..."})
        zd("/api/v2/tickets/35436")
    """
    base = base_url.rstrip("/")
    hdrs = {"Accept": "application/json", **dict(headers or {})}

    def fetch(path: str) -> Any:
        url = path if path.startswith(("https://", "http://")) else base + "/" + path.lstrip("/")
        if session is not None:
            r = session.get(url, headers=hdrs, timeout=timeout)
            status = int(getattr(r, "status_code", 0) or getattr(r, "status", 0))
            if not 200 <= status < 300:
                raise HttpError(status, url, str(getattr(r, "text", "")))
            return r.json()
        req = urllib.request.Request(url, headers=hdrs, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - caller-chosen URL
                raw = r.read()
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
            raise HttpError(e.code, url, body) from None
        return json.loads(raw) if raw else None

    return fetch
