"""Generic read-back over HTTP/JSON, for any system of record without a dedicated module.

``http_json_matches(get_url=..., fetch=..., expected=...)``: build the URL of the object from the
call and the tool's response, fetch it as JSON, and compare the expected fields (dotted paths
into the JSON). ``fetch`` can be :func:`gleipnir.outcomes.json_get` or any callable
``url -> parsed JSON`` (raise an exception with ``status == 404`` or
:class:`gleipnir.outcomes.NotFound` for a missing object).

There is no external API to cite here; the comparison rules are those of
:func:`gleipnir.outcomes._core.values_equal` (numbers numerically, ids as text, a dict is a
subset match).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from ..recorder import Call, Outcome
from ._core import ABSENT, Check, ConfigError, NotFound, check_fn, get_path, plain, resolve_fields, values_equal


def http_json_matches(
    *,
    get_url: Callable[[Call, Any], str],
    fetch: Callable[[str], Any],
    expected: Callable[[Call, Any], Mapping[str, Any]] | Mapping[str, Any],
    root: str | None = None,
    eq: Mapping[str, Callable[[Any, Any], bool]] | None = None,
    method: str = "http.json_matches",
    **retry: Any,
) -> Any:
    """Fetch ``get_url(call, response)`` with ``fetch`` and compare ``expected`` fields.

    ``root`` is a dotted path to the object inside the body (e.g. ``"data"``); ``eq`` overrides
    the comparison for given fields (``{"total": lambda exp, got: abs(exp - got) <= 1}``).
    A null/empty body is "not found".
    """
    if not callable(get_url) or not callable(fetch):
        raise TypeError("get_url and fetch must be callables")
    eqs = dict(eq or {})

    def read(call: Call, response: Any) -> Outcome:
        url = get_url(call, response)
        if not isinstance(url, str) or not url:
            raise ConfigError("get_url returned no URL")
        want = resolve_fields(expected, call, response)
        body = plain(fetch(url))
        obj = body if root is None else get_path(body, root)
        if obj is None or obj is ABSENT or obj == {} or obj == []:
            raise NotFound(url)
        c = Check(method)
        for name, value in want.items():
            c.field(name, value, get_path(obj, name), eqs.get(name, values_equal))
        return c.outcome()

    return check_fn(method, read, retry)


__all__ = ["http_json_matches"]
