"""Shared machinery for the ready-made outcome checks.

Every factory in :mod:`gleipnir.outcomes` builds a ``verify_outcome`` callback with the same
contract:

* It reads the object back from the system of record through an injected client (an official
  SDK client or a minimal HTTP callable), so no SDK is a dependency of ``gleipnir-sdk``.
* It compares only the fields you ask for and records only those fields as ``observed``.
* It returns ``match`` or ``mismatch`` (with the mismatched field names), ``mismatch`` with
  ``fields=["exists"]`` when the object is not there, and ``error`` when the check itself could
  not run (network, auth, bad configuration). It never raises into the agent.
* Optional bounded retries with exponential backoff absorb eventual consistency (default off).
"""

from __future__ import annotations

import html
import re
import time
from collections.abc import Callable, Iterable, Mapping
from decimal import Decimal, InvalidOperation
from typing import Any, Union

from ..recorder import Call, Outcome


class _Sentinel:
    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return self.name


SKIP = _Sentinel("SKIP")  # a spec resolved to "don't compare this field"
ABSENT = _Sentinel("ABSENT")  # the field is not present in the observed object

Spec = Union[str, Callable[[Call, Any], Any], None]
"""How a factory learns an expected value or an id.

* ``str``: the name of an argument of the wrapped tool (``call.args[name]``); missing is an error.
* callable ``(call, response) -> value``: computed; return :data:`SKIP` to skip the field
  (``None`` is a real expected value: "empty / unassigned").
* ``None``: don't check this field.

Helpers: :func:`arg`, :func:`opt_arg`, :func:`resp`, :func:`const`, :func:`first_of`.
"""


class NotFound(Exception):
    """Raise from a fetch callable to say the object does not exist."""


class ConfigError(Exception):
    """The check is configured in a way that cannot work for this call."""


# ---- spec helpers --------------------------------------------------------------------------
def arg(name: str) -> Callable[[Call, Any], Any]:
    """Expected value is the tool argument ``name``; an error if the call has no such argument."""

    def get(call: Call, response: Any) -> Any:
        if name not in call.args:
            raise ConfigError(f"call has no argument {name!r}")
        return call.args[name]

    get.__name__ = f"arg({name!r})"
    return get


def opt_arg(name: str) -> Callable[[Call, Any], Any]:
    """Expected value is the tool argument ``name`` if present (and not None), else skip."""

    def get(call: Call, response: Any) -> Any:
        v = call.args.get(name)
        return SKIP if v is None else v

    get.__name__ = f"opt_arg({name!r})"
    return get


def resp(path: str) -> Callable[[Call, Any], Any]:
    """Value at a dotted ``path`` in the tool's response (dicts, lists, SDK objects); skip if absent."""

    def get(call: Call, response: Any) -> Any:
        v = get_path(response, path)
        return SKIP if v is ABSENT or v is None else v

    get.__name__ = f"resp({path!r})"
    return get


def const(value: Any) -> Callable[[Call, Any], Any]:
    """A fixed expected value."""
    return lambda call, response: value


def first_of(*specs: Spec) -> Callable[[Call, Any], Any]:
    """The first of ``specs`` that resolves to a value (not :data:`SKIP`)."""

    def get(call: Call, response: Any) -> Any:
        for s in specs:
            v = resolve(s, call, response)
            if v is not SKIP:
                return v
        return SKIP

    return get


def resolve(spec: Spec, call: Call, response: Any) -> Any:
    if spec is None:
        return SKIP
    if isinstance(spec, str):
        return arg(spec)(call, response)
    if callable(spec):
        return spec(call, response)
    raise ConfigError(f"a spec must be an argument name, a callable or None, not {type(spec).__name__}")


def resolve_id(spec: Spec, call: Call, response: Any, what: str) -> str:
    v = resolve(spec, call, response)
    if v is SKIP or v is None or v == "":
        raise ConfigError(f"could not determine the {what} to read back")
    if isinstance(v, Mapping) or hasattr(v, "id"):  # an expanded object: use its id
        v = get_path(v, "id")
    return str(v)


Fields = Union[Iterable[str], Mapping[str, Any], Callable[[Call, Any], Mapping[str, Any]], None]
"""Which fields to compare, for the ``fields=`` parameters.

* a list of names: each must equal the tool argument of the same name (skipped if the call lacks it);
* a mapping ``{field: value}``: literal expected values; a callable value is resolved per call
  (``{"Status": "Closed", "Email": arg("email")}``);
* a callable ``(call, response) -> mapping``: computed per call;
* ``None``: no extra fields.
"""


def resolve_fields(fields: Fields, call: Call, response: Any) -> dict[str, Any]:
    if fields is None:
        return {}
    if callable(fields) and not isinstance(fields, Mapping):
        got = fields(call, response)
        if got is None:
            return {}
        if not isinstance(got, Mapping):
            raise ConfigError("a fields callable must return a mapping of field -> expected value")
        items: Iterable[tuple[str, Any]] = got.items()
    elif isinstance(fields, Mapping):
        items = ((k, v(call, response) if callable(v) else v) for k, v in fields.items())
    elif isinstance(fields, str):
        raise ConfigError("fields must be a list of names or a mapping, not a string")
    else:
        items = ((f, call.args[f]) for f in fields if f in call.args)
    return {k: v for k, v in items if v is not SKIP}


# ---- reading objects -----------------------------------------------------------------------
def plain(obj: Any) -> Any:
    """Turn common SDK result objects into something :func:`get_path` can walk."""
    if obj is None or isinstance(obj, (Mapping, list, tuple, str, int, float, bool)):
        return obj
    for attr in ("model_dump", "to_dict"):
        fn = getattr(obj, attr, None)
        if callable(fn):
            try:
                return fn()
            except Exception:  # noqa: BLE001 - fall back to attribute access
                pass
    raw = getattr(obj, "raw", None)  # pycontribs jira Resource
    if isinstance(raw, Mapping):
        return raw
    return obj


def get_path(obj: Any, path: str) -> Any:
    """Walk ``a.b.0.c`` through mappings, sequences and attributes; :data:`ABSENT` if missing."""
    cur = obj
    for part in path.split("."):
        cur = plain(cur)
        if cur is None:
            return ABSENT
        if isinstance(cur, Mapping):
            if part in cur:
                cur = cur[part]
                continue
            return ABSENT
        if isinstance(cur, (list, tuple)):
            if part.isdigit() and int(part) < len(cur):
                cur = cur[int(part)]
                continue
            return ABSENT
        if isinstance(cur, (str, int, float, bool)):
            return ABSENT
        try:
            cur = getattr(cur, part)
        except AttributeError:
            return ABSENT
    return cur


def object_id(v: Any) -> Any:
    """A reference that may be an id string or an expanded object with an ``id``."""
    if v is None or v is ABSENT or isinstance(v, (str, int)):
        return v
    got = get_path(v, "id")
    return v if got is ABSENT else got


# ---- comparing ------------------------------------------------------------------------------
def _num(v: Any) -> Decimal | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, Decimal)):
        return Decimal(v)
    if isinstance(v, float):
        return Decimal(str(v))
    if isinstance(v, str):
        try:
            d = Decimal(v.strip())
        except InvalidOperation:
            return None
        return d if d.is_finite() else None
    return None


def values_equal(expected: Any, observed: Any) -> bool:
    """Equality that tolerates how APIs serialize values.

    Numbers compare numerically (``"1500.00" == 1500``, ``42.1 == 42.10``), ids compare as text
    (``123 == "123"``), booleans accept ``"true"``/``"false"``, ``None`` accepts a missing or empty
    value, lists compare element-wise and a dict is a subset match.
    """
    if expected is ABSENT:
        return observed is ABSENT
    if expected is None:
        return observed is None or observed is ABSENT or observed == ""
    if observed is ABSENT:
        return False
    if isinstance(expected, bool):
        if isinstance(observed, bool):
            return observed is expected
        return isinstance(observed, str) and observed.strip().lower() == str(expected).lower()
    if isinstance(expected, Mapping):
        observed = plain(observed)
        return isinstance(observed, Mapping) and all(
            values_equal(v, observed.get(k, ABSENT)) for k, v in expected.items())
    if isinstance(expected, (list, tuple)):
        observed = plain(observed)
        return (isinstance(observed, (list, tuple)) and len(observed) == len(expected)
                and all(values_equal(e, o) for e, o in zip(expected, observed, strict=False)))
    if isinstance(observed, bool):
        return isinstance(expected, str) and expected.strip().lower() == str(observed).lower()
    a, b = _num(expected), _num(observed)
    if a is not None and b is not None and not (isinstance(expected, str) and isinstance(observed, str)):
        return a == b
    if isinstance(expected, str) or isinstance(observed, str):
        return str(expected) == str(observed)
    return bool(expected == observed)


def ci_equal(expected: Any, observed: Any) -> bool:
    """Case-insensitive text equality (currencies, enum names)."""
    if isinstance(expected, str) and isinstance(observed, str):
        return expected.casefold() == observed.casefold()
    return values_equal(expected, observed)


def one_of(expected: Any, observed: Any) -> bool:
    """``expected`` is one allowed value or a collection of allowed values."""
    if isinstance(expected, (list, tuple, set, frozenset)):
        return any(values_equal(e, observed) for e in expected)
    return values_equal(expected, observed)


def _strset(v: Any) -> set[str] | None:
    v = plain(v)
    if isinstance(v, str):
        return {v}
    if isinstance(v, (list, tuple, set, frozenset)):
        return {str(plain(x)) for x in v}
    return None


def same_set(expected: Any, observed: Any) -> bool:
    a, b = _strset(expected), _strset(observed)
    return a is not None and b is not None and a == b


def includes_all(expected: Any, observed: Any) -> bool:
    a, b = _strset(expected), _strset(observed)
    return a is not None and b is not None and a <= b


_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def norm_text(v: Any) -> str:
    """Strip HTML tags and entities, collapse whitespace."""
    if v is None or v is ABSENT:
        return ""
    s = _TAG.sub(" ", str(v))
    return _WS.sub(" ", html.unescape(s)).strip()


def text_contains(expected: Any, observed: Any) -> bool:
    exp = norm_text(expected)
    return bool(exp) and exp in norm_text(observed)


class Check:
    """Collects field comparisons for one read-back and turns them into an Outcome."""

    def __init__(self, method: str) -> None:
        self.method = method
        self.observed: dict[str, Any] = {}
        self.mismatched: list[str] = []
        self.compared = 0

    def field(self, name: str, expected: Any, observed: Any,
              eq: Callable[[Any, Any], bool] = values_equal) -> None:
        if expected is SKIP:
            return
        self.compared += 1
        self.observed[name] = None if observed is ABSENT else plain(observed)
        if not eq(expected, observed):
            self.mismatched.append(name)

    def fields(self, expected: Mapping[str, Any], obj: Any, eq: Callable[[Any, Any], bool] = values_equal,
               prefix: str = "") -> None:
        for name, value in expected.items():
            self.field(name, value, get_path(obj, prefix + name), eq)

    def note(self, name: str, value: Any) -> None:
        """Record context (e.g. the id read) without comparing it."""
        self.observed[name] = None if value is ABSENT else plain(value)

    def fail(self, name: str, observed: Any) -> None:
        """A rule (not an expected value) failed, e.g. a refund status of ``failed``."""
        self.compared += 1
        self.observed[name] = None if observed is ABSENT else plain(observed)
        self.mismatched.append(name)

    def require(self, name: str, ok: bool, observed: Any) -> None:
        if ok:
            self.compared += 1
            self.observed[name] = None if observed is ABSENT else plain(observed)
        else:
            self.fail(name, observed)

    def outcome(self) -> Outcome:
        if not self.compared:
            return Outcome("error", detail="no fields to compare: every expected value was skipped",
                           method=self.method)
        if self.mismatched:
            fields = sorted(set(self.mismatched))
            return Outcome("mismatch", dict(self.observed), fields, "mismatched: " + ", ".join(fields),
                           method=self.method)
        return Outcome("match", dict(self.observed), method=self.method)


# ---- money ----------------------------------------------------------------------------------
_EXPONENT = {
    **dict.fromkeys(("BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI",
                     "VND", "VUV", "XAF", "XOF", "XPF"), 0),
    **dict.fromkeys(("BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"), 3),
    **dict.fromkeys(("CLF", "UYW"), 4),
}


def currency_exponent(currency: str) -> int:
    """ISO 4217 minor-unit digits (2 unless listed)."""
    return _EXPONENT.get(currency.upper(), 2)


def to_minor_units(amount: Any, currency: str) -> int:
    """``"209.00"`` USD -> ``20900``; ``"500"`` JPY -> ``500``. Exact (no floats); raises if not whole."""
    d = _num(amount)
    if d is None:
        raise ValueError(f"not a decimal amount: {amount!r}")
    minor = d.scaleb(currency_exponent(currency))
    if minor != minor.to_integral_value():
        raise ValueError(f"{amount!r} has more decimals than {currency.upper()} allows")
    return int(minor)


def expect_minor(v: Any, what: str = "amount") -> Any:
    """Expected money must already be an integer in minor units."""
    if v is SKIP:
        return v
    if isinstance(v, bool) or not isinstance(v, int):
        raise ConfigError(f"expected {what} must be an integer in minor units (cents), got {v!r}")
    return v


# ---- errors and retries -------------------------------------------------------------------
def http_status(exc: BaseException) -> int | None:
    for attr in ("status", "status_code", "http_status", "code"):
        v = getattr(exc, attr, None)
        if isinstance(v, int) and not isinstance(v, bool) and 100 <= v < 600:
            return v
    r = getattr(exc, "response", None)
    if r is not None:
        for attr in ("status_code", "status"):
            v = getattr(r, attr, None)
            if isinstance(v, int) and not isinstance(v, bool) and 100 <= v < 600:
                return v
    return None


def classify(exc: BaseException) -> str:
    """``not_found``, ``transient`` (worth retrying) or ``fatal``."""
    if isinstance(exc, NotFound):
        return "not_found"
    if isinstance(exc, ConfigError):
        return "fatal"
    st = http_status(exc)
    code = getattr(exc, "code", None) or getattr(exc, "error_code", None)
    name = type(exc).__name__
    if st == 404 or code in ("resource_missing", "NOT_FOUND", "RecordNotFound") or "NotFound" in name:
        return "not_found"
    if st is not None:
        return "transient" if st in (408, 409, 425, 429) or st >= 500 else "fatal"
    if any(s in name for s in ("Timeout", "Connection", "RateLimit", "Temporar", "Unavailable")):
        return "transient"
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return "transient"
    return "fatal"


def error_text(exc: BaseException) -> str:
    st = http_status(exc)
    s = f"{type(exc).__name__}" + (f" (HTTP {st})" if st else "") + f": {exc}"
    return s[:500]


_RETRY_KEYS = {"retries", "backoff", "max_backoff", "sleep"}


def retry_options(opts: Mapping[str, Any]) -> dict[str, Any]:
    """Validate ``retries=0, backoff=0.5, max_backoff=4.0, sleep=time.sleep`` at factory time."""
    unknown = set(opts) - _RETRY_KEYS
    if unknown:
        raise TypeError(f"unknown option(s): {', '.join(sorted(unknown))}")
    retries = opts.get("retries", 0)
    if not isinstance(retries, int) or isinstance(retries, bool) or not 0 <= retries <= 10:
        raise ValueError("retries must be an integer from 0 to 10")
    backoff = float(opts.get("backoff", 0.5))
    max_backoff = float(opts.get("max_backoff", 4.0))
    if backoff < 0 or max_backoff < 0:
        raise ValueError("backoff and max_backoff must be >= 0")
    return {"retries": retries, "backoff": backoff, "max_backoff": max_backoff,
            "sleep": opts.get("sleep") or time.sleep}


def run(method: str, call: Call, response: Any, read: Callable[[Call, Any], Outcome],
        opts: Mapping[str, Any]) -> Outcome:
    """Run ``read`` (which fetches and compares) with bounded retries; never raises.

    Retried, when ``retries > 0``: transient errors, not-found and mismatches (stale reads).
    Not retried: auth/permission/bad-request errors and configuration errors.
    """
    attempts = opts["retries"] + 1
    outcome = Outcome("error", detail="not run", method=method)
    for i in range(attempts):
        try:
            outcome = read(call, response)
            retryable = outcome.check == "mismatch"
        except Exception as exc:  # noqa: BLE001 - a failing check must never break the agent
            kind = classify(exc)
            if kind == "not_found":
                detail = "object not found" + (f" ({exc})" if str(exc) else "")
                outcome = Outcome("mismatch", {"exists": False}, ["exists"], detail[:500], method=method)
                retryable = True
            else:
                prefix = "configuration: " if isinstance(exc, ConfigError) else ""
                outcome = Outcome("error", detail=prefix + error_text(exc), method=method)
                retryable = kind == "transient"
        if outcome.check == "match" or not retryable or i == attempts - 1:
            break
        try:
            opts["sleep"](min(opts["backoff"] * (2 ** i), opts["max_backoff"]))
        except Exception:  # noqa: BLE001
            break
    if attempts > 1 and i > 0:
        note = f"after {i + 1} attempts"
        outcome.detail = f"{outcome.detail}; {note}" if outcome.detail else note
    return outcome


def check_fn(method: str, read: Callable[[Call, Any], Outcome], opts: Mapping[str, Any]
             ) -> Callable[[Call, Any], Outcome]:
    opts = retry_options(opts)

    def verify_outcome(call: Call, response: Any) -> Outcome:
        return run(method, call, response, read, opts)

    verify_outcome.__name__ = method.replace(".", "_")
    verify_outcome.__qualname__ = verify_outcome.__name__
    return verify_outcome


def http_get(client: Any, path: str) -> Any:
    """Call a minimal HTTP client: ``client(path) -> parsed JSON``."""
    if not callable(client):
        raise ConfigError(f"unsupported client {type(client).__name__}: pass an SDK client or a callable "
                          "path -> JSON (see gleipnir.outcomes.json_get)")
    return client(path)
