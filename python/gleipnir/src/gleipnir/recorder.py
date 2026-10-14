"""Recorder: the public API for wrapping agent tool calls."""

from __future__ import annotations

import contextlib
import contextvars
import functools
import hashlib
import hmac
import inspect
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar, Union

from .anchor import Anchor, LocalFileAnchor, RekorAnchor
from .chain import ChainWriter
from .keys import Signer, load_or_create_secret, load_or_create_signer
from .store import JsonlStore, Store
from .util import Clock, iso, new_id, to_jsonable, utcnow

F = TypeVar("F", bound=Callable[..., Any])

_CONTEXT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("gleipnir_context", default=None)
_CONTEXT_KEYS = {"trace_id", "span_id", "session", "on_behalf_of", "run_id", "parent_action"}
_TOP_LEVEL_KEYS = {"model", "versions", "identity"}


# ---- outcomes --------------------------------------------------------------------------
@dataclass
class Outcome:
    """Result of checking the external system after an action.

    ``check`` is one of ``match``, ``mismatch``, ``error`` (the check itself failed) or
    ``not_checked``.
    """

    check: str
    observed: Any = None
    fields: list[str] = field(default_factory=list)
    detail: str | None = None
    method: str = "verify_outcome"

    @classmethod
    def match(cls, observed: Any = None, detail: str | None = None) -> Outcome:
        return cls("match", observed, detail=detail)

    @classmethod
    def mismatch(cls, observed: Any = None, fields: list[str] | None = None, detail: str | None = None) -> Outcome:
        return cls("mismatch", observed, fields or [], detail)

    @classmethod
    def compare(cls, expected: Mapping[str, Any], observed: Mapping[str, Any]) -> Outcome:
        """Compare expected and observed values field by field."""
        diff = sorted(k for k in expected if k not in observed or observed[k] != expected[k])
        if diff:
            return cls("mismatch", dict(observed), diff)
        return cls("match", dict(observed))

    def as_record(self) -> dict[str, Any]:
        d: dict[str, Any] = {"check": self.check, "method": self.method}
        if self.observed is not None:
            d["observed"] = to_jsonable(self.observed)
        if self.fields:
            d["fields"] = list(self.fields)
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class Call:
    """What a ``verify_outcome`` callback receives about the action it checks."""

    action_id: str
    tool: str
    system: str
    args: dict[str, Any]


OutcomeFn = Callable[[Call, Any], Outcome | bool | None]

# ---- redaction ---------------------------------------------------------------------------
RedactionRule = Union[str, Callable[[Any], Any]]  # "drop" | "hmac" | callable
RedactSpec = Union[None, list[str], tuple[str, ...], Mapping[str, RedactionRule]]


class Redactor:
    """Applies field-level redaction before anything is hashed or stored."""

    def __init__(self, hmac_key: bytes | None, default_rule: str = "hmac"):
        self.hmac_key = hmac_key
        self.default_rule = default_rule if hmac_key else "drop"

    def rules(self, spec: RedactSpec) -> dict[str, RedactionRule]:
        if not spec:
            return {}
        if isinstance(spec, Mapping):
            return dict(spec)
        return {name: self.default_rule for name in spec}

    def apply(self, value: Any, rules: Mapping[str, RedactionRule], _depth: int = 0) -> Any:
        if not rules or _depth > 50:
            return value
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if k in rules:
                    red = self._redact(v, rules[k])
                    if red is not _DROP:
                        out[k] = red
                    else:
                        out[k] = {"redacted": "dropped"}
                else:
                    out[k] = self.apply(v, rules, _depth + 1)
            return out
        if isinstance(value, list):
            return [self.apply(v, rules, _depth + 1) for v in value]
        return value

    def _redact(self, value: Any, rule: RedactionRule) -> Any:
        if callable(rule):
            return to_jsonable(rule(value))
        if rule == "drop":
            return _DROP
        if rule == "hmac":
            if not self.hmac_key:
                return _DROP
            from gleipnir_verify.canon import canonicalize

            digest = hmac.new(self.hmac_key, canonicalize(to_jsonable(value)), hashlib.sha256).hexdigest()
            return {"redacted": "hmac-sha256:" + digest}
        raise ValueError(f"unknown redaction rule {rule!r}")


_DROP = object()


# ---- recorder ------------------------------------------------------------------------------
class Recorder:
    """Records agent tool calls as signed, chained, anchorable records.

    Typical use::

        rec = gleipnir.Recorder(agent_id="support-agent", agent_version="3.2.4")

        @rec.tool(system="payments-api", redact=["card_number"], verify_outcome=check_refund)
        def issue_refund(order_id, amount, card_number): ...
    """

    def __init__(
        self,
        agent_id: str,
        agent_version: str,
        *,
        home: str | Path = ".gleipnir",
        chain: str = "default",
        signer: Signer | None = None,
        store: Store | None = None,
        anchor: Anchor | str | None = "local",  # "local", "rekor", an Anchor instance, or None
        segment_max_records: int = 1000,
        heartbeat_seconds: int = 600,
        background: bool = True,
        clock: Clock = utcnow,
        redaction_key: bytes | None = None,
        default_redaction: str = "hmac",
        fsync: bool = True,
        quiet: bool = False,
    ):
        self.agent = {"id": agent_id, "version": agent_version}
        self.home = Path(home)
        self.clock = clock
        signer = signer or load_or_create_signer(self.home, quiet=quiet)
        store = store or JsonlStore(self.home / "chains" / chain, fsync=fsync)
        if anchor == "local":
            anchor = LocalFileAnchor(self.home / "anchors" / "local-anchor-log.jsonl", clock=clock)
        elif anchor == "rekor":
            anchor = RekorAnchor(self.home, clock=clock)
        elif isinstance(anchor, str):
            raise ValueError(f"unknown anchor {anchor!r}; pass an Anchor instance")
        if redaction_key is None:
            redaction_key = load_or_create_secret(self.home, "redaction-hmac.key")
        self.redactor = Redactor(redaction_key, default_redaction)
        self.chain = ChainWriter(
            store, signer, clock=clock, anchor=anchor, segment_max_records=segment_max_records,
            heartbeat_seconds=heartbeat_seconds, background=background,
        )
        self.tools: dict[str, dict[str, Any]] = {}
        self.features: set[str] = set()

    # -- context ---------------------------------------------------------------------------
    @contextlib.contextmanager
    def context(self, **values: Any) -> Iterator[None]:
        """Attach context to every record made inside this block.

        Known keys: trace_id, span_id, session, run_id, on_behalf_of, parent_action, plus
        model={...}, versions={...} (prompt/config/policy) and identity={...}
        (principal, credential_id, scope).
        """
        unknown = set(values) - _CONTEXT_KEYS - _TOP_LEVEL_KEYS
        if unknown:
            raise ValueError(f"unknown context keys: {sorted(unknown)}")
        merged = {**(_CONTEXT.get() or {}), **values}
        token = _CONTEXT.set(merged)
        try:
            yield
        finally:
            _CONTEXT.reset(token)

    def _context_fields(self) -> dict[str, Any]:
        ctx = dict(_CONTEXT.get() or {})
        if "trace_id" not in ctx:
            otel = _otel_ids()
            if otel:
                ctx.update(otel)
        out: dict[str, Any] = {}
        plain = {k: v for k, v in ctx.items() if k in _CONTEXT_KEYS}
        if plain:
            out["context"] = to_jsonable(plain)
        for k in _TOP_LEVEL_KEYS:
            if k in ctx:
                out[k] = to_jsonable(ctx[k])
                self.features.add(k)
        return out

    # -- recording --------------------------------------------------------------------------
    def record_action(
        self,
        *,
        tool: str,
        system: str,
        args: Mapping[str, Any],
        response: Any = None,
        error: BaseException | str | None = None,
        claim: str | None = None,
        outcome: Outcome | None = None,
        start: Any = None,
        end: Any = None,
        redact: RedactSpec = None,
        action_id: str | None = None,
        sources: list[Mapping[str, Any]] | None = None,
        calls: list[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Record one action. Use this directly when a decorator does not fit.

        ``sources``: documents or records the action relied on, e.g. ``[{"type": "kb", "id": "faq-7",
        "version": "3"}]``. ``calls``: outbound services the agent called for this action (model endpoints,
        APIs), e.g. ``[{"service": "provider-a", "endpoint": "chat", "region": "eu"}]``.
        """
        rules = self.redactor.rules(redact)
        now = self.clock()
        fields: dict[str, Any] = {
            "id": action_id or new_id("act"),
            "agent": self.agent,
            "tool": {"name": tool, "system": system},
            "args": self.redactor.apply(to_jsonable(dict(args)), rules),
            "t": {"start": iso(start or now), "end": iso(end or now)},
        }
        if error is not None:
            fields["response"] = {"status": "error", "error": _error_text(error)}
        else:
            fields["response"] = {"status": "ok", "body": self.redactor.apply(to_jsonable(response), rules)}
        if claim:
            fields["claim"] = {"text": claim}
        if outcome is not None:
            fields["outcome"] = outcome.as_record()
        if sources:
            fields["sources"] = to_jsonable([dict(x) for x in sources])
        if calls:
            fields["calls"] = to_jsonable([dict(x) for x in calls])
        if rules:
            fields["redaction"] = {"fields": sorted(rules), "default": self.redactor.default_rule}
        fields.update(self._context_fields())
        return self.chain.append("action", fields)

    def claim(self, action_id: str, text: str) -> dict[str, Any]:
        """Attach the agent's own statement about an action already recorded."""
        return self.chain.append("claim", {"claim": {"action": action_id, "text": text}})

    def review(self, action_id: str, *, reviewer: str, decision: str, rule: str | None = None,
               before_execution: bool | None = None, reason: str | None = None,
               changes: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Record a human review, approval, override or reversal of an action.

        Oversight rules are the buyer's; this records that a rule applied and what the reviewer
        decided. ``decision`` is free text, for example ``approved``, ``rejected``, ``overridden``.
        """
        body: dict[str, Any] = {"action": action_id, "reviewer": reviewer, "decision": decision}
        if rule is not None:
            body["rule"] = rule
        if before_execution is not None:
            body["before_execution"] = before_execution
        if reason:
            body["reason"] = reason
        if changes:
            body["changes"] = to_jsonable(dict(changes))
        return self.chain.append("review", {"review": body})

    def note(self, text: str, **data: Any) -> dict[str, Any]:
        return self.chain.append("note", {"note": {"text": text, **to_jsonable(data)}})

    def tool(
        self,
        fn: F | None = None,
        *,
        system: str,
        name: str | None = None,
        redact: RedactSpec = None,
        verify_outcome: OutcomeFn | None = None,
        claim: Callable[[dict[str, Any], Any], str] | None = None,
    ) -> Any:
        """Decorator that records every call of a tool function.

        The function's behaviour, signature and return value are unchanged. Exceptions are
        recorded and re-raised.
        """

        def decorate(func: F) -> F:
            tool_name = name or func.__name__
            sig = inspect.signature(func)
            self.tools[tool_name] = {"system": system, "verify_outcome": verify_outcome is not None,
                                     "redact": bool(redact)}

            def bind(a: tuple[Any, ...], kw: dict[str, Any]) -> dict[str, Any]:
                try:
                    b = sig.bind(*a, **kw)
                    b.apply_defaults()
                    args = dict(b.arguments)
                    args.pop("self", None)
                    return args
                except TypeError:
                    return {"args": list(a), **kw}

            def finish(action_id: str, args: dict[str, Any], start: Any, result: Any,
                       error: BaseException | None, outcome: Outcome | None = None, end: Any = None) -> None:
                end = end or self.clock()
                if outcome is None and error is None and verify_outcome is not None:
                    outcome = _run_outcome(verify_outcome, Call(action_id, tool_name, system, args), result)
                claim_text = None
                if claim is not None and error is None:
                    try:
                        claim_text = claim(args, result)
                    except Exception:  # noqa: BLE001
                        claim_text = None
                self.record_action(tool=tool_name, system=system, args=args, response=result, error=error,
                                   claim=claim_text, outcome=outcome, start=start, end=end, redact=redact,
                                   action_id=action_id)

            if inspect.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*a: Any, **kw: Any) -> Any:
                    args, start, action_id = bind(a, kw), self.clock(), new_id("act")
                    try:
                        result = await func(*a, **kw)
                    except BaseException as exc:
                        finish(action_id, args, start, None, exc)
                        raise
                    outcome = None
                    end = self.clock()
                    if verify_outcome is not None and inspect.iscoroutinefunction(verify_outcome):
                        try:
                            outcome = _coerce_outcome(
                                await verify_outcome(Call(action_id, tool_name, system, args), result))
                        except Exception as exc:  # noqa: BLE001
                            outcome = Outcome("error", detail=_error_text(exc))
                    finish(action_id, args, start, result, None, outcome, end)
                    return result

                async_wrapper.gleipnir_tool = tool_name  # type: ignore[attr-defined]
                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(func)
            def wrapper(*a: Any, **kw: Any) -> Any:
                args, start, action_id = bind(a, kw), self.clock(), new_id("act")
                try:
                    result = func(*a, **kw)
                except BaseException as exc:
                    finish(action_id, args, start, None, exc)
                    raise
                finish(action_id, args, start, result, None)
                return result

            wrapper.gleipnir_tool = tool_name  # type: ignore[attr-defined]
            return wrapper  # type: ignore[return-value]

        return decorate(fn) if fn is not None else decorate

    # -- lifecycle ---------------------------------------------------------------------------
    def export(self, out: str | Path, *, since: Any = None, until: Any = None) -> Path:
        """Close the open segment, anchor what is pending, and write a verification bundle."""
        from .export import export_bundle

        self.flush()
        anchor = self.chain.anchor
        local_log = anchor.path if isinstance(anchor, LocalFileAnchor) else None
        return export_bundle(self.chain.store.read_all(), out, since=since, until=until,
                             local_anchor_log=local_log)

    def pack(self, out: str | Path, *, since: Any = None, until: Any = None) -> Path:
        """Flush and build a Security Review Pack (summary.html, actions.csv, bundle.zip)."""
        from .pack import build_pack

        self.flush()
        anchor = self.chain.anchor
        local_log = anchor.path if isinstance(anchor, LocalFileAnchor) else None
        return build_pack(self.chain.store.read_all(), out, since=since, until=until, local_anchor_log=local_log)

    def check(self) -> list[Any]:
        """Checklist coverage of the records written so far."""
        from .check import capabilities_from_records, evaluate, load_checklist

        caps, _ = capabilities_from_records(self.chain.store.read_all())
        return evaluate(load_checklist(), caps)

    def flush(self) -> None:
        self.chain.flush()

    def close(self) -> None:
        self.chain.close()

    def __enter__(self) -> Recorder:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @property
    def key_id(self) -> str:
        return self.chain.signer.key_id


def _error_text(error: BaseException | str) -> str:
    if isinstance(error, BaseException):
        return f"{type(error).__name__}: {error}"[:2000]
    return str(error)[:2000]


def _coerce_outcome(value: Any) -> Outcome:
    if isinstance(value, Outcome):
        return value
    if value is True:
        return Outcome.match()
    if value is False:
        return Outcome.mismatch()
    if value is None:
        return Outcome("not_checked")
    raise TypeError("verify_outcome must return Outcome, bool or None")


def _run_outcome(fn: OutcomeFn, call: Call, result: Any) -> Outcome:
    try:
        return _coerce_outcome(fn(call, result))
    except Exception as exc:  # noqa: BLE001 - a failing check must not break the agent
        return Outcome("error", detail=_error_text(exc))


def _otel_ids() -> dict[str, str] | None:
    try:
        from opentelemetry import trace  # type: ignore[import-not-found]
    except ImportError:
        return None
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if not ctx or not ctx.is_valid:
        return None
    return {"trace_id": format(ctx.trace_id, "032x"), "span_id": format(ctx.span_id, "016x")}
