"""Playwright adapter: record what a browser / computer-use agent does on a page.

Browser agents act through human-style logins, so the vendor's own logs ("clicked Submit") are the
only trail. This adapter records each meaningful action on a Playwright page as a signed action
record, with the page URL, the frame, a stable description of the target element and SHA-256
hashes of screenshots taken right before and right after the action.

Works with the sync and the async Playwright API; ``playwright`` itself is not imported.

    from playwright.sync_api import sync_playwright
    from gleipnir.adapters.playwright import instrument_page

    page = browser.new_page()
    instrument_page(page, rec, system="bank-portal", screenshots="store",
                    redact_selectors=["#iban"], record_values=["#search", "country"])
    page.goto("https://portal.example/login")
    page.get_by_label("User").fill("agent-7")          # value recorded as an HMAC, not in clear
    page.get_by_role("button", name="Sign in").click()

What is recorded (``tool.name``):

- ``browser.navigate``: ``goto``, ``reload``, ``go_back``, ``go_forward``, and main-frame
  navigations caused by other actions (``via: "page"``, with ``cause`` = the action in flight, or
  ``after`` = the latest action when none is in flight: links, redirects, scripts).
  Response: final URL and HTTP status.
- ``browser.click`` (click, dblclick, tap, ``mouse.click`` and ``touchscreen.tap`` by coordinates,
  where the target is the element at that point), ``browser.check`` (check/uncheck),
  ``browser.select`` (select_option), ``browser.upload`` (set_input_files: file names, sizes and
  SHA-256, never contents).
- ``browser.fill`` and ``browser.type`` (fill, clear, type, press_sequentially, ``keyboard.type``,
  ``keyboard.insert_text``). The value is redacted by default with the recorder's default rule (HMAC
  with the vendor-held key, so the vendor can later prove what was typed without showing it). Values
  of targets matched by ``record_values`` are recorded in clear. Password fields, ``autocomplete``
  credential / card / one-time-code fields and targets inside ``redact_selectors`` are always
  dropped, allowlisted or not.
- ``browser.press``: key presses that submit (Enter, NumpadEnter, with or without modifiers);
  ``record_keys="all"`` records every press.
- ``browser.submit``: form submissions, reported by a capture-phase ``submit`` listener in the page
  (form action, method, id/name and field *names*, never values), with ``cause`` = the action that
  triggered it. This is reported by the page's own JavaScript (``reported_by: "page"``), so a hostile
  page could report submits that did not happen; treat it as evidence of what the page saw.
- ``browser.download``: ``cause``/``after`` as above, URL, suggested file name, SHA-256 and size of
  the downloaded file, recorded when the download finishes. In the sync API that happens during a
  later Playwright call (``download.path()`` waits for it); a download still running when the browser
  closes is recorded with an error.

URLs: query and fragment parameters are replaced by ``[redacted]`` in every recorded URL when their
name is a common secret name (``password``, ``token``, ``code``, ``access_token``, ...), is listed in
``redact_query``, or is the ``name`` of a field whose value was not recorded in clear (a GET form
puts typed values into the next URL).

Every action carries ``args.page_url``, ``args.frame`` (``{"main": true}`` or the iframe's name and
URL) and ``args.target``: the Playwright selector plus the element's tag, ARIA role, accessible name,
label, id, ``name`` attribute and test id when present (never its value). Grouping: every record
made after a main-frame navigation has ``context.parent_action`` set to that navigation record's
id, so a reviewer can read the run page by page.

Screenshots (``screenshots=``): ``"hash"`` (default) takes a PNG before and after each action and
records only its SHA-256 in ``sources`` as ``{"type": "screenshot", "phase": "before"|"after",
"sha256": ...}``; ``"store"`` also writes the PNG to ``<chain dir>/screenshots/<sha256>.png``
(content-addressed, or ``screenshot_dir``), so it can be handed over and checked against the signed
hash later; ``"none"`` takes none. Password fields and ``redact_selectors`` are masked in the
screenshot before hashing; anything else on screen, including fill values recorded only as an HMAC,
is visible in a stored PNG, so add such fields to ``redact_selectors`` when you store screenshots.
Screenshots add latency to each action.

Outcome checks: ``verify_outcome`` maps URL patterns (``fnmatch`` globs, or compiled regexes) to
sync or async callbacks ``(Call, result) -> Outcome | bool | None``. A callback runs for each action
whose page URL before or after the action matches; ``result`` is the record's response body (for
example ``{"url": ...}``). Returning ``None`` attaches no outcome. Do not use the sync Playwright API
inside a callback; read back from the system of record instead.

Limits: actions through ``ElementHandle`` objects (``page.query_selector(...).click()``) and raw
``mouse.down``/``up`` are not recorded; use locators. The adapter hooks Playwright's internal
client objects (tested with Playwright 1.64); instrumenting fails loudly if they are missing,
recording never breaks a page action.
"""

from __future__ import annotations

import asyncio
import contextvars
import fnmatch
import functools
import hashlib
import inspect
import os
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ..recorder import Call, Outcome, Recorder, _coerce_outcome, _error_text
from ..util import new_id
from ._common import logger

SUBMIT_KEYS = frozenset({"Enter", "NumpadEnter"})
SECRET_PARAMS = ("password", "passwd", "pwd", "pass", "token", "access_token", "id_token", "refresh_token", "code",
                 "secret", "client_secret", "api_key", "apikey", "key", "sig", "signature", "session", "sessionid",
                 "sid", "otp", "auth", "authorization", "jwt", "saml", "samlresponse", "ticket")
_ALWAYS_MASK = ("input[type=password]",)
_ACTIVE: contextvars.ContextVar[bool] = contextvars.ContextVar("gleipnir_playwright_active", default=False)

_DESCRIBE_JS = r"""(el, redact) => {
  if (!el || el.nodeType !== 1) return null;
  const txt = (s) => { s = (s || '').replace(/\s+/g, ' ').trim(); return s ? s.slice(0, 120) : null; };
  const tag = el.tagName.toLowerCase();
  const type = (el.getAttribute('type') || '').toLowerCase();
  const INPUT_ROLES = {button: 'button', submit: 'button', reset: 'button', image: 'button',
    checkbox: 'checkbox', radio: 'radio', range: 'slider', number: 'spinbutton', search: 'searchbox'};
  let role = el.getAttribute('role');
  if (!role) {
    if (tag === 'a' && el.hasAttribute('href')) role = 'link';
    else if (tag === 'button') role = 'button';
    else if (tag === 'input') role = type === 'hidden' ? null : (INPUT_ROLES[type] || 'textbox');
    else if (tag === 'textarea') role = 'textbox';
    else if (tag === 'select') role = (el.multiple || el.size > 1) ? 'listbox' : 'combobox';
    else if (/^h[1-6]$/.test(tag)) role = 'heading';
    else if (tag === 'img') role = 'img';
    else if (tag === 'form') role = 'form';
    else if (tag === 'option') role = 'option';
  }
  const label = el.labels && el.labels.length
    ? txt(Array.from(el.labels).map(l => l.textContent).join(' ')) : null;
  const lb = el.getAttribute('aria-labelledby');
  const byId = lb
    ? txt(lb.split(/\s+/).map(i => (document.getElementById(i) || {}).textContent || '').join(' ')) : null;
  const isField = (tag === 'input' && !['button', 'submit', 'reset', 'image'].includes(type))
    || tag === 'textarea' || tag === 'select';
  let name = txt(el.getAttribute('aria-label')) || byId || label;
  if (!name && !isField) name = txt(tag === 'input' ? el.value : (el.innerText || el.textContent));
  if (!name) name = txt(el.getAttribute('alt')) || txt(el.getAttribute('title')) || txt(el.getAttribute('placeholder'));
  const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
  const out = {tag: tag};
  if (role) out.role = role;
  if (name) out.name = name;
  if (label) out.label = label;
  if (el.id) out.id = el.id;
  const field = el.getAttribute('name'); if (field) out.field = field;
  if (type) out.type = type;
  const tid = el.getAttribute('data-testid'); if (tid) out.testid = tid;
  if (type === 'password' || /(^|\s)(cc-|one-time-code|current-password|new-password)/.test(ac)) out.sensitive = true;
  const w = el.ownerDocument && el.ownerDocument.defaultView;
  if (w && w !== w.top) { out.__frame = {main: false, url: w.location.href}; if (w.name) out.__frame.name = w.name; }
  if ((redact || []).some(s => { try { return !!el.closest(s); } catch (e) { return false; } })) out.redacted = true;
  return out;
}"""

_SUBMIT_JS = r"""(() => {
  const name = %s;
  if (window['__gleipnir_hooked_' + name]) return;
  window['__gleipnir_hooked_' + name] = true;
  document.addEventListener('submit', (e) => {
    try {
      const f = e.target, s = e.submitter;
      const fields = Array.from(f.elements || []).map(x => x.name).filter(Boolean).slice(0, 100);
      const info = {action: f.action || null, method: (f.method || 'get').toLowerCase(), fields: fields};
      if (f.id) info.id = f.id;
      if (f.getAttribute('name')) info.name = f.getAttribute('name');
      if (s) info.submitter = (s.getAttribute('aria-label') || s.textContent || s.value || s.name || '')
        .trim().slice(0, 120);
      if (typeof window[name] === 'function') window[name](info);
    } catch (err) {}
  }, true);
})()"""


def instrument_page(
    page: Any,
    recorder: Recorder,
    *,
    system: str,
    screenshots: str = "hash",
    redact_selectors: Sequence[str] = (),
    record_values: Sequence[str] = (),
    record_keys: str = "submit",
    redact_query: Sequence[str] = (),
    verify_outcome: Mapping[Any, Callable[[Call, Any], Any]] | None = None,
    screenshot_dir: str | Path | None = None,
    screenshot_timeout_ms: float = 5000,
    follow_popups: bool = True,
) -> Any:
    """Record actions on a Playwright ``Page`` (sync or async API) in place and return the page.

    ``record_values``: ``fnmatch`` patterns matched against the target's selector, id, ``name``
    attribute, label and accessible name; matching fill/type values are recorded in clear.
    ``follow_popups``: pages opened by this page (``target=_blank``, ``window.open``) are
    instrumented with the same settings.
    """
    if screenshots not in ("hash", "none", "store"):
        raise ValueError("screenshots must be 'hash', 'none' or 'store'")
    if record_keys not in ("submit", "all"):
        raise ValueError("record_keys must be 'submit' or 'all'")
    impl = getattr(page, "_impl_obj", page)
    if not hasattr(impl, "_main_frame") or not hasattr(impl, "keyboard"):
        raise TypeError("instrument_page expects a playwright Page (sync or async API)")
    if getattr(impl, "_gleipnir", None) is not None:
        return page
    if screenshot_dir is None:
        screenshot_dir = Path(getattr(recorder.chain.store, "directory", recorder.home)) / "screenshots"
    _PageRecorder(impl, recorder, dict(
        system=system, screenshots=screenshots, redact_selectors=list(redact_selectors),
        record_values=list(record_values), record_keys=record_keys,
        secret_params={n.lower() for n in (*SECRET_PARAMS, *redact_query)}, verify_outcome=dict(verify_outcome or {}),
        screenshot_dir=Path(screenshot_dir), screenshot_timeout_ms=screenshot_timeout_ms,
        follow_popups=follow_popups))
    return page


class _PageRecorder:
    def __init__(self, page: Any, recorder: Recorder, config: dict[str, Any]):
        self.page = page
        self.recorder = recorder
        self.config = config
        self.system = config["system"]
        self.redact_selectors: list[str] = config["redact_selectors"]
        self.masks = list(_ALWAYS_MASK) + self.redact_selectors
        self.group: str | None = None       # id of the latest main-frame navigation record
        self.current: str | None = None     # id of the action in flight
        self.last: str | None = None        # id of the latest action started
        self.nav_action: str | None = None  # id of the goto/reload/back/forward in flight
        self.binding = "__gleipnir_" + os.urandom(6).hex()
        self._setup: Any = None
        self._tasks: set[Any] = set()
        page._gleipnir = self
        for frame in page.frames:
            self._wrap_frame(frame)
        page.on("frameattached", self._wrap_frame)
        page.on("framenavigated", self._on_navigated)
        page.on("download", self._on_download)
        if config["follow_popups"]:
            page.on("popup", self._on_popup)
        for name, via in (("reload", "reload"), ("go_back", "back"), ("go_forward", "forward")):
            self._wrap(page, name, "navigate", page.main_frame, via=via)
        self._wrap(page.keyboard, "press", "key_press", None)
        self._wrap(page.keyboard, "type", "key_type", None)
        self._wrap(page.keyboard, "insert_text", "key_type", None)
        self._wrap(page.mouse, "_click", "point_click", None)
        self._wrap(page.touchscreen, "tap", "point_click", None, method="tap")

    # -- hooking --------------------------------------------------------------------------------
    def _wrap_frame(self, frame: Any) -> None:
        if getattr(frame, "_gleipnir_wrapped", False):
            return
        frame._gleipnir_wrapped = True
        # public and private entry points: Locator calls the private ones, Page the public ones; a call
        # that reaches both is recorded once (see _ACTIVE)
        for name, kind in (("goto", "navigate"), ("click", "click"), ("_click", "click"),
                           ("dblclick", "click"), ("tap", "click"), ("fill", "fill"), ("_fill", "fill"),
                           ("type", "type"), ("press", "press"), ("check", "check"), ("uncheck", "check"),
                           ("select_option", "select"), ("set_input_files", "upload")):
            self._wrap(frame, name, kind, frame, method=name)

    def _wrap(self, obj: Any, name: str, kind: str, frame: Any, **extra: Any) -> None:
        orig = getattr(obj, name, None)
        if orig is None:
            return
        try:
            sig = inspect.signature(orig)
        except (TypeError, ValueError):
            return

        @functools.wraps(orig)
        async def wrapper(*a: Any, **kw: Any) -> Any:
            if _ACTIVE.get():
                return await orig(*a, **kw)
            try:
                params = dict(sig.bind(*a, **kw).arguments)
            except TypeError:
                return await orig(*a, **kw)
            return await self._perform(kind, frame, {**extra, **params}, lambda: orig(*a, **kw))

        setattr(obj, name, wrapper)

    # -- recording -------------------------------------------------------------------------------
    async def _perform(self, kind: str, frame: Any, p: dict[str, Any], invoke: Callable[[], Any]) -> Any:
        try:
            plan = await self._plan(kind, frame, p)
        except Exception:  # noqa: BLE001 - never break the agent
            logger.exception("gleipnir: failed to describe a %s action", kind)
            plan = None
        if plan is None:
            return await invoke()

        action_id = new_id("act")
        is_main_nav = plan["tool"] == "browser.navigate" and _is_main(plan["frame_obj"])
        before = await self._screenshot("before")
        prev_current, prev_nav = self.current, self.nav_action
        self.current = self.last = action_id
        if is_main_nav:
            self.nav_action = action_id
        start = self.recorder.clock()
        result: Any = None
        error: BaseException | None = None
        token = _ACTIVE.set(True)  # nested Playwright calls inside this one are part of it
        try:
            result = await invoke()
        except BaseException as exc:  # noqa: BLE001 - recorded, then re-raised
            error = exc
        finally:
            _ACTIVE.reset(token)
            self.current, self.nav_action = prev_current, prev_nav
        end = self.recorder.clock()
        try:
            after = await self._screenshot("after") if not self.page.is_closed() else None
            body = self._response(plan, result)
            outcome = None
            if error is None:
                outcome = await self._check(Call(action_id, plan["tool"], self.system, plan["raw_args"]), body,
                                            plan["args"].get("page_url"))
            parent = None if is_main_nav else plan["group"]
            self._record(plan["tool"], plan["args"], body, error, start, end, action_id, plan["redact"],
                         parent, outcome, [s for s in (before, after) if s])
        except Exception:  # noqa: BLE001
            logger.exception("gleipnir: failed to record a %s action", kind)
        if error is not None:
            raise error
        return result

    async def _plan(self, kind: str, frame: Any, p: dict[str, Any]) -> dict[str, Any] | None:
        """What to record for one call, or None when the call is not recorded."""
        if p.get("trial"):  # actionability check only, nothing happens on the page
            return None
        if kind in ("press", "key_press") and self.config["record_keys"] == "submit":
            if str(p.get("key", "")).split("+")[-1] not in SUBMIT_KEYS:
                return None
        await self._ensure_setup()
        group = self.group
        target_frame = frame or self.page.main_frame
        args: dict[str, Any] = {"page_url": self.page.url, "frame": _frame_info(target_frame)}
        selector = p.get("selector")
        target: dict[str, Any] | None = None
        if selector is not None:
            target = {"selector": str(selector), **(await self._describe(target_frame, selector, p.get("strict")))}
        elif kind == "point_click":
            target = {"point": {"x": p.get("x"), "y": p.get("y")}, **(await self._describe_point(p))}
        elif kind in ("key_press", "key_type"):
            target = {"focused": True, **(await self._describe_focused())}
        if target is not None:
            inner = target.pop("__frame", None)
            if isinstance(inner, dict) and args["frame"].get("main"):  # reached through frame_locator
                args["frame"] = inner
            args["target"] = target

        tool, redact = "browser." + kind, None
        if kind == "navigate":
            tool = "browser.navigate"
            args["via"] = p.get("via", "goto")
            if p.get("url") is not None:
                args["url"] = str(p["url"])
        elif kind in ("click", "point_click"):
            tool = "browser.click"
            method = p.get("method")
            if method in ("dblclick", "tap"):
                args["gesture"] = method
            for key, name in (("button", "button"), ("clickCount", "click_count"), ("modifiers", "modifiers"),
                              ("position", "position")):
                if p.get(key) is not None:
                    args[name] = p[key]
        elif kind in ("fill", "type", "key_type"):
            tool = "browser.fill" if kind == "fill" else "browser.type"
            key = "value" if kind == "fill" else "text"
            args[key] = p.get("value") if kind == "fill" else p.get("text")
            if p.get("title"):
                args["gesture"] = str(p["title"]).lower()
            redact = self._value_rule(target, key)
            if redact is not None and target and target.get("field"):
                self.config["secret_params"].add(str(target["field"]).lower())
        elif kind in ("press", "key_press"):
            tool = "browser.press"
            args["key"] = p.get("key")
        elif kind == "check":
            args["checked"] = p.get("method") == "check"
        elif kind == "select":
            chosen = {k: _plain(p[k]) for k in ("value", "label", "index") if p.get(k) is not None}
            if p.get("element") is not None:
                chosen["element"] = True
            args["values"] = chosen
            if target and (target.get("sensitive") or target.get("redacted")):
                redact = {"values": "drop"}
                if target.get("field"):
                    self.config["secret_params"].add(str(target["field"]).lower())
        elif kind == "upload":
            args["files"] = _describe_files(p.get("files"))
        return {"tool": tool, "args": args, "raw_args": dict(args), "redact": redact, "group": group,
                "frame_obj": target_frame}

    def _value_rule(self, target: dict[str, Any] | None, key: str) -> Any:
        if target and (target.get("sensitive") or target.get("redacted")):
            return {key: "drop"}
        if target and self.config["record_values"]:
            names = [target.get(k) for k in ("selector", "id", "field", "label", "name")]
            for pattern in self.config["record_values"]:
                if any(isinstance(n, str) and fnmatch.fnmatchcase(n, pattern) for n in names):
                    return None
        return [key]

    def _response(self, plan: dict[str, Any], result: Any) -> dict[str, Any]:
        body: dict[str, Any] = {"url": self.page.url if not self.page.is_closed() else None}
        if plan["tool"] == "browser.navigate" and result is not None:
            status = getattr(result, "status", None)
            if status is not None:
                body["status"] = status
        if plan["tool"] == "browser.select" and isinstance(result, list):
            body["values"] = list(result)
        return body

    def _record(self, tool: str, args: dict[str, Any], body: Any, error: Any, start: Any, end: Any,
                action_id: str, redact: Any, parent: str | None, outcome: Outcome | None = None,
                shots: list[dict[str, Any]] | None = None) -> None:
        ctx = {"parent_action": parent} if parent else {}
        args, body = self._scrub(args), self._scrub(body)
        with self.recorder.context(**ctx):
            self.recorder.record_action(tool=tool, system=self.system, args=args, response=body, error=error,
                                        outcome=outcome, start=start, end=end, redact=redact,
                                        action_id=action_id, sources=shots or None)

    def _scrub(self, value: Any) -> Any:
        """Copy of args/body with secret URL parameters replaced."""
        if not isinstance(value, dict):
            return value
        out = dict(value)
        for k in ("url", "page_url"):
            if isinstance(out.get(k), str):
                out[k] = scrub_url(out[k], self.config["secret_params"])
        if isinstance(out.get("frame"), dict) and isinstance(out["frame"].get("url"), str):
            out["frame"] = {**out["frame"], "url": scrub_url(out["frame"]["url"], self.config["secret_params"])}
        if isinstance(out.get("form"), dict) and isinstance(out["form"].get("action"), str):
            out["form"] = {**out["form"], "action": scrub_url(out["form"]["action"], self.config["secret_params"])}
        return out

    async def _check(self, call: Call, body: dict[str, Any], url_before: str | None) -> Outcome | None:
        urls = [u for u in (url_before, body.get("url")) if isinstance(u, str)]
        for pattern, fn in self.config["verify_outcome"].items():
            matched = any(pattern.search(u) if isinstance(pattern, re.Pattern) else fnmatch.fnmatchcase(u, pattern)
                          for u in urls)
            if not matched:
                continue
            token = _ACTIVE.set(True)
            try:
                value = fn(call, body)
                if inspect.isawaitable(value):
                    value = await value
                return None if value is None else _coerce_outcome(value)
            except Exception as exc:  # noqa: BLE001 - a failing check must not break the agent
                return Outcome("error", detail=_error_text(exc))
            finally:
                _ACTIVE.reset(token)
        return None

    # -- page helpers -----------------------------------------------------------------------------
    async def _ensure_setup(self) -> None:
        if self._setup is None:
            self._setup = asyncio.ensure_future(self._do_setup())
        await asyncio.shield(self._setup)

    async def _do_setup(self) -> None:
        script = _SUBMIT_JS % ("'" + self.binding + "'")
        try:
            await self.page.expose_binding(self.binding, self._on_submit)
            await self.page.add_init_script(script=script)
        except Exception:  # noqa: BLE001
            logger.exception("gleipnir: could not install the form-submit listener")
            return
        for frame in self.page.frames:
            try:
                await frame.evaluate(script)
            except Exception:  # noqa: BLE001 - detached or navigating frame
                pass

    async def _describe(self, frame: Any, selector: Any, strict: Any) -> dict[str, Any]:
        try:
            info = await frame.eval_on_selector(str(selector), _DESCRIBE_JS, self.redact_selectors,
                                                strict=bool(strict) or None)
        except Exception:  # noqa: BLE001 - element not attached yet, or several matches
            return {}
        return info if isinstance(info, dict) else {}

    async def _describe_point(self, p: Mapping[str, Any]) -> dict[str, Any]:
        expr = f"([x, y, r]) => ({_DESCRIBE_JS})(document.elementFromPoint(x, y), r)"
        try:
            info = await self.page.main_frame.evaluate(expr, [p.get("x"), p.get("y"), self.redact_selectors])
        except Exception:  # noqa: BLE001
            return {}
        return info if isinstance(info, dict) else {}

    async def _describe_focused(self) -> dict[str, Any]:
        expr = f"(r) => ({_DESCRIBE_JS})(document.activeElement, r)"
        try:
            info = await self.page.main_frame.evaluate(expr, self.redact_selectors)
        except Exception:  # noqa: BLE001
            return {}
        return info if isinstance(info, dict) else {}

    async def _screenshot(self, phase: str) -> dict[str, Any] | None:
        mode = self.config["screenshots"]
        if mode == "none":
            return None
        try:
            masks = [self.page.locator(s) for s in self.masks]
            data = await self.page.screenshot(mask=masks, timeout=self.config["screenshot_timeout_ms"])
        except Exception as exc:  # noqa: BLE001 - closed page, timeout
            return {"type": "screenshot", "phase": phase, "error": _error_text(exc)[:200]}
        digest = hashlib.sha256(data).hexdigest()
        if mode == "store":
            try:
                _store_blob(self.config["screenshot_dir"], digest, data)
            except Exception:  # noqa: BLE001
                logger.exception("gleipnir: could not store screenshot")
        return {"type": "screenshot", "phase": phase, "sha256": digest, "media_type": "image/png"}

    # -- page events (run on Playwright's event loop; must not raise) -------------------------------
    def _on_navigated(self, frame: Any) -> None:
        try:
            if not _is_main(frame):
                return
            if self.nav_action is not None:
                self.group = self.nav_action
                return
            action_id = new_id("act")
            args: dict[str, Any] = {"url": frame.url, "via": "page", "frame": {"main": True}}
            args.update(self._cause())
            self._record("browser.navigate", args, {"url": frame.url}, None, None, None, action_id, None, None)
            self.group = action_id
        except Exception:  # noqa: BLE001
            logger.exception("gleipnir: failed to record a navigation")

    def _on_submit(self, source: Any, info: Any = None) -> None:
        try:
            frame = source.get("frame") if isinstance(source, Mapping) else None
            form = _bounded(info) if isinstance(info, Mapping) else {}
            args: dict[str, Any] = {"page_url": self.page.url, "frame": _frame_info(frame), "form": form,
                                    "reported_by": "page"}
            args.update(self._cause())
            self._record("browser.submit", args, None, None, None, None, new_id("act"), None, self.group)
        except Exception:  # noqa: BLE001
            logger.exception("gleipnir: failed to record a form submit")

    def _on_download(self, download: Any) -> None:
        try:
            task = asyncio.ensure_future(self._record_download(download, self._cause(), self.group,
                                                               self.recorder.clock()))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        except Exception:  # noqa: BLE001
            logger.exception("gleipnir: failed to watch a download")

    def _cause(self) -> dict[str, str]:
        """``cause``: the action in flight when a page event arrived; else ``after``: the latest action."""
        if self.current:
            return {"cause": self.current}
        return {"after": self.last} if self.last else {}

    async def _record_download(self, download: Any, cause: dict[str, str], group: str | None, start: Any) -> None:
        args: dict[str, Any] = {"url": download.url, "filename": download.suggested_filename,
                                "page_url": self.page.url}
        args.update(cause)
        body: dict[str, Any] | None = None
        error: str | None = None
        try:
            path = await download.path()
            error = await download.failure()
            if error is None:
                digest, size = await asyncio.get_running_loop().run_in_executor(None, _hash_file, Path(path))
                body = {"sha256": digest, "size": size}
        except Exception as exc:  # noqa: BLE001 - remote browser, cancelled, page closed
            error = _error_text(exc)
        try:
            self._record("browser.download", args, body, error, start, None, new_id("act"), None, group)
        except Exception:  # noqa: BLE001
            logger.exception("gleipnir: failed to record a download")

    def _on_popup(self, popup: Any) -> None:
        try:
            if getattr(popup, "_gleipnir", None) is None:
                _PageRecorder(popup, self.recorder, self.config)
        except Exception:  # noqa: BLE001
            logger.exception("gleipnir: failed to instrument a popup")


def scrub_url(url: str, secret: set[str] | frozenset[str]) -> str:
    """Replace the values of secret query / fragment parameters (and URL passwords) with ``[redacted]``."""
    try:
        from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

        parts = urlsplit(url)
        netloc = parts.netloc
        if "@" in netloc:
            creds, host = netloc.rsplit("@", 1)
            netloc = (creds.split(":", 1)[0] + ":[redacted]@" + host) if ":" in creds else netloc

        def clean(qs: str) -> str:
            if "=" not in qs:
                return qs
            pairs = parse_qsl(qs, keep_blank_values=True)
            if not any(k.lower() in secret for k, _ in pairs):
                return qs
            return urlencode([(k, "[redacted]" if k.lower() in secret else v) for k, v in pairs],
                             quote_via=quote, safe="[]")

        return urlunsplit((parts.scheme, netloc, parts.path, clean(parts.query), clean(parts.fragment)))
    except Exception:  # noqa: BLE001 - malformed URL: keep scheme and host only
        return url.split("?", 1)[0].split("#", 1)[0]


def _is_main(frame: Any) -> bool:
    return frame is not None and getattr(frame, "parent_frame", None) is None


def _frame_info(frame: Any) -> dict[str, Any]:
    if frame is None or _is_main(frame):
        return {"main": True}
    info: dict[str, Any] = {"main": False, "url": getattr(frame, "url", None)}
    if getattr(frame, "name", None):
        info["name"] = frame.name
    return info


def _plain(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value if isinstance(value, (str, int, float, bool)) else {"repr": type(value).__name__}


def _bounded(value: Any, depth: int = 0) -> Any:
    """Page-supplied data, size-limited."""
    if depth > 3:
        return None
    if isinstance(value, Mapping):
        return {str(k)[:64]: _bounded(v, depth + 1) for k, v in list(value.items())[:20]}
    if isinstance(value, (list, tuple)):
        return [_bounded(v, depth + 1) for v in value[:100]]
    if isinstance(value, str):
        return value[:500]
    return value if isinstance(value, (int, float, bool)) or value is None else str(value)[:100]


def _describe_files(files: Any) -> list[dict[str, Any]]:
    items = files if isinstance(files, (list, tuple)) else [files]
    out = []
    for f in items:
        try:
            if isinstance(f, Mapping):  # FilePayload
                buf = f.get("buffer") or b""
                out.append({"name": f.get("name"), "media_type": f.get("mimeType"), "size": len(buf),
                            "sha256": hashlib.sha256(buf).hexdigest()})
            else:
                path = Path(f)
                if path.is_file():
                    digest, size = _hash_file(path)
                    out.append({"name": path.name, "size": size, "sha256": digest})
                else:
                    out.append({"name": path.name})
        except Exception:  # noqa: BLE001
            out.append({"name": str(getattr(f, "name", "?"))})
    return out


def _hash_file(path: Path) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _store_blob(directory: Path, digest: str, data: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{digest}.png"
    if target.exists():
        return
    tmp = directory / f".{digest}.{os.getpid()}.tmp"
    tmp.write_bytes(data)
    os.replace(tmp, target)
