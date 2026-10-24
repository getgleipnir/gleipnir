"""site/demo (getgleipnir.com/demo): the four-step sales demo, in a real browser, under the production CSP.

Desktop signs with a passkey (virtual authenticator); the phone has none and falls back to a demo key. Both run
all four steps: CFO signs, the agent's payment is allowed with a receipt, the altered IBAN is blocked
(payee_not_on_mandate), the revoked mandate is blocked (mandate_revoked). Any CSP violation or console error fails.

Run with: uv run --with playwright pytest python/gleipnir-verify/tests/test_demo_page.py
Screenshots go to $DEMO_SHOTS if set.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

ROOT = Path(__file__).resolve().parents[3]
DEMO = ROOT / "site" / "demo"
SITE_CSS = Path(__file__).resolve().parent / "fixtures" / "site" / "site.css"  # snapshot of getgleipnir.com
# getgleipnir.com's headers (Netlify _headers), verbatim.
HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; "
    "frame-ancestors 'none'; upgrade-insecure-requests",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
TYPES = {".html": "text/html; charset=UTF-8", ".css": "text/css; charset=UTF-8",
         ".js": "text/javascript; charset=UTF-8"}
SHOTS = os.environ.get("DEMO_SHOTS")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        files = {"/demo/": DEMO / "index.html", "/demo/index.html": DEMO / "index.html",
                 "/demo/demo.css": DEMO / "demo.css", "/demo/demo.js": DEMO / "demo.js", "/assets/site.css": SITE_CSS}
        f = files.get(path)
        if f is None:
            self.send_response(404)
            for k, v in HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            return
        body = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", TYPES[f.suffix])
        self.send_header("Content-Length", str(len(body)))
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def base_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://localhost:{srv.server_address[1]}"
    srv.shutdown()


WATCH = """
window.__violations = [];
document.addEventListener('securitypolicyviolation',
  e => window.__violations.push(e.violatedDirective + ' ' + e.blockedURI));
"""


def run_demo(page, shots: dict[int, str]) -> dict:
    """Click through all four steps; returns what the bank showed and how long each step took."""
    errors: list[str] = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    seen: dict = {"times": []}
    assert page.inner_text("#next") == "Start the demo →"
    assert page.inner_text("#outcome") == "waiting"
    t_all = time.monotonic()
    expected = {1: None, 2: "ALLOW", 3: "BLOCK", 4: "BLOCK"}
    for step in range(1, 5):
        t = time.monotonic()
        page.click("#next")
        page.wait_for_selector(f'#main[data-step="{step}"]', timeout=15000)
        seen["times"].append(round(time.monotonic() - t, 2))
        assert page.is_enabled("#next")
        if expected[step]:
            assert page.inner_text("#outcome") == expected[step], step
        seen[step] = {"checks": page.inner_text("#checks"), "result": page.inner_text("#result"),
                      "json": json.loads(page.text_content("#json-full")), "badge": page.inner_text("#key-badge")}
        assert "Something went wrong" not in seen[step]["result"]
        # every line the bank shows is on screen (no class collides with site.css)
        boxes = page.eval_on_selector_all("#checks li", "els => els.map(e => e.getBoundingClientRect().left)")
        assert all(x >= 0 for x in boxes), boxes
        if step in shots:
            page.screenshot(path=shots[step], full_page=True)
    seen["total"] = round(time.monotonic() - t_all, 2)
    assert page.inner_text("#next") == "Start over"
    assert page.evaluate("window.__violations") == [], page.evaluate("window.__violations")
    assert errors == [], errors
    return seen


def check_story(seen: dict, how: str) -> None:
    m = seen[1]["json"]
    assert m["v"] == "gleipnir/mandate/0.4"
    assert m["signer"]["id"] == "k.berger@nordhafen.at" and m["signer"]["role"] == "CFO"
    assert m["scope"]["max_per_payment"] == "25000.00" and m["scope"]["currency"] == "EUR"
    assert m["scope"]["payees"] == [{"name": "Brenner Stahl AG",
                                     "account": {"scheme": "iban", "iban": "AT611904300234573201"}}]
    assert m["valid_until"].endswith("-12-31T23:59:59.000Z")
    if how == "passkey":
        assert m["sig"]["type"] == "webauthn" and m["signer"]["public_key"].startswith("ecdsa-p256:")
        assert seen[1]["badge"] == "Signed with passkey"
    else:
        assert m["sig"].startswith("ed25519:") and seen[1]["badge"] == "Signed with a demo key"
    d2 = seen[2]["json"]
    assert d2["outcome"] == "allow" and d2["reasons"] == [] and d2["payment"]["id"] == "INV-2026-0912"
    assert d2["sig"].startswith("ed25519:") and d2["signers"][0]["id"] == "k.berger@nordhafen.at"
    assert "Receipt verifies offline" in seen[2]["checks"] and "Within €25,000 per payment" in seen[2]["checks"]
    d3 = seen[3]["json"]
    assert d3["outcome"] == "block" and d3["reasons"] == ["payee_not_on_mandate"]
    assert "DE44" in seen[3]["checks"] and "Stopped" in seen[3]["result"]
    d4 = seen[4]["json"]
    assert d4["outcome"] == "block" and d4["reasons"] == ["mandate_revoked"] and d4["payment"]["id"] == "INV-2026-0914"
    assert "revoked by K. Berger" in seen[4]["checks"]
    assert seen[4]["checks"].count("(not reached)") == 2


def launch(p):
    exe = os.environ.get("CHROMIUM", "/opt/pw-browsers/chromium")
    return p.chromium.launch(executable_path=exe if Path(exe).exists() else None)


def test_demo_desktop_with_passkey(base_url):
    with sync_api.sync_playwright() as p:
        browser = launch(p)
        ctx = browser.new_context(viewport={"width": 1366, "height": 900})
        ctx.add_init_script(WATCH)
        page = ctx.new_page()
        cdp = ctx.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
            "isUserVerified": True}})
        page.goto(base_url + "/demo/")
        assert page.title() == "Live demo · Gleipnir"
        # two columns side by side
        a, b = page.locator(".demo-copy").bounding_box(), page.locator(".demo-bank").bounding_box()
        assert b["x"] > a["x"] + a["width"] - 1
        shots = {2: f"{SHOTS}/demo-desktop-2-allow.png", 3: f"{SHOTS}/demo-desktop-3-block.png"} if SHOTS else {}
        seen = run_demo(page, shots)
        check_story(seen, "passkey")
        # a second run reuses the passkey created in the first
        page.click("#next")
        page.wait_for_selector('#main[data-step="0"]')
        check_story(run_demo(page, {}), "passkey")
        print(f"\ndesktop step times {seen['times']} total {seen['total']}s")
        browser.close()


def test_demo_phone_without_passkey(base_url):
    with sync_api.sync_playwright() as p:
        browser = launch(p)
        phone = {k: v for k, v in p.devices["iPhone 13"].items() if k != "default_browser_type"}
        ctx = browser.new_context(**phone)
        ctx.add_init_script(WATCH)
        page = ctx.new_page()
        page.goto(base_url + "/demo/")
        a, b = page.locator(".demo-copy").bounding_box(), page.locator(".demo-bank").bounding_box()
        assert b["y"] >= a["y"] + a["height"] - 1  # stacked
        shots = {4: f"{SHOTS}/demo-phone-4-revoked.png"} if SHOTS else {}
        seen = run_demo(page, shots)
        check_story(seen, "demo key")
        width = page.evaluate("[document.documentElement.scrollWidth, window.innerWidth]")
        assert width[0] <= width[1], width  # no horizontal scroll
        print(f"\nphone step times {seen['times']} total {seen['total']}s")
        browser.close()
