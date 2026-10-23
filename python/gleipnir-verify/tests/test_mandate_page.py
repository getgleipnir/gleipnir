"""site/mandate: a signatory signs a mandate with a passkey in a real browser (virtual authenticator).

The page's output must be accepted by the Python checker exactly as a bank would accept it.
Run with: uv run --with playwright pytest python/gleipnir-verify/tests/test_mandate_page.py
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from kit import DEBTOR, holds

from gleipnir_verify import mandate as M

sync_api = pytest.importorskip("playwright.sync_api")

SITE = Path(__file__).resolve().parents[3] / "site" / "mandate"
BRENNER = {"name": "Brenner Stahl AG", "account": {"scheme": "iban", "iban": "AT611904300234573201"}}


@pytest.fixture(scope="module")
def page_url():
    handler = partial(SimpleHTTPRequestHandler, directory=str(SITE))
    handler.log_message = lambda *a: None  # type: ignore[assignment]
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://localhost:{srv.server_address[1]}/index.html"
    srv.shutdown()


def draft(**kw) -> dict:
    return M.issue(id="m_page", company={"name": "Nordhafen Logistik GmbH", "country": "AT"},
                   agent={"id": "ap-agent", "name": "Accounts payable agent"},
                   scope={"rails": ["sepa"], "currency": "EUR", "max_per_payment": "25000.00", "payees": [BRENNER],
                          "from_accounts": [DEBTOR]},
                   valid_until="2026-12-31T23:59:59.000Z", **kw)


def test_sign_mandate_with_passkey_in_browser(page_url):
    exe = os.environ.get("CHROMIUM", "/opt/pw-browsers/chromium")
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=exe if Path(exe).exists() else None)
        page = browser.new_page()
        cdp = page.context.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
            "isUserVerified": True}})
        page.goto(page_url)
        assert page.title() == "Sign an agent mandate"

        # 1. The signatory creates a passkey; the bank would enroll the public key it prints.
        placeholder = draft(signer={"id": "kberger@nordhafen.at", "public_key": "ed25519:" + "A" * 43})
        page.fill("#draft", json.dumps(placeholder))
        page.dispatch_event("#draft", "change")
        page.click("#register")
        page.wait_for_selector(".status.ok")
        enrolled = json.loads(page.input_value("#out"))
        assert enrolled["public_key"].startswith("ecdsa-p256:") and enrolled["rp_id"] == "localhost"

        # 2. The real mandate names that passkey; the page shows the scope and signs it.
        m = draft(signer={"id": "kberger@nordhafen.at", "role": "Authorised signatory",
                          "public_key": enrolled["public_key"]})
        page.fill("#draft", json.dumps(m))
        page.dispatch_event("#draft", "change")
        text = page.inner_text("#scope-rows")
        assert "Brenner Stahl AG: AT611904300234573201" in text and "up to 25000.00 EUR" in text
        assert "AT483200000012345864" in text  # the account it pays from
        page.click("#sign")
        page.wait_for_selector(".status.ok")
        signed = json.loads(page.input_value("#out"))
        assert signed["sig"]["type"] == "webauthn"

        # 3. A draft with a duplicate key is refused before anything is shown or signed.
        page.fill("#draft", '{"v": "gleipnir/mandate/0.3", "v": "x"}')
        page.dispatch_event("#draft", "change")
        assert 'Duplicate key "v"' in page.inner_text("#draft-error")
        assert page.is_hidden("#summary")
        browser.close()

    # 4. The bank accepts the browser's signature, with its KYB holding the enrolled passkey.
    now = datetime(2026, 10, 23, 9, 14, 2, tzinfo=timezone.utc)
    bank_sk, _ = M.new_key()
    kyb = {"kberger@nordhafen.at": M.AuthorityResult("bank_kyb", (enrolled["public_key"],))}
    checker = M.Checker(id="bank:test", sk=bank_sk, authority=lambda c, pid: kyb.get(pid), clock=lambda: now,
                        holds=holds,
                        webauthn={"rp_id": "localhost", "origins": [page_url.rsplit("/", 1)[0]]})
    pay = M.attach(signed, id="p_1", rail="sepa", amount="100.00", currency="EUR", payee=BRENNER,
                   requested_at=M.fmt_ts(now))
    d = checker.check(signed, pay)
    assert d["outcome"] == "allow", d["reasons"]
