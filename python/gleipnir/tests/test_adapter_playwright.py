import hashlib
import shutil
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("playwright")

from playwright.async_api import async_playwright  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

import gleipnir  # noqa: E402
from gleipnir.adapters.playwright import instrument_page  # noqa: E402
from gleipnir_verify import verify_bundle  # noqa: E402

FORM = b"""<!doctype html><html><head><title>Refund portal</title></head><body>
<h1>Issue refund</h1>
<form id="refund" name="refund" action="/done" method="get">
  <label for="order">Order id</label><input id="order" name="order">
  <label for="amount">Amount</label><input id="amount" name="amount">
  <label for="pw">Password</label><input id="pw" name="pw" type="password">
  <label for="iban">IBAN</label><input id="iban" name="iban">
  <label for="reason">Reason</label>
  <select id="reason" name="reason"><option value="damaged">Damaged</option><option value="late">Late</option></select>
  <label><input type="checkbox" id="notify" name="notify"> Notify customer</label>
  <button type="submit">Submit refund</button>
</form>
<a href="/report.csv" download>Download report</a>
<iframe name="side" src="/side.html"></iframe>
</body></html>"""
SIDE = b"<!doctype html><html><body><button onclick=\"this.textContent='done'\">Confirm in frame</button></body></html>"
DONE = b"<!doctype html><html><body><h1>Refund booked</h1></body></html>"
REPORT = b"order,amount\nA-1,4210\n"


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        pages = {"/": (FORM, "text/html"), "/side.html": (SIDE, "text/html"), "/done": (DONE, "text/html"),
                 "/report.csv": (REPORT, "text/csv")}
        if path not in pages:
            self.send_error(404)
            return
        body, ctype = pages[path]
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if path == "/report.csv":
            self.send_header("Content-Disposition", 'attachment; filename="report.csv"')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _launch_options():
    for name in ("chromium", "chromium-browser", "google-chrome"):
        path = shutil.which(name)
        if path:
            return {"executable_path": path}
    return None


def launch_sync(p):
    try:
        return p.chromium.launch()
    except Exception as exc:  # browsers not downloaded
        opts = _launch_options()
        if opts is None:
            pytest.skip(f"no chromium available: {exc}")
        return p.chromium.launch(**opts)


async def launch_async(p):
    try:
        return await p.chromium.launch()
    except Exception as exc:
        opts = _launch_options()
        if opts is None:
            pytest.skip(f"no chromium available: {exc}")
        return await p.chromium.launch(**opts)


def actions(rec):
    return [r for r in rec.chain.store.read_all() if r["kind"] == "action"]


def shots(a):
    return {s["phase"]: s for s in a.get("sources", []) if s.get("type") == "screenshot"}


def test_sync_form_flow(rec, server, tmp_path):
    checked = []

    def booked(call, result):
        checked.append((call.tool, result["url"]))
        return gleipnir.Outcome.match({"page": "done"}) if "/done" in result["url"] else None

    with sync_playwright() as p:
        browser = launch_sync(p)
        page = browser.new_page(accept_downloads=True)
        instrument_page(page, rec, system="refund-portal", screenshots="store", redact_selectors=["#iban"],
                        record_values=["order", "#amount"], verify_outcome={"*/done*": booked})
        page.goto(server + "/")
        page.get_by_label("Order id").fill("A-1")
        page.fill("#amount", "4210")
        page.get_by_label("Password").fill("hunter2")
        page.get_by_label("IBAN").fill("AT611904300234573201")
        page.locator("#reason").select_option("late")
        page.get_by_label("Notify customer").check()
        page.get_by_label("Order id").press("Tab")  # not a submitting key: not recorded
        page.frame_locator("iframe[name=side]").get_by_role("button", name="Confirm in frame").click()
        with page.expect_download() as dl:
            page.get_by_text("Download report").click()
        dl.value.path()
        page.get_by_role("button", name="Submit refund").click()
        page.wait_for_url("**/done**")
        page.wait_for_timeout(100)
        browser.close()

    acts = actions(rec)
    tools = [a["tool"]["name"] for a in acts]
    assert all(a["tool"]["system"] == "refund-portal" for a in acts)
    assert "browser.press" not in tools

    nav0 = acts[0]
    assert nav0["tool"]["name"] == "browser.navigate" and nav0["args"]["via"] == "goto"
    assert nav0["response"]["body"]["status"] == 200 and nav0["response"]["body"]["url"] == server + "/"
    assert "parent_action" not in nav0.get("context", {})

    fills = [a for a in acts if a["tool"]["name"] == "browser.fill"]
    assert len(fills) == 4  # page.fill goes through frame.fill and frame._fill: recorded once
    by_id = {f["args"]["target"]["id"]: f for f in fills}
    assert by_id["order"]["args"]["value"] == "A-1"  # allowlisted by field name
    assert by_id["order"]["args"]["target"]["label"] == "Order id"
    assert by_id["order"]["args"]["target"]["role"] == "textbox"
    assert by_id["amount"]["args"]["value"] == "4210"  # allowlisted by selector
    assert by_id["pw"]["args"]["value"] == {"redacted": "dropped"}
    assert by_id["pw"]["args"]["target"]["sensitive"] is True
    assert by_id["iban"]["args"]["value"] == {"redacted": "dropped"}

    for a in fills + [x for x in acts if x["tool"]["name"] in ("browser.select", "browser.check")]:
        assert a["context"]["parent_action"] == nav0["id"]  # grouped under the first page load
        assert a["args"]["page_url"] == server + "/" and a["args"]["frame"] == {"main": True}

    select = next(a for a in acts if a["tool"]["name"] == "browser.select")
    assert select["args"]["values"] == {"value": "late"} and select["response"]["body"]["values"] == ["late"]
    check = next(a for a in acts if a["tool"]["name"] == "browser.check")
    assert check["args"]["checked"] is True and check["args"]["target"]["role"] == "checkbox"

    frame_click = next(a for a in acts if a["tool"]["name"] == "browser.click"
                       and a["args"]["target"].get("name") == "Confirm in frame")
    assert frame_click["args"]["frame"]["main"] is False and frame_click["args"]["frame"]["name"] == "side"
    assert frame_click["args"]["target"]["role"] == "button"

    [download] = [a for a in acts if a["tool"]["name"] == "browser.download"]
    assert download["args"]["filename"] == "report.csv" and download["args"]["url"] == server + "/report.csv"
    assert download["response"]["body"] == {"sha256": hashlib.sha256(REPORT).hexdigest(), "size": len(REPORT)}
    dl_click = next(a for a in acts if a["tool"]["name"] == "browser.click"
                    and a["args"]["target"].get("name") == "Download report")
    assert download["args"].get("cause", download["args"].get("after")) == dl_click["id"]
    assert dl_click["args"]["target"]["role"] == "link"

    submit_click = next(a for a in acts if a["tool"]["name"] == "browser.click"
                        and a["args"]["target"].get("name") == "Submit refund")
    [submit] = [a for a in acts if a["tool"]["name"] == "browser.submit"]
    assert submit["args"]["form"]["id"] == "refund" and submit["args"]["form"]["method"] == "get"
    assert "pw" in submit["args"]["form"]["fields"] and submit["args"]["cause"] == submit_click["id"]
    assert "hunter2" not in str(submit)
    nav_done = next(a for a in acts if a["tool"]["name"] == "browser.navigate" and a["args"]["via"] == "page")
    assert "/done" in nav_done["args"]["url"] and nav_done["args"]["cause"] == submit_click["id"]
    # the GET form put the typed values in the URL: unrecorded fields are scrubbed, allowlisted ones kept
    assert "order=A-1" in nav_done["args"]["url"] and "pw=[redacted]" in nav_done["args"]["url"]
    assert "iban=[redacted]" in nav_done["args"]["url"]
    assert submit_click["outcome"]["check"] == "match"  # URL after the click matched */done*
    # the callback sees the live URL; only the record is scrubbed
    assert [t for t, u in checked if "/done" in u and "pw=hunter2" in u] == ["browser.click"]

    # screenshots: hashes in the record, PNGs stored content-addressed, bytes match the hash
    shot_dir = rec.chain.store.directory / "screenshots"
    stored = {p.stem: p.read_bytes() for p in shot_dir.glob("*.png")}
    assert stored
    for a in acts:
        if a["args"].get("via") == "page" or a["tool"]["name"] in ("browser.submit", "browser.download"):
            continue
        s = shots(a)
        assert set(s) == {"before", "after"}, a["tool"]
        for phase in ("before", "after"):
            data = stored[s[phase]["sha256"]]
            assert hashlib.sha256(data).hexdigest() == s[phase]["sha256"] and data[:4] == b"\x89PNG"

    raw = (rec.chain.store.directory / "records.jsonl").read_text()
    assert "hunter2" not in raw and "AT611904300234573201" not in raw

    bundle = rec.export(tmp_path / "bundle.zip")
    assert verify_bundle(bundle).valid()


async def test_async_api_keyboard_and_hash_only(rec, server, tmp_path):
    async with async_playwright() as p:
        browser = await launch_async(p)
        page = await browser.new_page()
        instrument_page(page, rec, system="refund-portal")  # screenshots="hash"
        await page.goto(server + "/")
        await page.click("#order")
        await page.keyboard.type("B-7")
        await page.locator("#amount").press_sequentially("99")
        await page.locator("#amount").press("Enter")  # submits the form
        await page.wait_for_url("**/done**")
        await page.go_back()
        await page.mouse.click(5, 5)
        await browser.close()

    acts = actions(rec)
    tools = [a["tool"]["name"] for a in acts]
    assert tools.count("browser.navigate") >= 3
    typed = [a for a in acts if a["tool"]["name"] == "browser.type"]
    assert typed[0]["args"]["target"]["focused"] is True and typed[0]["args"]["target"]["id"] == "order"
    assert typed[0]["args"]["text"]["redacted"].startswith("hmac-sha256:")  # redacted by default
    assert typed[1]["args"]["target"]["selector"] == "#amount"
    press = next(a for a in acts if a["tool"]["name"] == "browser.press")
    assert press["args"]["key"] == "Enter"
    assert any(a["tool"]["name"] == "browser.submit" and a["args"]["cause"] == press["id"] for a in acts)
    back = next(a for a in acts if a["args"].get("via") == "back")
    assert back["response"]["body"]["url"] == server + "/"
    point = acts[-1]
    assert point["tool"]["name"] == "browser.click" and point["args"]["target"]["point"] == {"x": 5, "y": 5}
    assert point["context"]["parent_action"] == back["id"]  # grouped under the latest navigation
    s = shots(typed[0])
    assert len(s["before"]["sha256"]) == 64 and s["before"]["sha256"] != s["after"]["sha256"]
    assert not (rec.chain.store.directory / "screenshots").exists()
    assert verify_bundle(rec.export(tmp_path / "b.zip")).valid()


def test_scrub_url():
    from gleipnir.adapters.playwright import SECRET_PARAMS, scrub_url

    secret = set(SECRET_PARAMS)
    assert scrub_url("https://a.example/cb?code=xyz&state=1#access_token=t&x=2", secret) == \
        "https://a.example/cb?code=[redacted]&state=1#access_token=[redacted]&x=2"
    assert scrub_url("https://u:pw@a.example/p?q=1", secret) == "https://u:[redacted]@a.example/p?q=1"
    assert scrub_url("https://a.example/#section", secret) == "https://a.example/#section"


def test_errors_are_recorded_and_reraised(rec, server):
    with sync_playwright() as p:
        browser = launch_sync(p)
        page = browser.new_page()
        instrument_page(page, rec, system="refund-portal", screenshots="none")
        page.goto(server + "/")
        with pytest.raises(Exception, match="Timeout"):
            page.click("#nope", timeout=300)
        browser.close()
    a = actions(rec)[-1]
    assert a["tool"]["name"] == "browser.click" and a["response"]["status"] == "error"
    assert a["args"]["target"] == {"selector": "#nope"} and "sources" not in a
