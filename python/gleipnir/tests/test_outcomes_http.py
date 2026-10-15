"""Generic HTTP/JSON read-back and the shared comparison rules."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from gleipnir import Call
from gleipnir.outcomes import HttpError, NotFound, http_json_matches, json_get
from gleipnir.outcomes._core import values_equal


def call(**args):
    return Call("act_1", "book", "orders", args)


def url(c, r):
    return f"/orders/{r['order_id']}"


def expected(c, r):
    return {"status": "booked", "total_cents": c.args["total_cents"], "customer.id": c.args["customer"]}


def test_match_mismatch_missing():
    db = {"/orders/o1": {"data": {"status": "booked", "total_cents": 4210, "customer": {"id": 7}}}}

    def fetch(u):
        if u not in db:
            raise NotFound(u)
        return db[u]

    chk = http_json_matches(get_url=url, fetch=fetch, expected=expected, root="data")
    assert chk(call(total_cents=4210, customer="7"), {"order_id": "o1"}).check == "match"
    o = chk(call(total_cents=4200, customer="7"), {"order_id": "o1"})
    assert o.check == "mismatch" and o.fields == ["total_cents"]
    assert o.method == "http.json_matches"
    assert chk(call(total_cents=1, customer=1), {"order_id": "o2"}).fields == ["exists"]


def test_custom_eq_and_retry_and_never_raises():
    calls = []

    def fetch(u):
        calls.append(u)
        if len(calls) == 1:
            raise HttpError(503, u)
        return {"total": 1001}

    chk = http_json_matches(get_url=lambda c, r: "/x", fetch=fetch, expected={"total": 1000},
                            eq={"total": lambda e, g: abs(e - g) <= 1}, retries=1, sleep=lambda s: None)
    assert chk(call(), {}).check == "match" and len(calls) == 2

    def boom(c, r):
        raise KeyError("order_id")

    o = http_json_matches(get_url=boom, fetch=lambda u: {}, expected={"a": 1})(call(), {})
    assert o.check == "error" and "KeyError" in o.detail


@pytest.mark.parametrize("exp,obs,eq", [
    (1500, "1500.00", True), ("1500.00", 1500, True), (42.1, 42.10, True), (123, "123", True),
    (True, "true", True), (False, "false", True), (None, "", True), (None, None, True),
    ("abc", "ABC", False), (1, True, False), (1000, 950, False), ({"a": 1}, {"a": 1, "b": 2}, True),
    ([1, 2], [1, 2, 3], False), ("01", "1", False),
])
def test_values_equal(exp, obs, eq):
    assert values_equal(exp, obs) is eq


def test_json_get_stdlib_against_local_server():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/ok":
                body = json.dumps({"status": "booked", "auth": self.headers.get("Authorization")}).encode()
                self.send_response(200)
            else:
                body = b'{"error": "nope"}'
                self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        fetch = json_get(f"http://127.0.0.1:{srv.server_port}", headers={"Authorization": "Bearer t"})
        assert fetch("/ok") == {"status": "booked", "auth": "Bearer t"}
        chk = http_json_matches(get_url=lambda c, r: r["path"], fetch=fetch, expected={"status": "booked"})
        assert chk(call(), {"path": "/ok"}).check == "match"
        assert chk(call(), {"path": "/missing"}).fields == ["exists"]
    finally:
        srv.shutdown()


def test_connection_refused_is_error():
    fetch = json_get("http://127.0.0.1:9", timeout=1)
    o = http_json_matches(get_url=lambda c, r: "/x", fetch=fetch, expected={"a": 1})(call(), {})
    assert o.check == "error"
