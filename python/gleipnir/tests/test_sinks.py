import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import gleipnir
from gleipnir.check import capabilities_from_records
from gleipnir.ocsf import to_ocsf
from gleipnir.sinks import DirectorySink, S3ObjectLockSink, SplunkHecSink, WebhookSink
from gleipnir_verify import verify_records


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, **kw):
        assert kw["ObjectLockMode"] in ("COMPLIANCE", "GOVERNANCE") and kw["ObjectLockRetainUntilDate"]
        self.objects[kw["Key"]] = kw


class Flaky:
    type, role = "flaky", "backup"

    def __init__(self):
        self.fail, self.got = True, []

    def describe(self):
        return {"type": self.type, "role": self.role, "target": "mem"}

    def write(self, chain, records):
        if self.fail:
            raise ConnectionError("down")
        self.got.extend(records)


def make(tmp_path, clock, sinks, **kw):
    return gleipnir.Recorder("a", "1", home=tmp_path / "h", background=False, clock=clock, quiet=True,
                             fsync=False, segment_max_records=3, sinks=sinks, **kw)


def test_directory_and_s3_buyer_copies_are_complete_and_verifiable(tmp_path, clock):
    s3 = FakeS3()
    d = DirectorySink(tmp_path / "buyer", role="buyer")
    r = make(tmp_path, clock, [d, S3ObjectLockSink("bank-bucket", client=s3, retention_days=2555)],
             retention_days=2555, retention_note="7 years per bank contract")

    @r.tool(system="s")
    def f(i):
        return i

    for i in range(7):
        f(i)
    r.flush()
    original = r.chain.store.read_all()
    copy = [json.loads(x) for x in (tmp_path / "buyer" / r.chain.chain_id / "records.jsonl").read_text()
            .split("\n") if x.strip()]
    assert copy == original
    assert verify_records(copy).valid()
    from_s3 = [json.loads(x) for o in sorted(s3.objects) for x in s3.objects[o]["Body"].decode().split("\n")
               if x.strip()]
    assert from_s3 == original
    caps, why = capabilities_from_records(original)
    assert {"buyer_copy", "retention_policy"} <= caps
    config = next(x for x in original if x["kind"] == "config")["config"]
    assert config["retention"] == {"days": 2555, "note": "7 years per bank contract"}
    assert {s["type"] for s in config["sinks"]} == {"directory", "s3-object-lock"}


def test_failed_delivery_is_retried_and_resumes_after_restart(tmp_path, clock):
    fl = Flaky()
    r = make(tmp_path, clock, [fl])

    @r.tool(system="s")
    def f(i):
        return i

    for i in range(4):
        f(i)
    r.flush()
    assert fl.got == []
    fl.fail = False
    r.chain.deliver()
    assert [x["seq"] for x in fl.got] == [x["seq"] for x in r.chain.store.read_all()]
    # restart: only new records are delivered
    n = len(fl.got)
    r2 = make(tmp_path, clock, [fl])

    @r2.tool(system="s")
    def g(i):
        return i

    g(1)
    r2.flush()
    seqs = [x["seq"] for x in fl.got]
    assert seqs == sorted(set(seqs)) and len(seqs) > n


def test_config_written_only_when_changed(tmp_path, clock):
    r = make(tmp_path, clock, [], retention_days=30)
    make(tmp_path, clock, [], retention_days=30)
    make(tmp_path, clock, [], retention_days=90)
    cfgs = [x["config"]["retention"]["days"] for x in r.chain.store.read_all() if x["kind"] == "config"]
    assert cfgs == [30, 90]


class Collector(BaseHTTPRequestHandler):
    bodies: list = []

    def do_POST(self):  # noqa: N802
        n = int(self.headers["Content-Length"])
        Collector.bodies.append((self.path, dict(self.headers), self.rfile.read(n)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    Collector.bodies = []
    srv = HTTPServer(("localhost", 0), Collector)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://localhost:{srv.server_address[1]}"
    srv.shutdown()


def test_webhook_and_splunk_hec(tmp_path, clock, server):
    r = make(tmp_path, clock, [WebhookSink(server + "/ingest", fmt="ocsf", headers={"X-Key": "k"}),
                               SplunkHecSink(server + "/services/collector", "tok", index="agents")])

    @r.tool(system="payments")
    def issue_refund(order):
        return {"refund_id": "R1"}

    issue_refund("o1")
    r.flush()
    paths = [b[0] for b in Collector.bodies]
    assert "/ingest" in paths and "/services/collector" in paths
    hook = next(b for b in Collector.bodies if b[0] == "/ingest")
    events = [json.loads(x) for x in hook[2].decode().split("\n") if x.strip()]
    assert events and events[0]["class_uid"] == 6003 and events[0]["activity_name"] == "Create"
    assert hook[1]["X-Key"] == "k"
    hec = next(b for b in Collector.bodies if b[0] == "/services/collector")
    assert hec[1]["Authorization"] == "Splunk tok"
    ev = json.loads(hec[2].decode().split("\n")[0])
    assert ev["index"] == "agents" and ev["event"]["api"]["service"]["name"] == "payments"


def test_webhook_requires_https():
    with pytest.raises(ValueError):
        WebhookSink("http://example.com/x")


def test_ocsf_mapping_failure_and_non_actions(rec):
    @rec.tool(system="crm")
    def delete_contact(cid):
        raise PermissionError("no")

    with pytest.raises(PermissionError):
        delete_contact("c1")
    recs = rec.chain.store.read_all()
    e = to_ocsf(next(x for x in recs if x["kind"] == "action"))
    assert e["activity_id"] == 4 and e["status_id"] == 2 and "PermissionError" in e["status_detail"]
    assert to_ocsf(recs[0]) is None


def test_cli_export_ocsf(tmp_path, clock, capsys):
    from gleipnir import cli

    home = tmp_path / "h"
    r = gleipnir.Recorder("a", "1", home=home, background=False, clock=clock, quiet=True, fsync=False)

    @r.tool(system="s")
    def get_order(i):
        return i

    get_order(1)
    r.flush()
    out = tmp_path / "e.ndjson"
    assert cli.main(["--home", str(home), "export", "--format", "ocsf", "-o", str(out)]) == 0
    lines = [json.loads(x) for x in out.read_text().split("\n") if x.strip()]
    assert lines[0]["activity_name"] == "Read"
    capsys.readouterr()
