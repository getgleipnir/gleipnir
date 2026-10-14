import os

import pytest

import gleipnir
from gleipnir_verify import verify_bundle

LIVE = os.environ.get("GLEIPNIR_LIVE_REKOR") == "1"


def test_bad_rekor_response_is_retried(tmp_path, clock):
    a = gleipnir.RekorAnchor(tmp_path, clock=clock)
    a._post = lambda body: {"not": "a receipt"}
    r = gleipnir.Recorder("a", "1", home=tmp_path, background=False, clock=clock, quiet=True, anchor=a,
                          segment_max_records=2, fsync=False)

    @r.tool(system="s")
    def f(i):
        return i

    f(1)
    f(2)
    assert len(r.chain.pending_anchor) == 1  # receipt failed verification, segment stays pending


def test_anchor_key_is_p256_and_persisted(tmp_path):
    a1 = gleipnir.RekorAnchor(tmp_path)
    a2 = gleipnir.RekorAnchor(tmp_path)
    assert a1.public_der == a2.public_der
    from cryptography.hazmat.primitives.asymmetric import ed25519

    with pytest.raises(ValueError):
        gleipnir.RekorAnchor(tmp_path, private_key=ed25519.Ed25519PrivateKey.generate())


@pytest.mark.skipif(not LIVE, reason="set GLEIPNIR_LIVE_REKOR=1 to publish test hashes to public Rekor")
def test_live_rekor_end_to_end(tmp_path):
    r = gleipnir.Recorder("live-test", "1", home=tmp_path, background=False, quiet=True, anchor="rekor",
                          segment_max_records=3, fsync=False)

    @r.tool(system="test")
    def f(i):
        return {"i": i}

    for i in range(4):
        f(i)
    path = r.export(tmp_path / "live.zip")
    rep = verify_bundle(path)
    assert rep.valid(), [x.as_dict() for x in rep.findings]
    assert rep.summary["anchors_independent"] == rep.summary["segments"] == 2
