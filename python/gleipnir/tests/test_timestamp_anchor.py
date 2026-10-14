import gleipnir


def test_bad_tsa_response_is_retried(tmp_path, clock):
    ts = gleipnir.TimestampAnchor(clock=clock)
    ts._post = lambda body: b"garbage"
    r = gleipnir.Recorder("a", "1", home=tmp_path, background=False, clock=clock, quiet=True,
                          anchor=[gleipnir.LocalFileAnchor(tmp_path / "log.jsonl", clock=clock), ts],
                          segment_max_records=2, fsync=False)

    @r.tool(system="s")
    def f(i):
        return i

    f(1)
    f(2)
    # local anchor succeeded, timestamp did not: segment stays pending, only the missing type is retried
    assert len(r.chain.pending_anchor) == 1
    assert r.chain.anchor_done[3] == {"local"}
    calls = []
    ts._post = lambda body: calls.append(1) or b"garbage"
    r.chain.anchor_pending()
    assert calls == [1]


def test_rekor_preset_includes_timestamp(tmp_path):
    r = gleipnir.Recorder("a", "1", home=tmp_path, background=False, quiet=True, anchor="rekor", fsync=False)
    assert [a.type for a in r.chain.anchors] == ["rekor", "rfc3161"]


def test_duplicate_anchor_types_rejected(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        gleipnir.Recorder("a", "1", home=tmp_path, background=False, quiet=True, fsync=False,
                          anchor=[gleipnir.TimestampAnchor(), gleipnir.TimestampAnchor()])
