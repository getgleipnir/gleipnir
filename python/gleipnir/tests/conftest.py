from datetime import datetime, timedelta, timezone

import pytest

import gleipnir


class FakeClock:
    def __init__(self):
        self.now = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def rec(tmp_path, clock):
    r = gleipnir.Recorder("support-agent", "1.0.0", home=tmp_path / "g", background=False, clock=clock,
                          segment_max_records=5, heartbeat_seconds=60, quiet=True, fsync=False)
    yield r
    r.chain._stop.set()
