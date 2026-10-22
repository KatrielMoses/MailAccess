from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from backend.config import settings
from backend.core import probe_cache


@pytest.fixture(autouse=True)
def _cache(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "probe_cache_enabled", True, raising=False)
    monkeypatch.setattr(settings, "probe_cache_path", str(tmp_path / "probe_cache.db"), raising=False)
    monkeypatch.setattr(settings, "probe_cache_ttl_days", 7, raising=False)
    monkeypatch.setattr(settings, "probe_cache_inconclusive_ttl_seconds", 3600, raising=False)
    probe_cache._CONN = None
    probe_cache._CONN_PATH = None
    probe_cache.set_no_cache_read(False)
    yield
    if probe_cache._CONN is not None:
        probe_cache._CONN.close()
    probe_cache._CONN = None


DEFN = {"id": "github", "name": "GitHub"}


def test_put_then_get_hit_with_fields():
    probe_cache.put(DEFN, "GitHub", "janedoe", "hit",
                    fields={"display_name": "Jane Doe", "_url": "https://github.com/janedoe"})
    got = probe_cache.get(DEFN, "GitHub", "janedoe")
    assert got["outcome"] == "hit"
    assert got["fields"]["display_name"] == "Jane Doe"
    assert got["age_days"] == 0


def test_miss_and_inconclusive_round_trip():
    probe_cache.put(DEFN, "GitHub", "nobody", "miss")
    probe_cache.put({"id": "x"}, "X", "nobody", "inconclusive")
    assert probe_cache.get(DEFN, "GitHub", "nobody")["outcome"] == "miss"
    assert probe_cache.get({"id": "x"}, "X", "nobody")["outcome"] == "inconclusive"


def test_no_read_flag_disables_reads_but_not_writes():
    probe_cache.put(DEFN, "GitHub", "janedoe", "hit")
    probe_cache.set_no_cache_read(True)
    assert probe_cache.get(DEFN, "GitHub", "janedoe") is None
    probe_cache.put(DEFN, "GitHub", "other", "miss")  # still writes
    probe_cache.set_no_cache_read(False)
    assert probe_cache.get(DEFN, "GitHub", "other")["outcome"] == "miss"


def test_disabled_cache_is_inert(monkeypatch):
    monkeypatch.setattr(settings, "probe_cache_enabled", False, raising=False)
    probe_cache.put(DEFN, "GitHub", "janedoe", "hit")
    assert probe_cache.get(DEFN, "GitHub", "janedoe") is None


def _backdate(handle, days):
    conn = probe_cache._connection()
    stamp = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    conn.execute("UPDATE probe_cache SET checked_at=? WHERE handle=?", (stamp, handle))
    conn.commit()


def test_found_row_expires_after_ttl():
    probe_cache.put(DEFN, "GitHub", "old", "hit")
    _backdate("old", 8)  # older than 7-day TTL
    assert probe_cache.get(DEFN, "GitHub", "old") is None
    probe_cache.put(DEFN, "GitHub", "fresh", "hit")
    _backdate("fresh", 6)
    assert probe_cache.get(DEFN, "GitHub", "fresh")["age_days"] == 6


def test_inconclusive_expires_after_one_hour():
    probe_cache.put(DEFN, "GitHub", "flap", "inconclusive")
    conn = probe_cache._connection()
    stamp = (datetime.now(timezone.utc) - timedelta(seconds=3700)).isoformat()
    conn.execute("UPDATE probe_cache SET checked_at=? WHERE handle='flap'", (stamp,))
    conn.commit()
    assert probe_cache.get(DEFN, "GitHub", "flap") is None


def test_cleanup_deletes_rows_older_than_twice_ttl():
    probe_cache.put(DEFN, "GitHub", "ancient", "hit")
    _backdate("ancient", 15)  # > 2x TTL
    probe_cache._CONN = None  # force reconnect, which runs cleanup
    conn = probe_cache._connection()
    rows = conn.execute("SELECT COUNT(*) FROM probe_cache WHERE handle='ancient'").fetchone()[0]
    assert rows == 0


def test_checked_ago_phrasing():
    assert probe_cache.checked_ago(0) == "checked today"
    assert probe_cache.checked_ago(1) == "checked 1 day ago"
    assert probe_cache.checked_ago(5) == "checked 5 days ago"


def test_live_counter_emits_found_label():
    from backend.core.run_events import RunEventEmitter

    emitter = RunEventEmitter("live-counter-test")
    seen: list = []
    emitter.add_sink(lambda ev: seen.append(ev))
    emitter.progress("username_platforms", 612, 750, found=14, force=True)
    prog = [e for e in seen if e.get("type") == "module_progress"]
    assert prog, "no module_progress event emitted"
    payload = prog[-1]["payload"] if "payload" in prog[-1] else prog[-1]
    assert payload["checked"] == 612 and payload["total"] == 750 and payload["found"] == 14
    assert payload["label"] == "612 / 750 checked · 14 found"
