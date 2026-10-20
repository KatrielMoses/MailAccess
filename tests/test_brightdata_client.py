from __future__ import annotations

import asyncio
import json
import logging

import httpx
import pytest

from backend.config import settings
from backend.core import brightdata_client as bd

KEY = "bd-test-key-0011223344"
URL = "https://www.linkedin.com/in/jane-doe/"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setattr(settings, "brightdata_api_key", KEY, raising=False)
    monkeypatch.setattr(settings, "brightdata_disabled", False, raising=False)
    monkeypatch.setattr(settings, "brightdata_timeout_seconds", 5.0, raising=False)
    monkeypatch.setattr(bd, "POLL_INTERVAL_S", 0.0)
    bd._STATES.clear()
    yield
    bd._STATES.clear()


def _run(handler):
    return asyncio.run(bd.fetch_profile(URL, transport=httpx.MockTransport(handler)))


def test_sync_200_returns_first_record_and_sends_one_url():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers["authorization"]
        seen["params"] = dict(request.url.params)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=[{"name": "Jane Doe", "city": "Pune"}])

    assert _run(handler) == {"name": "Jane Doe", "city": "Pune"}
    assert seen["auth"] == f"Bearer {KEY}"
    assert seen["params"] == {"dataset_id": bd.DATASET_ID, "format": "json", "include_errors": "true"}
    assert seen["body"] == [{"url": URL}]


def test_error_records_are_ignored():
    assert _run(lambda r: httpx.Response(200, json=[{"error": "dead_page"}])) is None


def test_202_polls_progress_then_reads_snapshot():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path.endswith("/scrape"):
            return httpx.Response(202, json={"snapshot_id": "s_1"})
        if "/progress/" in request.url.path:
            ready = sum("/progress/" in c for c in calls) >= 2
            return httpx.Response(200, json={"status": "ready" if ready else "running"})
        return httpx.Response(200, json=[{"name": "Jane Doe"}])

    assert _run(handler) == {"name": "Jane Doe"}
    assert calls == ["/datasets/v3/scrape", "/datasets/v3/progress/s_1",
                     "/datasets/v3/progress/s_1", "/datasets/v3/snapshot/s_1"]


def test_202_gives_up_after_max_polls():
    def handler(request):
        if request.url.path.endswith("/scrape"):
            return httpx.Response(202, json={"snapshot_id": "s_2"})
        return httpx.Response(200, json={"status": "running"})

    assert _run(handler) is None


def test_401_marks_key_rejected_and_stops_calling():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(401, json={"error": "unauthorized"})

    assert _run(handler) is None
    assert _run(handler) is None
    assert len(calls) == 1  # rejected key: no second call
    assert not bd.available(KEY)


def test_429_backs_off_for_retry_after():
    def handler(request):
        return httpx.Response(429, headers={"retry-after": "120"})

    assert _run(handler) is None
    assert not bd.available(KEY)
    state = bd._state(KEY)
    assert 100 < state["blocked_until"] - __import__("time").monotonic() <= 120


def test_timeout_returns_none(monkeypatch):
    monkeypatch.setattr(settings, "brightdata_timeout_seconds", 1.0, raising=False)

    async def slow(request):
        await asyncio.sleep(3)
        return httpx.Response(200, json=[])

    assert _run(slow) is None


def test_inactive_without_key(monkeypatch):
    monkeypatch.setattr(settings, "brightdata_api_key", None, raising=False)
    assert bd.brightdata_active() is False
    assert asyncio.run(bd.fetch_profile(URL)) is None


def test_key_never_reaches_logs(caplog):
    caplog.set_level(logging.INFO)
    logger = logging.getLogger("backend.core.brightdata_client")
    logger.info("token was %s", KEY)
    assert KEY not in caplog.text
