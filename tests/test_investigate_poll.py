"""Regression tests for the investigate completion poll.

Previously the CLI polled at most 60 x 2s = 120s and then ``return 3``
("server unavailable"), so any investigation running longer than 120s
server-side was misreported as a failure even though the backend finished
and persisted the report.  ``_poll_report_until_done`` now waits generously
and only reports ``timed_out`` when the server is still working.
"""
from __future__ import annotations

import asyncio

import cli.main as cli_main
from cli.main import _poll_report_until_done


class _FakeResp:
    def __init__(self, data: dict) -> None:
        self._data = data

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._data


class _FakeClient:
    """Returns each queued status on successive GETs, repeating the last."""

    def __init__(self, statuses: list[str]) -> None:
        self._statuses = list(statuses)

    async def get(self, url: str, **kwargs):
        status = self._statuses.pop(0) if len(self._statuses) > 1 else self._statuses[0]
        return _FakeResp({"status": status})


def test_slow_but_successful_run_is_not_a_timeout(monkeypatch):
    monkeypatch.setattr(cli_main, "_POLL_INTERVAL_S", 0)
    client = _FakeClient(["running", "running", "complete"])

    status, _data, timed_out = asyncio.run(
        _poll_report_until_done(client, "inv-id", "pending", {})
    )

    assert status == "complete"
    assert timed_out is False


def test_timeout_only_when_still_running(monkeypatch):
    monkeypatch.setattr(cli_main, "_POLL_INTERVAL_S", 0)
    monkeypatch.setattr(cli_main, "_POLL_TIMEOUT_S", 0.0)
    client = _FakeClient(["running"])

    status, _data, timed_out = asyncio.run(
        _poll_report_until_done(client, "inv-id", "pending", {})
    )

    assert status == "running"
    assert timed_out is True
