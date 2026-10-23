from __future__ import annotations

from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

import cli.main as cli_main
import cli.sponsor_feed as sponsor_feed
import cli.update_check as update_check
from backend.config import settings
from backend.core import local_only
from backend.core.mailaccess_pro_connector import (
    fetch_coverage_count,
    fetch_founder_status,
)
from cli.main import DoctorCheck, app


@pytest.fixture(autouse=True)
def _reset_local_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(local_only.ENV_VAR, raising=False)
    monkeypatch.setattr(settings, "mailaccess_local_only", False)
    monkeypatch.setattr(settings, "mailaccess_pro_api_url", "https://mailaccess.pro")


def test_is_enabled_defaults_off() -> None:
    assert local_only.is_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_is_enabled_from_env(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(local_only.ENV_VAR, value)
    assert local_only.is_enabled() is True


def test_is_enabled_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_local_only", True)
    assert local_only.is_enabled() is True


def test_activate_sets_env_and_settings() -> None:
    local_only.activate()
    assert local_only.env_flag() is True
    assert settings.mailaccess_local_only is True
    assert local_only.is_enabled() is True


class _BoomClient:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("httpx.AsyncClient must not be constructed in local-only mode")


@pytest.mark.asyncio
async def test_coverage_count_skips_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(local_only.ENV_VAR, "1")
    monkeypatch.setattr(httpx, "AsyncClient", _BoomClient)
    assert await fetch_coverage_count("acme.com") is None


@pytest.mark.asyncio
async def test_founder_status_skips_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(local_only.ENV_VAR, "1")
    monkeypatch.setattr(httpx, "AsyncClient", _BoomClient)
    assert await fetch_founder_status() is None


def test_sponsor_feed_skips_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(local_only.ENV_VAR, "1")

    def _fetch(*_args: Any, **_kwargs: Any) -> dict:
        raise AssertionError("sponsor feed must not fetch in local-only mode")

    monkeypatch.setattr(sponsor_feed, "_fetch", _fetch)
    assert sponsor_feed.load_payload() is None


def test_update_check_skips_notice_and_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(local_only.ENV_VAR, "1")
    monkeypatch.setattr(update_check.sys.stderr, "isatty", lambda: True)
    assert update_check._notice_enabled("harvest-emails", False) is False

    def _start(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("update-check thread must not start in local-only mode")

    monkeypatch.setattr(update_check.threading, "Thread", _start)
    update_check.start_background_refresh()


@pytest.fixture
def _quiet_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_check, "start_background_refresh", lambda: None)
    monkeypatch.setattr(update_check, "register_exit_notice", lambda *_a, **_k: None)
    monkeypatch.setattr(update_check, "enforce_or_exit", lambda *_a, **_k: None)


def test_local_only_status_cli(monkeypatch: pytest.MonkeyPatch, _quiet_cli: None) -> None:
    monkeypatch.setenv(local_only.ENV_VAR, "1")
    monkeypatch.setattr(cli_main, "_reload_settings", lambda: settings)
    result = CliRunner().invoke(app, ["local-only", "status"])
    assert result.exit_code == 0
    assert "yes" in result.stdout
    assert "skipped" in result.stdout


def test_local_only_enable_writes_env(
    tmp_path, monkeypatch: pytest.MonkeyPatch, _quiet_cli: None
) -> None:
    env_file = tmp_path / ".env"
    monkeypatch.setattr(cli_main, "ENV_FILE", env_file)
    monkeypatch.setattr(cli_main, "_reload_settings", lambda: settings)
    result = CliRunner().invoke(app, ["local-only", "enable"])
    assert result.exit_code == 0
    assert "Local-only on" in result.stdout
    assert local_only.ENV_VAR in env_file.read_text()
    assert local_only.is_enabled() is True


def test_doctor_reports_local_only_mode() -> None:
    import inspect

    source = inspect.getsource(cli_main._collect_doctor_checks)
    assert "local-only mode" in source
    assert "mailaccess local-only enable" in source


def test_doctor_privacy_row_when_on(monkeypatch: pytest.MonkeyPatch, _quiet_cli: None) -> None:
    monkeypatch.setenv(local_only.ENV_VAR, "1")

    async def collect():
        return [
            DoctorCheck(
                "Privacy",
                "local-only mode",
                True,
                "on — coverage teaser, sponsor feed, founder counter, "
                "and PyPI update check skipped",
                "mailaccess local-only enable",
            )
        ]

    monkeypatch.setattr(cli_main, "_collect_doctor_checks", collect)
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "local-only mode" in result.stdout
    assert "on —" in result.stdout


@pytest.mark.asyncio
async def test_coverage_still_calls_when_off(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            called.append("init")

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        async def get(self, url: str, params: dict | None = None) -> httpx.Response:
            called.append(url)
            request = httpx.Request("GET", url)
            return httpx.Response(500, request=request)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    assert await fetch_coverage_count("acme.com") is None
    assert called == ["init", "https://mailaccess.pro/v1/coverage"]
