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
    # setenv (not delenv): pytest only restores what it recorded, and delenv on an
    # unset variable records nothing, so activate()'s MAILACCESS_LOCAL_ONLY=1 leaked
    # into every later test file.
    monkeypatch.setenv(local_only.ENV_VAR, "0")
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



# --- Pro-key notice (local-only keeps keyed Pro enrichment, but says so first) ---

def test_pro_notice_only_with_local_only_and_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_key", "", raising=False)
    assert local_only.pro_notice("example.com") is None  # off, no key
    local_only.activate()
    assert local_only.pro_notice("example.com") is None  # on, no key
    monkeypatch.setattr(settings, "mailaccess_pro_key", "map_" + "0" * 40, raising=False)
    notice = local_only.pro_notice("example.com")
    assert notice and "example.com" in notice and "keys unset MAILACCESS_PRO_KEY" in notice


def _harvest_output(monkeypatch: pytest.MonkeyPatch, tmp_path, *, key: str) -> str:
    from io import StringIO

    from rich.console import Console

    from backend.core.domain_harvest_orchestrator import DomainHarvestResult
    from cli import harvest_emails as command

    result = DomainHarvestResult(
        domain="example.com", started_at="2026-07-16T10:00:00Z", completed_at="2026-07-16T10:00:01Z",
        duration_seconds=1.0, module_results={}, unique_emails=[], total_unique_emails=0,
        high_confidence_count=0, likely_confidence_count=0, medium_confidence_count=0,
        low_confidence_count=0, role_account_count=0, personal_email_count=0,
    )
    sent: list[str] = []

    async def fake_run(*_a: Any, **kwargs: Any) -> DomainHarvestResult:
        sent.append("network")  # stands in for the first call that could send the domain
        return result

    monkeypatch.setattr(settings, "harvest_results_dir", tmp_path)
    monkeypatch.setattr(settings, "mailaccess_pro_key", key, raising=False)
    monkeypatch.setattr(command, "_CFFI_AVAILABLE", True)
    monkeypatch.setattr(command, "run_domain_harvest", fake_run)
    monkeypatch.setattr(command, "format_harvest_cli_output", lambda *a, **k: "")
    stream = StringIO()
    console = Console(file=stream, force_terminal=False, width=200)
    printed_before_network: list[bool] = []
    real_print = console.print

    def spy(*args: Any, **kwargs: Any) -> None:
        if args and "Local-only mode is on" in str(args[0]):
            printed_before_network.append(not sent)
        real_print(*args, **kwargs)

    console.print = spy  # type: ignore[method-assign]
    local_only.activate()
    command.run_harvest_emails("example.com", no_verify=True, no_export=True,
                               mode="public-business-contact", console=console)
    out = stream.getvalue()
    if printed_before_network:
        assert printed_before_network == [True]
    return out


def test_harvest_prints_notice_before_sending_when_key_set(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    out = _harvest_output(monkeypatch, tmp_path, key="map_" + "0" * 40)
    assert "Local-only mode is on, but your Pro key is set" in out and "example.com" in out


def test_harvest_no_notice_without_key(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    out = _harvest_output(monkeypatch, tmp_path, key="")
    assert "Local-only mode is on" not in out


def test_per_command_flag_applies_before_update_check(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bool] = []
    monkeypatch.setattr(update_check, "start_background_refresh", lambda: seen.append(local_only.is_enabled()))
    monkeypatch.setattr(update_check, "register_exit_notice", lambda *a, **k: None)
    monkeypatch.setattr(cli_main.sys, "argv", ["mailaccess", "harvest-emails", "--local-only"])
    CliRunner().invoke(app, ["--no-banner", "commands"])
    assert seen == [True]
