"""Phase JEV-0.2 — `mailaccess reasoner` enable/disable/status/test flow.

Network-free: the adapters' HTTP transport is mocked. The wizard is driven
non-interactively via CLI options (through Typer's CliRunner, so Option defaults
resolve). Exercises all three providers, the live-test report, and disable →
inactive.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

import backend.config as config_mod
from backend.core import jev
from backend.core.jev import breaker as jev_breaker
from backend.core.jev import client as jev_client
from backend.core.jev import metrics as jev_metrics
from cli import main

runner = CliRunner()


@pytest.fixture
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    env_file = tmp_path / ".mailaccess" / ".env"
    monkeypatch.setattr(main, "ENV_FILE", env_file)
    monkeypatch.setattr(config_mod, "_PROFILE_ENV_FILE", env_file)
    monkeypatch.chdir(tmp_path)
    for name in ("JEV_PROVIDER", "JEV_ENABLED", "JEV_API_KEY", "JEV_BASE_URL", "JEV_MODEL"):
        monkeypatch.delenv(name, raising=False)
    # Isolate the verdict cache per test (the reloaded Settings reads this from env),
    # so a demo verdict from one test can't be replayed into another's live test.
    monkeypatch.setenv("JEV_CACHE_PATH", str(tmp_path / "cache"))
    jev_metrics.reset()
    jev_breaker.reset()
    return env_file


def _chat_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        content = json.dumps({"is_personal_name": True, "confidence": 0.95})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    monkeypatch.setattr(jev_client, "_TRANSPORT", httpx.MockTransport(handler))


def _ollaya_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"answers": {"is_personal_name": True},
                                        "confidence": 0.95})

    monkeypatch.setattr(jev_client, "_TRANSPORT", httpx.MockTransport(handler))


def _invoke(*args: str) -> Any:  # type: ignore[valid-type]
    return runner.invoke(main.app, ["reasoner", *args])


def test_enable_openai_provider_live_test_and_persist(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _chat_ok(monkeypatch)
    res = _invoke("enable", "--provider", "openai-compatible",
                  "--base-url", "http://localhost:8080/v1", "--model", "local", "--key", "")
    assert res.exit_code == 0, res.output
    text = profile.read_text()
    assert "JEV_PROVIDER=" in text and "JEV_ENABLED=" in text
    assert "Live test OK" in res.output and "provider=openai" in res.output
    monkeypatch.setattr(config_mod, "settings", config_mod.Settings())
    assert jev.is_active() is True


def test_enable_jev_provider(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _chat_ok(monkeypatch)
    res = _invoke("enable", "--provider", "jev", "--base-url", "https://jev/v1",
                  "--model", "m", "--key", "secret")
    assert res.exit_code == 0, res.output
    monkeypatch.setattr(config_mod, "settings", config_mod.Settings())
    from backend.core.jev import adapters
    prof = adapters.resolve_profile(config_mod.settings)
    assert prof.provider == "jev" and prof.api_key == "secret" and jev.is_active() is True


def test_enable_ollaya_and_disable(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _ollaya_ok(monkeypatch)
    res = _invoke("enable", "--provider", "ollaya",
                  "--base-url", "http://localhost:11435", "--model", "llama3")
    assert res.exit_code == 0, res.output
    assert "Live test OK" in res.output and "provider=ollaya" in res.output
    monkeypatch.setattr(config_mod, "settings", config_mod.Settings())
    assert jev.is_active() is True

    res = _invoke("disable")
    assert res.exit_code == 0
    monkeypatch.setattr(config_mod, "settings", config_mod.Settings())
    assert jev.is_active() is False


def test_enable_saves_even_when_live_test_defers(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(jev_client, "_TRANSPORT", httpx.MockTransport(refused))
    res = _invoke("enable", "--provider", "ollaya",
                  "--base-url", "http://localhost:11435", "--model", "llama3")
    assert res.exit_code == 0
    assert "deferred" in res.output.lower()
    assert "JEV_ENABLED=" in profile.read_text()


def test_unknown_provider_exits(profile: Path) -> None:
    res = _invoke("enable", "--provider", "not-a-provider",
                  "--base-url", "x", "--model", "y", "--key", "z")
    assert res.exit_code == 2


def test_status_reports_active(profile: Path) -> None:
    main._set_env_key("JEV_PROVIDER", "ollaya")
    main._set_env_key("JEV_MODEL", "llama3")
    main._set_env_key("JEV_ENABLED", "true")
    res = _invoke("status")
    assert res.exit_code == 0
    assert "ollaya" in res.output and "active" in res.output


def test_test_command_reports_defer_when_off(profile: Path) -> None:
    res = _invoke("test")
    assert res.exit_code == 0
    assert "not active" in res.output.lower()
