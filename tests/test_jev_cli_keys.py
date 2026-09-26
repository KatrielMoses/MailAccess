"""Phase JEV-0.1 — `mailaccess keys set/unset JEV_API_KEY` turns JEV on and off.

Exercises the real CLI key commands against a temp ~/.mailaccess/.env, then loads
Settings from that profile file exactly as the backend does and drives the seam
with a mocked model. Network-free.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from rich.console import Console

import backend.config as config_mod
from backend.core.jev import breaker as jev_breaker
from backend.core.jev import client as jev_client
from backend.core.jev import metrics as jev_metrics
from backend.core.jev.tasks import demo
from cli import main


@pytest.fixture
def profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    env_file = tmp_path / ".mailaccess" / ".env"
    monkeypatch.setattr(main, "ENV_FILE", env_file)
    monkeypatch.setattr(config_mod, "_PROFILE_ENV_FILE", env_file)
    monkeypatch.chdir(tmp_path)  # no repo ./.env in play
    for name in ("JEV_API_KEY", "JEV_BASE_URL", "JEV_MODEL", "JEV_FORCE_OFF",
                 "JEV_PROVIDER", "JEV_ENABLED", "JEV_CACHE_PATH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("JEV_CACHE_PATH", str(env_file.parent / "cache"))
    monkeypatch.setattr(main, "console", Console(record=True, width=160))
    jev_metrics.reset()
    jev_breaker.reset()
    return env_file


def _reload_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fresh = config_mod.Settings()
    fresh.jev_cache_path = str(tmp_path / "jev-cache")
    monkeypatch.setattr(config_mod, "settings", fresh)


def test_jev_key_is_registered_like_the_other_optional_keys(profile: Path) -> None:
    assert "JEV_API_KEY" in {name for name, _, _ in main._API_KEYS}
    main.keys_list()
    out = main.console.export_text()
    assert "JEV_API_KEY" in out and "NOT SET" in out


async def test_keys_set_activates_and_unset_deactivates(
    profile: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    requests: list[Any] = []

    def handler(request: httpx.Request) -> httpx.Response:
        # jev is a typed-decisions provider (System One): it POSTs /v1/systemone and
        # a boolean field comes back as a ``noul`` yes-probability.
        requests.append(request)
        return httpx.Response(200, json={"answers": {
            "is_personal_name": {"type": "noul", "noul": 0.95}}})

    monkeypatch.setattr(jev_client, "_TRANSPORT", httpx.MockTransport(handler))

    # Default install: no key → pure fallback, no network.
    _reload_settings(monkeypatch, tmp_path)
    assert await demo.is_plausible_personal_name("cher") == (False, "rule")

    main._set_env_key("JEV_BASE_URL", "https://jev.invalid/v1")
    main._set_env_key("JEV_MODEL", "jev-test")
    main.keys_set("JEV_API_KEY", "test-key-not-real")
    assert "JEV_API_KEY=" in profile.read_text()
    assert "Reasoner enabled" in main.console.export_text()

    _reload_settings(monkeypatch, tmp_path)
    assert await demo.is_plausible_personal_name("cher") == (True, "jev")
    assert len(requests) == 1
    assert requests[0].headers["Authorization"] == "Bearer test-key-not-real"

    main.keys_unset("JEV_API_KEY")
    _reload_settings(monkeypatch, tmp_path)
    # Removing the key deactivates: provider=jev stays but has no key → config
    # incomplete → DEFER, and the demo caller falls back to the rule.
    assert await demo.is_plausible_personal_name("Grace Hopper") == (True, "rule")
    assert len(requests) == 1


def test_keys_set_warns_when_endpoint_is_missing(profile: Path) -> None:
    main.keys_set("JEV_API_KEY", "test-key-not-real")
    out = main.console.export_text()
    assert "JEV still needs JEV_BASE_URL and JEV_MODEL" in out


def test_keys_list_shows_jev_key_as_set_without_revealing_it(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("JEV_API_KEY", "super-secret-value")
    main.keys_list()
    out = main.console.export_text()
    assert "JEV_API_KEY" in out
    assert "super-secret-value" not in out
