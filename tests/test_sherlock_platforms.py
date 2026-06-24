"""Integration tests for SherlockPlatformsModule."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from backend.modules.base import ModuleStatus
from backend.modules.sherlock_platforms import (
    SherlockPlatformsModule,
    _confidence,
    _username_variants,
    _wave,
)

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

_LOAD_META = {
    "source": "sherlock",
    "site_count": 3,
    "partial": False,
    "loaded_at": "2026-06-22T00:00:00+00:00",
}

_WAVE1_SITE = {
    "url": "https://github.com/{}",
    "url_main": "https://github.com",
    "error_type": "status_code",
    "category": "dev",
}
_WAVE2_SITE = {
    "url": "https://example.com/users/{}",
    "error_type": "message",
    "error_msg": "not found",
    "category": "social",
}
_WAVE1_SITES = {
    "GitHub": _WAVE1_SITE,
    "Dev": {"url": "https://dev.to/{}", "error_type": "status_code", "category": "dev"},
    "Codeberg": {"url": "https://codeberg.org/{}", "error_type": "status_code", "category": "dev"},
}
_MIXED_SITES = {
    "GitHub": _WAVE1_SITE,
    "ExampleMsg": _WAVE2_SITE,
    "Twitch": {"url": "https://www.twitch.tv/{}", "error_type": "response_url", "category": "media"},
}


def _make_health(should_probe: bool = True, fragility: float = 0.0) -> MagicMock:
    h = MagicMock()
    h.should_probe_async = AsyncMock(return_value=should_probe)
    h.should_probe.return_value = should_probe  # backward compat for any direct calls
    h.get_fragility_score.return_value = fragility
    h.record_probe_async = AsyncMock()
    h.record_probe = MagicMock()
    return h


# ---------------------------------------------------------------------------
# Helper: run the module with mocked internals
# ---------------------------------------------------------------------------

def _run_module(
    email: str,
    sites: dict,
    probe_map: dict[str, tuple[str, str | None]] | None = None,
    force: bool = False,
    health: MagicMock | None = None,
    settings_overrides: dict | None = None,
    catch_all: set[str] | None = None,
):
    """
    Run SherlockPlatformsModule.run() with mocked load / probe / health / settings.

    probe_map: {site_name: (outcome, detail)} — default is ('miss', None)
    catch_all: set of site names the catch-all detector should return (default empty)
    """
    probe_map = probe_map or {}
    health = health or _make_health()
    catch_all = catch_all if catch_all is not None else set()

    async def _fake_probe(client, sem, site_name, defn, username, timeout=8.0):
        return probe_map.get(site_name, ("miss", None))

    defaults = {
        "enable_sherlock_platforms": True,
        "enable_sherlock_wave2": True,
    }
    if settings_overrides:
        defaults.update(settings_overrides)

    mock_settings = MagicMock(**defaults)

    async def _inner():
        mod = SherlockPlatformsModule()
        with (
            patch("backend.modules.sherlock_platforms.settings", mock_settings),
            patch(
                "backend.modules.sherlock_platforms.load_sherlock_sites",
                AsyncMock(return_value=(sites, _LOAD_META)),
            ),
            patch("backend.modules.sherlock_platforms.get_health_db", return_value=health),
            patch.object(mod, "_detect_catch_all", AsyncMock(return_value=catch_all)),
            patch("backend.modules.sherlock_platforms.probe_sherlock_site", side_effect=_fake_probe),
        ):
            return await mod.run(email, force=force)

    return asyncio.run(_inner())


# ---------------------------------------------------------------------------
# Disable / force
# ---------------------------------------------------------------------------

def test_module_skips_when_disabled() -> None:
    mod = SherlockPlatformsModule()

    async def _inner():
        mock_settings = MagicMock()
        mock_settings.enable_sherlock_platforms = False
        with patch("backend.modules.sherlock_platforms.settings", mock_settings):
            return await mod.run("test@example.com", force=False)

    result = asyncio.run(_inner())
    assert result.status == ModuleStatus.SKIPPED


def test_module_force_bypasses_disabled() -> None:
    result = _run_module(
        "test@example.com",
        sites={"GitHub": _WAVE1_SITE},
        probe_map={"GitHub": ("miss", None)},
        force=True,
        settings_overrides={"enable_sherlock_platforms": False, "enable_sherlock_wave2": False},
    )
    assert result.status != ModuleStatus.SKIPPED


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def test_three_hits_become_three_findings() -> None:
    sites = {
        "GitHub": {"url": "https://github.com/{}", "error_type": "status_code", "category": "dev"},
        "Reddit": {"url": "https://reddit.com/user/{}", "error_type": "status_code", "category": "social"},
        "Twitch": {"url": "https://twitch.tv/{}", "error_type": "status_code", "category": "media"},
    }
    probe_map = {
        "GitHub": ("hit", "https://github.com/alice"),
        "Reddit": ("hit", "https://reddit.com/user/alice"),
        "Twitch": ("hit", "https://twitch.tv/alice"),
    }
    result = _run_module("alice@example.com", sites=sites, probe_map=probe_map)
    assert result.status in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL)
    assert len(result.findings) == 3
    platforms = {f["platform"] for f in result.findings}
    assert "sherlock:GitHub" in platforms
    assert "sherlock:Reddit" in platforms
    assert "sherlock:Twitch" in platforms


def test_mix_hit_miss_waf_only_hits_in_findings() -> None:
    sites = {
        "SiteHit": {"url": "https://site-hit.com/{}", "error_type": "status_code", "category": "other"},
        "SiteMiss": {"url": "https://site-miss.com/{}", "error_type": "status_code", "category": "other"},
        "SiteWAF": {"url": "https://site-waf.com/{}", "error_type": "message", "error_msg": "nope", "category": "other"},
    }
    probe_map = {
        "SiteHit": ("hit", "https://site-hit.com/alice"),
        "SiteMiss": ("miss", None),
        "SiteWAF": ("inconclusive", "waf_blocked"),
    }
    result = _run_module("alice@example.com", sites=sites, probe_map=probe_map)
    assert len(result.findings) == 1
    assert result.findings[0]["platform"] == "sherlock:SiteHit"
    # WAF inconclusive surfaces in errors (not waf_blocked or timeout)
    waf_errors = [e for e in result.errors if "SiteWAF" in e]
    assert len(waf_errors) == 0  # "waf_blocked" is excluded from the errors list


# ---------------------------------------------------------------------------
# FP warnings
# ---------------------------------------------------------------------------

def test_common_username_demoted_to_low() -> None:
    sites = {
        "GitHub": {"url": "https://github.com/{}", "error_type": "status_code", "category": "dev"},
    }
    probe_map = {"GitHub": ("hit", "https://github.com/john")}
    with patch("backend.core.common_names.is_common_username", return_value=True):
        result = _run_module("john@example.com", sites=sites, probe_map=probe_map)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["confidence"] == "low"
    assert "common_username_no_corroboration" in f["metadata"].get("fp_warnings", [])


def test_disposable_email_demoted_to_low() -> None:
    sites = {
        "GitHub": {"url": "https://github.com/{}", "error_type": "status_code", "category": "dev"},
    }
    probe_map = {"GitHub": ("hit", "https://github.com/alice")}
    with patch("backend.core.disposable_domains.is_disposable_email", return_value=True):
        result = _run_module("alice@mailinator.com", sites=sites, probe_map=probe_map)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["confidence"] == "low"
    assert "disposable_email_domain" in f["metadata"].get("fp_warnings", [])


# ---------------------------------------------------------------------------
# Wave classification
# ---------------------------------------------------------------------------

def test_wave_classification_status_code_is_wave1() -> None:
    assert _wave({"error_type": "status_code"}) == 1


def test_wave_classification_message_is_wave2() -> None:
    assert _wave({"error_type": "message"}) == 2


def test_wave_classification_response_url_is_wave2() -> None:
    assert _wave({"error_type": "response_url"}) == 2


def test_wave2_sites_skipped_when_wave2_disabled() -> None:
    sites = {
        "Wave1Site": {"url": "https://site1.com/{}", "error_type": "status_code", "category": "other"},
        "Wave2Site": {"url": "https://site2.com/{}", "error_type": "message", "error_msg": "nope", "category": "other"},
    }
    probe_map = {
        "Wave1Site": ("hit", "https://site1.com/alice"),
        "Wave2Site": ("hit", "https://site2.com/alice"),
    }
    result = _run_module(
        "alice@example.com",
        sites=sites,
        probe_map=probe_map,
        settings_overrides={"enable_sherlock_platforms": True, "enable_sherlock_wave2": False},
    )
    platforms = {f["platform"] for f in result.findings}
    assert "sherlock:Wave1Site" in platforms
    assert "sherlock:Wave2Site" not in platforms


# ---------------------------------------------------------------------------
# Catch-all detection
# ---------------------------------------------------------------------------

def test_catch_all_detection_skips_positive_sites() -> None:
    sites = {
        "CatchAll": {"url": "https://catchall.com/{}", "error_type": "status_code", "category": "other"},
        "Normal": {"url": "https://normal.com/{}", "error_type": "status_code", "category": "other"},
    }
    probe_map = {
        "CatchAll": ("hit", "https://catchall.com/alice"),
        "Normal": ("hit", "https://normal.com/alice"),
    }
    # Pass catch_all directly — CatchAll is already identified as catch-all
    result = _run_module(
        "alice@example.com",
        sites=sites,
        probe_map=probe_map,
        catch_all={"CatchAll"},
    )
    platforms = {f["platform"] for f in result.findings}
    assert "sherlock:CatchAll" not in platforms
    assert "sherlock:Normal" in platforms


# ---------------------------------------------------------------------------
# Health DB integration
# ---------------------------------------------------------------------------

def test_health_db_unhealthy_site_not_probed() -> None:
    sites = {
        "Healthy": {"url": "https://healthy.com/{}", "error_type": "status_code", "category": "other"},
        "Unhealthy": {"url": "https://unhealthy.com/{}", "error_type": "status_code", "category": "other"},
    }
    probe_map = {
        "Healthy": ("hit", "https://healthy.com/alice"),
        "Unhealthy": ("hit", "https://unhealthy.com/alice"),
    }

    async def _should_probe_async(platform_key: str) -> bool:
        return "Unhealthy" not in platform_key

    health = _make_health()
    health.should_probe_async.side_effect = _should_probe_async

    result = _run_module("alice@example.com", sites=sites, probe_map=probe_map, health=health)
    platforms = {f["platform"] for f in result.findings}
    assert "sherlock:Healthy" in platforms
    assert "sherlock:Unhealthy" not in platforms
    assert result.metadata.get("health_skipped", 0) >= 1


# ---------------------------------------------------------------------------
# Finding metadata fields
# ---------------------------------------------------------------------------

def test_finding_metadata_fields_present() -> None:
    sites = {
        "GitHub": {"url": "https://github.com/{}", "error_type": "status_code", "category": "dev"},
    }
    probe_map = {"GitHub": ("hit", "https://github.com/alice")}
    result = _run_module("alice@example.com", sites=sites, probe_map=probe_map)
    assert len(result.findings) == 1
    f = result.findings[0]
    meta = f.get("metadata", {})
    assert meta.get("source") == "sherlock"
    assert meta.get("wave") == 1
    assert meta.get("error_type") == "status_code"
    assert "waf_protected" in meta
    assert f.get("username") is not None
    assert f.get("profile_url") is not None


def test_finding_platform_prefixed_with_sherlock() -> None:
    sites = {
        "Twitch": {"url": "https://twitch.tv/{}", "error_type": "status_code", "category": "media"},
    }
    probe_map = {"Twitch": ("hit", "https://twitch.tv/alice")}
    result = _run_module("alice@example.com", sites=sites, probe_map=probe_map)
    assert result.findings[0]["platform"] == "sherlock:Twitch"


# ---------------------------------------------------------------------------
# Username variants
# ---------------------------------------------------------------------------

def test_username_variants_simple() -> None:
    variants = _username_variants("alice@example.com")
    assert "alice" in variants


def test_username_variants_dotted_email() -> None:
    variants = _username_variants("alice.smith@example.com")
    assert "alice.smith" in variants
    assert "alicesmith" in variants
    assert "alice_smith" in variants


def test_username_variants_no_duplicates() -> None:
    variants = _username_variants("alice@example.com")
    assert len(variants) == len(set(variants))


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def test_confidence_status_code_is_medium() -> None:
    assert _confidence({"error_type": "status_code"}) == "medium"


def test_confidence_message_is_high() -> None:
    assert _confidence({"error_type": "message", "error_msg": "not found"}) == "high"


def test_confidence_response_url_is_high() -> None:
    assert _confidence({"error_type": "response_url"}) == "high"
