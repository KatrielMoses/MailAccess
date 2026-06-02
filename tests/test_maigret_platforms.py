from __future__ import annotations

import json

from backend.core.maigret_detector import detect_hit, username_matches_regex
from backend.core.maigret_loader import _filter_sites, _site_mapping
from backend.core.platform_dedup import deduplicate_platform_findings, dedup_key
from backend.modules.base import ModuleResult, ModuleStatus
from backend.modules.maigret_platforms import _username_variants, _wave


def test_message_detection_uses_maigret_presense_spelling() -> None:
    defn = {"checkType": "message", "presenseStrs": ["profile-card", "katriel"]}

    assert detect_hit(defn, "<div>profile-card katriel</div>", 200, "https://x.test/u/katriel") == "hit"
    assert detect_hit(defn, "<div>profile-card</div>", 200, "https://x.test/u/katriel") == "miss"


def test_absence_marker_wins_before_presence() -> None:
    defn = {
        "checkType": "message",
        "absenceStrs": ["not found"],
        "presenseStrs": ["profile-card"],
    }

    assert detect_hit(defn, "profile-card not found", 200, "https://x.test/u/nope") == "miss"


def test_response_url_main_page_redirect_is_miss() -> None:
    defn = {"checkType": "response_url", "urlMain": "https://example.com"}

    assert detect_hit(defn, "", 200, "https://example.com/") == "miss"
    assert detect_hit(defn, "", 200, "https://example.com/u/katriel") == "hit"


def test_regex_filter_rejects_invalid_username() -> None:
    defn = {"regexCheck": r"[a-z0-9_]{3,16}"}

    assert username_matches_regex(defn, "katriel_1") is True
    assert username_matches_regex(defn, "Katriel Moses") is False


def test_loader_accepts_sites_mapping_and_filters_wave1_protections() -> None:
    raw = {
        "sites": {
            "Good": {"url": "https://good.test/{username}", "type": "username"},
            "Disabled": {"url": "https://bad.test/{username}", "disabled": True},
            "Gaia": {"url": "https://id.test/{username}", "type": "gaia_id"},
            "Protected": {
                "url": "https://cf.test/{username}",
                "protection": ["cf_js_challenge"],
            },
        }
    }

    sites = _filter_sites(_site_mapping(raw), include_wave2=False)
    assert set(sites) == {"Good"}
    assert set(_filter_sites(_site_mapping(raw), include_wave2=True)) == {"Good", "Protected"}


def test_username_variants_are_default_three_only() -> None:
    assert _username_variants("katriel.moses-test@example.com") == [
        "katriel.moses-test",
        "katrielmosestest",
        "katriel_moses_test",
    ]


def test_wave_classification_keeps_fast_status_code_in_wave1() -> None:
    assert _wave({"checkType": "status_code", "alexaRank": 100}) == 1
    assert _wave({"checkType": "message", "alexaRank": 100}) == 2
    assert _wave({"checkType": "status_code", "protection": "tls_fingerprint"}) == 2


def test_platform_dedup_merges_wmn_and_maigret_by_domain() -> None:
    results = {
        "whatsmyname": ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "platform": "GitHub",
                    "profile_url": "https://github.com/katriel",
                    "confidence": "high",
                    "metadata": {},
                }
            ],
        ),
        "maigret_platforms": ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "platform": "GitHub",
                    "profile_url": "https://www.github.com/katriel",
                    "confidence": "medium",
                    "metadata": {"source": "maigret"},
                }
            ],
        ),
    }

    stats = deduplicate_platform_findings(results)

    assert dedup_key("https://www.github.com/katriel") == "github.com"
    assert stats["dual_confirmed"] == 1
    assert len(results["whatsmyname"].findings) == 1
    assert results["maigret_platforms"].findings == []
    assert results["whatsmyname"].findings[0]["sources"] == ["maigret", "wmn"]
    assert results["whatsmyname"].metadata["unique_platforms"] == 1
