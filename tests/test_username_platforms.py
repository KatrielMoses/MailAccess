from __future__ import annotations

import asyncio

from backend.core.platform_dedup import dedup_key, deduplicate_platform_findings
from backend.core.probe_detector import detect_hit, username_matches_regex
from backend.core.username_sites import _is_supported_site, load_username_sites
from backend.modules.base import ModuleResult, ModuleStatus
from backend.modules.username_platforms import _username_variants, _wave


def test_message_detection_uses_presense_spelling() -> None:
    defn = {"checkType": "message", "presenseStrs": ["profile-card", "katriel"]}
    url = "https://x.test/u/katriel"

    assert detect_hit(defn, "<div>profile-card katriel</div>", 200, url) == "hit"
    assert detect_hit(defn, "<div>profile-card</div>", 200, url) == "miss"


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


def test_supported_site_filter_honors_disabled_and_wave1_protections() -> None:
    good = {"uri_check": "https://good.test/{username}"}
    disabled = {"uri_check": "https://bad.test/{username}", "disabled": True}
    protected = {"uri_check": "https://cf.test/{username}", "protection": ["cf_js_challenge"]}

    assert _is_supported_site(good, include_wave2=False) is True
    assert _is_supported_site(disabled, include_wave2=False) is False
    # A bot-walled site is held out of Wave 1 but admitted in Wave 2.
    assert _is_supported_site(protected, include_wave2=False) is False
    assert _is_supported_site(protected, include_wave2=True) is True


def test_load_username_sites_reads_local_corpus_offline() -> None:
    # No network: the username-url paradigm comes from data/mailaccess_sites.json.
    sites, meta = asyncio.run(load_username_sites())
    assert meta["source"] == "mailaccess_sites"
    assert meta["sites_loaded"] > 1000
    # Every loaded row is a probeable username-url site keyed by its display name.
    sample = next(iter(sites.values()))
    assert sample["check_type"] == "username-url"
    assert sample.get("uri_check") or sample.get("url")


def test_username_variants_are_default_three_only() -> None:
    assert _username_variants("katriel.moses-test@example.com") == [
        "katriel.moses-test",
        "katrielmosestest",
        "katriel_moses_test",
    ]


def test_wave_classification_is_popularity_not_method_based() -> None:
    # Cheap status-code existence checks stay Wave-1 (the safe corpus backbone),
    # ranked or not.
    assert _wave({"checkType": "status_code", "alexaRank": 100}) == 1
    assert _wave({"checkType": "status_code"}) == 1
    # A well-ranked platform is Wave-1 for ANY detection method — this pulls the
    # message/response_url majors (tiktok/youtube/telegram/…) back into the
    # default run instead of stranding them in the opt-in Wave 2.
    assert _wave({"checkType": "message", "alexaRank": 100}) == 1
    assert _wave({"checkType": "response_url", "alexaRank": 42}) == 1
    # The unranked message/response_url long tail stays Wave-2.
    assert _wave({"checkType": "message"}) == 2
    # Protected / regionally-fragile sites are always held for Wave 2.
    assert _wave({"checkType": "status_code", "protection": "tls_fingerprint"}) == 2
    assert _wave({"checkType": "message", "alexaRank": 5, "protection": ["ip_reputation"]}) == 2
    assert _wave({"checkType": "message", "alexaRank": 5, "tags": ["cn"]}) == 2


def test_platform_dedup_merges_enumeration_and_pivot_by_domain() -> None:
    results = {
        "username_pivot": ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "platform": "GitHub",
                    "profile_url": "https://github.com/katriel",
                    "confidence": "medium",
                    "metadata": {"source": "pivot"},
                }
            ],
        ),
        "username_platforms": ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "platform": "GitHub",
                    "profile_url": "https://www.github.com/katriel",
                    "confidence": "medium",
                    "metadata": {"source": "username_platforms"},
                }
            ],
        ),
    }

    stats = deduplicate_platform_findings(results)

    assert dedup_key("https://www.github.com/katriel") == "github.com"
    assert stats["dual_confirmed"] == 1
    # username_platforms outranks the pivot, so it keeps the merged finding.
    assert len(results["username_platforms"].findings) == 1
    assert results["username_pivot"].findings == []
    assert results["username_platforms"].findings[0]["sources"] == ["pivot", "username_platforms"]
    assert results["username_platforms"].metadata["unique_platforms"] == 1
