"""Confidence scoring constants and aggregator for email harvesting."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

SOURCE_WEIGHTS: dict[str, float] = {
    "pgp_uid": 1.00,
    "ca_attested": 0.95,
    "github_commit_author": 0.95,
    "npm_package_author": 0.75,
    "pypi_package_author": 0.75,
    "press_release": 0.70,
    "common_crawl_high_density": 0.75,
    "common_crawl_medium": 0.55,
    "common_crawl_single": 0.30,
    "wayback_archive": 0.45,  # 0.11.1 Phase 3 — historical but real
    "search_snippet_ddg": 0.35,
    "search_snippet_bing": 0.25,
    "search_snippet_google_cse": 0.55,  # 0.11.1 Phase 4
    "github_org_member": 0.85,  # 0.11.1 Phase 4
    "github_profile_email": 0.85,  # Public email on a name-matched GitHub profile
    "hunter_verified": 0.85,  # 0.11.1 Phase 4 — Hunter confidence >= 90
    "hunter_high": 0.70,  # 0.11.1 Phase 4 — Hunter confidence 70-89
    "hunter_low": 0.45,  # 0.11.1 Phase 4 — Hunter confidence < 70
    "github_code_match": 0.45,
    "permutation_verified": 0.65,
    "permutation_catchall": 0.10,
    "permutation_unverified": 0.00,
    # Direct company-owned identity surfaces.  These are strong evidence
    # of publication, but are kept below cryptographic/developer evidence.
    "security_txt_contact": 0.75,
    "structured_page": 0.70,
    "json_ld": 0.70,
    "microdata": 0.70,
    "rdfa": 0.70,
    "hcard": 0.70,
    "mailto": 0.70,
}

VERIFICATION_MULTIPLIER: dict[str, float] = {
    "single_source": 1.00,
    "multi_source_2": 1.20,
    "multi_source_3": 1.45,
    "multi_source_4plus": 1.65,
    "smtp_verified": 1.50,
    "pgp_or_ca": 1.55,
}

SOURCE_CLASS: dict[str, str] = {
    "pgp_uid": "cryptographic",
    "ca_attested": "cryptographic",
    "github_commit_author": "developer",
    "github_code_match": "developer",
    "npm_package_author": "developer",
    "pypi_package_author": "developer",
    "common_crawl_high_density": "scraping",
    "common_crawl_medium": "scraping",
    "common_crawl_single": "scraping",
    "wayback_archive": "scraping",  # 0.11.1 Phase 3 — CC/Wayback are sibling "scraping" buckets
    "search_snippet_ddg": "scraping",
    "search_snippet_bing": "scraping",
    "search_snippet_google_cse": "scraping",  # 0.11.1 Phase 4
    "github_org_member": "developer",  # 0.11.1 Phase 4
    "github_profile_email": "developer",
    "hunter_verified": "api",
    "hunter_high": "api",
    "hunter_low": "api",
    "press_release": "press",
    "permutation_verified": "verification",
    "permutation_catchall": "verification",
    "permutation_unverified": "verification",
    "security_txt_contact": "direct",
    "structured_page": "direct",
    "json_ld": "direct",
    "microdata": "direct",
    "rdfa": "direct",
    "hcard": "direct",
    "mailto": "direct",
}

MAX_SCORE = 1.5
HIGH_THRESHOLD = 0.85
MEDIUM_THRESHOLD = 0.55


@dataclass
class ConfidenceLabel:
    score: float
    label: str
    breakdown: dict[str, float | str | list[str]]


def freshness_factor(timestamp: str | None) -> float:
    """Return the freshness multiplier for the newest supporting hit."""
    if not timestamp:
        return 0.50

    cleaned = str(timestamp).strip()
    if not cleaned:
        return 0.50

    parsed: datetime | None = None
    for fmt in ("%Y%m%d%H%M%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(cleaned[: len(fmt) + 6], fmt)  # noqa: PERF203
        except ValueError:
            continue
        if parsed is not None:
            break

    if parsed is None:
        try:
            parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        except ValueError:
            return 0.50

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    age_days = max((datetime.now(timezone.utc) - parsed).days, 0)
    if age_days <= 180:
        return 1.00
    if age_days <= 365:
        return 0.85
    if age_days <= 365 * 2:
        return 0.65
    if age_days <= 365 * 3:
        return 0.40
    return 0.15


def _source_family(source_type: str) -> str:
    """Return the corroboration bucket for multiplier selection."""
    if source_type.startswith(("common_crawl_", "search_snippet_", "wayback_")):
        return source_type
    return SOURCE_CLASS.get(source_type, source_type)


def _label(final: float) -> str:
    if final >= HIGH_THRESHOLD:
        return "HIGH"
    if final >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def _select_verification_multiplier(
    source_types: list[str],
    is_smtp_verified: bool,
    is_pgp_or_ca: bool,
) -> tuple[float, str]:
    if is_pgp_or_ca:
        return VERIFICATION_MULTIPLIER["pgp_or_ca"], "pgp_or_ca"
    if is_smtp_verified:
        return VERIFICATION_MULTIPLIER["smtp_verified"], "smtp_verified"

    distinct_families = len({_source_family(st) for st in source_types if st})
    if distinct_families >= 4:
        return VERIFICATION_MULTIPLIER["multi_source_4plus"], "multi_source_4plus"
    if distinct_families >= 3:
        return VERIFICATION_MULTIPLIER["multi_source_3"], "multi_source_3"
    if distinct_families >= 2:
        return VERIFICATION_MULTIPLIER["multi_source_2"], "multi_source_2"
    return VERIFICATION_MULTIPLIER["single_source"], "single_source"


def _pgp_or_ca_flag(
    unique_types: set[str],
    *,
    is_ca_attested: bool,
    is_pgp_or_ca: bool | None,
) -> bool:
    if is_pgp_or_ca is not None:
        return is_pgp_or_ca
    return is_ca_attested or bool(unique_types & {"pgp_uid", "ca_attested"})


def compute_confidence(
    source_count: int,
    source_types: list[str],
    is_smtp_verified: bool = False,
    is_ca_attested: bool = False,
    is_pgp_or_ca: bool | None = None,
    oldest_timestamp: str | None = None,
    last_seen_timestamp: str | None = None,
) -> tuple[float, str]:
    """Compute a ``(score, label)`` pair for aggregated email evidence."""
    del source_count

    unique_types = {st for st in source_types if st}
    base_score = sum(SOURCE_WEIGHTS.get(t, 0.0) for t in unique_types)
    pgp_or_ca = _pgp_or_ca_flag(
        unique_types,
        is_ca_attested=is_ca_attested,
        is_pgp_or_ca=is_pgp_or_ca,
    )
    multiplier, _ = _select_verification_multiplier(
        source_types=list(unique_types),
        is_smtp_verified=is_smtp_verified,
        is_pgp_or_ca=pgp_or_ca,
    )
    freshness = freshness_factor(last_seen_timestamp or oldest_timestamp)
    final = min(max(base_score * multiplier * freshness, 0.0), MAX_SCORE)
    return final, _label(final)


def compute_confidence_breakdown(
    source_types: list[str],
    is_smtp_verified: bool = False,
    is_ca_attested: bool = False,
    is_pgp_or_ca: bool | None = None,
    oldest_timestamp: str | None = None,
    last_seen_timestamp: str | None = None,
) -> ConfidenceLabel:
    """Like :func:`compute_confidence` but returns the full breakdown."""
    unique_types = {st for st in source_types if st}
    base_score = sum(SOURCE_WEIGHTS.get(t, 0.0) for t in unique_types)
    pgp_or_ca = _pgp_or_ca_flag(
        unique_types,
        is_ca_attested=is_ca_attested,
        is_pgp_or_ca=is_pgp_or_ca,
    )
    multiplier, multiplier_label = _select_verification_multiplier(
        source_types=list(unique_types),
        is_smtp_verified=is_smtp_verified,
        is_pgp_or_ca=pgp_or_ca,
    )
    freshness = freshness_factor(last_seen_timestamp or oldest_timestamp)
    final = min(max(base_score * multiplier * freshness, 0.0), MAX_SCORE)
    breakdown = {
        "base_score": round(base_score, 4),
        "multiplier": multiplier,
        "multiplier_label": multiplier_label,
        "freshness": freshness,
        "source_types": sorted(unique_types),
    }
    return ConfidenceLabel(score=final, label=_label(final), breakdown=breakdown)


def label_for_score(score: float) -> str:
    """Public threshold helper, exposed for downstream consumers/tests."""
    return _label(score)
