"""Confidence scoring constants and aggregator for email harvesting.

The Common Crawl module today and every future domain-harvest module
(press releases, GitHub commit authors, name discovery, ...) feed into
the same scoring surface.  Keeping the model here — even though only
Common Crawl populates it in Phase A — means future phases plug in
without rewriting the scoring code.

Three signal classes stack multiplicatively:

* **Base weight** — how trustworthy the *source type* is
  (CA-attested > 0.7, single URL crawl > 0.5).
* **Verification multiplier** — whether the email was cross-confirmed
  by another source or a live SMTP handshake.
* **Freshness factor** — how recent the attestation is.

The final score is capped at 1.5 to keep the field numeric and
comparable across modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

SOURCE_WEIGHTS: dict[str, float] = {
    "ca_attested": 1.0,
    "smtp_verified": 1.0,
    "github_commit_author": 0.9,
    "github_code_match": 0.6,
    "common_crawl_high_density": 0.7,
    "common_crawl_single": 0.5,
    "press_release": 0.8,
    "search_snippet": 0.5,
    "search_snippet_ddg": 0.5,
    "search_snippet_bing": 0.4,
    "permutation_verified": 0.5,
    "permutation_catchall": 0.2,
    "permutation_unverified": 0.05,
    # W5: Phase 0.10.0 final additions — three new structured-source
    # modules added to the harvest pipeline.
    #
    # npm_package_author / pypi_package_author: explicit maintainer
    # attribution on a published package (not just a string mention in
    # code, which is what github_code_match catches). Both weighted at
    # 0.7 — same tier as common_crawl_high_density: a deliberate user
    # assertion that they own / maintain a published artifact, but
    # without the cryptographic / cross-source confirmation that pushes
    # ca_attested / smtp_verified up to 1.0.
    #
    # pgp_uid: a UID on a PGP key is a deliberate, user-verified
    # assertion of identity — the key holder signed the UID binding
    # the email to their real name. Matches the ca_attested tier of
    # 1.0 (both are "user-verified assertions").
    "npm_package_author": 0.7,
    "pypi_package_author": 0.7,
    "pgp_uid": 1.0,
}

VERIFICATION_MULTIPLIER: dict[str, float] = {
    "no_verification": 0.6,
    "single_source": 0.9,
    "multi_source": 1.2,
    "smtp_verified": 1.4,
    "ca_attested": 1.5,
}

MAX_SCORE = 1.5


@dataclass
class ConfidenceLabel:
    score: float
    label: str
    breakdown: dict[str, float]


def freshness_factor(timestamp: str | None) -> float:
    """Return a freshness multiplier in [0.3, 1.0].

    Bands:
        <= 90 days        → 1.0
        90 - 365 days     → 0.85
        365 - 1095 days   → 0.6
        > 1095 days       → 0.3
        None / unparseable→ 0.7 (unknown age, moderate penalty)
    """
    if not timestamp:
        return 0.7

    cleaned = str(timestamp).strip()
    if not cleaned:
        return 0.7

    parsed: datetime | None = None
    # Try common CC and ISO formats.
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
            return 0.7

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    age_days = max((now - parsed).days, 0)

    if age_days <= 90:
        return 1.0
    if age_days <= 365:
        return 0.85
    if age_days <= 1095:
        return 0.6
    return 0.3


def _select_verification_multiplier(
    source_types: list[str],
    is_smtp_verified: bool,
    is_ca_attested: bool,
) -> tuple[float, str]:
    if is_ca_attested:
        return VERIFICATION_MULTIPLIER["ca_attested"], "ca_attested"
    if is_smtp_verified:
        return VERIFICATION_MULTIPLIER["smtp_verified"], "smtp_verified"
    distinct = len(set(source_types))
    if distinct >= 2:
        return VERIFICATION_MULTIPLIER["multi_source"], "multi_source"
    if distinct == 1:
        return VERIFICATION_MULTIPLIER["single_source"], "single_source"
    return VERIFICATION_MULTIPLIER["no_verification"], "no_verification"


def compute_confidence(
    source_count: int,
    source_types: list[str],
    is_smtp_verified: bool = False,
    is_ca_attested: bool = False,
    oldest_timestamp: str | None = None,
) -> tuple[float, str]:
    """Compute a (score, label) pair for an aggregated email attestation.

    Parameters
    ----------
    source_count:
        Number of *distinct* evidence hits across all sources.
        Currently informational only — weights use ``source_types``.
    source_types:
        Strings drawn from :data:`SOURCE_WEIGHTS`.  Duplicates are
        de-duplicated before scoring so a single source appearing
        5 times does not 5x its weight.
    is_smtp_verified / is_ca_attested:
        See module docstring.
    oldest_timestamp:
        ISO-ish timestamp of the OLDEST supporting hit (CC format
        ``YYYYMMDDHHMMSS`` is supported).  Used for freshness decay.

    Returns
    -------
    (score, label): ``score`` ∈ [0, 1.5], ``label`` ∈ {"HIGH", "MEDIUM", "LOW"}.
    """
    del source_count  # reserved for future "extras boost" rules

    unique_types = {st for st in source_types if st}
    base_score = sum(SOURCE_WEIGHTS.get(t, 0.0) for t in unique_types)

    multiplier, multiplier_label = _select_verification_multiplier(
        source_types=list(unique_types),
        is_smtp_verified=is_smtp_verified,
        is_ca_attested=is_ca_attested,
    )

    freshness = freshness_factor(oldest_timestamp)

    raw = base_score * multiplier * freshness
    final = min(max(raw, 0.0), MAX_SCORE)

    if final >= 0.8:
        label = "HIGH"
    elif final >= 0.5:
        label = "MEDIUM"
    else:
        label = "LOW"

    # Stash a breakdown on the side-effect-free return; we return only
    # (score, label) here, callers that want the breakdown should
    # use :func:`compute_confidence_breakdown`.
    _ = ConfidenceLabel  # silence linters — public class for callers
    return final, label


def compute_confidence_breakdown(
    source_types: list[str],
    is_smtp_verified: bool = False,
    is_ca_attested: bool = False,
    oldest_timestamp: str | None = None,
) -> ConfidenceLabel:
    """Like :func:`compute_confidence` but returns the full breakdown.

    Useful for debugging and for surfacing the reasoning in API
    responses.
    """
    unique_types = {st for st in source_types if st}
    base_score = sum(SOURCE_WEIGHTS.get(t, 0.0) for t in unique_types)
    multiplier, multiplier_label = _select_verification_multiplier(
        source_types=list(unique_types),
        is_smtp_verified=is_smtp_verified,
        is_ca_attested=is_ca_attested,
    )
    freshness = freshness_factor(oldest_timestamp)
    raw = base_score * multiplier * freshness
    final = min(max(raw, 0.0), MAX_SCORE)
    if final >= 0.8:
        label = "HIGH"
    elif final >= 0.5:
        label = "MEDIUM"
    else:
        label = "LOW"
    breakdown = {
        "base_score": round(base_score, 4),
        "multiplier": multiplier,
        "multiplier_label": multiplier_label,
        "freshness": freshness,
        "source_types": sorted(unique_types),
    }
    return ConfidenceLabel(score=final, label=label, breakdown=breakdown)


def label_for_score(score: float) -> str:
    """Public threshold helper — exposed for downstream consumers/tests."""
    if score >= 0.8:
        return "HIGH"
    if score >= 0.5:
        return "MEDIUM"
    return "LOW"
