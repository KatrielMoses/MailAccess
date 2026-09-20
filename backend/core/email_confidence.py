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
    # FIX 4A: package-maintainer emails carry the same developer-evidence
    # weight as package-author emails.
    "npm_maintainer": 0.75,
    "pypi_maintainer": 0.75,
    "github_maintainer": 0.75,
    "press_release": 0.70,
    "common_crawl_high_density": 0.75,
    "common_crawl_medium": 0.55,
    "common_crawl_single": 0.30,
    "wayback_archive": 0.45,  # 0.11.1 Phase 3 — historical but real
    "search_snippet_ddg": 0.35,
    "search_snippet_bing": 0.25,
    "search_snippet_google_cse": 0.55,  # 0.11.1 Phase 4
    "search_snippet_brave": 0.40,  # FIX 4A: Brave was emitted but had no weight
    # FIX 4A: cached PGP finding — real UID evidence, but discounted
    # below live ``pgp_uid`` (1.00) for cache staleness.
    "pgp_cached": 0.65,
    "github_org_member": 0.85,  # 0.11.1 Phase 4
    "github_profile_email": 0.85,  # Public email on a name-matched GitHub profile
    "hunter_verified": 0.85,  # 0.11.1 Phase 4 — Hunter confidence >= 90
    "hunter_high": 0.70,  # 0.11.1 Phase 4 — Hunter confidence 70-89
    "hunter_low": 0.45,  # 0.11.1 Phase 4 — Hunter confidence < 70
    # Phase 7A/7B — enrichment-waterfall connectors. Deliberately BELOW the
    # neutral default (0.30) so an evidenced native person-field claim always
    # outranks enrichment: the waterfall only fills fields that have no native
    # claim, and these weights just order apollo-vs-pdl when both answer.
    "apollo": 0.28,  # lawful-public business data
    "pdl": 0.24,  # data-broker (security-only)
    "github_code_match": 0.45,
    "permutation_verified": 0.65,
    "permutation_catchall": 0.10,
    # P6: passive priors for generated name patterns. These rank
    # candidates but do not claim that a mailbox currently exists.
    "permutation_unverified_{first}_{last}": 0.15,
    "permutation_unverified_{first}": 0.13,
    "permutation_unverified_{f}{last}": 0.12,
    "permutation_unverified_{first}{last}": 0.09,
    "permutation_unverified_{last}": 0.07,
    "permutation_unverified_{last}_{first}": 0.05,
    "permutation_unverified_other": 0.03,
    # 0.16.0 Phase 2 — company email-pattern index. A learned, per-domain
    # pattern from the corpus (name+domain -> one graded email). This is the
    # high-confidence sibling of the corpus-prior "matches the known pattern"
    # nudge, so it sits at the top of the unverified band (level with
    # ``permutation_mx_valid``). The value here is only a *fallback* — callers
    # pass the per-candidate ``applied_confidence`` (Wilson lower bound) through
    # the scorer's ``source_confidence`` override, so the score tracks the
    # domain's real support. The signal is always unverified: it can never on
    # its own reach the CONFIRMED band (see ``company_pattern_index`` caller).
    "company_pattern_index": 0.30,
    # 0.17.0 Brief A (A2) — hosted "MailAccess Pro" corpus evidence. A deliberate
    # FLOOR weight, below the neutral default (0.30) and below every native
    # person-field source, so that even if a corpus observation ever reached the
    # person-field resolver on a row that also carries a native claim, the native
    # claim always outranks it (belt-and-suspenders over the primary fix, which is
    # that corpus evidence never enters a native row's resolution at all). Corpus
    # leads themselves are net-new rows scored at a fixed prior, so this weight
    # never inflates or deflates their own confidence.
    "mailaccess_pro": 0.05,
    # FIX 4D: removed dead SOURCE_WEIGHTS keys — no module ever emitted
    # these source types (verified by repo-wide grep), so they only
    # added confusion and could silently inflate a pure-guess candidate
    # to CONFIRMED if ever wired up.  Removed keys:
    #   * ``permutation_format_match``          (was 0.20)
    #   * ``permutation_name_match``            (was 0.25)
    #   * ``permutation_unverified_{first}_tier1`` (was 0.55)
    # Autodiscover existence probe (FIX 2). Kept just below SMTP/PGP
    # verification but above unverified permutations.
    "autodiscover_m365": 0.90,
    # M365 Passive Intel Phase 1.
    #   * autodiscover_rest — Check 3, just below autodiscover_m365 (0.90).
    #   * onedrive_probe    — Check 4, an independent existence signal.
    #   * m365_getuserrealm — Check 1, tenant intelligence, not an existence
    #                         signal, so it contributes 0 to the score.
    #   * openid_preflight  — Check 5, infrastructure signal only, 0 weight.
    "autodiscover_rest": 0.88,
    "onedrive_probe": 0.80,
    "m365_getuserrealm": 0.0,
    "openid_preflight": 0.0,
    # Enterprise Net Intel Phase 2 — infrastructure metadata only. Neither
    # signal claims a mailbox exists, so both contribute 0 to the score.
    "ntlm_challenge": 0.0,
    "lync_discovery": 0.0,
    # M365 Active Intel Phase 3 — single-probe account-state telemetry. Each
    # sends exactly one probe with an invalid credential. All three are direct
    # provider-side existence checks and, like autodiscover_m365, do not decay.
    #   * aadsts_probe     — direct AADSTS decode (highest signal).
    #   * wstrust_probe    — federated authentication attempt.
    #   * activesync_probe — timing heuristic, less definitive.
    "aadsts_probe": 0.90,
    "wstrust_probe": 0.85,
    "activesync_probe": 0.65,
    # Native syntax + DNS evidence. This is stronger than an untested
    # permutation, but intentionally below SMTP mailbox verification.
    # Phase 4 — IMAP single-probe existence. A decoded IMAP LOGIN response is a
    # direct provider-side existence signal for self-hosted / shared-hosting
    # domains, kept in line with the other verification checks.
    "imap_probe": 0.70,
    "permutation_mx_valid": 0.30,
    "permutation_verified_m365": 0.85,
    "permutation_verified_yahoo": 0.80,
    "permutation_verified_google": 0.80,
    "permutation_gravatar_hit": 0.30,
    "permutation_breach_hit": 0.15,
    "breach_recent": 0.20,
    "breach_historical": 0.10,
    # Phase 5 — breach aggregation. Corroborates that an email existed at
    # breach time (not necessarily current); ages via freshness_factor and
    # is never a PERMANENT source.
    "scylla_breach": 0.55,
    "hibp_paste": 0.50,
    "dehashed_breach": 0.70,  # paid aggregator, higher data quality
    "snusbase_breach": 0.68,
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
    "pgp_cached": "cryptographic",  # FIX 4A
    "ca_attested": "cryptographic",
    "github_commit_author": "developer",
    "github_code_match": "developer",
    "npm_package_author": "developer",
    "pypi_package_author": "developer",
    "npm_maintainer": "developer",  # FIX 4A
    "pypi_maintainer": "developer",  # FIX 4A
    "github_maintainer": "developer",  # FIX 4A
    "common_crawl_high_density": "scraping",
    "common_crawl_medium": "scraping",
    "common_crawl_single": "scraping",
    "wayback_archive": "scraping",  # 0.11.1 Phase 3 — CC/Wayback are sibling "scraping" buckets
    "search_snippet_ddg": "scraping",
    "search_snippet_bing": "scraping",
    "search_snippet_google_cse": "scraping",  # 0.11.1 Phase 4
    "search_snippet_brave": "scraping",  # FIX 4A
    "github_org_member": "developer",  # 0.11.1 Phase 4
    "github_profile_email": "developer",
    "hunter_verified": "api",
    "hunter_high": "api",
    "hunter_low": "api",
    # Phase 7A/7B enrichment connectors — third-party data APIs, grouped with
    # the other paid-API providers so every weighted source has a source *class*
    # for per-source-FP calibration accounting (invariant: SOURCE_WEIGHTS ⊆ SOURCE_CLASS).
    "apollo": "api",
    "pdl": "api",
    "press_release": "press",
    "permutation_verified": "verification",
    "permutation_catchall": "verification",
    "permutation_unverified_{first}_{last}": "verification",
    "permutation_unverified_{first}": "verification",
    "permutation_unverified_{f}{last}": "verification",
    "permutation_unverified_{first}{last}": "verification",
    "permutation_unverified_{last}": "verification",
    "permutation_unverified_{last}_{first}": "verification",
    "permutation_unverified_other": "verification",
    # 0.16.0 Phase 2 — the learned company-pattern index gets its OWN
    # corroboration family so it can never collude with real verification
    # signals to inflate the multi-source multiplier: an unverified inference
    # is one source, not a corroborator of a live probe.
    "company_pattern_index": "pattern_index",
    # 0.17.0 Brief A (A2) — hosted "MailAccess Pro" corpus evidence gets its OWN
    # corroboration family so it can never collude with real verification signals to
    # inflate the multi-source multiplier (invariant: SOURCE_WEIGHTS ⊆ SOURCE_CLASS).
    "mailaccess_pro": "corpus",
    # FIX 4D: dead keys removed (permutation_format_match,
    # permutation_name_match, permutation_unverified_{first}_tier1).
    "autodiscover_m365": "verification",  # FIX 2
    # M365 Passive Intel Phase 1. The two existence signals join the
    # "verification" family; the two infrastructure signals share a single
    # "infrastructure" family so that, even if they ever leak into a per-email
    # source-type list, they collapse to one family and cannot inflate the
    # multi-source multiplier.
    "autodiscover_rest": "verification",
    "onedrive_probe": "verification",
    "m365_getuserrealm": "infrastructure",
    "openid_preflight": "infrastructure",
    # Enterprise Net Intel Phase 2 — share the single "infrastructure"
    # family so they can never inflate the multi-source multiplier.
    "ntlm_challenge": "infrastructure",
    "lync_discovery": "infrastructure",
    # M365 Active Intel Phase 3 — all three join the "verification" family.
    "aadsts_probe": "verification",
    "activesync_probe": "verification",
    "wstrust_probe": "verification",
    # Phase 4 — IMAP single-probe existence joins the "verification" family.
    "imap_probe": "verification",
    "permutation_mx_valid": "verification",
    "permutation_verified_m365": "verification",
    "permutation_verified_yahoo": "verification",
    "permutation_verified_google": "verification",
    "permutation_gravatar_hit": "corroboration",
    "permutation_breach_hit": "corroboration",
    "breach_recent": "corroboration",
    "breach_historical": "corroboration",
    # Phase 5 — breach aggregation sources share the "breach" family.
    "scylla_breach": "breach",
    "hibp_paste": "breach",
    "dehashed_breach": "breach",
    "snusbase_breach": "breach",
    "security_txt_contact": "direct",
    "structured_page": "direct",
    "json_ld": "direct",
    "microdata": "direct",
    "rdfa": "direct",
    "hcard": "direct",
    "mailto": "direct",
}

MAX_SCORE = 1.5

# FIX 4B: sources whose evidence does not decay with age.  A PGP UID,
# a git commit authorship, or a confirmed provider-side existence check
# is exactly as strong eight years later as it was the day it was made —
# applying the freshness penalty to these inverts the evidence hierarchy
# (a fresh scrape outscoring a decade-old cryptographic signature).
PERMANENT_SOURCES: frozenset[str] = frozenset(
    {
        "pgp_uid",
        "pgp_cached",
        "pgp_subkey",
        "github_commit_author",
        "autodiscover_m365",
        # M365 Passive Intel Phase 1: provider-side existence checks. Like
        # autodiscover_m365, a confirmed REST-Autodiscover / OneDrive result
        # is exactly as strong later as the day it was made — it must not
        # decay with age.
        "autodiscover_rest",
        "onedrive_probe",
        "permutation_verified_m365",
        "permutation_verified_google",
        # M365 Active Intel Phase 3: single-probe account-state checks. A
        # confirmed AADSTS / WS-Trust / ActiveSync result reflects the account
        # state at probe time and does not decay with age.
        "aadsts_probe",
        "wstrust_probe",
        "activesync_probe",
        # Phase 4 — a decoded IMAP existence result reflects the account state
        # at probe time and does not decay with age.
        "imap_probe",
    }
)

# P7: 4-tier label system.  The legacy 3-tier thresholds
# (HIGH ≥ 0.85, MEDIUM ≥ 0.55, LOW < 0.55) collapsed two
# qualitatively different evidence bands into a single "MEDIUM"
# bucket — a real SMTP-confirmed-but-stale CC hit and a weak
# passive inference both landed in the same tier.  The new
# 4-tier split makes the analyst's per-tier counts directly
# actionable:
#
#   CONFIRMED  ≥ 0.85   cryptographic or SMTP-verified
#   LIKELY     ≥ 0.70   strong passive inference (Hunter high,
#                       format+name match, etc.)
#   MEDIUM     ≥ 0.50   weak corroboration (single source, CC,
#                       dork snippet, etc.)
#   LOW        <  0.50  speculative (unverified permutations,
#                       stale data, etc.)
#
# The 0.70 LIKELY band is the new "should I pivot on this"
# threshold — the old 0.55 was too lax and produced
# LIKELY-or-better counts that included everything that wasn't
# outright noise.
CONFIRMED_THRESHOLD = 0.85
LIKELY_THRESHOLD = 0.70
MEDIUM_THRESHOLD = 0.50

#: All valid label strings, in tier order (highest first).
LABEL_TIERS: tuple[str, ...] = ("CONFIRMED", "LIKELY", "MEDIUM", "LOW")
LOW_LABEL = "LOW"
MEDIUM_LABEL = "MEDIUM"
LIKELY_LABEL = "LIKELY"
CONFIRMED_LABEL = "CONFIRMED"


@dataclass
class ConfidenceLabel:
    score: float
    label: str
    breakdown: dict[str, float | str | list[str]]


#: 0.16.0 Phase 2 — non-permutation source types that are, like permutations, a
#: *present-tense inference* with no observation age. They opt in to the same
#: "no freshness penalty on a missing timestamp" rule (a learned pattern is not
#: a stale data point). Kept as a literal here to avoid importing the applier
#: module (which imports this one).
_INFERENCE_SOURCE_TYPES: frozenset[str] = frozenset(
    {"company_pattern_index", "pattern_generated", "pattern_inference"}
)


def _is_inference_source(source: str | None) -> bool:
    """True for permutation / learned-pattern sources — present-tense, no age."""
    if not source:
        return False
    s = str(source).strip().lower()
    return s.startswith("permutation_") or s in _INFERENCE_SOURCE_TYPES


def is_inference_source(source: str | None) -> bool:
    """Public alias of :func:`_is_inference_source` — the shared evidence-kind
    contract for "this source is a generated/learned inference, not an observation".

    0.16.0 fix-pass Root B: aggregation and the serving boundaries classify a
    finding as observed-vs-inferred through this one predicate (plus an explicit
    ``is_inference`` metadata flag), never a bespoke per-call source-name allowlist,
    so a permutation guess can never be mistaken for an observation that clears the
    verification gate.
    """
    return _is_inference_source(source)


def unverified_source_type_for_template(template: str | None) -> str:
    """Map a generated template to its passive confidence source key."""
    known = {
        "{first}.{last}@{domain}": "permutation_unverified_{first}_{last}",
        "{first}@{domain}": "permutation_unverified_{first}",
        "{f}{last}@{domain}": "permutation_unverified_{f}{last}",
        "{first}{last}@{domain}": "permutation_unverified_{first}{last}",
        "{last}@{domain}": "permutation_unverified_{last}",
        "{last}.{first}@{domain}": "permutation_unverified_{last}_{first}",
    }
    return known.get(template or "", "permutation_unverified_other")


def freshness_factor(timestamp: str | None, source: str | None = None) -> float:
    """Return the freshness multiplier for the newest supporting hit.

    P2: when *timestamp* is ``None`` AND *source* is a permutation
    type, return ``1.0`` instead of the default ``0.50``.  Generated
    patterns have no observation age — the template is a present-
    tense inference, not a stale data point.  The penalty was
    silently halving the score of every unverified permutation,
    which is a categorically different artifact from a real email
    whose timestamp is missing.

    The ``source`` check is opt-in: callers that pass ``source=None``
    get the legacy behaviour.  Pattern candidates and any source
    starting with ``"permutation_"`` — plus the learned company-pattern
    index (0.16.0 Phase 2) — opt in to the relaxed rule via
    :func:`_is_inference_source`.

    FIX 4B: sources in :data:`PERMANENT_SOURCES` never decay — they
    return ``1.0`` regardless of the timestamp.
    """
    if source and str(source) in PERMANENT_SOURCES:
        return 1.0
    if not timestamp:
        if _is_inference_source(source):
            return 1.0
        return 0.50

    cleaned = str(timestamp).strip()
    if not cleaned:
        if _is_inference_source(source):
            return 1.0
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
    """Return the corroboration bucket for multiplier selection.

    FIX 4C: collapse every Common Crawl density tier, every search
    snippet engine, and every Wayback variant to a SINGLE family each.
    Previously each tier/engine returned itself as its own family, so a
    single web page indexed by three CC collections (or surfaced by
    three search engines) counted as three distinct corroborating
    sources and wrongly triggered the multi-source multiplier.  One page
    is one source, regardless of how many crawlers indexed it.
    """
    if source_type.startswith("common_crawl_"):
        return "common_crawl"
    if source_type.startswith("search_snippet_"):
        return "search_snippet"
    if source_type.startswith("wayback_"):
        return "wayback"
    return SOURCE_CLASS.get(source_type, source_type)


def _label(final: float) -> str:
    # P7: 4-tier label system.  See :data:`CONFIRMED_THRESHOLD`
    # and the surrounding tier constants for the rationale.
    if final >= CONFIRMED_THRESHOLD:
        return CONFIRMED_LABEL
    if final >= LIKELY_THRESHOLD:
        return LIKELY_LABEL
    if final >= MEDIUM_THRESHOLD:
        return MEDIUM_LABEL
    return LOW_LABEL


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


def _assess_email_confidence(
    source_types: list[str],
    is_smtp_verified: bool = False,
    is_ca_attested: bool = False,
    is_pgp_or_ca: bool | None = None,
    oldest_timestamp: str | None = None,
    last_seen_timestamp: str | None = None,
    source_confidence: dict[str, float] | None = None,
    cap_unverified_inference: bool = False,
) -> ConfidenceLabel:
    """The single canonical email-confidence scorer — (score, label, breakdown).

    Part 0.1 / Q6: both the scalar ``compute_confidence`` and the
    ``compute_confidence_breakdown`` paths delegate here, so they can NEVER diverge.
    Previously the breakdown path selected its freshness ``perm_source`` from
    ``permutation_``-prefixed types only, ignoring ``PERMANENT_SOURCES`` — so a
    permanent source like ``github_commit_author`` (2010) scored 0.95 through the
    scalar path but ~0.14 through the breakdown path (age-decayed). Here the
    PERMANENT-source rule is applied once, and the MAX_SCORE clip is enforced once.

    0.16.0 Phase 2: ``source_confidence`` is an optional per-source-type weight
    OVERRIDE, e.g. ``{"company_pattern_index": 0.82}``. It lets a source carry a
    *calibrated per-candidate* base contribution instead of the fixed
    :data:`SOURCE_WEIGHTS` value, while still flowing through the one canonical
    multiplier / freshness / label pipeline — no parallel scorer. Unlisted source
    types fall back to :data:`SOURCE_WEIGHTS` as before, so this is backward
    compatible (default ``None`` reproduces the legacy score exactly).

    0.16.0 fix-pass Root B: ``cap_unverified_inference`` is the ONE canonical home
    of the honesty cap. When set, a score that reaches the CONFIRMED band is
    downgraded to LIKELY (the numeric score is unchanged) and the breakdown is
    stamped ``capped_from_confirmed``. An *unverified* inference — a corpus-pattern
    guess or a permutation with no per-mailbox proof — can therefore never present
    as CONFIRMED **anywhere the label is computed** (the applier, aggregation,
    export, ``read_leads``), not just in one adapter. ``False`` (the default)
    reproduces the legacy label exactly.
    """
    unique_types = {st for st in source_types if st}

    def _weight(t: str) -> float:
        if source_confidence is not None and t in source_confidence:
            return float(source_confidence[t])
        return SOURCE_WEIGHTS.get(t, 0.0)

    base_score = sum(_weight(t) for t in unique_types)
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
    # A PERMANENT source (PGP, commit, provider-verified) wins and disables decay;
    # otherwise the first permutation source (which returns 1.0 on a missing timestamp).
    perm_source = next(
        (st for st in unique_types if st in PERMANENT_SOURCES),
        None,
    ) or next(
        (st for st in unique_types if _is_inference_source(st)),
        None,
    )
    freshness = freshness_factor(
        last_seen_timestamp or oldest_timestamp,
        source=perm_source,
    )
    final = min(max(base_score * multiplier * freshness, 0.0), MAX_SCORE)
    breakdown: dict[str, float | str | list[str]] = {
        "base_score": round(base_score, 4),
        "multiplier": multiplier,
        "multiplier_label": multiplier_label,
        "freshness": freshness,
        "source_types": sorted(unique_types),
    }
    label = _label(final)
    # Root B — the honesty cap, applied in the ONE canonical scorer. An unverified
    # inference can never present as CONFIRMED, wherever the label is computed.
    if cap_unverified_inference and label == CONFIRMED_LABEL:
        label = LIKELY_LABEL
        breakdown["capped_from_confirmed"] = True
    return ConfidenceLabel(score=final, label=label, breakdown=breakdown)


def compute_confidence(
    source_count: int,
    source_types: list[str],
    is_smtp_verified: bool = False,
    is_ca_attested: bool = False,
    is_pgp_or_ca: bool | None = None,
    oldest_timestamp: str | None = None,
    last_seen_timestamp: str | None = None,
    source_confidence: dict[str, float] | None = None,
    cap_unverified_inference: bool = False,
) -> tuple[float, str]:
    """Compute a ``(score, label)`` pair for aggregated email evidence."""
    del source_count
    assessment = _assess_email_confidence(
        source_types,
        is_smtp_verified=is_smtp_verified,
        is_ca_attested=is_ca_attested,
        is_pgp_or_ca=is_pgp_or_ca,
        oldest_timestamp=oldest_timestamp,
        last_seen_timestamp=last_seen_timestamp,
        source_confidence=source_confidence,
        cap_unverified_inference=cap_unverified_inference,
    )
    return assessment.score, assessment.label


def compute_confidence_breakdown(
    source_types: list[str],
    is_smtp_verified: bool = False,
    is_ca_attested: bool = False,
    is_pgp_or_ca: bool | None = None,
    oldest_timestamp: str | None = None,
    last_seen_timestamp: str | None = None,
    source_confidence: dict[str, float] | None = None,
    cap_unverified_inference: bool = False,
) -> ConfidenceLabel:
    """Like :func:`compute_confidence` but returns the full breakdown.

    Delegates to the single canonical scorer so the score/label are byte-identical
    to :func:`compute_confidence` for the same inputs.
    """
    return _assess_email_confidence(
        source_types,
        is_smtp_verified=is_smtp_verified,
        is_ca_attested=is_ca_attested,
        is_pgp_or_ca=is_pgp_or_ca,
        oldest_timestamp=oldest_timestamp,
        last_seen_timestamp=last_seen_timestamp,
        source_confidence=source_confidence,
        cap_unverified_inference=cap_unverified_inference,
    )


def label_for_score(score: float, *, cap_unverified_inference: bool = False) -> str:
    """Public threshold helper, exposed for downstream consumers/tests."""
    label = _label(score)
    return LIKELY_LABEL if cap_unverified_inference and label == CONFIRMED_LABEL else label
