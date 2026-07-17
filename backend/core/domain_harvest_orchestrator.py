"""Domain Email Harvest orchestrator — Phase C3 (final) + W5 + 0.11.1 Phase 3.

Ties the domain-mode modules together:

    commoncrawl_email         ─┐
    wayback_domain_harvest    ─┤  ← 0.11.1 Phase 3 (CC + Wayback are the
    code_and_cert_email       ─┤    "best free sources when search is
    email_search_dork         ─┤    blocked").
    employee_name_discovery   ─┤ Phase 1+2 (run concurrently)
    npm_email                 ─┤
    pypi_email                ─┤
    pgp_domain_email          ─┘
                                │
                                │ (feeds pattern_and_verify)
                                ▼
                  pattern_and_verify   ─ Phase 3 (depends on C1)

The W5 additions (npm_email, pypi_email, pgp_domain_email) slot into
Phase 1 — they share the same "fast / cheap / parallel" budget as
commoncrawl_email and code_and_cert_email and run via
``asyncio.as_completed`` exactly like the existing Phase 1 modules.

0.11.1 Phase 3 adds two modules:

* ``commoncrawl_email`` was extended to sweep multiple CC collections
  and to apply Cloudflare ``data-cfemail`` decoding + structured
  person extraction on every fetched page.
* ``wayback_domain_harvest`` was added — it sweeps Wayback CDX for
  high-signal URLs on the target domain, fetches archived pages via
  the operator's ``StealthSession``, runs the same CF decode +
  person extraction, and emits findings tagged
  ``is_historical=True``.

This module does NOT modify the individual source modules.  It only
wires them together, performs cross-module deduplication and
confidence aggregation, and returns a single
:class:`DomainHarvestResult` for the report layer to consume.

Wayback historical findings naturally receive the freshness penalty
the spec calls for — the orchestrator's existing
:func:`backend.core.email_confidence.freshness_factor` reads
``snapshot_timestamp`` (which :func:`_extract_oldest_timestamp` and
the underlying metadata pick up).  Wayback snapshots are rarely
recent so most of them land in the 0.40 or 0.15 buckets.

SMTP verification is OFF BY DEFAULT — the *only* way to enable it is
for the caller to explicitly pass ``enable_smtp=True`` to
:func:`run_domain_harvest`.  The CLI flag is the single source of
truth for this decision.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..config import settings
from ..modules.base import ModuleResult, ModuleStatus
from ..modules.domain_intel import _FREE_PROVIDERS
from ..modules.pattern_and_verify import (
    EmployeeNameResult,
    employee_name_result_from_dict,
)
from .concurrent_fetch_cache import CachedFetch, ConcurrentFetchCache
from .context_router import IndustryVocabularyResult, IndustryVocabularyRouter
from .email_confidence import (
    MAX_SCORE,
    compute_confidence,
    compute_confidence_breakdown,
    label_for_score,
)
from .email_extraction import subaddress_key
from .email_validator import validate_email_batch
from .hunter_client import (
    HUNTER_MONTHLY_CAP,
    hunter_circuit_open,
)
from .hunter_client import (
    search_domain as hunter_search,
)
from .m365_tenant import get_user_realm
from .m365_verifier import M365Verifier
from .google_workspace_verifier import GoogleWorkspaceVerifier
from .mail_provider import MailProvider, detect_provider_from_mx
from .mx_resolver import resolve_mx
from .role_classifier import classify_email
from .signal_pool import AsyncSignalPool
from .smtp_verifier import (
    DEFAULT_PROBE_DELAY,
    DEFAULT_SENDER,
    MAX_PROBES_HARD_CAP,
    SMTPVerifier,
)
from .stealth_client import StealthSession, resolve_timing_profile
from .time_budget import TimeBudget, budget_for_profile
from .yahoo_verifier import YahooVerifier

_LOG = logging.getLogger(__name__)

#: Module names we orchestrate.  Used as keys in
#: ``DomainHarvestResult.module_results``.
MODULE_COMMONCRAWL = "commoncrawl_email"
MODULE_WAYBACK_DOMAIN = "wayback_domain_harvest"  # 0.11.1 Phase 3
MODULE_CODE_CERT = "code_and_cert_email"
MODULE_EMAIL_DORK = "email_search_dork"
MODULE_EMPLOYEE_NAMES = "employee_name_discovery"
MODULE_NPM_EMAIL = "npm_email"
MODULE_PYPI_EMAIL = "pypi_email"
MODULE_PGP_DOMAIN_EMAIL = "pgp_domain_email"
MODULE_SYNDICATION_FEED_SWEEPER = "syndication_feed_sweeper"
MODULE_CONTENT_INTELLIGENCE = "content_intelligence"
MODULE_PATTERN_VERIFY = "pattern_and_verify"
MODULE_GITHUB_ORG_MEMBERS = "github_org_members"  # 0.11.1 Phase 4
MODULE_GITHUB_DOMAIN_COMMITS = "github_domain_commits"
_PROXY_AWARE_MODULES = {
    MODULE_EMAIL_DORK,
    MODULE_EMPLOYEE_NAMES,
}

#: Domain validation regex — a basic sanity check.  We reuse the same
#: shape other modules in MailAccess use (whois_lookup, domain_intel).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$"
)


@dataclass
class HarvestedEmail:
    """One unique email aggregated across all module sources."""

    email: str
    on_domain: bool
    is_role: bool
    role_match_type: str | None
    confidence_score: float
    confidence_label: str  # "HIGH" | "MEDIUM" | "LOW"
    found_by_modules: list[str] = field(default_factory=list)
    source_count: int = 0
    evidence: list[dict[str, Any]] = field(default_factory=list)
    first_seen_timestamp: str | None = None
    last_seen_timestamp: str | None = None
    is_smtp_verified: bool = False
    is_provider_verified: bool = False
    # Provider verifier (Google Workspace / M365) attribution carried onto the
    # aggregated record. ``provider_verification_provider`` is the MailProvider
    # value ("google" / "m365"); ``provider_verification_status`` is the
    # verifier's per-email status ("verified", "inconclusive", ...). Both stay
    # None until a provider verifier reports on this email.
    provider_verification_provider: str | None = None
    provider_verification_status: str | None = None
    is_ca_attested: bool = False
    is_pgp_or_ca: bool = False
    # MUST-FIX M4: how many raw findings contributed to this email
    # overall (across all modules). A CC module finding the same
    # address on 200 indexed pages contributes 200 to this counter
    # but only ONE evidence entry below.
    total_finding_count: int = 0
    # MUST-FIX M4: occurrence count per module — preserves the
    # "this email was seen N times by the CC module" signal without
    # bloating the evidence list.
    occurrence_count_per_module: dict[str, int] = field(default_factory=dict)
    # MUST-FIX M4: deduplicated union of distinguishing source URLs
    # collected across all findings for this email. Capped at
    # ``_MAX_SOURCE_URLS_PER_EMAIL`` to keep JSON exports bounded.
    aggregated_source_urls: list[str] = field(default_factory=list)
    # MUST-FIX S2: alternate forms observed for this email
    # (``foo+filter@x.com`` and ``foo+list@x.com`` when the canonical
    # entry is ``foo@x.com``). Empty when no variants were seen.
    subaddress_variants: list[str] = field(default_factory=list)
    # MUST-FIX S4: full per-email reasoning snapshot — what the
    # ``compute_confidence_breakdown`` function produced for this entry
    # (base_score, multiplier, freshness, source_types, multiplier_label).
    # Surfaced into the CLI as a compact rationale chip and into the
    # JSON export in full so downstream tooling can build its own
    # explanations.
    confidence_breakdown: dict[str, Any] | None = None
    # Signal-pool identity-cluster snapshot. This is kept separate from the
    # source-confidence score so graph evidence is visible without silently
    # rewriting provenance-based email scoring.
    identity_graph_score: float | None = None
    identity_graph_label: str | None = None
    identity_graph_flags: list[str] = field(default_factory=list)


# MUST-FIX M4: cap on aggregated_source_urls to keep JSON export
# from blowing up on a high-traffic domain with thousands of CC hits.
_MAX_SOURCE_URLS_PER_EMAIL = 50


@dataclass
class DomainHarvestResult:
    domain: str
    started_at: str
    completed_at: str
    duration_seconds: float
    module_results: dict[str, ModuleResult]
    unique_emails: list[HarvestedEmail]
    total_unique_emails: int
    # P7: 4-tier counts.  ``high_confidence_count`` now counts
    # the CONFIRMED tier; ``medium_confidence_count`` is the
    # historical "anything above LOW" band (LIKELY + MEDIUM);
    # ``low_confidence_count`` is the LOW tier.  The new
    # ``likely_confidence_count`` field exposes the LIKELY
    # tier on its own for downstream consumers.
    high_confidence_count: int
    likely_confidence_count: int
    medium_confidence_count: int
    low_confidence_count: int
    role_account_count: int
    personal_email_count: int
    errors: list[str] = field(default_factory=list)
    smtp_verification_used: bool = False
    catchall_detected: bool | None = None
    confirmed_pattern: str | None = None
    employee_names_processed: int = 0
    # 0.11.1 Phase 3 cache: hits / misses / evictions from the
    # per-run ConcurrentFetchCache.  ``None`` when the cache was
    # disabled (e.g. curl-cffi unavailable in the test environment).
    fetch_cache_stats: dict[str, int] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    from_cache: bool = False
    cache_age_seconds: float = 0.0
    cached_at: str | None = None
    # Off-domain addresses discovered while harvesting ``domain``. They are
    # retained for analyst pivots but never mixed into ``unique_emails``.
    shadow_profiles: list[dict[str, Any]] = field(default_factory=list)


def _normalize_module_result(
    module_name: str, result: ModuleResult | None
) -> ModuleResult:
    if result is not None:
        return result
    _LOG.warning(
        "Module %s returned None instead of ModuleResult — skipping",
        module_name,
    )
    return ModuleResult(
        status=ModuleStatus.FAILED,
        findings=[],
        metadata={},
        errors=["Module returned None — this is a bug in the module"],
    )


# ---------------------------------------------------------------------
# Domain validation + free-provider rejection
# ---------------------------------------------------------------------
def _is_free_provider(domain: str) -> bool:
    """Reuse MailAccess's existing free-provider detection."""
    return bool(domain) and domain in _FREE_PROVIDERS


def _validate_domain(domain: str) -> str:
    """Normalize + validate a domain string.

    Raises ``ValueError`` with a human-readable explanation on failure.
    Returns the cleaned domain on success.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("Domain must be a non-empty string")
    cleaned = domain.strip().lower()
    if not _DOMAIN_RE.match(cleaned):
        raise ValueError(
            f"Invalid domain format: {domain!r}. "
            "Expected something like 'example.com'."
        )
    if _is_free_provider(cleaned):
        raise ValueError(
            f"{cleaned} is a free email provider — domain harvesting "
            "on free providers produces noisy / meaningless results. "
            "Pass a corporate / institutional domain instead."
        )
    return cleaned


# ---------------------------------------------------------------------
# Adapter: findings → EmployeeNameResult list
# ---------------------------------------------------------------------
def _employee_names_from_findings(
    findings: list[dict[str, Any]],
) -> list[EmployeeNameResult]:
    """Reconstruct :class:`EmployeeNameResult` objects from
    ``employee_name_discovery`` findings.

    The Phase C1 module emits findings whose ``metadata`` dict has
    the ``name`` field — we adapt that into a structured object that
    :class:`PatternAndVerifyModule.run` accepts.
    """
    out: list[EmployeeNameResult] = []
    for finding in findings:
        meta = finding.get("metadata") or {}
        if not isinstance(meta, dict):
            continue
        # Findings from employee_name_discovery look like:
        #   {"name": str, "sources": list[str], "source_count": int,
        #    "title_or_role": str|None, "confidence": float, ...}
        payload = {
            "name": meta.get("name") or "",
            "sources": meta.get("sources") or [],
            "source_count": meta.get("source_count") or 0,
            "title_or_role": meta.get("title_or_role"),
            "confidence": meta.get("confidence_score")
            or meta.get("confidence")
            or 0.5,
            "source_urls": meta.get("source_urls") or [],
        }
        try:
            out.append(employee_name_result_from_dict(payload))
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("Skipping malformed employee finding: %s", exc)
    return out


# ---------------------------------------------------------------------
# Aggregation: build HarvestedEmail list from module results
# ---------------------------------------------------------------------
def _extract_email(finding: dict[str, Any]) -> str | None:
    """Pull the canonical email string out of a FindingItem dict."""
    meta = finding.get("metadata") or {}
    if not isinstance(meta, dict):
        return None
    for key in ("email", "discovered_email"):
        candidate = meta.get(key)
        if isinstance(candidate, str) and "@" in candidate:
            return candidate.strip().lower()
    # Fallback: profile_url may be an email
    profile = finding.get("profile_url")
    if isinstance(profile, str) and "@" in profile:
        return profile.strip().lower()
    return None


def _extract_on_domain(
    finding: dict[str, Any], email: str | None, harvest_domain: str
) -> bool:
    """Determine whether the finding's email is on the harvest domain."""
    meta = finding.get("metadata") or {}
    if isinstance(meta, dict) and "on_domain" in meta:
        return bool(meta["on_domain"])
    if email and "@" in email:
        return email.rsplit("@", 1)[-1].lower() == harvest_domain
    return False


def _extract_timestamp(finding: dict[str, Any]) -> str | None:
    """Best-effort oldest-timestamp from a finding's metadata."""
    meta = finding.get("metadata") or {}
    if not isinstance(meta, dict):
        return None
    for key in ("oldest_timestamp", "first_seen_timestamp", "timestamp"):
        ts = meta.get(key)
        if isinstance(ts, str) and ts.strip():
            return ts
    return None


def _extract_last_seen_timestamp(finding: dict[str, Any]) -> str | None:
    """Best-effort newest timestamp from a finding's metadata."""
    meta = finding.get("metadata") or {}
    if not isinstance(meta, dict):
        return None
    for key in ("last_seen_timestamp", "newest_timestamp", "timestamp"):
        ts = meta.get(key)
        if isinstance(ts, str) and ts.strip():
            return ts
    return _extract_timestamp(finding)


def _extract_role(finding: dict[str, Any]) -> tuple[bool, str | None]:
    """Pull role classification from a finding's metadata."""
    meta = finding.get("metadata") or {}
    if not isinstance(meta, dict):
        return False, None
    return bool(meta.get("is_role")), meta.get("role_match_type")


def _extract_source_types(finding: dict[str, Any]) -> list[str]:
    """Pull source_type(s) from a finding's metadata."""
    meta = finding.get("metadata") or {}
    if not isinstance(meta, dict):
        return []
    out: list[str] = []
    for key in ("source_type", "source_types", "all_sources"):
        val = meta.get(key)
        if isinstance(val, str) and val.strip():
            out.append(val.strip())
        elif isinstance(val, list):
            out.extend(str(v).strip() for v in val if str(v).strip())
    platform = str(finding.get("platform") or "").lower()
    if "gravatar" in platform and "permutation_gravatar_hit" not in out:
        out.append("permutation_gravatar_hit")
    metadata = finding.get("metadata") or {}
    source_type_value = metadata.get("source_type") if isinstance(metadata, dict) else None
    if isinstance(metadata, dict) and not (
        isinstance(source_type_value, str)
        and source_type_value.startswith(("breach_recent", "breach_historical"))
    ) and (
        metadata.get("breach_date")
        or metadata.get("breach_name")
        or "breach" in platform
        or "pwned" in platform
    ) and "permutation_breach_hit" not in out:
        out.append("permutation_breach_hit")
    return out


def _finding_confidence(meta: dict[str, Any]) -> float:
    value = meta.get("confidence_score") or meta.get("confidence") or 0.5
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.5


def _emit_finding_signals(
    signal_pool: Any | None,
    module_name: str,
    findings: list[dict[str, Any]] | None,
    domain: str,
) -> None:
    """Mirror ModuleResult findings into the shared signal pool."""
    if signal_pool is None:
        return
    for finding in findings or []:
        meta = finding.get("metadata") or {}
        if not isinstance(meta, dict):
            continue
        confidence = _finding_confidence(meta)
        email = _extract_email(finding)
        if email and hasattr(signal_pool, "emit_email"):
            signal_pool.emit_email(
                email,
                module_name,
                confidence,
                domain=email.rsplit("@", 1)[-1].lower(),
                name=meta.get("name") or meta.get("person_name"),
            )
        name = meta.get("name") or meta.get("person_name")
        if isinstance(name, str) and name.strip() and hasattr(signal_pool, "emit_name"):
            signal_pool.emit_name(
                name,
                module_name,
                confidence,
                domain=domain,
                email=email,
            )


def _pattern_shape_for_email(email: str) -> str | None:
    local = email.rsplit("@", 1)[0].lower()
    if "." in local:
        parts = [p for p in local.split(".") if p]
        if len(parts) == 2 and all(part.isalpha() for part in parts):
            return "{first}.{last}@{domain}"
    if "_" in local:
        parts = [p for p in local.split("_") if p]
        if len(parts) == 2 and all(part.isalpha() for part in parts):
            return "{first}_{last}@{domain}"
    if re.fullmatch(r"[a-z][a-z]{2,}", local):
        return "{first}@{domain}"
    return None


def _infer_confirmed_pattern_from_emails(
    emails: list[HarvestedEmail],
    signal_pool: Any | None,
) -> str | None:
    """Infer and publish the dominant on-domain template.

    P7: 4-tier label filter.  The legacy 3-tier filter was
    ``{"HIGH", "MEDIUM"}`` (anything above LOW).  The 4-tier
    equivalent is "anything above LOW" — same intent, just
    expressed in the new vocabulary.  Legacy ``HIGH`` is kept
    as a backward-compat alias for any out-of-band label.
    """
    if signal_pool is None or not hasattr(signal_pool, "emit_confirmed_pattern"):
        return None
    counts: dict[str, int] = {}
    for entry in emails:
        # P7: 4-tier set.  LOW is excluded; everything else
        # (CONFIRMED / LIKELY / MEDIUM, plus the legacy ``HIGH``
        # alias) is included so the inference keeps working
        # for callers that still emit the legacy vocabulary.
        if not entry.on_domain or entry.confidence_label in {"LOW", None}:
            continue
        shape = _pattern_shape_for_email(entry.email)
        if shape is not None:
            counts[shape] = counts.get(shape, 0) + 1
    if not counts:
        return None
    dominant = max(counts.items(), key=lambda item: (item[1], item[0]))[0]
    signal_pool.emit_confirmed_pattern(dominant)
    return dominant


def _name_matches_email_local(name: str, local_part: str) -> bool:
    tokens = [t.lower() for t in re.findall(r"[a-zA-Z]+", name)]
    if len(tokens) < 2:
        return False
    local = re.sub(r"[^a-z0-9]", "", local_part.lower())
    first, last = tokens[0], tokens[-1]
    return (
        (first in local and last in local)
        or local.startswith(first[:1] + last)
        or local.startswith(first + last[:1])
        or local == f"{first[:1]}{last}"
    )


def _pattern_metadata(entry: HarvestedEmail) -> dict[str, Any] | None:
    for evidence in entry.evidence:
        metadata = evidence.get("metadata") or {}
        if isinstance(metadata, dict) and metadata.get("pattern_template"):
            return metadata
    return None


def _pattern_source_types(entry: HarvestedEmail) -> set[str]:
    source_types: set[str] = set()
    for evidence in entry.evidence:
        metadata = evidence.get("metadata") or {}
        if isinstance(metadata, dict) and isinstance(metadata.get("source_type"), str):
            source_types.add(str(metadata["source_type"]))
    return source_types


def _pattern_shape_for_email(email: str, name: str | None = None) -> str | None:
    """Infer a supported email template, using the source name when known."""
    local = email.rsplit("@", 1)[0].lower()
    if name:
        tokens = [token.lower() for token in re.findall(r"[a-zA-Z]+", name)]
        if len(tokens) >= 2:
            first, last = tokens[0], tokens[-1]
            by_local = {
                f"{first}.{last}": "{first}.{last}@{domain}",
                first: "{first}@{domain}",
                f"{first[:1]}{last}": "{f}{last}@{domain}",
                f"{first}{last}": "{first}{last}@{domain}",
                last: "{last}@{domain}",
                f"{last}.{first}": "{last}.{first}@{domain}",
            }
            if local in by_local:
                return by_local[local]
    if re.fullmatch(r"[a-z]+\.[a-z]+", local):
        return "{first}.{last}@{domain}"
    if re.fullmatch(r"[a-z]+", local):
        return "{first}@{domain}"
    return None


def _confirmed_format_counts(
    emails: list[HarvestedEmail],
    module_results: dict[str, ModuleResult] | None = None,
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in emails:
        # P7: 4-tier label set.  The legacy 3-tier aliases
        # (HIGH / MEDIUM) are accepted for backward compatibility
        # but the authoritative filter is "anything above LOW".
        if not entry.on_domain or entry.confidence_label in {"LOW", None}:
            continue
        metadata = _pattern_metadata(entry)
        if metadata is not None and metadata.get("verification_status") != "verified":
            continue
        name = str(metadata.get("source_name") or "") if metadata else None
        shape = _pattern_shape_for_email(entry.email, name)
        if shape:
            counts[shape] = counts.get(shape, 0) + 1
    if module_results:
        xposed_result = module_results.get("xposed_or_not")
        xposed_meta = xposed_result.metadata if xposed_result else {}
        if isinstance(xposed_meta, dict):
            template = xposed_meta.get("format_template")
            count = int(xposed_meta.get("format_count") or 0)
            if isinstance(template, str) and count >= 10:
                counts[template] = max(counts.get(template, 0), count)
    return counts


def _apply_passive_pattern_signals(
    emails: list[HarvestedEmail],
    module_results: dict[str, ModuleResult],
) -> None:
    """Apply Phase A's additive, mutually-exclusive pattern signals."""
    pattern_result = module_results.get(MODULE_PATTERN_VERIFY)
    pattern_meta = pattern_result.metadata if pattern_result else {}
    if isinstance(pattern_meta, dict):
        catchall = pattern_meta.get("is_catchall", pattern_meta.get("catch_all_detected"))
    else:
        catchall = None
    catchall_factor = 0.0 if catchall is True else 1.0 if catchall is False else 0.5

    format_counts = _confirmed_format_counts(emails, module_results)
    dominant_format = max(format_counts, key=format_counts.get) if format_counts else None
    dominant_count = format_counts.get(dominant_format, 0) if dominant_format else 0

    for entry in emails:
        metadata = _pattern_metadata(entry)
        if metadata is None or not entry.on_domain:
            continue

        name = str(metadata.get("source_name") or "")
        name_tokens = [token.lower() for token in re.findall(r"[a-zA-Z]+", name)]
        name_tokens = name_tokens[:2]
        compact_local = re.sub(r"[^a-z0-9]", "", entry.email.rsplit("@", 1)[0].lower())
        positions = [compact_local.find(token) for token in name_tokens]
        strong = bool(name_tokens) and len(name_tokens) == 2 and all(
            position >= 0 for position in positions
        ) and positions[0] <= positions[1]
        weak = len(name_tokens) == 2 and any(token in compact_local for token in name_tokens)
        name_boost = 0.25 if strong else 0.10 if weak else 0.0

        format_boost = 0.0
        if dominant_format and metadata.get("pattern_template") == dominant_format:
            format_boost = 0.30 if dominant_count >= 3 else 0.20

        boost = max(name_boost, format_boost) * catchall_factor
        if boost <= 0:
            continue

        base_score, _ = compute_confidence(
            source_count=len(entry.found_by_modules),
            source_types=sorted(_pattern_source_types(entry)),
            is_smtp_verified=entry.is_smtp_verified or entry.is_provider_verified,
            is_ca_attested=entry.is_ca_attested,
            is_pgp_or_ca=entry.is_pgp_or_ca,
            last_seen_timestamp=entry.last_seen_timestamp,
        )
        entry.confidence_score = round(min(base_score + boost, MAX_SCORE), 4)
        entry.confidence_label = label_for_score(entry.confidence_score)
        if entry.confidence_breakdown is not None:
            entry.confidence_breakdown["passive_signal_boost"] = round(boost, 4)
            entry.confidence_breakdown["passive_signal_kind"] = (
                "name_email" if name_boost >= format_boost else "confirmed_format"
            )


def _apply_signal_pool_correlation(
    emails: list[HarvestedEmail],
    signal_pool: Any | None,
) -> None:
    """Boost emails when a matching name was discovered by another source."""
    if signal_pool is None or not hasattr(signal_pool, "get_names_for_domain"):
        return
    for entry in emails:
        # Pattern candidates use the Phase A additive path; applying the old
        # multiplicative identity boost here would double count the name.
        if _pattern_metadata(entry) is not None:
            continue
        if "@" not in entry.email:
            continue
        if entry.is_role:
            continue
        local, domain = entry.email.rsplit("@", 1)
        if entry.is_pgp_or_ca and len(local) < 3:
            continue
        for name_signal in signal_pool.get_names_for_domain(domain):
            name = str(name_signal.get("name") or "")
            if not _name_matches_email_local(name, local):
                continue
            source_modules = set(entry.found_by_modules)
            name_sources = set(name_signal.get("sources") or [])
            if source_modules and name_sources and source_modules >= name_sources:
                continue
            entry.confidence_score = round(entry.confidence_score * 2.5, 4)
            entry.confidence_label = label_for_score(entry.confidence_score)
            entry.evidence.append(
                {
                    "module": "signal_pool",
                    "metadata": {
                        "signal_type": "cross_module_name_email_correlation",
                        "name": name,
                        "sources": sorted(name_sources),
                        "boost": "worksFor",
                    },
                }
            )
            if entry.confidence_breakdown is not None:
                entry.confidence_breakdown["signal_pool_correlation"] = {
                    "name": name,
                    "boost": "worksFor",
                }
            break


def _record_shadow_profile(
    grouped_shadow: dict[str, dict[str, Any]],
    email: str,
    finding: dict[str, Any],
    module_name: str,
) -> None:
    """Accumulate an off-domain email without promoting it to org output."""
    normalized = email.strip().lower()
    metadata = finding.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    entry = grouped_shadow.setdefault(
        normalized,
        {
            "email": normalized,
            "type": "personal_email_candidate",
            "display_name": metadata.get("display_name")
            or metadata.get("name")
            or metadata.get("person_name"),
            "username": metadata.get("username") or finding.get("username"),
            "found_by_modules": [],
            "source_count": 0,
            "total_finding_count": 0,
            "evidence": [],
        },
    )
    entry["total_finding_count"] += 1
    if module_name not in entry["found_by_modules"]:
        entry["found_by_modules"].append(module_name)
        entry["found_by_modules"].sort()
        entry["source_count"] = len(entry["found_by_modules"])
        entry["evidence"].append(
            {"module": module_name, "metadata": dict(metadata)}
        )


def _aggregate(
    harvest_domain: str,
    module_results: dict[str, ModuleResult],
    signal_pool: Any | None = None,
    identity_clusters: list[Any] | None = None,
    shadow_profiles_out: list[dict[str, Any]] | None = None,
) -> list[HarvestedEmail]:
    """Group findings across modules, dedup by email, aggregate confidence.

    MUST-FIX M4: previously this function appended one ``found_by_modules``
    entry and one ``evidence`` dict per FINDING (not per unique
    module+email pair), so a single email found by Common Crawl on 200
    indexed pages produced 200 evidence entries and ``['cc', 'cc', ...]``
    in ``found_by_modules``. The score was unaffected (compute_confidence
    dedupes) but the JSON export ballooned to 10+ MB for high-traffic
    domains.

    The fix:
    * ``found_by_modules`` becomes a sorted list of UNIQUE module names.
    * ``evidence`` becomes a list with AT MOST one entry per
      (module_name, email) pair. Subsequent findings from the same
      module are NOT duplicated; they increment
      ``occurrence_count_per_module[module]`` and contribute any new
      source URLs to ``aggregated_source_urls``.
    * New fields ``total_finding_count`` and ``occurrence_count_per_module``
      preserve the "seen N times" signal so analysts don't lose
      information about how widely an email is attested.

    MUST-FIX S2: dedup KEY uses ``subaddress_key(email)`` so Gmail-style
    ``+filter`` variants collapse into one record. The FIRST form
    encountered becomes the canonical ``entry.email``; subsequent
    variants are tracked in a new ``subaddress_variants`` list so
    analysts can still see all observed forms.
    """
    grouped: dict[str, HarvestedEmail] = {}
    grouped_shadow: dict[str, dict[str, Any]] = {}
    # subaddress_key(email) → HarvestedEmail — the dedup key.
    # Email variants seen for the same key are recorded in
    # entry.subaddress_variants for analyst visibility.
    first_meta_seen: dict[tuple[str, str], dict[str, Any]] = {}
    seen_urls: dict[str, set[str]] = {}

    for module_name, result in module_results.items():
        safe_result = _normalize_module_result(module_name, result)
        for finding in safe_result.findings or []:
            email = _extract_email(finding)
            if not email:
                continue

            actual_domain = email.rsplit("@", 1)[-1].strip().lower()
            if "@" in email and actual_domain != harvest_domain.strip().lower():
                _record_shadow_profile(grouped_shadow, email, finding, module_name)
                continue

            meta = finding.get("metadata") or {}
            if not isinstance(meta, dict):
                meta = {}

            # MUST-FIX S2: use subaddress_key for the dedup group key
            # so ``foo+filter@x.com`` and ``foo@x.com`` collapse into
            # one record. The original email string is preserved as
            # the canonical ``entry.email`` on first occurrence, and
            # any other variants are recorded in
            # ``entry.subaddress_variants`` for downstream visibility.
            key = subaddress_key(email)

            if key not in grouped:
                grouped[key] = HarvestedEmail(
                    email=email,
                    on_domain=_extract_on_domain(finding, email, harvest_domain),
                    is_role=False,
                    role_match_type=None,
                    confidence_score=0.0,
                    confidence_label="LOW",
                    found_by_modules=[],
                    source_count=0,
                    evidence=[],
                    first_seen_timestamp=None,
                    last_seen_timestamp=None,
                )
            else:
                # MUST-FIX S2: if this email variant is different from
                # the canonical one, record it in subaddress_variants.
                entry = grouped[key]
                if email != entry.email and email not in entry.subaddress_variants:
                    entry.subaddress_variants.append(email)

            entry = grouped[key]
            # MUST-FIX M4: occurrence count — increment per finding,
            # not per module. ``total_finding_count`` is the sum across
            # modules; ``occurrence_count_per_module[module]`` is the
            # per-module breakdown.
            entry.total_finding_count += 1
            entry.occurrence_count_per_module[module_name] = (
                entry.occurrence_count_per_module.get(module_name, 0) + 1
            )

            # OR-semantics on role: any source flagging role wins.
            is_role, role_match = _extract_role(finding)
            if not is_role:
                role_classification = classify_email(email)
                if role_classification.is_role:
                    is_role = True
                    role_match = role_classification.match_type
            if is_role:
                entry.is_role = True
                if role_match:
                    entry.role_match_type = role_match

            # OR-semantics on_domain: any source flagging on_domain wins.
            if _extract_on_domain(finding, email, harvest_domain):
                entry.on_domain = True

            # First and last timestamps across evidence. Freshness uses
            # the newest sighting; first_seen remains display-only.
            ts = _extract_timestamp(finding)
            if ts:
                if (
                    entry.first_seen_timestamp is None
                    or ts < entry.first_seen_timestamp  # noqa: SIM118
                ):
                    entry.first_seen_timestamp = ts
            last_ts = _extract_last_seen_timestamp(finding)
            if last_ts:
                if (
                    entry.last_seen_timestamp is None
                    or last_ts > entry.last_seen_timestamp  # noqa: SIM118
                ):
                    entry.last_seen_timestamp = last_ts

            # SMTP-verified flag (only set by pattern_and_verify).
            if meta.get("verification_status") == "verified" or meta.get(
                "smtp_verification_status"
            ) == "verified":
                entry.is_smtp_verified = True
            if meta.get("provider_verification_status") == "verified":
                entry.is_provider_verified = True
            # Fix 3: carry the provider verifier's provider + status onto the
            # record. A "verified" verdict is sticky — a later inconclusive
            # finding for the same email must not overwrite it.
            provider_status = meta.get("provider_verification_status")
            if provider_status and entry.provider_verification_status != "verified":
                entry.provider_verification_status = str(provider_status)
                provider_name = meta.get("provider_verification_provider")
                if provider_name:
                    entry.provider_verification_provider = str(provider_name)
            if meta.get("source_type") in ("ca_attested",):
                entry.is_ca_attested = True
            if meta.get("source_type") in ("ca_attested", "pgp_uid"):
                entry.is_pgp_or_ca = True

            # MUST-FIX M4: dedupe evidence by (module, email). The
            # FIRST finding's metadata is the canonical evidence
            # entry; subsequent findings from the same module do NOT
            # append another evidence dict.
            key = (module_name, email)
            if key not in first_meta_seen:
                first_meta_seen[key] = meta
                entry.evidence.append({"module": module_name, "metadata": meta})

            # MUST-FIX M4: aggregate distinguishing source URLs across
            # all findings (e.g. CC source_urls) into one deduped,
            # bounded list. We look at the metadata's ``source_urls`` /
            # ``html_url`` / ``url`` keys — these are the per-module
            # distinguishing details that justify multiple findings.
            url_set = seen_urls.setdefault(email, set())
            url_list = entry.aggregated_source_urls
            if len(url_list) < _MAX_SOURCE_URLS_PER_EMAIL:
                for url_key in ("source_urls", "html_urls"):
                    urls = meta.get(url_key)
                    if isinstance(urls, list):
                        for u in urls:
                            if isinstance(u, str) and u and u not in url_set:
                                url_set.add(u)
                                url_list.append(u)
                                if len(url_list) >= _MAX_SOURCE_URLS_PER_EMAIL:
                                    break
                    if len(url_list) >= _MAX_SOURCE_URLS_PER_EMAIL:
                        break
                # Single URL fields (commit html_url, etc.)
                for url_key in ("html_url", "url", "source_url"):
                    u = meta.get(url_key)
                    if (
                        isinstance(u, str)
                        and u
                        and u not in url_set
                        and len(url_list) < _MAX_SOURCE_URLS_PER_EMAIL
                    ):
                        url_set.add(u)
                        url_list.append(u)

    # ------------------------------------------------------------------
    # Compute final aggregated confidence per unique email.
    # MUST-FIX M4: ``found_by_modules`` is now built from the set of
    # unique modules that contributed (occurrence_count_per_module keys).
    # This matches the source_count semantics that compute_confidence
    # already expects.
    # ------------------------------------------------------------------
    final: list[HarvestedEmail] = []
    for entry in grouped.values():
        # Build the canonical, sorted, deduplicated found_by_modules list.
        unique_modules = sorted(entry.occurrence_count_per_module.keys())
        entry.found_by_modules = unique_modules

        # Collect all source_types across evidence.
        all_source_types: list[str] = []
        # MUST-FIX S4: also harvest a per-evidence
        # ``confidence_breakdown`` so the most useful breakdown (typically
        # the one with verification status set, or with the strongest
        # source) can be surfaced to the analyst.
        best_breakdown: dict[str, Any] | None = None
        for ev in entry.evidence:
            meta = ev.get("metadata") or {}
            if not isinstance(meta, dict):
                continue
            all_source_types.extend(_extract_source_types({"metadata": meta}))
            # Also pull permutation_verified variants from pattern_and_verify
            status = meta.get("verification_status")
            if status == "verified" and "permutation_verified" not in all_source_types:
                all_source_types.append("permutation_verified")
            elif status in ("catchall",) and "permutation_catchall" not in all_source_types:
                all_source_types.append("permutation_catchall")

            # MUST-FIX S4: pick the FIRST observed confidence_breakdown
            # the evidence carries. Modules that don't compute breakdowns
            # contribute nothing; pattern_and_verify is the only one
            # that does today, and its breakdown encodes both the
            # source_types AND the multiplier / freshness factors used
            # to land on the final score — exactly the "why this
            # confidence label" the analyst needs to see.
            cb = meta.get("confidence_breakdown")
            if isinstance(cb, dict) and best_breakdown is None:
                best_breakdown = cb

        score, label = compute_confidence(
            source_count=len(unique_modules),
            source_types=all_source_types,
            is_smtp_verified=entry.is_smtp_verified or entry.is_provider_verified,
            is_ca_attested=entry.is_ca_attested,
            is_pgp_or_ca=entry.is_pgp_or_ca,
            last_seen_timestamp=entry.last_seen_timestamp,
        )

        entry.confidence_score = round(score, 4)
        entry.confidence_label = label
        entry.source_count = len(unique_modules)
        # MUST-FIX S4: store the breakdown on the HarvestedEmail so it
        # survives into the CLI render and the JSON export. We use the
        # module-provided breakdown when available (richer — captures
        # freshness + multiplier math); otherwise we synthesise a
        # minimal one from the public input so the CLI / JSON shape
        # is uniform across emails.
        current_breakdown = compute_confidence_breakdown(
            source_types=all_source_types,
            is_smtp_verified=entry.is_smtp_verified or entry.is_provider_verified,
            is_ca_attested=entry.is_ca_attested,
            is_pgp_or_ca=entry.is_pgp_or_ca,
            last_seen_timestamp=entry.last_seen_timestamp,
        ).breakdown
        if best_breakdown is not None:
            best_breakdown.update(current_breakdown)
            entry.confidence_breakdown = best_breakdown
        else:
            current_breakdown["synthesised"] = True
            entry.confidence_breakdown = current_breakdown
        final.append(entry)

    _apply_passive_pattern_signals(final, module_results)
    _apply_signal_pool_correlation(final, signal_pool)
    _apply_identity_cluster_snapshot(final, identity_clusters)
    _infer_confirmed_pattern_from_emails(final, signal_pool)
    if shadow_profiles_out is not None:
        shadow_profiles_out.clear()
        shadow_profiles_out.extend(grouped_shadow[key] for key in sorted(grouped_shadow))
    return final


def _select_verifier_for_provider(provider: MailProvider) -> str:
    """Return the automatic low-email-validation path for a provider.

    This is intentionally pure routing logic. Provider-specific I/O remains
    in the existing verifier implementations and will be wired in a later
    phase.
    """
    if provider is MailProvider.M365:
        return "m365"
    if provider is MailProvider.YAHOO:
        return "yahoo"
    if provider is MailProvider.GOOGLE:
        return "google"
    if provider in {
        MailProvider.PROTON,
        MailProvider.ZOHO,
        MailProvider.FASTMAIL,
    }:
        return "gravatar_only"
    return "smtp"


async def resolve_domain_email_dns_signals(domain: str) -> dict[str, bool]:
    """Resolve the domain-level SPF and DMARC passive signals once."""
    try:
        import dns.asyncresolver  # type: ignore[import]
    except ImportError:
        return {"spf_present": False, "dmarc_strict": False}

    async def txt_records(name: str) -> list[str]:
        try:
            answers = await dns.asyncresolver.resolve(name, "TXT")
        except Exception:  # noqa: BLE001
            return []
        records: list[str] = []
        for answer in answers:
            strings = getattr(answer, "strings", None)
            if strings is not None:
                parts = []
                for part in strings:
                    parts.append(
                        part.decode("utf-8", errors="replace")
                        if isinstance(part, bytes)
                        else str(part)
                    )
                records.append("".join(parts))
            else:
                records.append(str(answer).strip('"'))
        return records

    spf_records, dmarc_records = await asyncio.gather(
        txt_records(domain.strip().lower()),
        txt_records(f"_dmarc.{domain.strip().lower()}"),
    )
    spf_present = any(record.strip().lower().startswith("v=spf1") for record in spf_records)
    dmarc_strict = any(
        record.strip().lower().startswith("v=dmarc1")
        and re.search(r"(?:^|;)\s*p\s*=\s*reject(?:\s*;|$)", record, re.IGNORECASE)
        for record in dmarc_records
    )
    return {"spf_present": spf_present, "dmarc_strict": dmarc_strict}


def apply_domain_email_dns_signals(
    emails: list[HarvestedEmail],
    signals: dict[str, bool],
) -> None:
    """Add SPF/DMARC evidence to all on-domain pattern candidates."""
    dns_boost = (0.02 if signals.get("spf_present") else 0.0) + (
        0.05 if signals.get("dmarc_strict") else 0.0
    )
    if dns_boost <= 0:
        return
    for entry in emails:
        metadata = _pattern_metadata(entry)
        if metadata is None or not entry.on_domain:
            continue
        source_types = sorted(_pattern_source_types(entry))
        base_score, _ = compute_confidence(
            source_count=len(entry.found_by_modules),
            source_types=source_types,
            is_smtp_verified=entry.is_smtp_verified or entry.is_provider_verified,
            is_ca_attested=entry.is_ca_attested,
            is_pgp_or_ca=entry.is_pgp_or_ca,
            last_seen_timestamp=entry.last_seen_timestamp,
        )
        passive_boost = 0.0
        if entry.confidence_breakdown is not None:
            passive_boost = float(entry.confidence_breakdown.get("passive_signal_boost") or 0.0)
            entry.confidence_breakdown["dns_passive_boost"] = round(dns_boost, 4)
            entry.confidence_breakdown["spf_present"] = bool(signals.get("spf_present"))
            entry.confidence_breakdown["dmarc_strict"] = bool(signals.get("dmarc_strict"))
        entry.confidence_score = round(min(base_score + passive_boost + dns_boost, MAX_SCORE), 4)
        entry.confidence_label = label_for_score(entry.confidence_score)


def _select_low_email_validation_candidates(
    harvest_domain: str,
    module_results: dict[str, ModuleResult],
    unique_emails: list[HarvestedEmail],
    *,
    max_candidates: int | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Select capped LOW-confidence personal emails for auto-validation.

    Selection is based on the post-aggregation ``HarvestedEmail`` records so
    role, domain, confidence, and prior-verification decisions reflect all
    contributing findings. The returned mapping keeps every raw finding for
    each selected canonical email so a later validation phase can attach
    evidence and promotion metadata at the existing aggregation boundary.
    """
    cap = (
        int(settings.harvest_validation_max_per_run)
        if max_candidates is None
        else int(max_candidates)
    )
    if cap <= 0:
        return {}

    eligible: dict[str, HarvestedEmail] = {}
    for email in unique_emails:
        if (
            email.on_domain
            and not email.is_role
            and email.confidence_label == "LOW"
            and not email.is_smtp_verified
            and not email.is_provider_verified
        ):
            eligible[subaddress_key(email.email)] = email

    findings_by_key: dict[str, list[dict[str, Any]]] = {}
    for result in module_results.values():
        for finding in result.findings or []:
            email = _extract_email(finding)
            if not email or not _extract_on_domain(finding, email, harvest_domain):
                continue
            key = subaddress_key(email)
            if key in eligible:
                findings_by_key.setdefault(key, []).append(finding)

    ranked: list[tuple[int, str, str]] = []
    selected_findings: dict[str, list[dict[str, Any]]] = {}
    for key, findings in findings_by_key.items():
        if not findings:
            continue
        already_verified = False
        disposable = False
        pattern_candidate = False
        for finding in findings:
            metadata = finding.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}
            source_types = _extract_source_types(finding)
            pattern_candidate = pattern_candidate or any(
                source_type.startswith("permutation_unverified_")
                for source_type in source_types
            )
            status = str(
                metadata.get("verification_status")
                or metadata.get("smtp_verification_status")
                or metadata.get("provider_verification_status")
                or ""
            ).lower()
            already_verified = already_verified or status == "verified"
            disposable = disposable or bool(
                metadata.get("disposable")
                or metadata.get("is_disposable")
                or status == "disposable"
            )
            native = metadata.get("native_email_validation")
            if isinstance(native, dict):
                disposable = disposable or native.get("status") == "disposable"

        if already_verified or disposable:
            continue
        email = eligible[key].email
        ranked.append((0 if pattern_candidate else 1, email, key))
        selected_findings[key] = findings

    ranked.sort(key=lambda item: (item[0], item[1]))
    selected_keys = {key for _, _, key in ranked[:cap]}
    return {
        eligible[key].email: selected_findings[key]
        for _, _, key in ranked[:cap]
        if key in selected_keys
    }


async def _run_low_email_validation(
    domain: str,
    candidates: dict[str, list[dict[str, Any]]],
    verifier_key: str,
    *,
    provider: MailProvider | None = None,
) -> dict[str, Any]:
    """Execute one provider-specific verifier against selected candidates.

    The existing provider verifiers own their request pacing, hard limits,
    throttling semantics, and SMTP catch-all/blocked-probe safeguards. This
    adapter only normalizes their result objects and records raw validation
    evidence on the selected findings for the promotion phase.
    """
    emails = list(candidates)
    summary: dict[str, Any] = {
        "method": verifier_key,
        "checked": len(emails),
        "candidates": len(emails),
        "results": [],
    }
    if not emails:
        summary["status"] = "no_candidates"
        return summary
    if verifier_key == "gravatar_only":
        summary["checked"] = 0
        summary["status"] = "provider_verification_unavailable"
        return summary

    result_objects: list[Any]
    shared_hosting = provider is MailProvider.SHARED_HOSTING
    if verifier_key == "m365":
        verifier = M365Verifier(
            delay_seconds=settings.m365_verification_delay_seconds,
            timeout_seconds=settings.m365_verification_timeout_seconds,
            max_checks=settings.m365_verification_max_checks,
        )
        result_objects = await verifier.verify_batch(emails)
    elif verifier_key == "yahoo":
        verifier = YahooVerifier(
            delay_seconds=settings.yahoo_verification_delay_seconds,
            timeout_seconds=settings.yahoo_verification_timeout_seconds,
            max_checks=settings.yahoo_verification_max_checks,
        )
        result_objects = await verifier.verify_batch(emails)
    elif verifier_key == "google":
        if not settings.google_workspace_verifier_enabled:
            summary["checked"] = 0
            summary["status"] = "google_verifier_disabled"
            summary["skipped"] = "google_verifier_disabled"
            return summary
        verifier = GoogleWorkspaceVerifier(
            delay_seconds=1.0,
            timeout_seconds=settings.google_verifier_timeout,
            gravatar_enabled=settings.gravatar_verification_enabled,
            max_checks=settings.smtp_verify_max_probes,
        )
        result_objects = await verifier.verify_batch(
            emails,
            domain,
            session=None,
            max_checks=settings.smtp_verify_max_probes,
        )
    elif verifier_key == "smtp":
        mx_records = await resolve_mx(domain)
        if not mx_records:
            summary["status"] = "no_mx_records"
            return summary
        async with SMTPVerifier(
            mx_records=mx_records,
            sender_address=settings.smtp_sender_address or DEFAULT_SENDER,
            probe_delay_seconds=float(settings.smtp_probe_delay_seconds) or DEFAULT_PROBE_DELAY,
            connect_timeout_seconds=float(settings.smtp_connect_timeout_seconds),
        ) as verifier:
            batch = await verifier.verify_batch(
                domain,
                emails,
                max_probes=min(int(settings.smtp_max_probes_per_domain), MAX_PROBES_HARD_CAP),
            )
        summary.update(
            {
                "probes_attempted": batch.probes_attempted,
                "is_catchall": None if shared_hosting else batch.is_catchall,
                "catchall_reliable": not shared_hosting,
                "stopped_early": batch.stopped_early,
                "stop_reason": batch.stop_reason,
                "error": batch.error,
            }
        )
        result_objects = batch.results
    else:
        summary["status"] = "unsupported_verifier"
        return summary

    for result in result_objects:
        if verifier_key == "smtp":
            status = str(getattr(result, "verification_status", "inconclusive"))
            payload = {
                "method": verifier_key,
                "status": status,
                "exists": getattr(result, "exists", None),
                "response_code": getattr(result, "response_code", None),
                "blocked_signal": getattr(result, "blocked_signal", False),
                "mx_host": getattr(result, "mx_host", None),
                "transport_error": getattr(result, "transport_error", None),
                "is_catchall": summary.get("is_catchall"),
                "catchall_reliable": not shared_hosting,
            }
        else:
            status = str(getattr(result, "status", "inconclusive"))
            payload = {
                "method": verifier_key,
                "status": status,
                "http_status": getattr(result, "http_status", None),
                "error": getattr(result, "error", None),
            }
            for field_name in (
                "if_exists_result",
                "is_unmanaged",
                "throttle_status",
            ):
                if hasattr(result, field_name):
                    payload[field_name] = getattr(result, field_name)
            if hasattr(result, "exists"):
                payload["exists"] = getattr(result, "exists")
            if hasattr(result, "gravatar_hit"):
                payload["gravatar_hit"] = getattr(result, "gravatar_hit")

        email = str(getattr(result, "email", "")).strip().lower()
        payload["inconclusive"] = status in {
            "inconclusive",
            "throttled",
            "not_attempted",
            "temporary_failure",
            "blocked",
        }
        summary["results"].append({"email": email, **payload})
        for finding in candidates.get(email, []):
            metadata = finding.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
                finding["metadata"] = metadata
            metadata["low_email_validation"] = payload
            if status == "possibly_exists" and payload.get("gravatar_hit"):
                metadata["source_type"] = "permutation_gravatar_hit"

    for item in summary["results"]:
        status = item["status"]
        summary[status] = int(summary.get(status, 0)) + 1
    if summary.get("status") is None:
        summary["status"] = "completed"
    return summary


async def _run_xposed_or_not_validation(
    domain: str,
    candidates: dict[str, list[dict[str, Any]]],
    *,
    max_checks: int,
    delay_seconds: float = 1.0,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Attach keyless breach evidence and return domain-format metadata."""
    from .xposed_or_not import check_emails, infer_domain_format

    emails = list(candidates)[: max(0, int(max_checks))]
    results = await check_emails(
        emails,
        max_checks=len(emails),
        delay_seconds=delay_seconds,
    )
    attached = 0
    for result in results:
        if result.source_type not in {"breach_recent", "breach_historical"}:
            continue
        attached += 1
        for finding in candidates.get(result.email, []):
            metadata = finding.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
                finding["metadata"] = metadata
            existing_types: list[str] = []
            existing = metadata.get("source_types")
            if isinstance(existing, str):
                existing_types.append(existing)
            elif isinstance(existing, list):
                existing_types.extend(str(item) for item in existing if str(item))
            current = metadata.get("source_type")
            if isinstance(current, str) and current:
                existing_types.append(current)
            existing_types.append(result.source_type)
            metadata["source_types"] = sorted(set(existing_types))
            metadata["breach_dates"] = list(result.breach_dates)
            metadata["breach_names"] = list(result.breaches)
            metadata["xposed_or_not"] = {
                "status": "breach_hit",
                "source_type": result.source_type,
                "breach_dates": list(result.breach_dates),
                "breaches": list(result.breaches),
            }
    format_metadata = await infer_domain_format(domain)
    return (
        {
            "method": "xposed_or_not",
            "checked": len(emails),
            "hits": attached,
            "results": [
                {
                    "email": result.email,
                    "source_type": result.source_type,
                    "breach_dates": list(result.breach_dates),
                    "breaches": list(result.breaches),
                }
                for result in results
            ],
        },
        format_metadata,
    )


def _apply_low_email_validation_results(
    candidates: dict[str, list[dict[str, Any]]],
    validation_summary: dict[str, Any],
    unique_emails: list[HarvestedEmail] | None = None,
) -> dict[str, int]:
    """Promote only confirmed mailbox results from automatic validation.

    ``not_found`` results remain visible and LOW, while throttled and other
    inconclusive results leave confidence and provenance unchanged. Existing
    findings are mutated in place; no synthetic finding is created.
    """
    method = str(validation_summary.get("method") or "")
    verified_source = {
        "m365": "permutation_verified_m365",
        "yahoo": "permutation_verified_yahoo",
        "smtp": "permutation_verified",
        "google": "permutation_verified_google",
    }.get(method)
    counts = {"promoted": 0, "not_found": 0, "inconclusive": 0}
    promoted_emails: set[str] = set()

    for result in validation_summary.get("results") or []:
        if not isinstance(result, dict):
            continue
        email = str(result.get("email") or "").strip().lower()
        status = str(result.get("status") or "inconclusive").lower()
        findings = candidates.get(email, [])
        if status == "verified" and verified_source:
            promoted_emails.add(email)
            counts["promoted"] += 1
            for finding in findings:
                metadata = finding.setdefault("metadata", {})
                if not isinstance(metadata, dict):
                    metadata = {}
                    finding["metadata"] = metadata
                metadata["source_type"] = verified_source
                metadata["verification_status"] = "verified"
                if method in {"m365", "yahoo", "google"}:
                    metadata["provider_verification_status"] = "verified"
                    metadata["provider_verification_provider"] = method
                else:
                    metadata["smtp_verification_status"] = "verified"
                metadata["validation_evidence"] = {
                    "method": method,
                    "status": "verified",
                    "reason": f"automatic_low_email_validation:{method}",
                }
                validation = metadata.get("low_email_validation")
                if isinstance(validation, dict):
                    validation["promoted"] = True
        elif status == "not_found":
            counts["not_found"] += 1
            for finding in findings:
                metadata = finding.setdefault("metadata", {})
                if not isinstance(metadata, dict):
                    metadata = {}
                    finding["metadata"] = metadata
                metadata["verification_status"] = "not_found"
                metadata["validation_evidence"] = {
                    "method": method,
                    "status": "not_found",
                    "reason": f"automatic_low_email_validation:{method}",
                }
        else:
            counts["inconclusive"] += 1

    if unique_emails and promoted_emails:
        for email in unique_emails:
            if email.email.strip().lower() not in promoted_emails:
                continue
            email.is_provider_verified = method in {"m365", "yahoo", "google"}
            email.is_smtp_verified = method == "smtp"
            source_types: list[str] = []
            for evidence in email.evidence:
                metadata = evidence.get("metadata") or {}
                if isinstance(metadata, dict):
                    source_types.extend(_extract_source_types({"metadata": metadata}))
                    if metadata.get("verification_status") == "verified":
                        source_types.append(
                            verified_source or "permutation_verified"
                        )
            score, label = compute_confidence(
                source_count=email.source_count,
                source_types=source_types,
                is_smtp_verified=email.is_smtp_verified or email.is_provider_verified,
                is_ca_attested=email.is_ca_attested,
                is_pgp_or_ca=email.is_pgp_or_ca,
                last_seen_timestamp=email.last_seen_timestamp,
            )
            email.confidence_score = round(score, 4)
            email.confidence_label = label
            email.confidence_breakdown = compute_confidence_breakdown(
                source_types=source_types,
                is_smtp_verified=email.is_smtp_verified or email.is_provider_verified,
                is_ca_attested=email.is_ca_attested,
                is_pgp_or_ca=email.is_pgp_or_ca,
                last_seen_timestamp=email.last_seen_timestamp,
            ).breakdown

    return counts


async def _attach_native_email_validation(
    domain: str,
    module_results: dict[str, ModuleResult],
) -> dict[str, int | str]:
    """Attach native validation evidence to every discovered email.

    This is intentionally additive: it never replaces stronger source
    evidence and never marks a mailbox as existing. MX is resolved once per
    harvest, then the result is copied into each finding's metadata.
    """
    findings_by_email: dict[str, list[dict[str, Any]]] = {}
    for result in module_results.values():
        for finding in result.findings or []:
            email = _extract_email(finding)
            if email:
                findings_by_email.setdefault(email.strip().lower(), []).append(finding)
    if not findings_by_email:
        return {"checked": 0}

    try:
        mx_records = await resolve_mx(domain)
    except Exception as exc:  # noqa: BLE001
        _LOG.debug("native email validation MX lookup failed: %s", exc)
        mx_records = []
    results = await validate_email_batch(
        list(findings_by_email),
        mx_records=mx_records,
    )
    counts: dict[str, int | str] = {
        "checked": len(results),
        "mx_records": len(mx_records),
    }
    for validation in results:
        counts[validation.status] = int(counts.get(validation.status, 0)) + 1
        payload = {
            "status": validation.status,
            "syntax_valid": validation.syntax_valid,
            "mx_valid": validation.mx_valid,
            "disposable": validation.disposable,
            "is_role": validation.is_role,
            "role_match_type": validation.role_match_type,
            "reasons": list(validation.reasons),
        }
        for finding in findings_by_email.get(validation.email, []):
            metadata = finding.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
                finding["metadata"] = metadata
            metadata["native_email_validation"] = payload
            # The adaptive runner can generate pattern findings directly,
            # bypassing PatternAndVerifyModule. Promote those candidates at
            # this shared boundary so MX evidence cannot be lost on that path.
            if (
                validation.status == "mx_valid"
                and metadata.get("verification_status") in (None, "unverified")
                and metadata.get("pattern_template")
            ):
                metadata["verification_status"] = "mx_valid"
                metadata["source_type"] = "permutation_mx_valid"
                metadata["confidence_score"] = max(
                    float(metadata.get("confidence_score") or 0.0),
                    0.30,
                )
    return counts


def _collect_smtp_findings(
    domain: str,
    module_results: dict[str, ModuleResult],
) -> dict[str, list[dict[str, Any]]]:
    """Collect valid on-domain findings eligible for the SMTP tail."""
    findings_by_email: dict[str, list[dict[str, Any]]] = {}
    for result in module_results.values():
        for finding in result.findings or []:
            email = _extract_email(finding)
            if not email or "@" not in email:
                continue
            normalized = email.strip().lower()
            if normalized.rsplit("@", 1)[-1] != domain.strip().lower():
                continue
            metadata = finding.get("metadata") or {}
            native = metadata.get("native_email_validation") if isinstance(metadata, dict) else None
            if isinstance(native, dict) and native.get("status") in {"invalid", "disposable", "mx_missing"}:
                continue
            findings_by_email.setdefault(normalized, []).append(finding)
    return findings_by_email


def _collect_all_on_domain_candidates(
    domain: str,
    module_results: dict[str, ModuleResult],
) -> dict[str, list[dict[str, Any]]]:
    """Fallback candidate set for provider verification.

    ``_collect_smtp_findings`` drops candidates that fail the native-validation
    SMTP-eligibility filter (PGP signers and some passive sources never carry
    ``mx_valid`` native evidence), so on domains with only a weak signal the
    provider verifier can receive zero candidates. This collector ignores that
    eligibility filter and instead selects on-domain, non-role candidates at
    MEDIUM+ confidence — i.e. ``CONFIRMED`` / ``LIKELY`` / ``MEDIUM`` — using
    the post-aggregation tier so it reflects all contributing findings. LOW is
    excluded so weak guesses are not sent to live provider/SMTP probes. Already
    verified addresses are skipped.
    """
    aggregated = _aggregate(domain, module_results)
    eligible: set[str] = {
        entry.email.strip().lower()
        for entry in aggregated
        if entry.on_domain
        and not entry.is_role
        and entry.confidence_label in {"CONFIRMED", "LIKELY", "MEDIUM"}
        and not entry.is_smtp_verified
        and not entry.is_provider_verified
    }
    if not eligible:
        return {}

    findings_by_email: dict[str, list[dict[str, Any]]] = {}
    for result in module_results.values():
        for finding in result.findings or []:
            email = _extract_email(finding)
            if not email or "@" not in email:
                continue
            normalized = email.strip().lower()
            if normalized in eligible:
                findings_by_email.setdefault(normalized, []).append(finding)
    return findings_by_email


async def _dispatch_provider_verifier(
    domain: str,
    findings_by_email: dict[str, list[dict[str, Any]]],
    detection: Any,
    module_results: dict[str, ModuleResult] | None = None,
) -> dict[str, int | str | bool | None]:
    """Dispatch GOOGLE / M365 candidates to their provider-specific verifier.

    Historically the primary harvest path short-circuited here with
    ``skipped: provider_specific_verifier`` and never called either verifier,
    so ``is_provider_verified`` and the ``provider_verification_*`` fields
    never populated on this path (0.13.0-0.13.1 regression). Both verifiers
    exist and are dispatched here directly. M365 works immediately
    (GetCredentialType is not patched); for Google the gxlu + SMTP + Gravatar
    fallback chain runs inside :meth:`GoogleWorkspaceVerifier.verify_batch`.
    """
    provider = detection.provider
    emails = list(findings_by_email)
    if not emails:
        # PGP signers and other passive sources don't pass the SMTP-eligibility
        # filter, so ``findings_by_email`` can be empty even when the domain has
        # MEDIUM+ on-domain candidates. Fall back to all on-domain candidates so
        # the provider verifier still has something to work with.
        fallback = (
            _collect_all_on_domain_candidates(domain, module_results)
            if module_results is not None
            else {}
        )
        if not fallback:
            return {"checked": 0, "status": "no_candidates", "provider": provider.value}
        findings_by_email = fallback
        emails = list(findings_by_email)[: settings.smtp_verify_max_probes]
    summary: dict[str, int | str | bool | None] = {
        "checked": len(emails),
        "candidates": len(emails),
        "provider": provider.value,
    }

    results: list[Any]
    if provider is MailProvider.GOOGLE:
        if not settings.google_workspace_verifier_enabled:
            summary["checked"] = 0
            summary["skipped"] = "google_verifier_disabled"
            return summary
        summary["method"] = "google"
        verifier = GoogleWorkspaceVerifier(
            delay_seconds=1.0,
            timeout_seconds=settings.google_verifier_timeout,
            gravatar_enabled=settings.gravatar_verification_enabled,
            smtp_fallback_enabled=settings.enable_smtp_verification,
            max_checks=settings.smtp_verify_max_probes,
        )
        results = await verifier.verify_batch(
            emails,
            domain,
            session=None,
            max_checks=settings.smtp_verify_max_probes,
        )
        promoted_source = "permutation_verified_google"
    else:  # MailProvider.M365
        summary["method"] = "m365"
        verifier = M365Verifier(
            delay_seconds=settings.m365_verification_delay_seconds,
            timeout_seconds=settings.m365_verification_timeout_seconds,
            max_checks=settings.m365_verification_max_checks,
        )
        results = await verifier.verify_batch(emails)
        promoted_source = "permutation_verified_m365"

    summary["checked"] = len(results)
    for result in results:
        status = str(getattr(result, "status", "inconclusive"))
        exists = getattr(result, "exists", None)
        summary[status] = int(summary.get(status, 0) or 0) + 1
        payload: dict[str, Any] = {
            "method": summary["method"],
            "status": status,
            "exists": exists,
            "http_status": getattr(result, "http_status", None),
            "error": getattr(result, "error", None),
            "provider": provider.value,
        }
        for field_name in ("gravatar_hit", "if_exists_result", "is_unmanaged", "throttle_status"):
            if hasattr(result, field_name):
                payload[field_name] = getattr(result, field_name)
        email = str(getattr(result, "email", "")).strip().lower()
        verified = status == "verified" or exists is True
        for finding in findings_by_email.get(email, []):
            metadata = finding.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
                finding["metadata"] = metadata
            metadata["provider_verification"] = payload
            metadata["provider_verification_provider"] = provider.value
            metadata["provider_verification_status"] = "verified" if verified else status
            if verified:
                metadata["verification_status"] = "verified"
                if metadata.get("pattern_template"):
                    metadata["source_type"] = promoted_source
    return summary


async def _attach_smtp_email_verification(
    domain: str,
    module_results: dict[str, ModuleResult],
) -> dict[str, int | str | bool | None]:
    """Probe every valid on-domain email through one guarded SMTP batch."""
    findings_by_email = _collect_smtp_findings(domain, module_results)

    mx_records = await resolve_mx(domain)
    if not mx_records:
        if not findings_by_email:
            return {"checked": 0, "status": "no_candidates", "is_catchall": None}
        return {"checked": len(findings_by_email), "status": "no_mx_records"}

    provider_detection = detect_provider_from_mx(mx_records, target_domain=domain)
    if provider_detection.provider in {MailProvider.GOOGLE, MailProvider.M365}:
        # Provider verifiers own their own candidate fallback (Fix 1), so we
        # dispatch even when the SMTP-eligible set is empty. ``module_results``
        # is threaded through so the verifier can collect MEDIUM+ on-domain
        # candidates when needed.
        return await _dispatch_provider_verifier(
            domain, findings_by_email, provider_detection, module_results
        )

    # Non-provider (SMTP) path needs at least one SMTP-eligible candidate.
    if not findings_by_email:
        return {"checked": 0, "status": "no_candidates", "is_catchall": None}
    shared_hosting = provider_detection.provider is MailProvider.SHARED_HOSTING

    async with SMTPVerifier(
        mx_records=mx_records,
        sender_address=settings.smtp_sender_address or DEFAULT_SENDER,
        probe_delay_seconds=float(settings.smtp_probe_delay_seconds) or DEFAULT_PROBE_DELAY,
        connect_timeout_seconds=float(settings.smtp_connect_timeout_seconds),
    ) as verifier:
        batch = await verifier.verify_batch(
            domain,
            list(findings_by_email),
            max_probes=min(int(settings.smtp_max_probes_per_domain), MAX_PROBES_HARD_CAP),
        )

    counts: dict[str, int | str | bool | None] = {
        "checked": len(findings_by_email),
        "probes_attempted": batch.probes_attempted,
        "is_catchall": None if shared_hosting else batch.is_catchall,
        "catchall_reliable": not shared_hosting,
        "stopped_early": batch.stopped_early,
    }
    for result in batch.results:
        status = result.verification_status
        counts[status] = int(counts.get(status, 0)) + 1
        payload = {
            "status": status,
            "exists": result.exists,
            "response_code": result.response_code,
            "blocked_signal": result.blocked_signal,
            "mx_host": result.mx_host,
            "transport_error": result.transport_error,
            "is_catchall": None if shared_hosting else batch.is_catchall,
            "catchall_reliable": not shared_hosting,
        }
        for finding in findings_by_email.get(result.email.lower(), []):
            metadata = finding.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
                finding["metadata"] = metadata
            metadata["smtp_verification_status"] = status
            metadata["smtp_validation"] = payload
            if result.exists is True:
                metadata["verification_status"] = "verified"
                if metadata.get("pattern_template"):
                    metadata["source_type"] = "permutation_verified"
    if batch.error:
        counts["error"] = batch.error
    return counts


async def _attach_m365_email_verification(
    domain: str,
    module_results: dict[str, ModuleResult],
) -> dict[str, Any]:
    """Run the opt-in M365 signal for valid on-domain candidates."""
    findings_by_email: dict[str, list[dict[str, Any]]] = {}
    for result in module_results.values():
        for finding in result.findings or []:
            email = _extract_email(finding)
            if not email or "@" not in email:
                continue
            normalized = email.strip().lower()
            if normalized.rsplit("@", 1)[-1] == domain.strip().lower():
                findings_by_email.setdefault(normalized, []).append(finding)
    if not findings_by_email:
        return {"checked": 0, "status": "no_candidates"}
    mx_records = await resolve_mx(domain)
    detection = detect_provider_from_mx(mx_records, target_domain=domain)
    summary: dict[str, Any] = {
        "provider": detection.provider.value,
        "primary_mx": detection.primary_mx,
        "matched_mx_hosts": list(detection.matched_mx_hosts),
        "checked": 0,
    }
    if detection.provider is not MailProvider.M365:
        summary["status"] = "provider_not_m365"
        return summary
    verifier = M365Verifier(
        delay_seconds=settings.m365_verification_delay_seconds,
        timeout_seconds=settings.m365_verification_timeout_seconds,
        max_checks=settings.m365_verification_max_checks,
    )
    realm = await get_user_realm(
        domain,
        timeout_seconds=settings.m365_verification_timeout_seconds,
    )
    summary["realm"] = {
        "status": realm.status,
        "namespace_type": realm.namespace_type,
        "auth_url": realm.auth_url,
        "federation_brand_name": realm.federation_brand_name,
        "cloud_instance_name": realm.cloud_instance_name,
        "http_status": realm.http_status,
        "error": realm.error,
    }
    results = await verifier.verify_batch(list(findings_by_email))
    summary["checked"] = len(results)
    for verification in results:
        summary[verification.status] = int(summary.get(verification.status, 0)) + 1
        payload = {
            "status": verification.status,
            "if_exists_result": verification.if_exists_result,
            "is_unmanaged": verification.is_unmanaged,
            "throttle_status": verification.throttle_status,
            "http_status": verification.http_status,
            "error": verification.error,
            "provider": detection.provider.value,
        }
        for finding in findings_by_email.get(verification.email, []):
            metadata = finding.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
                finding["metadata"] = metadata
            metadata["provider_detection"] = {
                "provider": detection.provider.value,
                "primary_mx": detection.primary_mx,
                "matched_mx_hosts": list(detection.matched_mx_hosts),
            }
            metadata["m365_verification"] = payload
            metadata["m365_realm"] = summary["realm"]
            metadata["provider_verification_status"] = verification.status
            if verification.status == "verified":
                metadata["verification_status"] = "verified"
                if metadata.get("pattern_template"):
                    metadata["source_type"] = "permutation_verified_m365"
    return summary


async def _attach_yahoo_email_verification(
    domain: str,
    module_results: dict[str, ModuleResult],
) -> dict[str, Any]:
    findings_by_email: dict[str, list[dict[str, Any]]] = {}
    for result in module_results.values():
        for finding in result.findings or []:
            email = _extract_email(finding)
            if email and "@" in email and email.rsplit("@", 1)[-1].lower() == domain.lower():
                findings_by_email.setdefault(email.strip().lower(), []).append(finding)
    if not findings_by_email:
        return {"checked": 0, "status": "no_candidates"}
    detection = detect_provider_from_mx(await resolve_mx(domain), target_domain=domain)
    summary: dict[str, Any] = {"provider": detection.provider.value, "checked": 0}
    if detection.provider is not MailProvider.YAHOO:
        summary["status"] = "provider_not_yahoo"
        return summary
    verifier = YahooVerifier(
        delay_seconds=settings.yahoo_verification_delay_seconds,
        timeout_seconds=settings.yahoo_verification_timeout_seconds,
        max_checks=settings.yahoo_verification_max_checks,
    )
    results = await verifier.verify_batch(list(findings_by_email))
    summary["checked"] = len(results)
    for verification in results:
        summary[verification.status] = int(summary.get(verification.status, 0)) + 1
        payload = {
            "status": verification.status,
            "http_status": verification.http_status,
            "error": verification.error,
            "provider": detection.provider.value,
        }
        for finding in findings_by_email.get(verification.email, []):
            metadata = finding.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
                finding["metadata"] = metadata
            metadata["yahoo_verification"] = payload
            metadata["provider_verification_provider"] = detection.provider.value
            metadata["provider_verification_status"] = verification.status
            if verification.status == "verified":
                metadata["verification_status"] = "verified"
                if metadata.get("pattern_template"):
                    metadata["source_type"] = "permutation_verified_yahoo"
    return summary


def _apply_identity_cluster_snapshot(
    emails: list[HarvestedEmail], clusters: list[Any] | None
) -> None:
    """Attach signal-pool identity cluster evidence to harvested emails."""
    if not clusters:
        return
    by_email: dict[str, Any] = {}
    for cluster in clusters:
        for signal in getattr(cluster, "signals", ()):
            if getattr(signal, "kind", "") != "email":
                continue
            value = str(getattr(signal, "value", "") or "").strip().lower()
            if value:
                by_email[value] = cluster
    for entry in emails:
        cluster = by_email.get(entry.email.lower())
        if cluster is None:
            cluster = next(
                (by_email.get(variant.lower()) for variant in entry.subaddress_variants if by_email.get(variant.lower())),
                None,
            )
        if cluster is None:
            continue
        score = float(getattr(cluster, "score", 0.0) or 0.0)
        tier = getattr(cluster, "export_tier", None)
        flags = sorted(getattr(cluster, "boost_flags", set()) or set())
        entry.identity_graph_score = round(score, 4)
        entry.identity_graph_label = tier
        entry.identity_graph_flags = flags
        if entry.confidence_breakdown is not None:
            entry.confidence_breakdown["identity_graph"] = {
                "score": entry.identity_graph_score,
                "label": tier,
                "flags": flags,
            }


# ---------------------------------------------------------------------
# Sort: CONFIRMED → LIKELY → MEDIUM → LOW; within tier,
# on-domain personal → role → off-domain personal.
# P7: the legacy 3-tier mapping (``HIGH``/``MEDIUM``/``LOW``)
# is preserved as a fallback so any out-of-band label
# (e.g. from a third-party module that has not yet migrated)
# still sorts predictably.
# ---------------------------------------------------------------------
_LABEL_ORDER = {
    "CONFIRMED": 0,
    "HIGH": 0,
    "LIKELY": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


def _sort_key(email: HarvestedEmail) -> tuple[int, int, int]:
    tier = _LABEL_ORDER.get(email.confidence_label, 2)
    on_domain = 0 if email.on_domain else 1
    is_role = 0 if email.is_role else 1
    # Inside the on_domain and role group, lower-confidence emails
    # come last; sort by the tier order we already computed above.
    return (tier, is_role, on_domain)


def _safe_run(module: Any, domain: str) -> ModuleResult:
    """Wrap a module's ``run`` so a single failure doesn't crash the batch."""
    try:
        result = asyncio.run(module.run(domain))
        return _normalize_module_result(module.name, result)
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("domain_harvest: %s crashed: %s", module.name, exc)
        return ModuleResult(
            status=ModuleStatus.FAILED,
            errors=[f"{module.name}: {exc}"],
        )


# ---------------------------------------------------------------------
# MUST-FIX M3: signature-aware kwargs helper.
# ---------------------------------------------------------------------
def _kwargs_accepted(callable_obj: Any) -> set[str] | None:
    """Return the set of kwarg names accepted by ``callable_obj.run``.

    Returns ``None`` if the signature is generic (*args, **kwargs)
    OR if introspection failed (e.g. AsyncMock raises TypeError on
    ``inspect.signature``). ``None`` means "pass everything through".
    Returns the empty set only when the signature is fully positional
    with no VAR_KEYWORD.

    MUST-FIX M3: helper for signature-aware kwarg filtering so we
    pass ``max_records`` / ``lite_mode`` only to modules that
    actually accept them, while still working with mocks that
    don't introspect cleanly.
    """
    try:
        sig = inspect.signature(callable_obj.run)
    except (TypeError, ValueError):
        # AsyncMock and friends — be permissive.
        return None
    params = list(sig.parameters.values())
    if not params:
        return None
    # Generic *args, **kwargs — accept everything.
    if any(
        p.kind == inspect.Parameter.VAR_KEYWORD
        or p.kind == inspect.Parameter.VAR_POSITIONAL
        for p in params
    ):
        return None
    return {
        p.name
        for p in sig.parameters.values()
        if p.kind in (
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        and p.name not in ("self",)
    }


async def _safe_phase12_run(
    name: str,
    module: Any,
    domain: str,
    *,
    cc_max_records: int | None = None,
    cc_max_collections: int | None = None,
    dork_lite_mode: bool | None = None,
    aggressive: bool = False,
    use_proxies: bool = False,
    proxy_fallback_ok: bool = False,
    fetch: CachedFetch | None = None,
    candidate_paths: tuple[str, ...] = (),
    signal_pool: Any | None = None,
    budget: TimeBudget | None = None,
    soft_timeout: float | None = None,
    with_subdomains: bool = False,
    subdomain_deep: bool = False,
    enable_scraping: bool = True,
    context_vertical: tuple[str, ...] | list[str] | str | None = None,
    scrape_session: Any | None = None,
    progress_callback: Any | None = None,
) -> tuple[str, ModuleResult]:
    """Run a Phase 1+2 module with its optional kwargs.

    MUST-FIX M3: each module gets its explicit per-run options via
    kwargs. Mocks from tests may not accept these — we accept that
    the call still goes through by passing only the kwargs the
    module accepts (we introspect signature).

    MUST-FIX M3 follow-up: if the module's ``run()`` raises, we
    fabricate a FAILED ``ModuleResult`` so the partial-result
    contract is preserved — every module that was attempted is
    present in the final ``module_results`` dict, even on failure.

    0.11.1 Phase 3: ``cc_max_collections`` and ``aggressive`` are
    threaded down.  Common Crawl picks them up via ``max_collections``
    / ``aggressive``; Wayback picks them up via ``aggressive`` +
    ``max_urls``; the rest ignore both.

    0.11.1 Phase 3 cache: ``fetch`` is the :class:`CachedFetch`
    facade wrapping the per-run :class:`ConcurrentFetchCache`.
    Modules that touch HTTP (email_search_dork, wayback,
    github_org_members) accept it and route their requests through
    it; the rest silently ignore it via the signature-aware kwarg
    filter.
    """
    kwargs: dict[str, Any] = {}
    if name == MODULE_COMMONCRAWL:
        if cc_max_records is not None:
            kwargs["max_records"] = cc_max_records
        if cc_max_collections is not None:
            kwargs["max_collections"] = cc_max_collections
        if aggressive:
            kwargs["aggressive"] = True
    elif name == MODULE_WAYBACK_DOMAIN:
        if aggressive:
            kwargs["aggressive"] = True
    elif name == MODULE_EMAIL_DORK:
        if dork_lite_mode is not None:
            kwargs["lite_mode"] = dork_lite_mode
        if aggressive:
            kwargs["aggressive"] = True  # run all 5 dork patterns vs default 2
    if use_proxies and name in _PROXY_AWARE_MODULES:
        kwargs["use_proxies"] = True
        # strict_proxy: True = raise on proxy failure (default when --use-proxies)
        #               False = allow direct fallback (when --proxy-fallback-ok)
        kwargs["strict_proxy"] = not proxy_fallback_ok
    if fetch is not None:
        kwargs["fetch"] = fetch
    if candidate_paths and name == MODULE_EMPLOYEE_NAMES:
        kwargs["candidate_paths"] = candidate_paths
    if signal_pool is not None:
        kwargs["signal_pool"] = signal_pool
    if progress_callback is not None:
        kwargs["progress_callback"] = progress_callback
    if name == "subdomain_intel":
        kwargs["with_subdomains"] = with_subdomains
        kwargs["subdomain_deep"] = subdomain_deep
        kwargs["enable_scraping"] = enable_scraping
        kwargs["context_vertical"] = context_vertical
        kwargs["scrape_session"] = scrape_session
    accepted = _kwargs_accepted(module)
    try:
        if accepted is None:
            # Generic callable — pass everything.
            result = await _run_with_soft_timeout(
                name,
                module.run(domain, **kwargs),
                budget,
                soft_timeout=soft_timeout,
            )
            normalized = _normalize_module_result(name, result)
            _emit_finding_signals(signal_pool, name, normalized.findings, domain)
            return name, normalized
        filtered = {k: v for k, v in kwargs.items() if k in accepted}
        result = await _run_with_soft_timeout(
            name,
            module.run(domain, **filtered),
            budget,
            soft_timeout=soft_timeout,
        )
        normalized = _normalize_module_result(name, result)
        _emit_finding_signals(signal_pool, name, normalized.findings, domain)
        return name, normalized
    except TypeError:
        # Mocks that don't accept our kwargs — fall back to positional.
        result = await _run_with_soft_timeout(name, module.run(domain), budget, soft_timeout=soft_timeout)
        normalized = _normalize_module_result(name, result)
        _emit_finding_signals(signal_pool, name, normalized.findings, domain)
        return name, normalized
    except Exception as exc:  # noqa: BLE001
        _LOG.warning(
            "domain_harvest: %s crashed: %s", name, exc
        )
        return name, ModuleResult(
            status=ModuleStatus.FAILED,
            errors=[f"{name}: {exc}"],
        )


async def _run_with_soft_timeout(
    module_name: str,
    awaitable: Any,
    budget: TimeBudget | None,
    *,
    soft_timeout: float | None = None,
) -> ModuleResult:
    if soft_timeout is None and budget is not None:
        soft_timeout = budget.soft_timeout_for_module()
    if soft_timeout is None:
        return await awaitable
    task = asyncio.create_task(awaitable)
    try:
        return await asyncio.wait_for(task, timeout=soft_timeout)
    except asyncio.TimeoutError:
        _LOG.warning(
            "Module %s exceeded soft timeout %.1fs - returning empty result",
            module_name,
            soft_timeout,
        )
        return ModuleResult(
            status=ModuleStatus.PARTIAL,
            findings=[],
            errors=[f"Soft timeout after {soft_timeout:.1f}s"],
        )


async def _run_pattern(
    pattern: Any,
    domain: str,
    *,
    employee_names: list[EmployeeNameResult],
    enable_smtp: bool | None = None,
    progress_callback: Any | None = None,
    signal_pool: Any | None = None,
    budget: TimeBudget | None = None,
) -> ModuleResult:
    """Run pattern_and_verify with explicit kwargs.

    MUST-FIX M3: enable_smtp is passed explicitly. Tests that pass a
    mock ``pattern_module`` whose ``run()`` accepts only ``(domain,
    employee_names)`` still work because we fall back gracefully when
    the signature doesn't include ``enable_smtp``.
    """
    pattern_accepted = _kwargs_accepted(pattern)
    pattern_kwargs: dict[str, Any] = {}
    if pattern_accepted is None or "employee_names" in pattern_accepted:
        pattern_kwargs["employee_names"] = employee_names
    if (
        enable_smtp is not None
        and (pattern_accepted is None or "enable_smtp" in pattern_accepted)
    ):
        pattern_kwargs["enable_smtp"] = enable_smtp
    if progress_callback is not None and (
        pattern_accepted is None or "progress_callback" in pattern_accepted
    ):
        pattern_kwargs["progress_callback"] = progress_callback
    if signal_pool is not None and (
        pattern_accepted is None or "signal_pool" in pattern_accepted
    ):
        pattern_kwargs["signal_pool"] = signal_pool
    result = await _run_with_soft_timeout(
        pattern.name,
        pattern.run(domain, **pattern_kwargs),
        budget,
    )
    normalized = _normalize_module_result(pattern.name, result)
    _emit_finding_signals(signal_pool, pattern.name, normalized.findings, domain)
    return normalized


async def route_sitemap_content(
    domain: str,
    fetch: CachedFetch,
    *,
    pool: Any | None = None,
    max_urls: int = 50,
) -> list[str]:
    """Discover sitemap-backed content hubs and stream them through extractors.

    This is the orchestration hook for the new sitemap router.  It keeps the
    routing logic separate from ``run_domain_harvest`` so callers can opt into
    the content sweep without forcing the email harvest pipeline to do extra
    live work by default.
    """
    from .pagination_handler import PaginationHandler
    from .schema_content_extractor import SchemaContentExtractor
    from .signal_pool import AsyncSignalPool
    from .sitemap_content_router import SitemapContentRouter

    router = SitemapContentRouter()
    urls = await router.route(domain, fetch, max_urls=max_urls)
    if not urls:
        return []

    owns_pool = pool is None
    content_pool = pool if pool is not None else AsyncSignalPool()
    paginator = PaginationHandler(fetch)
    extractor = SchemaContentExtractor(content_pool)

    try:
        for content_url in urls:
            async for page_url, raw_bytes in paginator.paginate(content_url):
                await extractor.extract_from_html(
                    raw_bytes,
                    page_url=page_url,
                    target_domain=domain,
                )
    finally:
        if owns_pool:
            await content_pool.close()

    return urls


async def _route_industry_candidates(
    domain: str,
    fetch: CachedFetch | None,
) -> IndustryVocabularyResult:
    """Run the homepage vocabulary router before harvest modules fire."""
    homepage = ""
    if fetch is not None:
        try:
            response = await fetch.get(f"https://{domain}/")
            homepage = getattr(response, "text", "") or ""
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("domain_harvest: industry router homepage fetch failed: %s", exc)
    return IndustryVocabularyRouter().route(homepage)


def _content_finding_from_email(
    *,
    email: str,
    domain: str,
    source_url: str = "",
    name: str | None = None,
    source_type: str = "content_intelligence",
    confidence_score: float = 0.7,
) -> dict[str, Any]:
    local_part = email.split("@", 1)[0] if "@" in email else ""
    return {
        "platform": MODULE_CONTENT_INTELLIGENCE,
        "profile_url": source_url or email,
        "username": local_part,
        "confidence": "high" if confidence_score >= 0.7 else "medium",
        "metadata": {
            "email": email,
            "name": name,
            "on_domain": email.rsplit("@", 1)[-1].lower() == domain,
            "source": MODULE_CONTENT_INTELLIGENCE,
            "source_url": source_url,
            "source_type": source_type,
            "confidence_score": round(confidence_score, 4),
        },
    }


async def discover_and_extract_content(
    *,
    domain: str,
    session: Any,
    signal_pool: Any | None = None,
    fetch_cache: CachedFetch | None = None,
    cache: CachedFetch | None = None,
    aggressive: bool = False,
    candidate_paths: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Run the content-intelligence extraction phase and return findings.

    This adapter wires the previously isolated content helpers into the
    harvest shape consumed by ``_aggregate`` without changing the legacy
    aggregation logic.
    """
    from .company_page_names import discover_and_extract
    from .hydration_extractor import HydrationDataExtractor
    from .pagination_handler import PaginationHandler
    from .schema_content_extractor import SchemaContentExtractor
    from .signal_pool import AsyncSignalPool
    from .sitemap_content_router import SitemapContentRouter

    fetch = fetch_cache or cache
    if session is None and fetch is None:
        return []
    owns_pool = signal_pool is None
    pool = signal_pool if signal_pool is not None else AsyncSignalPool(export_threshold=0.0)
    findings: list[dict[str, Any]] = []
    seen_emails: set[str] = set()

    def add_email(
        email: str | None,
        *,
        source_url: str = "",
        name: str | None = None,
        source_type: str = MODULE_CONTENT_INTELLIGENCE,
        confidence_score: float = 0.7,
    ) -> None:
        if not email or "@" not in email:
            return
        cleaned_email = email.strip().lower()
        if not cleaned_email or cleaned_email in seen_emails:
            return
        seen_emails.add(cleaned_email)
        findings.append(
            _content_finding_from_email(
                email=cleaned_email,
                domain=domain,
                source_url=source_url,
                name=name,
                source_type=source_type,
                confidence_score=confidence_score,
            )
        )

    try:
        records = await discover_and_extract(
            domain,
            session,
            aggressive=aggressive,
            max_candidates=max(
                1,
                int(getattr(settings, "site_discovery_max_candidates", 15) or 15),
            ),
            timeout=max(
                1.0,
                float(getattr(settings, "site_discovery_timeout_seconds", 5) or 5),
            ),
            candidate_paths=candidate_paths,
        )
        for record in records:
            add_email(
                getattr(record, "email", None),
                source_url=getattr(record, "page_url", "") or "",
                name=getattr(record, "name", None),
                source_type=getattr(record, "source_type", MODULE_CONTENT_INTELLIGENCE),
                confidence_score=float(getattr(record, "confidence", 0.7) or 0.7),
            )

        if fetch is not None:
            router = SitemapContentRouter()
            paginator = PaginationHandler(fetch)
            schema_extractor = SchemaContentExtractor(pool)
            hydration_extractor = HydrationDataExtractor(pool)
            routed_urls = await router.route(domain, fetch, max_urls=50)
            for content_url in routed_urls:
                async for page_url, raw_bytes in paginator.paginate(content_url):
                    await schema_extractor.extract_from_html(
                        raw_bytes,
                        page_url=page_url,
                        target_domain=domain,
                    )
                    await hydration_extractor.extract_from_html(
                        raw_bytes,
                        page_url=page_url,
                    )

        if owns_pool:
            await pool.close()
        for cluster in await pool.all_candidates():
            for signal in cluster.signals:
                meta = signal.metadata or {}
                person = meta.get("person") if isinstance(meta, dict) else None
                email = None
                if signal.kind == "email":
                    email = signal.value
                elif isinstance(person, dict):
                    email = person.get("email")
                add_email(
                    email,
                    source_url=str(meta.get("page_url") or ""),
                    name=str(meta.get("name") or "") or None,
                    source_type=str(meta.get("source_type") or signal.source),
                    confidence_score=max(0.7, float(cluster.score or 0.0)),
                )
    finally:
        if owns_pool:
            await pool.close()

    return findings


async def _run_content_intelligence(
    domain: str,
    session: Any,
    fetch: CachedFetch | None,
    *,
    aggressive: bool,
    candidate_paths: tuple[str, ...],
    discover_callable: Any,
) -> tuple[str, ModuleResult]:
    try:
        findings = await discover_callable(
            domain=domain,
            session=session,
            signal_pool=None,
            fetch_cache=fetch,
            aggressive=aggressive,
            candidate_paths=candidate_paths,
        )
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("domain_harvest: content intelligence crashed: %s", exc)
        return MODULE_CONTENT_INTELLIGENCE, ModuleResult(
            status=ModuleStatus.FAILED,
            findings=[],
            errors=[f"{MODULE_CONTENT_INTELLIGENCE}: {exc}"],
            metadata={"domain": domain},
        )
    if isinstance(findings, ModuleResult):
        return MODULE_CONTENT_INTELLIGENCE, _normalize_module_result(
            MODULE_CONTENT_INTELLIGENCE, findings
        )
    safe_findings = [f for f in (findings or []) if isinstance(f, dict)]
    return MODULE_CONTENT_INTELLIGENCE, ModuleResult(
        status=ModuleStatus.SUCCESS if safe_findings else ModuleStatus.PARTIAL,
        findings=safe_findings,
        metadata={"domain": domain, "findings": len(safe_findings)},
    )


# ---------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------
async def run_domain_harvest(
    domain: str,
    enable_smtp: bool | None = None,
    enable_m365: bool = False,
    enable_yahoo: bool = False,
    *,
    cc_module: Any | None = None,
    wayback_module: Any | None = None,
    code_cert_module: Any | None = None,
    dork_module: Any | None = None,
    employee_module: Any | None = None,
    npm_module: Any | None = None,
    pypi_module: Any | None = None,
    pgp_module: Any | None = None,
    syndication_module: Any | None = None,
    github_org_module: Any | None = None,
    pattern_module: Any | None = None,
    content_intelligence_callable: Any | None = None,
    dork_lite_mode: bool | None = None,
    cc_max_records: int | None = None,
    cc_max_collections: int | None = None,
    aggressive: bool = False,
    use_proxies: bool = False,
    proxy_fallback_ok: bool = False,
    on_module_complete: Any | None = None,
    timeout_seconds: float | None = None,
    enable_email_identity_enrichment: bool | None = None,
    skip_modules: tuple[str, ...] | list[str] | None = None,
    with_subdomains: bool = False,
    subdomain_deep: bool = False,
    subdomain_calibrate: bool = False,
    progress_callback: Any | None = None,
    display_subscriber: Any | None = None,
    force: bool = False,
) -> DomainHarvestResult:
    """Run all nine harvest modules in the recommended sequence.

    0.11.1 Phase 3 adds the ``wayback_module`` injection point and the
    ``aggressive`` threading argument.  ``cc_max_collections`` lets
    the operator override the default CC multi-collection cap.

    Parameters
    ----------
    domain:
        A corporate domain (e.g. ``"example.com"``).  Free-provider
        domains (gmail.com, yahoo.com, …) are rejected.
    enable_smtp:
        Explicit per-run override for SMTP RCPT TO verification. ``None``
        uses the default-on ``smtp_verify_default`` setting; the CLI's
        ``--no-verify`` passes ``False``.
        The orchestrator does NOT mutate ``settings.enable_smtp_verification``
        — it threads the value down to ``pattern_and_verify.run`` via the
        ``enable_smtp`` keyword argument. Previously this function
        captured the prior settings value and restored it in a
        try/finally block; that pattern was a race condition in any
        concurrent context (web server, parallel investigation). Now
        removed entirely.
    dork_lite_mode:
        MUST-FIX M3: explicit override for the email dork module's
        ``lite_mode`` flag. Threaded down to ``email_search_dork.run``.
        The orchestrator does NOT mutate ``settings.dork_lite_mode``.
    cc_max_records:
        MUST-FIX M3: explicit override for the Common Crawl module's
        record limit. Threaded down to ``commoncrawl_email.run`` as
        a backwards-compatible budget (the module redistributes it
        across the configured collection cap).
    cc_max_collections:
        0.11.1 Phase 3: explicit override for the Common Crawl
        multi-collection sweep cap. Threaded down to
        ``commoncrawl_email.run``.
    aggressive:
        0.11.1 Phase 3: when True the common-crawl + wayback modules
        use their aggressive budgets (24 collections / 500 records
        per collection / Wayback year-bounded sub-queries).
    use_proxies:
        When True, proxy-aware harvest modules route eligible HTML
        requests through the configured ScrapingAnt transport.
    *_module:
        Injection points used by tests — pass a mock module instance
        to bypass real network calls.  Each mock must expose
        ``.name`` and an async ``run(domain)`` method. Mock modules
        MUST accept the ``enable_smtp`` / ``lite_mode`` /
        ``max_records`` / ``aggressive`` keyword arguments and
        either consume them or accept them silently.
    npm_module / pypi_module / pgp_module:
        W5 injection points for the three new structured-source
        modules. Same contract as the other *_module kwargs.
    syndication_module:
        Optional feed-sweeper injection point. Crawls RSS / Atom
        feeds discovered from the homepage and publishes author data.
    wayback_module:
        0.11.1 Phase 3 injection point for Wayback domain harvest.
        Defaults to a real :class:`WaybackDomainHarvestModule`.
    """
    from .harvest_runner import run_adaptive_harvest
    from .harvest_cache import HarvestCache

    if enable_smtp is None:
        enable_smtp = bool(getattr(settings, "smtp_verify_default", True))

    profile = getattr(settings, "harvest_timing_profile", "t2")
    total = timeout_seconds or budget_for_profile(profile)
    module_overrides = {
        name: module
        for name, module in {
            MODULE_COMMONCRAWL: cc_module,
            MODULE_WAYBACK_DOMAIN: wayback_module,
            MODULE_CODE_CERT: code_cert_module,
            MODULE_EMAIL_DORK: dork_module,
            MODULE_EMPLOYEE_NAMES: employee_module,
            MODULE_NPM_EMAIL: npm_module,
            MODULE_PYPI_EMAIL: pypi_module,
            MODULE_PGP_DOMAIN_EMAIL: pgp_module,
            MODULE_SYNDICATION_FEED_SWEEPER: syndication_module,
            MODULE_GITHUB_ORG_MEMBERS: github_org_module,
            MODULE_PATTERN_VERIFY: pattern_module,
        }.items()
        if module is not None
    }

    # Explicit module injection is the deterministic test/embedder seam. It
    # must not consume or overwrite a user's normal on-disk harvest cache.
    cache = HarvestCache()
    cache_enabled = bool(getattr(settings, "harvest_cache_enabled", True)) and not bool(
        module_overrides
    )
    if cache_enabled and not force and not cache.is_stale(domain):
        cached = cache.get(domain)
        if cached is not None:
            return cached

    # Injected modules are the isolated/mock path used by the orchestrator
    # tests and embedders. Disable network-heavy identity enrichment there by
    # default; production calls without injected modules keep it enabled.
    if enable_email_identity_enrichment is None:
        enable_email_identity_enrichment = not bool(module_overrides)

    # An injected-module run is a deterministic test/embedder seam. Do not
    # launch real network modules that were not explicitly supplied; that
    # makes a one-finding fixture acquire unrelated live results and defeats
    # the purpose of module injection.
    effective_skip_modules = set(str(name).strip() for name in (skip_modules or ()) if str(name).strip())
    if module_overrides:
        all_injected_capable = {
            MODULE_COMMONCRAWL,
            MODULE_WAYBACK_DOMAIN,
            MODULE_CODE_CERT,
            MODULE_EMAIL_DORK,
            MODULE_EMPLOYEE_NAMES,
            MODULE_NPM_EMAIL,
            MODULE_PYPI_EMAIL,
            MODULE_PGP_DOMAIN_EMAIL,
            MODULE_SYNDICATION_FEED_SWEEPER,
            MODULE_GITHUB_ORG_MEMBERS,
            MODULE_GITHUB_DOMAIN_COMMITS,
            MODULE_PATTERN_VERIFY,
            "public_surface_sweeper",
            "public_forge",
            "package_ecosystems",
            "subdomain_intel",
            "hackertarget_hosts",
            "ripe_stat_asn",
            "wordpress_rest",
            "security_txt",
            "name_to_github_profile",
            "person_email_pivot",
            "email_identity_enrichment",
            "hunter",
        }
        effective_skip_modules.update(all_injected_capable - set(module_overrides))

    result = await run_adaptive_harvest(
        domain=domain,
        timeout_seconds=total,
        enable_smtp=enable_smtp,
        enable_m365=enable_m365,
        enable_yahoo=enable_yahoo,
        use_proxies=use_proxies,
        aggressive=aggressive,
        timing_profile=profile,
        module_overrides=module_overrides,
        on_module_complete=on_module_complete,
        dork_lite_mode=dork_lite_mode,
        cc_max_records=cc_max_records,
        cc_max_collections=cc_max_collections,
        proxy_fallback_ok=proxy_fallback_ok,
        enable_email_identity_enrichment=enable_email_identity_enrichment,
        skip_modules=tuple(sorted(effective_skip_modules)),
        with_subdomains=with_subdomains,
        subdomain_deep=subdomain_deep,
        subdomain_calibrate=subdomain_calibrate,
        progress_callback=progress_callback,
        display_subscriber=display_subscriber,
    )
    if cache_enabled:
        cache.set(domain, result)
    return result


async def _run_hunter(
    domain: str,
    api_key: str | None,
    signal_pool: Any | None = None,
) -> tuple[str, ModuleResult]:
    """Run Hunter.io domain search as a Phase 1 inline source.

    0.11.1 Phase 4: Hunter.io runs alongside the other Phase 1
    sources.  It is not a BaseModule subclass; this function wraps
    the raw ``hunter_search`` call in a ModuleResult so it slots
    into the same aggregation pipeline.

    P1 (Phase 3 workstream): when Hunter returns ``data.pattern``,
    it is emitted as a confirmed pattern through the signal pool
    so the pattern-generation phase (Phase 3) can boost matching
    candidates by +0.30 and demote non-matching ones by -0.12.
    The circuit breaker in :mod:`backend.core.hunter_client` is
    applied inside :func:`search_domain` itself; we just consume
    the empty result when the cap is reached.
    """
    if not api_key:
        return "hunter", ModuleResult(
            status=ModuleStatus.SKIPPED,
            findings=[],
            errors=["Hunter API key not configured"],
            metadata={"domain": domain, "skip_reason": "no_api_key"},
        )
    try:
        results = await hunter_search(domain, api_key, limit=50)
    except Exception as exc:
        _LOG.warning("domain_harvest: Hunter search failed: %s", exc)
        return "hunter", ModuleResult(
            status=ModuleStatus.FAILED,
            findings=[],
            errors=[f"Hunter: {exc}"],
            metadata={"domain": domain},
        )

    if not results:
        # The empty-list branch covers two cases: the API returned no
        # results, OR the monthly circuit breaker fired.  Surface the
        # latter explicitly so the CLI hint can show a useful message.
        breaker_open = hunter_circuit_open()
        return "hunter", ModuleResult(
            status=ModuleStatus.PARTIAL,
            findings=[],
            metadata={
                "domain": domain,
                "hunter_results": 0,
                "circuit_breaker_open": breaker_open,
                "monthly_cap": HUNTER_MONTHLY_CAP,
            },
        )

    # P1: surface Hunter's data.pattern as a confirmed pattern.
    # All results in a single response share the same pattern, so
    # we only need to emit once.  We emit only when the pattern
    # actually maps to one of our templates — unrecognised patterns
    # are kept in the metadata for audit but do not influence
    # pattern generation.
    hunter_pattern: str | None = None
    hunter_pattern_template: str | None = None
    for r in results:
        if r.pattern_template:
            hunter_pattern_template = r.pattern_template
            hunter_pattern = r.pattern
            break
    if (
        hunter_pattern_template is not None
        and signal_pool is not None
        and hasattr(signal_pool, "emit_confirmed_pattern")
    ):
        # Emit ONLY the mapped full template.  The raw Hunter
        # short form (e.g. ``{first}.{last}``) is preserved in
        # the metadata for traceability.
        signal_pool.emit_confirmed_pattern(hunter_pattern_template)

    findings: list[dict[str, Any]] = []
    for r in results:
        source_type = (
            "hunter_verified"
            if r.confidence >= 90
            else ("hunter_high" if r.confidence >= 70 else "hunter_low")
        )
        from ..core.email_confidence import compute_confidence_breakdown, label_for_score

        ci = compute_confidence_breakdown(
            source_types=[source_type],
            is_smtp_verified=False,
            is_ca_attested=False,
        )
        local_part = r.email.split("@", 1)[0] if "@" in r.email else ""
        findings.append(
            {
                "platform": "hunter",
                "profile_url": "",
                "username": local_part,
                "confidence": label_for_score(ci.score).lower(),
                "metadata": {
                    "email": r.email,
                    "on_domain": True,
                    "email_type": r.email_type,
                    "hunter_confidence": r.confidence,
                    "first_name": r.first_name,
                    "last_name": r.last_name,
                    "position": r.position,
                    "source_type": source_type,
                    "confidence_score": round(ci.score, 4),
                    "confidence_breakdown": ci.breakdown,
                    # P1: surface the pattern on each finding so
                    # downstream consumers can show WHY a Hunter hit
                    # was chosen.  ``hunter_pattern`` is the raw
                    # short form (or None); ``hunter_pattern_template``
                    # is the mapped full template (or None).
                    "hunter_pattern": r.pattern,
                    "hunter_pattern_template": r.pattern_template,
                },
            }
        )

    return "hunter", ModuleResult(
        status=ModuleStatus.SUCCESS,
        findings=findings,
        metadata={
            "domain": domain,
            "hunter_results": len(results),
            "hunter_verified": sum(1 for r in results if r.confidence >= 90),
            "hunter_high": sum(1 for r in results if 70 <= r.confidence < 90),
            "hunter_low": sum(1 for r in results if r.confidence < 70),
            "hunter_pattern": hunter_pattern,
            "hunter_pattern_template": hunter_pattern_template,
            "circuit_breaker_open": False,
            "monthly_cap": HUNTER_MONTHLY_CAP,
        },
    )


async def _orchestrate(
    domain: str,
    cc: Any,
    wayback: Any,
    cc_cert: Any,
    dork: Any,
    emp: Any,
    npm: Any,
    pypi: Any,
    pgp: Any,
    syndication: Any,
    github_org: Any,
    pattern: Any,
    content_intelligence: Any,
    content_fetch_enabled: bool,
    *,
    enable_smtp: bool = False,
    dork_lite_mode: bool | None = None,
    cc_max_records: int | None = None,
    cc_max_collections: int | None = None,
    aggressive: bool = False,
    use_proxies: bool = False,
    proxy_fallback_ok: bool = False,
    on_module_complete: Any | None = None,
    budget: TimeBudget | None = None,
) -> DomainHarvestResult:
    """Inner orchestration — runs the 9 modules in sequence.

    Sequence:
        Phase 1+2 — the domain data modules run concurrently
                    (``asyncio.as_completed`` so each callback fires
                    as soon as its module finishes).  W5 adds three
                    modules to this phase (npm_email, pypi_email,
                    pgp_domain_email); 0.11.1 Phase 3 adds
                    wayback_domain_harvest alongside Common Crawl.
        Phase 3  — pattern_and_verify runs AFTER employee_name_discovery
                   completes, since it consumes that module's findings.

    MUST-FIX M3: all per-run options (``enable_smtp``, ``dork_lite_mode``,
    ``cc_max_records``) are threaded down to each module's ``run()`` as
    keyword arguments. The orchestrator does NOT mutate the global
    settings object at any point.

    MUST-FIX S5: ``on_module_complete`` is an optional callable that
    receives ``(module_name: str, status: str)`` each time a module's
    :class:`ModuleResult` is finalized. The CLI uses this to update
    its ``Rich Live`` progress table in real time — without it the
    table would only refresh once at the very end. Callable signature
    is permissive (``*args, **kwargs``) so a plain function or a
    bound method both work.

    0.11.1 Phase 3: ``cc_max_collections`` and ``aggressive`` are
    threaded down to ``commoncrawl_email`` and ``wayback_domain_harvest``;
    Wayback runs concurrently with Common Crawl in Phase 1 because
    they hit different upstreams and have no shared rate-limited
    budget.
    """

    def _emit(name: str, mr: ModuleResult) -> None:
        if on_module_complete is None:
            return
        status_value = (
            mr.status.value if hasattr(mr.status, "value") else str(mr.status)
        )
        errors = list(mr.errors or [])
        try:
            on_module_complete(name, status_value, errors)
        except TypeError:
            # Backwards compatibility: old callbacks only accept (name, status).
            try:
                on_module_complete(name, status_value)
            except Exception:  # noqa: BLE001
                pass
        except Exception:  # noqa: BLE001
            # Callback must never break the harvest.
            _LOG.debug(
                "domain_harvest: on_module_complete(%s, %s) raised — ignored",
                name,
                status_value,
            )

    started = datetime.now(timezone.utc)
    started_iso = started.isoformat().replace("+00:00", "Z")
    signal_pool = AsyncSignalPool(export_threshold=0.0)

    # ------------------------------------------------------------------
    # 0.11.1 Phase 3: build the per-run HTTP cache.
    #
    # Every module in the new architecture fetches bytes through this
    # cache rather than invoking StealthSession directly, so duplicate
    # URLs across modules collapse to a single underlying request.
    # The cache owns one StealthSession for the run; it is created
    # here, passed to the modules via ``fetch=`` below, and torn down
    # in the ``finally`` block so no state leaks across runs.
    #
    # If StealthSession cannot be constructed (curl-cffi missing in
    # some test environment), we still wire the orchestrator together
    # and let modules fall back to their own transports — the cache
    # is best-effort, not load-bearing for tests.
    # ------------------------------------------------------------------
    cache: ConcurrentFetchCache | None = None
    fetch: CachedFetch | None = None
    cache_session: StealthSession | None = None
    cache_stats: dict[str, int] = {}
    try:
        try:
            cache_profile = resolve_timing_profile(
                getattr(settings, "harvest_timing_profile", None)
            )
            cache_session: StealthSession | None = StealthSession(
                timing_profile=cache_profile,
            )
        except Exception as exc:  # noqa: BLE001
            _LOG.debug(
                "domain_harvest: StealthSession unavailable, modules will "
                "fall back to their own transports: %s",
                exc,
            )
            cache_session = None

        if cache_session is not None:
            cache = ConcurrentFetchCache(cache_session)
            fetch = CachedFetch(cache)
    except Exception as exc:  # noqa: BLE001 — never let cache wiring kill the run
        _LOG.debug("domain_harvest: cache init failed, continuing without: %s", exc)
        cache = None
        fetch = None

    try:
        phase_fetch = fetch if content_fetch_enabled else None
        phase_session = phase_fetch if phase_fetch is not None else cache_session
        industry_result = await _route_industry_candidates(domain, phase_fetch)
        candidate_paths = tuple(industry_result.target_paths)
        # ------------------------------------------------------------------
        # Phase 1+2 — concurrent run of all data modules
        # MUST-FIX S5: ``asyncio.as_completed`` so we can fire the
        # ``on_module_complete`` callback as each module finishes, instead
        # of waiting for ``gather`` to return all at once.
        # W5: the three new structured-source modules (npm, pypi, pgp)
        # slot in here and run alongside commoncrawl_email and
        # code_and_cert_email — same parallel budget, no sequencing.
        # 0.11.1 Phase 3: wayback_domain_harvest joins Phase 1 alongside
        # Common Crawl — different upstream, no shared rate budget.
        # 0.11.1 Phase 3: syndication_feed_sweeper also runs here â€” it
        # discovers feed links from the homepage and extracts authors.
        # 0.11.1 Phase 4: github_org_members and Hunter.io join Phase 1.
        # Hunter.io is not a BaseModule — it is a direct function call
        # wrapped in _run_hunter below.
        # 0.11.1 Phase 3 cache: every module that touches HTTP gets the
        # shared ``fetch`` facade; the rest ignore it via signature-aware
        # kwarg filtering.
        # ------------------------------------------------------------------
        phase12_coroutines = [
            _safe_phase12_run(
                MODULE_COMMONCRAWL,
                cc,
                domain,
                cc_max_records=cc_max_records,
                cc_max_collections=cc_max_collections,
                aggressive=aggressive,
                fetch=fetch,
                signal_pool=signal_pool,
                budget=budget,
            ),
            _safe_phase12_run(
                MODULE_WAYBACK_DOMAIN,
                wayback,
                domain,
                aggressive=aggressive,
                fetch=fetch,
                signal_pool=signal_pool,
                budget=budget,
            ),
            _safe_phase12_run(
                MODULE_CODE_CERT,
                cc_cert,
                domain,
                fetch=fetch,
                signal_pool=signal_pool,
                budget=budget,
            ),
            _safe_phase12_run(
                MODULE_EMAIL_DORK,
                dork,
                domain,
                dork_lite_mode=dork_lite_mode,
                aggressive=aggressive,
                use_proxies=use_proxies,
                proxy_fallback_ok=proxy_fallback_ok,
                fetch=fetch,
                signal_pool=signal_pool,
                budget=budget,
            ),
            _safe_phase12_run(
                MODULE_EMPLOYEE_NAMES,
                emp,
                domain,
                use_proxies=use_proxies,
                proxy_fallback_ok=proxy_fallback_ok,
                fetch=fetch,
                candidate_paths=candidate_paths,
                signal_pool=signal_pool,
                budget=budget,
            ),
            _safe_phase12_run(
                MODULE_NPM_EMAIL,
                npm,
                domain,
                fetch=fetch,
                signal_pool=signal_pool,
                budget=budget,
            ),
            _safe_phase12_run(
                MODULE_PYPI_EMAIL,
                pypi,
                domain,
                fetch=fetch,
                signal_pool=signal_pool,
                budget=budget,
            ),
            _safe_phase12_run(
                MODULE_PGP_DOMAIN_EMAIL,
                pgp,
                domain,
                fetch=fetch,
                signal_pool=signal_pool,
                budget=budget,
            ),
            _safe_phase12_run(
                MODULE_SYNDICATION_FEED_SWEEPER,
                syndication,
                domain,
                fetch=fetch,
                signal_pool=signal_pool,
                budget=budget,
            ),
            _safe_phase12_run(
                MODULE_GITHUB_ORG_MEMBERS,
                github_org,
                domain,
                fetch=fetch,
                signal_pool=signal_pool,
                budget=budget,
            ),
            _run_content_intelligence(
                domain,
                phase_session,
                phase_fetch,
                aggressive=aggressive,
                candidate_paths=candidate_paths,
                discover_callable=content_intelligence,
            ),
            _run_hunter(domain, settings.hunter_io_api_key, signal_pool=signal_pool),
        ]
        phase12_results: dict[str, ModuleResult] = {}
        for fut in asyncio.as_completed(phase12_coroutines):
            try:
                outcome = await fut
            except BaseException as exc:  # noqa: BLE001
                _LOG.warning("domain_harvest: phase12 task raised: %s", exc)
                continue
            if isinstance(outcome, BaseException):
                _LOG.warning(
                    "domain_harvest: phase12 task raised: %s", outcome
                )
                continue
            name, result = outcome  # type: ignore[misc]
            phase12_results[name] = _normalize_module_result(name, result)
            # MUST-FIX S5: fire callback as soon as this module is final.
            _emit(name, phase12_results[name])

        # ------------------------------------------------------------------
        # Phase 3 — pattern_and_verify (depends on employee_name_discovery)
        # MUST-FIX M3: enable_smtp is threaded via the explicit kwarg.
        # MUST-FIX S5: emit callback when pattern_and_verify completes too.
        # ------------------------------------------------------------------
        employee_result = _normalize_module_result(
            MODULE_EMPLOYEE_NAMES,
            phase12_results.get(
                MODULE_EMPLOYEE_NAMES, ModuleResult(status=ModuleStatus.SKIPPED)
            ),
        )
        employee_findings = employee_result.findings or []
        employee_names = _employee_names_from_findings(employee_findings)

        try:
            pattern_result = await _run_pattern(
                pattern,
                domain,
                employee_names=employee_names,
                enable_smtp=enable_smtp,
                signal_pool=signal_pool,
                budget=budget,
            )
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("domain_harvest: pattern_and_verify crashed: %s", exc)
            pattern_result = ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"{MODULE_PATTERN_VERIFY}: {exc}"],
            )
        pattern_result = _normalize_module_result(MODULE_PATTERN_VERIFY, pattern_result)
        _emit(MODULE_PATTERN_VERIFY, pattern_result)

        # ------------------------------------------------------------------
        # Combine all results
        # ------------------------------------------------------------------
        module_results: dict[str, ModuleResult] = {
            **phase12_results,
            MODULE_PATTERN_VERIFY: pattern_result,
        }

        shadow_profiles: list[dict[str, Any]] = []
        unique_emails = _aggregate(
            domain,
            module_results,
            signal_pool=signal_pool,
            shadow_profiles_out=shadow_profiles,
        )
        unique_emails.sort(key=_sort_key)

        completed = datetime.now(timezone.utc)
        completed_iso = completed.isoformat().replace("+00:00", "Z")
        duration = (completed - started).total_seconds()

        # P7: 4-tier counts in the summary are PERSONAL-only
        # (``is_role=False``).  Role accounts are tracked separately
        # via ``role_account_count`` and rendered in their own
        # section.  The previous 3-tier semantics inflated the
        # analyst's HIGH/MEDIUM counts with weak passive
        # inferences; the new CONFIRMED / LIKELY / MEDIUM split
        # keeps the "above the noise floor" hits grouped under
        # LIKELY, the truly-verified hits in CONFIRMED, and the
        # weak-corroboration hits in MEDIUM.
        high = sum(
            1
            for e in unique_emails
            if e.confidence_label == "CONFIRMED" and not e.is_role
        )
        likely = sum(
            1
            for e in unique_emails
            if e.confidence_label == "LIKELY" and not e.is_role
        )
        # ``medium`` is the historical "anything above LOW" band —
        # LIKELY + MEDIUM.  Field name kept for backward
        # compatibility with downstream tooling.
        medium = sum(
            1
            for e in unique_emails
            if e.confidence_label in {"LIKELY", "MEDIUM"} and not e.is_role
        )
        low = sum(
            1
            for e in unique_emails
            if e.confidence_label == "LOW" and not e.is_role
        )
        role = sum(1 for e in unique_emails if e.is_role)
        personal = sum(1 for e in unique_emails if not e.is_role)

        errors: list[str] = []
        for mod_name, res in module_results.items():
            for err in res.errors or []:
                errors.append(f"[{mod_name}] {err}")

        # Catch-all signal: surface from pattern_and_verify metadata.
        catchall_detected: bool | None = None
        confirmed_pattern: str | None = None
        pattern_meta = pattern_result.metadata or {}
        if isinstance(pattern_meta, dict):
            if "is_catchall" in pattern_meta:
                catchall_detected = pattern_meta.get("is_catchall")
            confirmed_pattern = pattern_meta.get("confirmed_pattern")
        if confirmed_pattern is None:
            pool_patterns = signal_pool.get_confirmed_patterns()
            confirmed_pattern = pool_patterns[0] if pool_patterns else None

        # 0.11.1 Phase 3 cache: snapshot stats before teardown so the
        # CLI can print hits / misses / evictions at the end of the run.
        if cache is not None:
            try:
                cache_stats = cache.stats()
            except Exception:  # noqa: BLE001
                cache_stats = {}

        return DomainHarvestResult(
            domain=domain,
            started_at=started_iso,
            completed_at=completed_iso,
            duration_seconds=round(duration, 3),
            module_results=module_results,
            unique_emails=unique_emails,
            total_unique_emails=len(unique_emails),
            high_confidence_count=high,
            likely_confidence_count=likely,
            medium_confidence_count=medium,
            low_confidence_count=low,
            role_account_count=role,
            personal_email_count=personal,
            errors=errors,
            smtp_verification_used=bool(
                pattern_meta.get("smtp_verification_enabled", False)
            ),
            catchall_detected=catchall_detected,
            confirmed_pattern=confirmed_pattern,
            employee_names_processed=len(employee_names),
            fetch_cache_stats=cache_stats or None,
            metadata={"budget": budget.stats} if budget is not None else {},
            shadow_profiles=shadow_profiles,
        )
    finally:
        # 0.11.1 Phase 3 cache: per-run teardown.  ``aclose`` clears every
        # map, cancels in-flight futures, and closes the wrapped
        # StealthSession.  Best-effort — never let teardown noise mask the
        # real return value above.
        if cache is not None:
            with contextlib.suppress(Exception):
                await cache.aclose()
        with contextlib.suppress(Exception):
            await signal_pool.close()
