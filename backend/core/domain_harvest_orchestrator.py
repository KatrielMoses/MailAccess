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
import inspect
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..config import settings
from ..modules.base import ModuleResult, ModuleStatus
from ..modules.domain_intel import _FREE_PROVIDERS
from ..modules.pattern_and_verify import (
    EmployeeNameResult,
    employee_name_result_from_dict,
)
from .concurrent_fetch_cache import CachedFetch
from .context_router import IndustryVocabularyResult, IndustryVocabularyRouter
from .email_confidence import (
    MAX_SCORE,
    compute_confidence,
    compute_confidence_breakdown,
    label_for_score,
)
from .email_extraction import subaddress_key
from .email_validator import validate_email_batch
from .google_workspace_verifier import GoogleWorkspaceVerifier
from .hunter_client import (
    HUNTER_MONTHLY_CAP,
    hunter_circuit_open,
)
from .hunter_client import (
    search_domain as hunter_search,
)
from .m365_tenant import get_user_realm
from .m365_verifier import M365Verifier
from .mail_provider import MailProvider, detect_provider_from_mx
from .mx_resolver import MXRecord, resolve_mx
from .pattern_resolver import (
    DROP,
    EVIDENCE_INFERRED,
    EVIDENCE_OBSERVED,
    VERIFICATION_PROVIDER_VERIFIED,
    CanonicalResolver,
    classify_evidence_kind,
)
from .role_classifier import classify_email
from .smtp_verifier import (
    DEFAULT_PROBE_DELAY,
    MAX_PROBES_HARD_CAP,
    SMTPVerifier,
)
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
    # Phase 5 — post-confirmation breach aggregation. Populated only for
    # SMTP-/provider-confirmed emails; each entry is a privacy-safe breach
    # finding dict (password existence as a boolean flag, never the value).
    breach_enrichment: list[dict[str, Any]] = field(default_factory=list)
    # Phase 3A — person-centric Lead fields, promoted from existing evidence via
    # the 1E claim resolver (see lead_person.resolve_person_fields). Each is
    # evidence-or-null: populated only when an evidenced claim resolves for it,
    # and then it carries a provenance entry in person_field_provenance. A lead
    # with an email but no person fields is still a lead (quantity preserved).
    full_name: str | None = None
    first: str | None = None
    last: str | None = None
    job_title: str | None = None
    seniority: str | None = None  # Phase 3B band; None until a title resolves
    department: str | None = None
    linkedin_url: str | None = None
    phone: str | None = None
    location: str | None = None
    person_field_provenance: dict[str, Any] = field(default_factory=dict)
    # Phase 3C/3D — non-SMTP deliverability score (probability) + unified grade
    # (Valid/Risky/Catch-all/Invalid/Unknown). ``deliverability`` carries the
    # full reasons+evidence for both. None until the deliverability pass runs.
    deliverability_score: float | None = None
    deliverability_grade: str | None = None
    deliverability: dict[str, Any] | None = None
    # 0.16.0 Phase 3 — verification status of THIS address. ``None`` means "no
    # claim asserted" (an observed address whose eligibility is decided by its
    # confidence + grade, as before — zero regression). A corpus company-pattern
    # inference sets ``"unverified"`` so the eligibility gate caps it at REVIEW:
    # a learned-pattern guess is never a ready-to-send lead on its own.
    verification: str | None = None


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
    # Hosted Pro leads are a serving-only channel. They are deliberately kept
    # outside ``unique_emails`` so native collection, persistence, telemetry, and
    # read-first paths cannot retain or re-serve corpus PII by accident.
    corpus_leads: list[HarvestedEmail] = field(default_factory=list)
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


#: Person-relevant metadata keys used to detect COMPETING person claims (R6).
_PERSON_CLAIM_FIELDS = (
    "name",
    "full_name",
    "first",
    "first_name",
    "last",
    "last_name",
    "title",
    "job_title",
    "seniority",
    "department",
    "linkedin_url",
    "phone",
    "location",
)


def _person_claim_signature(meta: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """A hashable signature of the person claim carried by *meta*.

    R6 (S3): two findings from the same module for the same email carry
    DIFFERENT signatures only when their person fields (name/title/…) differ, so
    a competing claim is retained as distinct evidence while identical or
    person-claim-free repeats collapse. Deterministic (sorted, lower-cased).
    """
    if not isinstance(meta, dict):
        return ()
    return tuple(
        (field, str(meta[field]).strip().lower())
        for field in _PERSON_CLAIM_FIELDS
        if meta.get(field) not in (None, "")
    )


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
    """Whether a full name plausibly generated an email local-part.

    Q7: the initial+token clauses must match the local-part EXACTLY, not by prefix.
    A prefix match let "Alice Smith" corroborate the unrelated username "alicesanders"
    (``first + last[:1]`` = ``alices``, and ``alicesanders`` starts with ``alices``),
    manufacturing false high-confidence identities. Exact patterns (plus the
    both-tokens-present case) require genuine correspondence.
    """
    tokens = [t.lower() for t in re.findall(r"[a-zA-Z]+", name)]
    if len(tokens) < 2:
        return False
    local = re.sub(r"[^a-z0-9]", "", local_part.lower())
    if not local:
        return False
    first, last = tokens[0], tokens[-1]
    # Both full name tokens appear in the local part (e.g. "alice.smith" → alicesmith).
    if first in local and last in local:
        return True
    # Otherwise the local-part must EXACTLY equal a supported name pattern.
    patterns = {
        f"{first}{last}",       # alicesmith
        f"{last}{first}",       # smithalice
        f"{first[:1]}{last}",   # asmith
        f"{first}{last[:1]}",   # alices
        f"{last}{first[:1]}",   # smitha
        f"{last[:1]}{first}",   # salice
    }
    return local in patterns


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


def _entry_person_names(entry: HarvestedEmail) -> list[str]:
    """Every person name asserted for an entry across its evidence."""
    names: list[str] = []
    for ev in entry.evidence or []:
        meta = ev.get("metadata") if isinstance(ev, dict) else None
        if not isinstance(meta, dict):
            continue
        for k in ("name", "source_name", "person_name", "display_name"):
            v = meta.get(k)
            if isinstance(v, str) and v.strip():
                names.append(v)
    return names


def _entry_is_observed(entry: HarvestedEmail) -> bool:
    """Whether an aggregated entry carries at least one GENUINE observation.

    Applies the shared :func:`pattern_resolver.classify_evidence_kind` contract to
    each of the entry's evidence dicts — an entry is observed if any of its findings
    is an observation (a real sighting or an affirmative confirmation, including an
    oracle-confirmed pattern). A pure inference (only ``inferred`` / ``unknown``
    findings) is not observed, whatever its ``verification`` field happens to be.
    """
    for ev in entry.evidence or []:
        meta = ev.get("metadata") if isinstance(ev, dict) else None
        if classify_evidence_kind(meta) == EVIDENCE_OBSERVED:
            return True
    return False


def _apply_resolver_person_selection(
    emails: list[HarvestedEmail], resolver: CanonicalResolver | None
) -> list[HarvestedEmail]:
    """Derive person selection from all retained mailbox evidence, in either order."""
    from .pattern_resolver import person_key

    resolver = resolver if resolver is not None else CanonicalResolver()
    observed_emails = set()
    for entry in emails:
        kinds = []
        for evidence in entry.evidence or []:
            meta = dict(evidence.get("metadata") or {})
            # Confirmation proves a generated mailbox; it does not turn its
            # person/address attribution into an independent observed sighting.
            for status_field in ("verification", "verification_status", "smtp_verification_status",
                          "provider_verification_status"):
                meta.pop(status_field, None)
            kinds.append(classify_evidence_kind(meta))
        kind = "observed" if EVIDENCE_OBSERVED in kinds else (
            "confirmed" if entry.verification == VERIFICATION_PROVIDER_VERIFIED else "inferred"
        )
        if kind == "observed":
            observed_emails.add(entry.email)
        for name in _entry_person_names(entry):
            resolver.register_person_mailbox(
                entry.email, person_key=person_key(name), kind=kind,
                corpus="company_pattern_index" in _pattern_source_types(entry),
            )
    return [entry for entry in emails if resolver.is_visible(
        entry.email, inferred=entry.email not in observed_emails,
    )]


def _reconcile_pattern_inferences_by_person(emails: list[HarvestedEmail]) -> list[HarvestedEmail]:
    """Compatibility entry point; person resolution has one implementation."""
    return _apply_resolver_person_selection(emails, None)


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
        # Root B / Brief A — skip ONLY the corpus company-pattern inference, whose
        # score is a calibrated ``applied_confidence``: recomputing it here goes
        # through ``compute_confidence`` WITHOUT the ``source_confidence`` override
        # (falling back to the fixed weight), silently overwriting the calibrated
        # value (e.g. .9879 → .425). The predicate is the inference SOURCE, not the
        # ``unverified`` verification, because a permutation-spray guess is now also
        # derived-unverified (Brief A item 4) yet legitimately relies on this
        # additive name/format pass for its corroboration boost — exactly as it did
        # before pure inferences carried a derived verification. (Corpus entries also
        # lack ``pattern_template`` and are already excluded above; this is the
        # intent-revealing guard.)
        if "company_pattern_index" in _pattern_source_types(entry):
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
        entry.confidence_label = label_for_score(
            entry.confidence_score, cap_unverified_inference=entry.verification == "unverified"
        )
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
        # 0.16.0 Phase 4 — a corpus company-pattern inference (verification
        # ``"unverified"``, no observed corroboration) is BUILT from the very
        # name this loop would match, so boosting it by that name double-counts
        # the same signal. Its score is already the calibrated applied
        # confidence. An observed collision clears verification to None and
        # passes through normally.
        if entry.verification == "unverified":
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
            # Q7: clip the correlation boost to MAX_SCORE like every other boost site
            # (660/1404). Unclipped, a 1.5 score became 3.75, blowing the documented range.
            entry.confidence_score = round(min(entry.confidence_score * 2.5, MAX_SCORE), 4)
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


# 0.16.0 Phase 6 — confirmed verification claims a pattern candidate may carry
# (only ``provider_verified`` today, from the M365 existence oracle). When a pure
# inference group carries one, it propagates onto the entry so the eligibility
# gate can clear it and corpus_store/exports surface the confirmed status.
_CONFIRMED_PATTERN_VERIFICATIONS: frozenset[str] = frozenset({"provider_verified"})

# Root B / Brief A — a finding is classified observed-vs-inferred through the ONE
# shared evidence-kind contract (:func:`pattern_resolver.classify_evidence_kind`),
# which mirrors ``eligibility._CONFIRMED_VERIFICATIONS`` for the "confirmed finding
# is an observation" rule. The per-finding confirmation set no longer lives here.


# 0.17.0 Phase 2 — the module label carried on injected corpus leads (found_by /
# evidence source), and the fixed corpus prior. The confidence is COSMETIC: every
# corpus lead is ``verification="unverified"`` so the eligibility gate caps it at
# REVIEW regardless of the number. The prior sits below the native confirmed band
# (LOW, < MEDIUM) so a corpus guess never inflates the CONFIRMED/LIKELY counts and
# is never eligible for the live provider/SMTP-verification candidate set (which
# requires MEDIUM+); it stays at/above the eligibility review floor so a lawful-
# mode lead lands at REVIEW rather than research-only.
MODULE_MAILACCESS_PRO = "mailaccess_pro"
_PRO_CORPUS_CONFIDENCE = 0.45
_PRO_CORPUS_LABEL = "LOW"


def _pro_injection_active(mode: Any, key: str | None) -> bool:
    """Whether corpus-lead injection may run for this (mode, key).

    The "key never forces a mode" rule: injection requires BOTH a Pro key AND a
    lead-gen mode. security-investigation is excluded even with a key (no
    injection); the module classification (allowed in every mode, like apollo) is
    the capability layer, this is the run gate. Defense-in-depth over the
    authoritative server-side lawful-basis gate (Phase 1).
    """
    from .product_mode import ProductMode, is_module_allowed, normalize_mode

    if not key:
        return False
    m = normalize_mode(mode)
    if m is ProductMode.SECURITY_INVESTIGATION:
        return False
    return is_module_allowed(MODULE_MAILACCESS_PRO, m)


def _scalar_or_none(value: Any) -> str | None:
    """Brief C (C1) — only a plain string survives into evidence metadata; a
    dict/list (e.g. smuggled PII under ``source``) is dropped to None so it can
    never cross into a persisted/exported evidence entry as a nested value."""
    return value if isinstance(value, str) and value.strip() else None


def _pro_evidence_entry(lead: dict[str, Any]) -> dict[str, Any]:
    """Build the evidence entry for one corpus lead, in the native
    ``{"module", "metadata"}`` shape so ``resolve_person_fields`` attributes
    name/title/linkedin from it exactly like a native finding. The corpus fields
    (``corpus_verified`` provenance + ``corpus_source``) ride in the metadata; the
    resolver reads ``full_name``/``job_title``/``linkedin_url`` for person fields.

    C1 — every value carried here is coerced to a validated scalar: the connector
    already sanitized the projected lead, but this is a further belt so no nested
    object ever lands in evidence metadata (and thus a snapshot / export).
    """
    return {
        "module": MODULE_MAILACCESS_PRO,
        "metadata": {
            "source_type": MODULE_MAILACCESS_PRO,
            "full_name": _scalar_or_none(lead.get("name")),
            "job_title": _scalar_or_none(lead.get("title")),
            "linkedin_url": _scalar_or_none(lead.get("linkedin_url")),
            # Provenance only — NEVER promoted to a confirmed verification.
            "corpus_verified": lead.get("corpus_verified") is True,
            "corpus_source": _scalar_or_none(lead.get("source")),
        },
    }


def _email_host(email: str) -> str | None:
    """Lowercased domain part of an email, or None when it has no ``@``."""
    if "@" not in email:
        return None
    return email.rsplit("@", 1)[1].strip().lower().rstrip(".") or None


def _inject_one_pro_lead(
    lead: dict[str, Any],
    by_email: dict[str, HarvestedEmail],
    corpus_leads: list[HarvestedEmail],
    *,
    target_domain: str | None,
) -> None:
    """Inject one corpus lead as a net-new governed row.

    Brief A (A2) — a native row is NEVER influenced by corpus evidence, full stop.
    When the address already exists as a native row we do nothing: we do not append
    the corpus person-field evidence to it, and we do not stamp
    ``mailaccess_pro`` onto its ``found_by_modules``. Corpus person attributes live
    ONLY on net-new corpus rows (which get the corpus-only panel treatment). This
    closes the audit finding where a corpus name could replace a native confirmed
    person claim through the shared 1E resolver: the resolver can never pick a
    corpus name over a native one because corpus evidence never enters a native
    row's resolution.

    Brief B (B2) — ``on_domain`` is decided by POSITIVE validation here, never
    trusted from upstream: a corpus lead is on-domain only if its email host equals
    the harvested domain. When no target domain is threaded (direct-construction
    test seam) the default stays on-domain.
    """
    email = str(lead.get("email") or "").strip()
    if not email or "@" not in email:
        return
    if by_email.get(email.lower()) is not None:
        # Address already covered by a native row — leave it entirely untouched.
        return
    if target_domain:
        on_domain = _email_host(email) == target_domain
        if not on_domain:
            # B2 (re-audit) — a corpus lead MUST be on the requested domain. An
            # off-domain address (e.g. a forged/off-contract hosted response) is not
            # a valid business lead; DROP it rather than retain an off-domain row
            # that render/export would treat as business.
            return
    else:
        on_domain = True
    ev = _pro_evidence_entry(lead)
    row = HarvestedEmail(
        email=email,
        on_domain=on_domain,
        is_role=False,
        role_match_type=None,
        confidence_score=_PRO_CORPUS_CONFIDENCE,
        confidence_label=_PRO_CORPUS_LABEL,
        found_by_modules=[MODULE_MAILACCESS_PRO],
        source_count=1,
        evidence=[ev],
        verification="unverified",
    )
    corpus_leads.append(row)
    by_email[email.lower()] = row


def _inject_pro_leads(
    final: list[HarvestedEmail],
    pro_leads: list[dict[str, Any]] | None,
    *,
    mode: Any,
    key: str | None,
    domain: str | None = None,
    corpus_leads_out: list[HarvestedEmail] | None = None,
) -> None:
    """Merge corpus leads into a serving-only channel as governed, net-new evidence.

    Runs only when the (mode, key) gate is open. ``final`` (the native aggregate) is
    consulted ONLY for collision detection — a corpus row is never appended to it.
    ``domain`` (the harvested domain) drives B2 on-domain validation. The net-new
    rows land in ``corpus_leads_out`` (required in production; a throwaway list when
    a caller omits it — NEVER ``final``, so corpus PII can't leak into the native set).
    """
    if not _pro_injection_active(mode, key):
        return
    # P2(e) — the corpus channel is a dedicated list. A caller that omits it gets a
    # throwaway (the rows are discarded), never ``final`` — corpus data must never
    # land in the native aggregate.
    corpus_leads_out = corpus_leads_out if corpus_leads_out is not None else []
    # D1 — run EVERY corpus candidate through the LOCAL suppression index before it
    # is injected, so a locally-objecting subject is never materialised into the
    # channel (and thus never rendered, exported, or persisted). Defense-in-depth
    # over the hosted route's server-side suppression. Fail CLOSED: if the store
    # can't be read, inject NO corpus data (Stream 1 only) rather than unfiltered PII.
    from .suppression import SuppressionUnavailable, filter_rows, load_index_sync

    try:
        _supp = load_index_sync()
        pro_leads = filter_rows(list(pro_leads or []), _supp)
    except SuppressionUnavailable:
        _LOG.warning(
            "suppression store unavailable; skipping corpus injection (Stream 1 only)"
        )
        return
    target_domain = (
        str(domain).strip().lower().rstrip(".") if isinstance(domain, str) and domain.strip()
        else None
    )
    by_email: dict[str, HarvestedEmail] = {
        e.email.strip().lower(): e
        for e in final
        if isinstance(getattr(e, "email", None), str) and e.email.strip()
    }
    for lead in pro_leads or []:
        if isinstance(lead, dict):
            _inject_one_pro_lead(
                lead, by_email, corpus_leads_out, target_domain=target_domain
            )


def is_corpus_lead(entry: HarvestedEmail) -> bool:
    """Whether ``entry`` is a NET-NEW corpus lead (``mailaccess_pro`` its sole
    source) — covers both the business and personal sub-groups. A native lead that
    merely gained a corpus person-field candidate has other modules in
    ``found_by_modules`` and is NOT a corpus-only lead — it stays in its native tier."""
    mods = set(getattr(entry, "found_by_modules", None) or [])
    return mods == {MODULE_MAILACCESS_PRO}


async def _fetch_pro_leads(domain: str, mode: Any) -> dict[str, Any]:
    """Fetch corpus leads for ``domain`` when the (mode, key) gate is open.

    Returns ``{"requested": bool, "status": str, "leads": list}``. Fail-open: a
    closed gate → ``requested=False`` (Stream 1, no enrichment attempted); a dead
    API / error → ``requested=True, status="unavailable", leads=[]`` so the CLI can
    render the honest "corpus enrichment unavailable" note (invariant 4). The gate
    is checked HERE so the network call is never made in security mode / keyless.
    """
    from ..config import settings

    key = getattr(settings, "mailaccess_pro_key", None)
    if not _pro_injection_active(mode, key):
        return {"requested": False, "status": "not_requested", "leads": []}
    try:
        from . import mailaccess_pro_connector

        # Item B — 500-cap depth: request the full servable set in one call.
        env = await mailaccess_pro_connector.fetch_leads(domain, type="domain", limit=500)
    except Exception:  # pragma: no cover - connector is already fail-open
        _LOG.debug("mailaccess_pro fetch failed; Stream 1 only", exc_info=True)
        return {"requested": True, "status": "unavailable", "leads": []}
    leads = env.get("leads") if isinstance(env, dict) else None
    status = env.get("status") if isinstance(env, dict) else "unavailable"
    return {
        "requested": True,
        "status": str(status or "unavailable"),
        "leads": leads if isinstance(leads, list) else [],
    }


async def _attach_pro_enrichment(
    result: DomainHarvestResult, domain: str, mode: Any
) -> DomainHarvestResult:
    """0.17.0 — the SINGLE Pro-enrichment seam on the live ``run_domain_harvest``
    path (both the fresh return and the cache-hit early return).

    Fetch governed corpus leads for ``domain`` (gated on ``mode`` + key, fail-open)
    and attach them as a serving-only ``corpus_leads`` channel plus the
    ``mailaccess_pro`` metadata note. The channel is built from
    ``result.unique_emails`` ONLY for collision detection (a native address is never
    shadowed by a corpus row) and is NEVER merged back into ``unique_emails`` —
    native collection, persistence, telemetry, scoring, deliverability, and
    read-first never see corpus PII (invariants 3 & 5).

    ``mode`` is the run's resolved product mode, threaded explicitly so the gate is
    correct on the cache-hit path too (it returns before the lawful-gate's own
    ``set_active_mode``). Fail-open, hard: no key / not a lead-gen mode / any error →
    ``result`` returned unchanged (Stream 1 only), byte-identical to a keyless run
    (no ``corpus_leads``, no note).
    """
    try:
        pro_fetch = await _fetch_pro_leads(domain, mode)
    except Exception:  # pragma: no cover - _fetch_pro_leads is already fail-open
        _LOG.debug("mailaccess_pro enrichment failed; Stream 1 only", exc_info=True)
        return result
    return _inject_pro_sync(result, pro_fetch, domain, mode)


def _inject_pro_sync(
    result: DomainHarvestResult, pro_fetch: dict[str, Any] | None, domain: str, mode: Any
) -> DomainHarvestResult:
    """SYNCHRONOUS injection of ALREADY-FETCHED corpus leads as the serving-only
    ``corpus_leads`` channel + ``mailaccess_pro`` note.

    Split out of :func:`_attach_pro_enrichment` so it can also run inside the
    SYNCHRONOUS ``on_harvest_end`` export callback (which must not await): the async
    fetch is done up-front, this does only sync work. Idempotent — a no-op when the
    note is already attached to ``result`` (so the callback-side inject and the
    post-run inject converge on the same object) — and fail-open to Stream 1.
    """
    if result is None:
        return result
    md0 = getattr(result, "metadata", None)
    if isinstance(md0, dict) and "mailaccess_pro" in md0:
        return result  # already attached on this object
    if not isinstance(pro_fetch, dict) or not pro_fetch.get("requested"):
        # Closed gate (keyless / security) — Stream 1, no note; byte-identical to HEAD.
        return result

    channel: list[HarvestedEmail] = []
    try:
        _inject_pro_leads(
            result.unique_emails,
            pro_fetch.get("leads") or [],
            mode=mode,
            key=getattr(settings, "mailaccess_pro_key", None),
            domain=domain,
            corpus_leads_out=channel,
        )
        # The channel receives person projection only — it bypasses native signal
        # correlation, pattern inference, deliverability, scoring, and persistence.
        _apply_person_attribution(channel)
        # D1 (defense-in-depth) — re-filter the resolved channel through the local
        # suppression index; fail CLOSED to Stream 1 if the store is unreadable.
        from .suppression import SuppressionUnavailable, load_index_sync

        try:
            _supp = load_index_sync()
        except SuppressionUnavailable:
            _LOG.warning(
                "suppression store unavailable; dropping corpus channel (Stream 1 only)"
            )
            return result
        channel = [
            row
            for row in channel
            if isinstance(getattr(row, "email", None), str)
            and not _supp.hit(email=row.email)
        ]
    except Exception:  # pragma: no cover - defensive: enrichment must never break S1
        _LOG.debug("mailaccess_pro injection failed; Stream 1 only", exc_info=True)
        return result
    channel.sort(key=_sort_key)

    note = {
        "requested": True,
        "status": pro_fetch.get("status") or "unavailable",
        "injected": len(channel),
    }
    # ``DomainHarvestResult`` is a mutable dataclass; attach directly. Persistence
    # (write_back) uses a sanitized native-only copy, so this only adds the
    # serving-only channel + note to the returned live display object.
    result.corpus_leads = channel
    if isinstance(getattr(result, "metadata", None), dict):
        result.metadata["mailaccess_pro"] = note
    else:
        result.metadata = {"mailaccess_pro": note}
    return result


def _aggregate(
    harvest_domain: str,
    module_results: dict[str, ModuleResult],
    signal_pool: Any | None = None,
    identity_clusters: list[Any] | None = None,
    shadow_profiles_out: list[dict[str, Any]] | None = None,
    resolver: CanonicalResolver | None = None,
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
    first_meta_seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    seen_urls: dict[str, set[str]] = {}
    # Q3 / Part 0.2 — accumulate the source-types (and any confidence breakdowns) of
    # EVERY finding per email, order-independently. The evidence *dict* is still
    # deduped to one-per-(module,email) to bound duplicate URLs, but the aggregated
    # claims that drive the score are collected from all findings — so shuffling the
    # input can no longer change the retained source-types or the score.
    source_type_acc: dict[str, set[str]] = {}
    breakdown_acc: dict[str, list[dict[str, Any]]] = {}
    # 0.16.0 Phase 4 — per-group corpus company-pattern signals, accumulated
    # order-independently alongside the source-types:
    #  * verification_acc: the verification claims asserted for this mailbox
    #    (canonically ``"unverified"`` from the pattern index);
    #  * observed_keys: groups that carry at least one OBSERVED (non-inference)
    #    finding, so an observed address always beats a pattern guess;
    #  * pattern_applied_conf: the per-candidate Wilson-lower-bound
    #    ``applied_confidence`` that overrides the fixed source weight so the
    #    score tracks the domain's real support (max across findings).
    if resolver is not None:
        module_results = resolver.retained_results(module_results)
    verification_acc: dict[str, set[str]] = {}
    observed_keys: set[str] = set()
    # Brief A item 4 — groups carrying at least one INFERENCE finding, classified by
    # the shared evidence-kind contract. Derived verification for a pure-inference
    # group (inferred and not observed) is ``unverified`` even when no producer
    # supplied that literal field — a missing verification field is never proof of
    # observation, so a legacy fallback finding (``verification_status`` only) can no
    # longer masquerade as an observation that anchors a person and deletes the
    # corpus candidate.
    inferred_keys: set[str] = set()
    pattern_applied_conf: dict[str, float] = {}

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

            # Q3 / Part 0.2 / R5 (S3): accumulate this finding's source-types and
            # breakdown order-independently, keyed by the SAME group key
            # (``key`` == subaddress_key(email) here) used for ``grouped`` — NOT
            # the raw email. Keying by the raw email scattered a subaddress
            # variant's source-types under a different key from its group, so the
            # score depended on which variant happened to become canonical first.
            st_acc = source_type_acc.setdefault(key, set())
            st_acc.update(_extract_source_types({"metadata": meta}))
            _status = meta.get("verification_status")
            if _status == "verified":
                st_acc.add("permutation_verified")
            elif _status == "catchall":
                st_acc.add("permutation_catchall")
            _cb = meta.get("confidence_breakdown")
            if isinstance(_cb, dict):
                breakdown_acc.setdefault(key, []).append(_cb)

            # 0.16.0 Phase 4 — corpus company-pattern signals (order-independent,
            # keyed by the same group key as the source-types). A finding that
            # asserts a verification status contributes it; the pattern index is
            # the one inference source, so anything else is an observation that
            # wins the mailbox. The Wilson ``applied_confidence`` overrides the
            # fixed source weight for the score.
            _src_type = meta.get("source_type")
            _ver = meta.get("verification")
            if isinstance(_ver, str) and _ver.strip():
                verification_acc.setdefault(key, set()).add(_ver.strip().lower())
            if _src_type == "company_pattern_index":
                _applied = meta.get("applied_confidence")
                if isinstance(_applied, int | float) and not isinstance(_applied, bool):
                    pattern_applied_conf[key] = max(
                        pattern_applied_conf.get(key, 0.0), float(_applied)
                    )
            # Root B / Brief A — classify observed vs inferred by the SHARED
            # evidence-kind contract, NOT a source-name allowlist: an SMTP/provider
            # -verified permutation IS a confirmation (observed), a permutation or
            # corpus guess is inferred, and a plain sighting is observed. So a
            # permutation guess can no longer clear the verification gate and
            # auto-eligible a mailbox with no oracle.
            # Brief A item 1 — one ingestion-time evidence-kind normalization
            # (``observed`` / ``inferred`` / ``unknown``) over EVERY marker: the
            # scalar/collection source-types, the ``is_inference`` flag, the legacy
            # ``verification_status`` and SMTP/provider status, and the new
            # ``verification`` field. Missing verification is not observation; an
            # inferred source is not lifted to observed by an absent field.
            _kind = classify_evidence_kind(meta)
            if _kind == EVIDENCE_INFERRED:
                inferred_keys.add(key)
            elif _kind == EVIDENCE_OBSERVED:
                observed_keys.add(key)

            # M4 / R6 (S3): dedupe evidence by (module, email, person-claim
            # signature). The first finding for a given claim is the canonical
            # evidence entry, but a later finding from the SAME module carrying a
            # DIFFERENT person claim (e.g. a competing title) is RETAINED rather
            # than dropped by a first-wins rule — so the downstream 1E resolver
            # sees every competing claim and can resolve/flag the conflict.
            # Identical or person-claim-free repeats still collapse (their
            # distinguishing URLs are captured in aggregated_source_urls below),
            # so display isn't bloated.
            key = (module_name, email, _person_claim_signature(meta))
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
    for group_key, entry in grouped.items():
        # R5 (S3) — choose the canonical representative DETERMINISTICALLY so the
        # emitted address is invariant to finding arrival order (previously it was
        # whichever variant arrived first). Prefer the base mailbox form (the
        # group key, e.g. ``foo@gmail.com`` for a collapsed subaddress group),
        # else the lexicographically smallest observed variant. For a custom
        # domain nothing collapses, so ``forms`` is a singleton and this is a
        # no-op.
        forms = {entry.email, *entry.subaddress_variants}
        representative = group_key if group_key in forms else min(forms)
        entry.email = representative
        entry.subaddress_variants = sorted(forms - {representative})

        # Build the canonical, sorted, deduplicated found_by_modules list.
        unique_modules = sorted(entry.occurrence_count_per_module.keys())
        entry.found_by_modules = unique_modules

        # Q3 / Part 0.2 / R5 (S3): source_types come from the order-independent
        # accumulator (every finding's types unioned), keyed by the SAME group
        # key used at accumulation time (subaddress_key) — NOT the order-dependent
        # first-seen variant. Sorted for a deterministic breakdown.
        all_source_types = sorted(source_type_acc.get(group_key, set()))
        # Pick the module-provided breakdown deterministically: the one with the
        # highest base_score (tie-break by sorted source_types), not "first seen".
        candidate_breakdowns = breakdown_acc.get(group_key, [])
        best_breakdown: dict[str, Any] | None = None
        if candidate_breakdowns:
            best_breakdown = dict(
                max(
                    candidate_breakdowns,
                    key=lambda cb: (
                        float(cb.get("base_score") or 0.0),
                        str(sorted(cb.get("source_types") or [])),
                    ),
                )
            )

        # 0.16.0 Phase 4 — a corpus company-pattern email carries a calibrated
        # per-candidate ``applied_confidence`` (Wilson lower bound of the
        # domain's dominant-follow rate). Feed it through the ONE canonical
        # scorer as a source-weight override so the score tracks real support
        # instead of the fixed fallback weight. ``None`` for every other email →
        # the exact legacy score.
        source_confidence = (
            {"company_pattern_index": pattern_applied_conf[group_key]}
            if group_key in pattern_applied_conf
            else None
        )
        # 0.16.0 Phase 4/6 — verification precedence for a pure-inference group
        # (no observed finding shares the mailbox; an observation always wins and
        # leaves ``verification=None`` so a guess never downgrades a real hit):
        #   * a Phase-6 M365-oracle *confirmed* claim (``provider_verified``)
        #     propagates so the eligibility gate can clear it and the confirmed
        #     status reaches corpus_store / exports;
        #   * otherwise an ``"unverified"`` claim caps the lead at REVIEW.
        # Root B — computed BEFORE the label so the honesty cap can be applied in
        # the ONE canonical scorer for this group. A Phase-6 *confirmed* claim
        # always propagates (an oracle confirmation is an observation, so its group
        # is now in ``observed_keys``); the ``unverified`` cap is applied only to a
        # pure inference group (no observed finding shares the mailbox), so a real
        # observation still leaves ``verification=None`` and a guess never downgrades
        # a real hit.
        _claims = verification_acc.get(group_key, set())
        _confirmed = _claims & _CONFIRMED_PATTERN_VERIFICATIONS
        if _confirmed:
            entry.verification = sorted(_confirmed)[0]
        elif group_key not in observed_keys and group_key in inferred_keys:
            # Brief A item 4 — a pure-inference group (inferred, no observed/confirmed
            # finding sharing the mailbox) is ``unverified`` — DERIVED from the
            # evidence kind, not from a literal ``verification`` field a producer may
            # never have supplied. A legacy fallback finding (``verification_status``
            # only) is therefore correctly capped and cannot masquerade as observed.
            entry.verification = "unverified"
        # Brief A item 3/5 — the run-scoped resolver's retained oracle decision is
        # the authority and projects consistently at THIS boundary: a terminal
        # negative drops the mailbox (unless a real observation shares it), a
        # confirmation lifts it to ``provider_verified`` (an unverified duplicate can
        # never overwrite it), and an unresolved positive/negative conflict is held
        # ``unverified`` (never automatically eligible).
        if resolver is not None:
            _mv = resolver.mailbox_verification(entry.email)
            if _mv == DROP:
                continue  # retracted — excluded from every current projection
            if _mv == VERIFICATION_PROVIDER_VERIFIED:
                entry.verification = VERIFICATION_PROVIDER_VERIFIED
            elif _mv == "unverified":
                entry.verification = "unverified"
        # Root B — the honesty cap, in the canonical finalization: an unverified
        # inference (this group asserts ``unverified`` and has no observed/confirmed
        # finding) can never present as CONFIRMED, wherever the label is computed.
        cap_unverified = entry.verification == "unverified"
        score, label = compute_confidence(
            source_count=len(unique_modules),
            source_types=all_source_types,
            is_smtp_verified=entry.is_smtp_verified or entry.is_provider_verified,
            is_ca_attested=entry.is_ca_attested,
            is_pgp_or_ca=entry.is_pgp_or_ca,
            last_seen_timestamp=entry.last_seen_timestamp,
            source_confidence=source_confidence,
            cap_unverified_inference=cap_unverified,
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
            source_confidence=source_confidence,
            cap_unverified_inference=cap_unverified,
        ).breakdown
        if best_breakdown is not None:
            best_breakdown.update(current_breakdown)
            entry.confidence_breakdown = best_breakdown
        else:
            current_breakdown["synthesised"] = True
            entry.confidence_breakdown = current_breakdown
        final.append(entry)

    # Root A — retire company-pattern inferences superseded by a real observed
    # address for the same person (person-level dedup), before the additive signal
    # passes run over the surviving set.
    # Brief A item 2 — retire competing inferences for the same person via the run's
    # canonical resolver, so two producers converge on one deterministic selection.
    final = _apply_resolver_person_selection(final, resolver)
    # 0.17.0 — corpus (Pro) leads are NOT injected here. They are a serving-only
    # channel attached AFTER the native run by ``_attach_pro_enrichment`` on the live
    # ``run_domain_harvest`` path, so native aggregation, persistence, scoring, and
    # read-first never see corpus PII.
    _apply_passive_pattern_signals(final, module_results)
    _apply_signal_pool_correlation(final, signal_pool)
    _apply_identity_cluster_snapshot(final, identity_clusters)
    _infer_confirmed_pattern_from_emails(final, signal_pool)
    _apply_person_attribution(final)
    if shadow_profiles_out is not None:
        shadow_profiles_out.clear()
        shadow_profiles_out.extend(grouped_shadow[key] for key in sorted(grouped_shadow))
    return final


def _apply_person_attribution(emails: list[HarvestedEmail]) -> None:
    """Phase 3A — promote evidence into first-class person fields on each lead.

    Runs after aggregation, over the assembled evidence, resolving each person
    field through the 1E claim layer and honouring the run's product mode. Fully
    guarded and additive: it only *sets* typed fields (email-only leads are
    untouched, so yield never regresses), and every field it sets traces to an
    evidence entry (lead_person enforces the invariant).
    """
    try:
        from .lead_person import resolve_person_fields
        from .product_mode import get_active_mode

        mode = get_active_mode()
    except Exception:
        _LOG.exception("person attribution unavailable; leaving leads email-only")
        return

    for entry in emails:
        try:
            person = resolve_person_fields(entry, mode=mode)
        except Exception:
            _LOG.exception("person attribution failed for %s", entry.email)
            continue
        if person.is_empty():
            continue
        entry.full_name = person.full_name
        entry.first = person.first
        entry.last = person.last
        entry.job_title = person.job_title
        entry.seniority = person.seniority
        entry.department = person.department
        entry.linkedin_url = person.linkedin_url
        entry.phone = person.phone
        entry.location = person.location
        entry.person_field_provenance = person.field_provenance


def _email_verification_signals(entry: HarvestedEmail) -> dict[str, Any]:
    """Extract per-email SMTP/provider signals the grade fuser needs, from the
    already-assembled evidence + typed fields. No new probing."""
    smtp_status: str | None = None
    for ev in entry.evidence or []:
        meta = ev.get("metadata") if isinstance(ev, dict) else None
        if isinstance(meta, dict):
            s = meta.get("smtp_verification_status")
            if isinstance(s, str) and s:
                smtp_status = s
    smtp_exists: bool | None = None
    if entry.is_smtp_verified:
        smtp_exists = True
    elif smtp_status == "not_found":
        smtp_exists = False
    return {
        "smtp_status": smtp_status,
        "smtp_exists": smtp_exists,
        "provider_status": entry.provider_verification_status,
        "provider_name": entry.provider_verification_provider,
    }


def _history_recent_verified(history: list[dict[str, Any]] | None) -> bool:
    from datetime import datetime, timezone

    if not history:
        return False
    now = datetime.now(timezone.utc)
    for row in history:
        if str(row.get("status") or "").lower() != "verified":
            continue
        ts = row.get("verified_at")
        parsed: datetime | None = None
        if isinstance(ts, str) and ts.strip():
            try:
                parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                parsed = None
        if parsed is None:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        if (now - parsed).days <= 365:
            return True
    return False


def _record_source_accounting(
    domain: str, emails: list[HarvestedEmail], module_results: dict[str, Any]
) -> None:
    """Phase 4C — record per-source contribution accounting for this harvest.

    Reduces the graded leads + module telemetry to a plain shape and appends one
    accounting record (append-only JSONL). Fully guarded — accounting must never
    break a harvest."""
    from ..config import settings

    if not getattr(settings, "enable_source_accounting", True):
        return
    try:
        from .source_accounting import account_run, record_run_accounting

        email_rows = [
            {
                "email": e.email,
                "found_by_modules": list(getattr(e, "found_by_modules", None) or []),
                "confidence_label": getattr(e, "confidence_label", None),
                "deliverability_grade": getattr(e, "deliverability_grade", None),
            }
            for e in emails
        ]
        module_timings: dict[str, float] = {}
        module_status: dict[str, str] = {}
        for name, res in (module_results or {}).items():
            meta = getattr(res, "metadata", None) or {}
            duration = meta.get("duration_seconds") if isinstance(meta, dict) else None
            if isinstance(duration, int | float):
                module_timings[name] = float(duration)
            status = getattr(res, "status", None)
            module_status[name] = getattr(status, "value", None) or str(status or "")
        accounting = account_run(
            email_rows, module_timings=module_timings, module_status=module_status
        )
        record_run_accounting(domain, accounting)
    except Exception:
        _LOG.debug("source accounting unavailable for %s", domain, exc_info=True)


def _shadow_live_score(score: Any) -> tuple[float, dict[str, Any] | None]:
    """Phase 4D — resolve the LIVE deliverability score, running the calibrated
    model in shadow.

    Returns ``(live_score, shadow_info)``. The live score is the hand-tuned
    ``score.score`` unless the calibrated model has been promoted through the 4B
    gate; ``shadow_info`` (or ``None``) is monitoring metadata surfaced under
    ``deliverability.shadow``. Fully guarded — any failure yields the hand-tuned
    score with no shadow info, so live output is never at risk."""
    try:
        from .shadow_scorer import live_deliverability_score

        return live_deliverability_score(score)
    except Exception:
        return float(score.score), None


async def _apply_deliverability_grade(
    emails: list[HarvestedEmail], domain: str, *, catchall_detected: bool | None
) -> None:
    """Phase 3C/3D — score + grade every lead from non-SMTP signals.

    Resolves the domain-level signals once (MX / SPF / DMARC / provider), reads
    prior corpus verification history, then for each lead computes the 3C
    probability and fuses it with provider/SMTP/catch-all/disposable/role into
    the 3D grade. The provider-confirmation-on-catch-all bust is policy-gated
    (3E): trusted only in authorized modes. Every scored lead is logged for
    Phase-4 calibration. Fully guarded — a failure leaves leads ungraded rather
    than breaking the harvest, and yield is untouched (additive fields only)."""
    try:
        from . import corpus_store
        from .catchall_buster import trust_provider_confirmation_on_catchall
        from .deliverability_grade import grade_email
        from .deliverability_score import compute_deliverability_score, log_score_sample
        from .disposable_domains import is_disposable_domain, is_disposable_email
        from .mail_provider import detect_provider_from_mx
        from .mx_resolver import resolve_mx_typed
        from .product_mode import get_active_mode

        mode = get_active_mode()
        # R4 (S4): typed MX outcome so a DNS failure (unknown) is never conflated
        # with an authoritative "no mail" (which would grade every contact Invalid).
        mx_resolution = await resolve_mx_typed(domain)
        mx = mx_resolution.records
        mx_present = mx_resolution.usable
        mx_status = mx_resolution.status.value
        provider = detect_provider_from_mx(mx, target_domain=domain).provider
        dns = await resolve_domain_email_dns_signals(domain)
        spf_present = bool(dns.get("spf_present"))
        dmarc_strict = bool(dns.get("dmarc_strict"))
        domain_disposable = is_disposable_domain(domain)

        history_rows = await corpus_store.read_verification_history(domain=domain)
        history_by_email: dict[str, list[dict[str, Any]]] = {}
        for row in history_rows:
            history_by_email.setdefault(str(row.get("email") or "").lower(), []).append(row)
    except Exception:
        _LOG.exception("deliverability pass unavailable for %s; leads left ungraded", domain)
        return

    # Phase 4A/4D — accumulate a feature snapshot per lead for calibration capture,
    # written once after the loop (one txn beats one-per-email at harvest scale).
    capture_records: list[dict[str, Any]] = []
    for entry in emails:
        try:
            history = history_by_email.get(entry.email.lower(), [])
            is_disposable = domain_disposable or is_disposable_email(entry.email)
            score = compute_deliverability_score(
                mx_present=mx_present,
                spf_present=spf_present,
                dmarc_strict=dmarc_strict,
                provider=provider.value,
                is_role=entry.is_role,
                is_disposable=is_disposable,
                history=history,
            )
            sig = _email_verification_signals(entry)
            provider_status = sig["provider_status"]
            mailbox_confirmed = False
            # Phase 3E policy gate: a provider "verified" verdict may bust a
            # catch-all (→ Valid) only in an authorized mode with an oracle-capable
            # provider. In public-business-contact it must NOT, so we neutralise
            # the provider confirmation for the catch-all fuser there.
            if catchall_detected and str(provider_status or "").lower() == "verified":
                if trust_provider_confirmation_on_catchall(mode, provider):
                    mailbox_confirmed = True
                else:
                    provider_status = "inconclusive_public_mode"

            grade = grade_email(
                score=score,
                is_disposable=is_disposable,
                mx_present=mx_present,
                mx_status=mx_status,
                is_role=entry.is_role,
                catchall=catchall_detected,
                smtp_status=sig["smtp_status"],
                smtp_exists=sig["smtp_exists"],
                provider_status=provider_status,
                provider_name=sig["provider_name"],
                mailbox_confirmed=mailbox_confirmed,
                history_recent_verified=_history_recent_verified(history),
            )
            known = "verified" if _history_recent_verified(history) else None
            # Phase 4D — the calibrated model scores in SHADOW alongside the
            # hand-tuned scorer. Until the 4B promotion gate fires, the live score
            # is exactly the hand-tuned one (asserted in tests); the shadow delta
            # is logged for monitoring and surfaced under ``deliverability.shadow``.
            live_score, shadow_info = _shadow_live_score(score)
            entry.deliverability_score = round(live_score, 4)
            entry.deliverability_grade = grade.grade
            deliv: dict[str, Any] = {"score": score.as_dict(), "grade": grade.as_dict()}
            if shadow_info is not None:
                deliv["shadow"] = shadow_info
            entry.deliverability = deliv
            log_score_sample(entry.email, domain, score, known_outcome=known)
            capture_records.append(
                {
                    "subject": entry.email,
                    "subject_domain": domain,
                    "activity_id": domain,
                    "features": score.features,
                    "hand_score": round(score.score, 4),
                    "model_version": score.model_version,
                    "pipeline": "harvest",
                    "mode": mode.value,
                    "known_outcome": known,
                }
            )
        except Exception:
            _LOG.exception("deliverability grading failed for %s", entry.email)
            continue

    if capture_records:
        try:
            from .scoring_capture import capture_batch

            await capture_batch(capture_records)
        except Exception:
            _LOG.debug("scoring capture unavailable for %s", domain, exc_info=True)


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
        if "company_pattern_index" in _pattern_source_types(entry):
            continue  # Domain DNS cannot replace a calibrated mailbox inference score.
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
        entry.confidence_label = label_for_score(
            entry.confidence_score, cap_unverified_inference=entry.verification == "unverified"
        )


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
    mx_records: list[Any] | None = None,
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
        # Routed-vs-contacted telemetry (same pattern as the provider
        # dispatch): ``candidates_routed`` counts objects handed to the
        # verifier; ``gravatar_checked`` (Google route only) counts actual
        # Gravatar lookups performed, bounded by the probe cap.
        "candidates_routed": len(emails),
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
            smtp_fallback_enabled=False,
            gxlu_enabled=False,
            max_checks=settings.smtp_verify_max_probes,
        )
        result_objects = await verifier.verify_batch(
            emails,
            domain,
            session=None,
            max_checks=settings.smtp_verify_max_probes,
        )
        summary["gravatar_checked"] = sum(
            1 for r in result_objects if getattr(r, "gravatar_checked", False)
        )
    elif verifier_key == "smtp":
        resolved_mx_records = (
            list(mx_records) if mx_records is not None else await resolve_mx(domain)
        )
        if not resolved_mx_records:
            summary["status"] = "no_mx_records"
            return summary
        async with SMTPVerifier(
            mx_records=resolved_mx_records,
            sender_address=settings.smtp_sender_address,
            probe_delay_seconds=float(settings.smtp_probe_delay_seconds) or DEFAULT_PROBE_DELAY,
            connect_timeout_seconds=float(settings.smtp_connect_timeout_seconds),
            probe_domain_pattern=settings.smtp_probe_domain_pattern,
            probe_custom_domain=settings.smtp_probe_custom_domain,
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
            if isinstance(native, dict) and native.get("status") in {
                "invalid",
                "disposable",
                "mx_missing",
            }:
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
    m365_context: Any | None = None,
) -> dict[str, int | str | bool | None]:
    """Dispatch GOOGLE / M365 candidates to their provider-specific verifier.

    Historically the primary harvest path short-circuited here with
    ``skipped: provider_specific_verifier`` and never called either verifier,
    so ``is_provider_verified`` and the ``provider_verification_*`` fields
    never populated on this path (0.13.0-0.13.1 regression). Both verifiers
    exist and are dispatched here directly. M365 works immediately
    (GetCredentialType is not patched); for Google the verifier routes
    directly to the Gravatar signal — gxlu is patched server-side and SMTP
    probing against Google MX is forbidden (no usable RCPT responses).
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
            summary = {
                "candidates_routed": 0,
                "checked": 0,
                "status": "no_candidates",
                "provider": provider.value,
            }
            if provider is MailProvider.M365 and m365_context is not None:
                _apply_m365_passive_context(
                    m365_context,
                    findings_by_email,
                    summary,
                )
            return summary
        findings_by_email = fallback
        emails = list(findings_by_email)[: settings.smtp_verify_max_probes]
    # Routed vs contacted are ALWAYS separate fields: ``candidates_routed``
    # counts the candidate objects handed to the verifier; the mechanism
    # counter (``gravatar_checked`` for Google) counts actual lookups
    # performed and is bounded by the probe cap. ``candidates_routed`` is
    # fixed here at dispatch time — a re-probe artifact in the verifier's
    # result list must not inflate it. Any future verifier must follow the
    # same pattern: one routed field, one contacted field per mechanism.
    summary: dict[str, int | str | bool | None] = {
        "candidates_routed": len(emails),
        "candidates": len(emails),
        "provider": provider.value,
        "checked": 0,
    }
    probed_emails: set[str] = set()

    def record_probed_results(items: list[Any]) -> None:
        """Record candidates that reached a real provider probe."""
        for item in items:
            email = str(getattr(item, "email", "")).strip().lower()
            status = str(getattr(item, "status", "inconclusive"))
            # M365's control probe can return synthetic candidate results
            # when it detects a catch-all tenant; those candidates were not
            # actually contacted.
            error = str(getattr(item, "error", "") or "")
            if (
                email
                and status != "not_attempted"
                and error != "catchall_tenant"
            ):
                probed_emails.add(email)
    if provider is MailProvider.M365 and m365_context is not None:
        # The startup preflight already performed OpenID/GetUserRealm. Seed
        # the summary before active verification so ADFS/tenant routing uses
        # the cached context without issuing another passive probe.
        _apply_m365_passive_context(
            m365_context,
            findings_by_email,
            summary,
        )

    results: list[Any]
    # FIX 2: per-email promoted source override. Autodiscover-verified
    # addresses are promoted with ``autodiscover_m365``; everything else
    # keeps the branch default ``promoted_source``.
    source_by_email: dict[str, str] = {}
    if provider is MailProvider.GOOGLE:
        if not settings.google_workspace_verifier_enabled:
            summary["gravatar_checked"] = 0
            summary["skipped"] = "google_verifier_disabled"
            return summary
        summary["method"] = "google"
        # Google policy: cached provider detection says ``google`` → the
        # verifier MUST NOT attempt SMTP probing (Google MX returns no usable
        # RCPT responses; the v0.13.2 fallback burned the whole tail budget
        # for zero information) and the patched gxlu endpoint is skipped too.
        # Route directly to the Gravatar signal.
        verifier = GoogleWorkspaceVerifier(
            delay_seconds=1.0,
            timeout_seconds=settings.google_verifier_timeout,
            gravatar_enabled=settings.gravatar_verification_enabled,
            smtp_fallback_enabled=False,
            gxlu_enabled=False,
            max_checks=settings.smtp_verify_max_probes,
        )
        results = await verifier.verify_batch(
            emails,
            domain,
            session=None,
            max_checks=settings.smtp_verify_max_probes,
        )
        record_probed_results(results)
        promoted_source = "permutation_verified_google"
    else:  # MailProvider.M365
        summary["method"] = "m365"
        promoted_source = "permutation_verified_m365"
        results = []
        # Keep the provider tail bounded even when discovery produced a large
        # candidate set. The summary still reports every routed candidate,
        # while active M365 checks honor the harvest probe cap.
        provider_probe_cap = max(1, int(settings.smtp_verify_max_probes))
        if m365_context is not None:
            # Passive preflight already established the tenant strategy. Keep
            # the active provider tail bounded to one representative mailbox
            # so a slow Autodiscover endpoint cannot consume the harvest tail.
            provider_probe_cap = 1
        probe_emails = emails[:provider_probe_cap]
        # FIX 2: Autodiscover runs FIRST (faster, unthrottled). Any
        # address it confirms is promoted immediately and skipped by the
        # slower GetCredentialType probe; inconclusive addresses fall
        # through to GetCredentialType.
        confirmed: set[str] = set()
        if settings.enable_outlook_autodiscover:
            from ..modules.outlook_autodiscover import (
                AutodiscoverVerifier,
                reconcile_autodiscover,
            )

            autodiscover = AutodiscoverVerifier(
                timeout_seconds=settings.autodiscover_timeout_seconds,
                max_checks=settings.autodiscover_max_probes,
            )
            ad_results = await autodiscover.verify_batch(probe_emails)
            record_probed_results(ad_results)
            v1_status_by_email = {ad.email: ad.status for ad in ad_results}
            ad_by_email = {ad.email: ad for ad in ad_results}
            # Check 3: REST Autodiscover variant runs alongside the v1 probe.
            # Its verdict is reconciled with v1 — agreement raises confidence,
            # a REST-only "verified" still promotes, disagreement is dropped.
            rest_status_by_email: dict[str, str] = {}
            rest_by_email: dict[str, Any] = {}
            if settings.enable_autodiscover_rest:
                try:
                    # Keep the REST pass within the same active probe cap as
                    # the v1 pass.  ``emails`` may contain every routed
                    # candidate, while only ``probe_emails`` are permitted to
                    # consume provider-verification time.
                    rest_results = await autodiscover.rest_verify_batch(probe_emails)
                except Exception as exc:  # noqa: BLE001 - additive signal only
                    _LOG.debug("Autodiscover REST probe failed: %s", exc)
                    rest_results = []
                rest_status_by_email = {r.email: r.status for r in rest_results}
                rest_by_email = {r.email: r for r in rest_results}
                record_probed_results(rest_results)
                summary["autodiscover_rest_checked"] = len(rest_results)
            agreements = 0
            for email in probe_emails:
                v1_status = v1_status_by_email.get(email, "not_attempted")
                rest_status = rest_status_by_email.get(email, "not_attempted")
                if settings.enable_autodiscover_rest:
                    reconciliation = reconcile_autodiscover(v1_status, rest_status)
                    resolved = reconciliation.status
                    if reconciliation.agreement:
                        agreements += 1
                else:
                    resolved = v1_status
                if resolved != "verified":
                    continue
                confirmed.add(email)
                # Prefer the stronger v1 source type; fall back to the REST
                # source type when only REST confirmed the mailbox.
                if v1_status == "verified" and email in ad_by_email:
                    source_by_email[email] = "autodiscover_m365"
                    results.append(ad_by_email[email])
                elif email in rest_by_email:
                    source_by_email[email] = "autodiscover_rest"
                    results.append(rest_by_email[email])
            summary["autodiscover_checked"] = len(ad_results)
            summary["autodiscover_verified"] = len(confirmed)
            if settings.enable_autodiscover_rest:
                summary["autodiscover_rest_agreements"] = agreements
        remaining = [e for e in probe_emails if e not in confirmed]
        if remaining:
            verifier = M365Verifier(
                delay_seconds=settings.m365_verification_delay_seconds,
                timeout_seconds=settings.m365_verification_timeout_seconds,
                max_checks=settings.m365_verification_max_checks,
            )
            credential_results = await verifier.verify_batch(remaining)
            record_probed_results(credential_results)
            results.extend(credential_results)

    # ``gravatar_checked`` counts actual Gravatar lookups performed by the
    # Google verifier (bounded by the probe cap), never the candidates
    # merely routed to it. SMTP and gxlu are disabled on this route, so no
    # field here may imply SMTP contact occurred.
    if provider is MailProvider.GOOGLE:
        summary["gravatar_checked"] = sum(
            1 for r in results if getattr(r, "gravatar_checked", False)
        )
    google_unverifiable = {
        "inconclusive",
        "not_attempted",
        "rate_limited",
    }
    for result in results:
        status = str(getattr(result, "status", "inconclusive"))
        exists = getattr(result, "exists", None)
        if (
            provider is MailProvider.GOOGLE
            and status in google_unverifiable
            and not getattr(result, "gravatar_hit", False)
        ):
            # Honest non-verified stamp: Google offers no SMTP/gxlu existence
            # signal and Gravatar returned no hit for this address.
            status = "unverifiable_provider"
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
                    # FIX 2: Autodiscover-verified addresses carry
                    # ``autodiscover_m365``; the rest keep the branch default.
                    metadata["source_type"] = source_by_email.get(email, promoted_source)

    # M365 Passive Intel Phase 1 (Checks 5, 1, 4). Runs on the default M365
    # path, after the existence probes. Additive and fully exception-guarded:
    # it enriches the summary with tenant intelligence and an independent
    # OneDrive existence signal, and stashes the ADFS URL for Phase 3. A
    # failure here never affects the verification verdict.
    if (
        provider is MailProvider.M365
        and settings.enable_m365_passive_intel
        and m365_context is None
    ):
        try:
            # Hard overall bound: this is additive enrichment, never worth
            # stalling the harvest tail for. Individual checks also carry
            # their own httpx timeouts.
            await asyncio.wait_for(
                _attach_m365_passive_intel(domain, emails, findings_by_email, summary),
                timeout=settings.m365_passive_intel_budget_seconds,
            )
        except (TimeoutError, asyncio.TimeoutError):
            _LOG.debug("M365 passive intel exceeded its budget")
            summary["infrastructure"] = {"m365_tenant": {"error": "budget_exceeded"}}
        except Exception as exc:  # noqa: BLE001 - additive enrichment only
            _LOG.debug("M365 passive intel failed: %s", exc)
            summary["infrastructure"] = {"m365_tenant": {"error": str(exc)}}

    # M365 Active Intel Phase 3 (Checks 1/2/3). One single-probe account-state
    # check per candidate, selected by provider + ADFS availability. The module
    # enforces a hard one-probe-per-account guard, so there is no lockout risk.
    # Additive and fully exception-guarded: an ``exists`` verdict strengthens
    # the verification stamp and a ``not_found`` marks the address, but a
    # failure here never weakens an existing verdict.
    if provider is MailProvider.M365:
        try:
            await _attach_m365_active_intel(provider, emails, findings_by_email, summary)
        except Exception as exc:  # noqa: BLE001 - additive enrichment only
            _LOG.debug("M365 active intel failed: %s", exc)
    private_probes = summary.pop("_probed_emails", set())
    if isinstance(private_probes, set):
        probed_emails.update(private_probes)
    summary["checked"] = len(probed_emails)
    return summary


#: Maps a selected active check to the config flag that gates it.
_ACTIVE_PROBE_FLAG = {
    "aadsts": "enable_aadsts_probe",
    "activesync": "enable_activesync_probe",
    "wstrust": "enable_wstrust_probe",
}


def _promote_email_to_verified(
    email: str,
    source_type: str | None,
    confidence: float,
    findings_by_email: dict[str, list[dict[str, Any]]],
) -> None:
    """Stamp an active-probe ``exists`` verdict onto every finding for *email*."""
    for finding in findings_by_email.get(email, []):
        metadata = finding.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
            finding["metadata"] = metadata
        metadata["verification_status"] = "verified"
        metadata["is_provider_verified"] = True
        metadata["provider_verification_status"] = "verified"
        if source_type:
            metadata["source_type"] = source_type
            existing = metadata.get("source_types")
            source_types = list(existing) if isinstance(existing, list) else []
            if source_type not in source_types:
                source_types.append(source_type)
            metadata["source_types"] = source_types
        metadata["active_probe"] = {
            "status": "exists",
            "source_type": source_type,
            "confidence": confidence,
        }


def _mark_email_not_found(
    email: str,
    findings_by_email: dict[str, list[dict[str, Any]]],
) -> None:
    """Stamp an active-probe ``not_found`` verdict onto every finding for *email*."""
    for finding in findings_by_email.get(email, []):
        metadata = finding.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
            finding["metadata"] = metadata
        metadata["active_probe"] = {"status": "not_found"}
        # Only downgrade when nothing stronger has already verified the address.
        if metadata.get("verification_status") != "verified":
            metadata["verification_status"] = "not_found"


async def _attach_m365_active_intel(
    provider: Any,
    emails: list[str],
    findings_by_email: dict[str, list[dict[str, Any]]],
    summary: dict[str, Any],
) -> None:
    """Run one single-probe active check per candidate and fold in the verdict.

    The ADFS ``AuthURL`` (surfaced and stashed by Phase 1 GetUserRealm) is read
    back from the passive-intel infrastructure block on *summary*; a federated
    tenant routes to WS-Trust, a cloud/managed tenant to AADSTS, everything
    else to ActiveSync.
    """
    from backend.modules.m365_active_intel import run_active_probe, select_active_check

    infra = summary.get("infrastructure")
    adfs_url = (
        infra.get("m365_tenant", {}).get("adfs_url") if isinstance(infra, dict) else None
    )
    probed = 0
    probed_emails = summary.setdefault("_probed_emails", set())
    for email in emails[: settings.smtp_verify_max_probes]:
        check = select_active_check(provider=provider, adfs_url=adfs_url)
        flag = _ACTIVE_PROBE_FLAG.get(check)
        if flag is not None and not getattr(settings, flag, False):
            continue
        result = await run_active_probe(
            email=email,
            check=check,
            adfs_url=adfs_url,
            timeout=settings.active_probe_timeout,
        )
        probed += 1
        if isinstance(probed_emails, set):
            probed_emails.add(email.strip().lower())
        if result.status == "exists":
            _promote_email_to_verified(
                email, result.source_type, result.confidence, findings_by_email
            )
        elif result.status == "not_found":
            _mark_email_not_found(email, findings_by_email)
        # inconclusive: leave unchanged.
    summary["active_probe_checked"] = probed


async def _attach_m365_passive_intel(
    domain: str,
    emails: list[str],
    findings_by_email: dict[str, list[dict[str, Any]]],
    summary: dict[str, Any],
) -> None:
    """Run the M365 passive checks and fold results into *summary* + findings.

    * ``summary["infrastructure"]["m365_tenant"]`` gets the serialised tenant
      intelligence (Checks 5 + 1) and OneDrive probe outcomes (Check 4).
    * every on-domain finding's metadata carries ``m365_tenant`` and, when the
      tenant is federated, ``m365_adfs_url`` for Phase 3 (WS-Trust).
    * a ``provisioned`` OneDrive result contributes the ``onedrive_probe``
      existence signal to that email's ``source_types``.
    """
    from ..modules.m365_passive_intel import run_m365_passive_intel

    passive = await run_m365_passive_intel(
        domain,
        emails,
        openid_timeout_seconds=settings.m365_openid_timeout_seconds,
        realm_timeout_seconds=settings.m365_getuserrealm_timeout_seconds,
        onedrive_timeout_seconds=settings.m365_onedrive_timeout_seconds,
        max_onedrive_probes=settings.m365_onedrive_max_probes,
    )
    _apply_m365_passive_context(passive, findings_by_email, summary)


def _apply_m365_passive_context(
    m365_context: Any,
    findings_by_email: dict[str, list[dict[str, Any]]],
    summary: dict[str, Any],
) -> None:
    """Fold cached M365 passive context into verification output."""
    if hasattr(m365_context, "to_infrastructure_dict"):
        infra = dict(m365_context.to_infrastructure_dict())
    else:
        source = getattr(m365_context, "context", m365_context)
        infra = {
            "is_cloud": getattr(source, "is_cloud", None),
            "tenant_id": getattr(source, "tenant_id", None),
            "tenant_type": getattr(source, "tenant_type", None),
            "adfs_url": getattr(source, "adfs_url", None),
            "federation_brand": getattr(source, "federation_brand", None),
            "skipped_cloud_checks": bool(getattr(source, "skipped_cloud_checks", False)),
            "openid_status": getattr(source, "openid_status", None),
            "realm_status": getattr(source, "realm_status", None),
            "onedrive": [],
        }
    summary["infrastructure"] = {"m365_tenant": infra}

    adfs_url = infra.get("adfs_url")
    for findings in findings_by_email.values():
        for finding in findings:
            metadata = finding.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
                finding["metadata"] = metadata
            metadata["m365_tenant"] = infra
            if adfs_url:
                # Phase 3 (WS-Trust) reads this without re-probing.
                metadata["m365_adfs_url"] = adfs_url

    # Check 4: a provisioned OneDrive is an independent existence signal.
    for probe in getattr(m365_context, "onedrive", []) or []:
        if probe.status != "provisioned":
            continue
        for finding in findings_by_email.get(probe.email, []):
            metadata = finding.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
                finding["metadata"] = metadata
            existing = metadata.get("source_types")
            source_types = list(existing) if isinstance(existing, list) else []
            if "onedrive_probe" not in source_types:
                source_types.append("onedrive_probe")
            metadata["source_types"] = source_types
            metadata["onedrive_probe"] = {
                "status": probe.status,
                "http_status": probe.http_status,
            }


async def _attach_enterprise_net_intel(
    domain: str,
    module_results: dict[str, ModuleResult],
) -> dict[str, Any]:
    """Run the Phase 2 enterprise-net checks and fold them into the export.

    Domain-level and provider-agnostic: both checks run once per domain in
    the infrastructure-enrichment phase alongside Shodan / RIPE. The result
    is stashed on a synthetic ``enterprise_net_intel`` module result whose
    ``metadata.infrastructure`` is merged by the JSON exporter under
    ``infrastructure.active_directory`` and
    ``infrastructure.unified_communications``.
    """
    from ..modules.enterprise_net_intel import run_enterprise_net_intel

    result = await run_enterprise_net_intel(
        domain,
        enable_ntlm=settings.enable_ntlm_challenge,
        enable_lync=settings.enable_lync_discovery,
        budget_seconds=settings.enterprise_net_intel_budget_seconds,
    )
    infra = result.to_infrastructure_dict()
    module_results["enterprise_net_intel"] = ModuleResult(
        status=ModuleStatus.SUCCESS,
        findings=[],
        metadata={
            "infrastructure": {
                "active_directory": infra["active_directory"],
                "unified_communications": infra["unified_communications"],
            },
            "budget_exceeded": infra["budget_exceeded"],
        },
    )
    return infra


async def _attach_smtp_email_verification(
    domain: str,
    module_results: dict[str, ModuleResult],
    *,
    provider_detection: Any | None = None,
    mx_records: list[Any] | None = None,
    m365_context: Any | None = None,
) -> dict[str, int | str | bool | None]:
    """Probe every valid on-domain email through one guarded SMTP batch."""
    findings_by_email = _collect_smtp_findings(domain, module_results)

    resolved_mx_records = list(mx_records) if mx_records is not None else await resolve_mx(domain)
    if not resolved_mx_records:
        if not findings_by_email:
            summary = {"checked": 0, "status": "no_candidates", "is_catchall": None}
        else:
            summary = {"checked": 0, "status": "no_mx_records"}
        if m365_context is not None:
            _apply_m365_passive_context(m365_context, findings_by_email, summary)
        return summary

    if provider_detection is None:
        provider_detection = detect_provider_from_mx(resolved_mx_records, target_domain=domain)
    if provider_detection.provider in {MailProvider.GOOGLE, MailProvider.M365}:
        # Provider verifiers own their own candidate fallback (Fix 1), so we
        # dispatch even when the SMTP-eligible set is empty. ``module_results``
        # is threaded through so the verifier can collect MEDIUM+ on-domain
        # candidates when needed.
        return await _dispatch_provider_verifier(
            domain,
            findings_by_email,
            provider_detection,
            module_results,
            m365_context=m365_context,
        )

    # Non-provider (SMTP) path needs at least one SMTP-eligible candidate.
    if not findings_by_email:
        return {"checked": 0, "status": "no_candidates", "is_catchall": None}
    shared_hosting = provider_detection.provider is MailProvider.SHARED_HOSTING

    async with SMTPVerifier(
        mx_records=resolved_mx_records,
        sender_address=settings.smtp_sender_address,
        probe_delay_seconds=float(settings.smtp_probe_delay_seconds) or DEFAULT_PROBE_DELAY,
        connect_timeout_seconds=float(settings.smtp_connect_timeout_seconds),
        probe_domain_pattern=settings.smtp_probe_domain_pattern,
        probe_custom_domain=settings.smtp_probe_custom_domain,
    ) as verifier:
        batch = await verifier.verify_batch(
            domain,
            list(findings_by_email),
            max_probes=min(int(settings.smtp_max_probes_per_domain), MAX_PROBES_HARD_CAP),
        )

    smtp_probed_emails = {
        str(result.email).strip().lower()
        for result in batch.results
        if str(getattr(result, "verification_status", "not_attempted"))
        != "not_attempted"
    }
    counts: dict[str, int | str | bool | None] = {
        "checked": len(smtp_probed_emails),
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

    # Phase 4 — IMAP single-probe fallback. Additive and fully
    # exception-guarded: it only runs for self-hosted / shared-hosting /
    # unknown providers on addresses SMTP left inconclusive, and an ``exists``
    # verdict strengthens the stamp while a failure never weakens one.
    if settings.enable_imap_probe:
        try:
            await _attach_imap_existence(
                domain,
                provider_detection.provider,
                batch,
                findings_by_email,
                resolved_mx_records,
                counts,
            )
        except Exception as exc:  # noqa: BLE001 - additive enrichment only
            _LOG.debug("IMAP existence probe failed: %s", exc)

    if batch.error:
        counts["error"] = batch.error
    return counts


async def _attach_imap_existence(
    domain: str,
    provider: Any,
    batch: Any,
    findings_by_email: dict[str, list[dict[str, Any]]],
    mx_records: list[Any] | None,
    counts: dict[str, int | str | bool | None],
) -> None:
    """Run the Phase 4 IMAP fallback on SMTP-inconclusive candidates.

    Only self-hosted / shared-hosting / unknown providers are eligible, and
    only addresses that SMTP left unresolved are probed (one guarded probe
    each). ``exists`` promotes the address; ``not_found`` marks it.
    """
    from backend.modules.imap_existence import (
        run_imap_existence_check,
        should_run_imap_probe,
    )

    inconclusive_emails = [
        result.email.lower()
        for result in batch.results
        if should_run_imap_probe(provider, result.verification_status)
    ]
    probed_emails = {
        str(result.email).strip().lower()
        for result in batch.results
        if str(getattr(result, "verification_status", "not_attempted"))
        != "not_attempted"
    }
    if not inconclusive_emails:
        # imap_probe_count deprecated, use imap_checked. Remove in 0.15.0.
        counts["imap_probe_count"] = 0
        counts["imap_checked"] = 0
        counts["checked"] = len(probed_emails)
        return

    mx_hosts = [getattr(record, "host", None) for record in (mx_records or [])]
    mx_hosts = [host for host in mx_hosts if host]

    checked = exists = not_found = 0
    for email in inconclusive_emails:
        imap_result = await run_imap_existence_check(
            email=email,
            domain=domain,
            timeout=settings.imap_probe_timeout,
            port_check_timeout=settings.imap_port_check_timeout,
            mx_hosts=mx_hosts,
        )
        checked += 1
        probed_emails.add(email)
        if imap_result.status == "exists":
            exists += 1
            _promote_email_to_verified(
                email, "imap_probe", imap_result.confidence, findings_by_email
            )
        elif imap_result.status == "not_found":
            not_found += 1
            _mark_email_not_found(email, findings_by_email)
        # inconclusive: leave unchanged.

    # imap_probe_count deprecated, use imap_checked. Remove in 0.15.0.
    counts["imap_probe_count"] = checked
    counts["imap_checked"] = checked
    counts["checked"] = len(probed_emails)
    counts["imap_exists"] = exists
    counts["imap_not_found"] = not_found


async def _attach_m365_email_verification(
    domain: str,
    module_results: dict[str, ModuleResult],
    *,
    provider_detection: Any | None = None,
    mx_records: list[Any] | None = None,
    m365_context: Any | None = None,
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
    resolved_mx_records = list(mx_records) if mx_records is not None else await resolve_mx(domain)
    detection = provider_detection
    if detection is None:
        detection = detect_provider_from_mx(resolved_mx_records, target_domain=domain)
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
    if m365_context is not None:
        # The startup passive preflight already performed GetUserRealm. Keep
        # the legacy verification shape while consuming that cached result.
        infra = (
            dict(m365_context.to_infrastructure_dict())
            if hasattr(m365_context, "to_infrastructure_dict")
            else {
                "tenant_type": getattr(
                    getattr(m365_context, "context", m365_context),
                    "tenant_type",
                    None,
                ),
                "adfs_url": getattr(
                    getattr(m365_context, "context", m365_context),
                    "adfs_url",
                    None,
                ),
                "federation_brand": getattr(
                    getattr(m365_context, "context", m365_context),
                    "federation_brand",
                    None,
                ),
            }
        )
        summary["realm"] = {
            "status": infra.get("realm_status") or infra.get("tenant_type"),
            "namespace_type": infra.get("tenant_type") or "Unknown",
            "auth_url": infra.get("adfs_url"),
            "federation_brand_name": infra.get("federation_brand"),
            "cloud_instance_name": None,
            "http_status": None,
            "error": None,
        }
    else:
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
            if metadata.get("provider_verification_status") != "verified":
                metadata["provider_verification_status"] = verification.status
            if metadata.get("provider_verification_status") == "verified":
                metadata["provider_verification_provider"] = "m365"
                metadata["verification_status"] = "verified"
                if metadata.get("pattern_template"):
                    metadata["source_type"] = "permutation_verified_m365"
    return summary


async def _attach_yahoo_email_verification(
    domain: str,
    module_results: dict[str, ModuleResult],
    *,
    provider_detection: Any | None = None,
    mx_records: list[Any] | None = None,
) -> dict[str, Any]:
    findings_by_email: dict[str, list[dict[str, Any]]] = {}
    for result in module_results.values():
        for finding in result.findings or []:
            email = _extract_email(finding)
            if email and "@" in email and email.rsplit("@", 1)[-1].lower() == domain.lower():
                findings_by_email.setdefault(email.strip().lower(), []).append(finding)
    if not findings_by_email:
        return {"checked": 0, "status": "no_candidates"}
    resolved_mx_records = list(mx_records) if mx_records is not None else await resolve_mx(domain)
    detection = provider_detection
    if detection is None:
        detection = detect_provider_from_mx(resolved_mx_records, target_domain=domain)
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
                (
                    by_email.get(variant.lower())
                    for variant in entry.subaddress_variants
                    if by_email.get(variant.lower())
                ),
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
    source_telemetry: dict[str, dict[str, Any]] | None = None,
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
        kwargs["source_telemetry"] = source_telemetry
    accepted = _kwargs_accepted(module)
    filtered = kwargs if accepted is None else {k: v for k, v in kwargs.items() if k in accepted}

    # R15 (S5): validate the BINDING before invocation. A TypeError raised while
    # *calling* ``run`` is a signature mismatch (e.g. a bare test mock) — the only
    # case the positional fallback is meant to handle. A TypeError raised while
    # *executing* the coroutine is the module's own bug: it must be REPORTED, not
    # silently re-invoked with dropped options (which duplicated work and changed
    # behaviour). So we bind first, retry positionally only on a binding error,
    # then await exactly once.
    try:
        coroutine = module.run(domain, **filtered)
    except TypeError:
        coroutine = module.run(domain)

    try:
        result = await _run_with_soft_timeout(
            name, coroutine, budget, soft_timeout=soft_timeout
        )
        normalized = _normalize_module_result(name, result)
        _emit_finding_signals(signal_pool, name, normalized.findings, domain)
        return name, normalized
    except Exception as exc:  # noqa: BLE001 - once execution starts, report it
        _LOG.warning("domain_harvest: %s crashed: %s", name, exc)
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
    provider_detection: Any | None = None,
    mx_records: list[MXRecord] | None = None,
    pattern_run_state: Any | None = None,
) -> ModuleResult:
    """Run pattern_and_verify with explicit kwargs.

    MUST-FIX M3: enable_smtp is passed explicitly. Tests that pass a
    mock ``pattern_module`` whose ``run()`` accepts only ``(domain,
    employee_names)`` still work because we fall back gracefully when
    the signature doesn't include ``enable_smtp``.

    Root A — ``pattern_run_state`` (when the module accepts it) is the shared
    governed-pattern run-state, so the batch module and the reactive worker draw
    from one tombstone set and one oracle budget.
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
    if provider_detection is not None and (
        pattern_accepted is None or "provider_detection" in pattern_accepted
    ):
        pattern_kwargs["provider_detection"] = provider_detection
    if mx_records is not None and (
        pattern_accepted is None or "mx_records" in pattern_accepted
    ):
        pattern_kwargs["mx_records"] = mx_records
    if pattern_run_state is not None and (
        pattern_accepted is None or "pattern_run_state" in pattern_accepted
    ):
        pattern_kwargs["pattern_run_state"] = pattern_run_state
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
    log_callback: Any | None = None,
    display_subscriber: Any | None = None,
    force: bool = False,
    on_harvest_end: Any | None = None,
    mode: str | None = None,
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

    # R17 (S5): ``content_intelligence_callable`` is a legacy hook from the old
    # ``_orchestrate`` pipeline. The live adaptive path (``run_adaptive_harvest``)
    # does structured content extraction in ``harvest_runner._fetch_and_extract``
    # and does NOT consume this callable, so rather than silently accepting and
    # dropping it we reject it EXPLICITLY with a warning. It is retained in the
    # signature only for backward compatibility.
    if content_intelligence_callable is not None:
        _LOG.warning(
            "run_domain_harvest: content_intelligence_callable is deprecated and "
            "IGNORED by the adaptive pipeline; structured content extraction now "
            "runs in harvest_runner._fetch_and_extract."
        )

    # Injected modules are the isolated/mock path used by the orchestrator
    # tests and embedders. Disable network-heavy identity enrichment there by
    # default; production calls without injected modules keep it enabled.
    if enable_email_identity_enrichment is None:
        enable_email_identity_enrichment = not bool(module_overrides)

    # R1 (S1) — resolve the run's scope/policy ONCE, before any cache reuse.
    # The product mode plus the coverage-affecting flags together define a scope
    # signature; read-first may only reuse a snapshot collected under the EXACT
    # same signature (see corpus_store.scope_signature). Resolving the mode here,
    # rather than after the read, is precisely what makes read-first scope- and
    # mode-aware: a public-mode request must never reuse security-mode evidence,
    # and a narrower crawl must never satisfy a broader request.
    from .product_mode import active_mailbox_probing_allowed, normalize_mode

    resolved_mode = normalize_mode(mode if mode is not None else settings.product_mode)
    # Set the run's active mode BEFORE the read-first so BOTH the cache-hit early
    # return and the fresh path attach Pro under the correct mode (the cache-hit
    # return happens before the lawful-gate's own set_active_mode below).
    from .product_mode import set_active_mode as _set_active_mode

    _set_active_mode(resolved_mode)
    # A mode that forbids active mailbox probing (the FTC line for
    # public-business-contact) collects a strictly narrower crawl — SMTP
    # verification is disabled. Apply it here so the signature reflects the
    # actual collection scope and the two never alias.
    if not active_mailbox_probing_allowed(resolved_mode):
        enable_smtp = False

    from .corpus_store import SCOPE_SIGNATURE_KEY, read_fresh_crawl, scope_signature

    # Root D — the company-pattern index (and its oracle) are coverage-affecting, so
    # the cache signature includes their flags, the oracle cap, and — when the
    # feature is on — the shipped index version, so flag-off and an index refresh
    # both invalidate a cached crawl.
    _cpi_enabled = bool(getattr(settings, "enable_company_pattern_index", True))
    _cpi_version = None
    if _cpi_enabled:
        from .company_pattern_index import index_version as _cpi_index_version

        _cpi_version = _cpi_index_version()
    request_scope = scope_signature(
        mode=resolved_mode.value,
        with_subdomains=with_subdomains,
        subdomain_deep=subdomain_deep,
        subdomain_calibrate=subdomain_calibrate,
        enable_smtp=enable_smtp,
        enable_m365=enable_m365,
        enable_yahoo=enable_yahoo,
        aggressive=aggressive,
        dork_lite_mode=dork_lite_mode,
        enable_email_identity_enrichment=enable_email_identity_enrichment,
        enable_company_pattern_index=_cpi_enabled,
        enable_pattern_oracle_verify=bool(
            getattr(settings, "enable_pattern_oracle_verify", True)
        ),
        pattern_oracle_max_verifications=int(
            getattr(settings, "pattern_oracle_max_verifications_per_run", 50)
        ),
        company_pattern_index_version=_cpi_version,
    )

    # Phase 1D — read-first from the unified corpus DB (replaces the per-domain
    # JSON cache as the source of truth). Explicit module injection is the
    # deterministic test/embedder seam and must not consume or overwrite a real
    # corpus, so it disables the corpus entirely.
    corpus_enabled = bool(getattr(settings, "harvest_cache_enabled", True)) and not bool(
        module_overrides
    )
    if corpus_enabled and not force:
        cached = await read_fresh_crawl(domain, request_scope)
        if cached is not None:
            # Pro enrichment is live per-query, so it must apply on cache hits too —
            # the cached snapshot is native-only (corpus PII is never persisted).
            return await _attach_pro_enrichment(cached, domain, resolved_mode)

    # An injected-module run is a deterministic test/embedder seam. Do not
    # launch real network modules that were not explicitly supplied; that
    # makes a one-finding fixture acquire unrelated live results and defeats
    # the purpose of module injection.
    effective_skip_modules = {
        str(name).strip()
        for name in (skip_modules or ())
        if str(name).strip()
    }
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

    # Phase 2C — the lawful-public-data gate for harvest: translate the product
    # mode into skip_modules by unioning in every module the mode disallows. In
    # security-investigation the blocked set is empty (zero regression). Resolved
    # once here and reused for the run-manifest stamp below.
    from .product_mode import blocked_modules, set_active_mode

    # ``resolved_mode`` was resolved once above (before the read-first) so the
    # cache reuse could be mode-aware; reuse it here for the lawful gate.
    set_active_mode(resolved_mode)
    effective_skip_modules |= {str(name) for name in blocked_modules(resolved_mode)}
    # Phase 4C — skip sources auto-demoted for no longer earning their runtime.
    # Reversible and env-overridable (MAILACCESS_FORCE_SOURCE_<NAME>); the demoted
    # set is empty until a source earns demotion, so live behavior is unchanged.
    if getattr(settings, "enable_source_accounting", True):
        try:
            from .source_accounting import demoted_source_names

            effective_skip_modules |= demoted_source_names()
        except Exception:
            _LOG.debug("source demotion consult unavailable", exc_info=True)
    # (Active-mailbox-probing gate — ``enable_smtp`` disable for modes that
    #  forbid it — was applied above, before the read-first, so the scope
    #  signature reflects it.)

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
        log_callback=log_callback,
        display_subscriber=display_subscriber,
        on_harvest_end=on_harvest_end,
    )
    # Phase 2B — stamp the run's product mode onto the result (the harvest run
    # manifest) before write-back, so the corpus snapshot and the ledger record
    # the collection mode. ``resolved_mode`` was computed above with the gate.
    if isinstance(getattr(result, "metadata", None), dict):
        result.metadata["mode"] = resolved_mode.value
        # R1 — persist the full scope signature so a later read-first can require
        # an exact scope match (mode + coverage envelope) before reusing this
        # snapshot, rather than serving it to any request for the same domain.
        result.metadata[SCOPE_SIGNATURE_KEY] = request_scope
    if corpus_enabled:
        from .corpus_store import sanitize_for_persistence, write_back

        # A1 — persist a NATIVE-ONLY view: strip net-new corpus rows and any
        # ``mailaccess_pro`` evidence before write-back, so paid/personal corpus
        # data never enters a reusable snapshot or the generic projection (it is
        # per-query, live-only). ``result`` itself remains available to the live
        # renderer; export helpers use the native-only channel. write_back
        # re-sanitises defensively.
        await write_back(domain, sanitize_for_persistence(result))
    # Attach the serving-only Pro corpus channel AFTER mode-stamping + native-only
    # persistence, so the RETURNED result is fully finalized (mode + corpus_leads) for
    # the live renderer. Canonical exports remain native-only. ``on_harvest_end``
    # remains only the cancellation/partial fallback.
    return await _attach_pro_enrichment(result, domain, resolved_mode)


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
        results = await hunter_search(domain, api_key, limit=100)
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
                    "department": r.department,
                    "linkedin": r.linkedin,
                    "organization": r.organization,
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


def _smtp_availability_metadata(
    pattern_meta: dict[str, Any], budget: Any | None
) -> dict[str, Any]:
    """RC7 (Output-Trust): honest SMTP-availability signal on the harvest result.

    Distinguishes "SMTP disabled" from "SMTP enabled but no probe reached a mail
    server" (e.g. outbound port 25 blocked). In the latter case the grades are
    non-SMTP estimates, so the output must say so explicitly rather than implying
    verification happened.
    """
    meta: dict[str, Any] = {"budget": budget.stats} if budget is not None else {}
    smtp_enabled = bool(pattern_meta.get("smtp_verification_enabled", False))
    smtp_probes = int(pattern_meta.get("smtp_probes_used", 0) or 0)
    meta["smtp_verification_enabled"] = smtp_enabled
    meta["smtp_probes_used"] = smtp_probes
    if smtp_enabled and smtp_probes == 0:
        meta["smtp_unavailable"] = True
        meta["smtp_status_note"] = (
            "SMTP verification unavailable - no probe reached a mail server "
            "(e.g. outbound port 25 blocked); deliverability grades are non-SMTP "
            "estimates."
        )
    return meta
