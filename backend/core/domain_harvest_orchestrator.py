"""Domain Email Harvest orchestrator — Phase C3 (final) + W5.

Ties the eight domain-mode modules together:

    commoncrawl_email     ─┐
    code_and_cert_email  ─┤
    email_search_dork    ─┤ Phase 1+2 (run concurrently)
    employee_name_discovery ─┤
    npm_email            ─┤
    pypi_email           ─┤
    pgp_domain_email     ─┘
                            │
                            │ (feeds pattern_and_verify)
                            ▼
                  pattern_and_verify   ─ Phase 3 (depends on C1)

The W5 additions (npm_email, pypi_email, pgp_domain_email) slot into
Phase 1 — they share the same "fast / cheap / parallel" budget as
commoncrawl_email and code_and_cert_email and run via
``asyncio.as_completed`` exactly like the existing Phase 1 modules.

This module does NOT modify any of the eight sub-modules.  It only
wires them together, performs cross-module deduplication and
confidence aggregation, and returns a single
:class:`DomainHarvestResult` for the report layer to consume.

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
from datetime import datetime, timezone
from typing import Any

from ..modules.base import ModuleResult, ModuleStatus
from ..modules.code_and_cert_email import CodeAndCertEmailModule
from ..modules.commoncrawl_email import CommonCrawlEmailModule
from ..modules.domain_intel import _FREE_PROVIDERS
from ..modules.email_search_dork import EmailSearchDorkModule
from ..modules.employee_name_discovery import EmployeeNameDiscoveryModule
from ..modules.npm_email import NpmEmailModule
from ..modules.pattern_and_verify import (
    EmployeeNameResult,
    PatternAndVerifyModule,
    employee_name_result_from_dict,
)
from ..modules.pgp_domain_email import PgpDomainEmailModule
from ..modules.pypi_email import PyPIEmailModule
from .email_confidence import compute_confidence
from .email_extraction import subaddress_key

_LOG = logging.getLogger(__name__)

#: Module names we orchestrate.  Used as keys in
#: ``DomainHarvestResult.module_results``.
MODULE_COMMONCRAWL = "commoncrawl_email"
MODULE_CODE_CERT = "code_and_cert_email"
MODULE_EMAIL_DORK = "email_search_dork"
MODULE_EMPLOYEE_NAMES = "employee_name_discovery"
MODULE_NPM_EMAIL = "npm_email"
MODULE_PYPI_EMAIL = "pypi_email"
MODULE_PGP_DOMAIN_EMAIL = "pgp_domain_email"
MODULE_PATTERN_VERIFY = "pattern_and_verify"

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
    is_smtp_verified: bool = False
    is_ca_attested: bool = False
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
    high_confidence_count: int
    medium_confidence_count: int
    low_confidence_count: int
    role_account_count: int
    personal_email_count: int
    errors: list[str] = field(default_factory=list)
    smtp_verification_used: bool = False
    catchall_detected: bool | None = None
    confirmed_pattern: str | None = None
    employee_names_processed: int = 0


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
    return out


def _aggregate(
    harvest_domain: str,
    module_results: dict[str, ModuleResult],
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
    # subaddress_key(email) → HarvestedEmail — the dedup key.
    # Email variants seen for the same key are recorded in
    # entry.subaddress_variants for analyst visibility.
    first_meta_seen: dict[tuple[str, str], dict[str, Any]] = {}
    seen_urls: dict[str, set[str]] = {}

    for module_name, result in module_results.items():
        for finding in result.findings or []:
            email = _extract_email(finding)
            if not email:
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
            if is_role:
                entry.is_role = True
                if role_match:
                    entry.role_match_type = role_match

            # OR-semantics on_domain: any source flagging on_domain wins.
            if _extract_on_domain(finding, email, harvest_domain):
                entry.on_domain = True

            # Oldest timestamp across evidence.
            ts = _extract_timestamp(finding)
            if ts:
                if (
                    entry.first_seen_timestamp is None
                    or ts < entry.first_seen_timestamp  # noqa: SIM118
                ):
                    entry.first_seen_timestamp = ts

            # SMTP-verified flag (only set by pattern_and_verify).
            if meta.get("verification_status") == "verified":
                entry.is_smtp_verified = True
            if meta.get("source_type") in ("ca_attested",):
                entry.is_ca_attested = True

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
            is_smtp_verified=entry.is_smtp_verified,
            is_ca_attested=entry.is_ca_attested,
            oldest_timestamp=entry.first_seen_timestamp,
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
        if best_breakdown is not None:
            entry.confidence_breakdown = best_breakdown
        else:
            entry.confidence_breakdown = {
                "source_types": sorted({st for st in all_source_types if st}),
                "multiplier_label": (
                    "smtp_verified"
                    if entry.is_smtp_verified
                    else (
                        "ca_attested"
                        if entry.is_ca_attested
                        else (
                            "multi_source"
                            if len({st for st in all_source_types if st}) >= 2
                            else "single_source"
                        )
                    )
                ),
                "synthesised": True,
            }
        final.append(entry)

    return final


# ---------------------------------------------------------------------
# Sort: HIGH → MEDIUM → LOW; within tier, on-domain personal → role →
# off-domain personal.
# ---------------------------------------------------------------------
_LABEL_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


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
        return asyncio.run(module.run(domain))
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
    dork_lite_mode: bool | None = None,
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
    """
    kwargs: dict[str, Any] = {}
    if name == MODULE_COMMONCRAWL and cc_max_records is not None:
        kwargs["max_records"] = cc_max_records
    elif name == MODULE_EMAIL_DORK and dork_lite_mode is not None:
        kwargs["lite_mode"] = dork_lite_mode
    accepted = _kwargs_accepted(module)
    try:
        if accepted is None:
            # Generic callable — pass everything.
            return name, await module.run(domain, **kwargs)
        filtered = {k: v for k, v in kwargs.items() if k in accepted}
        return name, await module.run(domain, **filtered)
    except TypeError:
        # Mocks that don't accept our kwargs — fall back to positional.
        return name, await module.run(domain)
    except Exception as exc:  # noqa: BLE001
        _LOG.warning(
            "domain_harvest: %s crashed: %s", name, exc
        )
        return name, ModuleResult(
            status=ModuleStatus.FAILED,
            errors=[f"{name}: {exc}"],
        )


async def _run_pattern(
    pattern: Any,
    domain: str,
    *,
    employee_names: list[EmployeeNameResult],
    enable_smtp: bool | None = None,
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
    return await pattern.run(domain, **pattern_kwargs)


# ---------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------
async def run_domain_harvest(
    domain: str,
    enable_smtp: bool = False,
    *,
    cc_module: Any | None = None,
    code_cert_module: Any | None = None,
    dork_module: Any | None = None,
    employee_module: Any | None = None,
    npm_module: Any | None = None,
    pypi_module: Any | None = None,
    pgp_module: Any | None = None,
    pattern_module: Any | None = None,
    dork_lite_mode: bool | None = None,
    cc_max_records: int | None = None,
    on_module_complete: Any | None = None,
) -> DomainHarvestResult:
    """Run all eight harvest modules in the recommended sequence.

    Parameters
    ----------
    domain:
        A corporate domain (e.g. ``"example.com"``).  Free-provider
        domains (gmail.com, yahoo.com, …) are rejected.
    enable_smtp:
        Explicit opt-in for SMTP RCPT TO verification.  Default ``False``.
        MUST-FIX M3: this is the *only* path that can enable SMTP.
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
        record limit. Threaded down to ``commoncrawl_email.run``.
        The orchestrator does NOT mutate ``settings.cc_max_records``.
    *_module:
        Injection points used by tests — pass a mock module instance
        to bypass real network calls.  Each mock must expose
        ``.name`` and an async ``run(domain)`` method. Mock modules
        MUST accept the ``enable_smtp`` / ``lite_mode`` /
        ``max_records`` keyword arguments and either consume them or
        accept them silently.
    npm_module / pypi_module / pgp_module:
        W5 injection points for the three new structured-source
        modules. Same contract as the other *_module kwargs.
    """
    cleaned = _validate_domain(domain)

    # ------------------------------------------------------------------
    # 1. Instantiate the eight modules (or accept injected mocks).
    # ------------------------------------------------------------------
    cc = cc_module if cc_module is not None else CommonCrawlEmailModule()
    cc_cert = code_cert_module if code_cert_module is not None else CodeAndCertEmailModule()
    dork = dork_module if dork_module is not None else EmailSearchDorkModule()
    emp = employee_module if employee_module is not None else EmployeeNameDiscoveryModule()
    npm = npm_module if npm_module is not None else NpmEmailModule()
    pypi = pypi_module if pypi_module is not None else PyPIEmailModule()
    pgp = pgp_module if pgp_module is not None else PgpDomainEmailModule()
    pattern = pattern_module if pattern_module is not None else PatternAndVerifyModule()

    return await _orchestrate(
        cleaned,
        cc,
        cc_cert,
        dork,
        emp,
        npm,
        pypi,
        pgp,
        pattern,
        enable_smtp=enable_smtp,
        dork_lite_mode=dork_lite_mode,
        cc_max_records=cc_max_records,
        on_module_complete=on_module_complete,
    )


async def _orchestrate(
    domain: str,
    cc: Any,
    cc_cert: Any,
    dork: Any,
    emp: Any,
    npm: Any,
    pypi: Any,
    pgp: Any,
    pattern: Any,
    *,
    enable_smtp: bool = False,
    dork_lite_mode: bool | None = None,
    cc_max_records: int | None = None,
    on_module_complete: Any | None = None,
) -> DomainHarvestResult:
    """Inner orchestration — runs the 8 modules in sequence.

    Sequence:
        Phase 1+2 — all seven data modules run concurrently
                    (``asyncio.as_completed`` so each callback fires
                    as soon as its module finishes).  W5 adds three
                    modules to this phase (npm_email, pypi_email,
                    pgp_domain_email) — they hit different upstreams
                    and have no shared rate-limited budget, so
                    running them in parallel is safe and gives the
                    user faster results.
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
    """

    def _emit(name: str, mr: ModuleResult) -> None:
        if on_module_complete is None:
            return
        status_value = (
            mr.status.value if hasattr(mr.status, "value") else str(mr.status)
        )
        try:
            on_module_complete(name, status_value)
        except Exception:  # noqa: BLE001
            # Callback must never break the harvest.
            _LOG.debug(
                "domain_harvest: on_module_complete(%s, %s) raised — ignored",
                name,
                status_value,
            )

    started = datetime.now(timezone.utc)
    started_iso = started.isoformat().replace("+00:00", "Z")

    # ------------------------------------------------------------------
    # Phase 1+2 — concurrent run of all seven data modules
    # MUST-FIX S5: ``asyncio.as_completed`` so we can fire the
    # ``on_module_complete`` callback as each module finishes, instead
    # of waiting for ``gather`` to return all seven at once.
    # W5: the three new structured-source modules (npm, pypi, pgp)
    # slot in here and run alongside commoncrawl_email and
    # code_and_cert_email — same parallel budget, no sequencing.
    # ------------------------------------------------------------------
    phase12_coroutines = [
        _safe_phase12_run(
            MODULE_COMMONCRAWL, cc, domain, cc_max_records=cc_max_records
        ),
        _safe_phase12_run(MODULE_CODE_CERT, cc_cert, domain),
        _safe_phase12_run(
            MODULE_EMAIL_DORK, dork, domain, dork_lite_mode=dork_lite_mode
        ),
        _safe_phase12_run(MODULE_EMPLOYEE_NAMES, emp, domain),
        _safe_phase12_run(MODULE_NPM_EMAIL, npm, domain),
        _safe_phase12_run(MODULE_PYPI_EMAIL, pypi, domain),
        _safe_phase12_run(MODULE_PGP_DOMAIN_EMAIL, pgp, domain),
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
        phase12_results[name] = result
        # MUST-FIX S5: fire callback as soon as this module is final.
        _emit(name, result)

    # ------------------------------------------------------------------
    # Phase 3 — pattern_and_verify (depends on employee_name_discovery)
    # MUST-FIX M3: enable_smtp is threaded via the explicit kwarg.
    # MUST-FIX S5: emit callback when pattern_and_verify completes too.
    # ------------------------------------------------------------------
    employee_findings = phase12_results.get(
        MODULE_EMPLOYEE_NAMES, ModuleResult(status=ModuleStatus.SKIPPED)
    ).findings or []
    employee_names = _employee_names_from_findings(employee_findings)

    try:
        pattern_result = await _run_pattern(
            pattern, domain, employee_names=employee_names, enable_smtp=enable_smtp
        )
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("domain_harvest: pattern_and_verify crashed: %s", exc)
        pattern_result = ModuleResult(
            status=ModuleStatus.FAILED,
            errors=[f"{MODULE_PATTERN_VERIFY}: {exc}"],
        )
    _emit(MODULE_PATTERN_VERIFY, pattern_result)

    # ------------------------------------------------------------------
    # Combine all results
    # ------------------------------------------------------------------
    module_results: dict[str, ModuleResult] = {
        **phase12_results,
        MODULE_PATTERN_VERIFY: pattern_result,
    }

    unique_emails = _aggregate(domain, module_results)
    unique_emails.sort(key=_sort_key)

    completed = datetime.now(timezone.utc)
    completed_iso = completed.isoformat().replace("+00:00", "Z")
    duration = (completed - started).total_seconds()

    high = sum(1 for e in unique_emails if e.confidence_label == "HIGH")
    medium = sum(1 for e in unique_emails if e.confidence_label == "MEDIUM")
    low = sum(1 for e in unique_emails if e.confidence_label == "LOW")
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

    return DomainHarvestResult(
        domain=domain,
        started_at=started_iso,
        completed_at=completed_iso,
        duration_seconds=round(duration, 3),
        module_results=module_results,
        unique_emails=unique_emails,
        total_unique_emails=len(unique_emails),
        high_confidence_count=high,
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
    )