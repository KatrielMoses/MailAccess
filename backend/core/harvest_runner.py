"""Adaptive two-track runner for domain harvest mode."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..config import Settings, settings
from ..modules.base import ModuleResult, ModuleStatus
from ..modules.code_and_cert_email import CodeAndCertEmailModule
from ..modules.commoncrawl_email import CommonCrawlEmailModule
from ..modules.email_search_dork import EmailSearchDorkModule
from ..modules.employee_name_discovery import EmployeeNameDiscoveryModule
from ..modules.github_commits import GitHubDomainCommitsModule
from ..modules.github_org_members import GitHubOrgMembersModule
from ..modules.hackertarget_hosts import HackerTargetHostsModule
from ..modules.m365_passive_intel import run_m365_passive_intel
from ..modules.npm_email import NpmEmailModule
from ..modules.package_ecosystems import PackageEcosystemsModule
from ..modules.pattern_and_verify import PatternAndVerifyModule
from ..modules.pgp_domain_email import PgpDomainEmailModule
from ..modules.public_forge import PublicForgeModule
from ..modules.public_surface_sweeper import PublicSurfaceSweeper
from ..modules.pypi_email import PyPIEmailModule
from ..modules.ripe_stat_asn import RIPEStatASNModule
from ..modules.shodan_internetdb import ShodanInternetDBModule
from ..modules.subdomain_intel import SubdomainIntelModule
from ..modules.syndication_feed_sweeper import SyndicationFeedSweeper
from ..modules.wayback import WaybackDomainHarvestModule
from ..modules.wordpress_rest import WordPressRestModule
from .concurrent_fetch_cache import CachedFetch, ConcurrentFetchCache
from .context_router import IndustryVocabularyRouter
from .email_extraction import extract_emails
from .mail_provider import detect_provider_from_mx
from .mx_resolver import resolve_mx
from .name_quality import _NAVIGATION_TOKENS, COMMON_ENGLISH_NOUNS, _clean_token
from .pagination_handler import PaginationHandler
from .signal_pool import AsyncSignalPool
from .stealth_client import StealthSession, resolve_timing_profile
from .structured_data_extractor import extract_people
from .time_budget import TimeBudget, budget_for_profile
from .work_scheduler import (
    PRIORITY_ARCHIVE,
    PRIORITY_GUARANTEED,
    PRIORITY_HIGH_SIGNAL,
    PRIORITY_REGISTRY,
    PRIORITY_ROUTER_EXPANSION,
    PRIORITY_UNIVERSAL,
    TRACK_GUARANTEED,
    TRACK_OPPORTUNISTIC,
    WorkItem,
    WorkResult,
    WorkScheduler,
)

logger = logging.getLogger(__name__)


def _m365_context_infrastructure(context: Any | None) -> dict[str, Any] | None:
    """Serialize startup M365 context for exports and timeout summaries."""
    if context is None:
        return None
    if hasattr(context, "to_infrastructure_dict"):
        return dict(context.to_infrastructure_dict())
    source = getattr(context, "context", context)
    return {
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

SUBDOMAIN_INTEL_HARD_CAP_FRACTION = 0.30
# Default only; each harvest computes and stores its profile-specific value on
# WorkerContext at the start of run_adaptive_harvest().
SUBDOMAIN_INTEL_HARD_CAP = budget_for_profile("t2") * SUBDOMAIN_INTEL_HARD_CAP_FRACTION


def subdomain_intel_hard_cap_for_profile(profile: str) -> float:
    """Return the hard wall for subdomain_intel for a timing profile."""
    return budget_for_profile(profile) * SUBDOMAIN_INTEL_HARD_CAP_FRACTION

MODULE_COMMONCRAWL = "commoncrawl_email"
MODULE_WAYBACK_DOMAIN = "wayback_domain_harvest"
MODULE_CODE_CERT = "code_and_cert_email"
MODULE_EMAIL_DORK = "email_search_dork"
MODULE_NPM_EMAIL = "npm_email"
MODULE_PYPI_EMAIL = "pypi_email"
MODULE_PUBLIC_SURFACE = "public_surface_sweeper"
MODULE_PUBLIC_FORGE = "public_forge"
MODULE_PACKAGE_ECOSYSTEMS = "package_ecosystems"
MODULE_SUBDOMAIN_INTEL = "subdomain_intel"
# Compatibility alias for callers that used the pre-intelligence module name.
MODULE_SUBDOMAIN_SURFACE = MODULE_SUBDOMAIN_INTEL
MODULE_PGP_DOMAIN_EMAIL = "pgp_domain_email"
MODULE_GITHUB_ORG_MEMBERS = "github_org_members"
MODULE_GITHUB_DOMAIN_COMMITS = "github_domain_commits"
MODULE_EMPLOYEE_NAMES = "employee_name_discovery"
MODULE_PATTERN_VERIFY = "pattern_and_verify"
MODULE_PERSON_EMAIL_PIVOT = "person_email_pivot"
MODULE_PERSONA_EMAIL_PIVOT = "persona_email_pivot"
MODULE_EMAIL_IDENTITY_ENRICHMENT = "email_identity_enrichment"
MODULE_WORDPRESS_REST = "wordpress_rest"
MODULE_SYNDICATION_FEED_SWEEPER = "syndication_feed_sweeper"
MODULE_HUNTER = "hunter"
MODULE_HACKERTARGET = "hackertarget_hosts"
MODULE_RIPE_STAT_ASN = "ripe_stat_asn"
MODULE_SHODAN_INTERNETDB = "shodan_internetdb"
# The provider/validation tail is deliberately short: discovery owns the
# profile budget, while the tail must not turn a 600-second harvest into a
# second long-running phase.  Enrichment is dropped when this window closes.
VERIFICATION_TAIL_SECONDS = 15.0

# Seed dispatch priorities for the discovery scheduler. Insertion order is the
# submission order; the scheduler pulls lower numbers first. Kept at module
# scope so priority regressions can be asserted directly in tests.
_MODULE_PRIORITIES: dict[str, int] = {
    MODULE_COMMONCRAWL: PRIORITY_ARCHIVE,
    MODULE_WAYBACK_DOMAIN: PRIORITY_ARCHIVE,
    MODULE_CODE_CERT: PRIORITY_HIGH_SIGNAL,
    # 0.13.3: promoted from PRIORITY_SEARCH (40) so on-domain email snippet
    # discovery competes alongside code_and_cert_email and the GitHub modules
    # instead of after the archive crawlers and 11 other higher-priority seeds.
    MODULE_EMAIL_DORK: PRIORITY_HIGH_SIGNAL,
    MODULE_NPM_EMAIL: PRIORITY_REGISTRY,
    MODULE_PYPI_EMAIL: PRIORITY_REGISTRY,
    MODULE_PUBLIC_SURFACE: PRIORITY_GUARANTEED,
    MODULE_SUBDOMAIN_SURFACE: PRIORITY_HIGH_SIGNAL,
    MODULE_HACKERTARGET: PRIORITY_HIGH_SIGNAL,
    MODULE_PUBLIC_FORGE: PRIORITY_HIGH_SIGNAL,
    MODULE_PACKAGE_ECOSYSTEMS: PRIORITY_REGISTRY,
    MODULE_PGP_DOMAIN_EMAIL: PRIORITY_REGISTRY,
    MODULE_GITHUB_ORG_MEMBERS: PRIORITY_HIGH_SIGNAL,
    MODULE_GITHUB_DOMAIN_COMMITS: PRIORITY_HIGH_SIGNAL,
    MODULE_EMPLOYEE_NAMES: PRIORITY_UNIVERSAL,
    MODULE_WORDPRESS_REST: PRIORITY_HIGH_SIGNAL,
    MODULE_SYNDICATION_FEED_SWEEPER: PRIORITY_UNIVERSAL,
    # Phase 3: pattern_and_verify is always seeded so it appears in
    # module_results even when no employee names are found (the mock-based
    # test path). In real harvests it also fires via signal emission.
    MODULE_PATTERN_VERIFY: PRIORITY_UNIVERSAL,
}
_PERSON_PIVOT_MODULES = frozenset(
    {
        MODULE_EMPLOYEE_NAMES,
        MODULE_PATTERN_VERIFY,
        MODULE_PERSON_EMAIL_PIVOT,
        MODULE_EMAIL_IDENTITY_ENRICHMENT,
        "name_to_github_profile",
    }
)
_ACCUMULATING_MODULES = frozenset(
    {
        MODULE_PERSON_EMAIL_PIVOT,
        MODULE_PERSONA_EMAIL_PIVOT,
        MODULE_EMAIL_IDENTITY_ENRICHMENT,
        "name_to_github_profile",
    }
)
_YIELD_PREDICTION_CANDIDATES = frozenset(
    {
        MODULE_NPM_EMAIL,
        MODULE_PYPI_EMAIL,
        MODULE_PACKAGE_ECOSYSTEMS,
        MODULE_PGP_DOMAIN_EMAIL,
        MODULE_SYNDICATION_FEED_SWEEPER,
    }
)
_PAGE_HEADING_TOKENS = frozenset(
    {
        "blue",
        "convention",
        "curiosity",
        "going",
        "impact",
        "industry",
        "key",
        "over",
        "team",
    }
)


@dataclass(frozen=True)
class WorkerContext:
    domain: str
    scheduler: WorkScheduler
    signal_pool: AsyncSignalPool
    page_cache: CachedFetch
    budget: TimeBudget
    stealth_session: StealthSession
    settings: Settings
    enable_smtp: bool = False
    enable_m365: bool = False
    enable_yahoo: bool = False
    use_proxies: bool = False
    aggressive: bool = False
    module_results: dict[str, ModuleResult] | None = None
    on_module_complete: Any | None = None
    module_overrides: dict[str, Any] | None = None
    dork_lite_mode: bool | None = None
    cc_max_records: int | None = None
    cc_max_collections: int | None = None
    proxy_fallback_ok: bool = False
    skip_modules: frozenset[str] = frozenset()
    with_subdomains: bool = False
    subdomain_deep: bool = False
    subdomain_calibrate: bool = False
    context_vertical: tuple[str, ...] = ()
    progress_callback: Any | None = None
    log_callback: Any | None = None
    provider_detection: Any | None = None
    provider_mx_records: list[Any] | None = None
    provider_detection_ready: asyncio.Event | None = None
    subdomain_source_telemetry: dict[str, dict[str, Any]] | None = None
    subdomain_intel_hard_cap: float = SUBDOMAIN_INTEL_HARD_CAP
    m365_context: Any | None = None


def _is_obvious_non_person_name(name: str) -> bool:
    """Reject noun/navigation-only labels before invoking NER."""
    tokens = [_clean_token(token) for token in str(name).split()]
    return bool(tokens) and all(
        token in COMMON_ENGLISH_NOUNS
        or token in _NAVIGATION_TOKENS
        or token in _PAGE_HEADING_TOKENS
        for token in tokens
    )


def _derive_harvest_status(ctx: WorkerContext, *, timed_out: bool) -> str:
    """Classify termination from scheduler state, not wall-clock duration."""
    if not timed_out:
        return "terminated_early"
    return "completed_saturated" if ctx.budget.track1_closed else "partial_timeout"


def _hydrate_subdomain_source_telemetry(ctx: WorkerContext) -> None:
    """Copy incremental source telemetry into the exportable module result."""
    telemetry = ctx.subdomain_source_telemetry or {}
    result = (ctx.module_results or {}).get(MODULE_SUBDOMAIN_INTEL)
    if result is None or not telemetry:
        return
    metadata = dict(result.metadata or {})
    metadata["sources"] = {
        source: dict(details) for source, details in telemetry.items()
    }
    healthy = sum(
        1 for details in telemetry.values() if details.get("status") == "ok"
    )
    metadata.setdefault(
        "passive_quorum",
        {
            "required": 2,
            "returned_results": healthy,
            "met": healthy >= 2,
            "warning": None if healthy >= 2 else "passive enumeration quorum failed",
        },
    )
    result.metadata = metadata


def _termination_snapshot(
    ctx: WorkerContext,
    cleaned: str,
    *,
    started: datetime,
    started_iso: str,
    timeout_seconds: float,
    timed_out: bool,
) -> Any:
    """Snapshot the harvest context exactly as it exists at termination.

    Used by the harvest-termination handler when the run cannot return a
    result object (stage exception, soft kill). Stages write to the shared
    context; this function only READS it. It never raises — the export must
    depend on nothing except the harvest ending.
    """
    from .domain_harvest_orchestrator import (
        DomainHarvestResult,
        _aggregate,
        _sort_key,
    )

    module_results = ctx.module_results or {}
    _hydrate_subdomain_source_telemetry(ctx)
    try:
        unique_emails = _aggregate(
            cleaned,
            module_results,
            signal_pool=None,
            identity_clusters=[],
            shadow_profiles_out=[],
        )
        unique_emails.sort(key=_sort_key)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Termination snapshot aggregation degraded: %s", exc)
        unique_emails = []
    completed = datetime.now(timezone.utc)
    errors = [
        f"[{name}] {err}"
        for name, result in module_results.items()
        for err in (result.errors or [])
    ]
    errors.append("harvest terminated before completion; context snapshot exported")
    metadata = {
        "harvest_status": _derive_harvest_status(ctx, timed_out=timed_out),
        "terminated_early": True,
        "timed_out": timed_out,
        "timeout_at_seconds": timeout_seconds,
        "budget": ctx.budget.stats,
    }
    return DomainHarvestResult(
        domain=cleaned,
        started_at=started_iso,
        completed_at=completed.isoformat().replace("+00:00", "Z"),
        duration_seconds=round((completed - started).total_seconds(), 3),
        module_results=module_results,
        unique_emails=unique_emails,
        total_unique_emails=len(unique_emails),
        high_confidence_count=sum(
            1 for e in unique_emails
            if e.confidence_label in {"CONFIRMED", "HIGH"} and not e.is_role
        ),
        likely_confidence_count=sum(
            1 for e in unique_emails
            if e.confidence_label == "LIKELY" and not e.is_role
        ),
        medium_confidence_count=sum(
            1 for e in unique_emails
            if e.confidence_label in {"LIKELY", "MEDIUM"} and not e.is_role
        ),
        low_confidence_count=sum(
            1 for e in unique_emails
            if e.confidence_label == "LOW" and not e.is_role
        ),
        role_account_count=sum(1 for e in unique_emails if e.is_role),
        personal_email_count=sum(1 for e in unique_emails if not e.is_role),
        errors=errors,
        smtp_verification_used=bool(ctx.enable_smtp and not ctx.module_overrides),
        employee_names_processed=len(
            (
                module_results.get(MODULE_EMPLOYEE_NAMES).findings
                if module_results.get(MODULE_EMPLOYEE_NAMES) is not None
                else []
            )
            or []
        ),
        fetch_cache_stats=None,
        metadata=metadata,
        shadow_profiles=[],
    )


async def run_adaptive_harvest(
    domain: str,
    timeout_seconds: float,
    enable_smtp: bool | None = None,
    enable_m365: bool = False,
    enable_yahoo: bool = False,
    use_proxies: bool = False,
    aggressive: bool = False,
    timing_profile: str = "t2",
    *,
    module_overrides: dict[str, Any] | None = None,
    on_module_complete: Any | None = None,
    dork_lite_mode: bool | None = None,
    cc_max_records: int | None = None,
    cc_max_collections: int | None = None,
    proxy_fallback_ok: bool = False,
    enable_email_identity_enrichment: bool = True,
    skip_modules: tuple[str, ...] | list[str] | None = None,
    with_subdomains: bool = False,
    subdomain_deep: bool = False,
    subdomain_calibrate: bool = False,
    progress_callback: Any | None = None,
    log_callback: Any | None = None,
    display_subscriber: Any | None = None,
    on_harvest_end: Any | None = None,
) -> Any:
    from .domain_harvest_orchestrator import (
        DomainHarvestResult,
        _aggregate,
        _sort_key,
        _validate_domain,
    )

    cleaned = _validate_domain(domain)
    if enable_smtp is None:
        enable_smtp = bool(getattr(settings, "smtp_verify_default", True))

    # M365 GetUserRealm/OpenID are domain-level preflight checks. Run them
    # before creating the scheduler and budget so they cannot compete with
    # discovery work or consume the harvest clock.
    m365_context: Any | None = None
    if getattr(settings, "enable_m365_passive_intel", False):
        try:
            m365_context = await asyncio.wait_for(
                run_m365_passive_intel(cleaned, []),
                timeout=20.0,
            )
        except asyncio.TimeoutError:
            logger.info("M365 preflight timed out — skipping")
            m365_context = None
        except Exception as exc:  # noqa: BLE001 - optional preflight
            logger.info("M365 preflight failed: %s", exc)
            m365_context = None

    started = datetime.now(timezone.utc)
    started_iso = started.isoformat().replace("+00:00", "Z")
    scheduler = WorkScheduler()
    signal_pool = AsyncSignalPool(export_threshold=0.0)
    signal_pool.set_scheduler(scheduler)
    budget = TimeBudget(timeout_seconds)
    # subdomain_intel gets a profile-derived hard wall that is independent of
    # the generic module soft timeout.  Store the computed value on the run
    # context so concurrent harvests do not share mutable timing state.
    subdomain_intel_hard_cap = subdomain_intel_hard_cap_for_profile(timing_profile)
    session = StealthSession(timing_profile=resolve_timing_profile(timing_profile))
    cache = ConcurrentFetchCache(session)
    page_cache = CachedFetch(cache)
    module_results: dict[str, ModuleResult] = {}
    normalized_skip_modules = {
        str(name).strip() for name in (skip_modules or ()) if str(name).strip()
    }
    if "subdomain_surface" in normalized_skip_modules:
        normalized_skip_modules.add(MODULE_SUBDOMAIN_INTEL)
    ctx = WorkerContext(
        domain=cleaned,
        scheduler=scheduler,
        signal_pool=signal_pool,
        page_cache=page_cache,
        budget=budget,
        stealth_session=session,
        settings=settings,
        enable_smtp=enable_smtp,
        enable_m365=enable_m365,
        enable_yahoo=enable_yahoo,
        use_proxies=use_proxies,
        aggressive=aggressive,
        module_results=module_results,
        on_module_complete=on_module_complete,
        module_overrides=module_overrides or {},
        dork_lite_mode=dork_lite_mode,
        cc_max_records=cc_max_records,
        cc_max_collections=cc_max_collections,
        proxy_fallback_ok=proxy_fallback_ok,
        skip_modules=frozenset(normalized_skip_modules),
        with_subdomains=with_subdomains,
        subdomain_deep=subdomain_deep,
        subdomain_calibrate=subdomain_calibrate,
        progress_callback=progress_callback,
        log_callback=log_callback,
        provider_detection_ready=asyncio.Event(),
        subdomain_source_telemetry={},
        subdomain_intel_hard_cap=subdomain_intel_hard_cap,
        m365_context=m365_context,
    )
    if ctx.module_overrides:
        ctx.provider_detection_ready.set()

    # Preserve a truthful per-run module inventory even when the budget is
    # exhausted before a queued item starts. A missing key used to look like
    # a configuration bug and made benchmark comparisons non-deterministic.
    seeded_module_names = (
        MODULE_COMMONCRAWL, MODULE_WAYBACK_DOMAIN, MODULE_CODE_CERT,
        MODULE_EMAIL_DORK, MODULE_NPM_EMAIL, MODULE_PYPI_EMAIL,
        MODULE_PUBLIC_SURFACE, MODULE_PUBLIC_FORGE, MODULE_PACKAGE_ECOSYSTEMS,
        MODULE_SUBDOMAIN_SURFACE,
        MODULE_PGP_DOMAIN_EMAIL, MODULE_GITHUB_ORG_MEMBERS,
        MODULE_GITHUB_DOMAIN_COMMITS, MODULE_EMPLOYEE_NAMES,
        MODULE_WORDPRESS_REST, MODULE_SYNDICATION_FEED_SWEEPER,
        MODULE_PATTERN_VERIFY, "security_txt",
        MODULE_HACKERTARGET,
        MODULE_RIPE_STAT_ASN,
    )
    for module_name in seeded_module_names:
        skip_reason = (
            "runtime_policy" if module_name in ctx.skip_modules else "not_started"
        )
        seed_metadata: dict[str, Any] = {"domain": cleaned, "skip_reason": skip_reason}
        if module_name == MODULE_SUBDOMAIN_INTEL:
            from ..modules.subdomain_intel import DISCOVERY_SOURCE_NAMES

            seeded_sources = {
                source: {"status": "not_run", "count": 0}
                for source in DISCOVERY_SOURCE_NAMES
            }
            seed_metadata["sources"] = seeded_sources
            seed_metadata["passive_phase"] = {
                "status": "not_started",
                "termination": "not_started",
            }
            if ctx.subdomain_source_telemetry is not None:
                ctx.subdomain_source_telemetry.update(
                    {source: dict(details) for source, details in seeded_sources.items()}
                )
        module_results[module_name] = ModuleResult(
            status=ModuleStatus.SKIPPED,
            metadata=seed_metadata,
        )

    await _seed_scheduler(ctx)

    from ..modules.name_to_github_profile import _github_name_pivot
    
    signal_pool.register_name_subscriber(_on_name_found)
    signal_pool.register_name_subscriber(_github_name_pivot)
    persona_seen: set[str] = set()
    signal_pool.register_name_subscriber(
        lambda name, source, metadata: _on_name_found_persona_pivot(
            name, source, metadata, persona_seen
        )
    )
    if display_subscriber is not None:
        signal_pool.register_display_subscriber(display_subscriber)
    if enable_email_identity_enrichment:
        enrichment_seen: set[str] = set()
        signal_pool.register_email_subscriber(
            lambda email, source, metadata: _on_email_found(
                email, source, metadata, enrichment_seen
            )
        )

    timed_out = False

    async def _run_smtp_validation_tail() -> dict[str, Any]:
        """Run the guarded SMTP/provider tail for complete or partial runs."""
        from .domain_harvest_orchestrator import (
            _attach_smtp_email_verification,
            _collect_smtp_findings,
        )

        if not ctx.enable_smtp or ctx.module_overrides:
            return {"candidates_routed": 0, "skipped": "smtp_disabled"}

        smtp_candidate_count = len(_collect_smtp_findings(cleaned, module_results))
        if ctx.log_callback is not None:
            ctx.log_callback("SMTP", "provider verification started")
        try:
            attach_kwargs: dict[str, Any] = {}
            try:
                accepted = inspect.signature(_attach_smtp_email_verification).parameters
            except (TypeError, ValueError):
                accepted = {}
            if "provider_detection" in accepted:
                attach_kwargs["provider_detection"] = ctx.provider_detection
            if "mx_records" in accepted:
                attach_kwargs["mx_records"] = ctx.provider_mx_records
            if "m365_context" in accepted:
                attach_kwargs["m365_context"] = ctx.m365_context
            summary = await asyncio.wait_for(
                _attach_smtp_email_verification(
                    cleaned,
                    module_results,
                    **attach_kwargs,
                ),
                timeout=45.0,
            )
            if ctx.log_callback is not None:
                provider = summary.get("provider") or "smtp"
                routed = int(summary.get("candidates_routed") or 0)
                ctx.log_callback(
                    "SMTP",
                    f"provider verification completed: {provider}, {routed} candidates routed",
                )
            return summary
        except (TimeoutError, asyncio.TimeoutError):
            for result in module_results.values():
                for finding in result.findings or []:
                    metadata = finding.setdefault("metadata", {})
                    if not isinstance(metadata, dict):
                        metadata = {}
                        finding["metadata"] = metadata
                    native_meta = metadata.get("native_email_validation") or {}
                    if not isinstance(native_meta, dict):
                        native_meta = {}
                    if native_meta.get("status") not in {
                        "invalid",
                        "disposable",
                        "mx_missing",
                    }:
                        metadata["smtp_verification_status"] = "verification_timeout"
            timeout_summary = {
                "candidates_routed": smtp_candidate_count,
                "status": "verification_timeout",
            }
            if ctx.provider_detection is not None:
                timeout_summary["provider"] = ctx.provider_detection.provider.value
            m365_infra = _m365_context_infrastructure(ctx.m365_context)
            if m365_infra is not None:
                timeout_summary["infrastructure"] = {"m365_tenant": m365_infra}
            if ctx.log_callback is not None:
                ctx.log_callback(
                    "SMTP",
                    f"provider verification timed out for {smtp_candidate_count} candidates",
                )
            return timeout_summary
        except Exception as exc:  # noqa: BLE001
            logger.warning("SMTP/provider verification failed: %s", exc)
            failure_summary = {
                "candidates_routed": smtp_candidate_count,
                "status": "verification_failed",
                "error": str(exc),
            }
            if ctx.provider_detection is not None:
                failure_summary["provider"] = ctx.provider_detection.provider.value
            m365_infra = _m365_context_infrastructure(ctx.m365_context)
            if m365_infra is not None:
                failure_summary["infrastructure"] = {"m365_tenant": m365_infra}
            if ctx.log_callback is not None:
                ctx.log_callback("SMTP", "provider verification failed")
            return failure_summary

    async def _run_verification_tail(
        identity_clusters: list[Any],
    ) -> dict[str, Any]:
        """Run verification, low-email validation, then droppable enrichment.

        This deadline starts when the tail starts, independently of the
        discovery budget. It is shared by normal and partial harvests.
        """
        from .domain_harvest_orchestrator import (
            _aggregate,
            _apply_low_email_validation_results,
            _attach_m365_email_verification,
            _attach_yahoo_email_verification,
            _run_low_email_validation,
            _select_low_email_validation_candidates,
            _select_verifier_for_provider,
        )

        tail: dict[str, Any] = {}
        tail_started = asyncio.get_running_loop().time()

        async def _body() -> None:
            if not ctx.enable_smtp or ctx.module_overrides:
                tail["smtp_email_verification"] = {
                    "candidates_routed": 0,
                    "skipped": "smtp_disabled",
                }
                tail["m365_email_verification"] = {"checked": 0, "status": "m365_disabled"}
                tail["yahoo_email_verification"] = {"checked": 0, "status": "yahoo_disabled"}
                tail["low_email_validation"] = {"checked": 0, "status": "disabled"}
            else:
                await _ensure_provider_detection(ctx)
                detection = ctx.provider_detection
                mx_records = ctx.provider_mx_records
                tail["smtp_email_verification"] = await _run_smtp_validation_tail()
                if ctx.enable_m365 and not ctx.module_overrides:
                    tail["m365_email_verification"] = await _attach_m365_email_verification(
                        cleaned,
                        module_results,
                        provider_detection=detection,
                        mx_records=mx_records,
                        m365_context=ctx.m365_context,
                    )
                else:
                    tail["m365_email_verification"] = {"checked": 0, "status": "m365_disabled"}
                if ctx.enable_yahoo and not ctx.module_overrides:
                    tail["yahoo_email_verification"] = await _attach_yahoo_email_verification(
                        cleaned,
                        module_results,
                        provider_detection=detection,
                        mx_records=mx_records,
                    )
                else:
                    tail["yahoo_email_verification"] = {"checked": 0, "status": "yahoo_disabled"}

                provisional = _aggregate(
                    cleaned,
                    module_results,
                    signal_pool=signal_pool,
                    identity_clusters=identity_clusters,
                    shadow_profiles_out=[],
                )
                if not settings.enable_low_email_validation:
                    tail["low_email_validation"] = {"checked": 0, "status": "disabled"}
                else:
                    candidates = _select_low_email_validation_candidates(
                        cleaned, module_results, provisional
                    )
                    if not candidates:
                        tail["low_email_validation"] = {"checked": 0, "status": "no_candidates"}
                    else:
                        method = _select_verifier_for_provider(
                            detection.provider if detection is not None else None
                        )
                        low = await _run_low_email_validation(
                            cleaned,
                            candidates,
                            method,
                            provider=detection.provider if detection is not None else None,
                            mx_records=mx_records,
                        )
                        low["provider"] = (
                            detection.provider.value if detection is not None else "unknown"
                        )
                        low["promotion"] = _apply_low_email_validation_results(
                            candidates, low, provisional
                        )
                        tail["low_email_validation"] = low

                if settings.xposed_or_not_enabled and not ctx.module_overrides:
                    from .domain_harvest_orchestrator import _run_xposed_or_not_validation

                    primary_checked = int(tail["low_email_validation"].get("checked") or 0)
                    shared_cap = min(25, int(settings.harvest_validation_max_per_run))
                    xposed_budget = max(0, shared_cap - primary_checked)
                    xposed_candidates = _select_low_email_validation_candidates(
                        cleaned,
                        module_results,
                        provisional,
                        max_candidates=xposed_budget,
                    )
                    try:
                        xposed_summary, format_metadata = await _run_xposed_or_not_validation(
                            cleaned,
                            xposed_candidates,
                            max_checks=xposed_budget,
                            delay_seconds=1.0,
                        )
                        tail["low_email_validation"]["xposed_or_not"] = xposed_summary
                        module_results["xposed_or_not"] = ModuleResult(
                            status=ModuleStatus.SUCCESS,
                            findings=[],
                            metadata=format_metadata,
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("XposedOrNot passive validation skipped: %s", exc)
                        tail["low_email_validation"]["xposed_or_not"] = {
                            "checked": 0,
                            "status": "skipped",
                        }

            # Enrichment is intentionally last and can be dropped when the
            # dedicated tail budget is consumed by verification.
            for module_name, module_budget in (
                (MODULE_RIPE_STAT_ASN, 60.0),
                (MODULE_SHODAN_INTERNETDB, 45.0),
            ):
                if module_name in ctx.skip_modules:
                    continue
                remaining = VERIFICATION_TAIL_SECONDS - (
                    asyncio.get_running_loop().time() - tail_started
                )
                if remaining <= 1.0:
                    tail.setdefault("enrichment", {})[module_name] = "dropped_tail_budget"
                    continue
                try:
                    await _run_module(module_name, ctx, soft_timeout=min(module_budget, remaining))
                    tail.setdefault("enrichment", {})[module_name] = "completed"
                except Exception as exc:  # noqa: BLE001
                    tail.setdefault("enrichment", {})[module_name] = f"failed: {exc}"

            # Enterprise Network Intelligence (Phase 2). Domain-level and
            # provider-agnostic; runs once per domain in the same enrichment
            # phase as Shodan / RIPE. Fully budget-capped inside the module and
            # exception-guarded here so a failure never disturbs the tail.
            if (
                not ctx.module_overrides
                and (settings.enable_ntlm_challenge or settings.enable_lync_discovery)
                and "enterprise_net_intel" not in ctx.skip_modules
            ):
                from .domain_harvest_orchestrator import _attach_enterprise_net_intel

                remaining = VERIFICATION_TAIL_SECONDS - (
                    asyncio.get_running_loop().time() - tail_started
                )
                if remaining <= 1.0:
                    tail.setdefault("enrichment", {})[
                        "enterprise_net_intel"
                    ] = "dropped_tail_budget"
                else:
                    try:
                        await _attach_enterprise_net_intel(cleaned, module_results)
                        tail.setdefault("enrichment", {})[
                            "enterprise_net_intel"
                        ] = "completed"
                    except Exception as exc:  # noqa: BLE001
                        tail.setdefault("enrichment", {})[
                            "enterprise_net_intel"
                        ] = f"failed: {exc}"

        try:
            await asyncio.wait_for(_body(), timeout=VERIFICATION_TAIL_SECONDS)
            tail["tail_status"] = "completed"
        except (TimeoutError, asyncio.TimeoutError):
            tail["tail_status"] = "partial_timeout"
            tail.setdefault("low_email_validation", {"checked": 0, "status": "tail_timeout"})
            logger.warning(
                "Verification tail exhausted its dedicated %.0fs budget",
                VERIFICATION_TAIL_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001
            tail["tail_status"] = "failed"
            tail["error"] = str(exc)
            logger.warning("Verification tail failed: %s", exc)
        return tail

    # ``final_result`` is set by the completion branches below. The
    # harvest-termination handler (the ``finally`` at the bottom of this
    # function) exports exactly this object — or a snapshot of the live
    # context when no result object could be built (stage exception,
    # soft kill). This outer try is what makes the export reachable from
    # every termination path.
    final_result: Any | None = None
    try:
        try:
            await asyncio.wait_for(_run_tracks(ctx), timeout=timeout_seconds)
        except (TimeoutError, asyncio.TimeoutError):
            timed_out = True
            budget.mark_exhausted()
            logger.info("Budget exhausted - returning partial results")
        except asyncio.CancelledError:
            # ``wait_for`` can surface cancellation from a child track on very
            # short budgets instead of translating it to TimeoutError. Preserve
            # the partial-result contract once the configured budget is spent.
            if budget.is_expired():
                timed_out = True
                budget.mark_exhausted()
                logger.info("Budget exhausted during track cancellation")
            else:
                raise
        except Exception as exc:  # noqa: BLE001
            logger.error("Track failure: %s", exc)

        # A module can soft-timeout internally while the overall harvest still
        # completes normally. Preserve incremental source telemetry on that
        # path too; the export must not depend on the module returning its
        # end-of-run metadata.
        _hydrate_subdomain_source_telemetry(ctx)

        if timed_out:
            # The discovery timeout is a valid partial-result boundary. The
            # dedicated post-discovery tail still runs before aggregation and
            # export, using its own deadline.
            try:
                await asyncio.wait_for(signal_pool.close(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Signal-pool shutdown exceeded 5s during timeout recovery")
            from .domain_harvest_orchestrator import (
                DomainHarvestResult,
                _aggregate,
                _sort_key,
            )

            identity_clusters = await signal_pool.all_candidates()
            _hydrate_subdomain_source_telemetry(ctx)
            shadow_profiles: list[dict[str, Any]] = []
            tail = await _run_verification_tail(identity_clusters)
            smtp_validation = tail.get("smtp_email_verification", {})
            unique_emails = _aggregate(
                cleaned,
                module_results,
                signal_pool=signal_pool,
                identity_clusters=identity_clusters,
                shadow_profiles_out=shadow_profiles,
            )
            unique_emails.sort(key=_sort_key)
            if not ctx.module_overrides:
                await _attach_breach_enrichment(unique_emails, module_results, ctx)
            completed = datetime.now(timezone.utc)
            errors = [
                f"[{name}] {err}"
                for name, result in module_results.items()
                for err in (result.errors or [])
            ]
            errors.append("harvest timed out during discovery; partial result exported")
            partial_metadata = {
                "harvest_status": _derive_harvest_status(ctx, timed_out=True),
                "timed_out": True,
                "timeout_at_seconds": timeout_seconds,
                "budget": budget.stats,
                "smtp_email_verification": smtp_validation,
                "m365_email_verification": tail.get("m365_email_verification", {}),
                "yahoo_email_verification": tail.get("yahoo_email_verification", {}),
                "low_email_validation": tail.get("low_email_validation", {}),
                "verification_tail": tail,
            }
            m365_infra = _m365_context_infrastructure(ctx.m365_context)
            if m365_infra is not None:
                partial_metadata["m365_tenant"] = m365_infra
            final_result = DomainHarvestResult(
                domain=cleaned,
                started_at=started_iso,
                completed_at=completed.isoformat().replace("+00:00", "Z"),
                duration_seconds=round((completed - started).total_seconds(), 3),
                module_results=module_results,
                unique_emails=unique_emails,
                total_unique_emails=len(unique_emails),
                high_confidence_count=sum(
                    1 for e in unique_emails
                    if e.confidence_label in {"CONFIRMED", "HIGH"} and not e.is_role
                ),
                likely_confidence_count=sum(
                    1 for e in unique_emails
                    if e.confidence_label == "LIKELY" and not e.is_role
                ),
                medium_confidence_count=sum(
                    1 for e in unique_emails
                    if e.confidence_label in {"LIKELY", "MEDIUM"} and not e.is_role
                ),
                low_confidence_count=sum(
                    1 for e in unique_emails
                    if e.confidence_label == "LOW" and not e.is_role
                ),
                role_account_count=sum(1 for e in unique_emails if e.is_role),
                personal_email_count=sum(1 for e in unique_emails if not e.is_role),
                errors=errors,
                smtp_verification_used=bool(ctx.enable_smtp and not ctx.module_overrides),
                employee_names_processed=len(
                    (
                        module_results.get(MODULE_EMPLOYEE_NAMES).findings
                        if module_results.get(MODULE_EMPLOYEE_NAMES) is not None
                        else []
                    )
                    or []
                ),
                fetch_cache_stats=cache.stats(),
                metadata=partial_metadata,
                shadow_profiles=shadow_profiles,
            )
            return final_result

        # Flush subscriber work before taking the identity-cluster snapshot.
        try:
            await asyncio.wait_for(signal_pool.close(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("Signal-pool shutdown exceeded 5s; continuing with snapshot")
        from .domain_harvest_orchestrator import _attach_native_email_validation
        from .historical_diff import annotate_historical_diff
        historical_metrics = annotate_historical_diff(module_results)
        identity_clusters = await signal_pool.all_candidates()
        if ctx.module_overrides:
            # Injected modules are deterministic unit-test/embedder paths;
            # do not introduce live DNS into them.
            native_validation = {
                "checked": 0,
                "skipped": "injected_modules",
            }
        else:
            native_validation = await _attach_native_email_validation(
                cleaned,
                module_results,
            )
        tail = await _run_verification_tail(identity_clusters)
        smtp_validation = tail.get("smtp_email_verification", {})
        m365_validation = tail.get("m365_email_verification", {})
        yahoo_validation = tail.get("yahoo_email_verification", {})
        shadow_profiles: list[dict[str, Any]] = []
        unique_emails = _aggregate(
            cleaned,
            module_results,
            signal_pool=signal_pool,
            identity_clusters=identity_clusters,
            shadow_profiles_out=shadow_profiles,
        )
        dns_signals = {"spf_present": False, "dmarc_strict": False}
        has_pattern_candidates = any(
            isinstance(finding.get("metadata"), dict)
            and finding["metadata"].get("pattern_template")
            for result in module_results.values()
            for finding in result.findings or []
        )
        if has_pattern_candidates and not ctx.module_overrides:
            from .domain_harvest_orchestrator import (
                apply_domain_email_dns_signals,
                resolve_domain_email_dns_signals,
            )

            dns_signals = await resolve_domain_email_dns_signals(cleaned)
            apply_domain_email_dns_signals(unique_emails, dns_signals)
        if not ctx.module_overrides:
            await _attach_breach_enrichment(unique_emails, module_results, ctx)
        unique_emails.sort(key=_sort_key)
        low_email_validation = tail.get("low_email_validation", {})
        completed = datetime.now(timezone.utc)
        completed_iso = completed.isoformat().replace("+00:00", "Z")
        duration = (completed - started).total_seconds()
        high = sum(
            1
            for e in unique_emails
            if e.confidence_label in {"CONFIRMED", "HIGH"} and not e.is_role
        )
        likely = sum(
            1
            for e in unique_emails
            if e.confidence_label == "LIKELY" and not e.is_role
        )
        # ``medium`` is the historical "anything above LOW" band
        # (LIKELY + MEDIUM) for backward compatibility with
        # downstream tooling.
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
        errors = [
            f"[{name}] {err}"
            for name, result in module_results.items()
            for err in (result.errors or [])
        ]
        pattern_meta = module_results.get(
            MODULE_PATTERN_VERIFY,
            ModuleResult(status=ModuleStatus.SKIPPED),
        ).metadata or {}
        confirmed_patterns = signal_pool.get_confirmed_patterns()
        metadata = {
            "harvest_status": "completed",
            "timed_out": False,
            "budget": budget.stats,
            "identity_clusters": [
                {
                    "canonical_key": list(cluster.canonical_key),
                    "score": cluster.score,
                    "export_tier": cluster.export_tier,
                    "boost_flags": sorted(cluster.boost_flags),
                    "signal_count": len(cluster.signals),
                }
                for cluster in identity_clusters
            ],
            "historical_diff": historical_metrics,
            "native_email_validation": native_validation,
            "smtp_email_verification": smtp_validation,
            "m365_email_verification": m365_validation,
            "yahoo_email_verification": yahoo_validation,
            "low_email_validation": low_email_validation,
            "verification_tail": tail,
        }
        m365_infra = _m365_context_infrastructure(ctx.m365_context)
        if m365_infra is not None:
            metadata["m365_tenant"] = m365_infra
        final_result = DomainHarvestResult(
            domain=cleaned,
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
            personal_email_count=len(unique_emails) - role,
            errors=errors,
            smtp_verification_used=bool(ctx.enable_smtp),
            catchall_detected=(
                pattern_meta.get("is_catchall")
                if pattern_meta.get("is_catchall") is not None
                else smtp_validation.get("is_catchall")
            ),
            confirmed_pattern=pattern_meta.get("confirmed_pattern")
            or (confirmed_patterns[0] if confirmed_patterns else None),
            employee_names_processed=_employee_name_count(module_results),
            fetch_cache_stats=cache.stats(),
            metadata=metadata,
            shadow_profiles=shadow_profiles,
        )
        return final_result
    finally:
        with contextlib.suppress(Exception):
            await signal_pool.close()
        with contextlib.suppress(Exception):
            await cache.aclose()
        # --------------------------------------------------------------
        # Harvest-termination handler — the single unconditional export
        # trigger. It runs on EVERY exit path (normal completion, budget
        # timeout, stage exception, soft kill) and exports the harvest
        # context exactly as it exists at this moment: the finished
        # result object when one was built, otherwise a snapshot of the
        # shared in-memory state. Stages write to context; only this
        # handler emits the harvest-end event the export hangs off of,
        # so the export depends on nothing except the harvest ending.
        # No pipeline stage owns, gates, or chains it.
        #
        # ``on_harvest_end`` must be a SYNCHRONOUS callable: it may run
        # while the task is being cancelled, so it must not await.
        # --------------------------------------------------------------
        if on_harvest_end is not None:
            snapshot = final_result
            if snapshot is None:
                snapshot = _termination_snapshot(
                    ctx,
                    cleaned,
                    started=started,
                    started_iso=started_iso,
                    timeout_seconds=timeout_seconds,
                    timed_out=timed_out,
                )
            try:
                on_harvest_end(snapshot)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Harvest-end export trigger failed: %s", exc)


async def _seed_scheduler(ctx: WorkerContext) -> None:
    homepage = await _read_homepage_for_router(ctx)
    router_result = IndustryVocabularyRouter().route(homepage)
    object.__setattr__(ctx, "context_vertical", tuple(router_result.inferred_industries))
    for path in router_result.target_paths:
        await ctx.scheduler.submit(
            WorkItem(
                kind="fetch_page",
                url=f"https://{ctx.domain}{path}",
                priority=PRIORITY_GUARANTEED,
                track=TRACK_GUARANTEED,
                source="industry_router",
            )
        )
    if not ctx.module_overrides:
        await ctx.scheduler.submit(
            WorkItem(
                kind="provider_detection",
                priority=PRIORITY_GUARANTEED,
                track=TRACK_GUARANTEED,
                source="mx_provider_detection",
            )
        )
    await ctx.scheduler.submit(
        WorkItem(
            kind="fetch_page",
            url=f"https://{ctx.domain}/",
            priority=PRIORITY_GUARANTEED,
            track=TRACK_GUARANTEED,
            source="homepage",
        )
    )

    seeds = tuple(_MODULE_PRIORITIES.items())
    for module_name, priority in seeds:
        if module_name in ctx.skip_modules:
            continue
        seed_track = (
            TRACK_GUARANTEED
            if module_name in {MODULE_PUBLIC_SURFACE, MODULE_HACKERTARGET}
            else TRACK_OPPORTUNISTIC
        )
        await ctx.scheduler.submit(
            WorkItem(
                kind="run_module",
                module_name=module_name,
                priority=priority,
                track=seed_track,
                source="legacy_module",
            )
        )
    if getattr(ctx.settings, "hunter_io_api_key", None):
        await ctx.scheduler.submit(
            WorkItem(
                kind="run_module",
                module_name=MODULE_HUNTER,
                priority=PRIORITY_HIGH_SIGNAL,
                track=TRACK_OPPORTUNISTIC,
                source="hunter",
            )
        )
    await ctx.scheduler.submit(
        WorkItem(
            kind="run_module",
            module_name="security_txt",
            priority=PRIORITY_GUARANTEED,
            track=TRACK_GUARANTEED,
            source="seed",
        )
    )


async def _run_tracks(ctx: WorkerContext) -> None:
    progress = asyncio.create_task(_progress_loop(ctx))
    tracks = [
        asyncio.create_task(_track1_loop(ctx, concurrency=3)),
        asyncio.create_task(_track2_loop(ctx, concurrency=5)),
    ]
    try:
        outcomes = await asyncio.gather(*tracks, return_exceptions=True)
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                logger.error("Harvest track failed: %r", outcome)
    finally:
        progress.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await progress


async def _track1_loop(ctx: WorkerContext, concurrency: int = 3) -> None:
    sem = asyncio.Semaphore(concurrency)
    running: set[asyncio.Task[None]] = set()

    async def _run_one(item: WorkItem) -> None:
        async with sem:
            result = await _execute_item(item, ctx)
            _record_work_failure(ctx, result)
            for new_item in result.new_items:
                await ctx.scheduler.submit(new_item)
            _write_to_signal_pool(result, ctx.signal_pool)

    try:
        while True:
            if not ctx.budget.can_start_track1():
                break
            _prune_done(running)
            item = await ctx.scheduler.pull_matching(
                lambda work: work.track == TRACK_GUARANTEED,
                timeout=0.05,
            )
            if item is None:
                if ctx.scheduler.is_empty() and not running:
                    break
                await asyncio.sleep(0)
                continue
            task = asyncio.create_task(_run_one(item))
            running.add(task)
    except asyncio.CancelledError:
        for task in running:
            task.cancel()
        if running:
            await asyncio.gather(*running, return_exceptions=True)
        raise

    if running:
        outcomes = await asyncio.gather(*running, return_exceptions=True)
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                logger.error("Guaranteed harvest task failed: %r", outcome)
    ctx.budget.mark_track1_closed()


async def _track2_loop(ctx: WorkerContext, concurrency: int = 5) -> None:
    sem = asyncio.Semaphore(concurrency)
    running: set[asyncio.Task[None]] = set()

    async def _run_one(item: WorkItem) -> None:
        async with sem:
            result = await _execute_item(item, ctx)
            _record_work_failure(ctx, result)
            for new_item in result.new_items:
                if new_item.track == TRACK_GUARANTEED:
                    new_item.track = TRACK_OPPORTUNISTIC
                await ctx.scheduler.submit(new_item)
            _write_to_signal_pool(result, ctx.signal_pool)

    def _is_person_pivot(item: WorkItem) -> bool:
        return (
            item.kind == "generate_patterns"
            or item.module_name in _PERSON_PIVOT_MODULES
        )

    try:
        while True:
            # We must still pull one item inside the reserve window so a
            # person-keyed pivot can run; non-pivot work is requeued below.
            if ctx.budget.is_expired():
                break
            _prune_done(running)
            item = await ctx.scheduler.pull_matching(
                lambda work: work.track == TRACK_OPPORTUNISTIC,
                timeout=0.05,
            )
            if item is None:
                if ctx.scheduler.is_empty() and not running:
                    break
                # A producer may have drained immediately after the pull.
                # Recheck after yielding briefly so an empty queue cannot
                # hold track 2 open until the full harvest budget expires.
                if ctx.scheduler.is_empty():
                    await asyncio.sleep(0.01)
                    if ctx.scheduler.is_empty() and not running:
                        break
                await asyncio.sleep(0)
                continue
            if not ctx.budget.can_start_track2(person_pivot=_is_person_pivot(item)):
                # Put the non-pivot work back and preserve the final budget tail
                # for names discovered late in the run.
                await ctx.scheduler.requeue(item)
                break
            task = asyncio.create_task(_run_one(item))
            running.add(task)
    except asyncio.CancelledError:
        for task in running:
            task.cancel()
        if running:
            await asyncio.gather(*running, return_exceptions=True)
        raise

    if running:
        outcomes = await asyncio.gather(*running, return_exceptions=True)
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                logger.error("Opportunistic harvest task failed: %r", outcome)


async def _execute_item(item: WorkItem, ctx: WorkerContext) -> WorkResult:
    start = asyncio.get_event_loop().time()
    # Phase 3 fix: track-2 modules (employee_name_discovery, pattern_and_verify)
    # can be slow (DDG/Bing search + structured page fetch + ML classification).
    # Using 0.75 fraction instead of the default 0.10 gives them up to 75% of
    # the remaining budget as soft timeout — sufficient for ~10s DDG requests
    # even on a 90s total budget (vs. the old 9s which was too short).
    is_track2 = getattr(item, "track", None) == TRACK_OPPORTUNISTIC
    fraction = 0.75 if is_track2 else 0.10
    try:
        soft_timeout = ctx.budget.soft_timeout_for_module(fraction=fraction)
    except TypeError:
        # Keep lightweight test doubles and older embedders compatible with
        # the pre-fraction budget interface.
        soft_timeout = ctx.budget.soft_timeout_for_module()
    try:
        if item.module_name and item.module_name in ctx.skip_modules:
            skip_result = ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"domain": ctx.domain, "skip_reason": "runtime_policy"},
            )
            _record_module_result(ctx, item.module_name, skip_result)
            _emit_module_complete(ctx, item.module_name, skip_result)
            return WorkResult(
                item=item,
                success=True,
                findings=[],
                new_items=[],
                errors=["skipped by runtime policy"],
                duration_seconds=0.0,
            )
        if (
            item.module_name == MODULE_PATTERN_VERIFY
            and ctx.provider_detection_ready is not None
            and not ctx.provider_detection_ready.is_set()
        ):
            await ctx.provider_detection_ready.wait()
        if ctx.subdomain_calibrate and item.module_name != MODULE_SUBDOMAIN_INTEL:
            if item.module_name:
                skip_result = ModuleResult(
                    status=ModuleStatus.SKIPPED,
                    metadata={
                        "domain": ctx.domain,
                        "skip_reason": "subdomain_calibration",
                    },
                )
                _record_module_result(ctx, item.module_name, skip_result)
                _emit_module_complete(ctx, item.module_name, skip_result)
            return WorkResult(
                item=item,
                success=True,
                findings=[],
                new_items=[],
                errors=["skipped for subdomain calibration"],
                duration_seconds=0.0,
            )
        if item.module_name and _should_defer_for_yield(ctx, item.module_name):
            skip_result = ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"domain": ctx.domain, "skip_reason": "yield_prediction"},
            )
            _record_module_result(ctx, item.module_name, skip_result)
            _emit_module_complete(ctx, item.module_name, skip_result)
            return WorkResult(
                item=item,
                success=True,
                findings=[],
                new_items=[],
                errors=["deferred by yield prediction"],
                duration_seconds=0.0,
            )
        if item.kind == "provider_detection":
            await _ensure_provider_detection(ctx)
            findings, new_items = [], []
        elif item.kind == "fetch_page" and item.url:
            findings, new_items = await _fetch_and_extract(item.url, ctx)
        elif item.kind == "run_module" and item.module_name:
            if item.module_name == MODULE_SUBDOMAIN_INTEL:
                findings, new_items = await _run_subdomain_intel_with_hard_cap(ctx)
            else:
                module = _get_module_instance(item.module_name, ctx)
                if item.payload and hasattr(module, "run_with_payload"):
                    findings, new_items = await _run_module_with_payload(
                        item.module_name,
                        module,
                        item.payload,
                        ctx,
                        soft_timeout,
                    )
                else:
                    findings, new_items = await _run_module(
                        item.module_name,
                        ctx,
                        soft_timeout,
                    )
        elif item.kind == "generate_patterns":
            findings, new_items = await _run_pattern_for_name(
                item.payload, ctx
            )
        else:
            findings, new_items = [], []
        return WorkResult(
            item=item,
            success=True,
            findings=findings,
            new_items=new_items,
            errors=[],
            duration_seconds=asyncio.get_event_loop().time() - start,
        )
    except Exception as exc:  # noqa: BLE001
        return WorkResult(
            item=item,
            success=False,
            findings=[],
            new_items=[],
            errors=[str(exc)],
            duration_seconds=asyncio.get_event_loop().time() - start,
        )


def _should_defer_for_yield(ctx: WorkerContext, module_name: str) -> bool:
    """Defer only low-yield candidates in the final budget tail.

    At least two earlier registry/archive sources must have completed with no
    findings. High-signal and guaranteed modules are never deferred here.
    """
    if module_name not in _YIELD_PREDICTION_CANDIDATES:
        return False
    if not getattr(ctx.settings, "enable_yield_prediction", True):
        return False
    tail = float(getattr(ctx.settings, "yield_prediction_tail_seconds", 15.0) or 15.0)
    if ctx.budget.remaining() > tail:
        return False
    results = ctx.module_results or {}
    observed = [
        results.get(name)
        for name in (
            MODULE_COMMONCRAWL,
            MODULE_WAYBACK_DOMAIN,
            MODULE_NPM_EMAIL,
            MODULE_PYPI_EMAIL,
            MODULE_PGP_DOMAIN_EMAIL,
        )
    ]
    completed = [
        item
        for item in observed
        if item is not None and item.status in {ModuleStatus.SUCCESS, ModuleStatus.PARTIAL}
    ]
    return len(completed) >= 2 and sum(len(item.findings or []) for item in completed) == 0


async def _fetch_and_extract(
    url: str,
    ctx: WorkerContext,
) -> tuple[list[dict[str, Any]], list[WorkItem]]:
    response = await ctx.page_cache.get(url)
    html = getattr(response, "text", "") or ""
    if not html:
        content = getattr(response, "content", b"") or b""
        if isinstance(content, bytes | bytearray):
            html = bytes(content).decode("utf-8", errors="replace")
    if not html:
        return [], []

    findings: list[dict[str, Any]] = []
    for extracted in extract_emails(html, ctx.domain):
        findings.append(
            {
                "platform": "structured_page",
                "profile_url": url,
                "username": extracted.email.split("@", 1)[0],
                "confidence": "medium",
                "metadata": {
                    "email": extracted.email,
                    "on_domain": extracted.on_domain,
                    "source_url": url,
                    "source_type": "structured_page",
                    "confidence_score": 0.7,
                    "source_text_snippet": extracted.source_text_snippet,
                },
            }
        )

    # Blog/profile pages use the same full person extractor as the normal
    # site-intelligence fetch path. This preserves names and direct emails
    # discovered in JSON-LD, hCards, mailto links, LinkedIn slugs, and other
    # structured page surfaces.
    for person in extract_people(
        html,
        url,
        ctx.domain,
        aggressive=ctx.aggressive,
    ):
        metadata = {
            "name": person.name,
            "person_name": person.name,
            "title_or_role": person.title,
            "source_type": person.source_type,
            "confidence_score": person.confidence,
            "source_url": person.page_url,
            "on_domain": bool(
                person.email and person.email.lower().endswith("@" + ctx.domain.lower())
            ),
        }
        if person.email:
            metadata["email"] = person.email
        findings.append(
            {
                "platform": "structured_page",
                "profile_url": url,
                "username": person.email.split("@", 1)[0] if person.email else person.name,
                "confidence": "high" if person.confidence >= 0.7 else "medium",
                "metadata": metadata,
            }
        )

    next_url = PaginationHandler(ctx.page_cache).extract_next_url(url, html)
    new_items = []
    if next_url:
        new_items.append(
            WorkItem(
                kind="fetch_page",
                url=next_url,
                priority=PRIORITY_ROUTER_EXPANSION,
                track=TRACK_GUARANTEED,
                source="pagination",
            )
        )
    return findings, new_items


async def _run_module(
    module_name: str,
    ctx: WorkerContext,
    soft_timeout: float,
) -> tuple[list[dict[str, Any]], list[WorkItem]]:
    return await _run_module_core(
        module_name,
        ctx,
        soft_timeout=soft_timeout,
        outer_timeout=True,
    )


def _partial_subdomain_result(module: Any, ctx: WorkerContext) -> ModuleResult:
    """Build a cancellation result without discarding live discoveries."""
    existing = (ctx.module_results or {}).get(MODULE_SUBDOMAIN_INTEL)
    existing_findings = list(getattr(existing, "findings", None) or [])
    partial_findings = list(
        getattr(module, "partial_findings", lambda: [])() or []
    )
    findings = existing_findings or partial_findings
    metadata = dict(
        getattr(module, "partial_metadata", lambda: {})() or {}
    )
    metadata.setdefault("domain", ctx.domain)
    return ModuleResult(
        status=ModuleStatus.PARTIAL,
        findings=findings,
        errors=["Cancelled by subdomain_intel hard cap"],
        metadata=metadata,
    )


def _module_outputs(
    result: ModuleResult | None,
) -> tuple[list[dict[str, Any]], list[WorkItem]]:
    if result is None:
        return [], []
    findings = [dict(f) for f in (result.findings or []) if isinstance(f, dict)]
    new_items = result.new_items if hasattr(result, "new_items") else []
    return findings, new_items


def _ensure_subdomain_partial_result(ctx: WorkerContext) -> ModuleResult:
    """Publish a partial result when a test double or adapter owns the task."""
    existing = (ctx.module_results or {}).get(MODULE_SUBDOMAIN_INTEL)
    if existing is not None and existing.status is ModuleStatus.PARTIAL:
        return existing
    metadata = dict(getattr(existing, "metadata", None) or {})
    metadata.setdefault("domain", ctx.domain)
    result = ModuleResult(
        status=ModuleStatus.PARTIAL,
        findings=list(getattr(existing, "findings", None) or []),
        errors=["Cancelled by subdomain_intel hard cap"],
        metadata=metadata,
    )
    _record_module_result(ctx, MODULE_SUBDOMAIN_INTEL, result)
    _emit_module_complete(ctx, MODULE_SUBDOMAIN_INTEL, result)
    return result


async def _run_module_core(
    module_name: str,
    ctx: WorkerContext,
    *,
    soft_timeout: float | None,
    outer_timeout: bool,
) -> tuple[list[dict[str, Any]], list[WorkItem]]:
    module = _get_module_instance(module_name, ctx)
    started = time.perf_counter()
    if ctx.progress_callback is not None:
        ctx.progress_callback(module_name, "Starting module...")
    result: ModuleResult | None = None
    try:
        instance = _run_module_instance(module_name, module, ctx, soft_timeout)
        if outer_timeout:
            assert soft_timeout is not None
            # _run_module_instance applies the same soft timeout internally
            # and returns a PARTIAL result. A small grace window prevents the
            # outer guard from cancelling that result at the exact deadline.
            result = await asyncio.wait_for(instance, timeout=soft_timeout + 1.0)
        else:
            # subdomain_intel is governed by the explicit task hard wall. Do
            # not install a second soft timeout around the module coroutine.
            result = await instance
    except asyncio.TimeoutError:
        elapsed = round(time.perf_counter() - started, 3)
        partial_metadata = {}
        if module_name == MODULE_SUBDOMAIN_INTEL:
            partial_metadata = getattr(module, "partial_metadata", lambda: {})()
        timeout_label = soft_timeout if soft_timeout is not None else elapsed
        result = ModuleResult(
            status=ModuleStatus.FAILED,
            errors=[f"module timed out after {timeout_label:.1f}s"],
            metadata={"domain": ctx.domain, **partial_metadata, "duration_seconds": elapsed},
        )
    except asyncio.CancelledError:
        elapsed = round(time.perf_counter() - started, 3)
        if module_name == MODULE_SUBDOMAIN_INTEL:
            result = _partial_subdomain_result(module, ctx)
        else:
            result = ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[],
                errors=["Cancelled by budget timeout"],
                metadata={"domain": ctx.domain, "duration_seconds": elapsed},
            )
        raise
    finally:
        if result is not None:
            result.metadata.setdefault(
                "duration_seconds", round(time.perf_counter() - started, 3)
            )
            _record_module_result(ctx, module_name, result)
            _emit_module_complete(ctx, module_name, result)
            for finding in result.findings or []:
                _emit_finding(ctx.signal_pool, module_name, finding, ctx.domain)

    assert result is not None
    out_findings, new_items = _module_outputs(result)
    if module_name == MODULE_EMPLOYEE_NAMES:
        names = [
            {
                "name": (finding.get("metadata") or {}).get("name"),
                "title_or_role": (finding.get("metadata") or {}).get("title_or_role"),
            }
            for finding in result.findings or []
            if isinstance(finding, dict)
            and isinstance(finding.get("metadata"), dict)
            and (finding.get("metadata") or {}).get("name")
        ]
        if names:
            new_items.append(WorkItem(
                kind="run_module",
                module_name=MODULE_PERSON_EMAIL_PIVOT,
                payload={"domain": ctx.domain, "names": names},
                priority=PRIORITY_HIGH_SIGNAL,
                track=TRACK_OPPORTUNISTIC,
                source="employee_name_discovery_complete",
            ))
    return out_findings, new_items


async def _ensure_provider_detection(ctx: WorkerContext) -> Any:
    """Resolve and classify MX exactly once for this harvest context."""
    if ctx.provider_detection is not None:
        if ctx.provider_detection_ready is not None:
            ctx.provider_detection_ready.set()
        return ctx.provider_detection
    if ctx.module_overrides:
        return None
    try:
        mx_records = await resolve_mx(ctx.domain)
        detection = detect_provider_from_mx(mx_records, target_domain=ctx.domain)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Provider detection failed for %s: %s", ctx.domain, exc)
        mx_records = []
        detection = detect_provider_from_mx([], target_domain=ctx.domain)
    object.__setattr__(ctx, "provider_mx_records", list(mx_records))
    object.__setattr__(ctx, "provider_detection", detection)
    if ctx.provider_detection_ready is not None:
        ctx.provider_detection_ready.set()
    return detection


async def run_subdomain_intel(
    ctx: WorkerContext,
) -> tuple[list[dict[str, Any]], list[WorkItem]]:
    """Run subdomain_intel without the generic module soft timeout."""
    return await _run_module_core(
        MODULE_SUBDOMAIN_INTEL,
        ctx,
        # _safe_phase12_run interprets None as "derive the generic soft
        # timeout from ctx.budget". Infinity disables that inner boundary;
        # _run_subdomain_intel_with_hard_cap owns the real wall.
        soft_timeout=float("inf"),
        outer_timeout=False,
    )


async def _run_subdomain_intel_with_hard_cap(
    ctx: WorkerContext,
) -> tuple[list[dict[str, Any]], list[WorkItem]]:
    """Run subdomain_intel in a tracked task with a real cancellation wall."""
    hard_cap = float(
        getattr(ctx, "subdomain_intel_hard_cap", SUBDOMAIN_INTEL_HARD_CAP)
    )
    subdomain_task = asyncio.ensure_future(run_subdomain_intel(ctx))
    try:
        return await asyncio.wait_for(
            subdomain_task,
            timeout=hard_cap,
        )
    except asyncio.TimeoutError:
        subdomain_task.cancel()
        try:
            await subdomain_task
        except asyncio.CancelledError:
            pass
        logger.warning(
            "subdomain_intel cancelled at hard cap %ds",
            hard_cap,
        )
        return _module_outputs(_ensure_subdomain_partial_result(ctx))
    except asyncio.CancelledError:
        # If the harvest itself is cancelled, do not leave the child task
        # running after its parent has unwound.
        subdomain_task.cancel()
        try:
            await subdomain_task
        except asyncio.CancelledError:
            pass
        raise

async def _run_module_with_payload(
    module_name: str,
    module: Any,
    payload: dict,
    ctx: WorkerContext,
    soft_timeout: float,
) -> tuple[list[dict[str, Any]], list[WorkItem]]:
    started = time.perf_counter()
    if ctx.progress_callback is not None:
        ctx.progress_callback(module_name, "Starting module...")
    result: ModuleResult | None = None
    try:
        # Person-keyed pivots must use the same per-run cache/session as the
        # rest of harvest.  Passing it explicitly also keeps the module
        # independently testable without relying on a mutable ``session``
        # attribute being injected after construction.
        run_with_payload = module.run_with_payload
        try:
            parameters = inspect.signature(run_with_payload).parameters
            accepts_fetch = "fetch" in parameters or any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD
                for parameter in parameters.values()
            )
        except (TypeError, ValueError):
            # Async mocks and dynamically generated modules may not expose a
            # signature; pass the new keyword and let the module decide.
            accepts_fetch = True
        kwargs = {"fetch": ctx.page_cache} if accepts_fetch else {}
        if ctx.progress_callback is not None:
            try:
                accepts_progress = "progress_callback" in parameters or any(
                    parameter.kind is inspect.Parameter.VAR_KEYWORD
                    for parameter in parameters.values()
                )
            except UnboundLocalError:
                accepts_progress = True
            if accepts_progress:
                kwargs["progress_callback"] = (
                    lambda action: ctx.progress_callback(module_name, action)
                )
        result = await asyncio.wait_for(
            run_with_payload(payload, **kwargs),
            timeout=soft_timeout,
        )
    except asyncio.TimeoutError:
        elapsed = round(time.perf_counter() - started, 3)
        result = ModuleResult(
            status=ModuleStatus.FAILED,
            errors=[f"module timed out after {soft_timeout:.1f}s"],
            metadata={"domain": ctx.domain, "duration_seconds": elapsed},
        )
    except asyncio.CancelledError:
        elapsed = round(time.perf_counter() - started, 3)
        result = ModuleResult(
            status=ModuleStatus.PARTIAL,
            findings=[],
            errors=["Cancelled by budget timeout"],
            metadata={"domain": ctx.domain, "duration_seconds": elapsed},
        )
        raise
    finally:
        if result is not None:
            result.metadata.setdefault(
                "duration_seconds", round(time.perf_counter() - started, 3)
            )
            _record_module_result(ctx, module_name, result)
            _emit_module_complete(ctx, module_name, result)
            for finding in result.findings or []:
                _emit_finding(ctx.signal_pool, module_name, finding, ctx.domain)

    assert result is not None
    out_findings = [dict(f) for f in (result.findings or []) if isinstance(f, dict)]
    new_items = result.new_items if hasattr(result, "new_items") else []
    return out_findings, new_items


def _record_module_result(
    ctx: WorkerContext, module_name: str, result: ModuleResult
) -> None:
    """Store results without discarding earlier reactive pivot findings."""
    if ctx.module_results is None:
        return
    if module_name not in _ACCUMULATING_MODULES:
        ctx.module_results[module_name] = result
        return

    previous = ctx.module_results.get(module_name)
    if previous is None:
        ctx.module_results[module_name] = result
        return

    previous_findings = [item for item in (previous.findings or []) if isinstance(item, dict)]
    current_findings = [item for item in (result.findings or []) if isinstance(item, dict)]
    metadata = dict(previous.metadata or {})
    for key, value in (result.metadata or {}).items():
        if key in {"per_person", "sources"} and isinstance(value, list):
            existing = metadata.get(key)
            metadata[key] = [*(existing if isinstance(existing, list) else []), *value]
        elif (
            key.endswith("_found")
            or key.endswith("_attempted")
            or key.endswith("_checked")
            or key == "findings_count"
        ):
            try:
                metadata[key] = int(metadata.get(key, 0)) + int(value)
            except (TypeError, ValueError):
                metadata[key] = value
        else:
            metadata[key] = value
    if module_name == MODULE_EMAIL_IDENTITY_ENRICHMENT:
        # Per-email enrichment can produce useful findings while one or more
        # backing sources fail. Preserve that degraded health signal across
        # the accumulating reactive runs instead of upgrading it to SUCCESS
        # merely because a finding exists.
        statuses = {previous.status, result.status}
        if ModuleStatus.PARTIAL in statuses:
            status = ModuleStatus.PARTIAL
        elif ModuleStatus.SUCCESS in statuses:
            status = ModuleStatus.SUCCESS
        elif ModuleStatus.FAILED in statuses:
            status = ModuleStatus.FAILED
        else:
            status = result.status
    else:
        status = ModuleStatus.SUCCESS if previous_findings or current_findings else (
            ModuleStatus.PARTIAL
            if previous.status == ModuleStatus.PARTIAL or result.status == ModuleStatus.PARTIAL
            else result.status
        )
    ctx.module_results[module_name] = ModuleResult(
        status=status,
        findings=[*previous_findings, *current_findings],
        errors=[*(previous.errors or []), *(result.errors or [])],
        metadata=metadata,
    )

async def _run_pattern_for_name(
    payload: dict,
    ctx: WorkerContext
) -> tuple[list[dict], list[WorkItem]]:
    name = payload["name"]
    domain = ctx.domain

    if _is_obvious_non_person_name(name):
        return [], []

    from backend.core.name_classifier import classify_name
    if not classify_name(name).is_person:
        return [], []

    from backend.core.email_pattern_generator import _PATTERN_TEMPLATES, generate_patterns
    if "templates" in payload:
        templates = payload["templates"]
    elif payload.get("has_title"):
        templates = None
    else:
        templates = _PATTERN_TEMPLATES[:3]

    candidates = generate_patterns(name, domain, patterns=templates)
    ctx.signal_pool.emit_name(
        name,
        source="pattern_confirmed",
        confidence=0.55,
        domain=domain,
    )
    findings = []
    for c in candidates:
        ctx.signal_pool.emit_email(
            c.email,
            source="pattern_generated",
            confidence=0.05,
            domain=domain,
        )
        findings.append({
            "platform": "pattern_and_verify",
            "profile_url": c.email,
            "confidence": "low",
            "metadata": {
                "email": c.email,
                "source_name": name,
                "pattern_template": c.pattern_template,
                "verification_status": "unverified",
                "confidence_score": 0.05,
            },
        })
    if ctx.module_results is not None:
        existing = ctx.module_results.get(MODULE_PATTERN_VERIFY)
        existing_findings = []
        existing_metadata = {}
        if existing is not None:
            existing_findings = list(existing.findings or [])
            existing_metadata = dict(existing.metadata or {})
        existing_metadata.update(
            {
                "generated_count": existing_metadata.get("generated_count", 0)
                + len(findings),
                "smtp_verification_enabled": ctx.enable_smtp,
            }
        )
        ctx.module_results[MODULE_PATTERN_VERIFY] = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[*existing_findings, *findings],
            metadata=existing_metadata,
        )
    return findings, []


async def _on_name_found(
    name: str,
    source: str,
    metadata: dict
) -> list[WorkItem]:
    from backend.core.email_pattern_generator import _PATTERN_TEMPLATES
    from backend.core.name_classifier import classify_name
    from backend.modules.employee_name_discovery import classify_role_bucket

    confidence = float(metadata.get(
        "confidence_score", 0.5
    ))
    medium_threshold = float(
        getattr(settings, "pattern_medium_confidence_threshold", 0.50) or 0.50
    )
    if _is_obvious_non_person_name(name):
        return []
    result = classify_name(name)
    if not result.is_person:
        return []
    tokens = name.strip().split()
    if len(tokens) < 2:
        return []
    # Keep the reactive subscriber aligned with PatternAndVerifyModule's
    # batch path: LOW-confidence names are recorded, but do not generate
    # speculative permutations.
    if confidence < medium_threshold:
        return []
    title_or_role = str(metadata.get("title_or_role", "")).strip()
    has_title = bool(title_or_role)
    role_bucket = classify_role_bucket(title_or_role)
    if role_bucket == "executive":
        first_template = "{first}@{domain}"
        templates = [
            first_template,
            *[template for template in _PATTERN_TEMPLATES if template != first_template],
        ]
    else:
        templates = None if has_title else _PATTERN_TEMPLATES[:3]
    return [WorkItem(
        kind="generate_patterns",
        module_name=MODULE_PATTERN_VERIFY,
        payload={
            "name": name,
            "title": title_or_role,
            "confidence": confidence,
            "has_title": has_title,
            "templates": templates,
        },
        priority=PRIORITY_UNIVERSAL,
        track=TRACK_OPPORTUNISTIC,
        source=f"name_subscriber:{source}",
    )]


async def _on_email_found(
    email: str,
    source: str,
    metadata: dict[str, Any],
    seen: set[str],
) -> list[WorkItem]:
    """Schedule bounded identity enrichment for each personal email once."""
    if metadata.get("is_role"):
        return []
    cleaned = str(email or "").strip().lower()
    if "@" not in cleaned or cleaned in seen:
        return []
    seen.add(cleaned)
    return [WorkItem(
        kind="run_module",
        module_name=MODULE_EMAIL_IDENTITY_ENRICHMENT,
        payload={
            "email": email,
            "original_email": metadata.get("original_email") or email,
            "trigger_source": source,
        },
        priority=PRIORITY_HIGH_SIGNAL,
        track=TRACK_OPPORTUNISTIC,
        source=f"email_subscriber:{source}",
    )]


async def _on_name_found_persona_pivot(
    name: str,
    source: str,
    metadata: dict[str, Any],
    seen: set[str] | None = None,
) -> list[WorkItem]:
    """Schedule at most one public-email pivot for a qualified person."""
    confidence = float(metadata.get("confidence_score", metadata.get("confidence", 0.0)))
    cleaned = " ".join(str(name).split())
    if confidence < 0.50 or len(cleaned.split()) < 2:
        return []
    if not bool(getattr(settings, "persona_pivot_enabled", True)):
        return []
    if seen is not None:
        key = cleaned.casefold()
        if key in seen or len(seen) >= int(getattr(settings, "persona_pivot_max_names", 10)):
            return []
        seen.add(key)
    return [WorkItem(
        kind="run_module",
        module_name=MODULE_PERSONA_EMAIL_PIVOT,
        payload={
            "name": cleaned,
            "domain": metadata.get("domain", ""),
            "title": metadata.get("title_or_role", ""),
        },
        priority=PRIORITY_HIGH_SIGNAL,
        track=TRACK_OPPORTUNISTIC,
        source="name_subscriber:persona_pivot",
    )]

async def _run_module_instance(
    module_name: str,
    module: Any,
    ctx: WorkerContext,
    soft_timeout: float,
) -> ModuleResult:
    from .domain_harvest_orchestrator import (
        _employee_names_from_findings,
        _normalize_module_result,
        _run_hunter,
        _run_pattern,
        _safe_phase12_run,
    )

    if module_name == MODULE_HUNTER:
        _name, result = await _run_hunter(ctx.domain, ctx.settings.hunter_io_api_key)
        return _normalize_module_result(module_name, result)
    if module_name == MODULE_PATTERN_VERIFY:
        employee_result = (
            (ctx.module_results or {}).get(MODULE_EMPLOYEE_NAMES)
            or ModuleResult(status=ModuleStatus.SKIPPED)
        )
        return await _run_pattern(
            module,
            ctx.domain,
            employee_names=_employee_names_from_findings(employee_result.findings or []),
            enable_smtp=ctx.enable_smtp,
            signal_pool=ctx.signal_pool,
            budget=ctx.budget,
            provider_detection=ctx.provider_detection,
            mx_records=ctx.provider_mx_records,
            progress_callback=(
                (lambda action: ctx.progress_callback(module_name, action))
                if ctx.progress_callback is not None else None
            ),
        )
    if module_name == MODULE_RIPE_STAT_ASN:
        hackertarget = (ctx.module_results or {}).get(MODULE_HACKERTARGET)
        infrastructure = (
            (hackertarget.metadata or {}).get("infrastructure", {})
            if hackertarget
            else {}
        )
        ip_rows = infrastructure.get("ips", []) if isinstance(infrastructure, dict) else []
        resolved_ips = [
            str(row.get("ip"))
            for row in ip_rows
            if isinstance(row, dict) and row.get("ip")
        ]
        return await module.run(ctx.domain, resolved_ips=resolved_ips)
    if module_name == MODULE_SHODAN_INTERNETDB:
        hackertarget = (ctx.module_results or {}).get(MODULE_HACKERTARGET)
        infrastructure = (
            (hackertarget.metadata or {}).get("infrastructure", {})
            if hackertarget
            else {}
        )
        ip_rows = infrastructure.get("ips", []) if isinstance(infrastructure, dict) else []
        resolved_ips = [
            str(row.get("ip"))
            for row in ip_rows
            if isinstance(row, dict) and row.get("ip")
        ]
        if not resolved_ips:
            return ModuleResult(
                ModuleStatus.SKIPPED,
                metadata={
                    "domain": ctx.domain,
                    "skip_reason": "no_resolved_ips",
                    "infrastructure": {"ips": [], "asns": []},
                },
            )
        records = await module.enrich(resolved_ips)
        enriched_ips = [
            {
                "ip": ip,
                "shodan_data": data,
                "sources": ["shodan_internetdb"],
            }
            for ip, data in sorted(records.items())
        ]
        return ModuleResult(
            ModuleStatus.SUCCESS if records else ModuleStatus.PARTIAL,
            metadata={
                "domain": ctx.domain,
                "resolved_ips": len(resolved_ips),
                "shodan_ips_enriched": len(records),
                "infrastructure": {"ips": enriched_ips, "asns": []},
            },
        )
    name, result = await _safe_phase12_run(
        module_name,
        module,
        ctx.domain,
        cc_max_records=ctx.cc_max_records,
        cc_max_collections=ctx.cc_max_collections,
        dork_lite_mode=ctx.dork_lite_mode,
        aggressive=ctx.aggressive,
        use_proxies=ctx.use_proxies,
        proxy_fallback_ok=ctx.proxy_fallback_ok,
        fetch=ctx.page_cache,
        signal_pool=ctx.signal_pool,
        budget=ctx.budget,
        soft_timeout=soft_timeout,
        with_subdomains=ctx.with_subdomains,
        subdomain_deep=ctx.subdomain_deep,
        enable_scraping=not ctx.subdomain_calibrate,
        context_vertical=ctx.context_vertical,
        scrape_session=ctx.stealth_session,
        source_telemetry=ctx.subdomain_source_telemetry,
        progress_callback=(
            (lambda action: ctx.progress_callback(module_name, action))
            if ctx.progress_callback is not None else None
        ),
    )
    return _normalize_module_result(name, result)


def _get_module_instance(module_name: str, ctx: WorkerContext) -> Any:
    overrides = ctx.module_overrides or {}
    if module_name in overrides:
        return overrides[module_name]
    factories = {
        MODULE_COMMONCRAWL: CommonCrawlEmailModule,
        MODULE_WAYBACK_DOMAIN: WaybackDomainHarvestModule,
        MODULE_CODE_CERT: CodeAndCertEmailModule,
        MODULE_EMAIL_DORK: EmailSearchDorkModule,
        MODULE_NPM_EMAIL: NpmEmailModule,
        MODULE_PYPI_EMAIL: PyPIEmailModule,
        MODULE_PUBLIC_SURFACE: PublicSurfaceSweeper,
        MODULE_PUBLIC_FORGE: PublicForgeModule,
        MODULE_PACKAGE_ECOSYSTEMS: PackageEcosystemsModule,
        MODULE_SUBDOMAIN_SURFACE: SubdomainIntelModule,
        MODULE_PGP_DOMAIN_EMAIL: PgpDomainEmailModule,
        MODULE_GITHUB_ORG_MEMBERS: GitHubOrgMembersModule,
        MODULE_GITHUB_DOMAIN_COMMITS: GitHubDomainCommitsModule,
        MODULE_EMPLOYEE_NAMES: EmployeeNameDiscoveryModule,
        MODULE_PATTERN_VERIFY: PatternAndVerifyModule,
        MODULE_WORDPRESS_REST: WordPressRestModule,
        MODULE_SYNDICATION_FEED_SWEEPER: SyndicationFeedSweeper,
        MODULE_HACKERTARGET: HackerTargetHostsModule,
        MODULE_RIPE_STAT_ASN: RIPEStatASNModule,
        MODULE_SHODAN_INTERNETDB: ShodanInternetDBModule,
    }
    
    from ..modules.email_identity_enrichment import EmailIdentityEnrichmentModule
    from ..modules.name_to_github_profile import NameToGitHubProfileModule
    from ..modules.person_email_pivot import PersonEmailPivotModule
    from ..modules.persona_email_pivot import PersonaEmailPivotModule
    from ..modules.security_txt import SecurityTxtModule
    
    factories["security_txt"] = SecurityTxtModule
    factories["name_to_github_profile"] = NameToGitHubProfileModule
    factories[MODULE_PERSON_EMAIL_PIVOT] = PersonEmailPivotModule
    factories[MODULE_PERSONA_EMAIL_PIVOT] = PersonaEmailPivotModule
    factories[MODULE_EMAIL_IDENTITY_ENRICHMENT] = EmailIdentityEnrichmentModule

    try:
        return factories[module_name]()
    except KeyError as exc:
        raise ValueError(f"unknown harvest module: {module_name}") from exc


async def _progress_loop(ctx: WorkerContext) -> None:
    try:
        while not ctx.budget.is_expired():
            stats = ctx.scheduler.stats
            budget = ctx.budget.stats
            logger.debug(
                "Queue: %d items | Budget: %.0fs remaining | Track1: %s",
                stats["queue_size"],
                budget["remaining_seconds"],
                budget["track1_status"],
            )
            await asyncio.sleep(5.0)
    except asyncio.CancelledError:
        raise


async def _read_homepage_for_router(ctx: WorkerContext) -> str:
    try:
        response = await asyncio.wait_for(
            ctx.page_cache.get(f"https://{ctx.domain}/"),
            timeout=min(5.0, max(0.05, ctx.budget.remaining())),
        )
    except Exception:  # noqa: BLE001
        return ""
    return getattr(response, "text", "") or ""


def _write_to_signal_pool(result: WorkResult, signal_pool: AsyncSignalPool) -> None:
    source = result.item.module_name or result.item.source or result.item.kind
    for finding in result.findings or []:
        _emit_finding(signal_pool, source, finding, "")


def _emit_finding(
    signal_pool: AsyncSignalPool,
    source: str,
    finding: dict[str, Any],
    domain: str,
) -> None:
    meta = finding.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {}
    email = meta.get("email") or finding.get("email")
    confidence = meta.get("confidence_score") or meta.get("confidence") or 0.5
    try:
        confidence_value = float(confidence)
    except (TypeError, ValueError):
        confidence_value = 0.5
    if isinstance(email, str) and "@" in email:
        finding_name = meta.get("name") or meta.get("person_name")
        signal_pool.emit_email(
            email,
            source=source,
            confidence=confidence_value,
            domain=email.rsplit("@", 1)[-1].lower(),
            name=finding_name,
            is_role=bool(meta.get("is_role")),
            original_email=meta.get("original_email") or email,
        )
        if not finding_name:
            from ..modules.person_email_pivot import derive_name_from_email

            finding_name = derive_name_from_email(email)
            if finding_name:
                signal_pool.emit_name(
                    finding_name,
                    source,
                    confidence=max(0.35, confidence_value * 0.75),
                    domain=domain or email.rsplit("@", 1)[-1].lower(),
                    email=email,
                    derived_from_email=True,
                )
    name = meta.get("name") or meta.get("person_name") or finding.get("name")
    if isinstance(name, str) and name.strip():
        signal_pool.emit_name(
            name,
            source=source,
            confidence=confidence_value,
            domain=domain or meta.get("domain"),
            email=email if isinstance(email, str) else None,
            title_or_role=meta.get("title_or_role"),
        )


def _emit_module_complete(
    ctx: WorkerContext,
    module_name: str,
    result: ModuleResult,
) -> None:
    status_value = result.status.value if hasattr(result.status, "value") else str(result.status)
    errors = list(result.errors or [])
    # 0.12.7: persist a per-source health row so the `mailaccess
    # doctor` command can surface success rate + average duration
    # over the last 24h.  Done BEFORE invoking the callback so a
    # misbehaving callback never silently blocks the health
    # record from being written.
    try:
        from .platform_health import get_health_db

        health_db = get_health_db()
        duration = getattr(result, "duration_seconds", None) or 0.0
        if not duration:
            meta = getattr(result, "metadata", {}) or {}
            if isinstance(meta, dict):
                duration = float(
                    meta.get("duration_seconds")
                    or meta.get("elapsed_seconds")
                    or 0.0
                )
        health_db.record_module_run(
            module_name=module_name,
            domain=ctx.domain if hasattr(ctx, "domain") else None,
            status=status_value,
            duration_seconds=duration if duration else None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("platform_health: record_module_run failed: %s", exc)
    if ctx.on_module_complete is None:
        return
    try:
        ctx.on_module_complete(module_name, status_value, errors)
    except TypeError:
        with contextlib.suppress(Exception):
            ctx.on_module_complete(module_name, status_value)
    except Exception:  # noqa: BLE001
        logger.debug("on_module_complete(%s) raised", module_name, exc_info=True)


async def _attach_breach_enrichment(
    unique_emails: list[Any],
    module_results: dict[str, ModuleResult] | None = None,
    ctx: WorkerContext | None = None,
) -> None:
    """Phase 5 — run breach aggregation on confirmed emails only.

    Post-confirmation enrichment: only SMTP-/provider-verified mailboxes
    are probed; unverified pattern candidates are never sent to the breach
    sources.  Failures are swallowed so enrichment can never stall or fail
    the harvest tail.  Each confirmed email's ``breach_enrichment`` field is
    populated with privacy-safe finding dicts.
    """
    try:
        from ..modules.breach_aggregator import enrich_confirmed_emails

        telemetry_by_email: dict[str, dict[str, dict[str, Any]]] = {}
        enrichment = await enrich_confirmed_emails(
            unique_emails,
            settings,
            telemetry_by_email=telemetry_by_email,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("breach enrichment tail failed: %s", exc)
        if module_results is not None:
            module_results["breach_aggregator"] = ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"breach_aggregator: {exc}"],
                metadata={"sources": {}},
            )
        return

    by_email = {getattr(e, "email", None): e for e in unique_emails}
    for address, findings in enrichment.items():
        entry = by_email.get(address)
        if entry is not None:
            entry.breach_enrichment = [bf.to_finding() for bf in findings]

    if module_results is None:
        return

    source_names = ("scylla", "hibp_paste", "dehashed", "snusbase")
    source_rows: dict[str, dict[str, Any]] = {}
    for source in source_names:
        rows = [
            per_email.get(source, {})
            for per_email in telemetry_by_email.values()
            if isinstance(per_email.get(source), dict)
        ]
        statuses = [str(row.get("status", "not_run")) for row in rows]
        attempted = [status for status in statuses if status not in {"skipped", "not_run"}]
        if not rows or not attempted:
            status = "skipped"
        elif "rate_limited" in attempted:
            status = "rate_limited"
        elif "success" in attempted:
            status = "success"
        else:
            status = "error"
        source_rows[source] = {
            "status": status,
            "checked": sum(int(row.get("checked") or 0) for row in rows),
            "hits": sum(int(row.get("hits") or 0) for row in rows),
            "http_status": next(
                (row.get("http_status") for row in rows if row.get("http_status") is not None),
                None,
            ),
            "duration_seconds": round(
                sum(float(row.get("duration_seconds") or 0.0) for row in rows),
                3,
            ),
            "error": next(
                (row.get("error") for row in rows if row.get("error")),
                None,
            ),
        }

    total_hits = sum(row["hits"] for row in source_rows.values())
    attempted_rows = [
        row for row in source_rows.values() if row["status"] not in {"skipped", "not_run"}
    ]
    if not attempted_rows:
        status = ModuleStatus.SKIPPED
    elif any(row["status"] == "rate_limited" for row in attempted_rows):
        status = ModuleStatus.PARTIAL
    elif total_hits:
        status = ModuleStatus.SUCCESS
    elif all(row["status"] == "success" for row in attempted_rows):
        status = ModuleStatus.SUCCESS_EMPTY
    elif all(row["status"] == "error" for row in attempted_rows):
        status = ModuleStatus.FAILED
    else:
        status = ModuleStatus.PARTIAL

    breach_findings = [
        finding
        for findings in enrichment.values()
        for finding in findings
    ]
    metadata = {
        "sources": source_rows,
        "total_breach_records": len(breach_findings),
        "sources_with_password_data": sum(
            1
            for finding in breach_findings
            if finding.has_plaintext_password or finding.has_hash
        ),
        "source_types": sorted({finding.source_type for finding in breach_findings}),
    }
    result = ModuleResult(
        status=status,
        findings=[finding.to_finding() for finding in breach_findings],
        metadata=metadata,
    )
    module_results["breach_aggregator"] = result
    if ctx is not None:
        _emit_module_complete(ctx, "breach_aggregator", result)


def _employee_name_count(module_results: dict[str, ModuleResult]) -> int:
    result = module_results.get(MODULE_EMPLOYEE_NAMES)
    if result is None:
        return 0
    return len(result.findings or [])


def _record_work_failure(ctx: WorkerContext, work: WorkResult) -> None:
    """Surface worker exceptions in module results, health, and live progress."""
    module_name = work.item.module_name
    if work.success or not module_name:
        return
    result = ModuleResult(
        status=ModuleStatus.FAILED,
        errors=list(work.errors or ["module worker failed"]),
        metadata={
            "domain": ctx.domain,
            "duration_seconds": round(float(work.duration_seconds or 0.0), 3),
        },
    )
    _record_module_result(ctx, module_name, result)
    _emit_module_complete(ctx, module_name, result)
    logger.error("Harvest module %s failed: %s", module_name, "; ".join(result.errors))


def _prune_done(tasks: set[asyncio.Task[None]]) -> None:
    done = {task for task in tasks if task.done()}
    for task in done:
        tasks.remove(task)
        if task.cancelled():
            logger.warning("Harvest task was cancelled before completion")
            continue
        error = task.exception()
        if error is not None:
            logger.error("Harvest task failed: %r", error)


__all__ = [
    "WorkerContext",
    "run_adaptive_harvest",
    "_execute_item",
    "_fetch_and_extract",
    "_progress_loop",
    "_run_module",
    "_track1_loop",
    "_track2_loop",
]
