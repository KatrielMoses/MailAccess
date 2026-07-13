"""Adaptive two-track runner for domain harvest mode."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..config import Settings, settings
from ..modules.base import ModuleResult, ModuleStatus
from ..modules.code_and_cert_email import CodeAndCertEmailModule
from ..modules.commoncrawl_email import CommonCrawlEmailModule
from ..modules.email_search_dork import EmailSearchDorkModule
from ..modules.employee_name_discovery import EmployeeNameDiscoveryModule
from ..modules.github_org_members import GitHubOrgMembersModule
from ..modules.npm_email import NpmEmailModule
from ..modules.pattern_and_verify import PatternAndVerifyModule
from ..modules.pgp_domain_email import PgpDomainEmailModule
from ..modules.pypi_email import PyPIEmailModule
from ..modules.syndication_feed_sweeper import SyndicationFeedSweeper
from ..modules.wayback import WaybackDomainHarvestModule
from ..modules.wordpress_rest import WordPressRestModule
from .concurrent_fetch_cache import CachedFetch, ConcurrentFetchCache
from .context_router import IndustryVocabularyRouter
from .email_extraction import extract_emails
from .pagination_handler import PaginationHandler
from .signal_pool import AsyncSignalPool
from .stealth_client import StealthSession, resolve_timing_profile
from .time_budget import TimeBudget
from .work_scheduler import (
    PRIORITY_ARCHIVE,
    PRIORITY_GUARANTEED,
    PRIORITY_HIGH_SIGNAL,
    PRIORITY_REGISTRY,
    PRIORITY_ROUTER_EXPANSION,
    PRIORITY_SEARCH,
    PRIORITY_UNIVERSAL,
    TRACK_GUARANTEED,
    TRACK_OPPORTUNISTIC,
    WorkItem,
    WorkResult,
    WorkScheduler,
)

logger = logging.getLogger(__name__)

MODULE_COMMONCRAWL = "commoncrawl_email"
MODULE_WAYBACK_DOMAIN = "wayback_domain_harvest"
MODULE_CODE_CERT = "code_and_cert_email"
MODULE_EMAIL_DORK = "email_search_dork"
MODULE_NPM_EMAIL = "npm_email"
MODULE_PYPI_EMAIL = "pypi_email"
MODULE_PGP_DOMAIN_EMAIL = "pgp_domain_email"
MODULE_GITHUB_ORG_MEMBERS = "github_org_members"
MODULE_EMPLOYEE_NAMES = "employee_name_discovery"
MODULE_PATTERN_VERIFY = "pattern_and_verify"
MODULE_PERSON_EMAIL_PIVOT = "person_email_pivot"
MODULE_EMAIL_IDENTITY_ENRICHMENT = "email_identity_enrichment"
MODULE_WORDPRESS_REST = "wordpress_rest"
MODULE_SYNDICATION_FEED_SWEEPER = "syndication_feed_sweeper"
MODULE_HUNTER = "hunter"
_PERSON_PIVOT_MODULES = frozenset(
    {MODULE_EMPLOYEE_NAMES, MODULE_PATTERN_VERIFY, MODULE_PERSON_EMAIL_PIVOT, MODULE_EMAIL_IDENTITY_ENRICHMENT, "name_to_github_profile"}
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
    use_proxies: bool = False
    aggressive: bool = False
    module_results: dict[str, ModuleResult] | None = None
    on_module_complete: Any | None = None
    module_overrides: dict[str, Any] | None = None
    dork_lite_mode: bool | None = None
    cc_max_records: int | None = None
    cc_max_collections: int | None = None
    proxy_fallback_ok: bool = False


async def run_adaptive_harvest(
    domain: str,
    timeout_seconds: float,
    enable_smtp: bool = False,
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
) -> Any:
    from .domain_harvest_orchestrator import (
        DomainHarvestResult,
        _aggregate,
        _sort_key,
        _validate_domain,
    )

    cleaned = _validate_domain(domain)
    started = datetime.now(timezone.utc)
    started_iso = started.isoformat().replace("+00:00", "Z")
    scheduler = WorkScheduler()
    signal_pool = AsyncSignalPool(export_threshold=0.0)
    signal_pool.set_scheduler(scheduler)
    budget = TimeBudget(timeout_seconds)
    session = StealthSession(timing_profile=resolve_timing_profile(timing_profile))
    cache = ConcurrentFetchCache(session)
    page_cache = CachedFetch(cache)
    module_results: dict[str, ModuleResult] = {}
    ctx = WorkerContext(
        domain=cleaned,
        scheduler=scheduler,
        signal_pool=signal_pool,
        page_cache=page_cache,
        budget=budget,
        stealth_session=session,
        settings=settings,
        enable_smtp=enable_smtp,
        use_proxies=use_proxies,
        aggressive=aggressive,
        module_results=module_results,
        on_module_complete=on_module_complete,
        module_overrides=module_overrides or {},
        dork_lite_mode=dork_lite_mode,
        cc_max_records=cc_max_records,
        cc_max_collections=cc_max_collections,
        proxy_fallback_ok=proxy_fallback_ok,
    )

    await _seed_scheduler(ctx)

    from ..modules.name_to_github_profile import _github_name_pivot
    
    signal_pool.register_name_subscriber(_on_name_found)
    signal_pool.register_name_subscriber(_github_name_pivot)
    if enable_email_identity_enrichment:
        enrichment_seen: set[str] = set()
        signal_pool.register_email_subscriber(
            lambda email, source, metadata: _on_email_found(
                email, source, metadata, enrichment_seen
            )
        )

    try:
        await asyncio.wait_for(_run_tracks(ctx), timeout=timeout_seconds)
    except TimeoutError:
        budget.mark_exhausted()
        logger.info("Budget exhausted - returning partial results")
    except Exception as exc:  # noqa: BLE001
        logger.error("Track failure: %s", exc)

    try:
        # Flush subscriber work before taking the identity-cluster snapshot.
        await signal_pool.close()
        identity_clusters = await signal_pool.all_candidates()
        unique_emails = _aggregate(
            cleaned,
            module_results,
            signal_pool=signal_pool,
            identity_clusters=identity_clusters,
        )
        unique_emails.sort(key=_sort_key)
        completed = datetime.now(timezone.utc)
        completed_iso = completed.isoformat().replace("+00:00", "Z")
        duration = (completed - started).total_seconds()
        high = sum(
            1
            for e in unique_emails
            if e.confidence_label == "HIGH" and not e.is_role
        )
        medium = sum(
            1
            for e in unique_emails
            if e.confidence_label == "MEDIUM" and not e.is_role
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
        }
        return DomainHarvestResult(
            domain=cleaned,
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
            personal_email_count=len(unique_emails) - role,
            errors=errors,
            smtp_verification_used=bool(
                pattern_meta.get("smtp_verification_enabled", False)
            ),
            catchall_detected=pattern_meta.get("is_catchall"),
            confirmed_pattern=pattern_meta.get("confirmed_pattern")
            or (confirmed_patterns[0] if confirmed_patterns else None),
            employee_names_processed=_employee_name_count(module_results),
            fetch_cache_stats=cache.stats(),
            metadata=metadata,
        )
    finally:
        with contextlib.suppress(Exception):
            await signal_pool.close()
        with contextlib.suppress(Exception):
            await cache.aclose()


async def _seed_scheduler(ctx: WorkerContext) -> None:
    homepage = await _read_homepage_for_router(ctx)
    router_result = IndustryVocabularyRouter().route(homepage)
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
    await ctx.scheduler.submit(
        WorkItem(
            kind="fetch_page",
            url=f"https://{ctx.domain}/",
            priority=PRIORITY_GUARANTEED,
            track=TRACK_GUARANTEED,
            source="homepage",
        )
    )

    seeds = (
        (MODULE_COMMONCRAWL, PRIORITY_ARCHIVE),
        (MODULE_WAYBACK_DOMAIN, PRIORITY_ARCHIVE),
        (MODULE_CODE_CERT, PRIORITY_HIGH_SIGNAL),
        (MODULE_EMAIL_DORK, PRIORITY_SEARCH),
        (MODULE_NPM_EMAIL, PRIORITY_REGISTRY),
        (MODULE_PYPI_EMAIL, PRIORITY_REGISTRY),
        (MODULE_PGP_DOMAIN_EMAIL, PRIORITY_REGISTRY),
        (MODULE_GITHUB_ORG_MEMBERS, PRIORITY_HIGH_SIGNAL),
        (MODULE_EMPLOYEE_NAMES, PRIORITY_UNIVERSAL),
        (MODULE_WORDPRESS_REST, PRIORITY_HIGH_SIGNAL),
        (MODULE_SYNDICATION_FEED_SWEEPER, PRIORITY_UNIVERSAL),
        # Phase 3: pattern_and_verify is always seeded so it appears in
        # module_results even when no employee names are found (the mock-based
        # test path). In real harvests it also fires via signal emission.
        (MODULE_PATTERN_VERIFY, PRIORITY_UNIVERSAL),
    )
    for module_name, priority in seeds:
        await ctx.scheduler.submit(
            WorkItem(
                kind="run_module",
                module_name=module_name,
                priority=priority,
                track=TRACK_OPPORTUNISTIC,
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
        await asyncio.gather(*tracks)
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
            for new_item in result.new_items:
                await ctx.scheduler.submit(new_item)
            _write_to_signal_pool(result, ctx.signal_pool)

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

    if running:
        await asyncio.gather(*running, return_exceptions=True)
    ctx.budget.mark_track1_closed()


async def _track2_loop(ctx: WorkerContext, concurrency: int = 5) -> None:
    sem = asyncio.Semaphore(concurrency)
    running: set[asyncio.Task[None]] = set()

    async def _run_one(item: WorkItem) -> None:
        async with sem:
            result = await _execute_item(item, ctx)
            for new_item in result.new_items:
                if new_item.track == TRACK_GUARANTEED:
                    new_item.track = TRACK_OPPORTUNISTIC
                await ctx.scheduler.submit(new_item)
            _write_to_signal_pool(result, ctx.signal_pool)

    def _is_person_pivot(item: WorkItem) -> bool:
        return (
            item.kind == "generate_patterns"
            or item.module_name in _PERSON_PIVOT_MODULES
            or item.source.startswith("name_subscriber:")
        )

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
            await asyncio.sleep(0)
            continue
        if not ctx.budget.can_start_track2(person_pivot=_is_person_pivot(item)):
            # Put the non-pivot work back and preserve the final budget tail
            # for names discovered late in the run.
            await ctx.scheduler.requeue(item)
            break
        task = asyncio.create_task(_run_one(item))
        running.add(task)

    if running:
        await asyncio.gather(*running, return_exceptions=True)


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
        if item.kind == "fetch_page" and item.url:
            findings, new_items = await _fetch_and_extract(item.url, ctx)
        elif item.kind == "run_module" and item.module_name:
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
    module = _get_module_instance(module_name, ctx)
    try:
        result = await asyncio.wait_for(
            _run_module_instance(module_name, module, ctx, soft_timeout),
            timeout=soft_timeout,
        )
    except asyncio.TimeoutError:
        return [], []

    if ctx.module_results is not None:
        ctx.module_results[module_name] = result
    _emit_module_complete(ctx, module_name, result)
    for finding in result.findings or []:
        _emit_finding(ctx.signal_pool, module_name, finding, ctx.domain)
    
    out_findings = [dict(f) for f in (result.findings or []) if isinstance(f, dict)]
    new_items = result.new_items if hasattr(result, "new_items") else []
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

async def _run_module_with_payload(
    module_name: str,
    module: Any,
    payload: dict,
    ctx: WorkerContext,
    soft_timeout: float,
) -> tuple[list[dict[str, Any]], list[WorkItem]]:
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
        result = await asyncio.wait_for(
            run_with_payload(payload, **kwargs),
            timeout=soft_timeout,
        )
    except asyncio.TimeoutError:
        return [], []

    if ctx.module_results is not None:
        ctx.module_results[module_name] = result
    _emit_module_complete(ctx, module_name, result)
    for finding in result.findings or []:
        _emit_finding(ctx.signal_pool, module_name, finding, ctx.domain)
        
    out_findings = [dict(f) for f in (result.findings or []) if isinstance(f, dict)]
    new_items = result.new_items if hasattr(result, "new_items") else []
    return out_findings, new_items

async def _run_pattern_for_name(
    payload: dict,
    ctx: WorkerContext
) -> tuple[list[dict], list[WorkItem]]:
    name = payload["name"]
    domain = ctx.domain

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

    confidence = float(metadata.get(
        "confidence_score", 0.5
    ))
    medium_threshold = float(
        getattr(settings, "pattern_medium_confidence_threshold", 0.50) or 0.50
    )
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
    has_title = bool(str(metadata.get("title_or_role", "")).strip())
    templates = None if has_title else _PATTERN_TEMPLATES[:3]
    return [WorkItem(
        kind="generate_patterns",
        module_name=MODULE_PATTERN_VERIFY,
        payload={
            "name": name,
            "title": metadata.get("title_or_role", ""),
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
        MODULE_PGP_DOMAIN_EMAIL: PgpDomainEmailModule,
        MODULE_GITHUB_ORG_MEMBERS: GitHubOrgMembersModule,
        MODULE_EMPLOYEE_NAMES: EmployeeNameDiscoveryModule,
        MODULE_PATTERN_VERIFY: PatternAndVerifyModule,
        MODULE_WORDPRESS_REST: WordPressRestModule,
        MODULE_SYNDICATION_FEED_SWEEPER: SyndicationFeedSweeper,
    }
    
    from ..modules.name_to_github_profile import NameToGitHubProfileModule
    from ..modules.person_email_pivot import PersonEmailPivotModule
    from ..modules.email_identity_enrichment import EmailIdentityEnrichmentModule
    from ..modules.security_txt import SecurityTxtModule
    
    factories["security_txt"] = SecurityTxtModule
    factories["name_to_github_profile"] = NameToGitHubProfileModule
    factories[MODULE_PERSON_EMAIL_PIVOT] = PersonEmailPivotModule
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
    for finding in result.findings:
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
        )


def _emit_module_complete(
    ctx: WorkerContext,
    module_name: str,
    result: ModuleResult,
) -> None:
    if ctx.on_module_complete is None:
        return
    status_value = result.status.value if hasattr(result.status, "value") else str(result.status)
    errors = list(result.errors or [])
    try:
        ctx.on_module_complete(module_name, status_value, errors)
    except TypeError:
        with contextlib.suppress(Exception):
            ctx.on_module_complete(module_name, status_value)
    except Exception:  # noqa: BLE001
        logger.debug("on_module_complete(%s) raised", module_name, exc_info=True)


def _employee_name_count(module_results: dict[str, ModuleResult]) -> int:
    result = module_results.get(MODULE_EMPLOYEE_NAMES)
    if result is None:
        return 0
    return len(result.findings or [])


def _prune_done(tasks: set[asyncio.Task[None]]) -> None:
    done = {task for task in tasks if task.done()}
    for task in done:
        tasks.remove(task)


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
