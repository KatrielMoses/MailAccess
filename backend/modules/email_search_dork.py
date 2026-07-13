"""Email discovery via search-engine dorking (DuckDuckGo + Bing HTML + Google CSE).

0.11.1 Phase 4 adds Google Custom Search Engine (CSE) as an optional
concurrent third engine.  When ``GOOGLE_CSE_API_KEY`` and
``GOOGLE_CSE_CX`` are both set, CSE runs alongside DDG and Bing.
CSE results receive the ``search_snippet_google_cse`` source type
(weight 0.55) and take priority in dedup over DDG/Bing results.

Design constraints (from the phase spec):

* All active engines run **concurrently** with each other.
* CAPTCHA / block detection aborts that engine immediately.
* Multi-engine hits fall into the ``multi_source`` multiplier branch
  via :func:`compute_confidence_breakdown`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from ..config import settings
from ..core.bing_dorker import BingDorker
from ..core.concurrent_fetch_cache import CachedFetch
from ..core.dork_queries import build_dork_queries
from ..core.duckduckgo_dorker import DuckDuckGoDorker
from ..core.email_confidence import compute_confidence_breakdown, label_for_score
from ..core.email_extraction import extract_emails
from ..core.http_client import build_client
from ..core.role_classifier import classify_email
from ..core.scrapingant import get_active_transport
from ..core.stealth_client import StealthSession, resolve_timing_profile
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_MAX_QUERIES_HARD_CAP = 50  # safety valve
_MAX_CONSECUTIVE_ENGINE_ERRORS = 2

_CSE_URL = "https://www.googleapis.com/customsearch/v1"
_CSE_RATE_LIMIT_DELAY = 1.0  # 1 req/sec


class _CseResult:
    """A single Google CSE result."""

    __slots__ = ("title", "snippet", "url", "query_used")

    def __init__(
        self,
        title: str,
        snippet: str,
        url: str,
        query_used: str,
    ) -> None:
        self.title = title
        self.snippet = snippet
        self.url = url
        self.query_used = query_used


async def _run_cse_query(
    client: httpx.AsyncClient,
    query: str,
    api_key: str,
    cx: str,
    max_results: int = 10,
) -> tuple[list[_CseResult], bool]:
    """Execute one Google CSE query.  Returns (results, blocked)."""
    try:
        resp = await client.get(
            _CSE_URL,
            params={"key": api_key, "cx": cx, "q": query},
            timeout=10.0,
        )
        if resp.status_code == 429:
            _LOG.warning("Google CSE rate limit hit for query=%r", query)
            return [], True
        if resp.status_code != 200:
            _LOG.warning(
                "Google CSE returned HTTP %s for query=%r",
                resp.status_code,
                query,
            )
            return [], False

        data = resp.json()
        items: list[dict[str, Any]] = data.get("items") or []
        return (
            [
                _CseResult(
                    title=str(item.get("title", "")),
                    snippet=str(item.get("snippet", "")),
                    url=str(item.get("link", "")),
                    query_used=query,
                )
                for item in items[:max_results]
            ],
            False,
        )
    except Exception as exc:
        _LOG.warning("Google CSE query failed for query=%r: %s", query, exc)
        return [], False


async def _cse_available() -> tuple[bool, str, str]:
    """Return (available, api_key, cx)."""
    api_key = getattr(settings, "google_cse_api_key", None) or ""
    cx = getattr(settings, "google_cse_cx", None) or ""
    available = bool(api_key and cx)
    return available, api_key, cx


class EmailSearchDorkModule(BaseModule):
    name = "email_search_dork"
    description = (
        "Email discovery via search engine dorking — "
        "DuckDuckGo, Bing HTML, and optional Google CSE."
    )
    requires_key = False
    default_enabled = False  # Opt-in: domain harvest mode only

    async def run(
        self,
        target: str,
        *,
        lite_mode: bool | None = None,
        aggressive: bool | None = None,
        use_proxies: bool = False,
        fetch: CachedFetch | None = None,
        signal_pool: Any | None = None,
    ) -> ModuleResult:  # type: ignore[override]
        if not settings.enable_email_search_dork:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["email_search_dork disabled — set ENABLE_EMAIL_SEARCH_DORK=true to enable"],
            )

        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["email_search_dork: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        effective_lite_mode = (
            bool(lite_mode) if lite_mode is not None else bool(settings.dork_lite_mode)
        )
        effective_aggressive = bool(aggressive) if aggressive is not None else bool(
            getattr(settings, "harvest_aggressive", False)
        )
        queries = build_dork_queries(
            domain, lite_mode=effective_lite_mode, aggressive=effective_aggressive
        )
        if not queries:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=["email_search_dork: no usable queries generated"],
                metadata={"domain": domain},
            )

        per_engine_cap = max(
            1,
            min(int(settings.dork_max_queries_per_engine), _MAX_QUERIES_HARD_CAP),
        )
        queries_for_run = queries[:per_engine_cap]

        ddg_delay = float(settings.dork_ddg_delay_seconds)
        bing_delay = float(settings.dork_bing_delay_seconds)

        ddg_findings: list[DorkRunSummary] = []
        bing_findings: list[DorkRunSummary] = []
        cse_findings: list[DorkRunSummary] = []
        ddg_blocked = False
        bing_blocked = False
        cse_blocked = False
        ddg_failed = False
        bing_failed = False
        cse_failed = False

        cse_available, cse_api_key, cse_cx = await _cse_available()

        # 0.11.1 Phase 4: build StealthSession for DDG/Bing.
        # 0.11.1 Phase 3 cache: when ``fetch`` is injected by the
        # orchestrator, the dorkers route through it instead of
        # building their own session.  The cache owns the per-run
        # StealthSession so the dorkers no longer construct one when
        # the cache is in play.
        if fetch is None:
            try:
                profile = resolve_timing_profile(settings.harvest_timing_profile)
                stealth_session: StealthSession | None = StealthSession(
                    timing_profile=profile,
                    impersonate=settings.harvest_impersonate_browser,
                )
            except ImportError as exc:
                _LOG.debug(
                    "email_search_dork: curl-cffi unavailable; using httpx "
                    "fallback (install 'mailaccess[harvest]'): %s",
                    exc,
                )
                stealth_session = None
        else:
            stealth_session = None

        client_factory = build_client
        client_kwargs: dict[str, Any] = {"timeout": 10.0, "follow_redirects": True}
        if use_proxies:
            client_kwargs["scrapingant_zone"] = "dorking"
            client_kwargs["strict_proxy"] = True

        try:
            async with client_factory(**client_kwargs) as shared_client:
                ddg = DuckDuckGoDorker(
                    transport=shared_client,
                    min_interval=ddg_delay,
                    scrapingant_zone="dorking",
                    stealth=stealth_session,
                    fetch=fetch,
                )
                bing = BingDorker(
                    transport=shared_client,
                    min_interval=bing_delay,
                    scrapingant_zone="dorking",
                    stealth=stealth_session,
                    fetch=fetch,
                )

                # CSE gets its own httpx client (different upstream).
                cse_client: httpx.AsyncClient | None = None
                if cse_available:
                    cse_client = httpx.AsyncClient(timeout=10.0)

                async def run_ddg() -> None:
                    nonlocal ddg_blocked, ddg_failed
                    consecutive_errors = 0
                    for q in queries_for_run:
                        results, captcha = await ddg.search(q.query)
                        error = getattr(ddg, "_last_error", None)
                        ddg_findings.append(
                            DorkRunSummary(query=q, results=results, error=error)
                        )
                        if error:
                            consecutive_errors += 1
                            if consecutive_errors >= _MAX_CONSECUTIVE_ENGINE_ERRORS:
                                ddg_failed = True
                                _LOG.warning(
                                    "email_search_dork: DDG fast-failed after %d consecutive errors",
                                    consecutive_errors,
                                )
                                return
                            continue
                        consecutive_errors = 0
                        if captcha:
                            ddg_blocked = True
                            return

                async def run_bing() -> None:
                    nonlocal bing_blocked, bing_failed
                    consecutive_errors = 0
                    for q in queries_for_run:
                        results, blocked = await bing.search(q.query)
                        error = getattr(bing, "_last_error", None)
                        bing_findings.append(
                            DorkRunSummary(query=q, results=results, error=error)
                        )
                        if error:
                            consecutive_errors += 1
                            if consecutive_errors >= _MAX_CONSECUTIVE_ENGINE_ERRORS:
                                bing_failed = True
                                _LOG.warning(
                                    "email_search_dork: Bing fast-failed after %d consecutive errors",
                                    consecutive_errors,
                                )
                                return
                            continue
                        consecutive_errors = 0
                        if blocked:
                            bing_blocked = True
                            return

                async def run_cse() -> None:
                    """Run all CSE queries sequentially (rate-limited 1/s)."""
                    nonlocal cse_blocked, cse_failed
                    if cse_client is None:
                        cse_failed = True
                        return
                    try:
                        for q in queries_for_run:
                            results, blocked = await _run_cse_query(
                                cse_client,
                                q.query,
                                cse_api_key,
                                cse_cx,
                            )
                            cse_findings.append(
                                DorkRunSummary(query=q, results=results, error=None)
                            )
                            if blocked:
                                cse_blocked = True
                                return
                            # Rate limit: 1 req/sec.
                            await asyncio.sleep(_CSE_RATE_LIMIT_DELAY)
                    except Exception as exc:
                        _LOG.warning("email_search_dork: CSE task crashed: %s", exc)
                        cse_failed = True
                    finally:
                        if cse_client is not None:
                            await cse_client.aclose()

                # Build the task list — CSE is only included when configured.
                tasks_kw: dict[str, Any] = {
                    "ddg": asyncio.create_task(run_ddg()),
                    "bing": asyncio.create_task(run_bing()),
                }
                if cse_available:
                    tasks_kw["cse"] = asyncio.create_task(run_cse())

                outcomes = await asyncio.gather(
                    *[tasks_kw[k] for k in tasks_kw],
                    return_exceptions=True,
                )
                outcome_map = dict(zip(tasks_kw.keys(), outcomes))

        except Exception as exc:
            _LOG.error("email_search_dork: shared client crashed: %s", exc)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"email_search_dork: shared client error: {exc}"],
                metadata={"domain": domain},
            )

        if isinstance(outcome_map.get("ddg"), BaseException):
            ddg_failed = True
            _LOG.warning("email_search_dork: DDG task crashed: %s", outcome_map["ddg"])
        if isinstance(outcome_map.get("bing"), BaseException):
            bing_failed = True
            _LOG.warning("email_search_dork: Bing task crashed: %s", outcome_map["bing"])

        # ------------------------------------------------------------------
        # Aggregate per-engine SearchResult → emails
        # ------------------------------------------------------------------
        # email -> {
        #   "ddg": bool, "bing": bool, "cse": bool,
        #   "queries": list[str], "snippets": list[str], "on_domain": bool,
        # }
        aggregated: dict[str, dict[str, Any]] = {}

        def _ingest(engine: str, summary: DorkRunSummary) -> None:
            for result in summary.results:
                combined = f"{result.title}\n{result.snippet}"
                for extracted in extract_emails(combined, target_domain=domain):
                    bucket = aggregated.setdefault(
                        extracted.email,
                        {
                            "ddg": False,
                            "bing": False,
                            "cse": False,
                            "queries": [],
                            "snippets": [],
                            "on_domain": False,
                        },
                    )
                    bucket[engine] = True  # type: ignore[index]
                    bucket["queries"].append(summary.query.query)  # type: ignore[index]
                    if extracted.on_domain:
                        bucket["on_domain"] = True  # type: ignore[index]
                    if extracted.source_text_snippet:
                        bucket["snippets"].append(  # type: ignore[index]
                            extracted.source_text_snippet
                        )

        for summary in ddg_findings:
            _ingest("ddg", summary)
        for summary in bing_findings:
            _ingest("bing", summary)
        for summary in cse_findings:
            _ingest("cse", summary)

        # ------------------------------------------------------------------
        # Build findings
        # ------------------------------------------------------------------
        findings: list[dict[str, Any]] = []
        on_domain_count = 0
        role_count = 0
        personal_count = 0
        dual_engine_confirmed = 0

        for email, data in sorted(aggregated.items()):
            source_types: list[str] = []
            if data["ddg"]:
                source_types.append("search_snippet_ddg")
            if data["bing"]:
                source_types.append("search_snippet_bing")
            if data["cse"]:
                source_types.append("search_snippet_google_cse")

            confidence_info = compute_confidence_breakdown(
                source_types=source_types,
                is_smtp_verified=False,
                is_ca_attested=False,
                oldest_timestamp=None,
            )
            classification = classify_email(email)

            if data["on_domain"]:
                on_domain_count += 1

            active_engines = sum(1 for k in ("ddg", "bing", "cse") if data.get(k))
            if active_engines >= 2:
                dual_engine_confirmed += 1

            local_part = email.split("@", 1)[0]
            on_domain = bool(data["on_domain"])

            findings.append(
                {
                    "platform": "email_search_dork",
                    "profile_url": f"https://{domain}" if on_domain else "",
                    "username": local_part,
                    "confidence": label_for_score(confidence_info.score).lower(),
                    "metadata": {
                        "email": email,
                        "on_domain": on_domain,
                        "found_via_ddg": bool(data["ddg"]),
                        "found_via_bing": bool(data["bing"]),
                        "found_via_cse": bool(data["cse"]),
                        "matching_queries": sorted(set(data["queries"]))[:8],
                        "is_role": classification.is_role,
                        "role_match_type": classification.match_type,
                        "role_confidence": classification.confidence,
                        "role_matched_prefix": classification.matched_prefix,
                        "source_types": source_types,
                        "confidence_score": round(confidence_info.score, 4),
                        "confidence_breakdown": confidence_info.breakdown,
                        "sample_snippet": (data["snippets"][0] if data["snippets"] else ""),
                    },
                }
            )
            if classification.is_role:
                role_count += 1
            else:
                personal_count += 1

        # ------------------------------------------------------------------
        # Module status
        # ------------------------------------------------------------------
        ddg_has_error = any(s.error for s in ddg_findings)
        bing_has_error = any(s.error for s in bing_findings)
        cse_has_error = any(s.error for s in cse_findings)
        ddg_all_empty = ddg_findings and all(not s.results for s in ddg_findings)
        bing_all_empty = bing_findings and all(not s.results for s in bing_findings)
        cse_all_empty = cse_findings and all(not s.results for s in cse_findings)

        # Collect active blocked/failed flags.
        any_blocked = ddg_blocked or bing_blocked or cse_blocked
        any_failed = ddg_failed or bing_failed or cse_failed

        if (any_failed and not cse_available) or (ddg_failed and bing_failed and cse_failed):
            status = ModuleStatus.FAILED
        elif (
            any_failed
            or any_blocked
            or (ddg_all_empty and ddg_has_error)
            or (bing_all_empty and bing_has_error)
            or (cse_available and cse_all_empty and cse_has_error)
        ):
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS

        errors: list[str] = []
        for s in ddg_findings:
            if s.error:
                errors.append(f"[DuckDuckGo] {s.error}")
        for s in bing_findings:
            if s.error:
                errors.append(f"[Bing] {s.error}")
        for s in cse_findings:
            if s.error:
                errors.append(f"[Google CSE] {s.error}")

        return ModuleResult(
            status=status,
            findings=findings,
            errors=errors,
            metadata={
                "domain": domain,
                "ddg_queries_run": len(ddg_findings),
                "bing_queries_run": len(bing_findings),
                "cse_queries_run": len(cse_findings),
                "ddg_results_collected": sum(len(s.results) for s in ddg_findings),
                "bing_results_collected": sum(len(s.results) for s in bing_findings),
                "cse_results_collected": sum(len(s.results) for s in cse_findings),
                "ddg_blocked": ddg_blocked,
                "bing_blocked": bing_blocked,
                "cse_blocked": cse_blocked,
                "ddg_failed": ddg_failed,
                "bing_failed": bing_failed,
                "cse_failed": cse_failed,
                "cse_available": cse_available,
                "total_emails_found": len(aggregated),
                "on_domain_emails": on_domain_count,
                "role_accounts": role_count,
                "personal_emails": personal_count,
                "dual_engine_confirmed": dual_engine_confirmed,
                "lite_mode": effective_lite_mode,
                "aggressive": effective_aggressive,
                "use_proxies": use_proxies,
                "active_scrapingant_transport": get_active_transport()
                if use_proxies
                else None,
            },
        )


class DorkRunSummary:
    """Internal: one query's worth of results, kept for debugging/extension."""

    __slots__ = ("query", "results", "error")

    def __init__(
        self, query: Any, results: list[Any], error: str | None = None
    ) -> None:
        self.query = query
        self.results = results
        self.error = error
