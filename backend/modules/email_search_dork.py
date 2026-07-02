"""Email discovery via search-engine dorking (DuckDuckGo + Bing HTML).

The orchestrator module for Phase B1 of the 0.10.0 rebuild.  Builds
dork queries, runs them across two free engines, and merges the
results into the same FindingItem shape Phase A's
``commoncrawl_email`` produces.

Design constraints (from the phase spec):

* Both engines run **concurrently** with each other; queries within
  each engine run sequentially (because rate-limits are per-source).
* CAPTCHA / block detection aborts that engine immediately and
  returns whatever was already collected — we never retry against
  a rate-limit wall.
* Multi-engine hits naturally fall into the ``multi_source`` 1.2
  multiplier branch via :func:`compute_confidence_breakdown`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..config import settings
from ..core.bing_dorker import BingDorker
from ..core.dork_queries import build_dork_queries
from ..core.duckduckgo_dorker import DuckDuckGoDorker
from ..core.email_confidence import compute_confidence_breakdown, label_for_score
from ..core.email_extraction import extract_emails
from ..core.http_client import build_client
from ..core.role_classifier import classify_email
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_MAX_QUERIES_HARD_CAP = 50  # safety valve — never query more than this


class EmailSearchDorkModule(BaseModule):
    name = "email_search_dork"
    description = (
        "Email discovery via search engine dorking — DuckDuckGo and Bing HTML."
    )
    requires_key = False
    default_enabled = False  # Opt-in: domain harvest mode only

    async def run(
        self,
        target: str,
        *,
        lite_mode: bool | None = None,
    ) -> ModuleResult:  # type: ignore[override]
        """Run dorking for email discovery.

        Parameters
        ----------
        target:
            Target domain (e.g. ``"example.com"``).
        lite_mode:
            Explicit lite-mode override. MUST-FIX M3: when the
            orchestrator calls this method it MUST pass ``lite_mode``
            explicitly; ``None`` falls back to ``settings.dork_lite_mode``
            only for standalone/test use. This eliminates the previous
            race where the CLI mutated ``settings.dork_lite_mode``
            globally and any concurrent reader saw the wrong value.
        """
        if not settings.enable_email_search_dork:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "email_search_dork disabled — set ENABLE_EMAIL_SEARCH_DORK=true to enable"
                ],
            )

        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["email_search_dork: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        # MUST-FIX M3: explicit parameter wins; settings is a fallback
        # for standalone callers that don't pass it.
        effective_lite_mode = (
            bool(lite_mode)
            if lite_mode is not None
            else bool(settings.dork_lite_mode)
        )
        queries = build_dork_queries(
            domain, lite_mode=effective_lite_mode
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

        # ddg_results / bing_results accumulate findings from each engine.
        ddg_findings: list[DorkRunSummary] = []
        bing_findings: list[DorkRunSummary] = []
        ddg_blocked = False
        bing_blocked = False
        ddg_failed = False
        bing_failed = False

        try:
            async with build_client(timeout=10.0, follow_redirects=True) as shared_client:
                ddg = DuckDuckGoDorker(
                    transport=shared_client, min_interval=ddg_delay
                )
                bing = BingDorker(
                    transport=shared_client, min_interval=bing_delay
                )

                async def run_ddg() -> None:
                    nonlocal ddg_blocked
                    for q in queries_for_run:
                        results, captcha = await ddg.search(q.query)
                        ddg_findings.append(
                            DorkRunSummary(query=q, results=results)
                        )
                        if captcha:
                            ddg_blocked = True
                            return

                async def run_bing() -> None:
                    nonlocal bing_blocked
                    for q in queries_for_run:
                        results, blocked = await bing.search(q.query)
                        bing_findings.append(
                            DorkRunSummary(query=q, results=results)
                        )
                        if blocked:
                            bing_blocked = True
                            return

                # Run both engines concurrently — *different* IP/domain
                # pools, so the per-engine rate limiters don't collide.
                ddg_task = asyncio.create_task(run_ddg())
                bing_task = asyncio.create_task(run_bing())
                outcomes = await asyncio.gather(
                    ddg_task, bing_task, return_exceptions=True
                )
        except Exception as exc:
            _LOG.error("email_search_dork: shared client crashed: %s", exc)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"email_search_dork: shared client error: {exc}"],
                metadata={"domain": domain},
            )

        if isinstance(outcomes[0], BaseException):
            ddg_failed = True
            _LOG.warning("email_search_dork: DDG task crashed: %s", outcomes[0])
        if isinstance(outcomes[1], BaseException):
            bing_failed = True
            _LOG.warning("email_search_dork: Bing task crashed: %s", outcomes[1])

        # ------------------------------------------------------------------
        # Aggregate per-engine SearchResult -> emails
        # ------------------------------------------------------------------
        # email -> {
        #     "ddg": bool, "bing": bool,
        #     "queries": list[str], "snippets": list[str], "on_domain": bool,
        # }
        aggregated: dict[str, dict[str, Any]] = {}

        def _ingest(engine: str, summary: DorkRunSummary) -> None:
            for result in summary.results:
                # Combine title + snippet — DDG/Bing snippets are short,
                # so this maximises recall without ballooning work.
                combined = f"{result.title}\n{result.snippet}"
                for extracted in extract_emails(combined, target_domain=domain):
                    bucket = aggregated.setdefault(
                        extracted.email,
                        {
                            "ddg": False,
                            "bing": False,
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

            confidence_info = compute_confidence_breakdown(
                source_types=source_types,
                is_smtp_verified=False,
                is_ca_attested=False,
                oldest_timestamp=None,  # snippet timestamps unavailable
            )
            classification = classify_email(email)

            if data["on_domain"]:
                on_domain_count += 1
            if data["ddg"] and data["bing"]:
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
        if (ddg_failed and bing_failed) or (not ddg_findings and not bing_findings):
            status = ModuleStatus.FAILED
        elif (ddg_blocked or ddg_failed) and (bing_blocked or bing_failed):
            status = ModuleStatus.FAILED
        elif ddg_blocked or ddg_failed or bing_blocked or bing_failed:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "domain": domain,
                "ddg_queries_run": len(ddg_findings),
                "bing_queries_run": len(bing_findings),
                "ddg_results_collected": sum(
                    len(s.results) for s in ddg_findings
                ),
                "bing_results_collected": sum(
                    len(s.results) for s in bing_findings
                ),
                "ddg_blocked": ddg_blocked,
                "bing_blocked": bing_blocked,
                "ddg_failed": ddg_failed,
                "bing_failed": bing_failed,
                "total_emails_found": len(aggregated),
                "on_domain_emails": on_domain_count,
                "role_accounts": role_count,
                "personal_emails": personal_count,
                "dual_engine_confirmed": dual_engine_confirmed,
                "lite_mode": effective_lite_mode,
            },
        )


class DorkRunSummary:
    """Internal: one query's worth of results, kept for debugging/extension."""

    __slots__ = ("query", "results")

    def __init__(self, query: Any, results: list[Any]) -> None:
        self.query = query
        self.results = results
