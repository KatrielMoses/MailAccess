"""Employee / executive name discovery — Phase C1 of the 0.10.0 rebuild.

Aggregates five independent name sources:

1. **LinkedIn-via-search-engine** — DDG + Bing dorkers reused from
   Phase B1 (``backend.core.linkedin_name_discovery``).
2. **Company pages** — direct fetch of about/team/leadership URLs
   on the target's own domain (``backend.core.company_page_names``).
3. **Press releases** — additive name extraction in
   ``backend.modules.press_intel`` (new ``signal_type="executive_name"``
   findings; existing phone findings are unchanged).
4. **SEC EDGAR** — additive name extraction in
   ``backend.modules.sec_edgar`` (same additive pattern as #3).
5. **OpenCorporates** — no module edit needed; ``opencorporates`` already
   surfaces officer names under ``metadata.officers``. We just read
   them.

This module produces ``NameDiscovery`` records consumed by Phase C2
(permutator → SMTP verifier). It does NOT generate email patterns or
verify addresses.

The three existing modules (press_intel, sec_edgar, opencorporates)
all expose an ``run(email: str)`` method that derives the target domain
from the email's local part. We call them with a synthetic
``any@<domain>`` value, then filter their findings for the relevant
``signal_type`` (or, for opencorporates, the ``officers`` field).
This avoids touching their existing behavior — the test that locks
in this contract is ``test_*_extension_does_not_break_existing_behavior``.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from ..config import settings
from ..core.bing_dorker import BingDorker
from ..core.company_page_names import (
    CompanyPageName,
    discover_company_page_names,
)
from ..core.duckduckgo_dorker import DuckDuckGoDorker
from ..core.http_client import build_client
from ..core.linkedin_name_discovery import discover_linkedin_names
from ..core.name_quality import is_plausible_person_name
from .base import BaseModule, ModuleResult, ModuleStatus

# Imported eagerly so monkeypatch.setattr works in tests; the three
# sub-source modules are tiny and only do I/O on demand anyway.
from .opencorporates import OpenCorporatesModule
from .press_intel import PressIntelModule
from .sec_edgar import SecEdgarModule

_LOG = logging.getLogger(__name__)

# Per-source confidence baselines (mirrors spec).
_SOURCE_CONFIDENCE: dict[str, float] = {
    "linkedin_search": 0.7,
    "company_page": 0.6,
    "press_release": 0.5,
    "sec_edgar": 0.55,
    "opencorporates": 0.65,
}

# Multi-source bonus (cumulative beyond 2 sources adds nothing).
_MULTI_SOURCE_BONUS: dict[int, float] = {
    1: 0.0,
    2: 0.15,
    3: 0.25,
}

_LABEL_FOR_SCORE_BOUNDARIES = (0.8, 0.5)  # >=0.8 high, 0.5-0.8 medium, else low


@dataclass
class NameDiscovery:
    name: str
    source: str
    source_url: str | None = None
    title_or_role: str | None = None
    confidence: float = 0.5


@dataclass
class EmployeeNameResult:
    name: str
    sources: list[str] = field(default_factory=list)
    source_count: int = 0
    title_or_role: str | None = None
    confidence: float = 0.5
    source_urls: list[str] = field(default_factory=list)


class EmployeeNameDiscoveryModule(BaseModule):
    name = "employee_name_discovery"
    description = (
        "Discovers employee / executive names tied to a domain for Phase C2 "
        "email-pattern generation."
    )
    requires_key = False
    default_enabled = False  # domain harvest mode only

    async def run(self, target: str) -> ModuleResult:  # type: ignore[override]
        if not settings.enable_employee_name_discovery:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "employee_name_discovery disabled — "
                    "set ENABLE_EMPLOYEE_NAME_DISCOVERY=true to enable"
                ],
            )

        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["employee_name_discovery: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        # ------------------------------------------------------------------
        # Source 1 — LinkedIn (reuse DDG/Bing dorkers from Phase B1)
        # ------------------------------------------------------------------
        linkedin_task = asyncio.create_task(self._linkedin(domain))
        # ------------------------------------------------------------------
        # Source 2 — Company pages (direct fetch)
        # ------------------------------------------------------------------
        company_task = asyncio.create_task(self._company_pages(domain))
        # ------------------------------------------------------------------
        # Sources 3 + 4 + 5 — Existing email-mode modules, invoked with a
        # synthetic email so they derive the domain cleanly. We pull the
        # NAME-only findings out via signal_type filtering.
        # ------------------------------------------------------------------
        press_task = asyncio.create_task(self._press_intel_names(domain))
        sec_task = asyncio.create_task(self._sec_edgar_names(domain))
        oc_task = asyncio.create_task(self._opencorporates_names(domain))

        outcomes = await asyncio.gather(
            linkedin_task,
            company_task,
            press_task,
            sec_task,
            oc_task,
            return_exceptions=True,
        )

        linkedin_findings: list[NameDiscovery] = self._unwrap(
            outcomes[0], default=[], label="linkedin_search"
        )
        company_findings: list[NameDiscovery] = self._unwrap(
            outcomes[1], default=[], label="company_page"
        )
        press_findings: list[NameDiscovery] = self._unwrap(
            outcomes[2], default=[], label="press_release"
        )
        sec_findings: list[NameDiscovery] = self._unwrap(
            outcomes[3], default=[], label="sec_edgar"
        )
        oc_findings: list[NameDiscovery] = self._unwrap(
            outcomes[4], default=[], label="opencorporates"
        )

        all_names: list[NameDiscovery] = (
            linkedin_findings
            + company_findings
            + press_findings
            + sec_findings
            + oc_findings
        )

        # Source-OK mask: True if that source finished without raising
        # (zero-name successes count as "OK" per spec).  A source that
        # raised is reflected as ``False`` here.
        source_ok = [
            outcomes[0] is not None and not isinstance(outcomes[0], BaseException),
            outcomes[1] is not None and not isinstance(outcomes[1], BaseException),
            outcomes[2] is not None and not isinstance(outcomes[2], BaseException),
            outcomes[3] is not None and not isinstance(outcomes[3], BaseException),
            outcomes[4] is not None and not isinstance(outcomes[4], BaseException),
        ]
        ok_count = sum(source_ok)

        # ------------------------------------------------------------------
        # Aggregate + boost + dedupe
        # ------------------------------------------------------------------
        aggregated: dict[str, EmployeeNameResult] = {}

        def _record(nd: NameDiscovery) -> None:
            cleaned = nd.name.strip()
            if not is_plausible_person_name(cleaned):
                return
            key = cleaned.lower()
            existing = aggregated.get(key)
            if existing is None:
                aggregated[key] = EmployeeNameResult(
                    name=cleaned,
                    sources=[nd.source],
                    source_count=1,
                    title_or_role=nd.title_or_role,
                    confidence=nd.confidence,
                    source_urls=[nd.source_url] if nd.source_url else [],
                )
                return
            if nd.source not in existing.sources:
                existing.sources.append(nd.source)
                existing.source_count += 1
                # Boost: top base confidence × (1 + bonus).
                best_base = max(existing.confidence, nd.confidence)
                bonus = _MULTI_SOURCE_BONUS.get(
                    min(existing.source_count, 3),
                    _MULTI_SOURCE_BONUS[3],
                )
                existing.confidence = min(best_base + bonus, 1.5)
                if nd.title_or_role and not existing.title_or_role:
                    existing.title_or_role = nd.title_or_role
            if nd.source_url and nd.source_url not in existing.source_urls:
                existing.source_urls.append(nd.source_url)

        for nd in all_names:
            _record(nd)

        # ------------------------------------------------------------------
        # Wrap into BaseModule's FindingItem shape so Phase C2's
        # orchestrator can consume via the standard findings pipeline.
        # ------------------------------------------------------------------
        findings: list[dict[str, Any]] = []
        multi_source_count = 0

        for key in sorted(aggregated):
            agg = aggregated[key]
            if agg.source_count >= 2:
                multi_source_count += 1
            label = _label_for_score(agg.confidence)
            findings.append(
                {
                    "platform": "employee_name_discovery",
                    "profile_url": agg.source_urls[0] if agg.source_urls else "",
                    "username": agg.name.replace(" ", "."),
                    "confidence": label,
                    "metadata": {
                        "name": agg.name,
                        "sources": sorted(agg.sources),
                        "source_count": agg.source_count,
                        "title_or_role": agg.title_or_role,
                        "confidence_score": round(agg.confidence, 4),
                        "source_urls": agg.source_urls,
                    },
                }
            )

        if ok_count == 0:
            status = ModuleStatus.FAILED
        elif ok_count == 1:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "domain": domain,
                "linkedin_names_found": len(linkedin_findings),
                "company_page_names_found": len(company_findings),
                "press_release_names_found": len(press_findings),
                "sec_edgar_names_found": len(sec_findings),
                "opencorporates_names_found": len(oc_findings),
                "total_unique_names": len(aggregated),
                "multi_source_confirmed_names": multi_source_count,
            },
        )

    # ----------------------------------------------------------------------
    # Source 1 — LinkedIn via search-engine dorking
    # ----------------------------------------------------------------------
    async def _linkedin(self, domain: str) -> list[NameDiscovery]:
        async with build_client(timeout=10.0, follow_redirects=True) as shared:
            ddg = DuckDuckGoDorker(transport=shared, min_interval=0.0)
            bing = BingDorker(transport=shared, min_interval=0.0)
            # Exceptions propagate to ``_unwrap`` via ``asyncio.gather`` so
            # the source-failure mask reflects reality.
            return await discover_linkedin_names(
                domain=domain, ddg=ddg, bing=bing
            )



    # ----------------------------------------------------------------------
    # Source 2 — Company pages (direct fetch)
    # ----------------------------------------------------------------------
    async def _company_pages(self, domain: str) -> list[NameDiscovery]:
        max_pages = max(
            1,
            int(getattr(settings, "employee_name_max_company_pages", 5) or 5),
        )
        async with build_client(timeout=5.0, follow_redirects=True) as shared:
            pages: list[CompanyPageName] = await discover_company_page_names(
                domain, transport=shared, max_pages=max_pages
            )
        return [
            NameDiscovery(
                name=p.name,
                source="company_page",
                source_url=p.source_url,
                title_or_role=p.title_or_role,
                confidence=p.confidence,
            )
            for p in pages
        ]



    # ----------------------------------------------------------------------
    # Sources 3 / 4 / 5 — Wrap the existing email-mode modules so we get
    # their domain-derived behavior without modifying them.
    # ----------------------------------------------------------------------
    async def _press_intel_names(self, domain: str) -> list[NameDiscovery]:
        synthetic = f"any@{domain}"
        result = await PressIntelModule().run(synthetic)



        names: list[NameDiscovery] = []
        for finding in result.findings:
            if not isinstance(finding, dict):
                continue
            meta = finding.get("metadata") or {}
            if finding.get("signal_type") != "executive_name":
                continue
            name = str(meta.get("name") or "").strip()
            if not name:
                continue
            names.append(
                NameDiscovery(
                    name=name,
                    source="press_release",
                    source_url=str(meta.get("source_url") or ""),
                    title_or_role=str(meta.get("press_release_title") or ""),
                    confidence=_SOURCE_CONFIDENCE["press_release"],
                )
            )
        return names

    async def _sec_edgar_names(self, domain: str) -> list[NameDiscovery]:
        synthetic = f"any@{domain}"
        result = await SecEdgarModule().run(synthetic)



        names: list[NameDiscovery] = []
        for finding in result.findings:
            if not isinstance(finding, dict):
                continue
            meta = finding.get("metadata") or {}
            if finding.get("signal_type") != "executive_name":
                continue
            name = str(meta.get("name") or "").strip()
            if not name:
                continue
            names.append(
                NameDiscovery(
                    name=name,
                    source="sec_edgar",
                    source_url=str(meta.get("filing_url") or ""),
                    title_or_role=str(meta.get("company_name") or ""),
                    confidence=_SOURCE_CONFIDENCE["sec_edgar"],
                )
            )
        return names

    async def _opencorporates_names(self, domain: str) -> list[NameDiscovery]:
        synthetic = f"any@{domain}"
        result = await OpenCorporatesModule().run(synthetic)



        names: list[NameDiscovery] = []
        for finding in result.findings:
            if not isinstance(finding, dict):
                continue
            meta = finding.get("metadata") or {}
            officers = meta.get("officers") or []
            if not isinstance(officers, list):
                continue
            for officer in officers:
                if not isinstance(officer, dict):
                    continue
                name = str(officer.get("name") or "").strip()
                if not name:
                    continue
                position = str(officer.get("position") or "").strip() or None
                names.append(
                    NameDiscovery(
                        name=name,
                        source="opencorporates",
                        source_url=str(finding.get("url") or ""),
                        title_or_role=position,
                        confidence=_SOURCE_CONFIDENCE["opencorporates"],
                    )
                )
        return names

    @staticmethod
    def _unwrap(
        outcome: Any, default: list[NameDiscovery], label: str
    ) -> list[NameDiscovery]:
        if isinstance(outcome, BaseException):
            _LOG.warning(
                "employee_name_discovery: %s task raised %s",
                label,
                outcome.__class__.__name__,
            )
            return list(default)
        if outcome is None:
            return list(default)
        return outcome


def _label_for_score(score: float) -> str:
    high, medium = _LABEL_FOR_SCORE_BOUNDARIES
    if score >= high:
        return "high"
    if score >= medium:
        return "medium"
    return "low"


def discover_names_for_tests(
    pages: list[CompanyPageName],
    linkedin: list[NameDiscovery],
    press: list[NameDiscovery],
    sec: list[NameDiscovery],
    oc: list[NameDiscovery],
) -> list[EmployeeNameResult]:
    """Pure helper for orchestrator unit tests — same dedupe + boost
    logic as :meth:`EmployeeNameDiscoveryModule.run`, but synchronous
    and only over the inputs you pass in.
    """
    all_names = linkedin + [
        NameDiscovery(name=p.name, source="company_page", source_url=p.source_url,
                      title_or_role=p.title_or_role, confidence=p.confidence)
        for p in pages
    ] + press + sec + oc
    aggregated: dict[str, EmployeeNameResult] = {}
    for nd in all_names:
        cleaned = nd.name.strip()
        if not is_plausible_person_name(cleaned):
            continue
        key = cleaned.lower()
        existing = aggregated.get(key)
        if existing is None:
            aggregated[key] = EmployeeNameResult(
                name=cleaned,
                sources=[nd.source],
                source_count=1,
                title_or_role=nd.title_or_role,
                confidence=nd.confidence,
                source_urls=[nd.source_url] if nd.source_url else [],
            )
            continue
        if nd.source not in existing.sources:
            existing.sources.append(nd.source)
            existing.source_count += 1
            best_base = max(existing.confidence, nd.confidence)
            bonus = _MULTI_SOURCE_BONUS.get(
                min(existing.source_count, 3),
                _MULTI_SOURCE_BONUS[3],
            )
            existing.confidence = min(best_base + bonus, 1.5)
            if nd.title_or_role and not existing.title_or_role:
                existing.title_or_role = nd.title_or_role
        if nd.source_url and nd.source_url not in existing.source_urls:
            existing.source_urls.append(nd.source_url)
    return list(aggregated.values())
