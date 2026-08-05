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
import re
from dataclasses import dataclass, field
from typing import Any

from ..config import settings
from ..core.bing_dorker import BingDorker
from ..core.company_page_names import (
    CompanyPageName,
    PersonRecord,
    discover_and_extract,
)
from ..core.duckduckgo_dorker import DuckDuckGoDorker
from ..core.http_client import build_client
from ..core.linkedin_name_discovery import discover_linkedin_names
from ..core.name_classifier import classify_name
from ..core.scrapingant import get_active_transport
from ..core.stealth_client import StealthSession, resolve_timing_profile
from .base import BaseModule, ModuleResult, ModuleStatus

# Imported eagerly so monkeypatch.setattr works in tests; the three
# sub-source modules are tiny and only do I/O on demand anyway.
from .opencorporates import OpenCorporatesModule
from .press_intel import PressIntelModule
from .sec_edgar import SecEdgarModule

_LOG = logging.getLogger(__name__)

# P3: role-aware format inference.  Titles cluster into two
# real-world behavioural buckets: executives and seniors.  Each
# bucket correlates with a different expected email template —
# founders/presidents tend to use ``{first}@`` (short, brand-
# forward), senior ICs and managers tend to use ``{first}.{last}@``
# (formal).  The regexes are intentionally loose and word-
# bounded so a title like ``"Co-founder & CTO"`` matches both
# ``founder`` AND ``cto`` in the same regex pass.
_EXECUTIVE_RE: re.Pattern[str] = re.compile(
    r"\b(?:"
    r"founder|co[\s\-]?founder|founding|"
    r"ceo|cto|cfo|coo|cmo|cio|cpo|"
    r"president|owner|chairman|chairwoman|chair"
    r")\b",
    re.IGNORECASE,
)
_SENIOR_RE: re.Pattern[str] = re.compile(
    r"\b(?:"
    r"lead|principal|staff|senior|manager|head(?:[\s\-]of)?|"
    r"director|vp|vice[\s\-]?president"
    r")\b",
    re.IGNORECASE,
)

# P3: the per-bucket × per-template adjustments.  Negative
# values demote, positive values boost.  These match the
# spec: executives on ``{first}@`` get +0.20; on ``{first}.{last}@``
# get -0.10; seniors on ``{first}.{last}@`` get +0.10.
_ROLE_FORMAT_DELTAS: dict[tuple[str, str], float] = {
    ("executive", "{first}@{domain}"): 0.20,
    ("executive", "{first}.{last}@{domain}"): -0.10,
    ("senior", "{first}.{last}@{domain}"): 0.10,
}


def classify_role_bucket(title: str | None) -> str | None:
    """Return ``"executive"`` / ``"senior"`` / ``None`` for *title*.

    Executive wins over senior when a title matches both
    (e.g. ``"Co-founder & CEO"`` is an executive, not a
    senior — founders/CTOs/CEOs have higher signal weight).
    Senior is the fallback bucket for ICs and managers.
    Unknown titles return ``None`` so the caller knows not
    to apply any role-format delta.
    """
    if not title:
        return None
    if _EXECUTIVE_RE.search(title):
        return "executive"
    if _SENIOR_RE.search(title):
        return "senior"
    return None


def role_format_delta(bucket: str | None, confirmed_template: str | None) -> float:
    """Return the per-bucket × per-template confidence delta.

    Returns ``0.0`` when no rule applies.  The mapping is a
    small fixed table — see :data:`_ROLE_FORMAT_DELTAS`.
    """
    if not bucket:
        return 0.0
    if not confirmed_template:
        if bucket == "executive":
            return 0.10
        if bucket == "senior":
            return 0.05
        return 0.0
    return _ROLE_FORMAT_DELTAS.get((bucket, confirmed_template), 0.0)


def _try_build_stealth_session() -> StealthSession | None:
    """Build a :class:`StealthSession` from current settings, returning
    ``None`` when curl-cffi is not installed.

    Harvest modules call this on every source; the lookup is cheap
    (the heavy import work happens in ``StealthSession.__post_init__``)
    and the ``None`` return is the documented "fall back to httpx"
    signal used by the dorker / company-page code paths.
    """
    try:
        profile = resolve_timing_profile(settings.harvest_timing_profile)
        return StealthSession(
            timing_profile=profile,
            impersonate=settings.harvest_impersonate_browser,
        )
    except ImportError:
        # curl-cffi missing — caller falls back to httpx.  The
        # ImportError message already includes the install hint, so
        # we just log at debug level (one line) and return None.
        _LOG.debug(
            "employee_name_discovery: curl-cffi unavailable; "
            "falling back to httpx (install mailaccess)",
        )
        return None


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

# FIX 1 — confidence multiplier for multi-token "names" extracted from
# company pages.  Real person names are overwhelmingly 2 tokens (first
# + last).  Three- and four-token candidates ("Mary Anne Johnson",
# "Acme Io Smith") are rare in real data and disproportionately likely
# to be page fragments that escaped the
# :func:`is_plausible_person_name` filter.  We demote their confidence
# so they contribute less to the pattern-generation pool.  2-token
# candidates keep the full source confidence.
_COMPANY_PAGE_MULTI_TOKEN_DEMOTION = 0.6  # applied when 3-4 tokens

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

    async def run(
        self,
        target: str,
        *,
        use_proxies: bool = False,
        candidate_paths: list[str] | tuple[str, ...] | None = None,
        signal_pool: Any | None = None,
        progress_callback: Any | None = None,
    ) -> ModuleResult:  # type: ignore[override]
        self._use_proxies = use_proxies
        self._candidate_paths = tuple(candidate_paths or ())
        # Phase 2: structured-data emails from the company-page
        # pipeline are stashed here by :meth:`_company_pages`.  We
        # default to an empty list so a fresh ``.run()`` call
        # doesn't carry emails from a previous invocation.
        self._structured_emails = []  # type: ignore[attr-defined]  (Phase 2 side-channel)
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
        if progress_callback:
            progress_callback(f"Scraping https://{domain}/...")
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
        if progress_callback:
            progress_callback("Consolidating employee names from 5 sources...")

        linkedin_findings: list[NameDiscovery] = self._unwrap(
            outcomes[0], default=[], label="linkedin_search"
        )
        company_findings: list[NameDiscovery] = self._unwrap(
            outcomes[1], default=[], label="company_page"
        )
        press_findings: list[NameDiscovery] = self._unwrap(
            outcomes[2], default=[], label="press_release"
        )
        sec_findings: list[NameDiscovery] = self._unwrap(outcomes[3], default=[], label="sec_edgar")
        oc_findings: list[NameDiscovery] = self._unwrap(
            outcomes[4], default=[], label="opencorporates"
        )

        # Phase 2: pull any direct emails the structured-data
        # pipeline collected in :meth:`_company_pages`.  Default to
        # an empty list when the company-page task failed.
        structured_emails: list[dict[str, Any]] = list(
            getattr(self, "_structured_emails", []) or []
        )

        all_names: list[NameDiscovery] = (
            linkedin_findings + company_findings + press_findings + sec_findings + oc_findings
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
        # P3: pull the confirmed pattern from the signal pool so
        # role-aware format deltas can target the right template.
        # When no confirmed pattern is available yet (e.g. Hunter has
        # not run), the delta is 0.0 and the existing multi-source
        # logic is preserved verbatim.
        confirmed_template: str | None = None
        if signal_pool is not None and hasattr(signal_pool, "get_confirmed_patterns"):
            try:
                confirmed = signal_pool.get_confirmed_patterns()
                if confirmed:
                    confirmed_template = confirmed[0]
            except Exception:  # noqa: BLE001 - defensive
                confirmed_template = None
        aggregated: dict[str, EmployeeNameResult] = {}
        # Track which names received a role-format delta so the
        # report layer can surface "3 executives +{first} boost" etc.
        role_delta_counts: dict[str, int] = {"executive": 0, "senior": 0, "none": 0}

        def _record(nd: NameDiscovery) -> None:
            cleaned = nd.name.strip()
            result = classify_name(cleaned)
            if not result.is_person:
                return
            # Phase 4: apply suspicion penalty before recording.
            # 0.0 penalty means the name was already rejected by
            # name_quality but the caller skipped that check — skip here too.
            penalty = result.confidence
            key = cleaned.lower()
            existing = aggregated.get(key)
            if existing is None:
                # P3: classify the role bucket for the title we have
                # at record time.  When the same name is later seen
                # with a different title, the bucket can move — we
                # re-resolve on the finalised EmployeeNameResult
                # below.
                role_bucket = classify_role_bucket(nd.title_or_role)
                role_delta = role_format_delta(role_bucket, confirmed_template)
                aggregated[key] = EmployeeNameResult(
                    name=cleaned,
                    sources=[nd.source],
                    source_count=1,
                    title_or_role=nd.title_or_role,
                    confidence=round(nd.confidence * penalty + role_delta, 4),
                    source_urls=[nd.source_url] if nd.source_url else [],
                )
                return
            if nd.source not in existing.sources:
                existing.sources.append(nd.source)
                existing.source_count += 1
                # Boost: top base confidence × (1 + bonus), then reapply penalty.
                best_base = max(existing.confidence, nd.confidence * penalty)
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

        # P3: post-aggregation pass — re-resolve the role bucket
        # against the FINAL ``title_or_role`` on the
        # EmployeeNameResult.  This way a name that arrived first
        # from a low-fidelity source (no title) and then from a
        # higher-fidelity source (with title) still gets the
        # correct bucket.  We then (a) re-apply the delta to
        # the already-multi-source-boosted confidence and (b) cap
        # the result so it never exceeds ``1.5`` (the existing
        # MAX_SCORE ceiling for the rest of the pipeline).
        for agg in aggregated.values():
            bucket = classify_role_bucket(agg.title_or_role)
            delta = role_format_delta(bucket, confirmed_template)
            if delta != 0.0:
                agg.confidence = round(min(agg.confidence + delta, 1.5), 4)
                role_delta_counts[bucket or "none"] += 1
            else:
                role_delta_counts["none"] += 1

        # ------------------------------------------------------------------
        # Wrap into BaseModule's FindingItem shape so Phase C2's
        # orchestrator can consume via the standard findings pipeline.
        # ------------------------------------------------------------------
        # P5: index snippet emails by name so the per-finding
        # metadata can include them.  We take the FIRST name
        # discovery that carries a non-empty ``snippet_emails``
        # list per name — the multi-source dedupe has already
        # collapsed duplicates, so this is deterministic.
        #
        # We use ``getattr`` with a default empty list so the
        # loop also works for any third-party ``NameDiscovery``
        # class that has not yet adopted the P5 ``snippet_emails``
        # field.  The two ``NameDiscovery`` classes (one in
        # ``backend.core.linkedin_name_discovery`` for SERP
        # results, one in this module for non-LinkedIn sources)
        # are kept separate to avoid an import cycle.
        snippet_emails_by_name: dict[str, list[str]] = {}
        for nd in all_names:
            snippet_emails = getattr(nd, "snippet_emails", None) or []
            if not snippet_emails:
                continue
            key = nd.name.strip().lower()
            existing = snippet_emails_by_name.get(key)
            if not existing:
                snippet_emails_by_name[key] = list(snippet_emails)
        findings: list[dict[str, Any]] = []
        multi_source_count = 0

        for key in sorted(aggregated):
            agg = aggregated[key]
            if agg.source_count >= 2:
                multi_source_count += 1
            label = _label_for_score(agg.confidence)
            finding_metadata: dict[str, Any] = {
                "name": agg.name,
                "sources": sorted(agg.sources),
                "source_count": agg.source_count,
                "title_or_role": agg.title_or_role,
                "confidence_score": round(agg.confidence, 4),
                "source_urls": agg.source_urls,
            }
            # P5: surface snippet-emails on the finding so the
            # report layer can show the analyst the exact email
            # we already saw, alongside the name.  Empty when no
            # SERP snippet for this name contained an email.
            snippet_emails = snippet_emails_by_name.get(agg.name.strip().lower())
            if snippet_emails:
                finding_metadata["snippet_emails"] = list(snippet_emails)
            findings.append(
                {
                    "platform": "employee_name_discovery",
                    "profile_url": agg.source_urls[0] if agg.source_urls else "",
                    "username": agg.name.replace(" ", "."),
                    "confidence": label,
                    "metadata": finding_metadata,
                }
            )

        # Phase 2: append structured-email findings as a separate
        # signal_type so downstream pattern-generation can both
        # (1) skip pattern build for names with a known direct
        # email and (2) surface the email in the harvest report.
        findings.extend(structured_emails)

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
                # Phase 2: direct emails harvested from structured
                # data (JSON-LD, microdata, hCard, mailto:).  Used
                # by the CLI / report layer to surface "we know
                # this person's exact address" rather than just a
                # pattern candidate.
                "structured_emails_found": len(structured_emails),
                "use_proxies": use_proxies,
                "active_scrapingant_transport": get_active_transport()
                if use_proxies
                else None,
                # P3: surface the role-aware format delta summary so
                # the report layer can show "N executives +0.20,
                # M seniors +0.10" without re-deriving the regex
                # match.  Counts only the names that actually got
                # a non-zero delta.
                "role_format_delta_counts": role_delta_counts,
                "confirmed_template": confirmed_template,
                # P5: count of unique names that came with at least
                # one email in the SERP snippet.  The actual email
                # strings live on each finding's
                # ``metadata.snippet_emails``.
                "snippet_emails_name_count": sum(
                    1 for emails in snippet_emails_by_name.values() if emails
                ),
            },
        )

    # ----------------------------------------------------------------------
    # Source 1 — LinkedIn via search-engine dorking
    # ----------------------------------------------------------------------
    async def _linkedin(self, domain: str) -> list[NameDiscovery]:
        # scrapingant: keep for LinkedIn/search HTML where proxy/fingerprint helps
        if getattr(self, "_use_proxies", False):
            async with build_client(
                scrapingant_zone="platforms",
                strict_proxy=True,
                timeout=10.0,
                follow_redirects=True,
            ) as shared:
                ddg = DuckDuckGoDorker(transport=shared, min_interval=0.0)
                bing = BingDorker(transport=shared, min_interval=0.0)
                # Exceptions propagate to ``_unwrap`` via ``asyncio.gather`` so
                # the source-failure mask reflects reality.
                return await discover_linkedin_names(domain=domain, ddg=ddg, bing=bing)
        # No proxy: Chrome-impersonating StealthSession.  Falls back
        # to a plain httpx transport if curl-cffi is not installed.
        stealth = _try_build_stealth_session()
        if stealth is None:
            async with build_client(timeout=10.0, follow_redirects=True) as shared:
                ddg = DuckDuckGoDorker(transport=shared, min_interval=0.0)
                bing = BingDorker(transport=shared, min_interval=0.0)
                return await discover_linkedin_names(domain=domain, ddg=ddg, bing=bing)
        async with build_client(timeout=10.0, follow_redirects=True) as shared:
            ddg = DuckDuckGoDorker(
                transport=shared, min_interval=0.0, stealth=stealth
            )
            bing = BingDorker(
                transport=shared, min_interval=0.0, stealth=stealth
            )
            return await discover_linkedin_names(domain=domain, ddg=ddg, bing=bing)

    # ----------------------------------------------------------------------
    # Source 2 — Company pages (direct fetch)
    # ----------------------------------------------------------------------
    async def _company_pages(self, domain: str) -> list[NameDiscovery]:
        r"""Phase 2: discovery-first structured-data pipeline.

        The legacy ``discover_company_page_names`` (fixed path list +
        body-text extraction) is preserved as a fallback for sites
        where the structured pipeline returns empty.  This method
        ALSO collects direct emails from ``PersonRecord`` instances
        onto ``self._structured_emails`` so :meth:`run` can emit
        them as separate ``structured_email`` findings.
        """
        max_candidates = max(
            1,
            int(
                getattr(settings, "site_discovery_max_candidates", 15)
                or 15
            ),
        )
        timeout = max(
            1, float(getattr(settings, "site_discovery_timeout_seconds", 5) or 5)
        )
        aggressive = bool(getattr(settings, "harvest_aggressive", False))
        use_proxies = getattr(self, "_use_proxies", False)

        async def _scrape_with(session: Any) -> list[PersonRecord]:
            return await discover_and_extract(
                domain,
                session,
                aggressive=aggressive,
                max_candidates=max_candidates,
                timeout=timeout,
                candidate_paths=getattr(self, "_candidate_paths", ()),
            )

        records: list[PersonRecord] = []
        # scrapingant: keep for public company-page HTML with anti-bot variance
        if use_proxies:
            async with build_client(
                scrapingant_zone="platforms",
                strict_proxy=True,
                timeout=timeout,
                follow_redirects=True,
            ) as shared:
                records = await _scrape_with(shared)
        else:
            # 0.11.1 Phase 1: Chrome-impersonating direct fetch via
            # the same StealthSession used by the LinkedIn source.
            # Falls back to a plain httpx transport if curl-cffi is
            # not installed (StealthSession's ``__post_init__`` raises
            # ``ImportError`` with install instructions in that case).
            stealth = _try_build_stealth_session()
            if stealth is not None:
                records = await _scrape_with(stealth)
            else:
                async with build_client(
                    timeout=timeout, follow_redirects=True
                ) as shared:
                    records = await _scrape_with(shared)

        # Stash the discovered emails on the module instance so
        # ``run()`` can emit them as separate ``structured_email``
        # findings.  We attach a side-channel list rather than
        # mixing email records into the names stream — the dedupe
        # / boost logic in :meth:`run` is name-centric, and emails
        # don't participate in the multi-source boost (they already
        # carry a high confidence from the structured-data source).
        self._structured_emails = [
            {
                "platform": "employee_name_discovery",
                "signal_type": "structured_email",
                "metadata": {
                    "name": r.name,
                    "email": r.email,
                    "source": "structured_page",
                    "source_url": r.page_url,
                    "source_type": r.source_type,
                    "confidence_score": r.confidence,
                },
                "profile_url": r.page_url,
                "username": (r.email or "").split("@", 1)[0],
                "confidence": "high" if r.confidence >= 0.7 else "medium",
            }
            for r in records
            if (r.email or "").strip()
        ]

        # FIX 1 — apply token-count-based confidence demotion for
        # company-page names.  Real names are 2 tokens; multi-token
        # candidates are disproportionately likely to be page
        # fragments and should contribute less to pattern generation.
        out: list[NameDiscovery] = []
        for record in records:
            if record.source_type == "github_contributor":
                continue
            token_count = len(record.name.split())
            confidence = record.confidence
            if token_count >= 3:
                confidence = round(confidence * _COMPANY_PAGE_MULTI_TOKEN_DEMOTION, 4)
            out.append(
                NameDiscovery(
                    name=record.name,
                    source="company_page",
                    source_url=record.page_url,
                    title_or_role=record.title,
                    confidence=confidence,
                )
            )
        return out

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
    def _unwrap(outcome: Any, default: list[NameDiscovery], label: str) -> list[NameDiscovery]:
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
    all_names = (
        linkedin
        + [
            NameDiscovery(
                name=p.name,
                source="company_page",
                source_url=p.source_url,
                title_or_role=p.title_or_role,
                confidence=p.confidence,
            )
            for p in pages
        ]
        + press
        + sec
        + oc
    )
    aggregated: dict[str, EmployeeNameResult] = {}
    for nd in all_names:
        cleaned = nd.name.strip()
        result = classify_name(cleaned)
        if not result.is_person:
            continue
        penalty = result.confidence
        key = cleaned.lower()
        existing = aggregated.get(key)
        if existing is None:
            aggregated[key] = EmployeeNameResult(
                name=cleaned,
                sources=[nd.source],
                source_count=1,
                title_or_role=nd.title_or_role,
                confidence=round(nd.confidence * penalty, 4),
                source_urls=[nd.source_url] if nd.source_url else [],
            )
            continue
        if nd.source not in existing.sources:
            existing.sources.append(nd.source)
            existing.source_count += 1
            best_base = max(existing.confidence, nd.confidence * penalty)
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
