"""LinkedIn name discovery via the Phase B1 search dorkers.

Reuses :class:`backend.core.duckduckgo_dorker.DuckDuckGoDorker` and
:class:`backend.core.bing_dorker.BingDorker` rather than building a
new DDG/Bing scraper.  Calls them with the standard
``"site:linkedin.com/in/ ..."`` dorks and parses the result titles,
which typically follow the format::

    "<Full Name> - <Title> - <Company> | LinkedIn"

The two engines run concurrently (different IP / domain pools mean
neither rate limiter interferes with the other).
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .bing_dorker import BingDorker
from .bing_dorker import SearchResult as BingResult
from .duckduckgo_dorker import DuckDuckGoDorker
from .duckduckgo_dorker import SearchResult as DDGResult
from .email_extraction import extract_emails
from .name_quality import is_plausible_person_name, matches_domain

_LOG = logging.getLogger(__name__)

# Confidence baseline per research — LinkedIn enforces real-name norms,
# so a snippet with a parseable name is high-confidence.
_LINKEDIN_CONFIDENCE = 0.7

# LinkedIn URL pattern we trust.
_LINKEDIN_PROFILE_RE = re.compile(
    r"https?://(?:www\.)?linkedin\.com/in/([\w\-]+)/?",
    re.IGNORECASE,
)

# Title separators in LinkedIn result titles.
_TITLE_SEP_RE = re.compile(r"\s*[|·—\-]\s*")
# " | LinkedIn" or " - LinkedIn" trailing suffixes.
_LINKEDIN_SUFFIX_RE = re.compile(r"\s*[|·—\-]\s*linkedin\s*$", re.IGNORECASE)


@dataclass
class NameDiscovery:
    name: str
    source: str
    source_url: str | None
    title_or_role: str | None
    confidence: float
    # P5: emails surfaced in the same SERP snippet that produced
    # this name.  Often the snippet is the only place the email
    # actually appears ("John Smith — jsmith@example.com — Senior
    # Engineer — LinkedIn"), so we capture the addresses inline
    # instead of forcing the caller to re-query the search engine.
    # Empty list when the snippet had no email-looking text.
    snippet_emails: list[str] = field(default_factory=list)


# ----------------------------------------------------------------------
# Title parsing
# ----------------------------------------------------------------------
def _parse_linkedin_title(
    title: str,
    domain: str | None = None,
) -> tuple[str, str | None] | None:
    """Extract (name, role) from a LinkedIn search-result title.

    The standard format is::

        "FirstName LastName - Title - Company | LinkedIn"

    Returns ``(name, role_or_None)`` or ``None`` if the title doesn't
    look like a clean LinkedIn profile title.
    """
    if not title:
        return None
    cleaned = _LINKEDIN_SUFFIX_RE.sub("", title).strip()
    if not cleaned:
        return None

    parts = _TITLE_SEP_RE.split(cleaned)
    if not parts:
        return None

    name_candidate = parts[0].strip()
    role = parts[1].strip() if len(parts) >= 2 else None

    if not is_plausible_person_name(name_candidate):
        return None

    if domain and matches_domain(name_candidate, domain):
        return None

    return name_candidate, role or None


def _is_profile_url(url: str) -> bool:
    return bool(url) and bool(_LINKEDIN_PROFILE_RE.search(url))


def _extract_slug(url: str) -> str | None:
    if not url:
        return None
    match = _LINKEDIN_PROFILE_RE.search(url)
    return match.group(1) if match else None


def _emails_in_snippet(snippet: str | None) -> list[str]:
    """Return the deduped, lowercased emails found in *snippet*.

    P5: the snippet text often contains the person's actual email
    ("John Smith — jsmith@example.com — Senior Engineer — LinkedIn").
    We previously discarded this signal entirely.  Now we extract
    it so the orchestrator can correlate name + email in a single
    SERP hit, dramatically reducing the work the downstream email
    pattern generator needs to do.

    Returns an empty list when the snippet is empty/None or has
    no email-shaped text.  The list is in ``extract_emails``'s
    natural sorted order so callers can rely on the ordering.
    """
    if not snippet:
        return []
    extracted = extract_emails(snippet, target_domain=None)
    return [item.email for item in extracted]


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
async def discover_linkedin_names(
    domain: str,
    company_name: str | None = None,
    ddg: DuckDuckGoDorker | None = None,
    bing: BingDorker | None = None,
) -> list[NameDiscovery]:
    """Run the two dorkers in parallel, parse titles, return NameDiscoveries.

    Parameters
    ----------
    domain:
        Target domain (e.g. ``example.com``).
    company_name:
        Optional company name hint. When provided, the second dork
        uses ``site:linkedin.com/in/ "<company_name>"`` which often
        returns more relevant hits than the bare-domain version.
    ddg / bing:
        Caller-supplied dorkers.  Tests pass ``MockTransport``-backed
        instances; production code may pass ``None`` to use the
        default ``build_client()``-backed ones.
    """
    cleaned = (domain or "").strip().lower()
    if not cleaned or "." not in cleaned:
        return []

    queries: list[str] = [
        f'site:linkedin.com/in/ "{cleaned}"',
    ]
    if company_name:
        queries.append(f'site:linkedin.com/in/ "{company_name.strip()}"')

    async def _use_ddg(
        dorker: DuckDuckGoDorker | None, items: list[NameDiscovery]
    ) -> None:
        if dorker is None:
            return
        for q in queries:
            results, captcha = await dorker.search(q)
            if captcha:
                _LOG.warning("linkedin_name_discovery: DDG captcha hit")
                return
            for r in results:
                parsed = _parse_linkedin_title(r.title, domain=cleaned)
                if not parsed:
                    continue
                name, role = parsed
                if not _is_profile_url(r.url):
                    continue
                # P5: pull emails from the same snippet that gave us
                # the name.  We do NOT filter by ``on_domain`` here
                # — the parent caller (employee_name_discovery) can
                # decide whether to use off-domain personal emails
                # (e.g. a personal Gmail on a "Sr. Engineer at X"
                # profile) as a corroboration signal.
                snippet_emails = _emails_in_snippet(r.snippet)
                items.append(
                    NameDiscovery(
                        name=name,
                        source="linkedin_search",
                        source_url=r.url,
                        title_or_role=role,
                        confidence=_LINKEDIN_CONFIDENCE,
                        snippet_emails=snippet_emails,
                    )
                )

    async def _use_bing(
        dorker: BingDorker | None, items: list[NameDiscovery]
    ) -> None:
        if dorker is None:
            return
        for q in queries:
            results, blocked = await dorker.search(q)
            if blocked:
                _LOG.warning("linkedin_name_discovery: Bing block hit")
                return
            for r in results:
                parsed = _parse_linkedin_title(r.title, domain=cleaned)
                if not parsed:
                    continue
                name, role = parsed
                if not _is_profile_url(r.url):
                    continue
                # P5: same extraction as the DDG branch — see the
                # comment above.  Keeping both branches in sync
                # matters because tests parameterise over both
                # engines.
                snippet_emails = _emails_in_snippet(r.snippet)
                items.append(
                    NameDiscovery(
                        name=name,
                        source="linkedin_search",
                        source_url=r.url,
                        title_or_role=role,
                        confidence=_LINKEDIN_CONFIDENCE,
                        snippet_emails=snippet_emails,
                    )
                )

    findings: list[NameDiscovery] = []
    await asyncio.gather(
        _use_ddg(ddg, findings),
        _use_bing(bing, findings),
        return_exceptions=True,
    )
    return findings


def discover_names_for_tests(
    ddg_results: list[Any],
    bing_results: list[Any],
    domain: str,
) -> list[NameDiscovery]:
    """Pure helper used by tests to derive NameDiscovery lists from
    already-fetched SearchResult objects without spinning up a client.
    """
    cleaned = domain.strip().lower()
    out: list[NameDiscovery] = []
    for result in list(ddg_results) + list(bing_results):
        if not isinstance(result, DDGResult | BingResult):
            continue
        parsed = _parse_linkedin_title(result.title, domain=cleaned)
        if not parsed:
            continue
        name, role = parsed
        if not _is_profile_url(result.url):
            continue
        out.append(
            NameDiscovery(
                name=name,
                source="linkedin_search",
                source_url=result.url,
                title_or_role=role,
                confidence=_LINKEDIN_CONFIDENCE,
                # P5: include snippet emails in the test helper so
                # downstream tests can exercise the new field
                # without rebuilding the dorker flow.  We reuse
                # the same helper as the production code path.
                snippet_emails=_emails_in_snippet(result.snippet),
            )
        )
    return out
