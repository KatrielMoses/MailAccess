"""Async Bing HTML scraper for the email-harvest phase.

0.11.1 Phase 4:
  * Rewrites the HTTP transport to use :class:`StealthSession`
    exclusively (same pattern as :mod:`backend.core.duckduckgo_dorker`).
  * All Bing Web Search API references removed — the API was retired
    2025-08-11 and returns HTTP 410 Gone.  This module now uses only
    the Bing HTML search page, the same as the DDG dorker.
  * On HTTP 202 (Bing's CAPTCHA/success-challenge signal) the dorker
    sets ``self.blocked = True`` so callers can produce actionable logs.

All other logic (HTML parsing, rate limiting) is unchanged.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from dataclasses import dataclass
from html import unescape
from typing import Any

import httpx

from ..config import APP_VERSION
from .stealth_client import StealthSession, resolve_timing_profile

_LOG = logging.getLogger(__name__)

_BING_URL = "https://www.bing.com/search"
_DEFAULT_UA = f"MailAccess/{APP_VERSION} (+https://github.com/KatrielMoses/MailAccess)"
_UA_POOL: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
)
_BLOCK_MARKERS = (
    "captcha",
    "are you a human",
    "unusual traffic",
    "automated queries",
    "access denied",
    "request is blocked",
)


@dataclass
class SearchResult:
    title: str
    snippet: str
    url: str
    query_used: str


# Bing pattern: every result is a <li class="b_algo"> enclosing an
# <h2><a href="URL">TITLE</a></h2> and a <p>SNIPPET</p>.  We capture
# each block then extract.
_BING_RESULT_BLOCK_RE = re.compile(
    r'<li[^>]*class="b_algo"[^>]*>(.*?)</li>',
    re.IGNORECASE | re.DOTALL,
)
_BING_HREF_RE = re.compile(
    r'<h2>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>\s*</h2>',
    re.IGNORECASE | re.DOTALL,
)
_BING_SNIPPET_RE = re.compile(
    r"<p[^>]*>(.*?)</p>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")


def _pick_user_agent() -> str:
    return random.choice(_UA_POOL) if _UA_POOL else _DEFAULT_UA


def _looks_like_block(body: str) -> bool:
    if not body:
        return False
    lower = body.lower()
    return any(marker in lower for marker in _BLOCK_MARKERS)


def _clean(text: str) -> str:
    text = _TAG_RE.sub(" ", text or "")
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _parse_bing_html(html: str, query: str, max_results: int) -> list[SearchResult]:
    """Extract up to *max_results* search results from a Bing HTML page."""
    if not html:
        return []
    results: list[SearchResult] = []
    seen_urls: set[str] = set()
    for block_match in _BING_RESULT_BLOCK_RE.finditer(html):
        if len(results) >= max_results:
            break
        block = block_match.group(1)
        href_match = _BING_HREF_RE.search(block)
        if not href_match:
            continue
        url = href_match.group(1).strip()
        if not url or url in seen_urls:
            continue
        title_html = href_match.group(2)

        snippet_match = _BING_SNIPPET_RE.search(block)
        snippet_html = snippet_match.group(1) if snippet_match else ""

        seen_urls.add(url)
        results.append(
            SearchResult(
                title=_clean(title_html),
                snippet=_clean(snippet_html),
                url=url,
                query_used=query,
            )
        )
    return results


class BingDorker:
    """Search Bing HTML for a single dork query.

    0.11.1 Phase 4: all HTTP requests go through the injected
    :class:`StealthSession`.  When no session is provided at
    construction time the dorker builds one with the T2 timing
    profile.

    NOTE: The Bing Web Search API was retired 2025-08-11.
    This module uses only the Bing HTML search page.
    """

    def __init__(
        self,
        transport: httpx.AsyncClient | None = None,
        min_interval: float = 3.0,
        timeout: float = 10.0,
        follow_redirects: bool = True,
        *,
        scrapingant_zone: str | None = None,
        stealth: StealthSession | None = None,
    ) -> None:
        # Phase 4: when a StealthSession is injected, use it.
        # When neither transport nor stealth is provided, build a
        # StealthSession with T2 timing as the default HTTP transport.
        # When transport is explicitly provided (for tests), skip
        # StealthSession entirely so tests can mock the client directly.
        if stealth is not None:
            self._session: StealthSession = stealth
        elif transport is None:
            try:
                profile = resolve_timing_profile("t2")
                self._session = StealthSession(timing_profile=profile)
            except ImportError:
                self._session = None  # type: ignore[assignment]
        else:
            self._session = None  # type: ignore[assignment]

        self._owns_transport = transport is None
        if transport is None and self._session is None:
            self._client: httpx.AsyncClient = httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
        elif transport is not None:
            self._client = transport
        else:
            self._client = None  # type: ignore[assignment]

        self._min_interval = max(float(min_interval), 0.0)
        self._last_request_at: float = 0.0
        self._lock = asyncio.Lock()
        self._last_error: str | None = None
        # 0.11.1 Phase 4: tracks whether a block (202/403/429/body marker)
        # was hit.  Set by ``search()``; callers read it to produce
        # actionable logs.
        self.blocked: bool = False

    async def aclose(self) -> None:
        if self._owns_transport and self._client is not None:
            await self._client.aclose()

    async def __aenter__(self) -> BingDorker:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def search(
        self,
        query: str,
        max_results: int = 20,
    ) -> tuple[list[SearchResult], bool]:
        if not query:
            return [], False

        async with self._lock:
            await self._throttle()
            self._last_error = None
            self.blocked = False

            try:
                if self._session is not None:
                    response = await self._session.get(
                        _BING_URL,
                        params={"q": query, "count": max_results},
                    )
                elif self._client is not None:
                    response = await self._client.get(
                        _BING_URL,
                        params={"q": query, "count": max_results},
                        headers={"User-Agent": _pick_user_agent()},
                    )
                else:
                    _LOG.error("Bing dork: no transport and no session available")
                    return [], False
            except httpx.TimeoutException:
                _LOG.warning("Bing dork timed out: %s", query)
                return [], False
            except Exception as exc:
                _LOG.warning("Bing dork network error: %s", exc)
                self._last_error = str(exc)
                return [], False

            # 0.11.1 Phase 4: HTTP 202 is Bing's CAPTCHA/success-challenge
            # signal (same as DDG).  Treat it identically to 403/429.
            if response.status_code in (202, 403, 429):
                self.blocked = True
                _LOG.warning(
                    "Bing blocked (HTTP %s) for query=%r",
                    response.status_code,
                    query,
                )
                return [], True
            if response.status_code != 200:
                _LOG.warning(
                    "Bing HTTP %s for query=%r",
                    response.status_code,
                    query,
                )
                return [], False

            body = response.text or ""
            if _looks_like_block(body):
                self.blocked = True
                _LOG.warning("Bing block-marker detected in body for query=%r", query)
                return [], True

            return _parse_bing_html(body, query, max_results=max_results), False

    async def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_request_at
        wait = self._min_interval - elapsed
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_at = time.monotonic()


def parse_bing_html_for_tests(html: str, query: str, max_results: int = 20) -> list[SearchResult]:
    """Test-facing alias."""
    return _parse_bing_html(html, query, max_results)
