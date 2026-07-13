"""Async DuckDuckGo HTML dork scraper for the email-harvest phase.

0.11.1 Phase 4 — rewrites the HTTP transport to use
:class:`StealthSession` exclusively, replacing the legacy httpx
fallback path.  On HTTP 202 responses (DDG's CAPTCHA/success-challenge
pattern) the dorker sets ``self.blocked = True`` so the orchestrator
can log a useful "DDG blocked — stealth client may help, try --stealth"
message instead of returning a silent PARTIAL result.

All other logic (query construction, HTML parsing, rate limiting)
is unchanged from the previous version.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
from dataclasses import dataclass
from html import unescape
from typing import Any
from urllib.parse import urlencode

import httpx

from ..config import APP_VERSION
from .concurrent_fetch_cache import CachedFetch
from .stealth_client import StealthSession, resolve_timing_profile

_LOG = logging.getLogger(__name__)

_DDG_HTML_URL = "https://html.duckduckgo.com/html/"
_DEFAULT_UA = f"MailAccess/{APP_VERSION} (+https://github.com/KatrielMoses/MailAccess)"
# Rotated realistic-browser pool — matches the spirit of
# ``proxy._UA_POOL`` but self-contained to avoid a hard import.
_UA_POOL: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
)
_CAPTCHA_MARKERS = (
    "anomaly",
    "captcha",
    "are you a human",
    "unusual traffic",
    "blocked",
)


@dataclass
class SearchResult:
    title: str
    snippet: str
    url: str
    query_used: str


# DDG result block shape: each result is enclosed in an <a class="result__a">
# anchor with the visible title, followed by <a class="result__snippet"> for
# the body, and the href is either direct OR a `duckduckgo.com/l/?uddg=...`
# redirect.  We capture both shapes.
_DDG_RESULT_LINK_RE = re.compile(
    r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_DDG_SNIPPET_RE = re.compile(
    r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_DDG_UDDG_RE = re.compile(r"uddg=([^&\"]+)", re.IGNORECASE)
_DDG_REDIRECT_HOST = "duckduckgo.com/l/"

_TAG_RE = re.compile(r"<[^>]+>")


def _pick_user_agent() -> str:
    return random.choice(_UA_POOL) if _UA_POOL else _DEFAULT_UA


def _looks_like_captcha(body: str) -> bool:
    if not body:
        return False
    lower = body.lower()
    return any(marker in lower for marker in _CAPTCHA_MARKERS)


def _clean(text: str) -> str:
    text = _TAG_RE.sub(" ", text or "")
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _extract_uddg_target(href: str) -> str | None:
    """Resolve ``duckduckgo.com/l/?uddg=...`` redirects to the real URL."""
    if not href:
        return None
    if _DDG_REDIRECT_HOST not in href:
        return href
    match = _DDG_UDDG_RE.search(href)
    if not match:
        return None
    try:
        from urllib.parse import unquote

        return unquote(match.group(1))
    except Exception:
        return None


def _parse_ddg_html(html: str, query: str, max_results: int) -> list[SearchResult]:
    """Extract up to *max_results* search results from DDG HTML."""
    if not html:
        return []
    results: list[SearchResult] = []
    seen_urls: set[str] = set()
    for link_match in _DDG_RESULT_LINK_RE.finditer(html):
        if len(results) >= max_results:
            break
        href_raw = link_match.group(1)
        title_html = link_match.group(2)
        url = _extract_uddg_target(href_raw)
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)

        # Find the closest snippet that follows this link in the page.
        start = link_match.end()
        snippet_match = _DDG_SNIPPET_RE.search(html, start)
        snippet_html = snippet_match.group(1) if snippet_match else ""

        results.append(
            SearchResult(
                title=_clean(title_html),
                snippet=_clean(snippet_html),
                url=url,
                query_used=query,
            )
        )
    return results


class DuckDuckGoDorker:
    """Search DuckDuckGo HTML for a single dork query.

    0.11.1 Phase 4: all HTTP requests go through the injected
    :class:`StealthSession`.  When no session is provided at
    construction time the dorker builds one with the T2 timing
    profile (the same profile the orchestrator uses for other
    harvest sources).

    On HTTP 202 the dorker sets ``self.blocked = True`` so
    callers can distinguish a CAPTCHA block from a plain
    non-200 error.
    """

    def __init__(
        self,
        transport: httpx.AsyncClient | None = None,
        min_interval: float = 4.0,
        timeout: float = 10.0,
        follow_redirects: bool = True,
        *,
        scrapingant_zone: str | None = None,
        stealth: StealthSession | None = None,
        fetch: CachedFetch | None = None,
    ) -> None:
        # 0.11.1 Phase 3 cache: when a CachedFetch facade is provided,
        # route every request through it (the orchestrator's
        # per-run ConcurrentFetchCache).  This supersedes both the
        # stealth session and the transport — the cache is the new
        # owner of HTTP for the harvest run.
        #
        # Otherwise follow the legacy priority:
        #   1. ``stealth`` injected — use it (Phase 4 path).
        #   2. ``transport`` injected (tests) — use it; skip stealth.
        #   3. nothing injected — build a StealthSession with T2 timing,
        #      or fall back to httpx if curl-cffi is unavailable.
        self._fetch: CachedFetch | None = fetch
        if fetch is not None:
            self._session = None  # type: ignore[assignment]
        elif stealth is not None:
            self._session: StealthSession = stealth
        elif transport is None:
            try:
                profile = resolve_timing_profile("t2")
                self._session = StealthSession(timing_profile=profile)
            except ImportError:
                # curl-cffi not installed — fall back to building a
                # plain httpx client as before.
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
        # 0.11.1 Phase 4: tracks whether a 202 CAPTCHA/block was hit.
        # Set by ``search()``; callers read it to produce actionable logs.
        self.blocked: bool = False

    async def aclose(self) -> None:
        if self._owns_transport and self._client is not None:
            await self._client.aclose()

    async def __aenter__(self) -> DuckDuckGoDorker:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def search(
        self,
        query: str,
        max_results: int = 20,
    ) -> tuple[list[SearchResult], bool]:
        """Run a single DDG HTML search.

        Returns ``(results, captcha_hit)``.  When ``captcha_hit`` is
        ``True`` the caller should stop issuing further queries.
        ``self.blocked`` will also be ``True`` so the orchestrator
        can log a helpful message.
        """
        if not query:
            return [], False

        async with self._lock:
            await self._throttle()
            self._last_error = None
            self.blocked = False

            try:
                if self._fetch is not None:
                    # 0.11.1 Phase 3 cache path: build the full URL
                    # with the query param so the cache key is
                    # ``https://html.duckduckgo.com/html/?q=...`` —
                    # identical queries across modules collapse to a
                    # single underlying request.
                    full_url = f"{_DDG_HTML_URL}?{urlencode({'q': query})}"
                    response = await self._fetch.get(full_url)
                elif self._session is not None:
                    # StealthSession routes through curl-cffi's
                    # Chrome-impersonation path.
                    response = await self._session.get(
                        _DDG_HTML_URL,
                        params={"q": query},
                    )
                elif self._client is not None:
                    response = await self._client.get(
                        _DDG_HTML_URL,
                        params={"q": query},
                        headers={"User-Agent": _pick_user_agent()},
                    )
                else:
                    _LOG.error("DuckDuckGo dork: no transport and no session available")
                    return [], False
            except httpx.TimeoutException:
                _LOG.warning("DuckDuckGo dork timed out: %s", query)
                return [], False
            except Exception as exc:
                _LOG.warning("DuckDuckGo dork network error: %s", exc)
                self._last_error = str(exc)
                return [], False

            # 0.11.1 Phase 4: HTTP 202 is DDG's CAPTCHA/success-challenge
            # signal.  Treat it identically to 403/429.
            if response.status_code in (202, 403, 429):
                self.blocked = True
                _LOG.warning(
                    "DuckDuckGo CAPTCHA/block (HTTP %s) for query=%r",
                    response.status_code,
                    query,
                )
                return [], True
            if response.status_code != 200:
                _LOG.warning(
                    "DuckDuckGo HTTP %s for query=%r",
                    response.status_code,
                    query,
                )
                return [], False

            body = response.text or ""
            if _looks_like_captcha(body):
                self.blocked = True
                _LOG.warning(
                    "DuckDuckGo CAPTCHA marker detected in body for query=%r",
                    query,
                )
                return [], True

            return _parse_ddg_html(body, query, max_results=max_results), False

    async def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        import time as _time

        elapsed = _time.monotonic() - self._last_request_at
        wait = self._min_interval - elapsed
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_at = _time.monotonic()


def parse_ddg_html_for_tests(html: str, query: str, max_results: int = 20) -> list[SearchResult]:
    """Test-facing alias — keeps test imports compact."""
    return _parse_ddg_html(html, query, max_results)
