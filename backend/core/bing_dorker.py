"""Async Bing HTML scraper for the email-harvest phase.

Mirror of :mod:`backend.core.duckduckgo_dorker`, but for Bing's HTML
search results page.  Bing result blocks live inside ``<li
class="b_algo">`` containers with a heading anchor (``<h2><a>...</a></h2>``)
and a snippet paragraph (``<p>...</p>``).  We parse these with the
same regex-and-``build_client`` discipline used elsewhere in the
codebase.
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
from ..core.http_client import build_client

_LOG = logging.getLogger(__name__)

_BING_URL = "https://www.bing.com/search"
_DEFAULT_UA = (
    f"MailAccess/{APP_VERSION} "
    "(+https://github.com/KatrielMoses/MailAccess)"
)
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

    Returns ``(results, blocked)``.  Blocked == CAPTCHA / rate-limit
    pattern matched, caller should stop the current run.
    """

    def __init__(
        self,
        transport: httpx.AsyncClient | None = None,
        min_interval: float = 3.0,
        timeout: float = 10.0,
        follow_redirects: bool = True,
    ) -> None:
        self._owns_transport = transport is None
        if transport is None:
            self._client: httpx.AsyncClient = build_client(
                timeout=timeout, follow_redirects=follow_redirects
            )
        else:
            self._client = transport
        self._min_interval = max(float(min_interval), 0.0)
        self._last_request_at: float = 0.0
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        if self._owns_transport:
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

            try:
                response = await self._client.get(
                    _BING_URL,
                    params={"q": query, "count": max_results},
                    headers={"User-Agent": _pick_user_agent()},
                )
            except httpx.TimeoutException:
                _LOG.warning("Bing dork timed out: %s", query)
                return [], False
            except Exception as exc:
                _LOG.warning("Bing dork network error: %s", exc)
                return [], False

            if response.status_code in (403, 429):
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
                _LOG.warning(
                    "Bing block-marker detected in body for query=%r", query
                )
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
