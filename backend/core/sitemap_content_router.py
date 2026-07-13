"""SitemapContentRouter - prioritize content-hub URLs from sitemap feeds.

The router stays intentionally narrow:

* Fetch ``/sitemap.xml`` and any sitemap URLs advertised by
  ``robots.txt`` using the shared :class:`CachedFetch` facade.
* Follow sitemap indexes recursively instead of guessing extra paths.
* Keep only URLs whose path segments point at content hubs such as
  blog, news, article, course, academy, podcast, or press.
* Return the matching URLs in priority order so a caller can feed them
  into :class:`backend.core.pagination_handler.PaginationHandler` and
  :class:`backend.core.schema_content_extractor.SchemaContentExtractor`.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

from .concurrent_fetch_cache import CachedFetch, normalize_url

_LOG = logging.getLogger(__name__)

_DEFAULT_MAX_URLS: Final[int] = 50
_MAX_SITEMAP_DOCS: Final[int] = 32
_CONTENT_PATH_MARKERS: Final[tuple[str, ...]] = (
    "blog",
    "news",
    "article",
    "course",
    "academy",
    "podcast",
    "press",
)
_ROBOTS_SITEMAP_RE = re.compile(r"^sitemap\s*:\s*(?P<url>\S+)", re.IGNORECASE)


@dataclass(slots=True, frozen=True)
class _Candidate:
    url: str
    marker_rank: int
    order: int


def _clean_domain(domain: str) -> str:
    raw = (domain or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.netloc or "").strip().lower()
        if host:
            return host
        return ""
    return raw.strip("/")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower() if "}" in tag else tag.lower()


def _response_text(response: Any) -> str:
    text = getattr(response, "text", "")
    if isinstance(text, str):
        return text
    content = getattr(response, "content", b"")
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    if isinstance(content, bytearray):
        return bytes(content).decode("utf-8", errors="replace")
    return ""


def _response_status(response: Any) -> int:
    try:
        return int(getattr(response, "status_code", 0) or 0)
    except Exception:  # noqa: BLE001 - defensive against odd response shapes
        return 0


def _robots_sitemaps(robots_text: str, base_url: str) -> list[str]:
    out: list[str] = []
    for line in (robots_text or "").splitlines():
        match = _ROBOTS_SITEMAP_RE.match(line.strip())
        if not match:
            continue
        loc = match.group("url").strip()
        if not loc:
            continue
        out.append(urljoin(base_url, loc))
    return out


def _loc_urls_from_sitemap(xml_text: str, base_url: str) -> tuple[list[str], list[str]]:
    """Return ``(page_urls, nested_sitemaps)`` from a sitemap document."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return [], []

    root_kind = _local_name(root.tag)
    if root_kind not in {"urlset", "sitemapindex"}:
        return [], []

    page_urls: list[str] = []
    nested_sitemaps: list[str] = []
    for node in root.iter():
        if _local_name(node.tag) != "loc":
            continue
        loc = (node.text or "").strip()
        if not loc:
            continue
        resolved = urljoin(base_url, loc)
        if root_kind == "sitemapindex":
            nested_sitemaps.append(resolved)
        else:
            page_urls.append(resolved)
    return page_urls, nested_sitemaps


def _path_marker_rank(url: str) -> int | None:
    parsed = urlparse(url)
    path = (parsed.path or "").lower()
    if not path:
        return None
    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return None
    for rank, marker in enumerate(_CONTENT_PATH_MARKERS):
        for segment in segments:
            if segment == marker:
                return rank
            if segment.startswith(f"{marker}-") or segment.startswith(f"{marker}_"):
                return rank
            if segment == f"{marker}s" or segment == f"{marker}es":
                return rank
    return None


def _content_candidate(url: str, order: int) -> _Candidate | None:
    rank = _path_marker_rank(url)
    if rank is None:
        return None
    return _Candidate(url=url, marker_rank=rank, order=order)


class SitemapContentRouter:
    """Locate sitemap-backed content hubs without guessing page URLs."""

    async def route(
        self,
        domain: str,
        cache: CachedFetch,
        *,
        max_urls: int = _DEFAULT_MAX_URLS,
    ) -> list[str]:
        cleaned = _clean_domain(domain)
        if not cleaned:
            return []
        if max_urls <= 0:
            return []
        cap = min(int(max_urls), _DEFAULT_MAX_URLS)

        base = f"https://{cleaned}/"
        roots: list[str] = [urljoin(base, "sitemap.xml")]
        robots_url = urljoin(base, "robots.txt")

        try:
            robots_response = await cache.get(robots_url)
        except Exception as exc:  # noqa: BLE001 - robots is best-effort
            _LOG.debug("SitemapContentRouter: robots fetch failed: %s", exc)
        else:
            if 200 <= _response_status(robots_response) < 300:
                roots.extend(_robots_sitemaps(_response_text(robots_response), base))

        seen_sitemaps: set[str] = set()
        seen_candidates: set[str] = set()
        queue: deque[str] = deque()
        for root in roots:
            normalized = normalize_url(root)
            if normalized in seen_sitemaps:
                continue
            seen_sitemaps.add(normalized)
            queue.append(root)

        discovered: list[_Candidate] = []
        processed_docs = 0

        while queue and processed_docs < _MAX_SITEMAP_DOCS:
            sitemap_url = queue.popleft()
            processed_docs += 1
            try:
                response = await cache.get(sitemap_url)
            except Exception as exc:  # noqa: BLE001 - bad sitemap should not abort routing
                _LOG.debug("SitemapContentRouter: sitemap fetch failed: %s", exc)
                continue

            if _response_status(response) < 200 or _response_status(response) >= 300:
                continue

            page_urls, nested_sitemaps = _loc_urls_from_sitemap(
                _response_text(response),
                sitemap_url,
            )
            for nested in nested_sitemaps:
                normalized = normalize_url(nested)
                if normalized in seen_sitemaps:
                    continue
                seen_sitemaps.add(normalized)
                queue.append(nested)

            for url in page_urls:
                candidate = _content_candidate(url, len(discovered))
                if candidate is None:
                    continue
                normalized = normalize_url(candidate.url)
                if normalized in seen_candidates:
                    continue
                seen_candidates.add(normalized)
                discovered.append(candidate)

        discovered.sort(key=lambda cand: (cand.marker_rank, cand.order, cand.url))
        return [cand.url for cand in discovered[:cap]]


__all__ = ["SitemapContentRouter"]
