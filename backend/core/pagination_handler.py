"""General-purpose pagination traversal for list-style endpoints.

The handler is intentionally transport-agnostic apart from the
``CachedFetch`` interface.  Callers hand it a start URL and it yields
each successfully fetched page as ``(url, raw_bytes)`` while it walks
forward through common pagination styles:

* query parameters: ``?page=N``, ``?p=N``, ``?offset=N``
* path segments: ``/page/2/``, ``/instructors/2/``
* relation links: ``<a rel="next">`` / ``<link rel="next">`` and
  ``Link: ...; rel="next"`` headers

Traversal stops when it hits a 404/410, when it cannot find any next
candidate, when the normalized first-2KB body hash repeats, or when it
reaches the configured page / item ceiling.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .concurrent_fetch_cache import CachedFetch

_SAMPLE_BYTES = 2048
_DEFAULT_MAX_PAGES = 50
_DEFAULT_MAX_ITEMS = 5000
_PAGE_PARAM_NAMES = ("page", "p")
_OFFSET_PARAM_NAMES = ("offset",)
_OFFSET_SIZE_PARAM_NAMES = ("limit", "per_page", "perpage", "page_size", "pagesize")
_PATH_PAGE_RE = re.compile(
    r"^(?P<prefix>.*?)/(?:page|p)/(?P<num>\d+)(?P<suffix>/?)$",
    flags=re.IGNORECASE,
)
_PATH_TRAILING_NUM_RE = re.compile(r"^(?P<prefix>.*?)/(?P<num>\d+)(?P<suffix>/?)$")
_WHITESPACE_RE = re.compile(r"\s+")
_LINK_HEADER_URL_RE = re.compile(r"<([^>]+)>")
_LINK_HEADER_REL_NEXT_RE = re.compile(r"\brel\s*=\s*['\"]?next['\"]?", re.IGNORECASE)


@dataclass(frozen=True)
class _PageCandidate:
    url: str
    source: str


class _NextLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.next_hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() not in {"a", "link"}:
            return
        attr_map = {name.lower(): value or "" for name, value in attrs}
        rel = attr_map.get("rel", "")
        href = attr_map.get("href", "")
        if not href or not rel:
            return
        rel_tokens = {token.strip().lower() for token in rel.split()}
        if "next" in rel_tokens:
            self.next_hrefs.append(href)


def _read_status(response: Any) -> int:
    try:
        return int(getattr(response, "status_code", 0) or 0)
    except Exception:  # noqa: BLE001 - defensive against odd response shapes
        return 0


def _read_content(response: Any) -> bytes:
    content = getattr(response, "content", b"")
    if isinstance(content, bytes):
        return content
    if isinstance(content, bytearray):
        return bytes(content)
    if isinstance(content, str):
        return content.encode("utf-8", errors="replace")
    return b""


def _read_text(response: Any) -> str:
    text = getattr(response, "text", "")
    if isinstance(text, str):
        return text
    content = _read_content(response)
    return content.decode("utf-8", errors="replace")


def _get_header(headers: Any, name: str) -> str:
    if not headers:
        return ""
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == name.lower():
                return str(value or "")
        return ""
    try:
        value = headers.get(name)
    except Exception:  # noqa: BLE001
        return ""
    return str(value or "")


def _normalize_body_text(raw_bytes: bytes) -> str:
    sample = raw_bytes[:_SAMPLE_BYTES].decode("utf-8", errors="replace")
    sample = re.sub(
        r"<(?:script|style|noscript|svg|iframe)[^>]*>.*?</(?:script|style|noscript|svg|iframe)>",
        " ",
        sample,
        flags=re.IGNORECASE | re.DOTALL,
    )
    sample = re.sub(r"<[^>]+>", " ", sample)
    sample = unescape(sample)
    sample = sample.lower()
    sample = _WHITESPACE_RE.sub(" ", sample)
    return sample.strip()


def _body_hash(raw_bytes: bytes) -> str:
    normalized = _normalize_body_text(raw_bytes)
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def _parse_next_links_from_headers(headers: Any) -> list[str]:
    link_header = _get_header(headers, "link")
    if not link_header:
        return []
    candidates: list[str] = []
    for part in link_header.split(","):
        if not _LINK_HEADER_REL_NEXT_RE.search(part):
            continue
        match = _LINK_HEADER_URL_RE.search(part)
        if match:
            candidates.append(match.group(1).strip())
    return candidates


def _parse_next_links_from_html(text: str) -> list[str]:
    if not text:
        return []
    parser = _NextLinkParser()
    try:
        parser.feed(text[:_SAMPLE_BYTES])
    except Exception:  # noqa: BLE001 - malformed HTML should not abort pagination
        return []
    return parser.next_hrefs


def _parse_json_item_count(raw_bytes: bytes) -> int:
    text = raw_bytes.decode("utf-8", errors="replace").strip()
    if not text:
        return 0
    try:
        payload = json.loads(text)
    except Exception:
        return 0
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        for key in ("items", "results", "data", "entries"):
            value = payload.get(key)
            if isinstance(value, list):
                return len(value)
    return 0


def _estimate_item_count(raw_bytes: bytes, url: str) -> int:
    count = _parse_json_item_count(raw_bytes)
    if count > 0:
        return count
    text = raw_bytes[:_SAMPLE_BYTES].decode("utf-8", errors="replace").lower()
    count = len(re.findall(r"<(?:li|tr|article|option)\b", text, flags=re.IGNORECASE))
    if count > 0:
        return count
    if raw_bytes:
        return 1
    return 0


def _normalize_url_for_seen(url: str) -> str:
    split = urlsplit(url)
    query_pairs = parse_qsl(split.query, keep_blank_values=True)
    query_pairs.sort()
    query = urlencode(query_pairs)
    scheme = (split.scheme or "https").lower()
    netloc = split.netloc.lower()
    path = split.path or "/"
    return urlunsplit((scheme, netloc, path, query, ""))


def _replace_query_value(url: str, key: str, value: int) -> str | None:
    split = urlsplit(url)
    if not split.scheme or not split.netloc:
        return None
    pairs = parse_qsl(split.query, keep_blank_values=True)
    updated = False
    rebuilt: list[tuple[str, str]] = []
    for current_key, current_value in pairs:
        if current_key == key and not updated:
            rebuilt.append((current_key, str(value)))
            updated = True
        else:
            rebuilt.append((current_key, current_value))
    if not updated:
        return None
    query = urlencode(rebuilt)
    return urlunsplit((split.scheme, split.netloc, split.path, query, split.fragment))


def _increment_query_candidate(url: str, key: str, step: int = 1) -> str | None:
    split = urlsplit(url)
    pairs = parse_qsl(split.query, keep_blank_values=True)
    for current_key, current_value in pairs:
        if current_key != key:
            continue
        try:
            next_value = int(current_value) + step
        except ValueError:
            return None
        return _replace_query_value(url, key, next_value)
    return None


def _increment_path_candidate(url: str) -> str | None:
    split = urlsplit(url)
    path = split.path or "/"
    match = _PATH_PAGE_RE.match(path)
    if not match:
        match = _PATH_TRAILING_NUM_RE.match(path)
    if not match:
        return None
    prefix = match.group("prefix")
    suffix = match.group("suffix") or ""
    try:
        next_num = int(match.group("num")) + 1
    except ValueError:
        return None
    next_path = f"{prefix}/{next_num}{suffix}"
    return urlunsplit((split.scheme, split.netloc, next_path, split.query, split.fragment))


def _infer_offset_step(url: str, raw_bytes: bytes) -> int:
    split = urlsplit(url)
    pairs = parse_qsl(split.query, keep_blank_values=True)
    for key, value in pairs:
        if key.lower() in _OFFSET_SIZE_PARAM_NAMES:
            try:
                step = int(value)
            except ValueError:
                continue
            if step > 0:
                return step
    return max(1, _estimate_item_count(raw_bytes, url))


def _increment_offset_candidate(url: str, raw_bytes: bytes) -> str | None:
    split = urlsplit(url)
    pairs = parse_qsl(split.query, keep_blank_values=True)
    for key, value in pairs:
        if key.lower() not in _OFFSET_PARAM_NAMES:
            continue
        try:
            offset = int(value)
        except ValueError:
            return None
        step = _infer_offset_step(url, raw_bytes)
        return _replace_query_value(url, key, offset + step)
    return None


def _candidate_next_urls(url: str, response: Any, raw_bytes: bytes) -> list[_PageCandidate]:
    candidates: list[_PageCandidate] = []
    seen: set[str] = set()

    def add(candidate_url: str | None, source: str) -> None:
        if not candidate_url:
            return
        resolved = urljoin(url, candidate_url)
        normalized = _normalize_url_for_seen(resolved)
        if normalized in seen:
            return
        seen.add(normalized)
        candidates.append(_PageCandidate(url=resolved, source=source))

    headers = getattr(response, "headers", {}) or {}
    for candidate in _parse_next_links_from_headers(headers):
        add(candidate, "link_header")

    text = _read_text(response)
    for candidate in _parse_next_links_from_html(text):
        add(candidate, "html_next")

    if not candidates:
        for key in _PAGE_PARAM_NAMES:
            add(_increment_query_candidate(url, key), f"query:{key}")
    if not candidates:
        add(_increment_offset_candidate(url, raw_bytes), "query:offset")
    if not candidates:
        add(_increment_path_candidate(url), "path")

    return candidates


class PaginationHandler:
    """Traverse list endpoints while following the next-page chain."""

    def __init__(
        self,
        fetch: CachedFetch,
        *,
        max_pages: int = _DEFAULT_MAX_PAGES,
        max_items: int = _DEFAULT_MAX_ITEMS,
        item_counter: Callable[[bytes, str], int] | None = None,
    ) -> None:
        if max_pages <= 0:
            raise ValueError("max_pages must be positive")
        if max_items <= 0:
            raise ValueError("max_items must be positive")
        self._fetch = fetch
        self._max_pages = int(max_pages)
        self._max_items = int(max_items)
        self._item_counter = item_counter

    def extract_next_url(self, current_url: str, html: bytes | str) -> str | None:
        """Return the first HTML rel=next URL for a fetched listing page."""
        if not current_url:
            return None
        if isinstance(html, bytes):
            text = html.decode("utf-8", errors="replace")
        else:
            text = str(html or "")
        for candidate in _parse_next_links_from_html(text):
            return urljoin(current_url, candidate)
        return None

    async def paginate(self, url: str) -> AsyncIterator[tuple[str, bytes]]:
        current_url = (url or "").strip()
        if not current_url:
            return

        seen_urls: set[str] = set()
        previous_hash: str | None = None
        total_items = 0

        for _page_index in range(self._max_pages):
            normalized_current = _normalize_url_for_seen(current_url)
            if normalized_current in seen_urls:
                break
            seen_urls.add(normalized_current)

            response = await self._fetch.get(current_url)
            status = _read_status(response)
            if status in (404, 410):
                break
            if status < 200 or status >= 300:
                break

            raw_bytes = _read_content(response)
            current_hash = _body_hash(raw_bytes)
            if previous_hash is not None and current_hash == previous_hash:
                break

            yield current_url, raw_bytes

            if self._item_counter is not None:
                try:
                    page_items = int(self._item_counter(raw_bytes, current_url))
                except Exception:  # noqa: BLE001 - caller-provided counter is advisory
                    page_items = 0
            else:
                page_items = _estimate_item_count(raw_bytes, current_url)
            total_items += max(0, page_items)
            if total_items >= self._max_items:
                break

            previous_hash = current_hash
            next_candidates = _candidate_next_urls(current_url, response, raw_bytes)
            if not next_candidates:
                break

            next_url = next_candidates[0].url
            normalized_next = _normalize_url_for_seen(next_url)
            if normalized_next in seen_urls:
                break
            current_url = next_url


__all__ = ["PaginationHandler"]
