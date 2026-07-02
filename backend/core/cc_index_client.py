"""Async Common Crawl Index API client.

This module is the entry point for Domain Email Harvest (Phase A of the
0.10.0 rebuild).  It exposes a thin wrapper around the Common Crawl
Index API — used to discover WARC records for a target domain, which are
later fetched and scanned for email addresses.

Design notes:
- Public endpoints only, no API key required.
- We respect a 1-request-per-2-seconds courtesy window per research
  recommendations.
- The latest collection index name (CC-MAIN-YYYY-WW) is cached for 24h
  because the index changes roughly monthly.
- Every method degrades gracefully — network failures return empty data
  and log a warning rather than raising.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

from ..config import APP_VERSION, settings

_LOG = logging.getLogger(__name__)

_INDEX_BASE = "https://index.commoncrawl.org"
_COLLINFO_URL = f"{_INDEX_BASE}/collinfo.json"
_CC_UA = (
    f"MailAccess/{APP_VERSION} "
    "(+https://github.com/KatrielMoses/MailAccess)"
)
_DEFAULT_TIMEOUT = 10.0
_CACHE_TTL_SECONDS = 24 * 60 * 60
_CC_REQUEST_INTERVAL = 2.0


@dataclass
class CCRecord:
    """A single Common Crawl URL Index hit ready to be fetched."""

    url: str
    timestamp: str
    filename: str
    offset: int
    length: int
    mime: str | None
    status: str


class CommonCrawlClient:
    """Thin async wrapper around the Common Crawl Index API.

    A single instance should be used per logical harvest run.  The class
    does not manage its own :class:`httpx.AsyncClient` lifetime — pass
    one in via the *transport* argument (typically a ``httpx.AsyncClient``
    returned by :func:`backend.core.http_client.build_client`).
    """

    def __init__(
        self,
        transport: httpx.AsyncClient | None = None,
        min_interval: float = _CC_REQUEST_INTERVAL,
    ) -> None:
        self._owns_transport = transport is None
        if transport is None:
            self._client: httpx.AsyncClient = httpx.AsyncClient(
                timeout=_DEFAULT_TIMEOUT,
                headers={"User-Agent": _CC_UA},
            )
        else:
            self._client = transport
        self._min_interval = max(float(min_interval), 0.0)
        self._last_request_at: float = 0.0
        self._index_lock = asyncio.Lock()
        self._cached_index: str | None = None
        self._cached_at: float = 0.0

    async def aclose(self) -> None:
        """Close the underlying client if this instance owns it."""
        if self._owns_transport:
            await self._client.aclose()

    async def __aenter__(self) -> CommonCrawlClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_request_at
        wait = self._min_interval - elapsed
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_at = time.monotonic()

    async def _get(self, url: str, params: dict[str, Any] | None = None) -> httpx.Response | None:
        """GET with one retry on timeout / connection errors."""
        attempt = 0
        backoff = 2.0
        while attempt < 2:
            attempt += 1
            await self._throttle()
            try:
                response = await self._client.get(
                    url,
                    params=params,
                    headers={"User-Agent": _CC_UA},
                )
                return response
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                _LOG.warning("Common Crawl request failed (%s/2): %s", attempt, exc)
                if attempt >= 2:
                    return None
                await asyncio.sleep(backoff)
            except Exception as exc:  # pragma: no cover - defensive
                _LOG.warning("Common Crawl unexpected error: %s", exc)
                return None
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def get_latest_index_name(self, force_refresh: bool = False) -> str | None:
        """Return the most recent ``CC-MAIN-YYYY-WW`` index name.

        Cached for 24h — collections update monthly.
        """
        async with self._index_lock:
            now = time.monotonic()
            if (
                not force_refresh
                and self._cached_index is not None
                and (now - self._cached_at) < _CACHE_TTL_SECONDS
            ):
                return self._cached_index

            response = await self._get(_COLLINFO_URL)
            if response is None or response.status_code != 200:
                _LOG.warning("Common Crawl collinfo.json unavailable (latest index)")
                return self._cached_index

            try:
                payload = response.json()
            except json.JSONDecodeError:
                _LOG.warning("Common Crawl collinfo.json returned invalid JSON")
                return self._cached_index

            if not isinstance(payload, list) or not payload:
                _LOG.warning("Common Crawl collinfo.json unexpected shape")
                return self._cached_index

            # Each entry is a dict with an "id" key like "CC-MAIN-2025-13".
            # Sort by id descending (lexicographic works because the WW tag
            # increments), take the first.
            best_id: str | None = None
            for entry in payload:
                if not isinstance(entry, dict):
                    continue
                candidate = entry.get("id")
                if not isinstance(candidate, str):
                    continue
                if best_id is None or candidate > best_id:
                    best_id = candidate
            if best_id is None:
                _LOG.warning("Common Crawl collinfo.json contains no usable id")
                return self._cached_index

            self._cached_index = best_id
            self._cached_at = now
            return best_id

    async def invalidate_index_cache(self) -> None:
        """Drop the cached index name.  Tests use this to bypass the TTL."""
        async with self._index_lock:
            self._cached_index = None
            self._cached_at = 0.0

    async def query_url_index(
        self,
        domain: str,
        limit: int = 200,
        index_name: str | None = None,
    ) -> list[CCRecord]:
        """Query the URL Index for a wildcard match of ``*.<domain>/*``.

        Parameters
        ----------
        domain:
            Target domain (e.g. ``example.com``).  Lowercased and stripped.
        limit:
            Maximum number of records to return.
        index_name:
            Optional explicit index.  Defaults to the most recent cached
            ``CC-MAIN-YYYY-WW`` collection — refetched if not yet cached.
        """
        cleaned = (domain or "").strip().lower()
        if not cleaned or "." not in cleaned:
            _LOG.debug("query_url_index: invalid domain %r", domain)
            return []

        if index_name is None:
            index_name = await self.get_latest_index_name()

        if not index_name:
            _LOG.warning("query_url_index: no Common Crawl index available")
            return []

        url = f"{_INDEX_BASE}/{index_name}-index"
        params = {
            "url": f"*.{cleaned}/*",
            "output": "json",
            "limit": str(max(1, int(limit))),
        }

        response = await self._get(url, params=params)
        if response is None:
            _LOG.warning("Common Crawl URL index unreachable for %s", cleaned)
            return []
        if response.status_code != 200:
            _LOG.warning(
                "Common Crawl URL index returned HTTP %s for %s", response.status_code, cleaned
            )
            return []

        records = self._parse_jsonl(response.text)
        return self._filter_and_sort(records, limit=int(limit))

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_jsonl(payload: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if not payload:
            return rows
        for line in payload.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
        return rows

    @staticmethod
    def _filter_and_sort(rows: list[dict[str, Any]], limit: int) -> list[CCRecord]:
        records: list[CCRecord] = []
        for row in rows:
            url = row.get("url")
            filename = row.get("filename")
            offset = row.get("offset")
            length = row.get("length")
            timestamp = row.get("timestamp")
            status = row.get("status")
            mime = row.get("mime")

            if not (isinstance(url, str) and isinstance(filename, str)):
                continue
            if not (isinstance(offset, int) and isinstance(length, int)):
                # Some CC payloads encode these as numeric strings.
                try:
                    offset_i = int(offset)  # type: ignore[arg-type]
                    length_i = int(length)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    continue
            else:
                offset_i = offset
                length_i = length

            # Normalize status: 200 / "200" both treated as success.
            if status is None:
                continue
            status_str = str(status)
            if status_str != "200":
                continue

            # MIME filter — we only handle text-ish content.
            mime_str = str(mime) if mime is not None else ""
            if mime_str and ("html" not in mime_str and "text" not in mime_str):
                continue

            records.append(
                CCRecord(
                    url=url,
                    timestamp=str(timestamp) if timestamp is not None else "",
                    filename=filename,
                    offset=offset_i,
                    length=length_i,
                    mime=mime_str or None,
                    status=status_str,
                )
            )

        # Sort by timestamp descending; ties broken by URL for stable output.
        records.sort(key=lambda r: (r.timestamp, r.url), reverse=True)
        return records[: max(0, int(limit))]


def build_default_client() -> CommonCrawlClient:
    """Convenience factory used by the module layer."""
    _ = settings  # imported for parity with other modules; no settings used yet
    return CommonCrawlClient()
