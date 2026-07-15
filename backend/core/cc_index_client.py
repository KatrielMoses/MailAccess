"""Async Common Crawl Index API client.

This module is the entry point for Domain Email Harvest (Phase A of the
0.10.0 rebuild) and is extended in 0.11.1 Phase 3 to sweep multiple
Common Crawl collections concurrently and deduplicate by content
digest — not just by URL.

Design notes:
- Public endpoints only, no API key required.
- We respect a 1-request-per-2-seconds courtesy window per research
  recommendations.
- The latest collection index name (CC-MAIN-YYYY-WW) is cached for 24h
  because the index changes roughly monthly.  The full collection
  list has the same TTL — both refresh together when forced.
- Every method degrades gracefully — network failures return empty data
  and log a warning rather than raising.
- ``query_multi_collection`` sweeps up to N collections sequentially while
  honouring the per-request politeness budget so we do not hammer the index.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ..config import APP_VERSION, settings

_LOG = logging.getLogger(__name__)

_INDEX_BASE = "https://index.commoncrawl.org"
_INDEX_BASES = (
    _INDEX_BASE,
    "https://test-index.commoncrawl.org",
)
_COLLINFO_URL = f"{_INDEX_BASE}/collinfo.json"
_CDX_BASE = f"{_INDEX_BASE}/cdx-by-index"
_CC_UA = (
    f"MailAccess/{APP_VERSION} "
    "(+https://github.com/KatrielMoses/MailAccess)"
)
_DEFAULT_TIMEOUT = 10.0
_CDX_TIMEOUT = 15.0
_CACHE_TTL_SECONDS = 24 * 60 * 60
_CC_REQUEST_INTERVAL = 2.0
_COLLECTION_CACHE_PATH = Path.home() / ".mailaccess" / "cache" / "commoncrawl_collections.json"

# Regex syntax used by Common Crawl to match high-signal URL paths
# (about / team / contact / leadership / people / staff / board /
# press / news).  ``( )`` groups are alternations the index treats
# as "match any of these path segments".
_HIGH_SIGNAL_PATH_REGEX = (
    "(team|about|contact|leadership|people|staff|board|press|news)"
)


@dataclass
class CCRecord:
    """A single Common Crawl URL Index hit ready to be fetched.

    ``collection`` was added in 0.11.1 Phase 3 — it tracks which
    collection the record came from so analysts can see which crawl
    surfaced an address.  Older single-collection callers leave it
    ``None``.
    """

    url: str
    timestamp: str
    filename: str
    offset: int
    length: int
    mime: str | None
    status: str
    collection: str | None = None
    digest: str | None = field(default=None)


@dataclass
class _CollInfo:
    """Internal cache struct — the full collection list + the latest id."""

    ids: tuple[str, ...]
    latest: str | None
    fetched_at: float


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
        # Phase 3: separate cache for the full collection list.  Both
        # caches use the same TTL — refreshing ``get_available_collections``
        # also brings ``get_latest_index_name`` up to date.
        self._cached_collections: _CollInfo | None = None
        self._load_persisted_collections()

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
                    follow_redirects=True,
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

    def _load_persisted_collections(self) -> None:
        """Load the last known collection list for upstream outage fallback."""
        try:
            payload = json.loads(_COLLECTION_CACHE_PATH.read_text(encoding="utf-8"))
            ids = payload.get("ids") if isinstance(payload, dict) else None
            if not isinstance(ids, list) or not ids:
                return
            valid_ids = tuple(item for item in ids if isinstance(item, str) and item.startswith("CC-MAIN-"))
            if valid_ids:
                latest = payload.get("latest") if isinstance(payload.get("latest"), str) else valid_ids[0]
                self._cached_collections = _CollInfo(valid_ids, latest, time.monotonic())
                self._cached_index = latest
                self._cached_at = time.monotonic()
        except (OSError, ValueError, TypeError):
            return

    def _persist_collections(self, info: _CollInfo) -> None:
        try:
            _COLLECTION_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            _COLLECTION_CACHE_PATH.write_text(
                json.dumps({"ids": list(info.ids), "latest": info.latest}),
                encoding="utf-8",
            )
        except OSError:
            _LOG.debug("Unable to persist Common Crawl collection cache", exc_info=True)

    async def _get_collinfo(self) -> httpx.Response | None:
        """Try the primary and documented test index hosts in order."""
        for base in _INDEX_BASES:
            response = await self._get(f"{base}/collinfo.json")
            if response is not None and response.status_code == 200:
                return response
        return None

    # ------------------------------------------------------------------
    # Public API — single-collection (legacy / 0.10.0 callers)
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

            response = await self._get_collinfo()
            if response is None or response.status_code != 200:
                _LOG.warning("Common Crawl collinfo.json unavailable (latest index)")
                return self._cached_index

            try:
                payload = response.json()
            except json.JSONDecodeError:
                _LOG.warning("Common Crawl collinfo.json returned invalid JSON")
                return self._cached_index

            info = self._parse_collinfo(payload)
            if info is None:
                return self._cached_index

            self._cached_collections = info
            self._cached_index = info.latest
            self._cached_at = now
            self._persist_collections(info)
            return info.latest

    async def invalidate_index_cache(self) -> None:
        """Drop the cached index name.  Tests use this to bypass the TTL."""
        async with self._index_lock:
            self._cached_index = None
            self._cached_at = 0.0
            self._cached_collections = None

    # ------------------------------------------------------------------
    # Public API — multi-collection (Phase 3)
    # ------------------------------------------------------------------
    async def get_available_collections(
        self,
        force_refresh: bool = False,
    ) -> list[str]:
        """Return all known collection IDs newest-first.

        The list comes from ``collinfo.json`` and is cached for 24h.
        Each entry is a ``CC-MAIN-YYYY-WW`` ID suitable for direct use
        as the ``index_name`` argument on :meth:`query_url_index` or
        as the ``collection`` field on the per-collection URL Index.
        """
        async with self._index_lock:
            now = time.monotonic()
            if (
                not force_refresh
                and self._cached_collections is not None
                and (now - self._cached_collections.fetched_at) < _CACHE_TTL_SECONDS
            ):
                return list(self._cached_collections.ids)

            response = await self._get_collinfo()
            if response is None or response.status_code != 200:
                _LOG.warning("Common Crawl collinfo.json unavailable (list)")
                return list(self._cached_collections.ids) if self._cached_collections else []

            try:
                payload = response.json()
            except json.JSONDecodeError:
                _LOG.warning("Common Crawl collinfo.json returned invalid JSON (list)")
                return (
                    list(self._cached_collections.ids) if self._cached_collections else []
                )

            info = self._parse_collinfo(payload)
            if info is None:
                return (
                    list(self._cached_collections.ids) if self._cached_collections else []
                )

            self._cached_collections = info
            self._cached_index = info.latest
            self._cached_at = now
            self._persist_collections(info)
            return list(info.ids)

    async def query_multi_collection(
        self,
        domain: str,
        max_collections: int = 6,
        max_records_per_collection: int = 250,
        aggressive: bool = False,
    ) -> list[CCRecord]:
        """Sweep multiple Common Crawl collections for *domain*.

        Parameters
        ----------
        domain:
            Target domain (e.g. ``"example.com"``).  Lowercased / stripped.
        max_collections:
            Cap on the number of collections to sweep.  When
            ``aggressive=True`` the value is doubled to 24.
        max_records_per_collection:
            ``limit`` value handed to CDX per collection.  When
            ``aggressive=True`` this is raised to 500.
        aggressive:
            Opt-in flag for low-recall-but-coverage-heavy harvests
            (the CLI ``--aggressive`` mode sets this).

        Returns
        -------
        list[CCRecord]
            De-duplicated across collections by ``(urlkey, digest)``
            pair — a page seen in two collections only appears once.
            Sorted newest-first by ``timestamp`` then URL for stable
            output.  Every record carries its origin ``collection``.
        """
        cleaned = (domain or "").strip().lower()
        if not cleaned or "." not in cleaned:
            _LOG.debug("query_multi_collection: invalid domain %r", domain)
            return []

        eff_max_collections = 24 if aggressive else int(max_collections)
        eff_max_records = 500 if aggressive else int(max_records_per_collection)
        eff_max_collections = max(1, eff_max_collections)
        eff_max_records = max(1, eff_max_records)

        # Resolve the collection list.
        try:
            collection_ids = await self.get_available_collections()
        except Exception as exc:  # noqa: BLE001 — defensive
            _LOG.warning("query_multi_collection: collinfo failed (%s)", exc)
            collection_ids = []

        # If the cache is empty (network unreachable), fall back to the
        # single-collection legacy method so the module never starves.
        if not collection_ids:
            fallback = await self.get_latest_index_name()
            if not fallback:
                return []
            collection_ids = [fallback]

        collection_ids = collection_ids[:eff_max_collections]

        # ------------------------------------------------------------------
        # Parallel sweep — broad + targeted query per collection.
        # ``asyncio.gather`` keeps the total wall-time bounded by the
        # slowest single query, not the sum of all of them.
        # ------------------------------------------------------------------
        async def _sweep_one(coll: str) -> list[CCRecord]:
            try:
                broad, targeted = await asyncio.gather(
                    self._query_index(
                        coll,
                        cleaned,
                        url_pattern=f"*.{cleaned}/*",
                        limit=eff_max_records,
                    ),
                    self._query_index(
                        coll,
                        cleaned,
                        url_pattern=f"{cleaned}/{_HIGH_SIGNAL_PATH_REGEX}/*",
                        limit=None,  # no cap on the targeted query
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                _LOG.debug(
                    "query_multi_collection: collection %s sweep failed (%s)",
                    coll,
                    exc,
                )
                return []

            combined = broad + targeted
            for record in combined:
                record.collection = coll
            return combined

        flat: list[CCRecord] = []
        # Common Crawl asks clients not to run multiple CDX requests at once.
        # Keep collection order deterministic and let _get enforce the
        # courtesy interval between requests.
        for coll in collection_ids:
            try:
                flat.extend(await _sweep_one(coll))
            except Exception:  # pragma: no cover - defensive per-collection guard
                _LOG.debug("query_multi_collection: collection %s sweep failed", coll, exc_info=True)

        return self._dedupe_across_collections(flat)

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_collinfo(payload: Any) -> _CollInfo | None:
        """Parse ``collinfo.json`` and return a sorted collection list.

        ``payload`` is an iterable of dicts each with an ``id`` key
        like ``CC-MAIN-2025-13``.  The list is sorted descending (newest
        first).  ``latest`` is the highest-id entry.

        Returns ``None`` when the payload is malformed / empty so the
        caller can keep the previous cached value.
        """
        if not isinstance(payload, list) or not payload:
            return None

        ids: list[str] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            cid = entry.get("id")
            if not isinstance(cid, str):
                continue
            ids.append(cid)
        if not ids:
            return None

        ids.sort(reverse=True)
        return _CollInfo(
            ids=tuple(ids),
            latest=ids[0],
            fetched_at=time.monotonic(),
        )

    async def _query_index(
        self,
        collection: str,
        domain: str,
        *,
        url_pattern: str,
        limit: int | None,
    ) -> list[CCRecord]:
        """Run a single CDX query against a single collection.

        The CDX endpoint URL is constructed per-collection; we add
        ``collapse=urlkey:digest`` so the response is already deduped
        *within* a single collection.  Cross-collection dedup happens
        in :meth:`_dedupe_across_collections`.
        """
        params: dict[str, Any] = {
            "url": url_pattern,
            "output": "json",
            "filter": ["statuscode:200", "mime:text/html"],
            "collapse": "urlkey:digest",
        }
        if limit is not None and int(limit) > 0:
            params["limit"] = str(int(limit))

        response: httpx.Response | None = None
        for base in _INDEX_BASES:
            candidate = await self._get(f"{base}/{collection}-index", params=params)
            if candidate is not None and candidate.status_code == 200:
                response = candidate
                break
        if response is None:
            _LOG.debug("Common Crawl CDX query unreachable for collection %s", collection)
            return []

        records = self._parse_jsonl(response.text)
        # Mark each record with this collection's id before we sort.
        for record in records:
            record["__collection__"] = collection
        return self._filter_and_sort(records, limit=int(limit) if limit else 0)

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
    def _filter_and_sort(
        rows: list[dict[str, Any]],
        limit: int,
    ) -> list[CCRecord]:
        """CDX JSONL → ``CCRecord`` list, sorted newest-first.

        Populated rows must already be filtered to status=200 + text-ish
        MIME by the upstream call (we still re-check defensively
        because CDX occasionally emits a row that fails to deserialise
        its offset/length fields cleanly).
        """
        records: list[CCRecord] = []
        for row in rows:
            url = row.get("url")
            filename = row.get("filename")
            offset = row.get("offset")
            length = row.get("length")
            timestamp = row.get("timestamp")
            status = row.get("status")
            mime = row.get("mime")
            digest = row.get("digest")
            collection = row.get("__collection__")

            if not (isinstance(url, str) and isinstance(filename, str)):
                continue
            if not (isinstance(offset, int) and isinstance(length, int)):
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
                    collection=collection if isinstance(collection, str) else None,
                    digest=digest if isinstance(digest, str) else None,
                )
            )

        # Sort by timestamp descending; ties broken by URL for stable output.
        records.sort(key=lambda r: (r.timestamp, r.url), reverse=True)
        if limit and int(limit) > 0:
            return records[: int(limit)]
        return records

    @staticmethod
    def _dedupe_across_collections(records: list[CCRecord]) -> list[CCRecord]:
        """Drop records whose content digest we've already seen.

        Dedup key preference (highest fidelity first):

        1. ``digest`` — same digest ⇒ byte-identical WARC payload.
        2. ``url`` + ``filename`` + ``offset`` — when digest is absent,
           the same ``(URL, WARC file, offset)`` triple maps to one
           physical record on the S3 mirror.

        The first occurrence wins.  Records with neither digest nor a
        parseable offset are kept as-is because we have no safe way to
        decide whether they are duplicates.
        """
        by_digest: dict[str, CCRecord] = {}
        by_anchor: dict[tuple[str, str, int], CCRecord] = {}
        kept: list[CCRecord] = []
        for record in records:
            digest_key = record.digest
            anchor_key: tuple[str, str, int] | None = None
            try:
                if record.filename and record.offset is not None:
                    anchor_key = (record.url, record.filename, int(record.offset))
            except (TypeError, ValueError):
                anchor_key = None

            if digest_key:
                existing = by_digest.get(digest_key)
                if existing is not None:
                    continue
                by_digest[digest_key] = record
                kept.append(record)
                continue
            if anchor_key is not None:
                existing = by_anchor.get(anchor_key)
                if existing is not None:
                    continue
                by_anchor[anchor_key] = record
                kept.append(record)
                continue
            kept.append(record)
        return kept

    # ------------------------------------------------------------------
    # Legacy single-collection entry point — preserved for tests
    # ------------------------------------------------------------------
    async def query_url_index(
        self,
        domain: str,
        limit: int = 200,
        index_name: str | None = None,
    ) -> list[CCRecord]:
        """Query the URL Index for a wildcard match of ``*.<domain>/*``.

        Retained from 0.10.0 for the single-collection code path.
        Phase 3 callers should prefer :meth:`query_multi_collection`.
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

        return await self._query_index(
            index_name,
            cleaned,
            url_pattern=f"*.{cleaned}/*",
            limit=int(limit) if int(limit) > 0 else None,
        )


def build_default_client() -> CommonCrawlClient:
    """Convenience factory used by the module layer."""
    _ = settings  # imported for parity with other modules; no settings used yet
    return CommonCrawlClient()
