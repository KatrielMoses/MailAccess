"""WARC range fetcher + direct page-fetch fallback for Common Crawl records.

MailAccess 0.11.1 Phase 3 — Archive Intelligence.

Two fetch strategies, in priority order:

1.  WARC range fetch — issues an HTTP ``Range`` request against
    ``https://data.commoncrawl.org/`` to grab only the bytes that contain
    the record of interest.  Saves bandwidth and avoids hitting the
    target website.
2.  Direct page fetch — falls back to a normal GET when the WARC fetch
    fails (S3 outage, malformed record, etc.).

The 0.11.1 Phase 3 additions on top of the 0.10.0 fetcher:

* After WARC decode (and after every direct fetch) the page HTML is
  passed through :func:`backend.core.cf_decode.cf_decode` so the email
  pass downstream sees the raw address instead of the obfuscated form.
* Per-fetch metadata (``collection_id``, ``original_url``,
  ``fetch_timestamp``, ``warc_offset``) is preserved on the
  :class:`CCFetchResult` so the harvesting module can record
  provenance per email finding.
* Per-page structured person extraction is exposed as a separate
  helper so the module layer can ask for both Person records and
  email findings without re-fetching.

All public methods never raise on network failure — they return
``None`` and log the reason instead.  This is critical because the
Common Crawl module wraps hundreds of fetches per harvest and a single
crash should never nuke the whole run.
"""

from __future__ import annotations

import asyncio
import gzip
import io
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

from ..config import APP_VERSION, settings
from .cc_index_client import CCRecord
from .cf_decode import cf_decode
from .structured_data_extractor import PersonRecord, extract_people

_LOG = logging.getLogger(__name__)

_S3_BASE = "https://data.commoncrawl.org"
_CC_UA = (
    f"MailAccess/{APP_VERSION} "
    "(+https://github.com/KatrielMoses/MailAccess)"
)
_MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MB cap before HTML truncation


def _user_agent() -> str:
    return _CC_UA


@dataclass
class CCFetchResult:
    """One fetch worth of data + per-source metadata.

    ``html``
        The decoded HTML page body (Cloudflare-obfuscation stripped).
    ``collection_id``
        Origin collection — ``None`` for direct-fallback fetches.
    ``original_url``
        The URL the record points at (matches ``record.url``).
    ``fetch_timestamp``
        ISO-8601 UTC timestamp of when the fetch completed.
    ``warc_offset``
        Byte offset into the WARC file — ``None`` for direct fetches.
    """

    html: str
    collection_id: str | None
    original_url: str
    fetch_timestamp: str
    warc_offset: int | None

    @property
    def is_historical(self) -> bool:
        """Common Crawl snapshots are by definition historical."""
        return True


def _now_iso() -> str:
    """Cheap ISO-8601 UTC timestamp — no external imports needed."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class CCPageFetcher:
    """Asynchronous WARC / direct fetcher used by the Common Crawl module.

    The fetcher is intentionally transport-agnostic: pass it an
    :class:`httpx.AsyncClient` so it shares the rate-limiter / proxy /
    User-Agent rotation configured by ``build_client()``.
    """

    def __init__(
        self,
        transport: httpx.AsyncClient | None = None,
        warc_timeout: float | None = None,
        direct_timeout: float | None = None,
        concurrency: int | None = None,
    ) -> None:
        self._owns_transport = transport is None
        if transport is None:
            timeout = (warc_timeout if warc_timeout is not None else 8.0)
            self._client = httpx.AsyncClient(
                timeout=float(timeout),
                headers={"User-Agent": _user_agent()},
                follow_redirects=True,
            )
        else:
            self._client = transport
        self._warc_timeout = float(warc_timeout) if warc_timeout is not None else 8.0
        self._direct_timeout = float(direct_timeout) if direct_timeout is not None else 6.0
        sem_limit = (
            int(concurrency)
            if concurrency is not None
            else int(getattr(settings, "cc_fetch_concurrency", 10) or 10)
        )
        self._sem = asyncio.Semaphore(max(1, sem_limit))

    async def aclose(self) -> None:
        if self._owns_transport:
            await self._client.aclose()

    async def __aenter__(self) -> CCPageFetcher:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def fetch_content(self, record: CCRecord) -> str | None:
        """Fetch page content, preferring WARC range, falling back to direct.

        Returned content is *post-CF-decode* — the same ``html`` the
        email-extractor will see downstream.
        """
        result = await self.fetch_with_metadata(record)
        return result.html if result is not None else None

    async def fetch_with_metadata(self, record: CCRecord) -> CCFetchResult | None:
        """Fetch *record* and return a :class:`CCFetchResult` with provenance.

        ``result.html`` is post-CF-decode.  ``result.collection_id``
        carries the originating collection.  Direct-fallback fetches
        leave ``collection_id`` set from the original record (which is
        fine — the source is still the indexed CC URL).

        Returns ``None`` when both WARC and direct attempts fail.
        """
        warc_offset_value: int | None = None
        try:
            if record.offset is not None:
                warc_offset_value = int(record.offset)
        except (TypeError, ValueError):
            warc_offset_value = None

        async with self._sem:
            warc = await self.fetch_warc_content(record)
            if warc is not None:
                decoded = cf_decode(warc)
                return CCFetchResult(
                    html=decoded,
                    collection_id=getattr(record, "collection", None),
                    original_url=record.url,
                    fetch_timestamp=_now_iso(),
                    warc_offset=warc_offset_value,
                )
            direct_html = await self.fetch_direct(record.url)
            if direct_html is None:
                return None
            decoded = cf_decode(direct_html)
            return CCFetchResult(
                html=decoded,
                collection_id=getattr(record, "collection", None),
                original_url=record.url,
                fetch_timestamp=_now_iso(),
                warc_offset=warc_offset_value,
            )

    async def fetch_many(self, records: list[CCRecord]) -> list[str | None]:
        """Fetch many records concurrently, returning results in order.

        Each entry is the decoded HTML body (``None`` for failures).
        Convenience wrapper around :meth:`fetch_content` for callers
        that do not need per-record metadata.
        """
        if not records:
            return []
        tasks = [self.fetch_content(record) for record in records]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def fetch_many_with_metadata(
        self, records: list[CCRecord]
    ) -> list[CCFetchResult | None]:
        """Like :meth:`fetch_many` but returns full :class:`CCFetchResult`s."""
        if not records:
            return []
        tasks = [self.fetch_with_metadata(record) for record in records]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def extract_people_from_html(
        self,
        html: str,
        page_url: str,
        domain: str,
    ) -> list[PersonRecord]:
        """Run structured-data person extraction on a single page body.

        Wraps :func:`backend.core.structured_data_extractor.extract_people`
        so the module layer does not need to import the extractor
        directly — keeps the dependency arrow pointing one way.
        """
        if not html:
            return []
        return extract_people(html, page_url, domain)

    async def fetch_warc_content(self, record: CCRecord) -> str | None:
        """Fetch a single WARC record via HTTP Range request and decode gzip."""
        if not record.filename:
            return None
        try:
            end = int(record.offset) + int(record.length) - 1
        except (TypeError, ValueError):
            return None
        if end < int(record.offset):
            return None

        url = f"{_S3_BASE}/{record.filename.lstrip('/')}"
        range_header = f"bytes={int(record.offset)}-{end}"

        try:
            response = await self._client.get(
                url,
                headers={
                    "User-Agent": _user_agent(),
                    "Range": range_header,
                    "Accept-Encoding": "identity",
                },
                timeout=self._warc_timeout,
            )
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            _LOG.debug("WARC fetch timeout/connect error for %s: %s", url, exc)
            return None
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.debug("WARC fetch unexpected error for %s: %s", url, exc)
            return None

        if response.status_code not in (200, 206):
            _LOG.debug(
                "WARC fetch non-success status %s for %s", response.status_code, url
            )
            return None

        try:
            raw = response.content
        except Exception as exc:
            _LOG.debug("WARC fetch could not read body for %s: %s", url, exc)
            return None

        if not raw:
            return None

        try:
            decompressed = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            _LOG.debug("WARC gzip decode failed for %s: %s", url, exc)
            return None

        try:
            text = decompressed.decode("utf-8", errors="replace")
        except Exception:
            return None

        body = _strip_warc_http_headers(text)
        # Cap decoded HTML at the configured maximum — never return
        # arbitrarily huge page bodies.
        encoded = body.encode("utf-8", errors="replace")
        if len(encoded) > _MAX_CONTENT_BYTES:
            encoded = encoded[:_MAX_CONTENT_BYTES]
            body = encoded.decode("utf-8", errors="replace")
        return body or None

    async def fetch_direct(self, url: str) -> str | None:
        """Fetch a URL directly via normal HTTP GET."""
        if not url:
            return None

        try:
            response = await self._client.get(
                url,
                headers={"User-Agent": _user_agent()},
                timeout=self._direct_timeout,
                follow_redirects=True,
            )
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            _LOG.debug("Direct fetch timeout/connect error for %s: %s", url, exc)
            return None
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.debug("Direct fetch unexpected error for %s: %s", url, exc)
            return None

        if response.status_code >= 400:
            _LOG.debug("Direct fetch HTTP %s for %s", response.status_code, url)
            return None

        try:
            text = response.text
        except Exception:
            return None

        if len(text.encode("utf-8", errors="ignore")) > _MAX_CONTENT_BYTES:
            encoded = text.encode("utf-8", errors="ignore")[:_MAX_CONTENT_BYTES]
            text = encoded.decode("utf-8", errors="replace")

        return text or None


def _strip_warc_http_headers(payload: str) -> str:
    """Strip WARC / HTTP header block, return raw HTML body if present.

    A Common Crawl WARC response record has the layout::

        WARC/1.0\\r\\n
        WARC-Type: response\\r\\n
        ...\\r\\n
        \\r\\n
        HTTP/1.1 200 OK\\r\\n
        Content-Type: text/html\\r\\n
        ...\\r\\n
        \\r\\n
        <html>...</html>

    We tolerate both single-``\\n`` and ``\\r\\n`` line endings.
    """
    if not payload:
        return ""

    # Locate end of WARC header block: blank line separates WARC headers
    # from the embedded HTTP response.
    norm = payload.replace("\r\n", "\n")
    warc_end = norm.find("\n\n")
    if warc_end == -1:
        # Not a well-formed WARC record — return text as-is.
        return payload.strip()

    http_block = norm[warc_end + 2 :]
    body_idx = http_block.find("\n\n")
    if body_idx == -1:
        # Fallback to entire post-WARC payload — might still be HTML.
        candidate = http_block.lstrip()
        if candidate.lower().startswith("<") or "<html" in candidate.lower():
            return candidate
        return payload.strip()

    body = http_block[body_idx + 2 :]
    # Skip leading HTTP headers section (lines until we hit a line that
    # looks like a content-body start — first non-whitespace line that
    # doesn't contain ":").  When present, the headers are above the
    # blank line we already advanced past.
    body = body.lstrip()
    return body
