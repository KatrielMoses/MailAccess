"""Native async client for the IntelligenceX search API."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

_LOG = logging.getLogger(__name__)


class IntelxError(RuntimeError):
    """Base error raised by the IntelligenceX client."""


class IntelxAuthError(IntelxError):
    """The API key was rejected."""


class IntelxCreditsError(IntelxError):
    """The account has no remaining API credits."""


class IntelxRateLimitError(IntelxError):
    """The API continued to rate-limit requests after retries."""


class IntelxTimeoutError(IntelxError):
    """A search did not finish within the bounded polling window."""


@dataclass
class IntelxRecord:
    systemid: str
    storageid: str
    name: str
    bucket: str
    media: int
    type: int
    date: str
    xscore: int
    accesslevel: int
    raw: dict[str, Any]


class IntelxClient:
    """Rate-limited wrapper around IntelligenceX's init-and-poll API."""

    _MIN_REQUEST_INTERVAL = 1.0
    _MAX_RATE_LIMIT_RETRIES = 3
    _MAX_POLLS = 30

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://2.intelx.io",
        user_agent: str = ("mailaccess/0.8.3 (OSINT research; mailaccess@example.com)"),
        timeout: float = 30.0,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ValueError("IntelligenceX API key must not be empty")

        self._api_key = api_key.strip()
        self._base_url = base_url.rstrip("/")
        self._user_agent = user_agent
        self._headers = {
            "X-Key": self._api_key,
            "User-Agent": self._user_agent,
            "Accept": "application/json",
        }
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=timeout,
            transport=transport,
        )
        self._last_request_at: float | None = None
        self._authenticate_cache: dict[str, Any] | None = None

    async def __aenter__(self) -> IntelxClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def authenticate_info(self) -> dict[str, Any]:
        """Return key/account capabilities, caching the successful response."""
        if self._authenticate_cache is None:
            self._authenticate_cache = await self._request("GET", "/authenticate/info")
        return dict(self._authenticate_cache)

    async def search(
        self,
        term: str,
        *,
        buckets: list[str] | None = None,
        max_results: int = 50,
        sort: int = 4,
        media: int = 0,
        timeout_seconds: int = 5,
    ) -> list[IntelxRecord]:
        """Initiate a search, poll it to completion, and return normalized records."""
        selected_buckets = buckets or ["leaks.public", "pastes"]
        search_id = await self._init_search(
            term,
            selected_buckets,
            max_results,
            sort,
            media,
            timeout_seconds,
        )
        if search_id is None:
            return []

        raw_records = await self._poll_until_done(
            search_id,
            limit=max_results,
            max_polls=self._MAX_POLLS,
        )
        return [self._to_record(record) for record in raw_records[:max_results]]

    async def _init_search(
        self,
        term: str,
        buckets: list[str],
        max_results: int,
        sort: int,
        media: int,
        timeout_seconds: int,
    ) -> str | None:
        payload = {
            "term": term,
            "buckets": buckets,
            "lookuplevel": 0,
            "maxresults": max_results,
            "timeout": timeout_seconds,
            "datefrom": "",
            "dateto": "",
            "sort": sort,
            "media": media,
            "terminate": [],
        }
        data = await self._request("POST", "/intelligent/search", json=payload)
        status = data.get("status")
        if status == 1:
            return None
        if status != 0:
            _LOG.warning("Intelx search init returned unexpected status %r", status)
            return None

        search_id = data.get("id")
        if not isinstance(search_id, str) or not search_id:
            _LOG.warning("Intelx search init response did not include a search id")
            return None
        return search_id

    async def _poll_results(self, search_id: str, limit: int) -> dict[str, Any]:
        return await self._request(
            "GET",
            "/intelligent/search/result",
            params={"id": search_id, "limit": limit},
        )

    async def _poll_until_done(
        self,
        search_id: str,
        limit: int,
        max_polls: int = 30,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for _ in range(max_polls):
            page = await self._poll_results(search_id, limit=limit)
            page_records = page.get("records") or []
            if isinstance(page_records, list):
                records.extend(record for record in page_records if isinstance(record, dict))
            else:
                _LOG.warning("Intelx search result records were not a list")

            status = page.get("status")
            if status in (1, 2):
                return records
            if status in (0, 3):
                continue
            _LOG.warning("Intelx returned unknown search status %r", status)
            return records

        raise IntelxTimeoutError(
            f"Intelx search {search_id} did not complete after {max_polls} polls"
        )

    async def _rate_limit(self) -> None:
        if self._last_request_at is None:
            return
        remaining = self._MIN_REQUEST_INTERVAL - (time.monotonic() - self._last_request_at)
        if remaining > 0:
            await asyncio.sleep(remaining)

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        for attempt in range(self._MAX_RATE_LIMIT_RETRIES + 1):
            await self._rate_limit()
            try:
                response = await self._client.request(method, path, **kwargs)
            except httpx.HTTPError as exc:
                raise IntelxError(f"IntelligenceX request failed: {exc}") from exc
            finally:
                self._last_request_at = time.monotonic()

            if response.status_code == 429:
                if attempt >= self._MAX_RATE_LIMIT_RETRIES:
                    raise IntelxRateLimitError("HTTP 429 from IntelligenceX")
                await asyncio.sleep(float(2**attempt))
                continue
            if response.status_code in (401, 403):
                raise IntelxAuthError(f"HTTP {response.status_code} from IntelligenceX")
            if response.status_code == 402:
                raise IntelxCreditsError("HTTP 402 from IntelligenceX")
            if response.is_error:
                raise IntelxError(f"HTTP {response.status_code} from IntelligenceX {path}")

            try:
                data = response.json()
            except ValueError:
                _LOG.warning("Intelx returned non-JSON data from %s", path)
                return {}
            if not isinstance(data, dict):
                _LOG.warning("Intelx returned a non-object payload from %s", path)
                return {}
            return data

        raise IntelxRateLimitError("IntelligenceX rate-limit retry budget exhausted")

    @staticmethod
    def _to_record(raw: dict[str, Any]) -> IntelxRecord:
        return IntelxRecord(
            systemid=str(raw.get("systemid") or ""),
            storageid=str(raw.get("storageid") or ""),
            name=str(raw.get("name") or ""),
            bucket=str(raw.get("bucket") or ""),
            media=_safe_int(raw.get("media")),
            type=_safe_int(raw.get("type")),
            date=str(raw.get("date") or ""),
            xscore=_safe_int(raw.get("xscore")),
            accesslevel=_safe_int(raw.get("accesslevel")),
            raw=dict(raw),
        )


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
