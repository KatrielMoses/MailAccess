"""Supported Brave Search API adapter for harvest search queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from .http_client import build_client

_BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"


@dataclass
class SearchResult:
    title: str
    snippet: str
    url: str
    query_used: str


class BraveSearchDorker:
    """Query Brave's supported JSON search API with bounded requests."""

    def __init__(self, api_key: str, *, timeout: float = 10.0) -> None:
        self._api_key = api_key.strip()
        self._timeout = timeout

    async def search(
        self, client: httpx.AsyncClient, query: str, *, count: int = 20
    ) -> tuple[list[SearchResult], str | None, bool]:
        """Return results, an error string, and whether the provider blocked us."""
        if not query:
            return [], None, False
        try:
            response = await client.get(
                _BRAVE_SEARCH_URL,
                params={"q": query, "count": min(max(count, 1), 20)},
                headers={
                    "Accept": "application/json",
                    "X-Subscription-Token": self._api_key,
                },
                timeout=self._timeout,
            )
        except httpx.TimeoutException:
            return [], f"Brave Search timed out for query={query!r}", False
        except Exception as exc:  # noqa: BLE001
            return [], f"Brave Search transport error: {exc}", False

        if response.status_code in (401, 403):
            return [], f"Brave Search authentication rejected (HTTP {response.status_code})", True
        if response.status_code == 429:
            return [], "Brave Search rate limit reached (HTTP 429)", True
        if response.status_code != 200:
            return [], f"Brave Search returned HTTP {response.status_code}", False

        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            return [], f"Brave Search returned invalid JSON: {exc}", False
        web = payload.get("web") if isinstance(payload, dict) else {}
        rows = web.get("results") if isinstance(web, dict) else []
        results: list[SearchResult] = []
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or "").strip()
            if not url:
                continue
            results.append(
                SearchResult(
                    title=str(row.get("title") or ""),
                    snippet=str(row.get("description") or ""),
                    url=url,
                    query_used=query,
                )
            )
        return results, None, False


__all__ = ["BraveSearchDorker", "SearchResult"]
