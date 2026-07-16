"""Bounded search-provider routing for reactive harvest pivots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import settings
from .bing_dorker import BingDorker
from .brave_dorker import BraveSearchDorker
from .duckduckgo_dorker import DuckDuckGoDorker
from .http_client import build_client


@dataclass(frozen=True)
class RoutedSearchResult:
    title: str
    snippet: str
    url: str
    provider: str


class SearchProviderRouter:
    """Prefer configured Brave Search, then fall back from DDG to Bing."""

    def __init__(self, *, fetch: Any | None = None) -> None:
        self.fetch = fetch

    async def search(self, query: str, *, max_results: int = 10) -> list[RoutedSearchResult]:
        brave_key = str(getattr(settings, "brave_search_api_key", "") or "").strip()
        if brave_key:
            async with build_client(timeout=10.0) as client:
                rows, error, blocked = await BraveSearchDorker(brave_key).search(
                    client, query, count=max_results
                )
            if rows and not error:
                return [
                    RoutedSearchResult(row.title, row.snippet, row.url, "brave") for row in rows
                ]
            if blocked:
                return []

        ddg = DuckDuckGoDorker(fetch=self.fetch, min_interval=0.0)
        rows, blocked = await ddg.search(query, max_results=max_results)
        if rows:
            return [RoutedSearchResult(row.title, row.snippet, row.url, "ddg") for row in rows]
        # An empty DDG page is also a reason to try the secondary provider;
        # it often reflects a soft challenge that lacks explicit markers.
        bing = BingDorker(fetch=self.fetch, min_interval=0.0)
        rows, _blocked = await bing.search(query, max_results=max_results)
        return [RoutedSearchResult(row.title, row.snippet, row.url, "bing") for row in rows]


__all__ = ["RoutedSearchResult", "SearchProviderRouter"]
