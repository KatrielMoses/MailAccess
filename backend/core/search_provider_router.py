"""Bounded search-provider routing for reactive harvest pivots.

Phase 5B — a real failover chain with per-provider health/backoff. A provider
that returns a hard block (202/403/429/CAPTCHA) is benched for a cooldown and the
router transparently rolls to the next provider in the chain (Brave → DDG →
Bing). This replaces the old behaviour where a Brave block short-circuited the
whole chain and a benched provider was retried on every call.
"""

from __future__ import annotations

import time
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


class _ProviderHealth:
    """Process-wide per-provider block/backoff tracker.

    Shared across router instances within a run so that once (say) DDG throws a
    202 wall, subsequent reactive pivots skip it until the cooldown lapses
    instead of re-hitting the wall every time.
    """

    def __init__(self) -> None:
        self._benched_until: dict[str, float] = {}

    def available(self, provider: str) -> bool:
        until = self._benched_until.get(provider, 0.0)
        return time.monotonic() >= until

    def bench(self, provider: str) -> None:
        cooldown = float(getattr(settings, "search_provider_cooldown_seconds", 300.0))
        self._benched_until[provider] = time.monotonic() + cooldown

    def clear(self, provider: str | None = None) -> None:
        if provider is None:
            self._benched_until.clear()
        else:
            self._benched_until.pop(provider, None)


# Shared across the process (reactive pivots reuse the same health state).
_health = _ProviderHealth()


class SearchProviderRouter:
    """Failover chain: Brave (if keyed) → DuckDuckGo → Bing, with per-provider
    health/backoff. A block on one provider rolls to the next."""

    def __init__(self, *, fetch: Any | None = None) -> None:
        self.fetch = fetch

    def _chain(self) -> list[str]:
        chain = []
        if str(getattr(settings, "brave_search_api_key", "") or "").strip():
            chain.append("brave")
        chain.extend(["ddg", "bing"])
        return chain

    async def search(self, query: str, *, max_results: int = 10) -> list[RoutedSearchResult]:
        for provider in self._chain():
            if not _health.available(provider):
                continue
            rows, blocked = await self._run_provider(provider, query, max_results)
            if rows:
                return [
                    RoutedSearchResult(r.title, r.snippet, r.url, provider) for r in rows
                ]
            if blocked:
                # Hard block — bench this provider and roll to the next. An empty
                # (non-blocked) page also falls through to the next provider (it
                # often reflects a soft challenge with no explicit marker).
                _health.bench(provider)
        return []

    async def _run_provider(
        self, provider: str, query: str, max_results: int
    ) -> tuple[list[Any], bool]:
        """Return ``(rows, blocked)`` for one provider. Never raises."""
        try:
            if provider == "brave":
                brave_key = str(getattr(settings, "brave_search_api_key", "") or "").strip()
                if not brave_key:
                    return [], False
                async with build_client(timeout=10.0) as client:
                    rows, error, blocked = await BraveSearchDorker(brave_key).search(
                        client, query, count=max_results
                    )
                return (rows if (rows and not error) else []), bool(blocked)
            if provider == "ddg":
                ddg = DuckDuckGoDorker(fetch=self.fetch, min_interval=0.0)
                rows, blocked = await ddg.search(query, max_results=max_results)
                return rows or [], bool(blocked)
            if provider == "bing":
                bing = BingDorker(fetch=self.fetch, min_interval=0.0)
                rows, blocked = await bing.search(query, max_results=max_results)
                return rows or [], bool(blocked)
        except Exception:
            return [], False
        return [], False


__all__ = ["RoutedSearchResult", "SearchProviderRouter"]
