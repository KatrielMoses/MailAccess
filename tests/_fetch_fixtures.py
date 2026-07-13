"""Shared fetch-layer test fixtures.

Centralises the fakes used by tests that exercise modules wired to the
0.11.1 Phase 3 ``CachedFetch`` / ``ConcurrentFetchCache`` surface.  Reusing
these fakes across tests means:

* Module tests don't reinvent their own ``async def get`` stub.
* Tests assert against :class:`CachedResponse` attributes, never raw
  httpx / aiohttp objects, so the cache contract is what gets covered.
* ``make_cached_fetch`` records every URL the cache sees, which keeps
  "no extra fetches" assertions honest.

If a test wants real HTTP semantics (e.g. to exercise the cache's
URL normalisation across redirect edges) use the
``local_http_server`` fixture — but the default for module-level
tests is ``make_cached_fetch`` because it's faster and 100%
deterministic.

Everything here is async-safe and has no live network dependency.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from backend.core.concurrent_fetch_cache import (
    CachedFetch,
    CachedResponse,
    ConcurrentFetchCache,
)


# ---------------------------------------------------------------------------
# Response factory
# ---------------------------------------------------------------------------
def make_cached_response(
    body: str | bytes = "",
    *,
    status_code: int = 200,
    content_type: str = "text/html; charset=utf-8",
    headers: dict[str, str] | None = None,
) -> CachedResponse:
    """Build a :class:`CachedResponse` from a string body and metadata.

    Mirrors the shape :class:`ConcurrentFetchCache._wrap` produces from a
    curl-cffi / httpx response: ``status_code``, ``content`` (bytes),
    ``text`` (utf-8 decoded str), ``headers`` (str→str dict).
    """
    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
        text = body
    else:
        body_bytes = bytes(body)
        text = body_bytes.decode("utf-8", errors="replace")
    merged_headers = {"content-type": content_type}
    if headers:
        merged_headers.update(headers)
    return CachedResponse(
        status_code=status_code,
        content=body_bytes,
        text=text,
        headers=merged_headers,
    )


# ---------------------------------------------------------------------------
# Fake transport
# ---------------------------------------------------------------------------
class FakeSession:
    """Minimal stand-in for :class:`StealthSession` / the cache's transport.

    ``payloads`` is a URL → :class:`CachedResponse` lookup.  Calls to
    unknown URLs return a 200 with an empty body so tests that fan out
    to multiple endpoints only have to specify the ones they care
    about.  ``call_log`` records every URL the cache asked for, in
    order, which is what tests use to assert "no duplicate fetches".

    Two knobs that have proved useful:

    * ``call_delay`` — sleeps N seconds before returning, useful for
      forcing in-flight coalescing tests.
    * ``raise_after`` / ``exception`` — make the Nth call raise, useful
      for "cache error pass-through" coverage.
    """

    def __init__(
        self,
        payloads: dict[str, CachedResponse] | None = None,
        *,
        call_delay: float = 0.0,
        raise_after: int | None = None,
        exception: BaseException | None = None,
    ) -> None:
        self.payloads: dict[str, CachedResponse] = dict(payloads or {})
        self.call_log: list[str] = []
        self.call_count: int = 0
        self.call_delay: float = float(call_delay)
        self.raise_after = raise_after
        self.exception: BaseException | None = exception

    async def get(self, url: str, **kwargs: Any) -> CachedResponse:
        self.call_log.append(url)
        self.call_count += 1
        # Always yield so concurrent callers can race for the lock before
        # the fetch settles.  A synchronous raise lets the winner finish
        # before any waiter can coalesce — bad for coalescing coverage.
        await asyncio.sleep(0)
        if self.call_delay:
            await asyncio.sleep(self.call_delay)
        if self.raise_after is not None and self.call_count > self.raise_after:
            raise self.exception or RuntimeError(f"boom for {url}")
        return self.payloads.get(
            url,
            CachedResponse(
                status_code=200,
                content=b"",
                text="",
                headers={},
            ),
        )

    async def aclose(self) -> None:
        pass

    def close(self) -> None:  # pragma: no cover — sync fallback
        pass


# ---------------------------------------------------------------------------
# Convenience builders
# ---------------------------------------------------------------------------
def make_cached_fetch(
    responses_by_url: dict[str, CachedResponse] | None = None,
    *,
    session: FakeSession | None = None,
    max_entries: int = 500,
    max_bytes: int = 200 * 1024 * 1024,
) -> tuple[CachedFetch, ConcurrentFetchCache, FakeSession]:
    """Return ``(fetch, cache, session)`` wired for assertions.

    Tests usually want all three: the facade to inject into the module,
    the cache for ``stats()`` checks, and the session for
    ``call_log`` / ``call_count`` checks.  Returning the tuple saves a
    lot of repetitive boilerplate.

    Either pass canned responses by URL or your own pre-built session.
    """
    if session is None:
        session = FakeSession(payloads=responses_by_url or {})
    elif responses_by_url is not None:
        # Caller provided BOTH — treat the explicit responses as the
        # authoritative source and merge into the session.  Lets tests
        # like "session has a call_delay but also canned responses" work.
        session.payloads.update(responses_by_url)
    cache = ConcurrentFetchCache(
        session,
        max_entries=max_entries,
        max_bytes=max_bytes,
    )
    fetch = CachedFetch(cache)
    return fetch, cache, session


async def make_cached_fetch_async(
    responses_by_url: dict[str, CachedResponse] | None = None,
    **kwargs: Any,
) -> tuple[CachedFetch, ConcurrentFetchCache, FakeSession]:
    """Async variant of :func:`make_cached_fetch`.

    Use this from ``async def`` tests / fixtures where the surrounding
    code already owns an event loop, to keep the call site uniform.
    """
    return make_cached_fetch(responses_by_url, **kwargs)


# ---------------------------------------------------------------------------
# Optional: live-loopback HTTP dummy server
# ---------------------------------------------------------------------------
class LocalHttpServer:
    """Spin up a tiny aiohttp-style loopback HTTP server for cache tests.

    The dorker / sitemap / pagination modules only need GET with canned
    bodies, so we expose just enough of the http_client surface for the
    ConcurrentFetchCache to talk to.  Routes are added via :meth:`route`.

    Use sparingly — the default for module tests is
    :func:`make_cached_fetch`.  This fixture exists so that:
      * Cache normalisation tests can exercise real redirects / query
        ordering against a loopback socket.
      * ``pytest --integration`` runs can prove the cache itself does
        not break the wire contract.
    """

    def __init__(self) -> None:
        self._routes: dict[str, CachedResponse] = {}
        self._calls: list[str] = []

    def route(self, path: str, response: CachedResponse) -> None:
        self._routes[path] = response

    async def get(self, url: str, **kwargs: Any) -> CachedResponse:
        self._calls.append(url)
        # Strip host:port; we match on path + query.
        from urllib.parse import urlsplit

        path = urlsplit(url).path
        if path in self._routes:
            return self._routes[path]
        return CachedResponse(
            status_code=404, content=b"", text="", headers={}
        )

    async def aclose(self) -> None:
        pass


def make_local_fetch(
    routes: dict[str, CachedResponse] | None = None,
) -> tuple[CachedFetch, ConcurrentFetchCache, LocalHttpServer]:
    """Build a fetch/cache/server stack backed by :class:`LocalHttpServer`.

    The server is intentionally a thin shell, not a real aiohttp app,
    because none of our tests actually need a real socket — they need
    the cache to issue an ``async get(url)`` against something that
    returns a :class:`CachedResponse`.  Keeping it in-process avoids
    port collisions and shutdown races in CI.
    """
    server = LocalHttpServer()
    if routes:
        for path, response in routes.items():
            server.route(path, response)
    cache = ConcurrentFetchCache(server)
    fetch = CachedFetch(cache)
    return fetch, cache, server


__all__ = [
    "FakeSession",
    "LocalHttpServer",
    "make_cached_fetch",
    "make_cached_fetch_async",
    "make_cached_response",
    "make_local_fetch",
]


# Type alias kept here so test files don't have to import the typing
# module themselves when they want to type-annotate a fixture callback.
FetchFixtureFactory = Callable[
    ..., Awaitable[tuple[CachedFetch, ConcurrentFetchCache, FakeSession]]
]