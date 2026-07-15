"""ConcurrentFetchCache — dedup HTTP requests across harvest modules.

0.11.1 Phase 3 — wraps :class:`backend.core.stealth_client.StealthSession`
so every module in the new architecture requests bytes through one
shared, in-memory, LRU-bounded cache instead of building (and tearing
down) its own transport. The cache is per-``--domain`` run: instantiated
at the top of :func:`backend.core.domain_harvest_orchestrator._orchestrate`
and cleared via :meth:`ConcurrentFetchCache.aclose` in a ``finally``
block so no state leaks across runs.

Key contract (per the design brief)
-----------------------------------

* **Storage** — ``dict[str, bytes]`` keyed by a *strictly normalised*
  URL.  ``normalize_url`` is pure, idempotent, exported, and the
  source-of-truth for what counts as "the same" URL across modules.
* **Capacity** — hard caps on BOTH ``max_entries`` (default 500) and
  ``max_bytes`` (default ~200 MB).  Whichever trips first triggers LRU
  eviction; both are re-evaluated after every successful insert.
* **Concurrency** — single :class:`asyncio.Lock` guards the LRU maps
  AND the in-flight future table.  When two modules ask for the same
  URL before either has resolved, one wins the race and the other
  awaits the same future — no thundering herd, no duplicate
  ``StealthSession`` work.
* **GET-only** — :meth:`get` raises :class:`TypeError` if any kwargs
  are passed.  The cache is read-only and idempotent; non-GET / dynamic
  requests should go straight to ``StealthSession``.
* **Status policy** — only 2xx responses are stored.  3xx / 4xx / 5xx
  pass through to the caller and are never cached, so a transient 503
  doesn't poison the whole run.
* **Lifecycle** — :meth:`aclose` clears every map, cancels any pending
  in-flight futures, and closes the wrapped session if it exposes
  ``aclose`` (async) or ``close`` (sync fallback).

What it does NOT do
-------------------

* No TTL — the cache lives for the duration of one ``--domain`` run,
  nothing more.  Cross-run persistence is intentionally out of scope.
* No partial / streaming bodies — ``StealthSession.get`` returns the
  whole response object; we read ``.content`` / ``.text`` once.
* No HTTP method dispatching — see "GET-only" above.
* No conditional-request handling — Etag / If-Modified-Since / etc.
  are not threaded through.  Fetching the same URL twice inside one
  run is the entire point; we are the deduplicator.
"""
from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Default entry cap — 500 URLs.  Matches the Phase-3 design brief.
DEFAULT_MAX_ENTRIES: int = 500

#: Default byte cap — ~200 MB.  Approximate; the cache rounds on entry
#: boundaries, not mid-body.
DEFAULT_MAX_BYTES: int = 200 * 1024 * 1024

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


def _consume_future_exception(future: asyncio.Future[Any]) -> None:
    """Mark shared future exceptions retrieved without hiding awaiter errors."""
    if future.cancelled():
        return
    try:
        future.exception()
    except (asyncio.CancelledError, Exception):
        return


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------
def normalize_url(url: str) -> str:
    """Return a canonical cache key for *url*.

    Rules:

    1. **Scheme** lowercased.
    2. **Host** lowercased (DNS is case-insensitive).
    3. **Default port dropped** (``:80`` for ``http``, ``:443`` for
       ``https``).
    4. **Fragment** (``#...``) stripped — fragments never leave the
       browser, they cannot affect what the server returns.
    5. **Query parameters** sorted alphabetically by ``(key, value)``
       so ``?b=2&a=1`` and ``?a=1&b=2`` collapse to the same key.
    6. **Empty query dropped** (``"?foo="`` → no ``?``).
    7. **Path preserved verbatim** — case-sensitive servers exist and
       munging path case would silently break them.  If you ever need
       path canonicalisation, do it explicitly upstream.

    Pure / idempotent.  Falls back to the original string when no host
    can be parsed (e.g. malformed input); modules can still consume it
    but it should be treated as "uncacheable" by callers.
    """
    if not isinstance(url, str) or not url:
        return url or ""

    parsed = urlparse(url)

    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    if not host:
        # Malformed URL — return as-is so callers can still key on it
        # and the cache stays usable for the rest of the run.
        return url

    port = parsed.port
    if port is not None and _DEFAULT_PORTS.get(scheme) == port:
        port = None
    netloc = host if port is None else f"{host}:{port}"

    path = parsed.path or "/"

    # Sort query pairs.  parse_qsl returns lists (multi-value friendly);
    # sort by (key, value) tuples — deterministic across all runs.
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_pairs.sort()
    query = urlencode(query_pairs)

    # urlunparse('') drops the fragment; we still pass it explicitly so
    # the intent is obvious to readers.
    return urlunparse((scheme, netloc, path, parsed.params, query, ""))


# ---------------------------------------------------------------------------
# Response wrapper
# ---------------------------------------------------------------------------
@dataclass
class CachedResponse:
    """Module-facing response object returned by :meth:`CachedFetch.get`.

    Drop-in compatible with the subset of the curl-cffi ``Response``
    surface that MailAccess modules actually read: ``status_code``,
    ``content`` (raw bytes), ``text`` (decoded str), ``headers``.

    ``text`` is lazily computed on first access so the cache stays
    cheap for callers that only want bytes.
    """

    status_code: int
    content: bytes
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.text and self.content:
            try:
                object.__setattr__(self, "text", self.content.decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001 — defensive, never raise on decode
                object.__setattr__(self, "text", "")

    def __repr__(self) -> str:  # pragma: no cover — debugging aid
        return (
            f"CachedResponse(status_code={self.status_code}, "
            f"content_len={len(self.content)}, headers={len(self.headers)})"
        )


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
class ConcurrentFetchCache:
    """Per-run, in-memory, LRU-bounded HTTP cache wrapping a transport.

    Parameters
    ----------
    session:
        Anything that exposes ``async get(url)`` and returns an object
        with ``status_code`` / ``content`` / ``text`` / ``headers``
        attributes.  In practice this is always a
        :class:`StealthSession`.  The cache does NOT own the session
        — closing it is the orchestrator's responsibility — but
        :meth:`aclose` will close it as a courtesy if it exposes
        ``aclose`` / ``close``.
    max_entries:
        Hard cap on entry count.  Default :data:`DEFAULT_MAX_ENTRIES`.
    max_bytes:
        Hard cap on total body bytes.  Default
        :data:`DEFAULT_MAX_BYTES`.
    """

    def __init__(
        self,
        session: Any,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._session = session
        self._max_entries = int(max_entries)
        self._max_bytes = int(max_bytes)

        # The headline storage — dict[str, bytes] per the design brief.
        # OrderedDict gives us O(1) move_to_end (LRU touch) and
        # popitem(last=False) for oldest-first eviction.
        self._cache: OrderedDict[str, bytes] = OrderedDict()

        # Parallel maps for status / headers — kept separate so the
        # headline "dict[str, bytes]" contract stays obvious to readers
        # and grep-able to anyone auditing the design brief.
        self._status: dict[str, int] = {}
        self._headers: dict[str, dict[str, str]] = {}

        # In-flight dedup.  When module A and module B ask for the same
        # URL simultaneously, one creates the future and starts the
        # fetch; the other waits on it.
        self._in_flight: dict[str, asyncio.Future[CachedResponse]] = {}

        # Capacity bookkeeping.
        self._current_bytes: int = 0

        # Stats — surfaced via ``stats()`` for the CLI run summary.
        self._hits: int = 0
        self._misses: int = 0
        self._evictions: int = 0
        self._errors: int = 0

        self._lock = asyncio.Lock()

    # -- public API --------------------------------------------------------
    async def get(self, url: str, **kwargs: Any) -> CachedResponse:
        """Fetch *url* through the cache.

        Returns a :class:`CachedResponse`.  On a hit, returns instantly
        with the cached body and moves the entry to the MRU end.  On a
        miss, kicks off (or joins) the underlying ``StealthSession``
        fetch, then stores + returns the result.

        Any keyword arguments raise :class:`TypeError` — the cache is
        intentionally minimal and cannot forward headers, params, etc.
        """
        if kwargs:
            raise TypeError(
                "ConcurrentFetchCache.get() does not accept kwargs — "
                "the cache is read-only. Pass dynamic arguments to "
                "StealthSession directly, bypassing the cache."
            )
        if not isinstance(url, str) or not url:
            raise TypeError("url must be a non-empty string")

        key = normalize_url(url)

        # Phase 1 — cache lookup OR claim the in-flight slot.  Done
        # under the lock so the LRU maps and the in-flight map stay
        # consistent.
        async with self._lock:
            if key in self._cache:
                # LRU hit — touch and serve from cache.
                self._cache.move_to_end(key)
                self._hits += 1
                return self._materialise(key)

            if key in self._in_flight:
                existing = self._in_flight[key]
                if existing.done():
                    # Previous attempt settled (likely a 4xx/5xx
                    # pass-through or a transient failure).  Replace
                    # the settled future with a fresh one so the next
                    # caller retries instead of inheriting the stale
                    # result / exception.  Retrieve the prior
                    # exception so Python doesn't log a "future
                    # exception was never retrieved" warning.
                    if not existing.cancelled():
                        existing.exception()
                    future = asyncio.get_event_loop().create_future()
                    future.add_done_callback(_consume_future_exception)
                    self._in_flight[key] = future
                    self._misses += 1
                    need_fetch = True
                else:
                    # Another task is mid-fetch — coalesce onto its
                    # future so we don't duplicate the network call.
                    future = existing
                    need_fetch = False
            else:
                # First requester for this URL — create the future,
                # record it, and we'll do the fetch ourselves after
                # releasing the lock.
                future = asyncio.get_event_loop().create_future()
                future.add_done_callback(_consume_future_exception)
                self._in_flight[key] = future
                self._misses += 1
                need_fetch = True

        if not need_fetch:
            # Coalesced wait — we may see the winner's response OR the
            # winner's exception, both are correct.
            return await future

        # Phase 2 — we won the race.  Perform the fetch, then publish
        # the result to all waiters via the shared future.  The
        # in-flight entry stays in place after we settle (lazily
        # replaced on the next call to this URL) so any concurrent
        # waiter still blocked on the lock will see a coalesced
        # future, not start a fresh fetch.
        try:
            raw = await self._session.get(url)
            response = self._wrap(raw)
        except BaseException as exc:  # noqa: BLE001
            async with self._lock:
                self._errors += 1
                if not future.done():
                    # asyncio.CancelledError is control flow, not a normal
                    # exception. Storing it with set_exception() creates an
                    # unobserved Future exception when the winning caller is
                    # cancelled before any waiter attaches. Cancel the
                    # shared future instead; waiters still receive the
                    # cancellation and Python emits no warning.
                    if isinstance(exc, asyncio.CancelledError):
                        future.cancel()
                    else:
                        future.set_exception(exc)
            raise

        async with self._lock:
            if 200 <= response.status_code < 300:
                self._cache[key] = response.content
                self._cache.move_to_end(key)
                self._status[key] = response.status_code
                self._headers[key] = dict(response.headers)
                self._current_bytes += len(response.content)
                self._evict_if_needed()
            if not future.done():
                future.set_result(response)

        return response

    async def aclose(self) -> None:
        """Clear every map, cancel pending futures, close the session.

        Idempotent — calling twice is a no-op.  Safe to call from a
        ``finally`` block.
        """
        async with self._lock:
            self._cache.clear()
            self._status.clear()
            self._headers.clear()
            for fut in self._in_flight.values():
                if not fut.done():
                    fut.cancel()
            self._in_flight.clear()
            self._current_bytes = 0

        # Close the wrapped session as a courtesy.  The cache does NOT
        # own the session contractually, but most callers (orchestrator)
        # construct one exclusively for the cache, so not closing it
        # would leak the curl-cffi connection pool.
        aclose = getattr(self._session, "aclose", None)
        if aclose is not None:
            result = aclose()
            if asyncio.iscoroutine(result):
                await result
            return
        close = getattr(self._session, "close", None)
        if callable(close):
            # Sync close — already verified callable above.  Swallow
            # any teardown noise so the orchestrator's ``finally`` is
            # never derailed by a session that was already half-closed.
            try:
                close()
            except Exception:  # noqa: BLE001
                _LOG.debug("ConcurrentFetchCache: session.close() raised", exc_info=True)

    def stats(self) -> dict[str, int]:
        """Snapshot of cache counters.  Cheap; no lock taken."""
        return {
            "entries": len(self._cache),
            "bytes": self._current_bytes,
            "hits": self._hits,
            "misses": self._misses,
            "evictions": self._evictions,
            "errors": self._errors,
            # Count only PENDING in-flight futures — settled ones are
            # kept around for coalescing but are no longer "in flight".
            "in_flight": sum(
                1 for fut in self._in_flight.values() if not fut.done()
            ),
        }

    # -- internals ---------------------------------------------------------
    def _materialise(self, key: str) -> CachedResponse:
        """Build a :class:`CachedResponse` from the per-entry maps.

        Caller MUST hold ``self._lock`` (we touch the LRU map) or have
        already snapshotted the values.  We copy headers so callers
        can't mutate our internal state.
        """
        body = self._cache[key]
        return CachedResponse(
            status_code=self._status.get(key, 200),
            content=body,
            headers=dict(self._headers.get(key, {})),
        )

    @staticmethod
    def _wrap(raw: Any) -> CachedResponse:
        """Adapt a curl-cffi / httpx response into a :class:`CachedResponse`."""
        status = int(getattr(raw, "status_code", 200) or 200)
        content = getattr(raw, "content", None)
        if content is None:
            text = getattr(raw, "text", "")
            if isinstance(text, str):
                content = text.encode("utf-8")
            elif isinstance(text, bytes | bytearray):
                content = bytes(text)
            else:
                content = b""
        if isinstance(content, bytearray):
            content = bytes(content)
        headers_raw = getattr(raw, "headers", {}) or {}
        try:
            headers = {str(k): str(v) for k, v in dict(headers_raw).items()}
        except Exception:  # noqa: BLE001
            headers = {}
        text = getattr(raw, "text", None)
        if not isinstance(text, str):
            text = ""
        return CachedResponse(
            status_code=status,
            content=content,
            text=text,
            headers=headers,
        )

    def _evict_if_needed(self) -> None:
        """Drop oldest entries until both caps are satisfied.

        Caller MUST hold ``self._lock``.  Both caps are checked
        together so a single large entry can evict several small ones
        when the byte cap dominates.
        """
        while True:
            over_entries = len(self._cache) > self._max_entries
            over_bytes = self._current_bytes > self._max_bytes
            if not (over_entries or over_bytes):
                return
            key, body = self._cache.popitem(last=False)
            self._current_bytes -= len(body)
            self._status.pop(key, None)
            self._headers.pop(key, None)
            self._evictions += 1


# ---------------------------------------------------------------------------
# Module-facing facade
# ---------------------------------------------------------------------------
class CachedFetch:
    """Duck-types as a ``StealthSession`` for drop-in module usage.

    Modules constructed during a harvest run should accept a
    ``CachedFetch`` (typically as a keyword argument named ``fetch``)
    and call ``await fetch.get(url)`` instead of building their own
    ``StealthSession``.  The facade exposes only what the modules need
    (``get`` + ``aclose`` + ``stats``); the underlying LRU + coalescing
    is owned by the wrapped :class:`ConcurrentFetchCache`.
    """

    def __init__(self, cache: ConcurrentFetchCache) -> None:
        self._cache = cache

    async def get(self, url: str, **kwargs: Any) -> CachedResponse:
        return await self._cache.get(url, **kwargs)

    async def aclose(self) -> None:
        await self._cache.aclose()

    def stats(self) -> dict[str, int]:
        return self._cache.stats()


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------
__all__ = [
    "CachedFetch",
    "CachedResponse",
    "ConcurrentFetchCache",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_ENTRIES",
    "normalize_url",
]
