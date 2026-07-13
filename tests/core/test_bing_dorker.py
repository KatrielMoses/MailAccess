"""Tests for :class:`backend.core.bing_dorker.BingDorker`.

0.11.1 Phase 4 rewrite: the dorker no longer owns an httpx client — it
takes a :class:`CachedFetch` facade, a :class:`StealthSession`, or a
legacy ``httpx.AsyncClient`` ``transport``.  These tests assert the
new contract:

* When ``fetch`` is injected, every request goes through
  ``fetch.get(url)`` and the cache (no live network, no implicit
  client construction).
* When ``transport`` is injected (legacy test path), the dorker uses
  it directly and skips the cache + StealthSession.
* Without any injection the dorker builds a StealthSession when
  curl-cffi is available, otherwise falls back to httpx.

The OLD tests asserted on ``dorker._client`` being a
``_MailAccessClient`` / ``_RoutedMailAccessClient`` — those classes
still exist for backward compat (they wrap httpx), but the dorker no
longer routes through them.  Dropping those assertions is intentional:
the dorker's HTTP path is now ``fetch.get`` or ``stealth.get``, not
``client.get``.
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlencode

import httpx

# Make the tests/ directory importable so we can pull in the shared
# _fetch_fixtures module without tests/ needing to be a package.
_TESTS_DIR = Path(__file__).resolve().parents[1]
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from _fetch_fixtures import FakeSession, make_cached_fetch, make_cached_response  # noqa: E402

from backend.core.bing_dorker import _BING_URL, BingDorker, _parse_bing_html  # noqa: E402

_BING_RESULT_HTML = """
<li class="b_algo">
  <h2><a href="https://example.com/contact">Example contact</a></h2>
  <p>Reach us at hello@example.com</p>
</li>
"""
_BING_CAPTCHA_HTML = """
<html><body>
unusual traffic from your computer
haveibeenpwned
</body></html>
"""


def _expected_bing_url(query: str, count: int) -> str:
    return f"{_BING_URL}?{urlencode({'q': query, 'count': count})}"


# ---------------------------------------------------------------------------
# fetch=CachedFetch path (the new canonical surface)
# ---------------------------------------------------------------------------
async def test_bing_dorker_with_cached_fetch_routes_through_cache() -> None:
    """The dorker's HTTP traffic must go through the injected CachedFetch.

    This is the headline assertion of the Phase 3 cache migration: no
    test should be able to prove the dorker works without exercising
    the cache facade.
    """
    query = '"@example.com"'
    url = _expected_bing_url(query, 20)
    fetch, cache, session = make_cached_fetch(
        {url: make_cached_response(_BING_RESULT_HTML)}
    )

    try:
        dorker = BingDorker(min_interval=0.0, fetch=fetch)
        try:
            results, blocked = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert blocked is False
    assert len(results) == 1
    assert results[0].snippet == "Reach us at hello@example.com"
    assert results[0].url == "https://example.com/contact"
    # Cache saw exactly one fetch; dorker must NOT have constructed
    # its own transport.
    assert session.call_log == [url]
    assert session.call_count == 1
    assert cache.stats()["misses"] == 1
    assert cache.stats()["hits"] == 0


async def test_bing_dorker_cache_hit_does_not_re_issue_request() -> None:
    """A second search for the same query should be served from cache.

    This is the dedup guarantee: the cache key is the fully-built
    Bing URL with ``q=`` and ``count=``, so identical (query, count)
    pairs collapse across modules.
    """
    query = '"@example.com"'
    url = _expected_bing_url(query, 20)
    fetch, cache, session = make_cached_fetch(
        {url: make_cached_response(_BING_RESULT_HTML)}
    )

    try:
        dorker = BingDorker(min_interval=0.0, fetch=fetch)
        try:
            await dorker.search(query)
            await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert session.call_count == 1
    assert cache.stats()["hits"] == 1
    assert cache.stats()["misses"] == 1


async def test_bing_dorker_202_response_marks_blocked() -> None:
    """Bing's CAPTCHA signal is HTTP 202; the dorker should set blocked."""
    query = '"@example.com"'
    url = _expected_bing_url(query, 20)
    fetch, cache, _session = make_cached_fetch(
        {
            url: make_cached_response(
                "<html>captcha</html>",
                status_code=202,
            )
        }
    )

    try:
        dorker = BingDorker(min_interval=0.0, fetch=fetch)
        try:
            results, blocked = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert blocked is True
    assert dorker.blocked is True
    assert results == []


async def test_bing_dorker_429_response_marks_blocked() -> None:
    """HTTP 429 (rate limited) is also a block signal."""
    query = '"@example.com"'
    url = _expected_bing_url(query, 20)
    fetch, cache, _session = make_cached_fetch(
        {url: make_cached_response("rate limited", status_code=429)}
    )

    try:
        dorker = BingDorker(min_interval=0.0, fetch=fetch)
        try:
            results, blocked = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert blocked is True
    assert results == []


async def test_bing_dorker_5xx_response_returns_empty_no_block() -> None:
    """5xx is an error, NOT a block — caller can retry with a backoff."""
    query = '"@example.com"'
    url = _expected_bing_url(query, 20)
    fetch, cache, _session = make_cached_fetch(
        {url: make_cached_response("upstream down", status_code=503)}
    )

    try:
        dorker = BingDorker(min_interval=0.0, fetch=fetch)
        try:
            results, blocked = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert blocked is False
    assert dorker.blocked is False
    assert results == []


async def test_bing_dorker_captcha_body_marker_marks_blocked() -> None:
    """A 200 with a captcha marker in the body still trips blocked."""
    query = '"@example.com"'
    url = _expected_bing_url(query, 20)
    fetch, cache, _session = make_cached_fetch(
        {url: make_cached_response(_BING_CAPTCHA_HTML)}
    )

    try:
        dorker = BingDorker(min_interval=0.0, fetch=fetch)
        try:
            results, blocked = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert blocked is True
    assert dorker.blocked is True
    assert results == []


async def test_bing_dorker_404_returns_empty_no_block() -> None:
    """Bing returning 404 (no results path) is a graceful empty, not a block."""
    query = '"@no-such-domain.invalid"'
    url = _expected_bing_url(query, 20)
    fetch, cache, _session = make_cached_fetch(
        {url: make_cached_response("not found", status_code=404)}
    )

    try:
        dorker = BingDorker(min_interval=0.0, fetch=fetch)
        try:
            results, blocked = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert blocked is False
    assert dorker.blocked is False
    assert results == []


async def test_bing_dorker_network_error_does_not_raise() -> None:
    """A transport-level error is swallowed; _last_error is set."""
    session = FakeSession(
        payloads={},
        raise_after=0,  # raise on the very first call
        exception=httpx.ConnectError("boom"),
    )
    fetch, cache, _ = make_cached_fetch(session=session)

    try:
        dorker = BingDorker(min_interval=0.0, fetch=fetch)
        try:
            results, blocked = await dorker.search('"@example.com"')
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert blocked is False
    assert dorker.blocked is False
    assert results == []
    assert dorker._last_error is not None
    assert "boom" in dorker._last_error


# ---------------------------------------------------------------------------
# Legacy: explicit transport injection
# ---------------------------------------------------------------------------
async def test_bing_dorker_with_explicit_transport_skips_cache() -> None:
    """When a transport is injected, the dorker uses it and ignores the cache.

    This is the legacy path for unit tests that want a hand-rolled
    transport — they're explicitly opting out of the cache facade.
    Asserting that the injected transport saw the request (and the
    cache did NOT) is what proves the bypass worked.
    """
    transport_calls: list[str] = []

    def direct_handler(request: httpx.Request) -> httpx.Response:
        transport_calls.append(str(request.url))
        return httpx.Response(200, text=_BING_RESULT_HTML, request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(direct_handler))
    try:
        dorker = BingDorker(
            transport=client,
            min_interval=0.0,
        )
        try:
            results, blocked = await dorker.search('"@example.com"')
        finally:
            await dorker.aclose()
    finally:
        await client.aclose()

    assert blocked is False
    assert len(results) == 1
    assert len(transport_calls) == 1


async def test_bing_dorker_with_explicit_transport_does_not_eagerly_build_stealth() -> None:
    """When ``transport`` is injected, the dorker must NOT build a StealthSession.

    This is the resource-cost guard: building a StealthSession pulls in
    curl-cffi, opens a connection pool, and allocates fingerprint
    buffers.  A test that only needs a canned transport must not pay
    that cost.

    We assert via ``dorker._session is None`` — that's the field the
    search() path checks before falling back to ``_client``.  If it's
    set, the transport was ignored.
    """
    def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=_BING_RESULT_HTML, request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(direct_handler))
    try:
        dorker = BingDorker(transport=client, min_interval=0.0)
        try:
            assert dorker._session is None
            assert dorker._client is client
        finally:
            await dorker.aclose()
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Default-construction behaviour (no fetch, no stealth, no transport)
# ---------------------------------------------------------------------------
async def test_bing_dorker_default_construction_does_not_eagerly_open_session() -> None:
    """``BingDorker()`` with no args must not hit the network at construction.

    Construction is supposed to be cheap and side-effect-free.  If it
    raises (e.g. curl-cffi missing) that's fine, but if it succeeds
    then the underlying session — if any — should not have done any
    work yet.
    """
    dorker = BingDorker(min_interval=0.0)
    try:
        # Either _session is set (curl-cffi path) or _client is set
        # (httpx fallback).  Both are inert until search() runs.
        assert dorker._session is None or dorker._client is None
    finally:
        await dorker.aclose()


# ---------------------------------------------------------------------------
# Pure-HTML parsing helper (no I/O)
# ---------------------------------------------------------------------------
def test_parse_bing_html_extracts_results() -> None:
    """The pure parser should extract the title/snippet/url triple."""
    results = _parse_bing_html(_BING_RESULT_HTML, '"@example.com"', 20)
    assert len(results) == 1
    assert results[0].title == "Example contact"
    assert results[0].url == "https://example.com/contact"
    assert "hello@example.com" in results[0].snippet


def test_parse_bing_html_empty_input_returns_empty() -> None:
    """An empty body should not crash the parser."""
    assert _parse_bing_html("", '"@example.com"', 20) == []
    assert _parse_bing_html("<html>no results</html>", '"@example.com"', 20) == []