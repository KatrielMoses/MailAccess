"""Tests for :class:`backend.core.duckduckgo_dorker.DuckDuckGoDorker`.

0.11.1 Phase 4 rewrite: the dorker takes a :class:`CachedFetch` facade,
a :class:`StealthSession`, or a legacy ``httpx.AsyncClient`` transport.
These tests assert the new contract — see
``tests/core/test_bing_dorker.py`` for the same pattern, since the
two dorkers are sibling modules with the same fetch-stack priority.
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

from backend.core.duckduckgo_dorker import (  # noqa: E402
    _DDG_HTML_URL,
    DuckDuckGoDorker,
    _parse_ddg_html,
)

_DDG_RESULT_HTML = """
<a class="result__a" href="https://example.com/contact">Example contact</a>
<a class="result__snippet">Reach us at hello@example.com</a>
"""
_DDG_CAPTCHA_HTML = """
<html><body>
anomaly detected
unusual traffic
</body></html>
"""


def _expected_ddg_url(query: str) -> str:
    return f"{_DDG_HTML_URL}?{urlencode({'q': query})}"


# ---------------------------------------------------------------------------
# fetch=CachedFetch path (the new canonical surface)
# ---------------------------------------------------------------------------
async def test_ddg_dorker_with_cached_fetch_routes_through_cache() -> None:
    """The dorker's HTTP traffic must go through the injected CachedFetch."""
    query = '"@example.com"'
    url = _expected_ddg_url(query)
    fetch, cache, session = make_cached_fetch(
        {url: make_cached_response(_DDG_RESULT_HTML)}
    )

    try:
        dorker = DuckDuckGoDorker(min_interval=0.0, fetch=fetch)
        try:
            results, captcha = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert captcha is False
    assert len(results) == 1
    assert results[0].snippet == "Reach us at hello@example.com"
    assert results[0].url == "https://example.com/contact"
    assert session.call_log == [url]
    assert session.call_count == 1
    assert cache.stats()["misses"] == 1


async def test_ddg_dorker_cache_hit_does_not_re_issue_request() -> None:
    """Second search for the same query must be served from cache."""
    query = '"@example.com"'
    url = _expected_ddg_url(query)
    fetch, cache, session = make_cached_fetch(
        {url: make_cached_response(_DDG_RESULT_HTML)}
    )

    try:
        dorker = DuckDuckGoDorker(min_interval=0.0, fetch=fetch)
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


async def test_ddg_dorker_202_response_marks_blocked() -> None:
    """DDG's CAPTCHA signal is HTTP 202; the dorker should set blocked."""
    query = '"@example.com"'
    url = _expected_ddg_url(query)
    fetch, cache, _session = make_cached_fetch(
        {url: make_cached_response("<html>captcha</html>", status_code=202)}
    )

    try:
        dorker = DuckDuckGoDorker(min_interval=0.0, fetch=fetch)
        try:
            results, captcha = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert captcha is True
    assert dorker.blocked is True
    assert results == []


async def test_ddg_dorker_429_response_marks_blocked() -> None:
    """HTTP 429 (rate limited) is also a CAPTCHA signal for DDG."""
    query = '"@example.com"'
    url = _expected_ddg_url(query)
    fetch, cache, _session = make_cached_fetch(
        {url: make_cached_response("rate limited", status_code=429)}
    )

    try:
        dorker = DuckDuckGoDorker(min_interval=0.0, fetch=fetch)
        try:
            results, captcha = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert captcha is True
    assert results == []


async def test_ddg_dorker_5xx_response_returns_empty_no_block() -> None:
    """5xx is an error, NOT a CAPTCHA block — caller can retry."""
    query = '"@example.com"'
    url = _expected_ddg_url(query)
    fetch, cache, _session = make_cached_fetch(
        {url: make_cached_response("upstream down", status_code=503)}
    )

    try:
        dorker = DuckDuckGoDorker(min_interval=0.0, fetch=fetch)
        try:
            results, captcha = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert captcha is False
    assert dorker.blocked is False
    assert results == []


async def test_ddg_dorker_captcha_body_marker_marks_blocked() -> None:
    """A 200 with a CAPTCHA marker in the body still trips blocked."""
    query = '"@example.com"'
    url = _expected_ddg_url(query)
    fetch, cache, _session = make_cached_fetch(
        {url: make_cached_response(_DDG_CAPTCHA_HTML)}
    )

    try:
        dorker = DuckDuckGoDorker(min_interval=0.0, fetch=fetch)
        try:
            results, captcha = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert captcha is True
    assert dorker.blocked is True
    assert results == []


async def test_ddg_dorker_404_returns_empty_no_block() -> None:
    """DDG returning 404 is a graceful empty, not a CAPTCHA block."""
    query = '"@no-such-domain.invalid"'
    url = _expected_ddg_url(query)
    fetch, cache, _session = make_cached_fetch(
        {url: make_cached_response("not found", status_code=404)}
    )

    try:
        dorker = DuckDuckGoDorker(min_interval=0.0, fetch=fetch)
        try:
            results, captcha = await dorker.search(query)
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert captcha is False
    assert dorker.blocked is False
    assert results == []


async def test_ddg_dorker_network_error_does_not_raise() -> None:
    """A transport-level error is swallowed; _last_error is set."""
    session = FakeSession(
        payloads={},
        raise_after=0,
        exception=httpx.ConnectError("boom"),
    )
    fetch, cache, _ = make_cached_fetch(session=session)

    try:
        dorker = DuckDuckGoDorker(min_interval=0.0, fetch=fetch)
        try:
            results, captcha = await dorker.search('"@example.com"')
        finally:
            await dorker.aclose()
    finally:
        await cache.aclose()

    assert captcha is False
    assert dorker.blocked is False
    assert results == []
    assert dorker._last_error is not None
    assert "boom" in dorker._last_error


# ---------------------------------------------------------------------------
# Legacy: explicit transport injection
# ---------------------------------------------------------------------------
async def test_ddg_dorker_with_explicit_transport_skips_cache() -> None:
    """When a transport is injected, the dorker uses it and ignores the cache."""
    transport_calls: list[str] = []

    def direct_handler(request: httpx.Request) -> httpx.Response:
        transport_calls.append(str(request.url))
        return httpx.Response(200, text=_DDG_RESULT_HTML, request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(direct_handler))
    try:
        dorker = DuckDuckGoDorker(transport=client, min_interval=0.0)
        try:
            results, captcha = await dorker.search('"@example.com"')
        finally:
            await dorker.aclose()
    finally:
        await client.aclose()

    assert captcha is False
    assert len(results) == 1
    assert len(transport_calls) == 1


async def test_ddg_dorker_with_explicit_transport_does_not_build_stealth() -> None:
    """With a transport, no StealthSession should be constructed.

    Building a StealthSession pulls in curl-cffi and a connection
    pool — costs a legacy unit test shouldn't pay.
    """
    def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=_DDG_RESULT_HTML, request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(direct_handler))
    try:
        dorker = DuckDuckGoDorker(transport=client, min_interval=0.0)
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
async def test_ddg_dorker_default_construction_does_not_eagerly_open_session() -> None:
    """``DuckDuckGoDorker()`` with no args must not hit the network at construction."""
    dorker = DuckDuckGoDorker(min_interval=0.0)
    try:
        assert dorker._session is None or dorker._client is None
    finally:
        await dorker.aclose()


# ---------------------------------------------------------------------------
# Pure-HTML parsing helper (no I/O)
# ---------------------------------------------------------------------------
def test_parse_ddg_html_extracts_results() -> None:
    """The pure parser should extract the title/snippet/url triple."""
    results = _parse_ddg_html(_DDG_RESULT_HTML, '"@example.com"', 20)
    assert len(results) == 1
    assert results[0].url == "https://example.com/contact"
    assert "hello@example.com" in results[0].snippet


def test_parse_ddg_html_resolves_uddg_redirect() -> None:
    """DDG wraps results in a uddg=... redirect; the parser must unwrap it."""
    html = (
        '<a class="result__a" '
        'href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpath">'
        'Title'
        "</a>"
        '<a class="result__snippet">Snippet text</a>'
    )
    results = _parse_ddg_html(html, "test", 20)
    assert len(results) == 1
    assert results[0].url == "https://example.com/path"


def test_parse_ddg_html_empty_input_returns_empty() -> None:
    """An empty body should not crash the parser."""
    assert _parse_ddg_html("", "test", 20) == []
    assert _parse_ddg_html("<html>no results</html>", "test", 20) == []