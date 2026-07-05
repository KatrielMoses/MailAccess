from __future__ import annotations

from collections.abc import Callable

import httpx

import backend.core.duckduckgo_dorker as duckduckgo_dorker
from backend.core.duckduckgo_dorker import DuckDuckGoDorker
from backend.core.http_client import _MailAccessClient, _RoutedMailAccessClient
from backend.core.scrapingant import ScrapingAntConfig


def _config(
    *,
    api_key: str | None,
    enabled_dorking: bool = True,
) -> ScrapingAntConfig:
    return ScrapingAntConfig(
        api_key=api_key,
        enabled_dorking=enabled_dorking,
        enabled_platforms=False,
        proxy_type="residential",
        transport="rest_api",
    )


def _ddg_html(email: str = "hello@example.com") -> str:
    return f"""
    <a class="result__a" href="https://example.com/contact">Example contact</a>
    <a class="result__snippet">Reach us at {email}</a>
    """


def _patch_build_client(
    monkeypatch,
    *,
    config: ScrapingAntConfig,
    direct_handler: Callable[[httpx.Request], httpx.Response],
    scrapingant_handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    real_build_client = duckduckgo_dorker.build_client

    def build_client_with_transports(**kwargs):
        return real_build_client(
            **kwargs,
            _scrapingant_config=config,
            _scrapingant_rest_transport=httpx.MockTransport(scrapingant_handler),
            transport=httpx.MockTransport(direct_handler),
        )

    monkeypatch.setattr(
        duckduckgo_dorker,
        "build_client",
        build_client_with_transports,
    )


async def test_duckduckgo_dorker_default_construction_uses_standard_client() -> None:
    dorker = DuckDuckGoDorker(min_interval=0.0)
    try:
        assert isinstance(dorker._client, _MailAccessClient)
        assert not isinstance(dorker._client, _RoutedMailAccessClient)
    finally:
        await dorker.aclose()


async def test_duckduckgo_dorker_with_scrapingant_zone_uses_routed_client() -> None:
    dorker = DuckDuckGoDorker(min_interval=0.0, scrapingant_zone="dorking")
    try:
        assert isinstance(dorker._client, _RoutedMailAccessClient)
    finally:
        await dorker.aclose()


async def test_duckduckgo_dorker_with_scrapingant_zone_disabled_routes_via_direct(
    monkeypatch,
) -> None:
    scrapingant_calls: list[str] = []

    def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        scrapingant_calls.append(str(request.url))
        return httpx.Response(200, json={"html": "should-not-run"}, request=request)

    def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=_ddg_html(), request=request)

    _patch_build_client(
        monkeypatch,
        config=_config(api_key=None),
        direct_handler=direct_handler,
        scrapingant_handler=scrapingant_handler,
    )

    dorker = DuckDuckGoDorker(min_interval=0.0, scrapingant_zone="dorking")
    try:
        results, captcha_hit = await dorker.search('"@example.com"')
    finally:
        await dorker.aclose()

    assert captcha_hit is False
    assert results[0].snippet == "Reach us at hello@example.com"
    assert scrapingant_calls == []


async def test_duckduckgo_dorker_fallback_to_direct_on_scrapingant_failure(
    monkeypatch,
) -> None:
    scrapingant_calls: list[str] = []
    direct_calls: list[str] = []

    def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        scrapingant_calls.append(str(request.url))
        return httpx.Response(503, json={"error": "upstream"}, request=request)

    def direct_handler(request: httpx.Request) -> httpx.Response:
        direct_calls.append(str(request.url))
        return httpx.Response(
            200,
            text=_ddg_html("fallback@example.com"),
            request=request,
        )

    _patch_build_client(
        monkeypatch,
        config=_config(api_key="secret-key"),
        direct_handler=direct_handler,
        scrapingant_handler=scrapingant_handler,
    )

    dorker = DuckDuckGoDorker(min_interval=0.0, scrapingant_zone="dorking")
    try:
        results, captcha_hit = await dorker.search('"@example.com"')
    finally:
        await dorker.aclose()

    assert captcha_hit is False
    assert results == []
    assert len(scrapingant_calls) == 1
    assert direct_calls == []


async def test_duckduckgo_dorker_with_explicit_transport_does_not_inject_zone(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        duckduckgo_dorker,
        "build_client",
        lambda **_: (_ for _ in ()).throw(AssertionError("unexpected build_client")),
    )

    transport_calls: list[str] = []

    def direct_handler(request: httpx.Request) -> httpx.Response:
        transport_calls.append(str(request.url))
        return httpx.Response(200, text=_ddg_html(), request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(direct_handler))
    dorker = DuckDuckGoDorker(
        transport=client,
        min_interval=0.0,
        scrapingant_zone="dorking",
    )
    try:
        results, captcha_hit = await dorker.search('"@example.com"')
    finally:
        await client.aclose()

    assert captcha_hit is False
    assert len(results) == 1
    assert len(transport_calls) == 1
