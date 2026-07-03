from __future__ import annotations

import httpx

from backend.core.http_client import _MailAccessClient, _RoutedMailAccessClient, build_client
from backend.core.scrapingant import ScrapingAntConfig


def _config(enabled: bool) -> ScrapingAntConfig:
    return ScrapingAntConfig(
        api_key="secret-key",
        enabled_dorking=enabled,
        enabled_platforms=False,
        proxy_type="residential",
        transport="rest_api",
        proxy_residential_username="res-user",
        proxy_residential_password="res-pass",
        proxy_datacenter_username="dc-user",
        proxy_datacenter_password="dc-pass",
    )


async def test_build_client_without_zone_returns_standard_client() -> None:
    async with build_client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200))
    ) as client:
        assert isinstance(client, _MailAccessClient)
        assert not isinstance(client, _RoutedMailAccessClient)


async def test_build_client_with_zone_returns_routed_client() -> None:
    async with build_client(
        scrapingant_zone="dorking",
        _scrapingant_config=_config(enabled=False),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)),
    ) as client:
        assert isinstance(client, _RoutedMailAccessClient)


async def test_build_client_with_disabled_scrapingant_uses_direct_transport() -> None:
    scrapingant_calls: list[str] = []

    async def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        scrapingant_calls.append(str(request.url))
        return httpx.Response(200, json={"content": "should-not-run"}, request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    async with build_client(
        scrapingant_zone="dorking",
        _scrapingant_config=_config(enabled=False),
        _scrapingant_rest_transport=httpx.MockTransport(scrapingant_handler),
        transport=httpx.MockTransport(direct_handler),
    ) as client:
        response = await client.get("https://example.com/check")

    assert response.text == "direct-ok"
    assert scrapingant_calls == []


async def test_build_routed_client_dispatches_residential_proxy_to_correct_host() -> None:
    calls: list[str] = []

    async def proxy_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="proxy-ok", request=request)

    config = _config(enabled=True)
    config = ScrapingAntConfig(
        api_key=config.api_key,
        enabled_dorking=config.enabled_dorking,
        enabled_platforms=config.enabled_platforms,
        proxy_type=config.proxy_type,
        transport="residential_proxy",
        proxy_residential_username=config.proxy_residential_username,
        proxy_residential_password=config.proxy_residential_password,
        proxy_datacenter_username=config.proxy_datacenter_username,
        proxy_datacenter_password=config.proxy_datacenter_password,
    )

    async with build_client(
        scrapingant_zone="dorking",
        _scrapingant_config=config,
        _scrapingant_proxy_transport=httpx.MockTransport(proxy_handler),
        transport=httpx.MockTransport(lambda request: httpx.Response(500, request=request)),
    ) as client:
        response = await client.get("https://example.com/check")

    assert response.text == "proxy-ok"
    assert calls == ["https://example.com/check"]
    assert (
        config.residential_proxy_url()
        == "http://res-user:res-pass@residential.scrapingant.com:8080"
    )


async def test_build_routed_client_dispatches_datacenter_proxy_to_correct_host() -> None:
    calls: list[str] = []

    async def proxy_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="proxy-ok", request=request)

    config = ScrapingAntConfig(
        api_key="secret-key",
        enabled_dorking=True,
        enabled_platforms=False,
        proxy_type="residential",
        transport="datacenter_proxy",
        proxy_residential_username="res-user",
        proxy_residential_password="res-pass",
        proxy_datacenter_username="dc-user",
        proxy_datacenter_password="dc-pass",
    )

    async with build_client(
        scrapingant_zone="dorking",
        _scrapingant_config=config,
        _scrapingant_proxy_transport=httpx.MockTransport(proxy_handler),
        transport=httpx.MockTransport(lambda request: httpx.Response(500, request=request)),
    ) as client:
        response = await client.get("https://example.com/check")

    assert response.text == "proxy-ok"
    assert calls == ["https://example.com/check"]
    assert config.datacenter_proxy_url() == "http://dc-user:dc-pass@datacenter.scrapingant.com:8080"


async def test_build_routed_client_uses_rest_api_when_transport_is_rest_api() -> None:
    scrapingant_calls: list[str] = []

    async def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        scrapingant_calls.append(str(request.url))
        return httpx.Response(
            200,
            json={"html": "rest-ok", "status_code": 200, "headers": []},
            request=request,
        )

    async with build_client(
        scrapingant_zone="dorking",
        _scrapingant_config=_config(enabled=True),
        _scrapingant_rest_transport=httpx.MockTransport(scrapingant_handler),
        transport=httpx.MockTransport(lambda request: httpx.Response(500, request=request)),
    ) as client:
        response = await client.get("https://example.com/check")

    assert response.text == "rest-ok"
    assert scrapingant_calls[0].startswith("https://api.scrapingant.com/v2/extended?")
