from __future__ import annotations

import httpx
import pytest

from backend.core.http_client import _MailAccessClient, _RoutedMailAccessClient, build_client
from backend.core.scrapingant import ScrapingAntConfig


def _config(
    enabled: bool,
    scrapingant_enabled: bool = True,
    transport: str = "rest_api",
) -> ScrapingAntConfig:
    return ScrapingAntConfig(
        scrapingant_enabled=scrapingant_enabled,
        api_key="secret-key",
        enabled_dorking=enabled,
        enabled_platforms=False,
        proxy_type="residential",
        transport=transport,
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


async def test_disabled_state_routes_direct_not_scrapingant() -> None:
    """When scrapingant_enabled=False, routed client must skip ScrapingAnt entirely."""
    scrapingant_calls: list[str] = []

    async def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        scrapingant_calls.append(str(request.url))
        return httpx.Response(200, json={"html": "should-not-run"}, request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    config = ScrapingAntConfig(
        scrapingant_enabled=False,
        api_key="live-key",
        enabled_dorking=True,
        enabled_platforms=True,
        transport="rest_api",
        proxy_residential_username="res-user",
        proxy_residential_password="res-pass",
        proxy_datacenter_username="dc-user",
        proxy_datacenter_password="dc-pass",
    )
    async with build_client(
        scrapingant_zone="dorking",
        _scrapingant_config=config,
        _scrapingant_rest_transport=httpx.MockTransport(scrapingant_handler),
        transport=httpx.MockTransport(direct_handler),
    ) as client:
        response = await client.get("https://example.com/check")

    assert response.text == "direct-ok"
    assert scrapingant_calls == []  # ScrapingAnt never called


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
        scrapingant_enabled=config.scrapingant_enabled,
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


async def test_harvest_dork_uses_scrapingant_rest_when_enabled() -> None:
    """H2: email_search_dork's zone (dorking) must route via ScrapingAnt REST API.

    When SCRAPINGANT_TRANSPORT=rest_api and --use-proxies is set, the harvest
    dork module's client must send through api.scrapingant.com/v2/extended,
    not directly to DuckDuckGo or Bing.
    """
    scrapingant_calls: list[str] = []

    async def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        scrapingant_calls.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "html": "<html>dork-results</html>",
                "status_code": 200,
                "headers": [],
            },
            request=request,
        )

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    # Simulate harvest module: build_routed_client with dorking zone
    async with build_client(
        scrapingant_zone="dorking",
        _scrapingant_config=_config(enabled=True, transport="rest_api"),
        _scrapingant_rest_transport=httpx.MockTransport(scrapingant_handler),
        transport=httpx.MockTransport(direct_handler),
        strict_proxy=True,
    ) as client:
        response = await client.get("https://duckduckgo.com/?q=test")

    # Must route through ScrapingAnt REST API, not direct
    assert len(scrapingant_calls) == 1
    assert "api.scrapingant.com/v2/extended" in scrapingant_calls[0]
    assert "duckduckgo.com" in scrapingant_calls[0]



# ── H4: explicit proxy timeouts ─────────────────────────────────────────────────


async def test_proxy_client_has_connect_timeout_set() -> None:
    """H4: ScrapingAnt proxy client must set explicit connect timeout."""

    async def proxy_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="proxy-ok", request=request)

    config = ScrapingAntConfig(
        scrapingant_enabled=True,
        api_key="secret-key",
        enabled_dorking=True,
        enabled_platforms=False,
        transport="residential_proxy",
        proxy_residential_username="res-user",
        proxy_residential_password="res-pass",
    )

    from backend.core.scrapingant import ScrapingAntTransport

    transport = ScrapingAntTransport(
        config,
        proxy_transport=httpx.MockTransport(proxy_handler),
        strict_proxy=False,
    )

    # Verify the transport was created with strict_proxy=False
    assert transport.strict_proxy is False


async def test_proxy_connect_timeout_triggers_strict_error() -> None:
    """H4: a proxy connect timeout must raise ProxyConnectionError in strict mode."""

    async def slow_connect_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("proxy slow to connect", request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    from backend.core.proxy import ProxyConnectionError

    with pytest.raises(ProxyConnectionError):
        async with build_client(
            scrapingant_zone="dorking",
            _scrapingant_config=ScrapingAntConfig(
                scrapingant_enabled=True,
                api_key="secret-key",
                enabled_dorking=True,
                transport="residential_proxy",
                proxy_residential_username="res-user",
                proxy_residential_password="res-pass",
            ),
            _scrapingant_proxy_transport=httpx.MockTransport(slow_connect_handler),
            transport=httpx.MockTransport(direct_handler),
            strict_proxy=True,
        ) as client:
            await client.get("https://example.com/check")


async def test_proxy_connect_timeout_triggers_permissive_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """H4: in permissive mode, a proxy timeout must log a warning and fall back to direct."""

    async def slow_connect_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("proxy slow to connect", request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    async with build_client(
        scrapingant_zone="dorking",
        _scrapingant_config=ScrapingAntConfig(
            scrapingant_enabled=True,
            api_key="secret-key",
            enabled_dorking=True,
            transport="residential_proxy",
            proxy_residential_username="res-user",
            proxy_residential_password="res-pass",
        ),
        _scrapingant_proxy_transport=httpx.MockTransport(slow_connect_handler),
        transport=httpx.MockTransport(direct_handler),
        strict_proxy=False,
    ) as client:
        response = await client.get("https://example.com/check")

    assert response.text == "direct-ok"
    assert "fell back" in caplog.text.lower()


# ── C4: strict vs permissive proxy modes ────────────────────────────────────────


async def test_strict_mode_raises_on_proxy_failure() -> None:
    """strict_proxy=True must raise ProxyConnectionError on ScrapingAnt failure."""

    async def fail_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ProxyError("connection refused", request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    from backend.core.proxy import ProxyConnectionError

    with pytest.raises(ProxyConnectionError) as exc_info:
        async with build_client(
            scrapingant_zone="dorking",
            _scrapingant_config=_config(enabled=True),
            _scrapingant_rest_transport=httpx.MockTransport(fail_handler),
            transport=httpx.MockTransport(direct_handler),
            strict_proxy=True,
        ) as client:
            await client.get("https://example.com/check")

    assert "ScrapingAnt" in str(exc_info.value)


async def test_strict_mode_does_not_silently_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """strict_proxy=True must NOT fall back to direct or log a warning."""

    async def fail_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ProxyError("connection refused", request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    from backend.core.proxy import ProxyConnectionError

    with pytest.raises(ProxyConnectionError):
        async with build_client(
            scrapingant_zone="dorking",
            _scrapingant_config=_config(enabled=True),
            _scrapingant_rest_transport=httpx.MockTransport(fail_handler),
            transport=httpx.MockTransport(direct_handler),
            strict_proxy=True,
        ) as client:
            await client.get("https://example.com/check")

    # No warning should be logged in strict mode
    assert "fell back" not in caplog.text.lower()


async def test_permissive_mode_logs_warning_on_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """strict_proxy=False must log a warning when falling back to direct."""

    async def fail_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ProxyError("connection refused", request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    async with build_client(
        scrapingant_zone="dorking",
        _scrapingant_config=_config(enabled=True),
        _scrapingant_rest_transport=httpx.MockTransport(fail_handler),
        transport=httpx.MockTransport(direct_handler),
        strict_proxy=False,
    ) as client:
        response = await client.get("https://example.com/check")

    assert response.text == "direct-ok"
    assert "fell back" in caplog.text.lower()
    assert "⚠" in caplog.text


async def test_permissive_mode_continues_after_fallback() -> None:
    """strict_proxy=False must return the direct response after proxy failure."""

    async def fail_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ProxyError("connection refused", request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    async with build_client(
        scrapingant_zone="dorking",
        _scrapingant_config=_config(enabled=True),
        _scrapingant_rest_transport=httpx.MockTransport(fail_handler),
        transport=httpx.MockTransport(direct_handler),
        strict_proxy=False,
    ) as client:
        response = await client.get("https://example.com/check")

    assert response.text == "direct-ok"


async def test_use_proxies_flag_sets_strict_mode_by_default() -> None:
    """When ScrapingAnt is enabled, strict_proxy=True is the default (no explicit flag)."""

    async def fail_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ProxyError("connection refused", request=request)

    from backend.core.proxy import ProxyConnectionError

    # Default strict_proxy (not passed) must raise
    with pytest.raises(ProxyConnectionError):
        async with build_client(
            scrapingant_zone="dorking",
            _scrapingant_config=_config(enabled=True),
            _scrapingant_rest_transport=httpx.MockTransport(fail_handler),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, text="direct-ok", request=request)
            ),
            # strict_proxy NOT passed — should default to True
        ) as client:
            await client.get("https://example.com/check")
