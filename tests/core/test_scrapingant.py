from __future__ import annotations

import httpx
import pytest

from backend.core.http_client import build_routed_client
from backend.core.scrapingant import ScrapingAntConfig, ScrapingAntMode


def _config(
    *,
    api_key: str | None = "secret-key",
    enabled_dorking: bool = True,
    enabled_platforms: bool = False,
    proxy_type: str = "residential",
    transport: str = "rest_api",
    proxy_residential_username: str | None = "res-user",
    proxy_residential_password: str | None = "res-pass",
    proxy_datacenter_username: str | None = "dc-user",
    proxy_datacenter_password: str | None = "dc-pass",
) -> ScrapingAntConfig:
    return ScrapingAntConfig(
        api_key=api_key,
        enabled_dorking=enabled_dorking,
        enabled_platforms=enabled_platforms,
        proxy_type=proxy_type,
        transport=transport,
        proxy_residential_username=proxy_residential_username,
        proxy_residential_password=proxy_residential_password,
        proxy_datacenter_username=proxy_datacenter_username,
        proxy_datacenter_password=proxy_datacenter_password,
    )


def test_mode_disabled_without_api_key() -> None:
    assert _config(api_key=None).mode_for("dorking") is ScrapingAntMode.DISABLED


def test_mode_disabled_when_zone_toggle_off() -> None:
    assert _config(enabled_dorking=False).mode_for("dorking") is ScrapingAntMode.DISABLED


def test_mode_enabled_when_key_and_zone_toggle_on() -> None:
    assert _config().mode_for("dorking") is ScrapingAntMode.REST_API


def test_mode_toggles_are_independent() -> None:
    config = _config(enabled_dorking=False, enabled_platforms=True)

    assert config.mode_for("dorking") is ScrapingAntMode.DISABLED
    assert config.mode_for("platforms") is ScrapingAntMode.REST_API


def test_mode_unknown_zone_is_disabled() -> None:
    assert _config().mode_for("not_a_real_zone") is ScrapingAntMode.DISABLED


def test_rest_api_param_shape() -> None:
    params = _config(transport="rest_api").rest_api_params("https://example.com/x?a=1&b=two")

    assert params == {
        "q": "https://example.com/x?a=1&b=two",
        "x-api-key": "secret-key",
        "browser": "false",
        "proxy_type": "residential",
    }


def test_residential_proxy_mode_disabled_without_credentials() -> None:
    config = _config(
        transport="residential_proxy",
        proxy_residential_username=None,
        proxy_residential_password=None,
    )

    assert config.mode_for("dorking") is ScrapingAntMode.DISABLED


def test_residential_proxy_mode_disabled_when_zone_toggle_off() -> None:
    config = _config(transport="residential_proxy", enabled_dorking=False)

    assert config.mode_for("dorking") is ScrapingAntMode.DISABLED


def test_datacenter_proxy_mode_disabled_without_credentials() -> None:
    config = _config(
        transport="datacenter_proxy",
        proxy_datacenter_username=None,
        proxy_datacenter_password=None,
    )

    assert config.mode_for("dorking") is ScrapingAntMode.DISABLED


def test_residential_proxy_url_uses_dashboard_creds_and_correct_host() -> None:
    url = _config(
        proxy_residential_username="test-user",
        proxy_residential_password="test-pass",
    ).residential_proxy_url()

    assert url == "http://test-user:test-pass@residential.scrapingant.com:8080"
    assert "browser=false" not in url
    assert "proxy_type=" not in url


def test_datacenter_proxy_url_uses_dashboard_creds_and_correct_host() -> None:
    url = _config(
        proxy_datacenter_username="test-user",
        proxy_datacenter_password="test-pass",
    ).datacenter_proxy_url()

    assert url == "http://test-user:test-pass@datacenter.scrapingant.com:8080"


def test_proxy_url_credentials_are_url_quoted() -> None:
    url = _config(
        proxy_residential_username="test/user",
        proxy_residential_password="a&b=c+d/e",
    ).residential_proxy_url()

    assert url == "http://test%2Fuser:a%26b%3Dc%2Bd%2Fe@residential.scrapingant.com:8080"


def test_transport_selection_picks_residential_when_credentials_present_and_transport_set() -> None:
    config = _config(transport="residential_proxy", enabled_platforms=True)

    assert config.mode_for("platforms") is ScrapingAntMode.RESIDENTIAL_PROXY


def test_proxy_mode_alias_selects_residential_proxy() -> None:
    config = _config(transport="proxy_mode")

    assert config.mode_for("dorking") is ScrapingAntMode.RESIDENTIAL_PROXY


def test_invalid_proxy_type_falls_back_to_residential(caplog: pytest.LogCaptureFixture) -> None:
    params = _config(proxy_type="mobile").rest_api_params("https://example.com")

    assert params["proxy_type"] == "residential"
    assert "Unsupported ScrapingAnt proxy_type" in caplog.text
    assert "secret-key" not in caplog.text


@pytest.mark.parametrize(
    ("status_code", "body"),
    [
        (401, {"error": "unauthorized"}),
        (502, {"error": "upstream"}),
        (200, "not-json"),
    ],
)
async def test_rest_api_failure_falls_back_to_direct_response(
    status_code: int,
    body: dict[str, str] | str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[str] = []

    async def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if isinstance(body, str):
            return httpx.Response(status_code, text=body, request=request)
        return httpx.Response(status_code, json=body, request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="direct-ok", request=request)

    async with build_routed_client(
        "dorking",
        _scrapingant_config=_config(transport="rest_api"),
        _scrapingant_rest_transport=httpx.MockTransport(scrapingant_handler),
        transport=httpx.MockTransport(direct_handler),
    ) as client:
        response = await client.get("https://example.com/profile")

    assert response.text == "direct-ok"
    assert calls[0].startswith("https://api.scrapingant.com/v2/extended?")
    assert calls[1] == "https://example.com/profile"
    assert "secret-key" not in caplog.text


async def test_rest_api_timeout_falls_back_to_direct_response(
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[str] = []

    async def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        raise httpx.ReadTimeout("slow", request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="direct-ok", request=request)

    async with build_routed_client(
        "dorking",
        _scrapingant_config=_config(transport="rest_api"),
        _scrapingant_rest_transport=httpx.MockTransport(scrapingant_handler),
        transport=httpx.MockTransport(direct_handler),
    ) as client:
        response = await client.get("https://example.com/profile")

    assert response.text == "direct-ok"
    assert len(calls) == 2
    assert "secret-key" not in caplog.text


async def test_rest_api_success_returns_scrapingant_payload() -> None:
    async def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "html": "via-scrapingant",
                "status_code": 203,
                "headers": [{"name": "Content-Type", "value": "text/html"}],
                "text": "via-scrapingant",
                "cookies": "",
            },
            request=request,
        )

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    async with build_routed_client(
        "dorking",
        _scrapingant_config=_config(transport="rest_api"),
        _scrapingant_rest_transport=httpx.MockTransport(scrapingant_handler),
        transport=httpx.MockTransport(direct_handler),
    ) as client:
        response = await client.get("https://example.com/profile")

    assert response.status_code == 203
    assert response.text == "via-scrapingant"
    assert response.headers["Content-Type"] == "text/html"


async def test_rest_api_response_parses_headers_array() -> None:
    async def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "html": "<html>ok</html>",
                "status_code": 200,
                "headers": [
                    {"name": "Content-Type", "value": "text/html; charset=utf-8"},
                    {"name": "X-Target", "value": "profile"},
                    {"name": 123, "value": "ignored"},
                    {"name": "X-Ignored", "value": None},
                ],
                "text": "ok",
                "cookies": "",
            },
            request=request,
        )

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    async with build_routed_client(
        "dorking",
        _scrapingant_config=_config(transport="rest_api"),
        _scrapingant_rest_transport=httpx.MockTransport(scrapingant_handler),
        transport=httpx.MockTransport(direct_handler),
    ) as client:
        response = await client.get("https://example.com/profile")

    assert response.headers["Content-Type"] == "text/html; charset=utf-8"
    assert response.headers["X-Target"] == "profile"
    assert "X-Ignored" not in response.headers


async def test_disabled_zone_never_calls_scrapingant() -> None:
    scrapingant_calls: list[str] = []

    async def scrapingant_handler(request: httpx.Request) -> httpx.Response:
        scrapingant_calls.append(str(request.url))
        return httpx.Response(200, json={"content": "should-not-run"}, request=request)

    async def direct_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="direct-ok", request=request)

    async with build_routed_client(
        "dorking",
        _scrapingant_config=_config(
            enabled_dorking=False,
            transport="rest_api",
        ),
        _scrapingant_rest_transport=httpx.MockTransport(scrapingant_handler),
        transport=httpx.MockTransport(direct_handler),
    ) as client:
        response = await client.get("https://example.com/profile")

    assert response.text == "direct-ok"
    assert scrapingant_calls == []
