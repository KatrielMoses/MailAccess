from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import quote

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

_REST_API_URL = "https://api.scrapingant.com/v2/extended"
_RESIDENTIAL_PROXY_HOST = "residential.scrapingant.com"
_DATACENTER_PROXY_HOST = "datacenter.scrapingant.com"
_VALID_PROXY_TYPES = {"residential", "datacenter"}
_ZONE_TOGGLES = {
    "dorking": "enabled_dorking",
    "platforms": "enabled_platforms",
}


class ScrapingAntMode(Enum):
    DISABLED = "disabled"
    REST_API = "rest_api"
    PROXY_MODE = "proxy_mode"
    RESIDENTIAL_PROXY = "residential_proxy"
    DATACENTER_PROXY = "datacenter_proxy"


class ScrapingAntError(Exception):
    pass


class ScrapingAntAuthError(ScrapingAntError):
    pass


@dataclass(frozen=True)
class ScrapingAntConfig:
    api_key: str | None
    enabled_dorking: bool
    enabled_platforms: bool
    proxy_type: str
    transport: str = "rest_api"
    proxy_residential_username: str | None = None
    proxy_residential_password: str | None = None
    proxy_datacenter_username: str | None = None
    proxy_datacenter_password: str | None = None
    timeout: float = 30.0

    def _proxy_type(self) -> str:
        if self.proxy_type in _VALID_PROXY_TYPES:
            return self.proxy_type
        logger.warning(
            "Unsupported ScrapingAnt proxy_type %r; falling back to residential",
            self.proxy_type,
        )
        return "residential"

    def mode_for(self, zone: str) -> ScrapingAntMode:
        """Resolve the active ScrapingAnt mode for a zone."""
        toggle_name = _ZONE_TOGGLES.get(zone)
        if not toggle_name:
            return ScrapingAntMode.DISABLED
        if not getattr(self, toggle_name):
            return ScrapingAntMode.DISABLED

        transport = self.transport
        if transport == ScrapingAntMode.PROXY_MODE.value:
            transport = ScrapingAntMode.RESIDENTIAL_PROXY.value

        if transport == ScrapingAntMode.REST_API.value:
            if self.api_key:
                return ScrapingAntMode.REST_API
            return ScrapingAntMode.DISABLED
        if transport == ScrapingAntMode.RESIDENTIAL_PROXY.value:
            if self.proxy_residential_username and self.proxy_residential_password:
                return ScrapingAntMode.RESIDENTIAL_PROXY
            return ScrapingAntMode.DISABLED
        if transport == ScrapingAntMode.DATACENTER_PROXY.value:
            if self.proxy_datacenter_username and self.proxy_datacenter_password:
                return ScrapingAntMode.DATACENTER_PROXY
            return ScrapingAntMode.DISABLED
        return ScrapingAntMode.DISABLED

    def rest_api_params(self, url: str) -> dict[str, str]:
        return {
            "q": url,
            "x-api-key": self.api_key or "",
            "browser": "false",
            "proxy_type": self._proxy_type(),
        }

    def residential_proxy_url(self) -> str | None:
        if not self.proxy_residential_username or not self.proxy_residential_password:
            return None
        username = quote(self.proxy_residential_username, safe="")
        password = quote(self.proxy_residential_password, safe="")
        return f"http://{username}:{password}@{_RESIDENTIAL_PROXY_HOST}:8080"

    def datacenter_proxy_url(self) -> str | None:
        if not self.proxy_datacenter_username or not self.proxy_datacenter_password:
            return None
        username = quote(self.proxy_datacenter_username, safe="")
        password = quote(self.proxy_datacenter_password, safe="")
        return f"http://{username}:{password}@{_DATACENTER_PROXY_HOST}:8080"


class ScrapingAntTransport:
    def __init__(
        self,
        config: ScrapingAntConfig,
        *,
        rest_transport: httpx.AsyncBaseTransport | None = None,
        proxy_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._rest_transport = rest_transport
        self._proxy_transport = proxy_transport

    def mode_for(self, zone: str) -> ScrapingAntMode:
        return self._config.mode_for(zone)

    async def send(self, request: httpx.Request, zone: str) -> httpx.Response:
        mode = self.mode_for(zone)
        if mode is ScrapingAntMode.REST_API:
            return await self._send_rest_api(request)
        if mode is ScrapingAntMode.RESIDENTIAL_PROXY:
            return await self._send_residential_proxy(request)
        if mode is ScrapingAntMode.DATACENTER_PROXY:
            return await self._send_datacenter_proxy(request)
        raise ScrapingAntError("ScrapingAnt is disabled")

    async def _send_rest_api(self, request: httpx.Request) -> httpx.Response:
        try:
            async with httpx.AsyncClient(
                timeout=self._config.timeout,
                transport=self._rest_transport,
            ) as client:
                response = await client.get(
                    _REST_API_URL,
                    params=self._config.rest_api_params(str(request.url)),
                )
            if response.status_code in {401, 403}:
                raise ScrapingAntAuthError("ScrapingAnt authentication failed")
            if response.status_code >= 500:
                raise ScrapingAntError("ScrapingAnt returned an upstream error")
            if response.status_code >= 400:
                raise ScrapingAntError("ScrapingAnt request failed")
            try:
                payload = response.json()
            except ValueError as exc:
                raise ScrapingAntError("ScrapingAnt returned malformed JSON") from exc
            return self._response_from_payload(request, payload)
        except httpx.TimeoutException as exc:
            raise ScrapingAntError("ScrapingAnt request timed out") from exc
        except httpx.HTTPError as exc:
            raise ScrapingAntError("ScrapingAnt request failed") from exc

    def _response_from_payload(self, request: httpx.Request, payload: Any) -> httpx.Response:
        if not isinstance(payload, dict):
            raise ScrapingAntError("ScrapingAnt returned malformed JSON")
        content = payload.get("html")
        if not isinstance(content, str):
            raise ScrapingAntError("ScrapingAnt response missing html field")
        status_code = payload.get("status_code")
        if not isinstance(status_code, int):
            raise ScrapingAntError("ScrapingAnt response missing status_code")
        raw_headers = payload.get("headers", [])
        headers: dict[str, str] = {}
        if isinstance(raw_headers, list):
            for entry in raw_headers:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                value = entry.get("value")
                if isinstance(name, str) and isinstance(value, str):
                    headers[name] = value
        return httpx.Response(
            status_code=status_code,
            content=content.encode("utf-8"),
            headers=headers,
            request=request,
        )

    async def _send_residential_proxy(self, request: httpx.Request) -> httpx.Response:
        proxy_url = self._config.residential_proxy_url()
        if proxy_url is None:
            raise ScrapingAntError("ScrapingAnt residential proxy mode is disabled")
        return await self._send_proxy(request, proxy_url)

    async def _send_datacenter_proxy(self, request: httpx.Request) -> httpx.Response:
        proxy_url = self._config.datacenter_proxy_url()
        if proxy_url is None:
            raise ScrapingAntError("ScrapingAnt datacenter proxy mode is disabled")
        return await self._send_proxy(request, proxy_url)

    async def _send_proxy(self, request: httpx.Request, proxy_url: str) -> httpx.Response:
        client_kwargs: dict[str, Any] = {
            "timeout": self._config.timeout,
            "verify": False,
        }
        if self._proxy_transport is None:
            client_kwargs["proxy"] = proxy_url
        else:
            client_kwargs["transport"] = self._proxy_transport

        proxy_request = self._clone_request(request)
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.send(proxy_request)
            if response.status_code in {401, 403}:
                raise ScrapingAntAuthError("ScrapingAnt authentication failed")
            if response.status_code >= 500:
                raise ScrapingAntError("ScrapingAnt returned an upstream error")
            if response.status_code >= 400:
                raise ScrapingAntError("ScrapingAnt request failed")
            return response
        except httpx.TimeoutException as exc:
            raise ScrapingAntError("ScrapingAnt request timed out") from exc
        except httpx.HTTPError as exc:
            raise ScrapingAntError("ScrapingAnt request failed") from exc

    def _clone_request(self, request: httpx.Request) -> httpx.Request:
        return httpx.Request(
            request.method,
            request.url,
            headers=request.headers,
            content=request.content,
            extensions=request.extensions.copy(),
        )


scrapingant_config = ScrapingAntConfig(
    api_key=settings.scrapingant_api_key,
    enabled_dorking=settings.scrapingant_enabled_dorking,
    enabled_platforms=settings.scrapingant_enabled_platforms,
    proxy_type=settings.scrapingant_proxy_type,
    transport=settings.scrapingant_transport,
    proxy_residential_username=settings.scrapingant_proxy_residential_username,
    proxy_residential_password=settings.scrapingant_proxy_residential_password,
    proxy_datacenter_username=settings.scrapingant_proxy_datacenter_username,
    proxy_datacenter_password=settings.scrapingant_proxy_datacenter_password,
)


def get_active_transport() -> str:
    """Return the configured ScrapingAnt transport selector."""
    return settings.scrapingant_transport
