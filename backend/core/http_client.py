from __future__ import annotations

import logging
from typing import Any

import httpx

from .proxy import ProxyConnectionError, proxy_config
from .rate_limiter import rate_limiter
from .scrapingant import (
    ScrapingAntError,
    ScrapingAntMode,
    ScrapingAntTransport,
    scrapingant_config,
)

logger = logging.getLogger(__name__)


async def _before_request(request: httpx.Request) -> None:
    """Event hook: enforce per-domain rate limit and rotate UA for Tor."""
    await rate_limiter.acquire(request.url.host)
    if proxy_config.is_tor:
        request.headers["user-agent"] = proxy_config.random_ua()


def build_client(
    *,
    scrapingant_zone: str | None = None,
    **kwargs: Any,
) -> _MailAccessClient:
    """
    Return a configured AsyncClient with rate limiting and optional proxy.

    All keyword arguments are forwarded to httpx.AsyncClient.
    Default timeout is 10 s when not specified by the caller.

    When PROXY_ENABLED=true, the proxy URL is applied to all requests.
    When the proxy is unreachable a ProxyConnectionError is raised with a hint
    to check PROXY_URL in .env.
    """
    if scrapingant_zone is not None:
        return build_routed_client(scrapingant_zone, **kwargs)

    kwargs.setdefault("timeout", 10.0)
    event_hooks: dict[str, list[Any]] = {"request": [_before_request]}

    proxy_url = proxy_config.proxy_url()
    if proxy_url:
        kwargs["proxy"] = proxy_url

    return _MailAccessClient(event_hooks=event_hooks, **kwargs)


def build_routed_client(zone: str, **kwargs: Any) -> _RoutedMailAccessClient:
    """
    Return a client that can route requests through ScrapingAnt for a zone.

    ScrapingAnt routing is active only when the module-level config and the
    zone toggle both enable it. Any ScrapingAnt failure falls back to direct.
    """
    config = kwargs.pop("_scrapingant_config", scrapingant_config)
    rest_transport = kwargs.pop("_scrapingant_rest_transport", None)
    proxy_transport = kwargs.pop("_scrapingant_proxy_transport", None)
    kwargs.setdefault("timeout", 10.0)
    event_hooks: dict[str, list[Any]] = {"request": [_before_request]}

    proxy_url = proxy_config.proxy_url()
    if proxy_url:
        kwargs["proxy"] = proxy_url

    return _RoutedMailAccessClient(
        zone=zone,
        scrapingant_transport=ScrapingAntTransport(
            config,
            rest_transport=rest_transport,
            proxy_transport=proxy_transport,
        ),
        event_hooks=event_hooks,
        **kwargs,
    )


class _MailAccessClient(httpx.AsyncClient):
    """AsyncClient subclass that converts proxy errors into ProxyConnectionError."""

    async def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        try:
            return await super().send(request, **kwargs)
        except (httpx.ProxyError, httpx.ConnectError) as exc:
            if proxy_config.is_enabled:
                from ..config import settings

                raise ProxyConnectionError(
                    f"Proxy connection failed ({settings.proxy_url!r}). "
                    "Check PROXY_URL in your .env file."
                ) from exc
            raise


class _RoutedMailAccessClient(_MailAccessClient):
    def __init__(
        self,
        *,
        zone: str,
        scrapingant_transport: ScrapingAntTransport,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._scrapingant_zone = zone
        self._scrapingant_transport = scrapingant_transport

    async def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        if self._scrapingant_transport.mode_for(self._scrapingant_zone) is ScrapingAntMode.DISABLED:
            return await super().send(request, **kwargs)
        try:
            return await self._scrapingant_transport.send(request, self._scrapingant_zone)
        except ScrapingAntError as exc:
            logger.warning(
                "ScrapingAnt routing failed for zone %s; falling back to direct: %s",
                self._scrapingant_zone,
                exc.__class__.__name__,
            )
            return await super().send(request, **kwargs)
