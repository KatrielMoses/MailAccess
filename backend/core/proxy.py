from __future__ import annotations

import random
from urllib.parse import urlparse

from ..config import settings

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

_TOR_URL = "socks5://127.0.0.1:9050"

_VALID_SCHEMES = {"socks5", "socks4", "http", "https"}


class ProxyConnectionError(Exception):
    pass


class ProxyConfig:
    def __init__(self) -> None:
        self._enabled: bool = settings.proxy_enabled
        self._url: str | None = settings.proxy_url
        if self._enabled and self._url:
            scheme = urlparse(self._url).scheme
            if scheme not in _VALID_SCHEMES:
                raise ValueError(
                    f"Unsupported proxy scheme {scheme!r} in PROXY_URL. "
                    f"Supported schemes: {', '.join(sorted(_VALID_SCHEMES))}"
                )

    @property
    def is_enabled(self) -> bool:
        # Phase 5B — enabled when the legacy single proxy is on OR the egress
        # rotation pool is configured (BYO list). Either way requests egress
        # through a proxy, so the error path should treat failures as proxy
        # failures.
        if self._enabled and bool(self._url):
            return True
        try:
            from .egress_pool import egress_pool

            return egress_pool.is_configured()
        except Exception:
            return False

    @property
    def is_tor(self) -> bool:
        return self._enabled and bool(self._url) and self._url == _TOR_URL

    def proxy_url(self) -> str | None:
        """Return the egress endpoint for the next request.

        Phase 5B — prefer the rotation pool (which already folds in the legacy
        single proxy as a pool-of-one), rotating + health-aware. Falls back to
        the legacy single URL only if the pool is somehow unavailable.
        """
        try:
            from .egress_pool import egress_pool

            if egress_pool.is_configured():
                return egress_pool.next_proxy()
        except Exception:
            pass
        return self._url if (self._enabled and bool(self._url)) else None

    def random_ua(self) -> str:
        return random.choice(_UA_POOL)  # noqa: S311


proxy_config = ProxyConfig()
