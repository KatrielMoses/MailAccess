"""Phase 5B — egress rotation pool.

Replaces the single static proxy (``proxy.py``) with a pluggable, health-checked,
auto-evicting pool of egress endpoints. Bring-your-own / config-driven: point
``egress_proxies`` at the Hetzner box, a self-supplied endpoint list, or leave it
empty (direct egress) — no hardcoded paid dependency. A dead endpoint is evicted
after repeated failures and benched for a cooldown, then re-admitted on
probation, so one bad proxy can't sink a bulk run.

The pool is transport-agnostic: both stacks consult it — httpx via
``proxy.ProxyConfig.proxy_url`` and the curl-cffi ``StealthSession`` via
``proxies=`` — and both report success/failure back so eviction reflects real
egress health across both.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..config import settings

logger = logging.getLogger(__name__)

_VALID_SCHEMES = {"socks5", "socks4", "http", "https"}


def _valid_proxy_url(url: str) -> bool:
    try:
        return urlparse(url).scheme in _VALID_SCHEMES
    except ValueError:
        return False


@dataclass
class _Endpoint:
    url: str
    failures: int = 0
    successes: int = 0
    benched_until: float = 0.0  # monotonic; >now means evicted

    def is_available(self, now: float) -> bool:
        return now >= self.benched_until


@dataclass
class EgressPool:
    """A rotating, health-tracked pool of egress proxy endpoints.

    Rotation is round-robin over currently-available endpoints. An endpoint that
    reaches ``max_failures`` consecutive failures is benched for
    ``cooldown_seconds`` (then re-admitted with its counter reset — a probation).
    Thread-safe: both the async httpx hook and the threaded curl-cffi calls touch
    it, so a plain lock guards the small critical sections.
    """

    urls: list[str] = field(default_factory=list)
    max_failures: int = 3
    cooldown_seconds: float = 300.0

    _endpoints: list[_Endpoint] = field(default_factory=list, init=False)
    _idx: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for u in self.urls:
            u = (u or "").strip()
            if not u or u in seen:
                continue
            if not _valid_proxy_url(u):
                logger.warning("egress pool: ignoring invalid proxy url %r", u)
                continue
            seen.add(u)
            self._endpoints.append(_Endpoint(url=u))

    # -- introspection ----------------------------------------------------
    @property
    def size(self) -> int:
        return len(self._endpoints)

    @property
    def healthy_urls(self) -> list[str]:
        now = time.monotonic()
        return [e.url for e in self._endpoints if e.is_available(now)]

    def is_configured(self) -> bool:
        return bool(self._endpoints)

    # -- rotation ---------------------------------------------------------
    def next_proxy(self) -> str | None:
        """Return the next available endpoint (round-robin), or None if the pool
        is empty or every endpoint is currently benched."""
        with self._lock:
            n = len(self._endpoints)
            if n == 0:
                return None
            now = time.monotonic()
            for _ in range(n):
                ep = self._endpoints[self._idx % n]
                self._idx = (self._idx + 1) % n
                if ep.is_available(now):
                    return ep.url
            return None  # all benched

    # -- health feedback --------------------------------------------------
    def report_success(self, url: str | None) -> None:
        if not url:
            return
        with self._lock:
            for ep in self._endpoints:
                if ep.url == url:
                    ep.successes += 1
                    ep.failures = 0
                    ep.benched_until = 0.0
                    return

    def report_failure(self, url: str | None) -> None:
        if not url:
            return
        with self._lock:
            for ep in self._endpoints:
                if ep.url == url:
                    ep.failures += 1
                    if ep.failures >= self.max_failures:
                        ep.benched_until = time.monotonic() + self.cooldown_seconds
                        logger.warning(
                            "egress pool: benched %s for %.0fs after %d failures",
                            url, self.cooldown_seconds, ep.failures,
                        )
                    return

    async def health_check(
        self, probe_url: str | None = None, *, timeout: float = 8.0
    ) -> dict[str, bool]:
        """Probe each endpoint and bench the dead ones. Best-effort, guarded.

        Returns ``{proxy_url: healthy}``. Uses httpx so it works without
        curl-cffi. A probe failure reports a failure (which may bench the
        endpoint); a success clears its counters.
        """
        url = probe_url or str(getattr(settings, "egress_health_check_url", "") or "").strip()
        if not url or not self._endpoints:
            return {}
        import httpx

        results: dict[str, bool] = {}
        for ep in list(self._endpoints):
            ok = False
            try:
                async with httpx.AsyncClient(proxy=ep.url, timeout=timeout) as client:
                    resp = await client.get(url)
                    ok = resp.status_code < 500
            except Exception:
                ok = False
            results[ep.url] = ok
            if ok:
                self.report_success(ep.url)
            else:
                self.report_failure(ep.url)
        return results


def _build_pool() -> EgressPool:
    """Construct the process pool from config (BYO list, else the single proxy)."""
    urls: list[str] = []
    configured = list(getattr(settings, "egress_proxies", []) or [])
    if configured:
        urls = [str(u) for u in configured]
    elif getattr(settings, "proxy_enabled", False) and getattr(settings, "proxy_url", None):
        # Backward-compat: a single configured proxy becomes a pool of one.
        urls = [str(settings.proxy_url)]
    return EgressPool(
        urls=urls,
        max_failures=int(getattr(settings, "egress_max_failures", 3)),
        cooldown_seconds=float(getattr(settings, "egress_cooldown_seconds", 300.0)),
    )


# Process-wide singleton, consulted by both transport stacks.
egress_pool = _build_pool()


def reload_egress_pool() -> EgressPool:
    """Rebuild the singleton from current settings (tests / config changes)."""
    global egress_pool
    egress_pool = _build_pool()
    return egress_pool


__all__ = ["EgressPool", "egress_pool", "reload_egress_pool"]
