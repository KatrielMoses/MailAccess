"""Async, caching, coalescing DNS resolver (c-ares via ``aiodns``).

Why this exists
---------------
An investigation fans out to dozens of modules, several of which each probe
*hundreds* of hosts concurrently (``account_discovery`` alone touches ~214
platforms). Python's default name resolution runs ``socket.getaddrinfo`` in the
event loop's ``ThreadPoolExecutor`` (only ~``min(32, cpu+4)`` threads — ~8 on a
4-vCPU box). Under that fan-out the thread pool and the system resolver
saturate, and lookups start failing with ``EAI_AGAIN``
("Temporary failure in name resolution"). Those failures then surface as
mass connect errors that the probe layer previously mislabelled as
"rate-limited", producing empty, misleading output.

This module replaces the loop's ``getaddrinfo`` with a c-ares backed resolver
that:

* never uses the blocking thread pool (c-ares is truly async), so thousands of
  concurrent lookups cost no threads;
* **caches** answers per host by TTL (bounded by config), so repeat hosts are
  free;
* **coalesces** in-flight lookups — N concurrent requests for the same host
  share ONE query instead of stampeding the resolver (the thundering-herd fix).

Safety: installation is best-effort and fully reversible. If ``aiodns`` is
missing or c-ares fails to initialise, we leave the default resolver in place.
Per lookup, any *infrastructure* failure falls back to the original
``getaddrinfo``; only a genuine "no such host" raises ``socket.gaierror`` (so
callers see a normal DNS miss, not a silent hang).
"""
from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Any

from ..config import settings

_LOG = logging.getLogger(__name__)

# Per-loop install state so we can restore cleanly and never double-install.
_INSTALLED: dict[int, Any] = {}

_AddrInfo = tuple[int, int, int, str, tuple]


class _HostResolver:
    """c-ares resolver with a TTL cache and per-host in-flight coalescing."""

    def __init__(self, orig_getaddrinfo: Any) -> None:
        self._orig = orig_getaddrinfo
        self._resolver: Any = None
        # cache: (host, family) -> (expiry_monotonic, [ip strings])
        self._cache: dict[tuple[str, int], tuple[float, list[str]]] = {}
        # coalescing: (host, family) -> Future[list[str]]
        self._inflight: dict[tuple[str, int], asyncio.Future] = {}

    def _get_resolver(self) -> Any:
        if self._resolver is None:
            import aiodns  # local import: optional dependency, only on first use

            kwargs: dict[str, Any] = {
                "timeout": float(settings.dns_resolver_timeout_seconds),
                "tries": 2,
            }
            nameservers = list(getattr(settings, "dns_nameservers", []) or [])
            if nameservers:
                kwargs["nameservers"] = nameservers
            self._resolver = aiodns.DNSResolver(**kwargs)
        return self._resolver

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(fam, host)
                return True
            except OSError:
                continue
        return False

    async def _query(self, host: str, family: int) -> list[str]:
        """Resolve host -> list of IPs via c-ares, cached + coalesced."""
        key = (host, family)
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached is not None and cached[0] > now:
            return cached[1]

        inflight = self._inflight.get(key)
        if inflight is not None:
            return await inflight

        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._inflight[key] = fut
        try:
            resolver = self._get_resolver()
            record = "AAAA" if family == socket.AF_INET6 else "A"
            # aiodns 4.x renamed ``query`` -> ``query_dns`` (old name deprecated);
            # 3.x only has ``query``. Prefer the new name when present.
            query = getattr(resolver, "query_dns", None) or resolver.query
            answers = await query(host, record)
            ips = [a.host for a in answers if getattr(a, "host", None)]
            ttls = [getattr(a, "ttl", 0) or 0 for a in answers]
            ttl = min([t for t in ttls if t > 0], default=int(settings.dns_cache_min_ttl_seconds))
            ttl = max(
                float(settings.dns_cache_min_ttl_seconds),
                min(float(ttl), float(settings.dns_cache_ttl_seconds)),
            )
            if ips:
                self._cache[key] = (now + ttl, ips)
            if not fut.done():
                fut.set_result(ips)
            return ips
        except Exception as exc:  # noqa: BLE001 - propagate to awaiters uniformly
            if not fut.done():
                fut.set_exception(exc)
            raise
        finally:
            self._inflight.pop(key, None)
            # If no coalesced awaiter attached before a fast failure, retrieve the
            # future's exception so asyncio doesn't log "exception never retrieved".
            if fut.done() and not fut.cancelled():
                fut.exception()

    async def getaddrinfo(
        self,
        host: Any,
        port: Any,
        *,
        family: int = 0,
        type: int = 0,  # noqa: A002 - mirror socket.getaddrinfo signature
        proto: int = 0,
        flags: int = 0,
    ) -> list[_AddrInfo]:
        # Only intervene for the common TCP client case. Anything unusual
        # (numeric-host flags, non-stream sockets, missing host, IP literals)
        # goes straight to the battle-tested system resolver.
        want_type = type or socket.SOCK_STREAM
        if (
            not host
            or not isinstance(host, str)
            or flags & socket.AI_NUMERICHOST
            or want_type != socket.SOCK_STREAM
            or (proto not in (0, socket.IPPROTO_TCP))
            or self._is_ip_literal(host)
        ):
            return await self._orig(
                host, port, family=family, type=type, proto=proto, flags=flags
            )

        families = (
            [socket.AF_INET6]
            if family == socket.AF_INET6
            else [socket.AF_INET]
            if family == socket.AF_INET
            else [socket.AF_INET, socket.AF_INET6]
        )
        port_num = int(port) if port is not None and str(port).isdigit() else 0

        results: list[_AddrInfo] = []
        last_error: Exception | None = None
        for fam in families:
            try:
                ips = await self._query(host, fam)
            except Exception as exc:  # noqa: BLE001 - try next family / fall back
                last_error = exc
                continue
            for ip in ips:
                if fam == socket.AF_INET6:
                    sockaddr: tuple = (ip, port_num, 0, 0)
                else:
                    sockaddr = (ip, port_num)
                results.append(
                    (fam, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)
                )

        if results:
            return results

        # No addresses. Distinguish a genuine miss from resolver trouble:
        # on any infrastructure error, defer to the system resolver rather than
        # inventing a failure; only a clean empty answer is a real NXDOMAIN.
        if last_error is not None:
            try:
                return await self._orig(
                    host, port, family=family, type=type, proto=proto, flags=flags
                )
            except socket.gaierror:
                raise
            except Exception:  # noqa: BLE001
                raise socket.gaierror(
                    socket.EAI_FAIL, f"async resolver failed for {host!r}: {last_error}"
                ) from last_error
        raise socket.gaierror(socket.EAI_NONAME, f"no address for {host!r}")


def install() -> bool:
    """Install the caching resolver on the running loop. Idempotent, best-effort.

    Returns True if the caching resolver is active after the call.
    """
    if not settings.async_dns_enabled:
        return False
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return False
    if id(loop) in _INSTALLED:
        return True
    try:
        import aiodns  # noqa: F401 - probe availability before swapping
    except Exception as exc:  # noqa: BLE001
        _LOG.info("async DNS resolver unavailable (aiodns import failed: %s) — "
                  "using system resolver", exc)
        return False
    try:
        orig = loop.getaddrinfo
        resolver = _HostResolver(orig)
        # Validate c-ares actually initialises on this platform/loop.
        resolver._get_resolver()
        # uvloop (uvicorn's default on Linux) is a C loop that rejects attribute
        # assignment, so the override below raises AttributeError and we fall
        # back. To actually use the async resolver on Linux, run the backend on
        # the plain asyncio loop (uvicorn ``--loop asyncio``). On Windows/asyncio
        # (e.g. local dev) the override attaches normally.
        loop.getaddrinfo = resolver.getaddrinfo  # type: ignore[method-assign]
        _INSTALLED[id(loop)] = orig
        _LOG.info("async DNS resolver installed (c-ares, cache ttl<=%ss, "
                  "coalescing on)", settings.dns_cache_ttl_seconds)
        return True
    except (AttributeError, TypeError) as exc:
        _LOG.warning(
            "async DNS resolver could not attach to this event loop (%s) — likely "
            "uvloop; run the backend with `--loop asyncio` to enable it. Falling "
            "back to the system resolver (the global request cap still applies).",
            exc,
        )
        return False
    except Exception as exc:  # noqa: BLE001 - never break the app over DNS wiring
        _LOG.warning("async DNS resolver install failed (%s) — using system "
                     "resolver", exc)
        return False


def uninstall() -> None:
    """Restore the original ``getaddrinfo`` on the running loop, if installed."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    orig = _INSTALLED.pop(id(loop), None)
    if orig is not None:
        try:
            loop.getaddrinfo = orig  # type: ignore[method-assign]
        except Exception:  # noqa: BLE001
            pass
