"""Phase 2F — API safe-by-default: shared auth/quota helpers.

Two ideas:

* **Localhost dev convenience, remote safety.** When no API key is configured,
  local (loopback) callers are allowed (dev UX) but non-local callers are
  refused — the "no key ⇒ open" bypass never applies off-localhost. When a key
  *is* configured it is enforced on every protected surface, including the
  WebSocket and Maltego endpoints.
* **Per-principal quotas.** An embedded, in-process fixed-window counter caps how
  often a principal may trigger an investigation. No shared-infra dependency.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from ..config import settings

LOCAL_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})


def client_host(scope_obj) -> str | None:
    """The peer host of a Request or WebSocket (``.client.host``)."""
    client = getattr(scope_obj, "client", None)
    return client.host if client else None


def is_local(scope_obj) -> bool:
    return client_host(scope_obj) in LOCAL_HOSTS


def provided_key(request) -> str | None:
    """Extract an API key from the ``X-API-Key`` header or an ``api_key`` query
    param (the query param supports WebSocket/Maltego clients that cannot set
    custom headers)."""
    header = request.headers.get("X-API-Key") if hasattr(request, "headers") else None
    if header:
        return header
    try:
        return request.query_params.get("api_key")
    except Exception:
        return None


def key_ok(request) -> bool:
    """Whether the request presents the configured key. Always True when no key
    is configured (the caller decides the local/remote policy separately)."""
    if not settings.mailaccess_api_key:
        return True
    return provided_key(request) == settings.mailaccess_api_key


def principal_of(request) -> str:
    """A stable principal id for quota accounting: the API key when present
    (hashed to a short id), else the client host."""
    if settings.mailaccess_api_key:
        key = provided_key(request)
        if key:
            import hashlib

            return "key:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return "host:" + (client_host(request) or "unknown")


class PrincipalQuota:
    """In-process fixed-window request quota, keyed by principal. Thread-safe."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self._limit = limit
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, principal: str, *, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits[principal]
            cutoff = now - self._window
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


_quota = PrincipalQuota(
    settings.api_quota_per_principal, settings.api_quota_window_seconds
)


def enforce_quota(request) -> None:
    """Raise HTTP 429 when the request's principal exceeds its quota."""
    if not settings.api_quota_enabled:
        return
    if not _quota.allow(principal_of(request)):
        from fastapi import HTTPException

        raise HTTPException(status_code=429, detail="rate limit exceeded")


def reset_quota() -> None:
    _quota.reset()
