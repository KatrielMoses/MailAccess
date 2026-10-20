"""Per-host politeness for profile probing (UC2).

At most one request in flight per host across a whole investigation: every
username variant and every enumeration module that opts in shares the same
per-host slot. Bursts of parallel requests to one host were the source of our
own 429s (Discord, TryHackMe), so this removes the cause rather than working
around a limit.

A 429 whose ``Retry-After`` is at most ``RETRY_AFTER_MAX_S`` seconds is retried
exactly once after waiting that long: that is the server's own instruction. Any
other 429 stays a 429, and the detectors report it as inconclusive.

Scope: a registry of per-host slots lives in a ContextVar. The engine opens one
per investigation (``new_run``); modules that probe third-party profile hosts
call ``activate()`` in their own task, so unrelated modules (search, DNS, APIs
with their own quotas) are unaffected. A caller with no run registry (a direct
module call, a test) gets a fresh one on ``activate()``.
"""

from __future__ import annotations

import asyncio
import contextlib
from contextvars import ContextVar
from typing import AsyncIterator

RETRY_AFTER_MAX_S = 5.0

_registry: ContextVar[dict[str, asyncio.Semaphore] | None] = ContextVar(
    "host_politeness_registry", default=None
)
_active: ContextVar[bool] = ContextVar("host_politeness_active", default=False)


def new_run() -> None:
    """Start a fresh per-host registry for this investigation's context."""
    _registry.set({})


def activate() -> None:
    """Opt the current task into per-host politeness (shares the run registry)."""
    if _registry.get() is None:
        _registry.set({})
    _active.set(True)


def is_active() -> bool:
    return _active.get() and _registry.get() is not None


@contextlib.asynccontextmanager
async def host_slot(host: str) -> AsyncIterator[None]:
    """Hold this host's single in-flight slot (no-op when politeness is off)."""
    registry = _registry.get()
    if not _active.get() or registry is None or not host:
        yield
        return
    key = host.lower().removeprefix("www.")
    sem = registry.get(key)
    if sem is None:
        sem = registry[key] = asyncio.Semaphore(1)
    async with sem:
        yield


def retry_after_seconds(headers: object) -> float | None:
    """``Retry-After`` in seconds when it is a small delta we may honour, else None."""
    try:
        raw = str(headers.get("retry-after") or "").strip()  # type: ignore[attr-defined]
    except Exception:
        return None
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None  # HTTP-date form: not a short wait; leave it inconclusive
    if 0 <= value <= RETRY_AFTER_MAX_S:
        return value
    return None
