"""Concurrency limiter + per-run wall-clock ceiling for the JEV seam.

Two independent brakes so JEV can never stall a run:

* a process-wide semaphore (``JEV_MAX_CONCURRENCY``), one per event loop. Time
  spent waiting for a slot counts against the per-call deadline, so a saturated
  seam DEFERs instead of queueing.
* :func:`run_scope` — an investigation / harvest wraps its work in this, and every
  JEV call inside it shares ONE wall-clock ceiling (``JEV_RUN_CEILING_SECONDS``),
  further capped by an optional :class:`InvestigationBudget`. Once either is spent
  every call DEFERs immediately. Outside a scope only the per-call deadline applies.
"""

from __future__ import annotations

import asyncio
import contextvars
import weakref
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Protocol


class _Budget(Protocol):
    def remaining(self) -> float: ...


class RunScope:
    def __init__(self, ceiling_seconds: float, budget: _Budget | None = None) -> None:
        self._ceiling = float(ceiling_seconds)
        self._budget = budget
        self._spent = 0.0

    def remaining(self) -> float:
        own = max(0.0, self._ceiling - self._spent) if self._ceiling > 0 else float("inf")
        if self._budget is not None:
            own = min(own, max(0.0, self._budget.remaining()))
        return own

    def charge(self, seconds: float) -> None:
        self._spent += max(0.0, seconds)

    @property
    def spent_seconds(self) -> float:
        return self._spent


_SCOPE: contextvars.ContextVar[RunScope | None] = contextvars.ContextVar(
    "jev_run_scope", default=None
)


def current_scope() -> RunScope | None:
    return _SCOPE.get()


@asynccontextmanager
async def run_scope(
    ceiling_seconds: float | None = None, *, budget: _Budget | None = None
) -> AsyncIterator[RunScope]:
    """Bound all JEV calls in this context to one shared wall-clock ceiling."""
    if ceiling_seconds is None:
        from ...config import settings

        ceiling_seconds = float(getattr(settings, "jev_run_ceiling_seconds", 0.0) or 0.0)
    scope = RunScope(ceiling_seconds, budget)
    token = _SCOPE.set(scope)
    try:
        yield scope
    finally:
        _SCOPE.reset(token)


# One semaphore per (event loop, limit); weak keys so dead loops (tests) vanish.
_SEMAPHORES: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, dict[int, asyncio.Semaphore]
] = weakref.WeakKeyDictionary()


def semaphore(limit: int) -> asyncio.Semaphore:
    limit = max(1, int(limit))
    per_loop = _SEMAPHORES.setdefault(asyncio.get_running_loop(), {})
    sem = per_loop.get(limit)
    if sem is None:
        sem = per_loop[limit] = asyncio.Semaphore(limit)
    return sem
