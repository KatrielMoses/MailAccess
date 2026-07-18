"""Time-aware execution budget for domain harvest orchestration."""

from __future__ import annotations

import asyncio
import time


class TimeBudget:
    def __init__(
        self,
        total_seconds: float,
        track1_soft_fraction: float = 0.50,
        track1_hard_fraction: float = 0.75,
        *,
        soft_fraction: float | None = None,
        hard_fraction: float | None = None,
    ) -> None:
        if soft_fraction is not None:
            track1_soft_fraction = soft_fraction
        if hard_fraction is not None:
            track1_hard_fraction = hard_fraction
        self._total = float(total_seconds)
        self._soft = self._total * track1_soft_fraction
        self._hard = self._total * track1_hard_fraction
        # Keep a small tail of the run available for person-keyed pivots.
        # The reserve scales down for short test/profile budgets and is never
        # allowed to exceed 20% of the total budget.
        self._person_pivot_reserve = max(0.0, min(self._total * 0.20, 60.0))
        self._start = time.monotonic()
        # asyncio.Event() must be created inside an event-loop context, so
        # we defer construction to a lazy property.  This lets
        # ``TimeBudget(...)`` itself be built outside an async context
        # (e.g. inside a sync test) without raising ``RuntimeError``.
        self._exhausted: asyncio.Event | None = None
        self._track1_closed: asyncio.Event | None = None

    @property
    def exhausted_event(self) -> asyncio.Event:
        """Return the ``_exhausted`` event, creating it on first access.

        ``asyncio.Event()`` is bound to the current event loop, so it
        can only be created inside an async context.  This lazy
        property lets the surrounding ``TimeBudget`` be constructed
        synchronously while still surfacing an awaitable ``Event`` to
        async callers via :meth:`wait_until_exhausted` /
        :meth:`mark_exhausted`.
        """
        if self._exhausted is None:
            self._exhausted = asyncio.Event()
        return self._exhausted

    @property
    def track1_closed_event(self) -> asyncio.Event:
        """Return the ``_track1_closed`` event, creating it on first access."""
        if self._track1_closed is None:
            self._track1_closed = asyncio.Event()
        return self._track1_closed

    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def remaining(self) -> float:
        return max(0.0, self._total - self.elapsed())

    def is_expired(self) -> bool:
        return self.elapsed() >= self._total

    def track1_status(self) -> str:
        elapsed = self.elapsed()
        if elapsed >= self._hard:
            return "over_hard_cap"
        if elapsed >= self._soft:
            return "over_soft_cap"
        return "within_budget"

    def can_start_track1(self) -> bool:
        return self.elapsed() < self._hard

    def can_start_track2(self, *, person_pivot: bool = False) -> bool:
        if self.elapsed() >= self._total:
            return False
        if person_pivot:
            return True
        return self.remaining() > self._person_pivot_reserve

    def soft_timeout_for_module(self, fraction: float = 0.10) -> float:
        return max(5.0, self.remaining() * fraction)

    def mark_exhausted(self) -> None:
        self.exhausted_event.set()

    def mark_track1_closed(self) -> None:
        self.track1_closed_event.set()

    @property
    def track1_closed(self) -> bool:
        """Whether all guaranteed work reached its scheduler boundary."""
        return bool(self._track1_closed is not None and self._track1_closed.is_set())

    async def wait_until_exhausted(self) -> None:
        await self.exhausted_event.wait()

    async def wait_until_track1_closed(self) -> None:
        await self.track1_closed_event.wait()

    @property
    def stats(self) -> dict[str, float | str | bool]:
        return {
            "total_seconds": self._total,
            "elapsed_seconds": round(self.elapsed(), 2),
            "remaining_seconds": round(self.remaining(), 2),
            "track1_status": self.track1_status(),
            "track1_closed": self.track1_closed,
            "is_expired": self.is_expired(),
        }


def budget_for_profile(profile_name: str) -> float:
    budgets = {
        "t0": 2700.0,
        "t1": 1200.0,
        "t2": 600.0,
        "t3": 300.0,
        "t4": 120.0,
        "t5": 60.0,
    }
    return budgets.get(str(profile_name or "").lower(), 600.0)
