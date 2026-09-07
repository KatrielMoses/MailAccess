"""Wall-clock completion budget for investigate mode (Phase 1B).

The investigation engine runs its phases/modules under a single wall-clock
budget. Each module's effective timeout is capped to the budget's remaining
time, and once the budget is (nearly) exhausted the remaining modules are
skipped rather than run. Both cases are recorded as *budget-truncated* so the
run degrades honestly to partial results instead of hanging or failing.

This is the investigate-side analogue of the harvest ``TimeBudget`` in
:mod:`backend.core.time_budget`; it is deliberately simpler (a single deadline,
no soft/hard tracks) because an investigation is one linear phase DAG rather
than harvest's two concurrent tracks.

A non-positive ``total_seconds`` means *unlimited* — the budget never bites,
which is the escape hatch for ``--budget 0``.
"""
from __future__ import annotations

import time


class InvestigationBudget:
    def __init__(
        self,
        total_seconds: float,
        *,
        min_module_seconds: float = 2.0,
    ) -> None:
        self._total = float(total_seconds)
        self._min_module = max(0.0, float(min_module_seconds))
        self._start = time.monotonic()
        # Insertion-ordered set of modules truncated by the budget (skipped or
        # cut short), preserved for the run's truncation record.
        self._truncated: dict[str, None] = {}

    @property
    def unlimited(self) -> bool:
        return self._total <= 0

    @property
    def total_seconds(self) -> float:
        return self._total

    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def remaining(self) -> float:
        if self.unlimited:
            return float("inf")
        return max(0.0, self._total - self.elapsed())

    def expired(self) -> bool:
        return not self.unlimited and self.remaining() <= 0

    def can_start_module(self) -> bool:
        """Whether there is enough budget left for a module to be worth starting."""
        if self.unlimited:
            return True
        return self.remaining() > self._min_module

    def cap(self, timeout: float) -> float:
        """Clamp a module's timeout to the time left in the budget."""
        if self.unlimited:
            return float(timeout)
        return max(0.0, min(float(timeout), self.remaining()))

    def note_truncated(self, module_name: str) -> None:
        self._truncated[module_name] = None

    @property
    def truncated_modules(self) -> list[str]:
        return list(self._truncated)

    @property
    def stats(self) -> dict[str, float | bool | list[str]]:
        return {
            "total_seconds": self._total,
            "elapsed_seconds": round(self.elapsed(), 2),
            "unlimited": self.unlimited,
            "expired": self.expired(),
            "truncated_modules": self.truncated_modules,
        }
