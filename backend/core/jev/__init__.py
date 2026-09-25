"""Phase JEV — the reasoning seam.

A single reusable entry point any module or core function can call for a bounded,
structured verdict from a hosted OpenAI-compatible model::

    from backend.core import jev

    verdict = await jev.judge("some.task", payload)
    if verdict is jev.DEFER:
        ...  # run today's deterministic logic, unchanged
    else:
        ...  # use verdict.output (schema-validated); mark verdict.provenance

Guarantees enforced here, not by callers:

1. JEV never owns a number — output schemas reject floats at registration, and
   no score is ever computed from a verdict by the seam.
2. Every call has a deterministic fallback — any failure resolves to DEFER.
3. Output is schema-bounded — strict validation against the task's pydantic model.
4. Active only when ``JEV_API_KEY`` is set — with no key the seam does no I/O at
   all; a circuit breaker stops retrying a key that is out of credits.

Adding a task = one new module in ``tasks/`` that calls :func:`register`.
"""

from __future__ import annotations

from . import breaker, metrics, tasks  # noqa: F401  (importing tasks registers them)
from .contract import (
    DEFER,
    DeferReason,
    DeferType,
    JevTask,
    Provenance,
    TaskSpecError,
    Verdict,
    get_task,
    register,
    registered_tasks,
)
from .limits import run_scope
from .seam import judge

__all__ = [
    "DEFER",
    "DeferReason",
    "DeferType",
    "JevTask",
    "Provenance",
    "TaskSpecError",
    "Verdict",
    "breaker",
    "get_task",
    "judge",
    "metrics",
    "register",
    "registered_tasks",
    "run_scope",
]
