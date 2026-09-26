"""Registered JEV task specs. Importing this package registers every task.

JEV-1…6 each add one module here and one import line below — nothing else.
"""

from __future__ import annotations

from . import (  # noqa: F401
    demo,
    identity,
    narrative,
    reach,
    roster,
    signal,
    verify,
)
