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

# JEV-0.4 — register the per-item Ollaya decomposers for the two decomposable
# list tasks (name_reconcile, platform_select). Import-time, after registration.
identity.register_ollaya_decomposers()
reach.register_ollaya_decomposers()
