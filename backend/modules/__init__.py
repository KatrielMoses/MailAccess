"""
Auto-discovers and registers every BaseModule subclass found in this package.

Any .py file dropped into backend/modules/ that defines a class inheriting
BaseModule (with a `name` attribute) is automatically registered at import time.
No manual wiring required.
"""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from .base import BaseModule, ModuleResult, ModuleStatus

_SKIP = frozenset({"base"})
_registry: dict[str, type[BaseModule]] = {}
_discovered = False


def _discover() -> None:
    package_dir = Path(__file__).parent
    for _finder, module_name, _ispkg in pkgutil.iter_modules([str(package_dir)]):
        if module_name in _SKIP:
            continue
        mod = importlib.import_module(f".{module_name}", package=__name__)
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseModule)
                and obj is not BaseModule
                and hasattr(obj, "name")
            ):
                _registry[obj.name] = obj


def _ensure_discovered() -> None:
    # T4 (Output-Trust final): discovery imports EVERY module in this package (and
    # each module's transitive deps — httpx, dns, corpus loaders, exporters), ~1s+ of
    # work. Running it at package import made ``import backend.modules[.base]`` — and
    # therefore the whole server boot — pay that cost up front, so a cold ``serve``
    # raced the CLI's /health wait window and a first ``investigate`` exited 3
    # ("server unavailable"). Defer it to first registry access: the server now binds
    # and answers /health fast, and the (unchanged) discovery cost lands on the first
    # request that actually needs the module list.
    global _discovered
    if not _discovered:
        _discover()
        _discovered = True


def get_all_modules() -> list[type[BaseModule]]:
    """Return all registered module classes."""
    _ensure_discovered()
    return list(_registry.values())


def get_module(name: str) -> type[BaseModule] | None:
    """Return the module class registered under *name*, or None."""
    _ensure_discovered()
    return _registry.get(name)


def loaded_module_names() -> list[str]:
    """Names of modules discovered SO FAR, without forcing discovery.

    T4 — used by the readiness probe (/health) so it answers immediately on a cold
    server (before the first request that needs the module list) instead of blocking on
    the ~3s discovery sweep and racing the CLI's health-poll timeout. Returns an empty
    list until the first real registry access triggers discovery.
    """
    return sorted(_registry)


__all__ = [
    "BaseModule",
    "ModuleResult",
    "ModuleStatus",
    "get_all_modules",
    "get_module",
]
