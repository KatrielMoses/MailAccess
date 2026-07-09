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
from typing import Type

from .base import BaseModule, ModuleResult, ModuleStatus

_SKIP = frozenset({"base"})
_registry: dict[str, type[BaseModule]] = {}


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


_discover()


def get_all_modules() -> list[type[BaseModule]]:
    """Return all registered module classes."""
    return list(_registry.values())


def get_module(name: str) -> type[BaseModule] | None:
    """Return the module class registered under *name*, or None."""
    return _registry.get(name)


__all__ = [
    "BaseModule",
    "ModuleResult",
    "ModuleStatus",
    "get_all_modules",
    "get_module",
]
