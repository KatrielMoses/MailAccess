from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
import inspect
import logging
from functools import wraps
from typing import Any

logger = logging.getLogger(__name__)


class ModuleStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ModuleResult:
    status: ModuleStatus
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class BaseModule(ABC):
    """
    Contract every OSINT module must satisfy.

    Class attributes (set at class level, not in __init__):
        name         – unique slug used in API responses and DB records
        description  – one-line human-readable purpose
        requires_key – True if the module will skip without an API key
    """

    name: str
    description: str
    requires_key: bool = False
    priority: int = 100

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

        run = cls.__dict__.get("run")
        if run is None or not inspect.iscoroutinefunction(run):
            return
        if getattr(run, "__mailaccess_wrapped__", False):
            return

        @wraps(run)
        async def _wrapped_run(self, *args: Any, **kwargs: Any) -> ModuleResult:
            result = await run(self, *args, **kwargs)
            if result is None:
                module_name = getattr(self, "name", cls.__name__)
                logger.warning(
                    "Module %s returned None instead of ModuleResult — raising",
                    module_name,
                )
                raise AssertionError(
                    "Module returned None — this is a bug in the module"
                )
            if not isinstance(result, ModuleResult):
                module_name = getattr(self, "name", cls.__name__)
                logger.warning(
                    "Module %s returned %s instead of ModuleResult — raising",
                    module_name,
                    type(result).__name__,
                )
                raise AssertionError(
                    f"Module returned {type(result).__name__} instead of ModuleResult"
                )
            return result

        _wrapped_run.__mailaccess_wrapped__ = True  # type: ignore[attr-defined]
        setattr(cls, "run", _wrapped_run)

    @abstractmethod
    async def run(self, email: str) -> ModuleResult:
        """Run the module against *email* and return a ModuleResult."""
        ...
