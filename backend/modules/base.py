from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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

    @abstractmethod
    async def run(self, email: str) -> ModuleResult:
        """Run the module against *email* and return a ModuleResult."""
        ...
