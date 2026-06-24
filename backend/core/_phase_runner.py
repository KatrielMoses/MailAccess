from __future__ import annotations

import asyncio
import inspect
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from ..modules.base import BaseModule, ModuleResult, ModuleStatus
from .policy import _MODULE_TIMEOUT_FLOORS

_ERROR_LIMIT = 200


def resolve_timeout(
    module_name: str,
    default_timeout: int,
    overrides: dict[str, int],
) -> int:
    chosen = max(default_timeout, _MODULE_TIMEOUT_FLOORS.get(module_name, 0))
    if module_name in overrides:
        return max(chosen, overrides[module_name])
    return chosen


async def run_one_module(
    mod: BaseModule,
    email: str,
    *,
    default_timeout: int,
    overrides: dict[str, int],
    explicit_module: bool,
    queue: asyncio.Queue | None = None,
    canonical_email: str | None = None,
    collected: dict[str, ModuleResult] | None = None,
) -> ModuleResult:
    timeout = resolve_timeout(mod.name, default_timeout, overrides)
    if queue is not None:
        from .engine import QueueEvent

        await queue.put(QueueEvent(type="module_start", module_name=mod.name))

    try:
        if collected is not None and canonical_email is not None:
            coroutine = mod.run(canonical_email, collected)
        else:
            target_email = canonical_email or email
            parameters = inspect.signature(mod.run).parameters
            accepts_keyword_args = any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD
                for parameter in parameters.values()
            )
            if "force" in parameters or accepts_keyword_args:
                coroutine = mod.run(target_email, force=explicit_module)
            elif "original_email" in parameters and target_email != email:
                coroutine = mod.run(target_email, original_email=email)
            else:
                coroutine = mod.run(target_email)
        return await asyncio.wait_for(coroutine, timeout=timeout)
    except asyncio.TimeoutError:
        return ModuleResult(
            status=ModuleStatus.PARTIAL,
            errors=[f"Module timed out after {timeout}s"],
        )
    except Exception as exc:
        return ModuleResult(
            status=ModuleStatus.FAILED,
            errors=[str(exc)[:_ERROR_LIMIT]],
        )


@contextmanager
def settings_override(settings: Any, **overrides: Any) -> Iterator[None]:
    saved = {name: getattr(settings, name, None) for name in overrides}
    try:
        for name, value in overrides.items():
            setattr(settings, name, value)
        yield
    finally:
        for name, value in saved.items():
            setattr(settings, name, value)
