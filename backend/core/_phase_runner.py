from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from ..modules.base import BaseModule, ModuleResult, ModuleStatus
from .investigation_budget import InvestigationBudget
from .policy import _MODULE_TIMEOUT_FLOORS

_ERROR_LIMIT = 200
logger = logging.getLogger(__name__)


def _normalize_module_result(module_name: str, result: ModuleResult | None) -> ModuleResult:
    if result is not None:
        return result
    logger.warning(
        "Module %s returned None instead of ModuleResult — skipping",
        module_name,
    )
    return ModuleResult(
        status=ModuleStatus.FAILED,
        errors=["Module returned None — this is a bug in the module"],
    )


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
    budget: InvestigationBudget | None = None,
    mode: str = "security-investigation",
) -> ModuleResult:
    # Phase 2C — the lawful-public-data gate, enforced at the single universal
    # module-execution point and ABOVE the force/explicit bypass: a mode-policy
    # denial is not something --force or an opt-in flag may override. In
    # security-investigation every module is allowed, so this is a no-op there
    # (zero regression). Fail closed: an unclassified module is denied in the two
    # non-security modes.
    from .product_mode import is_module_allowed, set_active_mode

    # Mark this module task's active mode for defense-in-depth guards deeper in
    # the call graph (e.g. reset_prober). Task-local; does not leak to siblings.
    set_active_mode(mode)

    if not is_module_allowed(mod.name, mode):
        if queue is not None:
            from .engine import QueueEvent

            await queue.put(QueueEvent(type="module_start", module_name=mod.name))
        return ModuleResult(
            status=ModuleStatus.SKIPPED,
            metadata={"skip_reason": "policy_mode", "mode": mode},
            errors=[f"Skipped: module '{mod.name}' not permitted in mode '{mode}'"],
        )

    timeout = resolve_timeout(mod.name, default_timeout, overrides)

    # Phase 1B — investigation time budget. If the run is out of budget, skip
    # the module rather than start it; if there is budget left but less than the
    # module's own timeout, cap the timeout to the remaining budget. Either way,
    # record the truncation so the partial result is reported honestly.
    if budget is not None and not budget.can_start_module():
        budget.note_truncated(mod.name)
        logger.info(
            "Module %s skipped: investigation time budget exhausted", mod.name
        )
        return ModuleResult(
            status=ModuleStatus.SKIPPED,
            metadata={"budget_truncated": True},
            errors=["Skipped: investigation time budget exhausted"],
        )

    budget_capped = False
    if budget is not None:
        effective_timeout = budget.cap(timeout)
        budget_capped = effective_timeout < timeout
    else:
        effective_timeout = float(timeout)

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
        result = await asyncio.wait_for(coroutine, timeout=effective_timeout)
        return _normalize_module_result(mod.name, result)
    except asyncio.TimeoutError:
        if budget_capped and budget is not None:
            budget.note_truncated(mod.name)
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                metadata={"budget_truncated": True},
                errors=[
                    f"Truncated by investigation time budget after "
                    f"{effective_timeout:.0f}s (module timeout {timeout}s)"
                ],
            )
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
