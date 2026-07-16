from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from backend.core import harvest_runner
from backend.core.harvest_runner import (
    MODULE_PERSONA_EMAIL_PIVOT,
    _execute_item,
    _run_module,
    _track2_loop,
)
from backend.core.work_scheduler import (
    TRACK_OPPORTUNISTIC,
    WorkItem,
    WorkResult,
    WorkScheduler,
)
from backend.modules.base import ModuleStatus


class _OpenBudget:
    def __init__(self) -> None:
        self.person_pivot_flags: list[bool] = []

    def is_expired(self) -> bool:
        return False

    def can_start_track2(self, *, person_pivot: bool = False) -> bool:
        self.person_pivot_flags.append(person_pivot)
        return True

    def soft_timeout_for_module(self, fraction: float = 0.1) -> float:
        return 30.0


async def _successful_work(item: WorkItem, _ctx: object) -> WorkResult:
    return WorkResult(item=item, success=True)


@pytest.mark.asyncio
async def test_track2_exits_when_queue_empty_without_persona_pivot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduler = WorkScheduler()
    for index in range(2):
        await scheduler.submit(
            WorkItem(
                kind="run_module",
                module_name=f"opportunistic_{index}",
                track=TRACK_OPPORTUNISTIC,
            )
        )
    monkeypatch.setattr(harvest_runner, "_execute_item", _successful_work)
    ctx = SimpleNamespace(
        scheduler=scheduler,
        budget=_OpenBudget(),
        signal_pool=SimpleNamespace(),
    )

    await asyncio.wait_for(_track2_loop(ctx, concurrency=2), timeout=1.0)

    assert scheduler.is_empty()


@pytest.mark.asyncio
async def test_persona_pivot_does_not_hold_track2_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduler = WorkScheduler()
    await scheduler.submit(
        WorkItem(
            kind="run_module",
            module_name=MODULE_PERSONA_EMAIL_PIVOT,
            track=TRACK_OPPORTUNISTIC,
            source="name_subscriber:persona_pivot",
        )
    )
    budget = _OpenBudget()
    monkeypatch.setattr(harvest_runner, "_execute_item", _successful_work)
    ctx = SimpleNamespace(
        scheduler=scheduler,
        budget=budget,
        signal_pool=SimpleNamespace(),
    )

    await asyncio.wait_for(_track2_loop(ctx), timeout=1.0)

    assert scheduler.is_empty()
    assert budget.person_pivot_flags == [False]


@pytest.mark.asyncio
async def test_cancelled_error_records_partial_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()

    async def slow_module(*_args: object, **_kwargs: object):
        started.set()
        await asyncio.sleep(30)

    monkeypatch.setattr(harvest_runner, "_run_module_instance", slow_module)
    results = {}
    ctx = SimpleNamespace(
        module_overrides={"slow": object()},
        module_results=results,
        progress_callback=None,
        on_module_complete=None,
        signal_pool=SimpleNamespace(),
        domain="example.com",
    )
    task = asyncio.create_task(_run_module("slow", ctx, 30.0))
    await started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert results["slow"].status is ModuleStatus.PARTIAL
    assert results["slow"].errors == ["Cancelled by budget timeout"]


@pytest.mark.asyncio
async def test_skip_branches_record_module_result() -> None:
    results = {}
    ctx = SimpleNamespace(
        budget=_OpenBudget(),
        skip_modules=frozenset({"skipped_source"}),
        subdomain_calibrate=False,
        module_results=results,
        on_module_complete=None,
        domain="example.com",
    )
    item = WorkItem(kind="run_module", module_name="skipped_source")

    await _execute_item(item, ctx)

    assert results["skipped_source"].status is ModuleStatus.SKIPPED
    assert results["skipped_source"].metadata["skip_reason"] == "runtime_policy"
