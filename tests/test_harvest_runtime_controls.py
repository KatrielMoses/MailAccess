import asyncio

import pytest

from backend.core.domain_harvest_orchestrator import (
    _run_with_soft_timeout,
    _safe_phase12_run,
)
from backend.core.harvest_runner import run_adaptive_harvest
from backend.modules.base import ModuleResult, ModuleStatus


def test_skip_modules_are_recorded_without_execution():
    async def run():
        result = await run_adaptive_harvest(
            "acme.org",
            timeout_seconds=1,
            skip_modules=("public_forge", "package_ecosystems"),
        )
        return result

    result = asyncio.run(run())
    assert result.module_results["public_forge"].metadata["skip_reason"] == "runtime_policy"
    assert result.module_results["package_ecosystems"].metadata["skip_reason"] == "runtime_policy"


def test_soft_timeout_cancels_source_task_and_returns_partial():
    cancelled = asyncio.Event()

    async def slow_source():
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.set()

    async def run():
        return await _run_with_soft_timeout(
            "slow_source",
            slow_source(),
            None,
            soft_timeout=0.01,
        )

    result = asyncio.run(run())
    assert result.status == ModuleStatus.PARTIAL
    assert cancelled.is_set()


def test_safe_module_runner_accepts_and_forwards_progress_callback():
    actions = []

    class ProgressModule:
        async def run(self, domain, *, progress_callback=None):
            progress_callback("querying source")
            return ModuleResult(status=ModuleStatus.SUCCESS)

    async def run():
        return await _safe_phase12_run(
            "progress_module",
            ProgressModule(),
            "example.com",
            progress_callback=actions.append,
        )

    _, result = asyncio.run(run())
    assert result.status == ModuleStatus.SUCCESS
    assert actions == ["querying source"]


@pytest.mark.asyncio
async def test_discovery_timeout_returns_exportable_partial_result(monkeypatch):
    async def timed_out_tracks(ctx):
        ctx.module_results["commoncrawl_email"] = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "metadata": {
                        "email": "found@example.com",
                        "confidence_score": 0.9,
                        "source_type": "commoncrawl_email",
                    }
                }
            ],
        )
        await asyncio.sleep(2)

    monkeypatch.setattr("backend.core.harvest_runner._run_tracks", timed_out_tracks)
    result = await run_adaptive_harvest("example.com", timeout_seconds=0.01)

    assert result.metadata["harvest_status"] == "partial_timeout"
    assert result.metadata["timed_out"] is True
    assert result.metadata["timeout_at_seconds"] == 0.01
    assert any(email.email == "found@example.com" for email in result.unique_emails)
