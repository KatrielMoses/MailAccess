import asyncio

from backend.core.harvest_runner import run_adaptive_harvest


def test_skip_modules_are_recorded_without_execution():
    async def run():
        result = await run_adaptive_harvest(
            "acme.org",
            timeout_seconds=1,
            skip_modules=("public_forge", "package_ecosystems"),
        )
        return result

    result = asyncio.run(run())
    assert result.module_results["public_forge"].metadata["skip_reason"] == "not_started"
    assert result.module_results["package_ecosystems"].metadata["skip_reason"] == "not_started"
