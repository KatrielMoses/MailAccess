from types import SimpleNamespace

from backend.core.harvest_runner import _should_defer_for_yield
from backend.modules.base import ModuleResult, ModuleStatus


class Budget:
    def remaining(self):
        return 5.0


def test_yield_prediction_defers_only_after_empty_sources():
    ctx = SimpleNamespace(
        settings=SimpleNamespace(enable_yield_prediction=True, yield_prediction_tail_seconds=15),
        budget=Budget(),
        module_results={
            "commoncrawl_email": ModuleResult(status=ModuleStatus.SUCCESS),
            "wayback_domain_harvest": ModuleResult(status=ModuleStatus.SUCCESS),
        },
    )
    assert _should_defer_for_yield(ctx, "npm_email") is True
    assert _should_defer_for_yield(ctx, "public_forge") is False


def test_yield_prediction_does_not_defer_when_source_has_findings():
    ctx = SimpleNamespace(
        settings=SimpleNamespace(enable_yield_prediction=True, yield_prediction_tail_seconds=15),
        budget=Budget(),
        module_results={
            "commoncrawl_email": ModuleResult(status=ModuleStatus.SUCCESS, findings=[{"metadata": {"email": "a@acme.org"}}]),
            "wayback_domain_harvest": ModuleResult(status=ModuleStatus.SUCCESS),
        },
    )
    assert _should_defer_for_yield(ctx, "npm_email") is False
