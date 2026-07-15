from backend.core.domain_harvest_orchestrator import DomainHarvestResult
from backend.core.domain_harvest_report import format_harvest_json_export
from backend.modules.base import ModuleResult, ModuleStatus


def test_export_contains_module_timing_and_skip_telemetry():
    result = DomainHarvestResult(
        domain="acme.org", started_at="x", completed_at="y", duration_seconds=1,
        module_results={
            "fast": ModuleResult(status=ModuleStatus.SUCCESS, metadata={"duration_seconds": 1.25}),
            "slow": ModuleResult(status=ModuleStatus.SKIPPED, metadata={"skip_reason": "yield_prediction"}),
        }, unique_emails=[], total_unique_emails=0, high_confidence_count=0,
        likely_confidence_count=0,
        medium_confidence_count=0, low_confidence_count=0, role_account_count=0,
        personal_email_count=0, errors=[],
    )
    summary = format_harvest_json_export(result)["summary"]
    assert summary["module_timings"] == {"fast": 1.25}
    assert summary["module_skip_reasons"] == {"slow": "yield_prediction"}
