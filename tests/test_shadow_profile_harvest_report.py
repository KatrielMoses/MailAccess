from backend.core.domain_harvest_orchestrator import DomainHarvestResult
from backend.core.domain_harvest_report import format_harvest_json_export
from backend.modules.base import ModuleResult, ModuleStatus


def test_harvest_export_surfaces_shadow_profiles():
    result = DomainHarvestResult(
        domain="acme.org",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:01Z",
        duration_seconds=1.0,
        module_results={
            "source_a": ModuleResult(status=ModuleStatus.SUCCESS, findings=[
                {"platform": "github", "metadata": {"email": "alice@acme.org", "display_name": "Alice Example", "username": "alice"}},
            ]),
            "source_b": ModuleResult(status=ModuleStatus.SUCCESS, findings=[
                {"platform": "keybase", "metadata": {"email": "alice@personal.example", "display_name": "Alice Example", "username": "alice"}},
            ]),
        },
        unique_emails=[],
        total_unique_emails=0,
        high_confidence_count=0,
        likely_confidence_count=0,
        medium_confidence_count=0,
        low_confidence_count=0,
        role_account_count=0,
        personal_email_count=0,
        errors=[],
    )
    export = format_harvest_json_export(result)
    assert export["summary"]["shadow_profile_count"] == 1
    assert export["shadow_profiles"][0]["display_name"] == "Alice Example"
