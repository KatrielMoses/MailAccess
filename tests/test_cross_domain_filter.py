from __future__ import annotations

from types import SimpleNamespace

from backend.core.domain_harvest_orchestrator import HarvestedEmail, _aggregate
from backend.core.harvest_results import _collect_personal_emails
from backend.modules.base import ModuleResult, ModuleStatus


def _export_entry(email: str, *, on_domain: bool) -> HarvestedEmail:
    return HarvestedEmail(
        email=email,
        on_domain=on_domain,
        is_role=False,
        role_match_type=None,
        confidence_score=0.8,
        confidence_label="LIKELY",
        found_by_modules=["test"],
        source_count=1,
        evidence=[],
    )


def test_off_domain_email_never_in_emails_txt() -> None:
    result = SimpleNamespace(
        domain="stripe.com",
        unique_emails=[_export_entry("danielk@jhu.edu", on_domain=True)],
    )

    assert _collect_personal_emails(result) == []


def test_on_domain_check_uses_actual_email_not_flag() -> None:
    result = SimpleNamespace(
        domain="stripe.com",
        unique_emails=[
            _export_entry("danielk@jhu.edu", on_domain=True),
            _export_entry("alice@stripe.com", on_domain=False),
        ],
    )

    assert [entry.email for entry in _collect_personal_emails(result)] == [
        "alice@stripe.com"
    ]


def test_off_domain_email_in_shadow_profiles() -> None:
    module_results = {
        "persona_email_pivot": ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "platform": "search",
                    "username": "danielk",
                    "metadata": {
                        "email": "danielk@jhu.edu",
                        "on_domain": True,
                        "display_name": "Daniel K",
                    },
                }
            ],
        )
    }
    shadow_profiles: list[dict] = []

    emails = _aggregate(
        "stripe.com",
        module_results,
        shadow_profiles_out=shadow_profiles,
    )

    assert emails == []
    assert shadow_profiles[0]["email"] == "danielk@jhu.edu"
    assert shadow_profiles[0]["type"] == "personal_email_candidate"
