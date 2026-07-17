from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

import backend.core.domain_harvest_orchestrator as orchestrator
from backend.core.domain_harvest_orchestrator import (
    DomainHarvestResult,
    HarvestedEmail,
    _apply_low_email_validation_results,
    _run_low_email_validation,
    _select_low_email_validation_candidates,
    _select_verifier_for_provider,
)
from backend.core.mail_provider import MailProvider
from backend.core.domain_harvest_report import (
    format_harvest_cli_output,
    format_harvest_json_export,
)
from backend.modules.base import ModuleResult, ModuleStatus


def _finding(email: str, source_type: str = "permutation_unverified", **extra):
    metadata = {
        "email": email,
        "on_domain": True,
        "source_type": source_type,
        **extra,
    }
    return {"platform": "pattern_and_verify", "metadata": metadata}


def test_provider_routing_covers_every_provider() -> None:
    assert _select_verifier_for_provider(MailProvider.M365) == "m365"
    assert _select_verifier_for_provider(MailProvider.YAHOO) == "yahoo"
    for provider in (
        MailProvider.PROTON,
        MailProvider.ZOHO,
        MailProvider.FASTMAIL,
    ):
        assert _select_verifier_for_provider(provider) == "gravatar_only"
    assert _select_verifier_for_provider(MailProvider.SELF_HOSTED) == "smtp"
    assert _select_verifier_for_provider(MailProvider.UNKNOWN) == "smtp"


def test_candidate_selection_filters_prioritizes_and_caps() -> None:
    findings = [
        _finding("z@example.com", "common_crawl_single"),
        _finding("a@example.com"),
        _finding("role@example.com", is_role=True),
        _finding("disposable@example.com", disposable=True),
        _finding("off@other.test", on_domain=False),
    ]
    emails = [
        HarvestedEmail("z@example.com", True, False, None, 0.30, "LOW"),
        HarvestedEmail("a@example.com", True, False, None, 0.00, "LOW"),
        HarvestedEmail("role@example.com", True, True, "role", 0.00, "LOW"),
        HarvestedEmail("disposable@example.com", True, False, None, 0.00, "LOW"),
        HarvestedEmail("off@other.test", False, False, None, 0.00, "LOW"),
        HarvestedEmail("medium@example.com", True, False, None, 0.55, "MEDIUM"),
    ]
    result = ModuleResult(status=ModuleStatus.SUCCESS, findings=findings)
    selected = _select_low_email_validation_candidates(
        "example.com", {"pattern_and_verify": result}, emails, max_candidates=1
    )
    assert list(selected) == ["a@example.com"]


def test_verified_result_promotes_and_recomputes_confidence() -> None:
    finding = _finding("person@example.com")
    metadata = finding["metadata"]
    email = HarvestedEmail(
        "person@example.com",
        True,
        False,
        None,
        0.0,
        "LOW",
        source_count=1,
        evidence=[{"module": "pattern_and_verify", "metadata": metadata}],
        last_seen_timestamp="2026-07-14T00:00:00Z",
    )
    counts = _apply_low_email_validation_results(
        {"person@example.com": [finding]},
        {"method": "m365", "results": [{"email": "person@example.com", "status": "verified"}]},
        [email],
    )
    assert counts["promoted"] == 1
    assert metadata["source_type"] == "permutation_verified_m365"
    assert metadata["provider_verification_status"] == "verified"
    # P7: the legacy ``HIGH`` is now ``CONFIRMED`` in the
    # 4-tier label system.  The promotion path is unchanged —
    # we just check the new top-tier label.
    assert email.confidence_label in {"HIGH", "CONFIRMED"}


def test_not_found_stays_visible_and_low() -> None:
    finding = _finding("missing@example.com")
    counts = _apply_low_email_validation_results(
        {"missing@example.com": [finding]},
        {"method": "yahoo", "results": [{"email": "missing@example.com", "status": "not_found"}]},
    )
    assert counts == {"promoted": 0, "not_found": 1, "inconclusive": 0}
    assert finding["metadata"]["verification_status"] == "not_found"
    assert finding["metadata"]["source_type"] == "permutation_unverified"


@pytest.mark.asyncio
async def test_throttled_result_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    @dataclass
    class FakeResult:
        email: str
        status: str = "throttled"
        http_status: int = 429
        error: str | None = None
        throttle_status: int | None = 1

    class FakeM365:
        def __init__(self, **kwargs):
            pass

        async def verify_batch(self, emails):
            return [FakeResult(email=emails[0])]

    monkeypatch.setattr(orchestrator, "M365Verifier", FakeM365)
    candidates = {"person@example.com": [_finding("person@example.com")]}
    summary = await _run_low_email_validation("example.com", candidates, "m365")
    assert summary["throttled"] == 1
    counts = _apply_low_email_validation_results(candidates, summary)
    assert counts["promoted"] == 0
    assert counts["inconclusive"] == 1


@pytest.mark.asyncio
async def test_smtp_catchall_does_not_probe_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    @dataclass
    class FakeResult:
        email: str
        verification_status: str = "not_attempted"
        exists: bool | None = None
        response_code: int | None = None
        blocked_signal: bool = False
        mx_host: str | None = None
        transport_error: str | None = None

    class FakeBatch:
        probes_attempted = 1
        is_catchall = True
        stopped_early = False
        stop_reason = None
        error = None
        results = [FakeResult("person@example.com")]

    class FakeSMTP:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def verify_batch(self, domain, emails, max_probes):
            return FakeBatch()

    async def fake_resolve_mx(domain):
        return [SimpleNamespace(host="mx.example.com", priority=10)]

    monkeypatch.setattr(orchestrator, "SMTPVerifier", FakeSMTP)
    monkeypatch.setattr(orchestrator, "resolve_mx", fake_resolve_mx)
    candidates = {"person@example.com": [_finding("person@example.com")]}
    summary = await _run_low_email_validation("example.com", candidates, "smtp")
    assert summary["is_catchall"] is True
    assert summary["not_attempted"] == 1


def test_reporting_includes_validation_summary_in_cli_and_json() -> None:
    result = DomainHarvestResult(
        domain="example.com",
        started_at="2026-07-14T00:00:00Z",
        completed_at="2026-07-14T00:00:01Z",
        duration_seconds=1.0,
        module_results={},
        unique_emails=[],
        total_unique_emails=0,
        high_confidence_count=0,
        likely_confidence_count=0,
        medium_confidence_count=0,
        low_confidence_count=0,
        role_account_count=0,
        personal_email_count=0,
        metadata={
            "low_email_validation": {
                "method": "m365",
                "provider": "m365",
                "checked": 3,
                "promotion": {"promoted": 1, "not_found": 1, "inconclusive": 1},
            }
        },
    )
    cli = format_harvest_cli_output(result)
    assert "validated 3 LOW emails" in cli
    exported = format_harvest_json_export(result)
    assert exported["summary"]["low_email_validation"]["promotion"]["promoted"] == 1
