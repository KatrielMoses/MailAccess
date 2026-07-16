from __future__ import annotations

from dataclasses import dataclass

import pytest

from backend.core.domain_harvest_orchestrator import DomainHarvestResult, HarvestedEmail
from backend.core.domain_harvest_report import format_harvest_cli_output, format_harvest_json_export
from backend.core.harvest_runner import _on_name_found_persona_pivot
from backend.modules.persona_email_pivot import PersonaEmailPivotModule


@dataclass
class Result:
    title: str
    snippet: str
    url: str = "https://example.test"
    provider: str = "test"


async def fake_search(self, query: str, *, max_results: int = 10):
    return [Result("Contact", "Alice Smith alice@acme.org alice.smith@gmail.com")]


@pytest.mark.asyncio
async def test_high_confidence_name_triggers_pivot() -> None:
    items = await _on_name_found_persona_pivot(
        "Alice Smith", "test", {"confidence_score": 0.8, "domain": "example.com"}
    )
    assert items and items[0].module_name == "persona_email_pivot"


@pytest.mark.asyncio
async def test_low_confidence_name_skipped() -> None:
    assert (
        await _on_name_found_persona_pivot("Alice Smith", "test", {"confidence_score": 0.49}) == []
    )


@pytest.mark.asyncio
async def test_org_email_tagged_org_email_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "backend.modules.persona_email_pivot.SearchProviderRouter.search", fake_search
    )
    result = await PersonaEmailPivotModule().run_with_payload(
        {"name": "Alice Smith", "domain": "acme.org"}
    )
    org = next(item for item in result.findings if item["metadata"]["email"] == "alice@acme.org")
    assert "org_email_candidate" in org["metadata"]["tags"]


@pytest.mark.asyncio
async def test_personal_email_tagged_personal_email_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "backend.modules.persona_email_pivot.SearchProviderRouter.search", fake_search
    )
    result = await PersonaEmailPivotModule().run_with_payload(
        {"name": "Alice Smith", "domain": "acme.org"}
    )
    personal = next(
        item for item in result.findings if item["metadata"]["email"].endswith("gmail.com")
    )
    assert "personal_email_candidate" in personal["metadata"]["tags"]


@pytest.mark.asyncio
async def test_max_10_names_respected() -> None:
    seen: set[str] = set()
    scheduled = []
    for index in range(12):
        scheduled += await _on_name_found_persona_pivot(
            f"Alice Smith{index}", "test", {"confidence_score": 0.8}, seen
        )
    assert len(scheduled) == 10


@pytest.mark.asyncio
async def test_max_3_queries_per_name(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def search(self, query: str, *, max_results: int = 10):
        calls.append(query)
        return []

    monkeypatch.setattr("backend.modules.persona_email_pivot.SearchProviderRouter.search", search)
    await PersonaEmailPivotModule().run_with_payload(
        {"name": "Alice Smith", "domain": "example.com"}
    )
    assert len(calls) == 3


def report_result() -> DomainHarvestResult:
    evidence = [
        {"metadata": {"source_type": "persona_pivot_personal", "source_name": "Alice Smith"}}
    ]
    email = HarvestedEmail(
        "alice@gmail.com", False, False, None, 0.35, "LOW", ["persona_email_pivot"], 1, evidence
    )
    return DomainHarvestResult("example.com", "", "", 0, {}, [email], 1, 0, 0, 0, 1, 0, 1)


def test_personal_emails_hidden_by_default() -> None:
    output = format_harvest_cli_output(report_result())
    assert "alice@gmail.com" not in output


def test_personal_emails_shown_with_flag() -> None:
    output = format_harvest_cli_output(report_result(), show_personal=True)
    assert "alice@gmail.com" in output


def test_personal_emails_always_in_json_export() -> None:
    payload = format_harvest_json_export(report_result())
    assert payload["personal_email_candidates"][0]["email"] == "alice@gmail.com"
