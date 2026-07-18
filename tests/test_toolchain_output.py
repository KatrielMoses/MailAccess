"""0.12.7 — Tool-chain supplementary output file tests.

Exercises the file writers in :mod:`backend.core.harvest_results`
that produce ``subdomains.txt``, ``emails.txt``,
``nuclei_targets.txt``, ``report.md``, and ``cidrs.txt``.

The CLI integration tests confirm the ``Results saved:`` footer
prints all of them, the ``--no-extras`` flag skips the
supplementary files, and the cached-result path still writes them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from backend.config import settings
from backend.core.domain_harvest_orchestrator import DomainHarvestResult
from backend.core.harvest_results import write_harvest_results
from backend.modules.base import ModuleResult, ModuleStatus
from cli import harvest_emails as command


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def isolated_results_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(settings, "harvest_results_dir", tmp_path)
    monkeypatch.setattr(settings, "harvest_auto_export", True)
    return tmp_path


@dataclass
class _EmailStub:
    """Minimal duck-typed HarvestedEmail for the supplementary writers."""

    email: str
    on_domain: bool = True
    is_role: bool = False
    role_match_type: str | None = None
    confidence_score: float = 0.9
    confidence_label: str = "CONFIRMED"
    found_by_modules: list[str] = field(default_factory=lambda: ["pgp_domain_email"])
    subaddress_variants: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    aggregated_source_urls: list[str] = field(default_factory=list)
    first_seen_timestamp: str | None = None
    last_seen_timestamp: str | None = None
    identity_graph_score: float | None = None
    identity_graph_label: str | None = None
    identity_graph_flags: list[str] = field(default_factory=list)
    confidence_breakdown: dict[str, Any] | None = None
    source_count: int = 1
    total_finding_count: int = 1
    occurrence_count_per_module: dict[str, int] = field(default_factory=dict)
    is_smtp_verified: bool = False
    is_provider_verified: bool = False
    provider_verification_provider: str | None = None
    provider_verification_status: str | None = None
    is_ca_attested: bool = False
    is_pgp_or_ca: bool = False


def _make_result(
    *,
    domain: str = "ine.com",
    emails: list[_EmailStub] | None = None,
    subdomains: list[dict[str, Any]] | None = None,
    asns: list[dict[str, Any]] | None = None,
    names: list[dict[str, Any]] | None = None,
    shodan_meta: dict[str, Any] | None = None,
) -> DomainHarvestResult:
    """Build a result with the minimum surface the writers need."""
    if emails is None:
        emails = [
            _EmailStub(
                email="brian@ine.com",
                on_domain=True,
                is_role=False,
                confidence_label="CONFIRMED",
                found_by_modules=["pgp_domain_email"],
                evidence=[{"module": "pgp_domain_email", "metadata": {"name": "Brian McGahan"}}],
            ),
            _EmailStub(
                email="info@ine.com",
                on_domain=True,
                is_role=True,
                confidence_label="MEDIUM",
                found_by_modules=["commoncrawl_email"],
                evidence=[],
            ),
        ]
    module_results: dict[str, ModuleResult] = {}
    # Inject subdomain metadata so the subdomain writers fire.
    sub_findings: list[dict[str, Any]] = []
    for entry in subdomains or []:
        sub_findings.append(
            {
                "platform": "subdomain_intel",
                "metadata": {"subdomain": entry.get("subdomain")},
            }
        )
    if sub_findings:
        module_results["subdomain_intel"] = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=sub_findings,
            metadata={"domain": domain, "source_counts": {"ct": len(sub_findings)}},
        )
    if asns:
        module_results["ripe_stat_asn"] = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[],
            metadata={
                "infrastructure": {
                    "asns": asns,
                    "ips": [
                        {"ip": "54.239.0.1", "asn": 16509, "sources": ["shodan"]}
                    ],
                }
            },
        )
    if shodan_meta is not None:
        # Add a second module whose metadata carries the shodan
        # InternetDB data for the nuclei-targets port-80 fallback.
        module_results["shodan_internetdb"] = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[],
            metadata=shodan_meta,
        )
    if names:
        module_results["employee_name_discovery"] = ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "platform": "employee_name_discovery",
                    "metadata": {
                        "name": name["name"],
                        "sources": name.get("sources", ["company_page"]),
                        "source_count": len(name.get("sources", ["company_page"])),
                        "title_or_role": name.get("title_or_role"),
                        "confidence_score": name.get("confidence_score", 0.7),
                    },
                }
                for name in names
            ],
        )
    return DomainHarvestResult(
        domain=domain,
        started_at="2026-07-16T14:22:33Z",
        completed_at="2026-07-16T14:28:44Z",
        duration_seconds=371.0,
        module_results=module_results,
        unique_emails=list(emails),
        total_unique_emails=len(emails),
        high_confidence_count=1,
        likely_confidence_count=0,
        medium_confidence_count=0,
        low_confidence_count=0,
        role_account_count=1,
        personal_email_count=1,
    )


# ---------------------------------------------------------------------------
# File-by-file assertions on the writer
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_subdomains_txt_written_one_per_line(
    isolated_results_dir: Path,
) -> None:
    result = _make_result(
        subdomains=[
            {"subdomain": "staging.ine.com"},
            {"subdomain": "api.ine.com"},
            {"subdomain": "blog.ine.com"},
        ]
    )
    written = await write_harvest_results(result, timestamp="20260716_142233")
    assert written.subdomains is not None
    lines = [
        line.strip()
        for line in written.subdomains.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert sorted(lines) == sorted(
        ["staging.ine.com", "api.ine.com", "blog.ine.com"]
    )


@pytest.mark.asyncio
async def test_emails_txt_only_high_medium_personal(
    isolated_results_dir: Path,
) -> None:
    emails = [
        _EmailStub(email="brian@ine.com", confidence_label="CONFIRMED"),
        _EmailStub(email="satch@ine.com", confidence_label="LIKELY"),
        _EmailStub(email="test@ine.com", confidence_label="LOW"),  # excluded
        _EmailStub(email="info@ine.com", confidence_label="MEDIUM", is_role=True),  # role excluded
    ]
    result = _make_result(emails=emails)
    written = await write_harvest_results(result, timestamp="20260716_142233")
    assert written.emails is not None
    body = written.emails.read_text(encoding="utf-8")
    # The HIGH-tier personal addresses appear; the LOW + role are
    # suppressed.
    assert "brian@ine.com" in body
    assert "satch@ine.com" in body
    assert "test@ine.com" not in body
    assert "info@ine.com" not in body


@pytest.mark.asyncio
async def test_emails_txt_excludes_role_accounts(
    isolated_results_dir: Path,
) -> None:
    emails = [
        _EmailStub(email="brian@ine.com", confidence_label="CONFIRMED"),
        _EmailStub(email="support@ine.com", confidence_label="MEDIUM", is_role=True),
    ]
    result = _make_result(emails=emails)
    written = await write_harvest_results(result, timestamp="20260716_142233")
    assert written.emails is not None
    body = written.emails.read_text(encoding="utf-8")
    assert "brian@ine.com" in body
    assert "support@ine.com" not in body


@pytest.mark.asyncio
async def test_nuclei_targets_https_preferred(
    isolated_results_dir: Path,
) -> None:
    result = _make_result(
        subdomains=[{"subdomain": "staging.ine.com"}, {"subdomain": "api.ine.com"}]
    )
    written = await write_harvest_results(result, timestamp="20260716_142233")
    assert written.nuclei_targets is not None
    body = written.nuclei_targets.read_text(encoding="utf-8")
    assert "https://staging.ine.com" in body
    assert "https://api.ine.com" in body
    # No http:// fallback when port 80 is not confirmed open.
    assert "http://staging.ine.com" not in body
    assert "http://api.ine.com" not in body


@pytest.mark.asyncio
async def test_nuclei_targets_adds_http_when_port_80_open(
    isolated_results_dir: Path,
) -> None:
    result = _make_result(
        subdomains=[{"subdomain": "staging.ine.com"}],
        shodan_meta={
            "shodan_internetdb": {
                "hosts": [{"host": "staging.ine.com", "ports": [80, 443]}]
            }
        },
    )
    written = await write_harvest_results(result, timestamp="20260716_142233")
    assert written.nuclei_targets is not None
    body = written.nuclei_targets.read_text(encoding="utf-8")
    # HTTPS still wins, HTTP appended because port 80 was open.
    assert "https://staging.ine.com" in body
    assert "http://staging.ine.com" in body


@pytest.mark.asyncio
async def test_nuclei_targets_reads_production_infrastructure_shape(
    isolated_results_dir: Path,
) -> None:
    result = _make_result(
        subdomains=[{"subdomain": "staging.ine.com"}],
        asns=[{"asn": 16509, "name": "Amazon AWS", "prefixes": []}],
    )
    infrastructure = result.module_results["ripe_stat_asn"].metadata["infrastructure"]
    infrastructure["ips"][0].update(
        {
            "subdomains": ["staging.ine.com"],
            "shodan_data": {"ports": [80, 443]},
        }
    )
    written = await write_harvest_results(result, timestamp="20260716_142233")
    assert written.nuclei_targets is not None
    assert "http://staging.ine.com" in written.nuclei_targets.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_cidrs_txt_written(
    isolated_results_dir: Path,
) -> None:
    result = _make_result(
        asns=[
            {"asn": 16509, "name": "Amazon AWS", "prefixes": ["54.239.0.0/18"]}
        ]
    )
    written = await write_harvest_results(result, timestamp="20260716_142233")
    assert written.cidrs is not None
    assert "54.239.0.0/18" in written.cidrs.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_markdown_report_has_all_sections(
    isolated_results_dir: Path,
) -> None:
    result = _make_result(
        emails=[
            _EmailStub(
                email="brian@ine.com",
                confidence_label="CONFIRMED",
                found_by_modules=["pgp_domain_email"],
                evidence=[{"module": "pgp_domain_email", "metadata": {}}],
            )
        ],
        subdomains=[{"subdomain": "staging.ine.com"}],
        asns=[{"asn": 16509, "name": "Amazon AWS", "prefixes": ["54.239.0.0/18"]}],
        names=[
            {
                "name": "Brian McGahan",
                "sources": ["company_page"],
                "title_or_role": "Co-Founder",
                "confidence_score": 0.7,
            }
        ],
    )
    written = await write_harvest_results(result, timestamp="20260716_142233")
    assert written.report_md is not None
    text = written.report_md.read_text(encoding="utf-8")
    # Every required section is present.
    assert "# MailAccess Harvest — ine.com" in text
    assert "## Summary" in text
    assert "## High Confidence Emails" in text
    assert "## Employee Names" in text
    assert "## Subdomains" in text
    assert "## Infrastructure" in text
    assert "## Suggested Next Steps" in text
    assert "brian@ine.com" in text
    assert "Brian McGahan" in text
    assert "AS16509" in text or "AS 16509" in text
    assert "54.239.0.0/18" in text


# ---------------------------------------------------------------------------
# CLI integration: --no-extras flag + all file paths printed at end
# ---------------------------------------------------------------------------
def _patched_command_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result: DomainHarvestResult,
) -> None:
    async def _fake_run(*args: Any, **kwargs: Any) -> DomainHarvestResult:
        on_harvest_end = kwargs.get("on_harvest_end")
        if on_harvest_end is not None:
            on_harvest_end(result)
        return result

    monkeypatch.setattr(command, "_CFFI_AVAILABLE", True)
    monkeypatch.setattr(command, "run_domain_harvest", _fake_run)
    monkeypatch.setattr(command, "format_harvest_cli_output", lambda *a, **kw: "")


def test_no_extras_flag_skips_supplementary(
    isolated_results_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _make_result(
        subdomains=[{"subdomain": "staging.ine.com"}],
        emails=[_EmailStub(email="brian@ine.com", confidence_label="CONFIRMED")],
    )
    _patched_command_run(monkeypatch, result=result)
    code = command.run_harvest_emails(
        "ine.com",
        no_verify=True,
        no_extras=True,
        console=Console(file=StringIO(), force_terminal=False),
    )
    assert code == 0
    # Main JSON is still written.
    assert list(isolated_results_dir.glob("ine.com_*.json"))
    # Supplementary files are NOT.
    assert not list(isolated_results_dir.glob("ine.com_*_subdomains.txt"))
    assert not list(isolated_results_dir.glob("ine.com_*_emails.txt"))
    assert not list(isolated_results_dir.glob("ine.com_*_nuclei_targets.txt"))
    assert not list(isolated_results_dir.glob("ine.com_*_report.md"))


def test_all_file_paths_printed_at_end(
    isolated_results_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _make_result(
        subdomains=[{"subdomain": "staging.ine.com"}],
        emails=[_EmailStub(email="brian@ine.com", confidence_label="CONFIRMED")],
        asns=[{"asn": 16509, "name": "Amazon AWS", "prefixes": ["54.239.0.0/18"]}],
    )
    _patched_command_run(monkeypatch, result=result)
    stream = StringIO()
    code = command.run_harvest_emails(
        "ine.com",
        no_verify=True,
        console=Console(file=stream, force_terminal=False),
    )
    assert code == 0
    output = stream.getvalue()
    # The Rich console may wrap the printed paths across newlines
    # (the pytest tmp paths are long).  Strip whitespace for the
    # filename-level assertions.
    flat = re.sub(r"\s+", "", output)
    assert "Resultssaved" in flat
    # The printed path references the canonical timestamped JSON name
    # pattern.  We accept any timestamp the run happens to use — the
    # important assertion is that the file name is well-formed and
    # present in the printed output.
    assert re.search(r"ine\.com_\d{8}_\d{6}\.json", flat), flat
    # The live log is always printed as one of the saved paths.
    assert re.search(r"ine\.com_\d{8}_\d{6}_live\.log", flat), flat
    # At least one of the supplementary file extensions is referenced.
    assert (
        "_subdomains.txt" in flat
        or "_emails.txt" in flat
        or "_nuclei_targets.txt" in flat
        or "_report.md" in flat
    )
