"""Harvest live view must match the final result.

Raw harvest signals are only CANDIDATES (no value). Findings come only from the final
exported result, in export order with the same values, and run_done carries counts that
equal the export. The "mailaccess.pro shape" is a harvest that streamed ~45 candidate
emails and kept none.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from rich.console import Console

from backend.config import settings
from backend.core.domain_harvest_orchestrator import DomainHarvestResult, HarvestedEmail
from backend.core.domain_harvest_report import format_harvest_json_export
from backend.core.harvest_events import HarvestEvents
from backend.modules.base import ModuleResult, ModuleStatus
from cli import harvest_emails as command

DOMAIN = "mailaccess.pro"


def _result(emails=(), names=(), subdomains=()) -> DomainHarvestResult:
    modules: dict[str, ModuleResult] = {}
    if names:
        modules["employee_name_discovery"] = ModuleResult(
            ModuleStatus.SUCCESS,
            findings=[{"metadata": {"name": n, "sources": ["company_pages"], "confidence": 0.8}}
                      for n in names],
        )
    if subdomains:
        modules["subdomain_intel"] = ModuleResult(
            ModuleStatus.SUCCESS,
            findings=[{"subdomain": s, "discovery_method": ["crtsh"]} for s in subdomains],
        )
    return DomainHarvestResult(
        domain=DOMAIN, started_at="2026-10-17T10:00:00Z", completed_at="2026-10-17T10:00:01Z",
        duration_seconds=1.0, module_results=modules, unique_emails=list(emails),
        total_unique_emails=len(emails), high_confidence_count=len(emails),
        likely_confidence_count=0, medium_confidence_count=0, low_confidence_count=0,
        role_account_count=0, personal_email_count=0,
    )


def _email(address: str) -> HarvestedEmail:
    return HarvestedEmail(
        email=address, on_domain=True, is_role=False, role_match_type=None,
        confidence_score=0.9, confidence_label="HIGH",
        found_by_modules=["github_domain_commits", "commoncrawl_email"], source_count=2,
    )


def _signals(n: int, kind: str = "email") -> list[SimpleNamespace]:
    # pattern guesses, other-domain addresses and a placeholder: all dropped later
    values = ["name@company.com", "someone@gmail.com", f"guess{{0}}@{DOMAIN}"]
    return [
        SimpleNamespace(kind=kind, source="github_domain_commits",
                        value=values[i % 3].format(i), metadata={})
        for i in range(n)
    ]


def _run_cli(monkeypatch, tmp_path: Path, result: DomainHarvestResult, signals) -> list[dict]:
    monkeypatch.setattr(settings, "harvest_results_dir", tmp_path / "results")
    monkeypatch.setattr(settings, "harvest_auto_export", True)

    async def fake_run(*args: Any, **kwargs: Any) -> DomainHarvestResult:
        kwargs["progress_callback"]("github_domain_commits", "Starting module...")
        for signal in signals:
            kwargs["display_subscriber"](signal)
        kwargs["on_module_complete"]("github_domain_commits", "success", [])
        return result

    monkeypatch.setattr(command, "_CFFI_AVAILABLE", True)
    monkeypatch.setattr(command, "run_domain_harvest", fake_run)
    monkeypatch.setattr(command, "format_harvest_cli_output", lambda *a, **kw: "")
    path = tmp_path / "events.jsonl"
    command.run_harvest_emails(
        domain=DOMAIN, console=Console(file=StringIO(), force_terminal=False),
        events_jsonl=str(path), no_verify=True,
    )
    return [json.loads(line) for line in path.read_text().splitlines()]


def _exported(tmp_path: Path) -> dict:
    files = sorted((tmp_path / "results").rglob("*.json"))
    assert files, "the harvest wrote no export"
    return json.loads(files[-1].read_text())


def test_mailaccess_pro_shape_many_candidates_none_kept(monkeypatch, tmp_path) -> None:
    events = _run_cli(monkeypatch, tmp_path, _result(), _signals(45))
    types = [e["type"] for e in events]
    assert "finding" not in types  # nothing in the export, so nothing is a finding
    candidates = [e for e in events if e["type"] == "candidate"]
    assert candidates and sum(e["count"] for e in candidates) == 45
    done = events[-1]
    assert done["type"] == "run_done"
    assert (done["candidates"], done["emails"], done["names"], done["subdomains"]) == (45, 0, 0, 0)
    assert done["findings"] == 0
    export = _exported(tmp_path)
    assert len(export["emails"]) == done["emails"] == 0


def test_candidates_carry_no_value(monkeypatch, tmp_path) -> None:
    events = _run_cli(monkeypatch, tmp_path, _result(), _signals(45))
    text = (tmp_path / "events.jsonl").read_text()
    for needle in ("name@company.com", "someone@gmail.com", "guess1@", "@gmail.com"):
        assert needle not in text
    for e in events:
        if e["type"] == "candidate":
            assert set(e) == {"seq", "ts", "type", "module", "kind", "count"}
            assert e["kind"] in ("email", "name", "domain", "other") and e["count"] >= 1


def test_findings_equal_the_exported_set_in_export_order(monkeypatch, tmp_path) -> None:
    result = _result(
        emails=[_email(f"a@{DOMAIN}"), _email(f"b@{DOMAIN}")],
        names=["Ada Lovelace", "Grace Hopper"],
        subdomains=["www.mailaccess.pro", "api.mailaccess.pro"],
    )
    events = _run_cli(monkeypatch, tmp_path, result, _signals(45) + _signals(3, "name"))
    export = _exported(tmp_path)
    findings = [e for e in events if e["type"] == "finding"]
    by_kind = lambda k: [f["value"] for f in findings if f["kind"] == k]  # noqa: E731
    assert by_kind("email") == [row["email"] for row in export["emails"]]
    assert by_kind("name") == [row["name"] for row in export["discovered_names"]]
    assert by_kind("domain") == [row["subdomain"] for row in export["subdomains"]]
    # every value is in the export, and nothing the export dropped is a finding
    exported_values = (
        {r["email"] for r in export["emails"]}
        | {r["name"] for r in export["discovered_names"]}
        | {r["subdomain"] for r in export["subdomains"]}
    )
    assert {f["value"] for f in findings} == exported_values
    # emails first, then names, then subdomains; run_done last, after every finding
    assert [f["kind"] for f in findings] == ["email"] * 2 + ["name"] * 2 + ["domain"] * 2
    done = events[-1]
    assert done["type"] == "run_done" and events.index(done) > max(events.index(f) for f in findings)
    assert (done["emails"], done["names"], done["subdomains"]) == (
        len(export["emails"]), len(export["discovered_names"]), len(export["subdomains"]),
    ) == (2, 2, 2)
    assert done["candidates"] == 48 and done["findings"] == 6
    for f in findings:
        assert f["trace"]["reason"] and "_" not in f["trace"]["reason"]


def test_run_done_counts_match_the_format_export_directly() -> None:
    result = _result(emails=[_email(f"a@{DOMAIN}")], names=["Ada Lovelace"], subdomains=["www.mailaccess.pro"])
    exported = format_harvest_json_export(result)
    events = HarvestEvents(Path("/dev/null"), DOMAIN, ["github_domain_commits"])
    events.finalize(exported)  # writes to /dev/null; the emitter keeps the events
    done = [e for e in events.emitter.events if e["type"] == "run_done"][0]["payload"]
    assert (done["emails"], done["names"], done["subdomains"]) == (
        len(exported["emails"]), len(exported["discovered_names"]), len(exported["subdomains"]))


def test_candidates_are_batched_to_at_most_four_a_second(tmp_path) -> None:
    events = HarvestEvents(tmp_path / "e.jsonl", DOMAIN, ["github_domain_commits"])
    for signal in _signals(3000):
        events.signal(signal)
    events.finalize({})
    emitted = [e for e in events.emitter.events if e["type"] == "candidate"]
    assert sum(e["payload"]["count"] for e in emitted) == 3000
    assert len(emitted) <= 4  # a tight loop lasts well under a second: first + final flush
    done = [e for e in events.emitter.events if e["type"] == "run_done"][0]["payload"]
    assert done["candidates"] == 3000 and done["emails"] == 0


def test_a_failed_harvest_still_ends_with_run_done(tmp_path) -> None:
    events = HarvestEvents(tmp_path / "e.jsonl", DOMAIN, [])
    events.signal(SimpleNamespace(kind="email", source="x", value="v@x.io", metadata={}))
    events.finish("failed")
    done = [json.loads(l) for l in (tmp_path / "e.jsonl").read_text().splitlines()][-1]
    assert done["type"] == "run_done" and done["status"] == "failed" and done["error"]
    assert (done["candidates"], done["emails"]) == (1, 0)
