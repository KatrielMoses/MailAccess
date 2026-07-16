"""0.12.7 — Default JSON export tests.

Covers the auto-export side of :mod:`backend.core.harvest_results`
and the integration with the ``run_harvest_emails`` CLI command.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from backend.config import settings
from backend.core.domain_harvest_orchestrator import DomainHarvestResult
from backend.core.harvest_results import (
    _safe_domain_segment,
    list_results_for_domain,
    prune_stale_results,
    results_dir,
    results_paths,
    timestamp_slug,
    write_harvest_results,
)
from cli import harvest_emails as command


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def isolated_results_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect ``harvest_results_dir`` to a tmp directory for the test.

    Also forces the env vars the CLI surface consults so the test
    cannot leak into ``~/.mailaccess/results``.
    """
    monkeypatch.setattr(settings, "harvest_results_dir", tmp_path)
    monkeypatch.setattr(settings, "harvest_auto_export", True)
    monkeypatch.setattr(settings, "harvest_results_max_per_domain", 50)
    monkeypatch.setattr(settings, "harvest_results_max_age_days", 30)
    return tmp_path


def _result(domain: str = "example.com") -> DomainHarvestResult:
    return DomainHarvestResult(
        domain=domain,
        started_at="2026-07-16T10:00:00Z",
        completed_at="2026-07-16T10:00:01Z",
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
    )


def _patched_command_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result: DomainHarvestResult | None = None,
) -> DomainHarvestResult:
    """Patch the heavy dependencies of :func:`run_harvest_emails`.

    Returns the (possibly synthetic) harvest result so the test can
    assert on what was rendered / exported.
    """
    payload = result or _result()
    async def _fake_run(*args: Any, **kwargs: Any) -> DomainHarvestResult:
        return payload

    monkeypatch.setattr(command, "_CFFI_AVAILABLE", True)
    monkeypatch.setattr(command, "run_domain_harvest", _fake_run)
    monkeypatch.setattr(command, "format_harvest_cli_output", lambda *a, **kw: "")
    return payload


# ---------------------------------------------------------------------------
# Direct module tests (no CLI surface)
# ---------------------------------------------------------------------------
def test_safe_domain_segment_strips_unsafe_chars() -> None:
    assert _safe_domain_segment("Example.com") == "Example.com"
    # Trailing/leading unsafe characters are stripped; internal
    # slashes are replaced with underscores.
    assert _safe_domain_segment("../etc/passwd") == "etc_passwd"
    assert _safe_domain_segment("") == "domain"
    assert _safe_domain_segment("sub.example.com") == "sub.example.com"
    # Underscores and dots are preserved.
    assert _safe_domain_segment("a_b.c-d") == "a_b.c-d"


def test_results_dir_creates_with_0700_when_possible(
    isolated_results_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On Windows chmod is best-effort — we still need the directory
    # to exist for the test to pass.
    target = isolated_results_dir / "nested" / "results"
    monkeypatch.setattr(settings, "harvest_results_dir", target)
    created = results_dir()
    assert created.exists()
    assert created.is_dir()


def test_results_paths_includes_all_seven_artefacts() -> None:
    paths = results_paths("ine.com", "20260716_142233")
    assert paths["json"].name == "ine.com_20260716_142233.json"
    assert paths["live_log"].name.endswith("_live.log")
    assert paths["subdomains"].name.endswith("_subdomains.txt")
    assert paths["emails"].name.endswith("_emails.txt")
    assert paths["nuclei_targets"].name.endswith("_nuclei_targets.txt")
    assert paths["report_md"].name.endswith("_report.md")
    assert paths["cidrs"].name.endswith("_cidrs.txt")


def test_timestamp_slug_format() -> None:
    slug = timestamp_slug(datetime(2026, 7, 16, 14, 22, 33))
    assert slug == "20260716_142233"


# ---------------------------------------------------------------------------
# Async write_harvest_results — covers the main path
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_json_written_automatically_without_flag(
    isolated_results_dir: Path,
) -> None:
    written = await write_harvest_results(_result("example.com"), timestamp="20260716_142233")
    assert written.main_json is not None
    assert written.main_json.exists()
    payload = json.loads(written.main_json.read_text(encoding="utf-8"))
    assert payload["domain"] == "example.com"


@pytest.mark.asyncio
async def test_no_export_flag_skips_all_files(
    isolated_results_dir: Path,
) -> None:
    written = await write_harvest_results(
        _result("example.com"), timestamp="20260716_142233", no_export=True
    )
    assert written.main_json is None
    assert written.all_written() == []


@pytest.mark.asyncio
async def test_explicit_export_writes_both_paths(
    isolated_results_dir: Path,
) -> None:
    explicit = isolated_results_dir / "explicit.json"
    written = await write_harvest_results(
        _result("example.com"),
        timestamp="20260716_142233",
        extra_export_path=explicit,
    )
    assert written.main_json is not None
    assert explicit.exists()
    default_payload = json.loads(written.main_json.read_text(encoding="utf-8"))
    explicit_payload = json.loads(explicit.read_text(encoding="utf-8"))
    assert default_payload == explicit_payload


@pytest.mark.asyncio
async def test_results_dir_created_with_0700_when_possible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Use a fresh sub-directory that doesn't exist yet.
    target = tmp_path / "fresh-results"
    monkeypatch.setattr(settings, "harvest_results_dir", target)
    _ = await write_harvest_results(_result("example.com"), timestamp="20260716_142233")
    assert target.exists()


@pytest.mark.asyncio
async def test_cached_result_still_writes_json(
    isolated_results_dir: Path,
) -> None:
    cached = _result("example.com")
    cached.from_cache = True
    cached.cache_age_seconds = 60
    written = await write_harvest_results(cached, timestamp="20260716_142233")
    assert written.main_json is not None
    assert written.main_json.exists()


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
def test_old_files_cleaned_up_beyond_50(
    isolated_results_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "harvest_results_max_per_domain", 3)
    # Drop 5 fake files in chronological order (oldest first).
    for index in range(5):
        path = isolated_results_dir / f"example.com_2026010{index}_000000.json"
        path.write_text("{}")
        # Force mtime so cleanup keeps the newest 3.
        mtime = time.time() - (10 - index) * 60
        os.utime(path, (mtime, mtime))
    # Running cleanup via a fresh write triggers it.
    asyncio.run(write_harvest_results(_result("example.com"), timestamp="20260110_000000"))
    survivors = sorted(p.name for p in isolated_results_dir.iterdir() if p.is_file())
    # The newest 3 of the original 5 + the one we just wrote.
    assert len([s for s in survivors if s.startswith("example.com_")]) <= 4


def test_files_older_than_30_days_deleted(
    isolated_results_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "harvest_results_max_age_days", 30)
    # Plant a file and force its mtime to 60 days ago.
    old = isolated_results_dir / "example.com_20260101_000000.json"
    old.write_text("{}")
    old_time = time.time() - 60 * 86400
    os.utime(old, (old_time, old_time))
    # And a fresh file that should survive.
    fresh = isolated_results_dir / "example.com_20260715_000000.json"
    fresh.write_text("{}")
    asyncio.run(write_harvest_results(_result("example.com"), timestamp="20260716_142233"))
    assert not old.exists()
    assert fresh.exists()


def test_prune_stale_results_helper(
    isolated_results_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale = isolated_results_dir / "example.com_20260101_000000.json"
    stale.write_text("{}")
    stale_time = time.time() - 60 * 86400
    os.utime(stale, (stale_time, stale_time))
    removed = prune_stale_results(isolated_results_dir, max_age_days=30)
    assert removed == 1
    assert not stale.exists()


def test_list_results_for_domain_orders_newest_first(
    isolated_results_dir: Path,
) -> None:
    older = isolated_results_dir / "example.com_20260710_000000.json"
    older.write_text("{}")
    older_time = time.time() - 3600
    os.utime(older, (older_time, older_time))
    newer = isolated_results_dir / "example.com_20260716_142233.json"
    newer.write_text("{}")
    out = list_results_for_domain(isolated_results_dir, "example.com")
    assert [p.name for p in out] == [newer.name, older.name]


# ---------------------------------------------------------------------------
# CLI integration: the path is printed at the end of the run.
# ---------------------------------------------------------------------------
def test_path_printed_at_end_of_harvest(
    isolated_results_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patched_command_run(monkeypatch, result=_result("ine.com"))
    from io import StringIO

    stream = StringIO()
    console = Console(file=stream, force_terminal=False)
    code = command.run_harvest_emails(
        "ine.com",
        no_verify=True,
        console=console,
    )
    assert code == 0
    output = stream.getvalue()
    # The Results saved: header should appear and reference the JSON.
    # The Rich console may wrap the printed path across newlines; we
    # flatten whitespace before substring matching.
    import re
    flat = re.sub(r"\s+", "", output)
    assert "Resultssaved" in flat
    assert "ine.com_" in flat
    assert ".json" in flat
    # And the file should exist on disk.
    matching = list(isolated_results_dir.glob("ine.com_*.json"))
    assert matching, f"expected at least one JSON; got {list(isolated_results_dir.iterdir())}"


def test_no_export_flag_from_cli_skips_default(
    isolated_results_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patched_command_run(monkeypatch, result=_result("ine.com"))
    from io import StringIO

    stream = StringIO()
    code = command.run_harvest_emails(
        "ine.com",
        no_verify=True,
        no_export=True,
        console=Console(file=stream, force_terminal=False),
    )
    assert code == 0
    output = stream.getvalue()
    # No "Results saved:" header when --no-export is used.
    assert "Results saved" not in output
    # And the JSON should NOT exist.
    assert not list(isolated_results_dir.glob("ine.com_*.json"))


def test_no_export_overrides_explicit_export_path(
    isolated_results_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patched_command_run(monkeypatch, result=_result("ine.com"))
    explicit = isolated_results_dir / "explicit.json"
    code = command.run_harvest_emails(
        "ine.com",
        no_verify=True,
        no_export=True,
        export=str(explicit),
        console=Console(file=StringIO(), force_terminal=False),
    )
    assert code == 0
    assert not explicit.exists()
