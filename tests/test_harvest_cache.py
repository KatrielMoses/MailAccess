import asyncio
import json
from datetime import datetime, timedelta, timezone
from io import StringIO

from rich.console import Console

from backend.core.domain_harvest_orchestrator import DomainHarvestResult, run_domain_harvest
from backend.core.harvest_cache import HarvestCache
from cli import harvest_emails as command


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


def test_cache_miss_returns_none(tmp_path):
    assert HarvestCache(tmp_path).get("example.com") is None


def test_cache_hit_returns_result(tmp_path):
    cache = HarvestCache(tmp_path)
    cache.set("example.com", _result())
    hit = cache.get("example.com")
    assert hit is not None and hit.domain == "example.com" and hit.from_cache


def test_cache_expired_returns_none(tmp_path):
    cache = HarvestCache(tmp_path)
    cache.set("example.com", _result())
    path = tmp_path / "example.com.json"
    data = json.loads(path.read_text())
    data["cached_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    path.write_text(json.dumps(data))
    assert cache.get("example.com") is None


def test_cache_version_mismatch_returns_none(tmp_path):
    cache = HarvestCache(tmp_path)
    cache.set("example.com", _result())
    path = tmp_path / "example.com.json"
    data = json.loads(path.read_text())
    data["mailaccess_version"] = "0.0.0"
    path.write_text(json.dumps(data))
    assert cache.get("example.com") is None


def test_force_flag_bypasses_cache(monkeypatch, tmp_path):
    cache = HarvestCache(tmp_path)
    cache.set("example.com", _result())
    calls = []

    async def fake_run(**kwargs):
        calls.append(kwargs)
        return _result()

    monkeypatch.setattr("backend.core.harvest_cache.HarvestCache", lambda: cache)
    monkeypatch.setattr("backend.core.harvest_runner.run_adaptive_harvest", fake_run)
    result = asyncio.run(run_domain_harvest("example.com", force=True))
    assert calls and not result.from_cache


def test_cache_written_after_harvest(monkeypatch, tmp_path):
    cache = HarvestCache(tmp_path)

    async def fake_run(**kwargs):
        return _result()

    monkeypatch.setattr("backend.core.harvest_cache.HarvestCache", lambda: cache)
    monkeypatch.setattr("backend.core.harvest_runner.run_adaptive_harvest", fake_run)
    asyncio.run(run_domain_harvest("example.com"))
    assert cache.get("example.com") is not None


def test_atomic_write_no_partial_reads(tmp_path):
    cache = HarvestCache(tmp_path)
    cache.set("example.com", _result())
    payload = json.loads((tmp_path / "example.com.json").read_text())
    assert payload["result"]["domain"] == "example.com"
    assert not list(tmp_path.glob("*.tmp"))


def test_clear_cache_removes_domain_file(tmp_path):
    cache = HarvestCache(tmp_path)
    cache.set("example.com", _result())
    cache.invalidate("example.com")
    assert cache.get("example.com") is None


def test_clear_all_cache_removes_all_files(tmp_path):
    cache = HarvestCache(tmp_path)
    cache.set("one.example", _result("one.example"))
    cache.set("two.example", _result("two.example"))
    cache.invalidate_all()
    assert not list(tmp_path.glob("*.json"))


def test_clear_all_cache_preserves_non_harvest_cache_files(tmp_path):
    cache = HarvestCache(tmp_path)
    cache.set("example.com", _result())
    internal = tmp_path / "commoncrawl_collections.json"
    internal.write_text('{"ids":["CC-MAIN-2026-30"]}', encoding="utf-8")
    cache.invalidate_all()
    assert not (tmp_path / "example.com.json").exists()
    assert internal.exists()


def test_list_domains_ignores_non_harvest_cache_files(tmp_path):
    cache = HarvestCache(tmp_path)
    cache.set("example.com", _result())
    (tmp_path / "maigret-data.json").write_text("{}", encoding="utf-8")
    assert cache.list_domains() == ["example.com"]


def test_cached_result_shows_cache_banner(monkeypatch, tmp_path):
    cached = _result()
    cached.from_cache = True
    cached.cache_age_seconds = 120

    async def fake_run(*args, **kwargs):
        return cached

    monkeypatch.setattr(command, "_CFFI_AVAILABLE", True)
    monkeypatch.setattr(command, "run_domain_harvest", fake_run)
    monkeypatch.setattr(command, "_write_cidr_file", lambda *args: tmp_path / "cidrs.txt")
    monkeypatch.setattr(command, "format_harvest_cli_output", lambda *args, **kwargs: "done")
    stream = StringIO()
    code = command.run_harvest_emails(
        "example.com",
        no_verify=True,
        console=Console(file=stream, force_terminal=False),
    )
    assert code == 0 and "Cached result (2 minutes ago)" in stream.getvalue()
