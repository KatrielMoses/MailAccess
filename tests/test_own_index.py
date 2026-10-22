"""MailAccess Index (``own_index``) harvest source.

It exists only when BOTH ``MAILACCESS_INDEX_URL`` and ``MA_INDEX_SERVICE_KEY`` are
set; ``--no-own-index`` turns it fully off (no calls, no events, no cached rows).
It runs first, feeds the shared dedup, and when it returns results the live
Common Crawl module is skipped for the run. Every finding carries a trace.

Network-free: the index's HTTP layer is an ``httpx.MockTransport`` that records
every request.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from backend.config import settings
from backend.core import harvest_runner
from backend.core import own_index_client as oic
from backend.core.domain_harvest_orchestrator import run_domain_harvest
from backend.core.domain_harvest_report import format_harvest_json_export
from backend.modules.base import ModuleResult, ModuleStatus

URL = "http://index.test:8765"
KEY = "index-secret-key-0123456789"
DOMAIN = "acme.io"
NOW = datetime.now(timezone.utc)
RECENT = (NOW - timedelta(days=60)).isoformat().replace("+00:00", "Z")
OLD = (NOW - timedelta(days=800)).isoformat().replace("+00:00", "Z")  # > 24 months


def _row(email: str, *, last_seen: str = RECENT, kind: str = "personal", count: int = 4,
         url: str = "https://acme.io/team", crawl: str = "CC-MAIN-2026-39",
         source: str = "cc") -> dict[str, Any]:
    return {
        "email": email,
        "domain": DOMAIN,
        "kind": kind,
        "first_seen": "2023-02-01T00:00:00Z",
        "last_seen": last_seen,
        "source_count": count,
        "crawls": ["CC-MAIN-2023-06", crawl],
        "sources": [
            {"url": url, "crawl": crawl, "fetch_time": last_seen,
             "snippet": f"Contact {email} for details", "source": source},
            {"url": "https://acme.io/about", "crawl": "CC-MAIN-2023-06",
             "fetch_time": "2023-02-01T00:00:00Z", "snippet": "about", "source": "cc"},
        ],
    }


class Index:
    """Recording fake of the index service."""

    def __init__(self, pages: list[list[dict]] | None = None, *, status: int = 200,
                 raise_timeout: bool = False) -> None:
        self.pages = pages if pages is not None else [[_row("jane.doe@acme.io")]]
        self.status = status
        self.raise_timeout = raise_timeout
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raise_timeout:
            raise httpx.ReadTimeout("slow", request=request)
        if self.status != 200:
            return httpx.Response(self.status, json={"detail": "nope"})
        path = request.url.path
        if path.startswith("/v1/index/domain/"):
            cursor = request.url.params.get("cursor")
            page = int(cursor) if cursor else 0
            rows = self.pages[page] if page < len(self.pages) else []
            nxt = str(page + 1) if page + 1 < len(self.pages) else None
            return httpx.Response(200, json={
                "domain": DOMAIN, "build_id": "b-2026-39",
                "total": sum(len(p) for p in self.pages), "emails": rows, "next_cursor": nxt,
            })
        if path.startswith("/v1/index/email/"):
            return httpx.Response(200, json={**_row("jane.doe@acme.io"), "sources": []})
        if path.startswith("/v1/index/coverage/"):
            return httpx.Response(200, json={"domain": DOMAIN, "count": 1})
        if path == "/health":
            return httpx.Response(200, json={"build_id": "b", "crawls": ["CC-MAIN-2026-39"],
                                             "rows": {"emails": 1, "sources": 2}})
        return httpx.Response(404)


@pytest.fixture(autouse=True)
def _own_database(monkeypatch, tmp_path):
    """Exports read the suppression store through ``settings.database_url``; give
    this file its own (empty) DB so an earlier test's leftover URL cannot break it."""
    from backend.config import settings as _settings

    monkeypatch.setattr(_settings, "database_url", f"sqlite+aiosqlite:///{tmp_path / 'own.db'}")


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "mailaccess_index_url", URL)
    monkeypatch.setattr(settings, "ma_index_service_key", KEY)
    monkeypatch.setattr(settings, "own_index_disabled", False)


def _serve(monkeypatch, index: Index) -> Index:
    real = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda **kw: real(**{**kw, "transport": httpx.MockTransport(index)}),
    )
    return index


@pytest.fixture(autouse=True)
def _stub_live_io(monkeypatch):
    class _FastFailSession:
        def __init__(self, *a, **k):
            pass

        async def get(self, url, **kw):
            raise ConnectionError("live network disabled")

        async def aclose(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr("backend.core.harvest_runner.StealthSession", _FastFailSession)


class _Mock:
    def __init__(self, name: str, emails: list[str] = ()) -> None:
        self.name = name
        self.emails = list(emails)
        self.calls = 0

    async def run(self, domain: str, **_kw: Any) -> ModuleResult:
        self.calls += 1
        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=[
                {
                    "platform": self.name,
                    "profile_url": f"https://{domain}/contact",
                    "metadata": {
                        "email": email, "on_domain": True,
                        "source_url": f"https://{domain}/contact",
                        "source_type": "structured_page",
                    },
                }
                for email in self.emails
            ],
        )


async def _harvest(*, cc=None, code_cert=None, **kw):
    progress: list[tuple[str, str]] = []
    completed: list[tuple[str, str]] = []
    result = await run_domain_harvest(
        DOMAIN,
        enable_smtp=False,
        cc_module=cc or _Mock("commoncrawl_email", ["cc.only@acme.io"]),
        code_cert_module=code_cert or _Mock("code_and_cert_email"),
        timeout_seconds=20,
        progress_callback=lambda m, a: progress.append((m, a)),
        on_module_complete=lambda name, status, errors=None: completed.append((name, status)),
        **kw,
    )
    return result, progress, completed


# ------------------------------------------------------------------ existence
@pytest.mark.parametrize(
    "url,key,expected",
    [(None, None, False), (URL, None, False), (None, KEY, False), (URL, "", False),
     ("  ", KEY, False), (URL, KEY, True)],
)
def test_module_exists_only_with_both_url_and_key(monkeypatch, url, key, expected):
    monkeypatch.setattr(settings, "mailaccess_index_url", url)
    monkeypatch.setattr(settings, "ma_index_service_key", key)
    assert oic.own_index_configured() is expected
    assert oic.own_index_active() is expected
    planned = harvest_runner.planned_harvest_modules(own_index=oic.own_index_active())
    assert ("own_index" in planned) is expected
    if expected:
        assert planned[0] == "own_index"  # it runs first


async def test_absent_without_url_makes_no_call_and_no_trace(monkeypatch, isolated_db):
    monkeypatch.setattr(settings, "mailaccess_index_url", None)
    monkeypatch.setattr(settings, "ma_index_service_key", KEY)
    index = _serve(monkeypatch, Index())
    result, progress, completed = await _harvest()
    assert index.requests == []
    assert "own_index" not in result.module_results
    assert all(m != "own_index" for m, _ in progress)
    assert all(n != "own_index" for n, _ in completed)


async def test_per_run_flag_means_fully_off(monkeypatch, configured, isolated_db):
    index = _serve(monkeypatch, Index())
    cc = _Mock("commoncrawl_email", ["cc.only@acme.io"])
    result, progress, completed = await _harvest(cc=cc, no_own_index=True)
    assert index.requests == []  # zero HTTP calls
    assert "own_index" not in result.module_results
    assert all(m != "own_index" for m, _ in progress)  # no events
    assert all(n != "own_index" for n, _ in completed)
    assert cc.calls == 1  # Common Crawl runs as usual
    export = format_harvest_json_export(result)
    assert "own_index" not in json.dumps(export)
    assert not oic.own_index_active(no_own_index=True)


def test_flag_off_strips_cached_index_rows():
    from backend.core.domain_harvest_orchestrator import HarvestedEmail

    def lead(email, modules):
        return HarvestedEmail(
            email=email, on_domain=True, is_role=False, role_match_type=None,
            confidence_score=0.5, confidence_label="MEDIUM", found_by_modules=modules,
            source_count=len(modules),
            evidence=[{"module": m, "metadata": {"email": email}} for m in modules],
        )

    leads = [lead("a@acme.io", ["own_index"]), lead("b@acme.io", ["own_index", "commoncrawl_email"]),
             lead("c@acme.io", ["wayback_domain_harvest"])]
    kept = oic.strip_own_index_leads(leads)
    assert [k.email for k in kept] == ["b@acme.io", "c@acme.io"]
    assert kept[0].found_by_modules == ["commoncrawl_email"]
    assert all(ev["module"] != "own_index" for ev in kept[0].evidence)


# ------------------------------------------------------------------ trace shape
def test_trace_shape_signal_dates_and_count():
    finding = oic.build_finding(_row("jane.doe@acme.io"), DOMAIN)
    trace = finding["trace"]
    assert trace["technique_id"] == "own_index"
    assert trace["technique"] == "Looking up our own index of the public web."
    assert trace["signal"] == "Found on https://acme.io/team in the Sep 2026 crawl"
    assert trace["first_seen"] == "2023-02-01T00:00:00Z"
    assert trace["last_seen"] == RECENT
    assert trace["source_count"] == 4
    assert trace["label"] is None
    meta = finding["metadata"]
    assert meta["trace"] == trace
    assert meta["email"] == "jane.doe@acme.io" and meta["on_domain"] is True
    assert meta["first_seen_timestamp"] == "2023-02-01T00:00:00Z"
    assert meta["last_seen_timestamp"] == RECENT
    assert meta["source_url"] == "https://acme.io/team"
    assert meta["older_source"] is False


def test_older_than_24_months_is_labelled_older_source():
    old = oic.build_finding(_row("old.timer@acme.io", last_seen=OLD), DOMAIN)
    assert old["trace"]["label"] == "older source"
    assert old["metadata"]["older_source"] is True
    assert old["metadata"]["age_label"] == "older source"
    edge = (NOW - timedelta(days=700)).isoformat()  # ~23 months
    assert oic.build_finding(_row("x@acme.io", last_seen=edge), DOMAIN)["trace"]["label"] is None


def test_automated_addresses_are_kept_and_marked():
    finding = oic.build_finding(_row("noreply@acme.io", kind="automated"), DOMAIN)
    assert finding is not None
    assert finding["trace"]["automated"] is True
    assert finding["metadata"]["automated"] is True


@pytest.mark.parametrize(
    "crawl,fetch,label",
    [("CC-MAIN-2026-39", None, "Sep 2026"), ("CC-MAIN-2024-10", None, "Mar 2024"),
     ("gha-2024", "2024-05-03T00:00:00Z", "May 2024"), ("weird", None, "weird")],
)
def test_crawl_label(crawl, fetch, label):
    assert oic.crawl_label(crawl, fetch) == label


# ------------------------------------------------------------------ client contract
async def test_client_paginates_sends_key_header_and_caps(monkeypatch, configured):
    pages = [[_row(f"p{i}.{j}@acme.io") for j in range(3)] for i in range(3)]
    index = _serve(monkeypatch, Index(pages))
    monkeypatch.setattr(settings, "own_index_max_emails", 7)
    answer = await oic.OwnIndexClient().domain_emails(DOMAIN)
    assert answer.status == "ok" and len(answer.emails) == 7 and answer.truncated
    assert [r.url.params.get("cursor") for r in index.requests] == [None, "1", "2"]
    for req in index.requests:
        assert req.headers["X-Index-Key"] == KEY
        assert KEY not in str(req.url)
        assert req.url.path == f"/v1/index/domain/{DOMAIN}"
        assert int(req.url.params["limit"]) <= 500


async def test_client_other_endpoints(monkeypatch, configured):
    _serve(monkeypatch, Index())
    client = oic.OwnIndexClient()
    assert (await client.email("jane.doe@acme.io"))[0] == "ok"
    assert (await client.coverage(DOMAIN)) == ("ok", {"domain": DOMAIN, "count": 1})
    status, health = await client.health()
    assert status == "ok" and health["rows"]["emails"] == 1


@pytest.mark.parametrize("code,error", [(401, "bad_key"), (422, "domain_rejected"),
                                        (400, "invalid_input"), (503, "http_503")])
async def test_errors_are_no_results(monkeypatch, configured, code, error):
    _serve(monkeypatch, Index(status=code))
    answer = await oic.OwnIndexClient().domain_emails(DOMAIN)
    assert answer.status == "error" and answer.error == error and answer.emails == []


async def test_timeout_is_no_results(monkeypatch, configured):
    _serve(monkeypatch, Index(raise_timeout=True))
    answer = await oic.OwnIndexClient().domain_emails(DOMAIN)
    assert answer.status == "error" and answer.error == "timeout"


# ------------------------------------------------------------------ harvest behaviour
async def test_index_results_skip_common_crawl_and_feed_dedup(
    monkeypatch, configured, isolated_db
):
    index = _serve(monkeypatch, Index([[_row("jane.doe@acme.io"),
                                        _row("old.timer@acme.io", last_seen=OLD),
                                        _row("noreply@acme.io", kind="automated")]]))
    cc = _Mock("commoncrawl_email", ["cc.only@acme.io"])
    # Another module finds the same address: one email, both sources.
    code_cert = _Mock("code_and_cert_email", ["jane.doe@acme.io"])
    result, progress, completed = await _harvest(cc=cc, code_cert=code_cert)

    assert len(index.requests) == 1
    assert progress and progress[0][0] == "own_index"  # first module to start
    # Common Crawl skipped, and the trace says why.
    assert cc.calls == 0
    cc_result = result.module_results["commoncrawl_email"]
    assert cc_result.status is ModuleStatus.SKIPPED
    assert cc_result.metadata["skip_reason"] == "own_index_had_results"
    assert cc_result.metadata["skip_note"] == "skipped: own index had results"
    assert ("commoncrawl_email", "skipped") in [(n, str(s).lower()) for n, s in completed]
    assert not any("own index" in e for e in result.errors)  # a skip, not a run error

    by_email = {e.email: e for e in result.unique_emails}
    jane = by_email["jane.doe@acme.io"]
    assert set(jane.found_by_modules) >= {"own_index", "code_and_cert_email"}
    assert {ev["module"] for ev in jane.evidence} >= {"own_index", "code_and_cert_email"}
    assert sum(1 for e in result.unique_emails if e.email == "jane.doe@acme.io") == 1
    assert "noreply@acme.io" in by_email  # automated kept

    export = format_harvest_json_export(result)
    rows = {r["email"]: r for r in export["emails"]}
    assert rows["jane.doe@acme.io"]["own_index"]["signal"].startswith("Found on https://acme.io/team")
    assert rows["old.timer@acme.io"]["own_index"]["labels"] == ["older source"]
    assert rows["noreply@acme.io"]["own_index"]["automated"] is True
    assert "own_index" not in rows.get("cc.only@acme.io", {})


async def test_older_source_label_in_report_output(monkeypatch, configured, isolated_db):
    from rich.console import Console

    from backend.core.domain_harvest_report import format_harvest_cli_output
    from backend.core.harvest_results import _build_markdown_report

    _serve(monkeypatch, Index([[_row("pat.miller@acme.io", last_seen=OLD)]]))
    result, _p, _c = await _harvest()
    md = _build_markdown_report(result)
    assert "From our own index of the public web" in md and "older source" in md
    console = Console(record=True, width=250)
    console.print(format_harvest_cli_output(result, show_low=True, full=True))
    assert "older source" in console.export_text()


@pytest.mark.parametrize("index", [Index([[]]), Index(status=401), Index(raise_timeout=True)])
async def test_common_crawl_not_skipped_when_index_empty_or_failing(
    monkeypatch, configured, index, isolated_db
):
    _serve(monkeypatch, index)
    cc = _Mock("commoncrawl_email", ["cc.only@acme.io"])
    result, _progress, _completed = await _harvest(cc=cc)
    assert cc.calls == 1
    assert result.module_results["commoncrawl_email"].metadata.get("skip_reason") != "own_index_had_results"
    assert "cc.only@acme.io" in {e.email for e in result.unique_emails}
    own = result.module_results["own_index"]
    assert own.findings == []
    if index.status != 200 or index.raise_timeout:
        assert own.status is ModuleStatus.FAILED and own.errors  # logged, run continued


# ------------------------------------------------------------------ capabilities + CLI
async def _capabilities() -> httpx.Response:
    from backend.main import app

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        return await client.get("/api/capabilities")


@pytest.mark.parametrize("url,key,expected", [(URL, KEY, True), (URL, None, False), (None, None, False)])
async def test_capabilities_shows_it_only_when_enabled(monkeypatch, url, key, expected):
    monkeypatch.setattr(settings, "mailaccess_index_url", url)
    monkeypatch.setattr(settings, "ma_index_service_key", key)
    response = await _capabilities()
    assert response.status_code == 200
    assert response.json()["providers"]["own_index"] is expected
    assert KEY not in response.text and URL not in response.text


def test_cli_and_bulk_accept_the_flag():
    import inspect

    from typer.testing import CliRunner

    from cli import harvest_bulk, harvest_emails, main

    out = CliRunner().invoke(main.app, ["harvest-emails", "--help"])
    assert out.exit_code == 0 and "no-own-index" in out.output
    assert "no_own_index" in inspect.signature(harvest_bulk.run_bulk_harvest_emails).parameters
    assert "no_own_index" in inspect.signature(harvest_emails.run_harvest_emails).parameters
    from backend.api.routes.investigations import InvestigateRequest

    assert InvestigateRequest(email="a@acme.io").no_own_index is False


def test_techniques_catalogue_has_own_index_and_homepage():
    from backend.core.techniques import technique_for

    assert technique_for("own_index") == ("own_index", "Looking up our own index of the public web.")
    tech_id, line = technique_for("homepage")
    assert tech_id == "public_pages" and "homepage" in line


def test_event_stream_records_the_common_crawl_skip(tmp_path):
    from backend.core.harvest_events import HarvestEvents

    path = tmp_path / "events.jsonl"
    events = HarvestEvents(path, DOMAIN, ["own_index", "commoncrawl_email"])
    events.complete("commoncrawl_email", "skipped", ["skipped: own index had results"])
    events.finish("complete")
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    done = [r for r in rows if r["type"] == "module_done" and r["module"] == "commoncrawl_email"]
    assert done and done[0]["skipped_reason"] == "own_index_had_results"


# -------------------------------------------------- corpus strip (phase 1b)
def _lead(email, modules):
    from backend.core.domain_harvest_orchestrator import HarvestedEmail

    return HarvestedEmail(
        email=email, on_domain=True, is_role=False, role_match_type=None,
        confidence_score=0.5, confidence_label="MEDIUM", found_by_modules=list(modules),
        source_count=len(modules),
        evidence=[{"module": m, "metadata": {"email": email}} for m in modules],
    )


def _result(*leads):
    from backend.core.domain_harvest_orchestrator import DomainHarvestResult

    return DomainHarvestResult(
        domain=DOMAIN, started_at=NOW.isoformat(), completed_at=NOW.isoformat(),
        duration_seconds=1.0, module_results={}, unique_emails=list(leads),
        total_unique_emails=len(leads), high_confidence_count=0, likely_confidence_count=0,
        medium_confidence_count=0, low_confidence_count=0, role_account_count=0,
        personal_email_count=len(leads),
    )


async def test_corpus_strip_index_only_emails_excluded_from_store(
    monkeypatch, configured, isolated_db
):
    """write_back with own_index active: index-only emails are stripped, native
    emails are preserved, and the live result is unaffected."""
    from dataclasses import replace

    from backend.core.corpus_store import read_leads, sanitize_for_persistence, write_back

    idx_only = _lead("idx.only@acme.io", ["own_index"])
    native = _lead("native@acme.io", ["code_and_cert_email"])
    full = _result(idx_only, native)

    corpus_result = sanitize_for_persistence(full)
    stripped = oic.strip_own_index_leads(list(corpus_result.unique_emails))
    corpus_result = replace(corpus_result, unique_emails=stripped,
                            total_unique_emails=len(stripped))
    await write_back(DOMAIN, corpus_result)

    assert {e.email for e in full.unique_emails} == {"idx.only@acme.io", "native@acme.io"}

    corpus = await read_leads(DOMAIN, limit=100)
    corpus_emails = {lead["email"] for lead in corpus["leads"]}
    assert "native@acme.io" in corpus_emails
    assert "idx.only@acme.io" not in corpus_emails


async def test_corpus_strip_dual_source_keeps_non_index_evidence(
    monkeypatch, configured, isolated_db
):
    """An email found by both own_index and another source: the corpus store
    keeps only the non-index evidence."""
    from dataclasses import replace

    from backend.core.corpus_store import read_leads, sanitize_for_persistence, write_back

    shared = _lead("shared@acme.io", ["own_index", "code_and_cert_email"])
    full = _result(shared)

    corpus_result = sanitize_for_persistence(full)
    stripped = oic.strip_own_index_leads(list(corpus_result.unique_emails))
    corpus_result = replace(corpus_result, unique_emails=stripped,
                            total_unique_emails=len(stripped))
    await write_back(DOMAIN, corpus_result)

    corpus = await read_leads(DOMAIN, limit=100)
    corpus_emails = {lead["email"]: lead for lead in corpus["leads"]}
    assert "shared@acme.io" in corpus_emails
    stored = corpus_emails["shared@acme.io"]
    assert "code_and_cert_email" in stored.get("found_by_modules", [])
    assert "own_index" not in stored.get("found_by_modules", [])


async def test_corpus_unchanged_when_own_index_off(monkeypatch, isolated_db):
    """With own_index off, write_back stores all emails — no strip applied."""
    from backend.core.corpus_store import read_leads, sanitize_for_persistence, write_back

    monkeypatch.setattr(settings, "mailaccess_index_url", None)
    monkeypatch.setattr(settings, "ma_index_service_key", None)
    native = _lead("native@acme.io", ["code_and_cert_email"])
    full = _result(native)

    assert not oic.own_index_active()
    await write_back(DOMAIN, sanitize_for_persistence(full))

    corpus = await read_leads(DOMAIN, limit=100)
    corpus_emails = {lead["email"] for lead in corpus["leads"]}
    assert "native@acme.io" in corpus_emails


# --- Round 3: index-derived name suppression tests ---

@pytest.mark.asyncio
async def test_pattern_gen_skipped_for_own_index_names():
    """_on_name_found returns [] when source is own_index."""
    items = await harvest_runner._on_name_found(
        "Jane Smith", "own_index", {"confidence_score": 0.9, "domain": "acme.io"}
    )
    assert items == []


@pytest.mark.asyncio
async def test_pattern_gen_runs_for_non_index_names(monkeypatch):
    """_on_name_found returns work items for non-index sources."""
    monkeypatch.setattr(settings, "pattern_medium_confidence_threshold", 0.50)
    items = await harvest_runner._on_name_found(
        "Jane Smith", "employee_name_discovery",
        {"confidence_score": 0.9, "domain": "acme.io"},
    )
    assert len(items) == 1
    assert items[0].kind == "generate_patterns"


@pytest.mark.asyncio
async def test_github_pivot_index_name_cap():
    """_github_name_pivot caps index-derived names at 5 per domain."""
    from backend.modules.name_to_github_profile import _github_name_pivot, _INDEX_NAME_CAP

    counter: dict[str, int] = {}
    accepted = 0
    for i in range(_INDEX_NAME_CAP + 3):
        items = await _github_name_pivot(
            f"Person{i} Lastname", "own_index",
            {"domain": "acme.io", "confidence_score": 0.9, "derived_from_email": True},
            counter,
        )
        accepted += len(items)
    assert accepted == _INDEX_NAME_CAP
    assert counter["acme.io"] == _INDEX_NAME_CAP


@pytest.mark.asyncio
async def test_github_pivot_no_cap_for_non_index():
    """_github_name_pivot does not cap names from non-index sources."""
    from backend.modules.name_to_github_profile import _github_name_pivot, _INDEX_NAME_CAP

    counter: dict[str, int] = {}
    accepted = 0
    for i in range(_INDEX_NAME_CAP + 3):
        items = await _github_name_pivot(
            f"Person{i} Lastname", "employee_name_discovery",
            {"domain": "acme.io", "confidence_score": 0.9, "derived_from_email": True},
            counter,
        )
        accepted += len(items)
    assert accepted == _INDEX_NAME_CAP + 3


@pytest.mark.asyncio
async def test_github_pivot_uses_opportunistic_track():
    """_github_name_pivot emits items on TRACK_OPPORTUNISTIC, not TRACK_GUARANTEED."""
    from backend.core.work_scheduler import TRACK_OPPORTUNISTIC
    from backend.modules.name_to_github_profile import _github_name_pivot

    items = await _github_name_pivot(
        "Jane Smith", "employee_name_discovery",
        {"domain": "acme.io", "confidence_score": 0.9, "derived_from_email": True},
        {},
    )
    assert len(items) == 1
    assert items[0].track == TRACK_OPPORTUNISTIC
