"""A1 structural boundary: Pro leads are serving-only, never native state.

Part 5 acceptance — exercised through the REAL entry point ``run_domain_harvest``
(not ``_orchestrate``/``_aggregate``): a keyed lead-gen run attaches corpus leads to
``result.corpus_leads`` while ``result.unique_emails`` stays corpus-free and no sink
(ledger, history, write_back/projection) ever sees corpus data. A cache-hit still
injects Pro. A keyless / security-mode run is unchanged (no channel, no note).
"""

from __future__ import annotations

import asyncio

from backend.config import settings
from backend.core import (
    bulk_harvest,
    harvest_history,
    harvest_runner,
    mailaccess_pro_connector,
    suppression,
)
from backend.core import domain_harvest_orchestrator as orchestrator
from backend.core.domain_harvest_orchestrator import (
    MODULE_MAILACCESS_PRO,
    DomainHarvestResult,
    HarvestedEmail,
)
from backend.core.domain_harvest_report import format_harvest_json_export
from backend.core.product_mode import ProductMode
from backend.modules.base import ModuleResult, ModuleStatus

PUBLIC = ProductMode.PUBLIC_BUSINESS_CONTACT.value
SECURITY = ProductMode.SECURITY_INVESTIGATION.value


def _row(email: str, modules: list[str]) -> HarvestedEmail:
    return HarvestedEmail(
        email=email,
        on_domain=True,
        is_role=False,
        role_match_type=None,
        confidence_score=0.45,
        confidence_label="LOW",
        found_by_modules=modules,
        source_count=1,
        evidence=[],
        verification="unverified" if modules == [MODULE_MAILACCESS_PRO] else None,
    )


def _native_only_result() -> DomainHarvestResult:
    """A fresh native-only result, as ``run_adaptive_harvest`` would return."""
    return DomainHarvestResult(
        domain="acme.com",
        started_at="2026-09-18T00:00:00Z",
        completed_at="2026-09-18T00:00:01Z",
        duration_seconds=1.0,
        module_results={"native": ModuleResult(status=ModuleStatus.SUCCESS)},
        unique_emails=[_row("native@acme.com", ["native"])],
        total_unique_emails=1,
        high_confidence_count=0,
        likely_confidence_count=0,
        medium_confidence_count=0,
        low_confidence_count=1,
        role_account_count=0,
        personal_email_count=1,
        corpus_leads=[],
        metadata={},
    )


def _result() -> DomainHarvestResult:
    """A served result carrying a serving-only corpus channel."""
    result = _native_only_result()
    result.corpus_leads = [_row("corpus@acme.com", [MODULE_MAILACCESS_PRO])]
    result.metadata = {"mode": PUBLIC}
    return result


def _pro_env(*, key="structural-test", cache=False):
    """Common monkeypatch bundle: keyed lead-gen run, connector serving one lead."""
    calls = {"n": 0}

    async def fake_fetch(domain, **_kw):
        calls["n"] += 1
        return {
            "status": "ok",
            "leads": [{"email": "corpus@acme.com", "name": "Corpus Person", "title": "CEO"}],
        }

    return calls, fake_fetch


def test_run_domain_harvest_attaches_pro_on_live_path(monkeypatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_key", "structural-test")
    monkeypatch.setattr(settings, "harvest_cache_enabled", False)  # no read-first / write_back
    monkeypatch.setattr(settings, "enable_company_pattern_index", False)
    monkeypatch.setattr(suppression, "load_index_sync", lambda: suppression._EMPTY_INDEX)

    calls, fake_fetch = _pro_env()
    monkeypatch.setattr(mailaccess_pro_connector, "fetch_leads", fake_fetch)

    async def fake_adaptive(**_kw):
        return _native_only_result()

    monkeypatch.setattr(harvest_runner, "run_adaptive_harvest", fake_adaptive)

    result = asyncio.run(orchestrator.run_domain_harvest("acme.com", mode=PUBLIC))

    # The connector was actually called on the live path.
    assert calls["n"] > 0
    # Corpus leads populate the serving-only channel...
    assert [e.email for e in result.corpus_leads] == ["corpus@acme.com"]
    assert result.corpus_leads[0].verification == "unverified"
    # Corpus leads bypass deliverability/scoring entirely (channel-only).
    assert result.corpus_leads[0].deliverability_grade is None
    assert result.corpus_leads[0].deliverability_score is None
    # ...and NEVER enter the native aggregate.
    assert all(e.email != "corpus@acme.com" for e in result.unique_emails)
    assert [e.email for e in result.unique_emails] == ["native@acme.com"]
    # The honest metadata note is attached.
    assert result.metadata["mailaccess_pro"] == {
        "requested": True,
        "status": "ok",
        "injected": 1,
    }


def test_run_domain_harvest_cache_hit_still_injects_pro(monkeypatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_key", "structural-test")
    monkeypatch.setattr(settings, "harvest_cache_enabled", True)
    monkeypatch.setattr(settings, "enable_company_pattern_index", False)
    monkeypatch.setattr(suppression, "load_index_sync", lambda: suppression._EMPTY_INDEX)

    calls, fake_fetch = _pro_env()
    monkeypatch.setattr(mailaccess_pro_connector, "fetch_leads", fake_fetch)

    from backend.core import corpus_store

    async def fake_read(domain, scope):  # cache hit → native-only snapshot
        return _native_only_result()

    async def fail_adaptive(**_kw):  # a cache hit must NOT run the harvest
        raise AssertionError("run_adaptive_harvest called on a cache hit")

    monkeypatch.setattr(corpus_store, "read_fresh_crawl", fake_read)
    monkeypatch.setattr(harvest_runner, "run_adaptive_harvest", fail_adaptive)

    result = asyncio.run(orchestrator.run_domain_harvest("acme.com", mode=PUBLIC))

    assert calls["n"] > 0  # Pro is live per-query — applied on cache hits too
    assert [e.email for e in result.corpus_leads] == ["corpus@acme.com"]
    assert all(e.email != "corpus@acme.com" for e in result.unique_emails)


def test_run_domain_harvest_keyless_security_unchanged(monkeypatch) -> None:
    monkeypatch.setattr(settings, "mailaccess_pro_key", None)
    monkeypatch.setattr(settings, "harvest_cache_enabled", False)
    monkeypatch.setattr(settings, "enable_company_pattern_index", False)

    def _boom(*_a, **_k):  # the connector must never be called keyless / in security
        raise AssertionError("connector called on a keyless / security run")

    monkeypatch.setattr(mailaccess_pro_connector, "fetch_leads", _boom)

    async def fake_adaptive(**_kw):
        return _native_only_result()

    monkeypatch.setattr(harvest_runner, "run_adaptive_harvest", fake_adaptive)

    result = asyncio.run(orchestrator.run_domain_harvest("acme.com", mode=SECURITY))
    assert list(result.corpus_leads) == []  # Stream 1 only
    assert "mailaccess_pro" not in (result.metadata or {})


def test_bulk_ledger_and_history_use_native_export_only(monkeypatch) -> None:
    result = _result()
    seen: dict[str, list[str]] = {}

    async def fake_harvest(*_args, **_kwargs):
        return result

    async def capture_ledger(_domain, harvested):
        seen["ledger"] = [entry.email for entry in harvested.unique_emails]

    def capture_history(_domain, payload):
        seen["history"] = [row["email"] for row in payload["emails"]]
        return True

    monkeypatch.setattr(orchestrator, "run_domain_harvest", fake_harvest)
    monkeypatch.setattr(bulk_harvest, "_record_ledger", capture_ledger)
    monkeypatch.setattr(harvest_history, "save_latest", capture_history)
    monkeypatch.setattr(settings, "enable_observation_ledger", True)

    outcome = asyncio.run(
        bulk_harvest._harvest_one_domain("acme.com", options={}, no_export=True)
    )
    assert outcome.emails == 1
    # Sinks (ledger, history) see the native row ONLY — never the corpus lead.
    assert seen == {"ledger": ["native@acme.com"], "history": ["native@acme.com"]}
    # The export view is native-only too: corpus data is live-display-only.
    assert [row["email"] for row in format_harvest_json_export(result)["emails"]] == [
        "native@acme.com",
    ]
