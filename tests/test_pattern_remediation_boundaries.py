"""Executed regression boundaries for the retained-evidence remediation."""

import asyncio
import gzip
import json
from types import SimpleNamespace as NS

import pytest

from backend.config import settings
from backend.core import company_pattern_index as cpi
from backend.core import pattern_candidate as pc
from backend.core import product_mode as pm
from backend.core.domain_harvest_orchestrator import HarvestedEmail, _aggregate
from backend.core.harvest_runner import (
    WorkerContext,
    _finalize_person_selection,
    _record_module_result,
    _run_pattern_for_name,
)
from backend.core.pattern_resolver import CanonicalResolver, classify_evidence_kind
from backend.core.signal_pool import AsyncSignalPool
from backend.core.suppression import SuppressionIndex
from backend.core.time_budget import TimeBudget
from backend.core.work_scheduler import WorkScheduler
from backend.modules import pattern_and_verify as pav
from backend.modules.base import ModuleResult, ModuleStatus

DOM = "audit-corp.example"
EMPTY = SuppressionIndex(frozenset(), frozenset(), frozenset(), {})
ORG = pm.ProductMode.ORG_AUTHORIZED_VERIFICATION


@pytest.fixture
def setup(tmp_path, monkeypatch):
    raw = {
        "_meta": {"schema": cpi.SCHEMA},
        DOM: {
            "pattern": "P04",
            "confidence": 0.99,
            "support_n": 9900,
            "considered_n": 10000,
            "mx": "m365",
        },
    }
    path = tmp_path / "index.gz"
    with gzip.open(path, "wt") as f:
        json.dump(raw, f)
    idx = cpi.CompanyPatternIndex(path)
    monkeypatch.setattr(cpi, "_SINGLETON", idx)
    monkeypatch.setattr(pc, "load_index_sync", lambda: EMPTY)
    monkeypatch.setattr(pav, "load_index_sync", lambda: EMPTY)
    monkeypatch.setattr("backend.core.suppression.load_index_sync", lambda: EMPTY)
    monkeypatch.setattr(
        "backend.core.name_classifier.classify_name", lambda *a, **k: NS(is_person=True)
    )
    monkeypatch.setattr(settings, "enable_company_pattern_index", True)
    monkeypatch.setattr(settings, "enable_pattern_oracle_verify", True)
    token = pm.set_active_mode(ORG)
    yield idx
    pm._ACTIVE_MODE.reset(token)


def context():
    return WorkerContext(
        domain=DOM,
        scheduler=WorkScheduler(),
        signal_pool=AsyncSignalPool(),
        page_cache=None,
        budget=TimeBudget(10),
        stealth_session=None,
        settings=settings,
        module_results={},
    )


def candidate(idx, name="Jane Smith"):
    return pc.pattern_email_to_candidate(idx.apply(name, DOM), mode=ORG, suppression_index=EMPTY)


def module(findings):
    return ModuleResult(status=ModuleStatus.SUCCESS, findings=findings)


async def batch(ctx):
    pairs, _, meta = pav._company_pattern_pass(
        [pav.EmployeeNameResult(name="Jane Smith", confidence=0.9)],
        DOM,
        signal_pool=ctx.signal_pool,
        run_state=ctx.pattern_run_state,
    )
    findings = await pav._verify_company_pattern_pairs(
        pairs,
        meta=meta,
        run_state=ctx.pattern_run_state,
    )
    _record_module_result(ctx, "pattern_and_verify", module(findings))


@pytest.mark.parametrize("first_batch", [False, True])
@pytest.mark.parametrize("status", ["not_found", "verified"])
async def test_overlapping_real_workers_share_verdict(setup, monkeypatch, first_batch, status):
    ctx = context()
    ctx.pattern_run_state.seed_oracle_budget(1)
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    class Oracle:
        async def verify_batch(self, emails):
            calls.append(emails)
            entered.set()
            await release.wait()
            return [NS(email=e, status=status, exists=status == "verified") for e in emails]

    monkeypatch.setattr("backend.core.m365_verifier.M365Verifier", Oracle)

    async def reactive():
        return await _run_pattern_for_name({"name": "Jane Smith", "confidence": 0.9}, ctx)

    owner = asyncio.create_task(batch(ctx) if first_batch else reactive())
    await asyncio.wait_for(entered.wait(), 2)
    waiter = asyncio.create_task(reactive() if first_batch else batch(ctx))
    await asyncio.sleep(0)
    release.set()
    await asyncio.wait_for(asyncio.gather(owner, waiter), 2)
    final = _aggregate(DOM, ctx.module_results, resolver=ctx.pattern_run_state.resolver)
    assert len(calls) == 1
    if status == "not_found":
        assert final == []
        assert ctx.signal_pool.get_emails(DOM) == []
        assert (await reactive())[0] == []
    else:
        assert len(final) == 1
        assert final[0].verification == "provider_verified"
        assert final[0].confidence_label == "CONFIRMED"
    await ctx.signal_pool.close()


async def test_actual_http_leads_uses_configured_mode_and_served_freshness(
    setup, tmp_path, monkeypatch
):
    from datetime import datetime, timedelta, timezone

    import httpx
    from fastapi import FastAPI
    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from backend.api.routes import leads
    from backend.db import database
    from backend.db.models import Base, Contact

    engine = create_async_engine("sqlite+aiosqlite:///" + (tmp_path / "leads.db").as_posix())
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as con:
        await con.run_sync(Base.metadata.create_all)
    monkeypatch.setattr(database, "AsyncSessionLocal", sessions)
    monkeypatch.setattr(leads, "enforce_quota", lambda request: None)
    monkeypatch.setattr(settings, "product_mode", ORG.value)
    monkeypatch.setattr(settings, "harvest_cache_enabled", True)
    monkeypatch.setattr(settings, "enable_corpus_decay", True)
    async with sessions() as session:
        session.add(
            Contact(
                email="jane.smith@" + DOM,
                domain=DOM,
                confidence_score=0.99,
                confidence_label="CONFIRMED",
                verification="provider_verified",
                deliverability_grade="Valid",
                policy_status=pm.policy_status_for_mode(ORG),
                last_verified=datetime.now(timezone.utc),
            )
        )
        await session.commit()
    app = FastAPI()
    app.include_router(leads.router, prefix="/api")
    token = pm.set_active_mode(pm.ProductMode.SECURITY_INVESTIGATION)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/leads/" + DOM)
            assert response.status_code == 200
            assert response.json()["leads"][0]["eligibility"] == "eligible"
            for age in [datetime.now(timezone.utc) - timedelta(days=3650), None]:
                async with sessions() as session:
                    await session.execute(update(Contact).values(last_verified=age))
                    await session.commit()
                row = (await client.get("/api/leads/" + DOM)).json()["leads"][0]
                assert row["verification"] == "provider_verified"
                assert row["needs_reverification"]
                assert row["eligibility"] != "eligible"
            assert (await client.get("/api/leads/" + DOM + "?mode=invalid")).status_code == 400
    finally:
        pm._ACTIVE_MODE.reset(token)
        await engine.dispose()


async def test_retained_negative_retracts_existing_pool_and_aggregate(setup):
    ctx = context()
    cand = candidate(setup)
    ctx.signal_pool.emit_email(cand.email, source="company_pattern_index", is_inference=True)
    finding = pav._pattern_candidate_finding(cand, pav.EmployeeNameResult(name="Jane Smith"))
    ctx.pattern_run_state.resolver.record_signal(cand.email, NS(status="not_found"))
    assert ctx.signal_pool.get_emails(DOM) == []
    assert (
        _aggregate(
            DOM, {"pattern_and_verify": module([finding])}, resolver=ctx.pattern_run_state.resolver
        )
        == []
    )
    await ctx.signal_pool.close()


@pytest.mark.parametrize("sources", ["permutation_mx_valid", ["permutation_mx_valid"]])
def test_legacy_inference_is_never_observation(setup, sources):
    cand = candidate(setup)
    corpus = pav._pattern_candidate_finding(cand, pav.EmployeeNameResult(name="Jane Smith"))
    legacy = {
        "metadata": {
            "email": "j.smith@" + DOM,
            "source_name": "Jane Smith",
            "source_type": sources,
            "verification_status": "unverified",
        }
    }
    for findings in ([legacy, corpus], [corpus, legacy]):
        final = _aggregate(DOM, {"pattern_and_verify": module(findings)})
        assert cand.email in {e.email for e in final}
        assert all(
            e.verification == "unverified" and e.confidence_label != "CONFIRMED" for e in final
        )
    assert classify_evidence_kind({"source_type": sources, "email": cand.email}) == "inferred"


@pytest.mark.parametrize("order", [("confirmed", "not_found"), ("not_found", "confirmed")])
def test_conflicting_oracle_evidence_cannot_keep_positive_label(setup, order):
    resolver = CanonicalResolver()
    cand = pc._upgrade_confirmed(candidate(setup), mode=ORG)
    for status in order:
        resolver.record_signal(cand.email, NS(status=status))
    finding = pav._pattern_candidate_finding(cand, pav.EmployeeNameResult(name="Jane Smith"))
    final = _aggregate(DOM, {"pattern_and_verify": module([finding])}, resolver=resolver)
    assert len(final) == 1
    assert final[0].verification == "unverified"
    assert final[0].confidence_label != "CONFIRMED"


async def test_batch_deduplicates_and_maps_shuffled_verdicts(setup):
    first, second = candidate(setup), candidate(setup, "Bob Jones")
    calls = []

    class Oracle:
        async def verify_batch(self, emails):
            calls.append(emails)
            return [
                NS(email=e, status="verified" if e == first.email else "not_found", exists=None)
                for e in reversed(emails)
            ]

    result = await pc.verify_pattern_candidates(
        [first, first, second], mode=ORG, verifier=Oracle(), max_verifications=2
    )
    assert calls == [[first.email, second.email]]
    assert [c.verification if c else None for c in result] == [
        "provider_verified",
        "provider_verified",
        None,
    ]


async def test_low_name_and_apply_error_accounted_on_actual_paths(setup, monkeypatch):
    ctx = context()
    findings, _ = await _run_pattern_for_name({"name": "Jane Smith", "confidence": 0.01}, ctx)
    assert not findings
    pairs, spray, meta = pav._company_pattern_pass(
        [pav.EmployeeNameResult(name="Jane Smith", confidence=0.01)],
        DOM,
        run_state=ctx.pattern_run_state,
        signal_pool=ctx.signal_pool,
    )
    assert not pairs and not spray
    assert meta["generation_decisions"] == {"low_name_evidence": 1}

    def fail(*a, **k):
        raise ValueError("invalid fixture")

    monkeypatch.setattr(setup, "apply", fail)
    assert not (await _run_pattern_for_name({"name": "Jane Smith", "confidence": 0.9}, ctx))[0]
    assert ctx.module_results["pattern_and_verify"].metadata["generation_decisions"] == {
        "low_name_evidence": 1,
        "apply_error": 1,
    }
    await ctx.signal_pool.close()


@pytest.mark.parametrize("reverse", [False, True])
async def test_role_selection_observed_precedence_and_rejected_fallback(
    setup, monkeypatch, reverse
):
    monkeypatch.setattr(settings, "enable_pattern_oracle_verify", False)
    setup._idx[DOM]["role_overrides"] = {
        "executive": {
            "pattern": "P06",
            "support_n": 990,
            "considered_n": 1000,
            "confidence": 0.99,
        }
    }
    ctx = context()

    async def titled():
        await _run_pattern_for_name({"name": "Jane Smith", "title": "CEO", "confidence": 0.9}, ctx)

    if reverse:
        await batch(ctx)
        await titled()
    else:
        await titled()
        await batch(ctx)

    def resolve():
        return _aggregate(DOM, ctx.module_results, resolver=ctx.pattern_run_state.resolver)

    assert [e.email for e in resolve()] == ["j.smith@" + DOM]
    # Rejecting the chosen variant must expose the retained alternative.
    ctx.pattern_run_state.resolver.record_signal("j.smith@" + DOM, NS(status="not_found"))
    assert [e.email for e in resolve()] == ["jane.smith@" + DOM]
    observed = {
        "metadata": {
            "email": "jane@" + DOM,
            "source_type": "common_crawl_single",
            "name": "Jane Smith",
        }
    }
    ctx.module_results["page"] = module([observed])
    assert [e.email for e in resolve()] == ["jane@" + DOM]
    await ctx.signal_pool.close()


def test_middle_name_identity_does_not_retire_distinct_person(setup):
    corpus = pav._pattern_candidate_finding(
        candidate(setup), pav.EmployeeNameResult(name="Jane Ann Smith")
    )
    observed = {
        "metadata": {
            "email": "jane.b@" + DOM,
            "source_type": "common_crawl_single",
            "name": "Jane Beth Smith",
        }
    }
    assert len(_aggregate(DOM, {"pattern_and_verify": module([corpus, observed])})) == 2


def test_late_observed_arrival_retires_inference_at_export_seam(setup):
    # Capstone finding: an observed address for a person that arrives AFTER the
    # mid-run aggregate (a slow discovery module completing under soft-timeout, or
    # the enrichment waterfall) must still retire the already-emitted pattern guess
    # for that person at the finalization/export seam. This injects the late arrival
    # rather than running person-selection over an already-complete set.
    ctx = context()
    cand = candidate(setup)  # jane.smith@ (P04) — the inference
    corpus = pav._pattern_candidate_finding(cand, pav.EmployeeNameResult(name="Jane Smith"))
    # Mid-run aggregate BEFORE the observed address exists → the guess is (correctly)
    # kept at this point.
    mid = _aggregate(
        DOM, {"pattern_and_verify": module([corpus])}, resolver=ctx.pattern_run_state.resolver
    )
    assert cand.email in {e.email for e in mid}

    # A DIFFERENT localpart, real observed address for the SAME person, discovered
    # late and merged into the finalized email set after the aggregate ran.
    observed = HarvestedEmail(
        email="j.smith@" + DOM,
        on_domain=True,
        is_role=False,
        role_match_type=None,
        confidence_score=0.95,
        confidence_label="CONFIRMED",
        evidence=[
            {"module": "github_domain_commits",
             "metadata": {"source_type": "github_commit_author", "email": "j.smith@" + DOM}},
            {"module": "signal_pool", "metadata": {"name": "Jane Smith"}},
        ],
    )
    complete = list(mid) + [observed]
    # Without the final pass (the shipped bug) BOTH the guess and the real address
    # would be exported.
    assert {cand.email, "j.smith@" + DOM} <= {e.email for e in complete}

    # The finalization/export seam re-runs person-selection over the complete set:
    # the real observed address retires the pattern guess.
    final = _finalize_person_selection(ctx, complete)
    emails = {e.email for e in final}
    assert "j.smith@" + DOM in emails
    assert cand.email not in emails


async def test_observed_evidence_survives_module_replacement(setup):
    ctx = context()
    observed = {
        "metadata": {
            "email": "jane@" + DOM,
            "source_type": "common_crawl_single",
            "name": "Jane Smith",
        }
    }
    _record_module_result(ctx, "page", module([observed]))
    _record_module_result(ctx, "page", module([]))
    corpus = pav._pattern_candidate_finding(
        candidate(setup), pav.EmployeeNameResult(name="Jane Smith")
    )
    _record_module_result(ctx, "pattern_and_verify", module([corpus]))
    final = _aggregate(DOM, ctx.module_results, resolver=ctx.pattern_run_state.resolver)
    assert [e.email for e in final] == ["jane@" + DOM]
    # Projection never discards the retained alternative: a subsequent negative
    # observation verdict allows the retained generated mailbox to surface.
    ctx.pattern_run_state.resolver.record_signal("jane@" + DOM, NS(status="not_found"))
    final = _aggregate(DOM, ctx.module_results, resolver=ctx.pattern_run_state.resolver)
    assert [e.email for e in final] == ["jane.smith@" + DOM]
    await ctx.signal_pool.close()


async def test_later_validation_negative_flows_through_retained_evidence(setup):
    ctx = context()
    finding = pav._pattern_candidate_finding(
        candidate(setup), pav.EmployeeNameResult(name="Jane Smith")
    )
    _record_module_result(ctx, "pattern_and_verify", module([finding]))
    negative = {"metadata": {"email": candidate(setup).email, "verification_status": "not_found"}}
    _record_module_result(ctx, "mailbox_validation", module([negative]))
    assert _aggregate(DOM, ctx.module_results, resolver=ctx.pattern_run_state.resolver) == []
    await ctx.signal_pool.close()


async def test_considered_denominator_survives_oracle_and_export(setup):
    class Oracle:
        async def verify_batch(self, emails):
            return [NS(email=e, status="verified", exists=True) for e in emails]

    cand = await pc.verify_pattern_candidate(candidate(setup), mode=ORG, verifier=Oracle())
    assert cand.considered_n == 10000
    assert cand.observation["claim"]["considered_n"] == 10000
    assert cand.as_harvested_email().evidence[0]["metadata"]["considered_n"] == 10000
    finding = pav._pattern_candidate_finding(cand, pav.EmployeeNameResult(name="Jane Smith"))
    assert (
        _aggregate(DOM, {"pattern_and_verify": module([finding])})[0].evidence[0]["metadata"][
            "considered_n"
        ]
        == 10000
    )


def test_passive_and_dns_scoring_preserve_cap_and_corpus_override(setup):
    from backend.core.domain_harvest_orchestrator import apply_domain_email_dns_signals

    cand = candidate(setup)
    legacy = {
        "metadata": {
            "email": cand.email,
            "source_name": "Jane Smith",
            "pattern_template": "{first}.{last}@{domain}",
            "is_inference": True,
            "source_types": [
                "permutation_mx_valid",
                "permutation_gravatar_hit",
                "permutation_unverified_{first}_{last}",
            ],
        }
    }
    for include_corpus in [False, True]:
        findings = [legacy]
        if include_corpus:
            findings.append(
                pav._pattern_candidate_finding(cand, pav.EmployeeNameResult(name="Jane Smith"))
            )
        final = _aggregate(DOM, {"pattern_and_verify": module(findings)})
        score = final[0].confidence_score
        assert final[0].verification == "unverified"
        assert final[0].confidence_label != "CONFIRMED"
        apply_domain_email_dns_signals(final, {"spf_present": True, "dmarc_strict": True})
        assert final[0].confidence_label != "CONFIRMED"
        if include_corpus:
            assert final[0].confidence_score == score


def test_content_and_mx_change_cache_identity(setup, tmp_path, monkeypatch):
    from backend.core.corpus_store import scope_signature

    raw = {"_meta": dict(setup.meta), DOM: dict(setup._idx[DOM])}
    signatures = []
    for changes in ({}, {"pattern": "P06"}, {"mx": "other"}):
        raw[DOM].update(changes)
        path = tmp_path / "changed.gz"
        with gzip.open(path, "wt") as f:
            json.dump(raw, f)
        monkeypatch.setattr(cpi, "_SINGLETON", cpi.CompanyPatternIndex(path))
        signatures.append(
            scope_signature(mode=ORG.value, company_pattern_index_version=cpi.index_version())
        )
    assert len(set(signatures)) == 3


def test_current_record_rejects_missing_denominator_and_bad_ratio(setup):
    setup.meta["confidence_basis"] = cpi.CONFIDENCE_BASIS
    for updates in ({"considered_n": None}, {"confidence": 0.995}, {"support_n": 10001}):
        original = dict(setup._idx[DOM])
        setup._idx[DOM].update(updates)
        with pytest.raises(cpi.MalformedPatternRecord):
            setup.apply("Jane Smith", DOM)
        setup._idx[DOM] = original


async def test_persisted_cache_rejects_artifact_flag_and_unsigned_reuse(
    setup, tmp_path, monkeypatch
):
    from datetime import datetime, timezone
    from unittest.mock import AsyncMock

    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from backend.core import corpus_store as store
    from backend.core.domain_harvest_orchestrator import DomainHarvestResult
    from backend.db import database
    from backend.db.models import Base, CrawlSnapshot

    engine = create_async_engine("sqlite+aiosqlite:///" + (tmp_path / "cache.db").as_posix())
    async with engine.begin() as con:
        await con.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(database, "AsyncSessionLocal", sessions)
    monkeypatch.setattr(database, "init_db", AsyncMock())
    monkeypatch.setattr(store, "_SCHEMA_READY", True)
    monkeypatch.setattr(settings, "harvest_cache_enabled", True)
    signature = store.scope_signature(
        mode=ORG.value, company_pattern_index_version=cpi.index_version()
    )
    now = datetime.now(timezone.utc).isoformat()
    result = DomainHarvestResult(
        domain=DOM,
        started_at=now,
        completed_at=now,
        duration_seconds=0,
        module_results={},
        unique_emails=[candidate(setup).as_harvested_email()],
        total_unique_emails=1,
        high_confidence_count=0,
        likely_confidence_count=1,
        medium_confidence_count=0,
        low_confidence_count=0,
        role_account_count=0,
        personal_email_count=1,
        metadata={"mode": ORG.value, store.SCOPE_SIGNATURE_KEY: signature},
    )
    try:
        await store.write_back(DOM, result)
        cached = await store.read_fresh_crawl(DOM, expected_scope=signature)
        assert cached is not None
        assert cached.unique_emails[0].verification == "unverified"
        changed = store.scope_signature(
            mode=ORG.value, company_pattern_index_version="new-artifact"
        )
        assert await store.read_fresh_crawl(DOM, expected_scope=changed) is None
        flags = store.scope_signature(
            mode=ORG.value,
            company_pattern_index_version=cpi.index_version(),
            enable_pattern_oracle_verify=False,
        )
        assert await store.read_fresh_crawl(DOM, expected_scope=flags) is None
        async with sessions() as session:
            await session.execute(
                update(CrawlSnapshot).values(result_json={"metadata": {"mode": ORG.value}})
            )
            await session.commit()
        assert await store.read_fresh_crawl(DOM, expected_scope=signature) is None
    finally:
        await engine.dispose()
