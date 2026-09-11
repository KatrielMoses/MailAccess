"""0.16.0 Phase 4 — pipeline wiring for the corpus company email-pattern index.

Executable contract for wiring the offline index (Phase 2 ``apply`` -> Phase 3
``pattern_email_to_candidate``) into the live harvest flow:

* on an *indexed* domain, each discovered-but-unresolved name yields exactly ONE
  governed, unverified corpus-pattern email — graded <= Risky, verdicted
  review/research-only, provenance present — and the permutation spray is skipped
  for those names;
* on a *non-indexed* domain the module output is byte-identical to pre-Phase-4;
* the feature flag reverts to pre-Phase-4 behaviour exactly;
* an observed on-domain address for a person suppresses the pattern guess
  (observed beats inferred);
* the aggregator propagates ``verification="unverified"`` and honours the
  per-candidate ``applied_confidence`` override, order-independently;
* the verification claim flows through corpus_store -> read_leads and the export
  eligibility gate caps the lead at REVIEW.

Pure/unit + a self-managed temp SQLite DB for the corpus round-trip. No network.
"""

from __future__ import annotations

import asyncio
import gzip
import importlib
import json
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import backend.config as config_mod
from backend.core import company_pattern_index as cpi
from backend.core import corpus_store as C
from backend.core import product_mode
from backend.core.company_pattern_index import CompanyPatternIndex
from backend.core.domain_harvest_orchestrator import (
    DomainHarvestResult,
    HarvestedEmail,
    _aggregate,
)
from backend.core.eligibility import evaluate
from backend.core.pattern_candidate import pattern_email_to_candidate
from backend.core.product_mode import ProductMode, policy_status_for_mode
from backend.core.suppression import SuppressionIndex
from backend.modules import pattern_and_verify as pav
from backend.modules.base import ModuleResult, ModuleStatus
from backend.modules.pattern_and_verify import (
    EmployeeNameResult,
    PatternAndVerifyModule,
    _pattern_candidate_finding,
)

# --------------------------------------------------------------------------- #
# Fixtures — synthetic index, empty suppression, active public-business mode.
# --------------------------------------------------------------------------- #
_FIXTURE_INDEX = {
    "_meta": {"schema": "company-patterns/1", "pattern_enum": [f"P{i:02d}" for i in range(1, 16)]},
    # first.last base (P04), lots of support -> a healthy applied_confidence.
    "role-corp.com": {"pattern": "P04", "support_n": 400, "confidence": 0.9, "mx": "m365"},
}
_EMPTY_SUPPRESSION = SuppressionIndex(frozenset(), frozenset(), frozenset(), {})


def _emp(name: str, *, title: str | None = None, confidence: float = 0.6) -> EmployeeNameResult:
    return EmployeeNameResult(name=name, confidence=confidence, title_or_role=title)


@pytest.fixture
def index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CompanyPatternIndex:
    path = tmp_path / "company_patterns.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(_FIXTURE_INDEX, fh)
    idx = CompanyPatternIndex(path)
    assert idx.available
    # Route both the module and the aggregator through the synthetic index.
    monkeypatch.setattr(cpi, "_SINGLETON", idx)
    # Keep the suppression check offline / empty (the export boundary is the
    # authoritative gate; this belt-and-braces check must not hit a DB in-unit).
    monkeypatch.setattr(pav, "load_index_sync", lambda: _EMPTY_SUPPRESSION)
    return idx


@pytest.fixture
def public_mode(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    token = product_mode.set_active_mode(ProductMode.PUBLIC_BUSINESS_CONTACT)
    try:
        yield
    finally:
        product_mode._ACTIVE_MODE.reset(token)


class _FakePool:
    """Minimal signal-pool stand-in exposing the ``get_emails`` read the pattern
    pass uses for observed-vs-inferred dedup."""

    def __init__(self, emails: list[dict[str, Any]]) -> None:
        self._emails = emails

    def get_emails(self, domain: str | None = None) -> list[dict[str, Any]]:
        return self._emails


def _run(mod: PatternAndVerifyModule, domain: str, **kwargs: Any) -> ModuleResult:
    return asyncio.run(
        mod.run(domain, enable_smtp=False, enable_native_validation=False, **kwargs)
    )


def _pattern_findings(result: ModuleResult) -> list[dict[str, Any]]:
    return [
        f
        for f in (result.findings or [])
        if (f.get("metadata") or {}).get("source_type") == "company_pattern_index"
    ]


# --------------------------------------------------------------------------- #
# 1. Indexed domain -> one governed unverified email per unresolved name.
# --------------------------------------------------------------------------- #
def test_indexed_domain_emits_one_governed_email_per_name(
    index: CompanyPatternIndex, public_mode: None
) -> None:
    mod = PatternAndVerifyModule()
    result = _run(
        mod,
        "role-corp.com",
        employee_names=[_emp("Jane Smith"), _emp("John Doe")],
    )
    assert result.status == ModuleStatus.SUCCESS

    pat = _pattern_findings(result)
    # Exactly one pattern email per name, and NO permutation-spray findings.
    assert len(pat) == 2
    assert len(result.findings) == 2
    emails = sorted(f["metadata"]["email"] for f in pat)
    assert emails == ["jane.smith@role-corp.com", "john.doe@role-corp.com"]

    for f in pat:
        md = f["metadata"]
        assert md["verification"] == "unverified"
        assert md["is_inference"] is True
        assert md["provenance"].startswith("company email pattern (P04")
        # Never falsely Valid; verdicted for review/research (never auto-eligible).
        assert md["deliverability_grade"] != "Valid"
        assert md["eligibility"] in {"review", "research-only"}

    meta = result.metadata["company_pattern_index"]
    assert meta["enabled"] is True
    assert meta["domain_indexed"] is True
    assert meta["emails"] == 2
    # The spray path saw none of these names.
    assert result.metadata["total_patterns_generated"] == 0
    assert result.metadata["employee_names_processed"] == 2


def test_title_routes_role_override_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, public_mode: None
) -> None:
    # A domain whose executives use f.last while ICs use first.last.
    fixture = {
        "_meta": {"schema": "company-patterns/1"},
        "role-corp.com": {
            "pattern": "P04",
            "support_n": 40,
            "confidence": 0.8,
            "role_overrides": {
                "executive": {"pattern": "P06", "support_n": 12, "confidence": 0.75}
            },
            "mx": "m365",
        },
    }
    path = tmp_path / "idx.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(fixture, fh)
    monkeypatch.setattr(cpi, "_SINGLETON", CompanyPatternIndex(path))
    monkeypatch.setattr(pav, "load_index_sync", lambda: _EMPTY_SUPPRESSION)

    mod = PatternAndVerifyModule()
    result = _run(
        mod,
        "role-corp.com",
        employee_names=[_emp("Jane Smith", title="Chief Executive Officer")],
    )
    (finding,) = _pattern_findings(result)
    # Executive title -> P06 (f.last) override, not the P04 base.
    assert finding["metadata"]["email"] == "j.smith@role-corp.com"
    assert finding["metadata"]["role_used"] == "executive"


# --------------------------------------------------------------------------- #
# 2. Non-indexed domain -> byte-identical to pre-Phase-4 (spray untouched).
# --------------------------------------------------------------------------- #
def test_non_indexed_domain_is_unchanged(
    index: CompanyPatternIndex, public_mode: None
) -> None:
    mod = PatternAndVerifyModule()
    names = [_emp("Jane Smith"), _emp("John Doe")]

    # Flag ON but domain NOT in the index -> apply() returns None for every name.
    with_flag = _run(mod, "not-indexed.example", employee_names=list(names))
    # Flag OFF entirely.
    import backend.config as cfg

    original = cfg.settings.enable_company_pattern_index
    cfg.settings.enable_company_pattern_index = False
    try:
        without_flag = _run(mod, "not-indexed.example", employee_names=list(names))
    finally:
        cfg.settings.enable_company_pattern_index = original

    assert _pattern_findings(with_flag) == []
    assert _pattern_findings(without_flag) == []
    # The spray findings (the servable output) are identical either way.
    assert with_flag.findings == without_flag.findings
    assert with_flag.metadata["total_patterns_generated"] == (
        without_flag.metadata["total_patterns_generated"]
    )
    assert with_flag.metadata["total_patterns_generated"] > 0


# --------------------------------------------------------------------------- #
# 3. Flag off on an indexed domain -> reverts to the spray exactly.
# --------------------------------------------------------------------------- #
def test_flag_off_reverts_to_spray(
    index: CompanyPatternIndex, public_mode: None
) -> None:
    import backend.config as cfg

    mod = PatternAndVerifyModule()
    original = cfg.settings.enable_company_pattern_index
    cfg.settings.enable_company_pattern_index = False
    try:
        result = _run(mod, "role-corp.com", employee_names=[_emp("Jane Smith")])
    finally:
        cfg.settings.enable_company_pattern_index = original

    assert _pattern_findings(result) == []
    assert result.metadata["company_pattern_index"]["enabled"] is False
    # The spray produced the guesses instead.
    assert result.metadata["total_patterns_generated"] > 0


# --------------------------------------------------------------------------- #
# 4. Observed beats inferred — no pattern guess for a resolved person.
# --------------------------------------------------------------------------- #
def test_observed_on_domain_email_suppresses_pattern_guess(
    index: CompanyPatternIndex, public_mode: None
) -> None:
    # The harvest already observed Jane's real address (different local-part) with
    # her name attached, but has nothing for John.
    pool = _FakePool(
        [
            {
                "email": "j.smith@role-corp.com",
                "metadata": {"name": "Jane Smith"},
            }
        ]
    )
    mod = PatternAndVerifyModule()
    result = _run(
        mod,
        "role-corp.com",
        employee_names=[_emp("Jane Smith"), _emp("John Doe")],
        signal_pool=pool,
    )
    pat = _pattern_findings(result)
    emails = [f["metadata"]["email"] for f in pat]
    # Only John gets a guess; Jane is already resolved.
    assert emails == ["john.doe@role-corp.com"]
    assert result.metadata["company_pattern_index"]["skipped_observed"] == 1


def test_observed_same_localpart_collision_is_skipped(
    index: CompanyPatternIndex, public_mode: None
) -> None:
    # Observed address equals what the pattern would generate (same string) but
    # carries no name — the local-part collision still suppresses the guess.
    pool = _FakePool([{"email": "jane.smith@role-corp.com", "metadata": {}}])
    mod = PatternAndVerifyModule()
    result = _run(
        mod, "role-corp.com", employee_names=[_emp("Jane Smith")], signal_pool=pool
    )
    assert _pattern_findings(result) == []
    assert result.metadata["company_pattern_index"]["skipped_observed"] == 1


# --------------------------------------------------------------------------- #
# 5. Aggregator — verification propagation + applied_confidence override.
# --------------------------------------------------------------------------- #
def _candidate_finding(index: CompanyPatternIndex, name: str, domain: str) -> dict[str, Any]:
    pe = index.apply(name, domain)
    assert pe is not None
    candidate = pattern_email_to_candidate(
        pe,
        mode=ProductMode.PUBLIC_BUSINESS_CONTACT,
        suppression_index=_EMPTY_SUPPRESSION,
    )
    return _pattern_candidate_finding(candidate, _emp(name))


def test_aggregator_marks_pure_inference_unverified(index: CompanyPatternIndex) -> None:
    finding = _candidate_finding(index, "Jane Smith", "role-corp.com")
    results = {
        "pattern_and_verify": ModuleResult(status=ModuleStatus.SUCCESS, findings=[finding])
    }
    emails = _aggregate("role-corp.com", results)
    (entry,) = emails
    assert entry.email == "jane.smith@role-corp.com"
    assert entry.verification == "unverified"
    # The score tracks the calibrated applied_confidence override (well above the
    # 0.30 fallback weight), not the fixed source weight.
    assert entry.confidence_score > 0.30


def test_aggregator_observed_beats_inferred_on_collision(index: CompanyPatternIndex) -> None:
    pattern = _candidate_finding(index, "Jane Smith", "role-corp.com")
    observed = {
        "platform": "commoncrawl_email",
        "metadata": {
            "email": "jane.smith@role-corp.com",
            "source_type": "common_crawl_single",
        },
    }
    results = {
        "commoncrawl_email": ModuleResult(status=ModuleStatus.SUCCESS, findings=[observed]),
        "pattern_and_verify": ModuleResult(status=ModuleStatus.SUCCESS, findings=[pattern]),
    }
    emails = _aggregate("role-corp.com", results)
    (entry,) = emails
    # Same mailbox observed by a real source -> the observation wins, so the
    # verification claim is cleared (never caps a real hit at REVIEW).
    assert entry.verification is None


def test_aggregator_is_order_independent(index: CompanyPatternIndex) -> None:
    pattern = _candidate_finding(index, "Jane Smith", "role-corp.com")
    other = {
        "platform": "commoncrawl_email",
        "metadata": {"email": "ceo@role-corp.com", "source_type": "common_crawl_single"},
    }

    def _fingerprint(findings: list[dict[str, Any]]) -> dict[str, tuple[Any, Any]]:
        results = {
            "m": ModuleResult(status=ModuleStatus.SUCCESS, findings=findings)
        }
        return {
            e.email: (e.confidence_score, e.verification)
            for e in _aggregate("role-corp.com", results)
        }

    assert _fingerprint([pattern, other]) == _fingerprint([other, pattern])


# --------------------------------------------------------------------------- #
# 6. Flows through corpus_store -> read_leads, and the export gate caps at REVIEW.
# --------------------------------------------------------------------------- #
@pytest.fixture
def corpus_db() -> Iterator[Any]:
    path = Path(tempfile.mkdtemp(prefix="cpi-wiring-"))
    config_mod.settings.database_url = f"sqlite+aiosqlite:///{(path / 'c.db').as_posix()}"
    import backend.db.database as db

    importlib.reload(db)

    async def _setup() -> None:
        await db.init_db()
        await db.engine.dispose()

    asyncio.run(_setup())
    try:
        yield db
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _harvest_result_with_pattern_lead() -> DomainHarvestResult:
    entry = HarvestedEmail(
        email="jane.smith@role-corp.com",
        on_domain=True,
        is_role=False,
        role_match_type=None,
        confidence_score=0.82,
        confidence_label="LIKELY",
        found_by_modules=["company_pattern_index"],
        source_count=1,
        evidence=[
            {
                "module": "company_pattern_index",
                "metadata": {
                    "source_type": "company_pattern_index",
                    "provenance": "company email pattern (P04, 400 verified samples, conf 0.9)",
                    "verification": "unverified",
                    "is_inference": True,
                },
            }
        ],
        deliverability_grade="Risky",
        verification="unverified",
    )
    return DomainHarvestResult(
        domain="role-corp.com",
        started_at="2026-09-11T00:00:00Z",
        completed_at="2026-09-11T00:05:00Z",
        duration_seconds=300.0,
        module_results={},
        unique_emails=[entry],
        total_unique_emails=1,
        high_confidence_count=0,
        likely_confidence_count=1,
        medium_confidence_count=0,
        low_confidence_count=0,
        role_account_count=0,
        personal_email_count=1,
    )


def test_pattern_lead_flows_to_read_leads_as_unverified(corpus_db: Any) -> None:
    asyncio.run(C.write_back("role-corp.com", _harvest_result_with_pattern_lead()))
    leads = asyncio.run(C.read_leads("role-corp.com"))
    assert leads["total"] == 1
    lead = leads["leads"][0]
    assert lead["email"] == "jane.smith@role-corp.com"
    # The verification claim survived into the servable lead + its provenance.
    assert lead["verification"] == "unverified"
    assert lead["found_by_modules"] == ["company_pattern_index"]


def test_export_eligibility_gate_caps_unverified_at_review() -> None:
    entry = _harvest_result_with_pattern_lead().unique_emails[0]
    # A high research confidence + a sendable grade would normally clear to
    # ELIGIBLE in a lead-gen mode; the unverified claim caps it at REVIEW.
    verdict = evaluate(
        mode=ProductMode.PUBLIC_BUSINESS_CONTACT,
        policy_status=policy_status_for_mode(ProductMode.PUBLIC_BUSINESS_CONTACT),
        suppressed=False,
        confidence=entry.confidence_score,
        deliverability_grade=entry.deliverability_grade,
        verification=entry.verification,
    )
    assert verdict.verdict.value == "review"

    # Same record WITHOUT the verification claim (an observed address) would clear.
    cleared = evaluate(
        mode=ProductMode.PUBLIC_BUSINESS_CONTACT,
        policy_status=policy_status_for_mode(ProductMode.PUBLIC_BUSINESS_CONTACT),
        suppressed=False,
        confidence=entry.confidence_score,
        deliverability_grade=entry.deliverability_grade,
        verification=None,
    )
    assert cleared.verdict.value == "eligible"
