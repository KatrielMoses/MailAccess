"""0.16.0 correctness fix-pass — the boundary net.

These tests exercise the *serving boundaries* (reactive live path, aggregation +
persistence, find-email, oracle cross-tenant batch, cache signature, normalization
differential, abstention) rather than the helpers, so "green" means the end-to-end
guarantee holds — the gap Astra's audit flagged.

Grouped by root:
  A — one governed generator on the live/reactive path + shared run-state.
  B — cap + classify in the ONE canonical finalization.
  D — serving-boundary governance (find-email, export, read_leads, cache).
  E — symmetry + edge cases (m365 cross-tenant, abstention, normalization, Li Li).

Pure/unit + a fake signal pool + injected fake oracle. No network.
"""

from __future__ import annotations

import asyncio
import gzip
import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import backend.config as config_mod
from backend.core import company_pattern_index as cpi
from backend.core import corpus_store as C
from backend.core import product_mode
from backend.core.company_pattern_index import (
    CompanyPatternIndex,
    _index_norm,
    index_version,
    roundtrip_gate,
)
from backend.core.corpus_store import scope_signature
from backend.core.domain_harvest_orchestrator import (
    DomainHarvestResult,
    HarvestedEmail,
    _aggregate,
)
from backend.core.eligibility import evaluate
from backend.core.harvest_runner import _run_pattern_for_name
from backend.core.pattern_candidate import (
    DECISION_EMITTED,
    DECISION_ORACLE_REJECTED,
    NameEvidence,
    PatternRunState,
    govern_name_to_candidate,
    pattern_email_to_candidate,
    verify_pattern_candidate,
)
from backend.core.product_mode import ProductMode, policy_status_for_mode
from backend.core.suppression import SuppressionIndex
from backend.modules import pattern_and_verify as pav
from backend.modules.base import ModuleResult, ModuleStatus
from backend.modules.pattern_and_verify import (
    EmployeeNameResult,
    PatternAndVerifyModule,
    _observed_person_index,
    _pattern_candidate_finding,
)

_EMPTY_SUPPRESSION = SuppressionIndex(frozenset(), frozenset(), frozenset(), {})

_FIXTURE_INDEX = {
    "_meta": {"schema": "company-patterns/1", "generated_at": "2026-09-10T00:00:00Z",
              "corpus_snapshot": "test-v1", "domains_emitted": 2},
    "role-corp.com": {"pattern": "P04", "support_n": 400, "confidence": 0.9, "mx": "m365"},
    # A very-high-support domain so applied_confidence clears the CONFIRMED band —
    # used to prove the honesty cap in aggregation.
    "hi-corp.com": {"pattern": "P04", "support_n": 6000, "confidence": 0.995, "mx": "m365"},
}


def _emp(name: str, *, title: str | None = None) -> EmployeeNameResult:
    return EmployeeNameResult(name=name, confidence=0.6, title_or_role=title)


def _write_index(path: Path, data: dict[str, Any]) -> CompanyPatternIndex:
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(data, fh)
    idx = CompanyPatternIndex(path)
    assert idx.available
    return idx


@pytest.fixture
def index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CompanyPatternIndex:
    idx = _write_index(tmp_path / "idx.json.gz", _FIXTURE_INDEX)
    monkeypatch.setattr(cpi, "_SINGLETON", idx)
    monkeypatch.setattr(pav, "load_index_sync", lambda: _EMPTY_SUPPRESSION)
    return idx


@pytest.fixture
def public_mode() -> Iterator[None]:
    token = product_mode.set_active_mode(ProductMode.PUBLIC_BUSINESS_CONTACT)
    try:
        yield
    finally:
        product_mode._ACTIVE_MODE.reset(token)


@pytest.fixture
def security_mode() -> Iterator[None]:
    token = product_mode.set_active_mode(ProductMode.SECURITY_INVESTIGATION)
    try:
        yield
    finally:
        product_mode._ACTIVE_MODE.reset(token)


class _FakePool:
    """Signal-pool stand-in with the emit/get surface the pattern paths use."""

    def __init__(self, seed: list[dict[str, Any]] | None = None) -> None:
        self._by_domain: dict[str, dict[str, dict[str, Any]]] = {}
        for row in seed or []:
            dom = row["email"].split("@", 1)[-1]
            self._by_domain.setdefault(dom, {})[row["email"]] = {
                "email": row["email"],
                "sources": set(row.get("sources") or []),
                "confidence": 0.5,
                "metadata": dict(row.get("metadata") or {}),
            }

    def emit_name(self, *a: Any, **k: Any) -> None:  # noqa: D401
        pass

    def emit_email(self, email: str, source: str, confidence: float = 0.5, **meta: Any) -> None:
        dom = email.split("@", 1)[-1]
        bucket = self._by_domain.setdefault(dom, {})
        entry = bucket.setdefault(
            email, {"email": email, "sources": set(), "confidence": 0.0, "metadata": {}}
        )
        entry["sources"].add(source)
        entry["metadata"].update(meta)

    def get_emails(self, domain: str | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for dom, bucket in self._by_domain.items():
            if domain and dom != domain.strip().lower():
                continue
            for p in bucket.values():
                out.append(
                    {
                        "email": p["email"],
                        "sources": sorted(p["sources"]),
                        "confidence": p["confidence"],
                        "metadata": dict(p["metadata"]),
                    }
                )
        return out


def _ctx(domain: str, pool: _FakePool, run_state: PatternRunState | None = None) -> Any:
    return SimpleNamespace(
        domain=domain,
        pattern_run_state=run_state or PatternRunState(),
        settings=SimpleNamespace(pattern_oracle_max_verifications_per_run=50),
        signal_pool=pool,
        module_results={},
        enable_smtp=False,
    )


class _FakeVerifier:
    """Fake provider oracle: every mailbox reports ``status`` (verify_batch shape)."""

    def __init__(self, status: str) -> None:
        self.status = status

    async def verify_batch(self, emails: list[str], *a: Any, **k: Any) -> list[Any]:
        return [
            SimpleNamespace(email=e, status=self.status, exists=(self.status == "verified"))
            for e in emails
        ]


def _pat_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        f for f in findings
        if (f.get("metadata") or {}).get("source_type") == "company_pattern_index"
    ]


# ======================================================================== #
# Root A — one governed generator on the reactive live path + shared state.
# ======================================================================== #
def test_reactive_worker_emits_one_governed_email(
    index: CompanyPatternIndex, public_mode: None
) -> None:
    pool = _FakePool()
    findings, new_items = asyncio.run(
        _run_pattern_for_name(
            {"name": "Jane Smith", "confidence": 0.9}, _ctx("role-corp.com", pool)
        )
    )
    assert new_items == []
    gov = _pat_findings(findings)
    assert len(gov) == 1
    md = gov[0]["metadata"]
    assert md["email"] == "jane.smith@role-corp.com"
    assert md["verification"] == "unverified"
    assert md["is_inference"] is True
    # The emitted address is tagged inference in the pool (reverse-timing guard).
    rows = pool.get_emails("role-corp.com")
    assert rows and rows[0]["metadata"].get("is_inference") is True


def test_reactive_worker_sprays_on_non_indexed(
    index: CompanyPatternIndex, public_mode: None
) -> None:
    pool = _FakePool()
    findings, _ = asyncio.run(
        _run_pattern_for_name(
            {"name": "Jane Smith", "confidence": 0.9}, _ctx("not-indexed.example", pool)
        )
    )
    assert findings  # the legacy spray produced guesses
    assert _pat_findings(findings) == []  # none are governed company-pattern findings
    # Every spray finding now carries the explicit inference flag (Root B contract).
    assert all(f["metadata"].get("is_inference") is True for f in findings)


def test_reactive_worker_governed_matches_batch(
    index: CompanyPatternIndex, public_mode: None
) -> None:
    pool = _FakePool()
    reactive, _ = asyncio.run(
        _run_pattern_for_name(
            {"name": "Jane Smith", "confidence": 0.9}, _ctx("role-corp.com", pool)
        )
    )
    r_email = _pat_findings(reactive)[0]["metadata"]["email"]

    batch = asyncio.run(
        PatternAndVerifyModule().run(
            "role-corp.com", employee_names=[_emp("Jane Smith")],
            enable_smtp=False, enable_native_validation=False,
        )
    )
    b_email = _pat_findings(batch.findings or [])[0]["metadata"]["email"]
    assert r_email == b_email == "jane.smith@role-corp.com"


def test_observed_index_excludes_generated_inference() -> None:
    pool = _FakePool(
        seed=[
            # a prior GENERATED guess (must NOT count as observed coverage)
            {"email": "jane.smith@role-corp.com", "sources": ["pattern_generated"],
             "metadata": {"is_inference": True, "name": "Jane Smith"}},
            # a real observation (must count)
            {"email": "bob.jones@role-corp.com", "sources": ["common_crawl_single"],
             "metadata": {"name": "Bob Jones"}},
        ]
    )
    locals_, names = _observed_person_index(pool, "role-corp.com")
    assert "jane.smith" not in locals_
    assert ("jane", "smith") not in names
    assert "bob.jones" in locals_
    assert ("bob", "jones") in names


def test_tombstone_not_found_never_regenerates(
    index: CompanyPatternIndex, security_mode: None
) -> None:
    rs = PatternRunState()
    c1 = govern_name_to_candidate(
        NameEvidence("Jane Smith", confidence=0.9),
        "role-corp.com", mode=ProductMode.SECURITY_INVESTIGATION,
        suppression_index=_EMPTY_SUPPRESSION, run_state=rs, index=index,
    )
    assert c1.decision == DECISION_EMITTED and c1.candidate is not None
    dropped = asyncio.run(
        verify_pattern_candidate(
            c1.candidate, mode=ProductMode.SECURITY_INVESTIGATION,
            verifier=_FakeVerifier("not_found"), run_state=rs,
        )
    )
    assert dropped is None
    assert rs.is_tombstoned("jane.smith@role-corp.com")
    # A later governed call for the same person yields NOTHING (tombstoned), never
    # regenerating the known-nonexistent mailbox.
    again = govern_name_to_candidate(
        NameEvidence("Jane Smith", confidence=0.9),
        "role-corp.com", mode=ProductMode.SECURITY_INVESTIGATION,
        suppression_index=_EMPTY_SUPPRESSION, run_state=rs, index=index,
    )
    assert again.decision == DECISION_ORACLE_REJECTED and again.candidate is None


# ======================================================================== #
# Root B — cap + classify in the ONE canonical finalization.
# ======================================================================== #
def _candidate_finding(idx: CompanyPatternIndex, name: str, domain: str) -> dict[str, Any]:
    pe = idx.apply(name, domain)
    assert pe is not None
    cand = pattern_email_to_candidate(
        pe, mode=ProductMode.PUBLIC_BUSINESS_CONTACT, suppression_index=_EMPTY_SUPPRESSION
    )
    return _pattern_candidate_finding(cand, _emp(name))


def test_aggregate_honesty_cap_unverified_never_confirmed(index: CompanyPatternIndex) -> None:
    finding = _candidate_finding(index, "Jane Smith", "hi-corp.com")
    results = {"pattern_and_verify": ModuleResult(status=ModuleStatus.SUCCESS, findings=[finding])}
    (entry,) = _aggregate("hi-corp.com", results)
    assert entry.confidence_score >= 0.85  # would be CONFIRMED absent the cap
    assert entry.confidence_label == "LIKELY"  # capped
    assert entry.confidence_breakdown.get("capped_from_confirmed") is True
    assert entry.verification == "unverified"


def test_permutation_inference_collision_does_not_clear_gate(index: CompanyPatternIndex) -> None:
    pattern = _candidate_finding(index, "Jane Smith", "role-corp.com")
    # A permutation GUESS on the same mailbox — is_inference, unverified. It must
    # NOT be classified as an observation that clears the verification gate.
    perm = {
        "platform": "pattern_and_verify",
        "metadata": {
            "email": "jane.smith@role-corp.com",
            "source_type": "permutation_unverified_{first}_{last}",
            "verification": "unverified",
            "verification_status": "unverified",
            "is_inference": True,
        },
    }
    results = {
        "pattern_and_verify": ModuleResult(status=ModuleStatus.SUCCESS, findings=[pattern, perm])
    }
    (entry,) = _aggregate("role-corp.com", results)
    assert entry.verification == "unverified"  # NOT cleared to None by the guess
    verdict = evaluate(
        mode=ProductMode.PUBLIC_BUSINESS_CONTACT,
        policy_status=policy_status_for_mode(ProductMode.PUBLIC_BUSINESS_CONTACT),
        suppressed=False,
        confidence=entry.confidence_score,
        deliverability_grade="Risky",
        verification=entry.verification,
    )
    assert verdict.verdict.value in {"review", "research-only"}  # never eligible w/o oracle


def test_smtp_verified_permutation_counts_as_observed(index: CompanyPatternIndex) -> None:
    pattern = _candidate_finding(index, "Jane Smith", "role-corp.com")
    verified = {
        "platform": "pattern_and_verify",
        "metadata": {
            "email": "jane.smith@role-corp.com",
            "source_type": "permutation_verified",
            "verification_status": "verified",
        },
    }
    results = {
        "pattern_and_verify": ModuleResult(
            status=ModuleStatus.SUCCESS, findings=[pattern, verified]
        )
    }
    (entry,) = _aggregate("role-corp.com", results)
    # An SMTP-verified permutation IS an observation → the unverified cap is cleared.
    assert entry.verification is None


def test_person_reconciliation_observed_retires_inference(index: CompanyPatternIndex) -> None:
    pattern = _candidate_finding(index, "Jane Smith", "role-corp.com")  # jane.smith@
    observed = {
        "platform": "structured_page",
        "metadata": {
            "email": "j.smith@role-corp.com",
            "source_type": "structured_page",
            "name": "Jane Smith",
        },
    }
    results = {
        "structured": ModuleResult(status=ModuleStatus.SUCCESS, findings=[observed]),
        "pattern_and_verify": ModuleResult(status=ModuleStatus.SUCCESS, findings=[pattern]),
    }
    addrs = {e.email for e in _aggregate("role-corp.com", results)}
    assert "j.smith@role-corp.com" in addrs
    assert "jane.smith@role-corp.com" not in addrs  # inference retired by the observed person


# ======================================================================== #
# Root D — serving-boundary governance.
# ======================================================================== #
def test_find_email_enforces_suppression(
    index: CompanyPatternIndex, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    import backend.core.pattern_candidate as pc
    from cli.main import app

    class _HitIndex:
        def hit(self, *, email: str | None = None, company: str | None = None) -> Any:
            return object() if email else None

    monkeypatch.setattr(pc, "load_index_sync", lambda: _HitIndex())
    result = CliRunner().invoke(
        app, ["find-email", "--name", "Jane Smith", "--domain", "role-corp.com"]
    )
    assert result.exit_code == 0
    assert "jane.smith@role-corp.com" not in result.output
    assert "Suppressed" in result.output


def test_csv_export_carries_verification_and_eligibility() -> None:
    from backend.core.domain_harvest_report import format_harvest_csv_export

    result = _result_with_unverified_lead()
    csv_str = format_harvest_csv_export(result)
    header, first_row = csv_str.splitlines()[0], csv_str.splitlines()[1]
    assert "verification" in header
    assert "eligibility" in header
    assert "unverified" in first_row


def test_json_export_carries_top_level_verification() -> None:
    from backend.core.domain_harvest_report import format_harvest_json_export

    payload = format_harvest_json_export(_result_with_unverified_lead())
    row = payload["emails"][0]
    assert row["verification"] == "unverified"
    assert row["eligibility"] in {"review", "research-only"}


def test_read_leads_attaches_real_eligibility() -> None:
    # Brief B — the serving mode is passed EXPLICITLY (no ContextVar reliance). The
    # decayed served score drives the verdict; here fresh rows (no last_verified
    # decay applied) serve at their given confidence.
    leads = [
        {"policy_status": "authorized-supplied", "confidence_score": 0.9,
         "served_confidence_score": 0.9, "needs_reverification": False,
         "deliverability_grade": "Risky", "verification": "unverified"},
        {"policy_status": "authorized-supplied", "confidence_score": 0.9,
         "served_confidence_score": 0.9, "needs_reverification": False,
         "deliverability_grade": "Risky", "verification": None},
    ]
    C._attach_lead_eligibility(leads, mode=ProductMode.ORG_AUTHORIZED_VERIFICATION)
    # An unverified inference caps at review even at high confidence...
    assert leads[0]["eligibility"] == "review"
    # ...but an observed address (no verification claim) clears.
    assert leads[1]["eligibility"] == "eligible"


def test_cache_signature_invalidates_on_pattern_flags_and_index() -> None:
    mode = "public-business-contact"
    base = scope_signature(mode=mode, company_pattern_index_version="v1")
    assert base != scope_signature(
        mode=mode, company_pattern_index_version="v1", enable_company_pattern_index=False
    )
    assert base != scope_signature(mode=mode, company_pattern_index_version="v2")
    assert base != scope_signature(
        mode=mode, company_pattern_index_version="v1", enable_pattern_oracle_verify=False
    )


def test_index_version_changes_with_meta(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    idx1 = _write_index(tmp_path / "a.json.gz", _FIXTURE_INDEX)
    monkeypatch.setattr(cpi, "_SINGLETON", idx1)
    v1 = index_version()
    altered = json.loads(json.dumps(_FIXTURE_INDEX))
    altered["_meta"]["generated_at"] = "2027-01-01T00:00:00Z"
    idx2 = _write_index(tmp_path / "b.json.gz", altered)
    monkeypatch.setattr(cpi, "_SINGLETON", idx2)
    assert index_version() != v1


# ======================================================================== #
# Root E — symmetry + edge cases.
# ======================================================================== #
def test_m365_verify_batch_is_cross_tenant_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.core import m365_verifier as m

    class _FakeClient:
        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

    monkeypatch.setattr(m, "build_client", lambda **k: _FakeClient())

    R = m.M365VerificationResult

    async def fake_verify_one(self: Any, client: Any, email: str) -> Any:
        dom = email.split("@", 1)[-1]
        if dom == "catch.com":
            # Catch-all tenant: reports EXISTS for everything (incl. the control).
            return R(email=email, if_exists_result=0, status="verified", exists=True)
        # Discriminating tenant: the control probe is not-found; real mailbox exists.
        if email.startswith("probe-"):
            return R(email=email, if_exists_result=1, status="not_found", exists=False)
        return R(email=email, if_exists_result=0, status="verified", exists=True)

    monkeypatch.setattr(m.M365Verifier, "_verify_one", fake_verify_one)
    res = asyncio.run(
        m.M365Verifier(delay_seconds=0).verify_batch(["alice@good.com", "bob@catch.com"])
    )
    by = {r.email: r for r in res}
    # The discriminating tenant verifies; the catch-all SECOND domain is NOT
    # falsely reported verified — its own control caught the catch-all.
    assert by["alice@good.com"].status == "verified"
    assert by["bob@catch.com"].status == "inconclusive"


def test_roundtrip_gate_flags_abstention_blowout(tmp_path: Path) -> None:
    idx_path = tmp_path / "abs.json.gz"
    with gzip.open(idx_path, "wt", encoding="utf-8") as fh:
        json.dump(
            {"_meta": {"schema": "company-patterns/1"},
             "abscorp.com": {"pattern": "P04", "support_n": 300, "confidence": 0.9, "mx": "other"}},
            fh,
        )
    sample = tmp_path / "s.csv"
    lines = ["full_name,domain,email"]
    for _ in range(99):
        lines.append("Cher,abscorp.com,cher@abscorp.com")  # mononym → abstains on P04
    lines.append("Jane Smith,abscorp.com,jane.smith@abscorp.com")  # applies + matches
    sample.write_text("\n".join(lines), encoding="utf-8")
    with pytest.raises(AssertionError, match="ABSTENTION"):
        roundtrip_gate(sample, index_path=idx_path)


_NORM_REFERENCE = {
    "José": "jose", "Müller": "muller", "straße": "strasse", "Łukasz": "lukasz",
    "Øystein": "oystein", "æon": "aeon", "naïve": "naive", "ﬃ": "ffi",
    "ＡＢＣ": "abc", "３Ｄ": "3d", "①": "1", "O’Brien": "obrien", "Ｏ’Ｎｅｉｌｌ": "oneill",
}


def test_normalization_differential_python_matches_reference() -> None:
    for inp, expected in _NORM_REFERENCE.items():
        assert _index_norm(inp) == expected, f"norm({inp!r})={_index_norm(inp)!r} != {expected!r}"


def test_li_li_allowed_cher_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    idx = _write_index(
        tmp_path / "lili.json.gz",
        {"_meta": {"schema": "company-patterns/1"},
         "lili.com": {"pattern": "P04", "support_n": 50, "confidence": 0.8, "mx": "other"}},
    )
    # Two DISTINCT tokens that normalize equal → allowed (li.li@).
    li = idx.apply("Li Li", "lili.com")
    assert li is not None and li.email == "li.li@lili.com"
    # A true single-token mononym cannot satisfy a distinct-name pattern → abstain.
    assert idx.apply("Cher", "lili.com") is None


def test_single_verify_honors_oracle_flag(index: CompanyPatternIndex, security_mode: None,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_mod.settings, "enable_pattern_oracle_verify", False, raising=False)
    outcome = govern_name_to_candidate(
        NameEvidence("Jane Smith", confidence=0.9),
        "role-corp.com", mode=ProductMode.SECURITY_INVESTIGATION,
        suppression_index=_EMPTY_SUPPRESSION, index=index,
    )
    cand = outcome.candidate
    assert cand is not None
    # Flag off → the single helper returns the candidate UNCHANGED (never dropped),
    # matching the batch path's flag handling.
    result = asyncio.run(
        verify_pattern_candidate(cand, mode=ProductMode.SECURITY_INVESTIGATION,
                                 verifier=_FakeVerifier("not_found"))
    )
    assert result is cand


def test_shared_oracle_budget_is_run_state() -> None:
    rs = PatternRunState()
    rs.seed_oracle_budget(2)
    assert rs.reserve_oracle(1) == 1
    assert rs.reserve_oracle(5) == 1  # only 1 left
    assert rs.reserve_oracle(1) == 0  # exhausted
    rs.seed_oracle_budget(99)  # first-seed-wins; already seeded
    assert rs.reserve_oracle(1) == 0


# --------------------------------------------------------------------------- #
# Shared fixtures for the export tests.
# --------------------------------------------------------------------------- #
def _result_with_unverified_lead() -> DomainHarvestResult:
    entry = HarvestedEmail(
        email="jane.smith@role-corp.com",
        on_domain=True,
        is_role=False,
        role_match_type=None,
        confidence_score=0.82,
        confidence_label="LIKELY",
        found_by_modules=["company_pattern_index"],
        source_count=1,
        evidence=[{
            "module": "company_pattern_index",
            "metadata": {"source_type": "company_pattern_index", "verification": "unverified",
                         "is_inference": True, "name": "Jane Smith"},
        }],
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
        metadata={"mode": "public-business-contact"},
    )
