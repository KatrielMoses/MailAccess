"""0.16.0 Phase 6 — M365 oracle verification of corpus-pattern candidates.

Executable contract for turning a *likely* corpus-pattern guess into a verified,
sendable lead (or dropping a nonexistent one) via the existing, governance-gated
M365 existence oracle — with NO live calls (a fake oracle is injected):

* an m365 candidate whose mailbox the oracle *confirms* is upgraded to
  ``provider_verified`` / Valid / (eligible in a lead-gen mode);
* a ``not_found`` candidate is dropped — a known-nonexistent address is never
  surfaced (the precision win: the oracle removes the pattern deviants);
* ``inconclusive`` / ``throttled`` / ``blocked_by_mode`` / ``no_oracle`` leave
  the candidate exactly as it was (unverified / Risky / capped) — honest
  degradation, never a false upgrade;
* a non-m365 candidate never touches the oracle (Phase 1: no working oracle for
  google/other);
* the per-run budget is respected, the m365 batch goes through a single
  ``verify_batch`` call, and the whole step is mode-gated (a no-op in public
  mode / when the flag is off);
* the upgrade flows through the harvest aggregator to a Valid, provider-verified,
  eligible lead.
"""

from __future__ import annotations

import asyncio
import gzip
import json
from pathlib import Path
from typing import Any

import pytest

import backend.config as cfg
from backend.core import pattern_candidate as pc
from backend.core import product_mode
from backend.core.catchall_buster import ExistenceSignal
from backend.core.company_pattern_index import PatternEmail
from backend.core.domain_harvest_orchestrator import _aggregate
from backend.core.m365_verifier import M365VerificationResult
from backend.core.pattern_candidate import (
    PatternCandidate,
    pattern_email_to_candidate,
    verify_pattern_candidate,
    verify_pattern_candidates,
)
from backend.core.product_mode import ProductMode
from backend.core.suppression import SuppressionIndex

_EMPTY_SUPPRESSION = SuppressionIndex(frozenset(), frozenset(), frozenset(), {})
# org-authorized-verification: active probing IS allowed (so the oracle fires)
# AND outreach eligibility is possible (lawful-supplied basis) — the one mode
# where a confirmed lead can legitimately reach ELIGIBLE.
_ORG = ProductMode.ORG_AUTHORIZED_VERIFICATION


# --------------------------------------------------------------------------- #
# Fake oracle — records every batch it is asked to verify (assert batching /
# no-call / budget) and answers from a per-email verdict table. No network.
# --------------------------------------------------------------------------- #
class FakeM365Verifier:
    def __init__(self, verdicts: dict[str, dict[str, Any]] | None = None) -> None:
        self.verdicts = {k.lower(): v for k, v in (verdicts or {}).items()}
        self.batches: list[list[str]] = []

    async def verify_batch(self, emails: list[str]) -> list[M365VerificationResult]:
        self.batches.append(list(emails))
        out: list[M365VerificationResult] = []
        for e in emails:
            spec = dict(self.verdicts.get(e.strip().lower(), {"status": "inconclusive"}))
            out.append(M365VerificationResult(email=e.strip().lower(), **spec))
        return out

    @property
    def emails_seen(self) -> list[str]:
        return [e for batch in self.batches for e in batch]


_CONFIRMED = {"status": "verified", "exists": True, "if_exists_result": 6}
_NOT_FOUND = {"status": "not_found", "exists": False, "if_exists_result": 1}
_THROTTLED = {"status": "throttled", "throttle_status": 1}
_INCONCLUSIVE = {"status": "inconclusive"}


def _candidate(
    email: str,
    *,
    mx: str = "m365",
    applied: float = 0.95,
    mode: ProductMode = _ORG,
) -> PatternCandidate:
    pe = PatternEmail(
        email=email,
        pattern_id="P04",
        support_n=400,
        confidence=0.9,
        applied_confidence=applied,
        mx=mx,
        role_used=None,
        provenance="company email pattern (P04, 400 verified samples, conf 0.9)",
    )
    return pattern_email_to_candidate(
        pe, mode=mode, suppression_index=_EMPTY_SUPPRESSION
    )


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# 1. confirmed → provider_verified / Valid / eligible.
# --------------------------------------------------------------------------- #
def test_confirmed_upgrades_to_provider_verified_valid_eligible() -> None:
    cand = _candidate("jane.smith@role-corp.com")
    # Pre-condition: an unverified guess is Risky and capped out of ELIGIBLE.
    assert cand.verification == "unverified"
    assert cand.deliverability_grade == "Risky"
    assert cand.eligibility != "eligible"

    fake = FakeM365Verifier({"jane.smith@role-corp.com": _CONFIRMED})
    up = _run(verify_pattern_candidate(cand, mode=_ORG, verifier=fake))

    assert up is not None
    assert up.verification == "provider_verified"
    assert up.deliverability_grade == "Valid"
    assert up.eligibility == "eligible"
    assert up.provenance.endswith("M365 oracle confirmed")
    # The observation lineage reflects the confirmation, not the original guess.
    assert up.observation["claim"]["verification"] == "provider_verified"


# --------------------------------------------------------------------------- #
# 2. not_found → dropped (never surfaced).
# --------------------------------------------------------------------------- #
def test_not_found_is_dropped() -> None:
    cand = _candidate("wrong.guess@role-corp.com")
    fake = FakeM365Verifier({"wrong.guess@role-corp.com": _NOT_FOUND})
    up = _run(verify_pattern_candidate(cand, mode=_ORG, verifier=fake))
    assert up is None


# --------------------------------------------------------------------------- #
# 3. inconclusive / throttled → unchanged (still unverified / Risky / capped).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("verdict", [_INCONCLUSIVE, _THROTTLED])
def test_inconclusive_or_throttled_leaves_candidate_unchanged(
    verdict: dict[str, Any]
) -> None:
    cand = _candidate("jane.smith@role-corp.com")
    fake = FakeM365Verifier({"jane.smith@role-corp.com": verdict})
    up = _run(verify_pattern_candidate(cand, mode=_ORG, verifier=fake))
    assert up is cand  # returned unchanged (identity)
    assert up.verification == "unverified"
    assert up.deliverability_grade == "Risky"


# --------------------------------------------------------------------------- #
# 4. blocked_by_mode (public) → unchanged, oracle never invoked.
# --------------------------------------------------------------------------- #
def test_public_mode_blocks_probe_and_leaves_unchanged() -> None:
    cand = _candidate("jane.smith@role-corp.com", mode=ProductMode.PUBLIC_BUSINESS_CONTACT)
    fake = FakeM365Verifier({"jane.smith@role-corp.com": _CONFIRMED})
    up = _run(
        verify_pattern_candidate(
            cand, mode=ProductMode.PUBLIC_BUSINESS_CONTACT, verifier=fake
        )
    )
    assert up is cand
    assert up.verification == "unverified"
    # The gate short-circuits before any oracle round-trip.
    assert fake.batches == []


# --------------------------------------------------------------------------- #
# 5. non-m365 candidate → oracle never called, candidate unchanged.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mx", ["google", "other"])
def test_non_m365_never_calls_oracle(mx: str) -> None:
    cand = _candidate(f"jane.smith@role-{mx}.com", mx=mx)
    fake = FakeM365Verifier({f"jane.smith@role-{mx}.com": _CONFIRMED})
    up = _run(verify_pattern_candidate(cand, mode=_ORG, verifier=fake))
    assert up is cand
    assert up.verification == "unverified"
    assert fake.batches == []


# --------------------------------------------------------------------------- #
# 6. no_oracle / unexpected status → unchanged (pure mapping).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("status", ["no_oracle", "blocked_by_mode", "inconclusive"])
def test_map_non_terminal_signal_leaves_unchanged(status: str) -> None:
    cand = _candidate("jane.smith@role-corp.com")
    signal = ExistenceSignal("jane.smith@role-corp.com", None, "m365", status, "")
    assert pc._map_existence_signal(cand, signal, mode=_ORG) is cand


# --------------------------------------------------------------------------- #
# 7. Batched — one verify_batch call for the whole m365 set; results aligned.
# --------------------------------------------------------------------------- #
def test_batched_single_call_and_aligned_results() -> None:
    a = _candidate("a.one@role-corp.com")
    b = _candidate("b.two@role-corp.com")
    c = _candidate("c.three@role-corp.com")
    fake = FakeM365Verifier(
        {
            "a.one@role-corp.com": _CONFIRMED,
            "b.two@role-corp.com": _NOT_FOUND,
            "c.three@role-corp.com": _INCONCLUSIVE,
        }
    )
    out = _run(verify_pattern_candidates([a, b, c], mode=_ORG, verifier=fake))

    # Exactly ONE batch, carrying all three addresses (batched, not per-call).
    assert len(fake.batches) == 1
    assert sorted(fake.batches[0]) == [
        "a.one@role-corp.com",
        "b.two@role-corp.com",
        "c.three@role-corp.com",
    ]
    # Positionally aligned: confirmed upgraded, not_found dropped, inconclusive kept.
    assert out[0] is not None and out[0].verification == "provider_verified"
    assert out[1] is None
    assert out[2] is c


# --------------------------------------------------------------------------- #
# 8. Budget cap — only the first N m365 candidates are probed; rest unverified.
# --------------------------------------------------------------------------- #
def test_budget_cap_is_respected() -> None:
    cands = [_candidate(f"p{i}.q@role-corp.com") for i in range(3)]
    fake = FakeM365Verifier({f"p{i}.q@role-corp.com": _CONFIRMED for i in range(3)})
    out = _run(
        verify_pattern_candidates(cands, mode=_ORG, verifier=fake, max_verifications=2)
    )
    # Only two addresses ever reach the oracle.
    assert len(fake.emails_seen) == 2
    assert out[0].verification == "provider_verified"
    assert out[1].verification == "provider_verified"
    # The over-budget third is left unverified (never dropped, never upgraded).
    assert out[2] is cands[2]
    assert out[2].verification == "unverified"


# --------------------------------------------------------------------------- #
# 9. Feature flag off → no-op, oracle never invoked.
# --------------------------------------------------------------------------- #
def test_flag_off_skips_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cfg.settings, "enable_pattern_oracle_verify", False)
    cand = _candidate("jane.smith@role-corp.com")
    fake = FakeM365Verifier({"jane.smith@role-corp.com": _CONFIRMED})
    out = _run(verify_pattern_candidates([cand], mode=_ORG, verifier=fake))
    assert out == [cand]
    assert fake.batches == []


# --------------------------------------------------------------------------- #
# 10. Invariant — only a confirmed result can produce Valid.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("verdict", [_NOT_FOUND, _INCONCLUSIVE, _THROTTLED])
def test_non_confirmed_never_reaches_valid(verdict: dict[str, Any]) -> None:
    cand = _candidate("jane.smith@role-corp.com")
    fake = FakeM365Verifier({"jane.smith@role-corp.com": verdict})
    up = _run(verify_pattern_candidate(cand, mode=_ORG, verifier=fake))
    if up is not None:
        assert up.deliverability_grade != "Valid"
        assert up.verification != "provider_verified"


# --------------------------------------------------------------------------- #
# 11. Determinism — same inputs + same fake oracle → same verdict fields.
# --------------------------------------------------------------------------- #
def test_deterministic_given_fixed_oracle() -> None:
    def once() -> tuple[Any, Any, Any]:
        cand = _candidate("jane.smith@role-corp.com")
        fake = FakeM365Verifier({"jane.smith@role-corp.com": _CONFIRMED})
        up = _run(verify_pattern_candidate(cand, mode=_ORG, verifier=fake))
        return up.verification, up.deliverability_grade, up.eligibility

    assert once() == once()


# --------------------------------------------------------------------------- #
# 12. End-to-end — the confirmed upgrade flows through the aggregator to a
#     Valid, provider-verified, eligible lead (no observed collision).
# --------------------------------------------------------------------------- #
def test_confirmed_finding_aggregates_to_valid_verified() -> None:
    from backend.modules.base import ModuleResult, ModuleStatus
    from backend.modules.pattern_and_verify import (
        EmployeeNameResult,
        _pattern_candidate_finding,
    )

    cand = _candidate("jane.smith@role-corp.com")
    fake = FakeM365Verifier({"jane.smith@role-corp.com": _CONFIRMED})
    up = _run(verify_pattern_candidate(cand, mode=_ORG, verifier=fake))
    finding = _pattern_candidate_finding(up, EmployeeNameResult(name="Jane Smith"))

    # The confirmed finding carries the provider-verification signals the harvest
    # aggregator understands.
    assert finding["metadata"]["provider_verification_status"] == "verified"
    assert finding["metadata"]["provider_verification_provider"] == "m365"

    token = product_mode.set_active_mode(_ORG)
    try:
        results = {
            "pattern_and_verify": ModuleResult(
                status=ModuleStatus.SUCCESS, findings=[finding]
            )
        }
        (entry,) = _aggregate("role-corp.com", results)
    finally:
        product_mode._ACTIVE_MODE.reset(token)

    # The aggregator propagated the confirmed verification (not "unverified").
    assert entry.verification == "provider_verified"
    assert entry.is_provider_verified is True
    assert entry.provider_verification_status == "verified"


# --------------------------------------------------------------------------- #
# 13. Module.run e2e — confirmed name upgraded, not_found name dropped.
# --------------------------------------------------------------------------- #
_FIXTURE_INDEX = {
    "_meta": {"schema": "company-patterns/1"},
    "role-corp.com": {"pattern": "P04", "support_n": 400, "confidence": 0.9, "mx": "m365"},
}


def test_module_run_upgrades_confirmed_and_drops_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backend.core import company_pattern_index as cpi
    from backend.core.company_pattern_index import CompanyPatternIndex
    from backend.modules import pattern_and_verify as pav
    from backend.modules.pattern_and_verify import (
        EmployeeNameResult,
        PatternAndVerifyModule,
    )

    path = tmp_path / "idx.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(_FIXTURE_INDEX, fh)
    monkeypatch.setattr(cpi, "_SINGLETON", CompanyPatternIndex(path))
    monkeypatch.setattr(pav, "load_index_sync", lambda: _EMPTY_SUPPRESSION)

    async def fake_confirm(emails, provider, *, mode, verifier=None):  # noqa: ANN001
        verdicts = {
            "jane.smith@role-corp.com": ("confirmed", True),
            "john.doe@role-corp.com": ("not_found", False),
        }
        out = []
        for e in emails:
            status, exists = verdicts.get(e.strip().lower(), ("inconclusive", None))
            out.append(ExistenceSignal(e.strip().lower(), exists, "m365", status, ""))
        return out

    monkeypatch.setattr(pc, "confirm_mailboxes", fake_confirm)

    token = product_mode.set_active_mode(_ORG)
    try:
        mod = PatternAndVerifyModule()
        result = asyncio.run(
            mod.run(
                "role-corp.com",
                employee_names=[
                    EmployeeNameResult(name="Jane Smith", confidence=0.6),
                    EmployeeNameResult(name="John Doe", confidence=0.6),
                ],
                enable_smtp=False,
                enable_native_validation=False,
            )
        )
    finally:
        product_mode._ACTIVE_MODE.reset(token)

    pat = [
        f
        for f in result.findings
        if (f.get("metadata") or {}).get("source_type") == "company_pattern_index"
    ]
    # John (not_found) is dropped; only Jane (confirmed) survives, upgraded.
    assert [f["metadata"]["email"] for f in pat] == ["jane.smith@role-corp.com"]
    md = pat[0]["metadata"]
    assert md["verification"] == "provider_verified"
    assert md["deliverability_grade"] == "Valid"
    assert md["provider_verification_status"] == "verified"

    oracle = result.metadata["company_pattern_index"]["oracle"]
    assert oracle["confirmed"] == 1
    assert oracle["dropped"] == 1
    assert oracle["m365_candidates"] == 2
