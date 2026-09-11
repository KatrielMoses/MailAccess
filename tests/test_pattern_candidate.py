"""0.16.0 Phase 3 — govern a PatternEmail into a lead candidate.

Invariants under test (policy-suite: a non-baseline failure here is a NEW
regression to the gate):

* **Never falsely Valid** — a pattern email grades ≤ Risky, even at perfect
  confidence / huge support (no per-mailbox proof exists offline).
* **Never auto-eligible** — a high-confidence *unverified* pattern email is
  verdicted review / research-only, never ``eligible`` on its own (the explicit
  regression).
* **Suppression wins** — a suppressed subject's pattern guess is filtered at the
  read-time seam (verdict ``suppressed``).
* **Provenance present** on every candidate; the PROV lineage tags it inference.
* **Determinism** — same inputs → same verdict/grade/provenance.

Pure/unit: no network, no DB (an explicit in-memory suppression index is passed).
"""

from __future__ import annotations

import pytest

from backend.core.eligibility import Eligibility
from backend.core.pattern_candidate import (
    PIPELINE,
    VERIFICATION_UNVERIFIED,
    PatternCandidate,
    grade_pattern_email,
    is_ready_to_send,
    pattern_email_to_candidate,
    pattern_observation,
)
from backend.core.company_pattern_index import SOURCE_TYPE, PatternEmail
from backend.core.suppression import (
    SuppressionIndex,
    SuppressionScope,
    match_key,
)
from backend.exporters.prov_exporter import to_prov

SECURITY = "security-investigation"
PUBLIC = "public-business-contact"
ORG = "org-authorized-verification"

_EMPTY_SUPPRESSION = SuppressionIndex(
    email_hashes=frozenset(),
    domain_hashes=frozenset(),
    company_norms=frozenset(),
    _meta={},
)


def _pe(
    *,
    email: str = "jane.smith@bigcorp.com",
    applied_confidence: float = 0.9,
    confidence: float = 0.95,
    mx: str = "m365",
    pattern_id: str = "P04",
    support_n: int = 500,
    role_used: str | None = None,
) -> PatternEmail:
    return PatternEmail(
        email=email,
        pattern_id=pattern_id,
        support_n=support_n,
        confidence=confidence,
        applied_confidence=applied_confidence,
        mx=mx,
        role_used=role_used,
        provenance=f"company email pattern ({pattern_id}, {support_n} verified samples, conf {confidence})",
    )


def _candidate(pe: PatternEmail, *, mode: str = PUBLIC, **kw) -> PatternCandidate:
    kw.setdefault("suppression_index", _EMPTY_SUPPRESSION)
    return pattern_email_to_candidate(pe, mode=mode, **kw)


# --------------------------------------------------------------------------- #
# Deliverability grade — never falsely Valid.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mx", ["m365", "google", "other"])
def test_grade_is_never_valid(mx: str) -> None:
    grade = grade_pattern_email(_pe(mx=mx))
    assert grade.grade != "Valid"


def test_grade_perfect_confidence_huge_support_still_not_valid() -> None:
    # No amount of research confidence manufactures a per-mailbox proof.
    pe = _pe(applied_confidence=0.999, confidence=1.0, support_n=100_000)
    assert grade_pattern_email(pe).grade != "Valid"


def test_grade_is_risky_for_a_normal_pattern_email() -> None:
    # MX present + reputable provider, unconfirmed → Risky (probably deliverable).
    assert grade_pattern_email(_pe(mx="m365")).grade == "Risky"
    assert grade_pattern_email(_pe(mx="other")).grade == "Risky"


def test_grade_surfaces_score_and_reasons() -> None:
    grade = grade_pattern_email(_pe())
    d = grade.as_dict()
    assert d["grade"] == "Risky"
    assert d["score"] is not None
    assert d["reasons"]  # explainable


# --------------------------------------------------------------------------- #
# The #1 regression — a high-confidence UNVERIFIED pattern email is never eligible.
# --------------------------------------------------------------------------- #
def test_high_confidence_unverified_is_never_eligible_public() -> None:
    # Score ~0.9, well above the 0.7 public threshold — but unverified/Risky, so
    # it must land REVIEW, never ELIGIBLE.
    cand = _candidate(_pe(applied_confidence=0.9), mode=PUBLIC)
    assert cand.confidence_score >= 0.7
    assert cand.verification == VERIFICATION_UNVERIFIED
    assert cand.eligibility == Eligibility.REVIEW.value
    assert cand.eligibility != Eligibility.ELIGIBLE.value


def test_high_confidence_unverified_is_never_eligible_org() -> None:
    # Even in org mode (lower threshold), unverified caps at REVIEW.
    cand = _candidate(_pe(applied_confidence=0.9), mode=ORG)
    assert cand.eligibility == Eligibility.REVIEW.value


def test_security_mode_is_research_only() -> None:
    cand = _candidate(_pe(applied_confidence=0.99), mode=SECURITY)
    assert cand.eligibility == Eligibility.RESEARCH_ONLY.value


def test_never_ready_to_send_on_its_own() -> None:
    for mode in (PUBLIC, ORG, SECURITY):
        assert is_ready_to_send(_candidate(_pe(applied_confidence=0.95), mode=mode)) is False


def test_low_confidence_unverified_is_research_only() -> None:
    cand = _candidate(_pe(applied_confidence=0.2), mode=PUBLIC)
    assert cand.eligibility == Eligibility.RESEARCH_ONLY.value


# --------------------------------------------------------------------------- #
# Suppression wins at read-time.
# --------------------------------------------------------------------------- #
def _suppression_for(*, email: str | None = None, domain: str | None = None, company: str | None = None) -> SuppressionIndex:
    return SuppressionIndex(
        email_hashes=frozenset({match_key(SuppressionScope.EMAIL, email)} if email else ()),
        domain_hashes=frozenset({match_key(SuppressionScope.DOMAIN, domain)} if domain else ()),
        company_norms=frozenset({match_key(SuppressionScope.COMPANY, company)} if company else ()),
        _meta={},
    )


def test_suppressed_email_is_filtered() -> None:
    pe = _pe(email="jane.smith@bigcorp.com")
    idx = _suppression_for(email="jane.smith@bigcorp.com")
    cand = _candidate(pe, mode=PUBLIC, suppression_index=idx)
    assert cand.suppressed is True
    assert cand.eligibility == Eligibility.SUPPRESSED.value


def test_suppressed_domain_filters_pattern_guess() -> None:
    # A domain-scope objection also excludes an address at that domain.
    pe = _pe(email="jane.smith@bigcorp.com")
    idx = _suppression_for(domain="bigcorp.com")
    cand = _candidate(pe, mode=PUBLIC, suppression_index=idx)
    assert cand.suppressed is True
    assert cand.eligibility == Eligibility.SUPPRESSED.value


def test_suppressed_company_filters_pattern_guess() -> None:
    pe = _pe(email="jane.smith@bigcorp.com")
    idx = _suppression_for(company="BigCorp Inc.")
    cand = pattern_email_to_candidate(pe, mode=PUBLIC, company="BigCorp", suppression_index=idx)
    assert cand.suppressed is True
    assert cand.eligibility == Eligibility.SUPPRESSED.value


def test_not_suppressed_when_absent() -> None:
    cand = _candidate(_pe(), mode=PUBLIC)
    assert cand.suppressed is False


# --------------------------------------------------------------------------- #
# Provenance + confidence surfacing.
# --------------------------------------------------------------------------- #
def test_candidate_carries_full_provenance() -> None:
    pe = _pe(pattern_id="P06", support_n=42, confidence=0.8, mx="google", role_used="executive")
    cand = _candidate(pe, mode=PUBLIC)
    assert cand.source_type == SOURCE_TYPE
    assert cand.pattern_id == "P06"
    assert cand.support_n == 42
    assert cand.confidence == 0.8
    assert cand.mx == "google"
    assert cand.role_used == "executive"
    assert "company email pattern" in cand.provenance


def test_confidence_is_capped_below_confirmed() -> None:
    # A very-high applied_confidence still labels LIKELY (an unverified guess is
    # never CONFIRMED), and the cap is recorded.
    cand = _candidate(_pe(applied_confidence=0.99), mode=PUBLIC)
    assert cand.confidence_label == "LIKELY"
    assert cand.confidence_breakdown.get("capped_from_confirmed") is True


def test_confidence_is_orthogonal_to_eligibility() -> None:
    # Same address, different modes → same confidence, different verdict.
    pe = _pe(applied_confidence=0.9)
    public = _candidate(pe, mode=PUBLIC)
    security = _candidate(pe, mode=SECURITY)
    assert public.confidence_score == security.confidence_score
    assert public.eligibility != security.eligibility


# --------------------------------------------------------------------------- #
# Observation ledger + PROV lineage tags it as inference.
# --------------------------------------------------------------------------- #
def test_observation_records_inference_provenance() -> None:
    pe = _pe(email="jane.smith@bigcorp.com")
    obs = pattern_observation(pe, mode=PUBLIC)
    assert obs["subject"] == "jane.smith@bigcorp.com"
    assert obs["source_type"] == SOURCE_TYPE
    assert obs["extraction_method"] == SOURCE_TYPE
    assert obs["pipeline"] == PIPELINE
    assert obs["mode"] == PUBLIC
    assert obs["claim"]["is_inference"] is True
    assert obs["claim"]["verification"] == VERIFICATION_UNVERIFIED
    assert obs["claim"]["pattern_id"] == "P04"


def test_candidate_embeds_the_observation() -> None:
    cand = _candidate(_pe(), mode=PUBLIC)
    assert cand.observation["source_type"] == SOURCE_TYPE
    assert cand.observation["claim"]["is_inference"] is True


def test_prov_lineage_tags_inference_agent() -> None:
    obs = pattern_observation(_pe(email="jane.smith@bigcorp.com"), mode=PUBLIC)
    doc = to_prov([obs])
    # The agent (source) node names the company-pattern inference.
    assert f"mailaccess:source/{SOURCE_TYPE}" in doc["agent"]
    agent = doc["agent"][f"mailaccess:source/{SOURCE_TYPE}"]
    assert agent["mailaccess:source_type"] == SOURCE_TYPE
    # The activity (run) is attributed to the inference extraction method.
    activity_key = f"mailaccess:run/bigcorp.com/{SOURCE_TYPE}"
    assert activity_key in doc["activity"]
    assert doc["activity"][activity_key]["mailaccess:extraction_method"] == SOURCE_TYPE


# --------------------------------------------------------------------------- #
# Determinism / order-independence.
# --------------------------------------------------------------------------- #
def test_candidate_is_deterministic() -> None:
    pe = _pe(applied_confidence=0.9)
    a = _candidate(pe, mode=PUBLIC)
    b = _candidate(pe, mode=PUBLIC)
    # Verdict/grade/provenance are pure functions of the inputs (ignore the
    # observation's capture time, the only nondeterministic field).
    for field_name in (
        "email", "verification", "confidence_score", "confidence_label",
        "deliverability_grade", "eligibility", "eligibility_reason",
        "suppressed", "provenance", "pattern_id", "applied_confidence",
    ):
        assert getattr(a, field_name) == getattr(b, field_name)


# --------------------------------------------------------------------------- #
# Projection into the harvest candidate type (Phase 4 seam).
# --------------------------------------------------------------------------- #
def test_as_harvested_email_carries_verification_and_grade() -> None:
    cand = _candidate(_pe(applied_confidence=0.9), mode=PUBLIC)
    he = cand.as_harvested_email()
    assert he.email == cand.email
    assert he.verification == VERIFICATION_UNVERIFIED
    assert he.deliverability_grade == "Risky"
    assert he.found_by_modules == [SOURCE_TYPE]
    assert he.confidence_score == cand.confidence_score


def test_harvested_email_projection_stays_non_eligible_in_export() -> None:
    # The projected HarvestedEmail, run through the harvest export eligibility
    # seam, must ALSO cap at REVIEW (the verification field carries through).
    from backend.core.domain_harvest_report import _row_eligibility
    from backend.core.eligibility import evaluate

    cand = _candidate(_pe(applied_confidence=0.9), mode=PUBLIC)
    he = cand.as_harvested_email()
    row = _row_eligibility(he, PUBLIC, "lawful-public", evaluate)
    assert row["eligibility"] == Eligibility.REVIEW.value
