"""Phase 2D — eligibility is not confidence.

"Technically likely deliverable" (research **confidence**) and "eligible for
outreach" (a **policy** decision) are different questions (Doc-1 #8). A
high-confidence address may still be personal, suppressed, or collected under the
wrong mode. Export therefore requires *both* a confidence threshold **and** a
policy verdict.

The verdict is computed from mode + `source_policy_status` (2C) + suppression
(2A) + the record's confidence (1E / harvest confidence), against a configurable
per-mode threshold. It is **orthogonal** to confidence and never mutates it —
both are surfaced independently on every exportable record.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .product_mode import ProductMode, normalize_mode

_LAWFUL_STATUSES = frozenset({"lawful-public", "authorized-supplied"})


class Eligibility(str, Enum):
    ELIGIBLE = "eligible"          # meets confidence + policy — sendable
    REVIEW = "review"             # lawful but below threshold — needs a human
    SUPPRESSED = "suppressed"     # objected — never in any outreach export
    RESEARCH_ONLY = "research-only"  # no lawful-outreach basis (e.g. security mode)


# Confidence-label → score fallback for records that carry a label but no numeric
# score. Covers the harvest 4-tier vocabulary (CONFIRMED/LIKELY/MEDIUM/LOW) and
# the legacy HIGH alias.
_LABEL_SCORE: dict[str, float] = {
    "CONFIRMED": 0.95,
    "HIGH": 0.95,
    "LIKELY": 0.75,
    "MEDIUM": 0.55,
    "LOW": 0.30,
    "NONE": 0.0,
}


@dataclass(frozen=True)
class EligibilityVerdict:
    verdict: Eligibility
    reason: str
    # The confidence the verdict was computed against — surfaced alongside the
    # verdict, independently; the verdict never changes it.
    confidence: float | None


def score_of(confidence: float | int | str | None) -> float | None:
    """Coerce a numeric score (0..1) or a confidence label to a 0..1 score."""
    if isinstance(confidence, bool):
        return None
    if isinstance(confidence, int | float):
        return float(confidence)
    if isinstance(confidence, str):
        return _LABEL_SCORE.get(confidence.strip().upper())
    return None


def _threshold_for_mode(mode: ProductMode) -> float:
    from ..config import settings

    if mode is ProductMode.ORG_AUTHORIZED_VERIFICATION:
        return float(getattr(settings, "eligibility_confidence_threshold_org", 0.6))
    return float(getattr(settings, "eligibility_confidence_threshold_public", 0.7))


def _review_floor() -> float:
    from ..config import settings

    return float(getattr(settings, "eligibility_review_floor", 0.4))


# Phase 3D — deliverability grades that can never be sent to. An Invalid or
# Catch-all address is not eligible for outreach regardless of confidence: you
# cannot confirm the mailbox, so sending burns sender reputation. This closes the
# loop left open in Phase 2D (eligibility now consumes the deliverability grade).
_NON_SENDABLE_GRADES = frozenset({"Invalid", "Catch-all"})


# 0.16.0 Phase 3 — verification statuses that establish a per-mailbox / identity
# confirmation strong enough to be *auto*-eligible for outreach. A record that
# carries any OTHER (non-None) verification status — canonically ``"unverified"``
# — has no such confirmation, so however high its research confidence, it can
# never auto-clear to ELIGIBLE: it caps at REVIEW (a human decides). This is the
# "eligibility gates on verification, not on the raw confidence score" rule: a
# well-supported but unverified inference (e.g. a corpus company-pattern email at
# score ~0.9) is deliberately *not* a ready-to-send lead on its own.
#
# ``verification=None`` (the default) means "not asserted" — the caller isn't
# making a verification claim, so the gate is inert and every pre-Phase-3 caller
# keeps its exact prior verdict.
_CONFIRMED_VERIFICATIONS = frozenset(
    {"verified", "confirmed", "smtp_verified", "provider_verified", "valid"}
)


def _is_confirmed(verification: str | None) -> bool:
    """Whether a verification status is a per-mailbox/identity confirmation.

    ``None`` → no claim made → treated as confirmed for gating purposes (the
    gate is inert; the caller's other signals decide). A non-None status is
    confirmed only if it names an affirmative verification.
    """
    if verification is None:
        return True
    return str(verification).strip().lower() in _CONFIRMED_VERIFICATIONS


def evaluate(
    *,
    mode: str | ProductMode,
    policy_status: str | None,
    suppressed: bool,
    confidence: float | int | str | None,
    threshold: float | None = None,
    review_floor: float | None = None,
    deliverability_grade: str | None = None,
    verification: str | None = None,
    needs_reverification: bool = False,
) -> EligibilityVerdict:
    """Compute the outreach eligibility verdict for one record.

    Orthogonal to confidence: the returned ``confidence`` is passed through for
    surfacing, never altered. When a Phase-3D ``deliverability_grade`` is
    supplied, an Invalid/Catch-all grade forces ``research-only`` — it can never
    be eligible for outreach, whatever the confidence.

    ``verification`` (0.16.0 Phase 3) gates the top band: a record whose
    verification is asserted-but-unconfirmed (e.g. ``"unverified"``) can never
    *auto*-clear to ELIGIBLE — it caps at REVIEW. ``None`` (the default) makes no
    verification claim and leaves the verdict exactly as it was pre-Phase-3.

    ``needs_reverification`` (Brief B item 2) makes a *stale positive verification*
    explicit: a confirmed record whose confirmation has aged past the corpus
    staleness threshold can no longer *auto*-clear to ELIGIBLE — it caps at REVIEW
    until refreshed, exactly as an unverified record does. The caller supplies this
    from the served row's freshness flag; it is orthogonal to the (already decayed)
    served confidence, so a still-high served score cannot keep a stale record
    eligible. ``False`` (the default) leaves the verdict unchanged.
    """
    m = normalize_mode(mode)
    score = score_of(confidence)

    # Suppression wins outright — an objection is absolute.
    if suppressed:
        return EligibilityVerdict(Eligibility.SUPPRESSED, "subject is suppressed", score)

    # Outreach eligibility only exists in the lead-gen / org modes, and only for
    # data with a lawful-public / authorized-supplied basis. security-investigation
    # output is research, not outreach.
    if m is ProductMode.SECURITY_INVESTIGATION:
        return EligibilityVerdict(
            Eligibility.RESEARCH_ONLY,
            "security-investigation output is research, not outreach",
            score,
        )
    if policy_status not in _LAWFUL_STATUSES:
        return EligibilityVerdict(
            Eligibility.RESEARCH_ONLY,
            f"no lawful-outreach basis (policy_status={policy_status!r})",
            score,
        )

    # Deliverability gate (3D): undeliverable can never be eligible, even at 0.99.
    if deliverability_grade in _NON_SENDABLE_GRADES:
        return EligibilityVerdict(
            Eligibility.RESEARCH_ONLY,
            f"deliverability grade {deliverability_grade!r} is not sendable",
            score,
        )

    thr = threshold if threshold is not None else _threshold_for_mode(m)
    floor = review_floor if review_floor is not None else _review_floor()

    if score is None:
        return EligibilityVerdict(
            Eligibility.REVIEW, "no confidence score — needs review", None
        )
    if score >= thr:
        # Brief B — a stale positive verification is not a current confirmation: a
        # confirmed record whose confirmation has aged past the staleness threshold
        # caps at REVIEW until re-verified, even at a high (already decayed) score.
        if needs_reverification:
            return EligibilityVerdict(
                Eligibility.REVIEW,
                f"confidence {score:.2f} >= threshold {thr:.2f} but verification is "
                "stale (needs_reverification) — refresh before outreach",
                score,
            )
        # Phase 3 — the verification gate. A high research confidence is not, on
        # its own, a per-mailbox confirmation: an asserted-but-unverified record
        # caps at REVIEW rather than auto-clearing to ELIGIBLE.
        if not _is_confirmed(verification):
            return EligibilityVerdict(
                Eligibility.REVIEW,
                f"confidence {score:.2f} >= threshold {thr:.2f} but unverified "
                f"(verification={verification!r}) — needs review before outreach",
                score,
            )
        return EligibilityVerdict(
            Eligibility.ELIGIBLE, f"confidence {score:.2f} >= threshold {thr:.2f}", score
        )
    if score >= floor:
        return EligibilityVerdict(
            Eligibility.REVIEW,
            f"confidence {score:.2f} in review band [{floor:.2f}, {thr:.2f})",
            score,
        )
    return EligibilityVerdict(
        Eligibility.RESEARCH_ONLY, f"confidence {score:.2f} < review floor {floor:.2f}", score
    )


# Verdicts permitted in an outreach/lead export.
_OUTREACH_VERDICTS = frozenset({Eligibility.ELIGIBLE.value})
_OUTREACH_VERDICTS_WITH_REVIEW = frozenset(
    {Eligibility.ELIGIBLE.value, Eligibility.REVIEW.value}
)


def is_outreach_verdict(verdict: str, *, include_review: bool = False) -> bool:
    allowed = _OUTREACH_VERDICTS_WITH_REVIEW if include_review else _OUTREACH_VERDICTS
    return verdict in allowed


def filter_outreach(rows: list[dict], *, include_review: bool = False) -> list[dict]:
    """Keep only rows whose ``eligibility`` is sendable. ``research-only`` and
    ``suppressed`` are never returned; ``review`` only when explicitly requested."""
    return [
        row
        for row in rows
        if is_outreach_verdict(str(row.get("eligibility", "")), include_review=include_review)
    ]
