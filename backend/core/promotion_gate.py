"""Phase 4B — the shadow→live promotion gate.

The explicit, testable criteria a calibrated candidate must clear before it is
eligible to become the live deliverability scorer. The gate exists to prevent
shipping an overfit or underpowered model: the hand-tuned scorer is the permanent
fallback and the promotion baseline, and it stays authoritative until a candidate
*earns* the swap on held-out data.

Criteria (all must hold):

1. **Powered** — at least :data:`PROMOTION_MIN_LABELS` labelled outcomes in the
   held-out set. Below this the result is not trustworthy, no matter how good.
2. **Better calibrated** — candidate Brier strictly below hand-tuned Brier by at
   least :data:`MIN_BRIER_IMPROVEMENT` (a margin, so noise alone can't promote).
3. **No per-source FP regression** — for every source present in both, the
   candidate's false-positive rate is no worse than hand-tuned by more than
   :data:`PER_SOURCE_FP_TOLERANCE`. Accepting more bad addresses for any source
   is never an acceptable trade, even for a better average.

N (=200) is the held-out label count chosen here as the powered threshold: large
enough that a Brier improvement and per-source FPR are stable, small enough to be
reachable as the tool accrues real outcomes. It is a module constant so the gate
is unit-testable and a single place changes it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# The minimum number of held-out labelled outcomes for a promotion to be eligible.
PROMOTION_MIN_LABELS = 200
# Candidate Brier must beat hand-tuned by at least this margin.
MIN_BRIER_IMPROVEMENT = 0.005
# A source's candidate FPR may exceed hand-tuned by at most this before it counts
# as a regression.
PER_SOURCE_FP_TOLERANCE = 0.02


@dataclass
class PromotionDecision:
    promote: bool
    n_labelled: int
    reasons: list[str] = field(default_factory=list)
    criteria: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "promote": self.promote,
            "n_labelled": self.n_labelled,
            "reasons": self.reasons,
            "criteria": self.criteria,
        }


def _fp_regressions(
    candidate_fp: dict[str, dict[str, Any]],
    baseline_fp: dict[str, dict[str, Any]],
    *,
    tolerance: float,
) -> list[dict[str, Any]]:
    """Sources where the candidate's FPR regressed beyond tolerance."""
    regressions: list[dict[str, Any]] = []
    for src, cand in candidate_fp.items():
        base = baseline_fp.get(src)
        if base is None:
            continue
        c_rate = cand.get("fp_rate")
        b_rate = base.get("fp_rate")
        if c_rate is None or b_rate is None:
            continue
        if c_rate > b_rate + tolerance:
            regressions.append(
                {"source": src, "candidate_fp_rate": c_rate, "baseline_fp_rate": b_rate}
            )
    return regressions


def evaluate_promotion(
    comparison: dict[str, Any],
    *,
    min_labels: int = PROMOTION_MIN_LABELS,
    min_brier_improvement: float = MIN_BRIER_IMPROVEMENT,
    per_source_fp_tolerance: float = PER_SOURCE_FP_TOLERANCE,
) -> PromotionDecision:
    """Decide whether a candidate is eligible for shadow→live promotion.

    ``comparison`` is the output of ``calibration_metrics.compare`` (candidate +
    baseline suites on the held-out set). Returns a :class:`PromotionDecision`
    with an explicit, auditable rationale. Refuses an underpowered set and a model
    that does not clear every criterion — this is the safety the whole phase turns
    on."""
    candidate = comparison.get("candidate") or {}
    baseline = comparison.get("baseline") or {}
    n = int(candidate.get("n") or 0)

    reasons: list[str] = []
    criteria: dict[str, Any] = {}

    powered = n >= min_labels
    criteria["powered"] = {"n_labelled": n, "required": min_labels, "pass": powered}
    if not powered:
        reasons.append(
            f"underpowered: {n} labelled outcomes < required {min_labels}"
        )

    cand_brier = candidate.get("brier")
    base_brier = baseline.get("brier")
    brier_ok = (
        cand_brier is not None
        and base_brier is not None
        and (base_brier - cand_brier) >= min_brier_improvement
    )
    criteria["brier"] = {
        "candidate": cand_brier,
        "baseline": base_brier,
        "improvement": round(base_brier - cand_brier, 6)
        if (cand_brier is not None and base_brier is not None)
        else None,
        "required_improvement": min_brier_improvement,
        "pass": brier_ok,
    }
    if not brier_ok:
        reasons.append("Brier not improved by the required margin over hand-tuned")

    regressions = _fp_regressions(
        candidate.get("per_source_fp") or {},
        baseline.get("per_source_fp") or {},
        tolerance=per_source_fp_tolerance,
    )
    fp_ok = not regressions
    criteria["per_source_fp"] = {
        "tolerance": per_source_fp_tolerance,
        "regressions": regressions,
        "pass": fp_ok,
    }
    if not fp_ok:
        srcs = ", ".join(r["source"] for r in regressions)
        reasons.append(f"per-source FP regressed for: {srcs}")

    promote = powered and brier_ok and fp_ok
    if promote:
        reasons.append(
            f"eligible: {n} labelled, Brier {cand_brier} < {base_brier}, no FP regression"
        )
    return PromotionDecision(promote=promote, n_labelled=n, reasons=reasons, criteria=criteria)
