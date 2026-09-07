# Phase 4B — Calibration & offline training harness

Confidence must become a *calibrated probability*, and a candidate must be proven
to beat the hand-tuned scorer before it is trusted. 4B is the offline pipeline
that trains an interpretable model, evaluates it candidate-vs-hand-tuned, and
defines the promotion gate.

## What shipped

- `backend/core/calibration.py` — the feature space (`FEATURE_NAMES`, mirroring
  `deliverability_score._W`), `featurize(...)`, and `CalibratedModel` (logistic
  regression). `predict` → a probability; `explain` → per-feature contributions
  that reconstruct the logit — the interpretable "why" the tool's ethos requires.
  Static weights (de)serialize to JSON; `load_shipped_model()` returns `None` until
  a candidate is promoted (no serving infra).
- `backend/core/calibration_trainer.py` — pure-stdlib L2 logistic regression
  (no numpy/sklearn, so it runs in the keyless baseline env). Deterministic.
- `backend/core/calibration_metrics.py` — precision / recall / **Brier** /
  reliability (calibration) curve / **per-source FP rate**, computed for the
  candidate and for the hand-tuned baseline (from each example's `hand_score`) on
  the same held-out rows; `compare(...)` reports the Brier delta.
- `backend/core/promotion_gate.py` — `evaluate_promotion(comparison)`: eligible
  iff **powered** (≥ `PROMOTION_MIN_LABELS` = 200 labelled holdout outcomes),
  **better calibrated** (Brier beats hand-tuned by ≥ `MIN_BRIER_IMPROVEMENT`), and
  **no per-source FP regression** (within `PER_SOURCE_FP_TOLERANCE`). Explicit,
  auditable rationale; refuses an underpowered or worse model.
- `eval/harness/calibrate.py` — the offline harness: synthetic generator (scores
  with the REAL hand-tuned scorer, samples labels from a separate ground-truth
  process the hand-tuned constants only approximate), deterministic train/holdout
  split, train → evaluate → gate → JSON report.

## Design decisions (exploration latitude)

- **Model family** = logistic regression: its per-feature contribution *is* the
  breakdown, so calibration doesn't cost interpretability (a black-box would).
- **Held-out strategy** = deterministic split by a stable hash of the subject.
- **N = 200** held-out labels — large enough that the Brier improvement and
  per-source FPR are stable, small enough to be reachable as outcomes accrue. A
  module constant so the gate is unit-testable in one place.

## Validation (done-when)

- `tests/test_calibration.py` (12) + `tests/test_promotion_gate.py` (6): featurize
  mapping; interpretable `explain`; weight round-trip; the trainer learns a
  separable signal and degrades gracefully with no labels; Brier / precision-recall
  / per-source FP / calibration curve correct on hand-checked inputs; the gate
  promotes only a powered, better, non-regressing candidate and refuses
  underpowered / worse / insufficient-margin / FP-regressing / missing-metric cases.
- `python -m eval.harness.calibrate --synthetic 1200 --seed 7` trains + evaluates
  end-to-end and reports an eligible promotion (candidate Brier ≪ hand-tuned).
- Gate green; local/uncommitted. No live model swap — that is 4D.
