"""Phase 4B — offline trainer for the interpretable calibrated model.

Trains an L2-regularized logistic regression over :data:`calibration.FEATURE_NAMES`
from Phase-4A capture (or synthetic data during validation), producing static
weights. Pure stdlib — no numpy/sklearn — so it runs in the keyless baseline env
(the ``ml`` extra is not required) and stays dependency-free for the shipped
product. Deterministic: zero-initialized, fixed learning rate / iterations, so a
given dataset always yields the same weights.

This is an *offline* step. It never runs during a harvest; it produces a weights
blob that 4D promotes (or not) behind the gate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .calibration import (
    CALIBRATED_MODEL_VERSION,
    FEATURE_NAMES,
    CalibratedModel,
    _sigmoid,
    featurize,
)


def _prepare(examples: list[dict[str, Any]]) -> list[tuple[dict[str, float], float]]:
    """Featurize labelled examples into (vector, label) pairs (label ∈ {0,1})."""
    rows: list[tuple[dict[str, float], float]] = []
    for ex in examples:
        label = ex.get("label")
        if label is None:
            continue
        feats = ex.get("features") or {}
        rows.append((featurize(feats), 1.0 if float(label) >= 0.5 else 0.0))
    return rows


def train(
    examples: list[dict[str, Any]],
    *,
    l2: float = 1.0,
    learning_rate: float = 0.3,
    iterations: int = 2000,
    model_version: str = CALIBRATED_MODEL_VERSION,
) -> CalibratedModel:
    """Train an L2 logistic regression and return the fitted model.

    ``examples`` are Phase-4A rows ({features, label, …}); rows without a label
    are ignored. Full-batch gradient descent with an L2 penalty on the
    coefficients (not the intercept). Deterministic for a fixed dataset + hypers.
    """
    rows = _prepare(examples)
    intercept = 0.0
    coef = {name: 0.0 for name in FEATURE_NAMES}
    n = len(rows)
    if n == 0:
        return CalibratedModel(
            intercept=0.0, coef=coef, model_version=model_version,
            meta={"n_train": 0, "note": "no labelled data"},
        )

    for _ in range(max(1, iterations)):
        grad_intercept = 0.0
        grad_coef = {name: 0.0 for name in FEATURE_NAMES}
        for vec, label in rows:
            logit = intercept
            for name in FEATURE_NAMES:
                logit += coef[name] * vec[name]
            error = _sigmoid(logit) - label  # dL/dlogit for log-loss
            grad_intercept += error
            for name in FEATURE_NAMES:
                grad_coef[name] += error * vec[name]
        # Mean gradient + L2 shrinkage on coefficients only.
        intercept -= learning_rate * (grad_intercept / n)
        for name in FEATURE_NAMES:
            g = grad_coef[name] / n + l2 * coef[name] / n
            coef[name] -= learning_rate * g

    return CalibratedModel(
        intercept=intercept,
        coef=coef,
        model_version=model_version,
        meta={
            "n_train": n,
            "l2": l2,
            "learning_rate": learning_rate,
            "iterations": iterations,
            "trained_at": datetime.now(timezone.utc).isoformat(),
        },
    )
