"""Phase 4B — the candidate-vs-hand-tuned metric suite.

Confidence must become a *calibrated probability*, and a candidate model must be
proven to beat the hand-tuned scorer before it is trusted. This module computes,
on a held-out labelled set, the full suite the promotion gate consumes:

* **precision / recall** at a decision threshold;
* **Brier score** — mean squared error of the probability (lower is better) — the
  headline calibration metric;
* a **reliability (calibration) curve** — binned mean-predicted vs mean-actual;
* **per-source false-positive rate** — FPR within each source, so a candidate that
  accepts more bad addresses for any one source is caught.

The candidate is a :class:`~backend.core.calibration.CalibratedModel`; the
hand-tuned baseline is scored from each example's captured ``hand_score`` (the
probability the live scorer produced), so the comparison is apples-to-apples on
the same rows. Every example needs a ``label`` (0/1); the ``source`` dimension
defaults to the example's provider.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .calibration import CalibratedModel


def _example_source(ex: dict[str, Any]) -> str:
    src = ex.get("source")
    if src:
        return str(src)
    provider = (ex.get("features") or {}).get("provider")
    return str(provider or "unknown")


def _labelled(examples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [ex for ex in examples if ex.get("label") is not None]


def brier(predictions: list[float], labels: list[float]) -> float | None:
    if not predictions:
        return None
    return sum((p - y) ** 2 for p, y in zip(predictions, labels)) / len(predictions)


def precision_recall(
    predictions: list[float], labels: list[float], *, threshold: float = 0.5
) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for p, y in zip(predictions, labels):
        pred_pos = p >= threshold
        actual_pos = y >= 0.5
        if pred_pos and actual_pos:
            tp += 1
        elif pred_pos and not actual_pos:
            fp += 1
        elif not pred_pos and actual_pos:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "threshold": threshold,
    }


def calibration_curve(
    predictions: list[float], labels: list[float], *, bins: int = 10
) -> list[dict[str, Any]]:
    """Binned reliability curve: mean predicted vs mean actual per probability bin."""
    buckets: list[dict[str, Any]] = [
        {"lo": i / bins, "hi": (i + 1) / bins, "sum_pred": 0.0, "sum_actual": 0.0, "count": 0}
        for i in range(bins)
    ]
    for p, y in zip(predictions, labels):
        idx = min(int(p * bins), bins - 1)
        b = buckets[idx]
        b["sum_pred"] += p
        b["sum_actual"] += y
        b["count"] += 1
    out: list[dict[str, Any]] = []
    for b in buckets:
        c = b["count"]
        if not c:
            continue
        out.append(
            {
                "bin": [round(b["lo"], 3), round(b["hi"], 3)],
                "count": c,
                "mean_predicted": round(b["sum_pred"] / c, 4),
                "mean_actual": round(b["sum_actual"] / c, 4),
            }
        )
    return out


def per_source_fp(
    examples: list[dict[str, Any]],
    predictions: list[float],
    *,
    threshold: float = 0.5,
) -> dict[str, dict[str, Any]]:
    """False-positive rate within each source: FP / (FP + TN) over actual-negatives.

    A "false positive" is predicting deliverable (p ≥ threshold) for an address
    whose true label is 0. The gate refuses a candidate that raises this for any
    source — accepting more bad addresses is never an acceptable trade."""
    by_source: dict[str, dict[str, int]] = {}
    for ex, p in zip(examples, predictions):
        y = float(ex["label"])
        src = _example_source(ex)
        d = by_source.setdefault(src, {"fp": 0, "tn": 0, "negatives": 0})
        if y < 0.5:  # actual negative
            d["negatives"] += 1
            if p >= threshold:
                d["fp"] += 1
            else:
                d["tn"] += 1
    return {
        src: {
            "negatives": d["negatives"],
            "fp": d["fp"],
            "fp_rate": round(d["fp"] / d["negatives"], 4) if d["negatives"] else None,
        }
        for src, d in sorted(by_source.items())
    }


def _evaluate(
    examples: list[dict[str, Any]],
    predict: Callable[[dict[str, Any]], float],
    *,
    threshold: float,
    bins: int,
) -> dict[str, Any]:
    labelled = _labelled(examples)
    preds = [float(predict(ex)) for ex in labelled]
    labels = [float(ex["label"]) for ex in labelled]
    return {
        "n": len(labelled),
        "brier": round(brier(preds, labels), 6) if preds else None,
        **precision_recall(preds, labels, threshold=threshold),
        "calibration_curve": calibration_curve(preds, labels, bins=bins),
        "per_source_fp": per_source_fp(labelled, preds, threshold=threshold),
    }


def evaluate_candidate(
    model: CalibratedModel,
    examples: list[dict[str, Any]],
    *,
    threshold: float = 0.5,
    bins: int = 10,
) -> dict[str, Any]:
    """Metric suite for the calibrated candidate on ``examples``."""
    return _evaluate(
        examples, lambda ex: model.predict(ex.get("features") or {}),
        threshold=threshold, bins=bins,
    )


def evaluate_hand_tuned(
    examples: list[dict[str, Any]],
    *,
    threshold: float = 0.5,
    bins: int = 10,
) -> dict[str, Any]:
    """Metric suite for the hand-tuned baseline, from each example's ``hand_score``."""
    return _evaluate(
        examples, lambda ex: float(ex.get("hand_score") or 0.0),
        threshold=threshold, bins=bins,
    )


def compare(
    model: CalibratedModel,
    examples: list[dict[str, Any]],
    *,
    threshold: float = 0.5,
    bins: int = 10,
) -> dict[str, Any]:
    """Both metric suites side by side, plus the Brier delta (negative = better)."""
    candidate = evaluate_candidate(model, examples, threshold=threshold, bins=bins)
    baseline = evaluate_hand_tuned(examples, threshold=threshold, bins=bins)
    brier_delta = None
    if candidate["brier"] is not None and baseline["brier"] is not None:
        brier_delta = round(candidate["brier"] - baseline["brier"], 6)
    return {"candidate": candidate, "baseline": baseline, "brier_delta": brier_delta}
