"""Phase 4B — the interpretable calibrated deliverability model.

Replaces the audit's structural weakness #1 (hundreds of hand-tuned constants)
with a model whose output is a *calibrated probability* of deliverability, trained
offline on the Phase-4A capture. The model family is deliberately **logistic
regression over the same feature space as the hand-tuned scorer**: its per-feature
contributions (weight × feature value) ARE the breakdown, so the tool's auditable
"why" is preserved — a black-box model would regress that ethos.

This module defines the feature space and the model object (predict + explain +
weight (de)serialization). Training is in ``calibration_trainer``; evaluation in
``calibration_metrics``; the promotion decision in ``promotion_gate``; shadow
serving + gated promotion in ``shadow_scorer``. No serving infra: the product
ships static weights (a JSON blob); nothing is hosted.

The feature names mirror the hand-tuned ``deliverability_score._W`` keys exactly,
so a calibrated coefficient is directly comparable to the constant it replaces.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The calibrated model version — bump when the feature space changes so captured
# samples stay attributable to the model that produced them.
CALIBRATED_MODEL_VERSION = "4b-logreg-v1"

# Canonical feature space. Order is the coefficient-vector order used by the
# trainer. Mirrors deliverability_score._W (mx_present/mx_absent are both kept so
# the calibrated breakdown reads parallel to the hand-tuned reasons; the L2 term
# in the trainer absorbs their collinearity with the intercept).
FEATURE_NAMES: tuple[str, ...] = (
    "mx_present",
    "mx_absent",
    "spf_present",
    "dmarc_strict",
    "provider_reputable",
    "provider_unknown",
    "disposable",
    "role",
    "history_verified_recent",
    "history_verified_stale",
    "history_negative",
)

_RECENT_DAYS = 365
_POSITIVE_STATUSES = frozenset({"verified"})
_NEGATIVE_STATUSES = frozenset({"not_found", "bounced", "invalid", "no_mx"})

# Where the promoted static weights ship (written by the 4D promotion, read at
# serve time). Absent by design until a candidate earns promotion.
_WEIGHTS_FILE = Path(__file__).resolve().parent / "data" / "calibration_weights.json"


def _history_feature(history_evidence: dict[str, Any] | None) -> str | None:
    """Map the 3C reduced history evidence ({status, age_days}) to its feature."""
    if not history_evidence:
        return None
    status = str(history_evidence.get("status") or "").lower()
    age_days = history_evidence.get("age_days")
    if status in _POSITIVE_STATUSES:
        if isinstance(age_days, int | float) and age_days <= _RECENT_DAYS:
            return "history_verified_recent"
        return "history_verified_stale"
    if status in _NEGATIVE_STATUSES:
        return "history_negative"
    return None


def featurize(features: dict[str, Any]) -> dict[str, float]:
    """Turn a captured 3C ``features`` dict into the numeric feature vector.

    Pure and total: unknown/missing inputs map to 0.0. The output keys are exactly
    :data:`FEATURE_NAMES`."""
    vec = {name: 0.0 for name in FEATURE_NAMES}
    mx = bool(features.get("mx_present"))
    vec["mx_present"] = 1.0 if mx else 0.0
    vec["mx_absent"] = 0.0 if mx else 1.0
    vec["spf_present"] = 1.0 if features.get("spf_present") else 0.0
    vec["dmarc_strict"] = 1.0 if features.get("dmarc_strict") else 0.0

    provider_class = str(features.get("provider_class") or "").lower()
    vec["provider_reputable"] = 1.0 if provider_class == "reputable" else 0.0
    vec["provider_unknown"] = 1.0 if provider_class == "unknown" else 0.0

    vec["disposable"] = 1.0 if features.get("is_disposable") else 0.0
    vec["role"] = 1.0 if features.get("is_role") else 0.0

    hist = _history_feature(features.get("history"))
    if hist:
        vec[hist] = 1.0
    return vec


def _sigmoid(x: float) -> float:
    if x < -60:
        return 0.0
    if x > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


@dataclass
class CalibratedModel:
    """An interpretable logistic-regression deliverability model.

    ``intercept`` + ``coef`` (per-feature) define ``P(deliverable) =
    sigmoid(intercept + Σ coef·feature)``. ``predict`` returns the probability;
    ``explain`` returns the same probability plus the per-feature contributions
    that sum (with the intercept) to the logit — the human-readable "why" the
    tool's ethos requires.
    """

    intercept: float = 0.0
    coef: dict[str, float] = field(default_factory=dict)
    model_version: str = CALIBRATED_MODEL_VERSION
    # Free-form provenance (n_train, l2, iterations, trained_at) for auditability.
    meta: dict[str, Any] = field(default_factory=dict)

    def logit(self, features: dict[str, Any]) -> float:
        vec = featurize(features)
        total = self.intercept
        for name in FEATURE_NAMES:
            total += self.coef.get(name, 0.0) * vec[name]
        return total

    def predict(self, features: dict[str, Any]) -> float:
        """Calibrated probability of deliverability in [0, 1]."""
        return _sigmoid(self.logit(features))

    def explain(self, features: dict[str, Any]) -> dict[str, Any]:
        """Probability + per-feature contributions (the breakdown/reasoning)."""
        vec = featurize(features)
        reasons: list[dict[str, Any]] = []
        for name in FEATURE_NAMES:
            value = vec[name]
            if value == 0.0:
                continue
            contribution = self.coef.get(name, 0.0) * value
            reasons.append(
                {
                    "feature": name,
                    "contribution": round(contribution, 4),
                    "value": value,
                }
            )
        reasons.sort(key=lambda r: abs(r["contribution"]), reverse=True)
        logit = self.logit(features)
        return {
            "score": round(_sigmoid(logit), 4),
            "logit": round(logit, 4),
            "intercept": round(self.intercept, 4),
            "reasons": reasons,
            "model_version": self.model_version,
        }

    # ── (de)serialization — static shipped weights, no serving infra ──────────
    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "intercept": self.intercept,
            "coef": {name: self.coef.get(name, 0.0) for name in FEATURE_NAMES},
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CalibratedModel:
        return cls(
            intercept=float(data.get("intercept", 0.0)),
            coef={k: float(v) for k, v in (data.get("coef") or {}).items()},
            model_version=str(data.get("model_version", CALIBRATED_MODEL_VERSION)),
            meta=dict(data.get("meta") or {}),
        )

    def save_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load_json(cls, path: Path) -> CalibratedModel | None:
        try:
            return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            return None


def weights_path() -> Path:
    """Path of the promoted static weights file (may not exist)."""
    return _WEIGHTS_FILE


def load_shipped_model() -> CalibratedModel | None:
    """The promoted calibrated model, or ``None`` when none has been promoted.

    ``None`` is the default state by design — until a candidate clears the 4B
    promotion gate, there are no shipped weights and the hand-tuned scorer stays
    authoritative."""
    if not _WEIGHTS_FILE.exists():
        return None
    return CalibratedModel.load_json(_WEIGHTS_FILE)
