"""Phase 4D — shadow scorer & gated promotion.

Where calibration becomes real — *safely*. The calibrated model runs in **shadow**
alongside the hand-tuned scorer: it scores every lead, logs its prediction and
the delta, and has **no effect on live output** until it is promoted. Promotion
fires only when the Phase-4B gate passes on sufficient data; until then the
hand-tuned scorer stays authoritative. Promotion is instantly reversible
(rollback → hand-tuned), and a promoted calibrated score still emits a
breakdown/reasoning and remains a probability of deliverability.

State (all under ``~/.mailaccess/calibration/`` so nothing new is hosted — "no
serving infra; static shipped weights"):

* ``shadow_weights.json`` — the current candidate's static weights (written by a
  promotion, or dropped in from an offline train). If absent, the repo's shipped
  weights (``calibration.load_shipped_model``) are used, else there is no shadow
  model and live output is exactly the hand-tuned score.
* ``promotion.json`` — the gated switch. ``{"promoted": true}`` makes the
  calibrated model authoritative; ``rollback`` flips it back.
* ``shadow_predictions.jsonl`` — the monitoring stream (hand vs calibrated + delta).

By design the promotion will NOT fire at current data scale — the gate refuses an
underpowered set — so this ships inert; Phase 5/6 feed it the data that eventually
trips it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .calibration import CalibratedModel, load_shipped_model

logger = logging.getLogger(__name__)


def _state_dir(state_dir: Path | None = None) -> Path:
    if state_dir is not None:
        return state_dir
    home = os.environ.get("HOME")
    base = Path(home) if home else Path.home()
    return base / ".mailaccess" / "calibration"


def shadow_weights_path(state_dir: Path | None = None) -> Path:
    return _state_dir(state_dir) / "shadow_weights.json"


def promotion_flag_path(state_dir: Path | None = None) -> Path:
    return _state_dir(state_dir) / "promotion.json"


def shadow_log_path(state_dir: Path | None = None) -> Path:
    return _state_dir(state_dir) / "shadow_predictions.jsonl"


def active_model(state_dir: Path | None = None) -> CalibratedModel | None:
    """The calibrated model in play (runtime shadow weights, else repo shipped)."""
    path = shadow_weights_path(state_dir)
    if path.exists():
        return CalibratedModel.load_json(path)
    return load_shipped_model()


def is_promoted(state_dir: Path | None = None) -> bool:
    """Whether the calibrated model is authoritative for live output."""
    path = promotion_flag_path(state_dir)
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return bool(data.get("promoted"))
    except Exception:
        return False


def promotion_state(state_dir: Path | None = None) -> dict[str, Any]:
    path = promotion_flag_path(state_dir)
    if not path.exists():
        return {"promoted": False}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"promoted": False}


def promote(
    model: CalibratedModel,
    *,
    metrics: dict[str, Any] | None = None,
    state_dir: Path | None = None,
) -> None:
    """Make ``model`` the authoritative live scorer — write its static weights and
    flip the gated switch on. Reversible via :func:`rollback`."""
    d = _state_dir(state_dir)
    d.mkdir(parents=True, exist_ok=True)
    model.save_json(shadow_weights_path(state_dir))
    promotion_flag_path(state_dir).write_text(
        json.dumps(
            {
                "promoted": True,
                "model_version": model.model_version,
                "promoted_at": datetime.now(timezone.utc).isoformat(),
                "metrics": metrics or {},
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def rollback(*, state_dir: Path | None = None) -> None:
    """Instant rollback to the hand-tuned scorer. The shadow weights are kept (the
    model keeps scoring in shadow); only the authoritative flag is cleared."""
    d = _state_dir(state_dir)
    d.mkdir(parents=True, exist_ok=True)
    promotion_flag_path(state_dir).write_text(
        json.dumps(
            {"promoted": False, "rolled_back_at": datetime.now(timezone.utc).isoformat()},
            indent=2,
        ),
        encoding="utf-8",
    )


def _log_shadow(record: dict[str, Any], state_dir: Path | None = None) -> None:
    try:
        path = shadow_log_path(state_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except Exception:
        logger.debug("shadow prediction log skipped", exc_info=True)


def live_deliverability_score(
    score: Any, *, state_dir: Path | None = None
) -> tuple[float, dict[str, Any] | None]:
    """Resolve the LIVE deliverability score, running the calibrated model in shadow.

    ``score`` is the hand-tuned :class:`~backend.core.deliverability_score.DeliverabilityScore`.
    Returns ``(live_score, shadow_info)``:

    * with no shadow model, ``(hand_score, None)`` — output is exactly hand-tuned;
    * with a shadow model but **not promoted**, ``(hand_score, info)`` — the
      calibrated prediction + delta are logged/surfaced for monitoring, but the
      live score is still the hand-tuned one (byte-for-byte);
    * once **promoted**, ``(calibrated_score, info)`` — the calibrated probability
      becomes authoritative, still carrying its breakdown/reasoning.

    Fully guarded: any failure yields ``(hand_score, None)``."""
    hand = float(score.score)
    try:
        from ..config import settings

        if not getattr(settings, "enable_shadow_scoring", True):
            return hand, None
        model = active_model(state_dir)
        if model is None:
            return hand, None
        features = getattr(score, "features", None) or {}
        explanation = model.explain(features)
        calibrated = float(explanation["score"])
        promoted = is_promoted(state_dir)
        live = calibrated if promoted else hand
        info = {
            "calibrated_score": round(calibrated, 4),
            "hand_score": round(hand, 4),
            "delta": round(calibrated - hand, 4),
            "promoted": promoted,
            "authoritative": "calibrated" if promoted else "hand_tuned",
            "model_version": model.model_version,
            "reasons": explanation["reasons"],
        }
        _log_shadow(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "hand_score": round(hand, 4),
                "calibrated_score": round(calibrated, 4),
                "delta": round(calibrated - hand, 4),
                "promoted": promoted,
                "model_version": model.model_version,
            },
            state_dir,
        )
        return live, info
    except Exception:
        return hand, None


def _split(
    examples: list[dict[str, Any]], *, holdout_pct: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministic train/holdout split (by subject hash, else by index)."""
    train_rows: list[dict[str, Any]] = []
    holdout_rows: list[dict[str, Any]] = []
    for i, ex in enumerate(examples):
        key = str(ex.get("subject") or i)
        bucket = int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16) % 100
        (holdout_rows if bucket < holdout_pct else train_rows).append(ex)
    return train_rows, holdout_rows


def run_promotion_check(
    examples: list[dict[str, Any]],
    *,
    holdout_pct: int = 30,
    state_dir: Path | None = None,
) -> Any:
    """Train a candidate from ``examples``, evaluate it against hand-tuned on the
    held-out split, apply the 4B gate, and promote only if it passes.

    Returns the :class:`~backend.core.promotion_gate.PromotionDecision`. This is
    the gated promotion switch — it stays on hand-tuned unless the candidate
    provably earns the swap. Offline/admin action; never runs during a harvest."""
    from . import calibration_metrics as metrics
    from .calibration_trainer import train
    from .promotion_gate import evaluate_promotion

    train_rows, holdout_rows = _split(examples, holdout_pct=holdout_pct)
    model = train(train_rows)
    comparison = metrics.compare(model, holdout_rows)
    decision = evaluate_promotion(comparison)
    if decision.promote:
        promote(model, metrics=comparison, state_dir=state_dir)
    return decision
