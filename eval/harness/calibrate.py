"""Phase 4B — offline calibration harness.

Trains the interpretable calibrated model, evaluates it against the hand-tuned
scorer on a held-out set, applies the promotion gate, and writes a report. Runs
entirely offline (Doc-1 #11 / Doc-2 F2). Validated on **synthetic** data now — as
the Phase-0B scorer was — and on real Phase-4A capture as it accrues.

Usage::

    python -m eval.harness.calibrate --synthetic 800          # synthetic validation
    python -m eval.harness.calibrate --synthetic 800 --seed 7
    python -m eval.harness.calibrate --from-db                # real 4A capture

The synthetic generator builds feature inputs, scores them with the REAL
hand-tuned scorer (so ``hand_score`` + ``features`` are production-shaped), and
samples labels from a separate "ground-truth" logistic process the hand-tuned
constants only approximate — so a trained LR is expected to beat the hand-tuned
Brier, exercising the whole train→evaluate→gate path.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core import calibration_metrics as M
from backend.core.calibration import FEATURE_NAMES, featurize
from backend.core.calibration_trainer import train
from backend.core.deliverability_score import compute_deliverability_score
from backend.core.promotion_gate import evaluate_promotion
from eval.harness.manifest import REPO_ROOT

OUT_ROOT = REPO_ROOT / "eval" / "scorecards" / "calibration"

# A "ground-truth" logit the hand-tuned constants only approximate. Deliberately
# different from deliverability_score._W so the hand-tuned scorer is miscalibrated
# relative to reality and a trained LR can beat its Brier.
_TRUE_INTERCEPT = -0.6
_TRUE_COEF = {
    "mx_present": 0.6,
    "mx_absent": -4.0,
    "spf_present": 0.9,
    "dmarc_strict": 0.8,
    "provider_reputable": 1.6,
    "provider_unknown": -1.4,
    "disposable": -4.5,
    "role": -0.4,
    "history_verified_recent": 3.0,
    "history_verified_stale": 0.3,
    "history_negative": -3.5,
}

_PROVIDERS = [
    ("google", "reputable"),
    ("m365", "reputable"),
    ("proton", "reputable"),
    ("self_hosted", "neutral"),
    ("shared_hosting", "neutral"),
    ("acme_mail", "other"),
    (None, "unknown"),
]


def _sigmoid(x: float) -> float:
    import math

    if x < -60:
        return 0.0
    if x > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


def _sample_history(rng: random.Random) -> list[dict[str, Any]] | None:
    roll = rng.random()
    if roll < 0.55:
        return None
    now = datetime.now(timezone.utc)
    if roll < 0.75:
        return [{"status": "verified", "verified_at": now.isoformat()}]  # recent
    if roll < 0.88:
        old = now.replace(year=now.year - 2)
        return [{"status": "verified", "verified_at": old.isoformat()}]  # stale
    return [{"status": "bounced", "verified_at": now.isoformat()}]  # negative


def generate_synthetic(n: int, *, seed: int = 1234) -> list[dict[str, Any]]:
    """Generate ``n`` production-shaped, labelled examples for validation."""
    rng = random.Random(seed)
    examples: list[dict[str, Any]] = []
    for i in range(n):
        mx_present = rng.random() < 0.9
        spf_present = mx_present and rng.random() < 0.7
        dmarc_strict = spf_present and rng.random() < 0.4
        provider, _pclass = rng.choice(_PROVIDERS)
        is_role = rng.random() < 0.15
        is_disposable = rng.random() < 0.05
        history = _sample_history(rng)

        score = compute_deliverability_score(
            mx_present=mx_present,
            spf_present=spf_present,
            dmarc_strict=dmarc_strict,
            provider=provider,
            is_role=is_role,
            is_disposable=is_disposable,
            history=history,
        )
        # Ground-truth probability from a separate process; sample the label.
        vec = featurize(score.features)
        true_logit = _TRUE_INTERCEPT + sum(_TRUE_COEF[k] * vec[k] for k in FEATURE_NAMES)
        label = 1.0 if rng.random() < _sigmoid(true_logit) else 0.0
        examples.append(
            {
                "subject": f"user{i}@example{i % 50}.test",
                "features": score.features,
                "hand_score": round(score.score, 6),
                "label": label,
                "source": provider or "unknown",
            }
        )
    return examples


def split(
    examples: list[dict[str, Any]], *, holdout_pct: int = 30
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministic train/holdout split keyed by a stable hash of the subject."""
    import hashlib

    train_rows: list[dict[str, Any]] = []
    holdout_rows: list[dict[str, Any]] = []
    for ex in examples:
        key = hashlib.sha256(str(ex.get("subject", "")).encode("utf-8")).hexdigest()
        bucket = int(key[:8], 16) % 100
        (holdout_rows if bucket < holdout_pct else train_rows).append(ex)
    return train_rows, holdout_rows


def run(examples: list[dict[str, Any]], *, holdout_pct: int = 30) -> dict[str, Any]:
    """Train on the train split, evaluate candidate-vs-hand-tuned on holdout, gate."""
    train_rows, holdout_rows = split(examples, holdout_pct=holdout_pct)
    model = train(train_rows)
    comparison = M.compare(model, holdout_rows)
    decision = evaluate_promotion(comparison)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_total": len(examples),
        "n_train": len(train_rows),
        "n_holdout_labelled": comparison["candidate"]["n"],
        "model": model.to_dict(),
        "comparison": comparison,
        "promotion": decision.as_dict(),
    }


def _load_from_db() -> list[dict[str, Any]]:
    import asyncio

    from backend.core.scoring_capture import load_training_examples

    return asyncio.run(load_training_examples())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline calibration harness (Phase 4B)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--synthetic", type=int, metavar="N",
                     help="generate and use N synthetic labelled examples")
    src.add_argument("--from-db", action="store_true",
                     help="use real Phase-4A capture from the database")
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--holdout", type=int, default=30, help="holdout percent (default 30)")
    ap.add_argument("--out", default=None, help="output dir (default eval/scorecards/calibration)")
    args = ap.parse_args(argv)

    if args.from_db:
        examples = _load_from_db()
        label = "from-db"
    else:
        n = args.synthetic or 800
        examples = generate_synthetic(n, seed=args.seed)
        label = f"synthetic-{n}-seed{args.seed}"

    report = run(examples, holdout_pct=args.holdout)
    report["source"] = label

    out_dir = Path(args.out) if args.out else OUT_ROOT / datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "calibration_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    p = report["promotion"]
    c = report["comparison"]
    print(f"source={label}  n_total={report['n_total']}  n_holdout={report['n_holdout_labelled']}")
    print(f"candidate Brier={c['candidate']['brier']}  hand-tuned Brier={c['baseline']['brier']}"
          f"  delta={c['brier_delta']}")
    print(f"promotion eligible={p['promote']}")
    for reason in p["reasons"]:
        print(f"  - {reason}")
    print(f"Wrote {out_dir / 'calibration_report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
