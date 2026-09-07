# Phase 4D — Shadow scorer & gated promotion

Where calibration becomes real — *safely*. The calibrated model runs in **shadow**
alongside the hand-tuned scorer, and is promoted to the live deliverability scorer
only when it provably earns it. Shadow mode lets the model prove itself on
accumulating data without risking output; the gate prevents shipping an overfit or
underpowered model.

## What shipped

`backend/core/shadow_scorer.py`:

- **Shadow scoring** — `live_deliverability_score(score)` runs the calibrated
  model alongside the hand-tuned one, logs its prediction + the delta to
  `~/.mailaccess/calibration/shadow_predictions.jsonl`, and surfaces monitoring
  metadata under `deliverability.shadow`. It returns `(live_score, info)`: with no
  shadow model, `(hand, None)`; with a shadow model **not promoted**, the live
  score is still the hand-tuned one **byte-for-byte**; once **promoted**, the
  calibrated probability becomes authoritative — still carrying its breakdown.
- **Gated promotion switch** — `run_promotion_check(examples)` trains a candidate,
  evaluates it candidate-vs-hand-tuned on the held-out split, applies the 4B gate,
  and calls `promote(...)` only if it passes. `is_promoted()` reads the gated flag;
  hand-tuned stays authoritative until it flips.
- **Instant, reversible rollback** — `rollback()` clears the authoritative flag
  (the shadow weights are kept, so the model keeps scoring in shadow). No serving
  infra: weights are a static JSON blob, the flag a small JSON file, both under
  `~/.mailaccess/calibration/`.

The orchestrator resolves the live score through `_shadow_live_score(...)`; the
grade fusion (3D) stays on the hand-tuned signal set — promotion changes the
deliverability *probability*, not the multi-signal grade.

## Design decisions (exploration latitude)

- **Monitoring surface** — shadow predictions are both logged (JSONL stream) and
  attached to each lead's `deliverability.shadow` (calibrated vs hand + delta +
  reasons), so the shadow can be watched per-lead and in aggregate.
- **Rollback mechanism** — a single flag file, flipped atomically; weights are
  never deleted, so rollback is instant and the hand-tuned scorer is a permanent
  fallback (never removed).
- **Inert by design** — the promotion will NOT fire at current data scale (the
  gate refuses an underpowered set). Phase 5/6 feed it the data that eventually
  trips it.

## Validation (done-when)

- `tests/test_shadow_scorer.py` (5): no-model → hand-tuned; a shadow model present
  but unpromoted leaves live output provably unchanged (monitoring only); the gate
  refuses to promote at current scale (stays on hand-tuned); fed sufficient
  synthetic data that beats hand-tuned, promotion fires (live = calibrated
  probability + breakdown) and `rollback()` restores hand-tuned cleanly; shadow
  predictions are logged.
- Gate green; local/uncommitted.
