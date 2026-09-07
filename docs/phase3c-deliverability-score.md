# Phase 3C — Non-SMTP probabilistic deliverability score

Phase 0 established SMTP is unmeasurable on the eval host (port 25 blocked), yet a
lead is worthless without a deliverability signal. 3C grades every email **without
touching port 25**, so the tool degrades gracefully instead of going dark.

## What shipped

`backend/core/deliverability_score.py` — `compute_deliverability_score(...)` →
`DeliverabilityScore(score, reasons, features, model_version)`, a probability in
`[0,1]` from signals the tool already resolves:

- **MX presence** (`mx_resolver`) — no MX ⇒ no mail infrastructure;
- **SPF / DMARC posture** (the harvest DNS pass);
- **mail provider** (`mail_provider`) — reputable managed vs unknown;
- **disposable** (`disposable_domains`) and **role** (`role_classifier`) flags;
- **corpus verification history** — a new `corpus_store.read_verification_history`
  read API (there was none), decay-aware (a prior verified within 365d is a strong
  prior; a prior negative is a strong penalty).

The pass `_apply_deliverability_grade` (orchestrator) resolves the domain-level
signals once, reads prior history, scores every lead, and sets
`deliverability_score` + the full reasons/evidence on the lead.

## Design decisions (exploration latitude)

- **Interpretable additive log-odds** squashed through a logistic — deliberately
  simple and auditable *now*, with a stable feature interface so **Phase 4 can
  replace the weights** with a trained model without touching callers. Weights
  carry `MODEL_VERSION` (`3c-loglinear-v1`).
- **Calibration-ready ground-truth capture, started here.** `log_score_sample`
  appends one JSONL line per scored email (feature vector + score + model version +
  any known outcome) to `~/.mailaccess/deliverability_outcomes.jsonl` — the
  Phase-4 (F1) training log, being written from day one. Brier is reported in the
  scorecard against the labelled subset.
- **Never depends on SMTP** — the signature has no SMTP input; works in every mode.

## Validation (done-when)

- `tests/test_deliverability_score.py` (8): full-signal high; no-MX low; disposable
  low even with MX; recent-verified history raises / negative lowers; score is a
  probability carrying features; no SMTP dependency; the JSONL sample log writes.
- Every lead on a harvested domain gets a score with reasons+evidence; the
  score→outcome log is written; `brier_deliverability` computed against labels
  (`no_truth`/null until they land).

## Non-scope (respected)

Not the final grade label (that's 3D). No SMTP. Weights are hand-set, not trained
(Phase 4).
