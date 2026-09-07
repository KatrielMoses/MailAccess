# Phase 4A — Ground-truth & feature capture

The self-calibrating scoring phase (Doc-1 #11, Doc-2 F1/F2) replaces the audit's
structural weakness #1 — hundreds of hand-tuned constants — with a *calibrated*
model. 4A lays the substrate: turn every score into a future training example.
3C started a JSONL log; 4A makes it a proper, immutable, provenance-linked,
DB-backed capture that the trainer learns from.

## What shipped

`backend/core/scoring_capture.py` + Alembic **0009** (two append-only tables):

- **`score_feature_snapshots`** — one immutable row per scored email per run: the
  exact 3C `features` vector, the `hand_score` it produced, a deterministic
  `content_hash` of the features, and the governance fields mirrored from the 1C
  ledger (`mode`, `source_policy_status`, `expires_at` from `ledger_default_ttl_days`).
  Linked to the ledger/corpus by `subject` + `activity_id`.
- **`score_outcome_labels`** — a NEW linked row when an objective outcome later
  becomes known (SMTP/provider verdict, corpus re-verification, human label). The
  snapshot is **never mutated**; the outcome joins by FK (and, denormalized, by
  `(subject, content_hash)` so a later run can attach without the id).

`capture_batch(...)` writes a whole harvest's snapshots in one transaction; the
orchestrator's deliverability pass accumulates a record per lead and flushes once.
`attach_outcome(...)` records an outcome as a new row; `load_training_examples(...)`
joins snapshots to their labels for the Phase-4B trainer.

## Design decisions (exploration latitude)

- **Feature set** = exactly the 3C `features` dict — no parallel taxonomy; capture
  stays in lock-step with the live scorer's inputs.
- **Join key** — snapshot `id` for same-pass outcomes; the deterministic
  `(subject, content_hash)` natural key for outcomes that arrive in a later run
  (`content_hash` strips volatile keys, e.g. the raw logit, so identical evidence
  fingerprints identically).
- **Governance** — capture obeys the ledger's policy/retention; no raw PII beyond
  the `subject` email the ledger/corpus already retain. `enable_scoring_capture`
  is the master switch; every write is guarded so it can never break a harvest.

## Validation (done-when)

- `tests/test_scoring_capture.py` (12): hash determinism/volatility/sensitivity;
  governance-complete record; capture writes an immutable snapshot; a known
  outcome attaches; a later outcome is a NEW row resolved by subject+hash and does
  not mutate the snapshot; the trainer join returns labelled examples; disabled
  writes nothing; head schema has both tables.
- Migration 0009 applies / downgrades / reapplies clean (guarded, idempotent).
- Gate green; local/uncommitted.
