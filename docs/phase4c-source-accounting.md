# Phase 4C — Novelty & source accounting

Measure what each source actually *earns*, and auto-demote the ones that don't
(Doc-1 #13). Needs no labels — it runs on harvest telemetry + the confirmations
the pipeline already produces — so it delivers value immediately and cuts the
noise/runtime the audit flagged.

## What shipped

`backend/core/source_accounting.py`:

- **Per-run accounting** — `account_run(emails, module_timings, module_status)`
  attributes, per source (harvest module): **marginal-unique** leads (emails only
  that source found), **incremental-confirmed** leads (Valid-graded emails only
  that source found), latency, failure/block rate, and FP rate (contributed
  addresses graded Invalid / gradable contributed). `record_run_accounting(...)`
  appends one record to `~/.mailaccess/source_accounting.jsonl` (append-only).
- **Aggregation** — `aggregate(window_days=30)` sums contribution and averages
  latency over the rolling window from the JSONL.
- **Reversible auto-demotion** — reuses the existing `demotion_log` pattern (no
  parallel one). `compute_demotion_candidates(...)` is reproducible from the log:
  a source with ≥ `min_runs` that added **0 marginal-unique AND 0
  incremental-confirmed** leads has stopped earning its runtime. `demote(...)`
  logs the decision with its trigger stats and the env var that reverses it;
  `reinstate(...)` logs an `upgrade`; `demoted_source_names()` replays the log
  (last action wins) and drops any source force-kept by
  `MAILACCESS_FORCE_SOURCE_<NAME>`.

The orchestrator records accounting after the deliverability pass, and unions
`demoted_source_names()` into `effective_skip_modules` before the harvest — a
demoted source is simply skipped (runtime saved), reversibly. Nothing is removed
(module removal is Phase 7).

## Design decisions (exploration latitude)

- **Demotion threshold** = 0 marginal-unique *and* 0 incremental-confirmed over
  ≥ 5 runs in a 30-day window. It targets sources that are pure duplication —
  every address they find, another source also finds — never a source that still
  adds novelty.
- **Earned, like the scorer** — the demoted set is empty until a source earns
  demotion, so at baseline scale live behavior is unchanged and the gate stays
  green. Force-keep + reinstate make every decision reversible.

## Validation (done-when)

- `tests/test_source_accounting.py` (5): per-run attribution of marginal-unique /
  incremental-confirmed / FP rate / failure status; window aggregation; the dead
  source (not the still-contributing one) is the demotion candidate and the
  decision is reproducible; demote → skipped, reinstate → active, env override
  wins.
- Gate green; local/uncommitted.
