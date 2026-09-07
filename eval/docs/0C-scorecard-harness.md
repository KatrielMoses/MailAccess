# 0C — Metrics Scorecard & Harness

**Goal:** a repeatable harness that runs **both pipelines** over the frozen
target set and emits a **fixed, machine-readable scorecard** scored against the
0B truth labels. The scorecard shape is the contract every later phase reports
against — its top-level keys are stable.

## Components

| File | Role |
|---|---|
| `harness/run_baseline.py` | Drives both pipelines over the target set, unattended. Writes raw tool exports + a `runlog.json` + a `manifest.json` per run. |
| `harness/manifest.py` | Captures the run manifest (below). |
| `harness/score.py` | Reads a run dir + truth labels → `scorecard.json` + `scorecard.md`. |

## How the tool is driven

Both pipelines are driven through the **public CLI** (`python -m cli.main …`),
not internal APIs, so the harness survives the coming internal refactors and the
scorecard stays comparable:

* investigate: `investigate <email> --format json --output <raw>.json --timeout 30`
* harvest: `harvest-emails -d <domain> --export <raw>.json --timeout <t>`

### Environment isolation (why numbers are trustworthy)

Each target runs with a **fresh, isolated HOME** (`USERPROFILE`/`HOME` redirected
to a per-run scratch dir), so the investigate SQLite DB, harvest results, and
caches are captured per-run and never touch the user's real `~/.mailaccess` or
leak state between targets.

* **`keyless-default` (PRIMARY):** every API key name and every dotenv-defined
  name is stripped from the child environment, and the tool runs from an
  isolated cwd so `./.env` is not read. Result: the tool falls back to code
  defaults — the true zero-key posture. Key-gated modules skip themselves.
* **`with-keys` (SECONDARY):** the tool runs from the repo root and reads the
  repo `./.env` keys itself. The harness never reads/stores key values.

## Run manifest (captured every run)

`manifest.json` records, for reproducibility:

* `tool_version`, `git_commit`, `git_dirty`
* `config_label` (keyless-default / with-keys) and a `config_hash`
* `host` (hostname, platform, python version + executable)
* `resolved_config` — whitelisted non-secret settings (opt-in module toggles,
  harvest export/results settings, sanitized DB url)
* `keys_present` — **names → bool only. Key values are never read, stored,
  printed, or serialized.** (`keys_present_names` lists the set ones.)
* `seed` (n/a for this tool today)

## Metrics computed (per-target and aggregate)

| Metric | Investigate | Harvest |
|---|---|---|
| **Yield** | finding_count, module_count, exposure_score | unique emails by tier (CONFIRMED/LIKELY/MEDIUM/LOW), role accounts, people |
| **Precision** | TP/(TP+FP) over labelled `accounts[]` | TP/(TP+FP) over labelled emails |
| **Recall** | (labelled accounts) | found ∩ known_contacts / known_contacts |
| **Latency** | wall-clock per target* | wall-clock + `summary.module_timings` per module |
| **Brier (calibration)** | per-finding confidence when present | tier→prob mapping (below) vs labelled outcome |
| **Per-source FP rate** | — (labelled accounts) | per `found_by_modules` over labelled emails |
| **Deliverability** | — | SMTP verdict counts + catch-all handling |
| **Pattern correctness** | — | `summary.confirmed_pattern` vs truth |
| **Catch-all correctness** | — | `summary.catchall_detected` vs truth |
| **Run-to-run stability (0D)** | yield/wall variance across `--runs` | yield/wall variance across `--runs` |
| **Policy/safety snapshot** | which sensitive modules fired/skipped | which sensitive modules fired/skipped |

\* **Investigate per-module timing is not reliable** at v0.14.4: every
`ModuleRun` is persisted with the whole-run `started_at`/`finished_at`, so
per-module durations collapse to the full-run span (`engine.py` `_persist`). The
scorecard flags this via `latency.per_module_timing_reliable = false`. Harvest
exposes real per-module timings (`summary.module_timings`). This is a baseline
finding for a later phase, not something to fix in Phase 0.

### Confidence → probability mapping (for Brier)

Documented and adjustable (you have latitude on method per the brief):

| Harvest tier | P(correct/deliverable) |
|---|---|
| CONFIRMED | 0.95 |
| LIKELY | 0.80 |
| MEDIUM | 0.60 |
| LOW | 0.30 |

Brier = mean((p − outcome)²) over **labelled** items only (outcome = 1 if the
email is a truth TP, 0 if an explicit FP). Lower is better. Unlabelled findings
are excluded because truth is non-exhaustive.

### Truth-dependent metrics degrade gracefully

Precision / recall / Brier / per-source-FP require 0B labels. For a target with
no truth file, these are `null` and the target carries `truth_status:
"no_truth"`. That is the expected baseline state for third-party targets and is
reported honestly — not hidden, not guessed.

## Scorecard outputs

Per run dir (`eval/scorecards/<run_id>/`, gitignored):

* `manifest.json` — the run manifest.
* `runlog.json` — per (target, run) exit code, wall time, artifact paths;
  written incrementally so a long run is **resumable/inspectable** mid-flight.
* `raw/<target>.run<N>.<pipeline>.json` — the tool's own export, untouched.
* `logs/<target>.run<N>.<pipeline>.log` — stdout/stderr.
* `scorecard.json` — the fixed machine-readable scorecard.
* `scorecard.md` — human-readable summary.

## Running

```bash
# Primary keyless baseline, one pass over all 8 targets:
uv run python -m eval.harness.run_baseline --config keyless-default --runs 1

# Stability (0D): 3 repeats of just the domains:
uv run python -m eval.harness.run_baseline --domains-only --runs 3

# One target, unattended (the 0C "done-when" smoke):
uv run python -m eval.harness.run_baseline --only corp_own_2 --emails-only

# Secondary, with keys (labelled separately, never mixed in):
uv run python -m eval.harness.run_baseline --config with-keys --runs 1

# Score any run:
uv run python -m eval.harness.score --run eval/scorecards/<run_id>
```

Timeouts: `--investigate-timeout` (default 240s) and `--harvest-timeout`
(default 720s; harvest profile default is T2=600s). A target that times out is
recorded with `timed_out: true` and `ok: false` rather than hanging the run.

## Done-when

- [x] Harness drives both pipelines over the target set unattended.
- [x] Run manifest captured every run (version, config, module set, opt-ins,
      keys-present names-only, timestamp, host, seed).
- [x] Scorecard emitted in machine-readable JSON **and** human-readable summary.
- [x] Keyless-default is the primary config; with-keys is separate and labelled.
