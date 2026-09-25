# MailAccess — Phase 0: Baseline & Evaluation Harness

This directory is the **frozen ruler** for the MailAccess re-architecture. It
measures what the tool does *today* (v0.14.4) so every future phase can prove it
improved things without regressing. **No engine/module/scoring changes live
here** — Phase 0 only *measures*.

The tool has two independent pipelines; both are baselined:

| Pipeline | Command | Shape | Persistence |
|---|---|---|---|
| **Investigate** | `mailaccess investigate <email>` | email → identity/exposure | server-backed, SQLite in `~/.mailaccess` |
| **Harvest** | `mailaccess harvest-emails -d <domain>` | domain → emails | in-process, JSON in `~/.mailaccess/results` |

## Layout

```
eval/
  targets.example.yaml     # committed template for the target set
  targets.yaml             # REAL authorized targets (gitignored — has PII)
  harness/
    manifest.py            # run manifest (tool version, config, keys-present names-only)
    run_baseline.py        # drive both pipelines over the target set, unattended
    score.py               # compute the fixed scorecard vs truth labels
    gate.py                # CI baseline-diff gate (new-failure detection)
    init_truth.py          # generate empty truth stubs to fill
  truth/                   # 0B gold labels — README + _schema committed; *.yaml gitignored
  scorecards/              # 0C outputs (gitignored) — one dir per run
  baseline/                # committed known-failure baselines for the gate
  docs/
    0A-reproducible-install.md
    0B-gold-corpus.md
    0C-scorecard-harness.md
    failure-catalogue.md
```

## Quickstart

```bash
# 0A — reproducible install (uv)
uv sync --extra dev            # fresh, locked venv from uv.lock

# 0B — create truth stubs, then fill them in by hand (see docs/0B)
uv run python -m eval.harness.init_truth

# 0C — run the baseline (keyless primary config) and score it
uv run python -m eval.harness.run_baseline --config keyless-default --runs 1
uv run python -m eval.harness.score --run eval/scorecards/<run_id>

# CI gate (locally)
uv run python -m eval.harness.gate check
```

## The two run configs

* **`keyless-default` (PRIMARY):** the tool runs in an isolated environment with
  **every API key stripped** and no dotenv picked up — exactly what a zero-key
  user gets. Key-gated modules (`hibp`, `google_dork`, `hunter_io`, `emailrep`,
  `domain_intel`/Shodan, …) skip themselves. This is the headline baseline.
* **`with-keys` (SECONDARY, labelled):** the tool runs from the repo root so it
  reads the repo `./.env` keys itself. Reported separately, never mixed into the
  primary numbers. The harness never reads or stores key values.

## Phase JEV — side-by-side (JEV off vs JEV on)

`jev_compare` runs the same target set twice on the local build — JEV forced
**off** (== current behavior) and JEV forced **on** — scores both with the
unchanged scorer, and writes `comparison.json` / `comparison.md`: per-task JEV
defer rate / reasons, cache-hit rate and latency, per-target output deltas,
quality deltas vs truth, and any score drift. Every JEV phase is accepted or
dropped on this scorecard.

```bash
export JEV_API_KEY=... JEV_BASE_URL=... JEV_MODEL=...   # read from THIS shell only
uv run python -m eval.harness.jev_compare run --base keyless-default --runs 2
uv run python -m eval.harness.jev_compare compare --off <dir>/off --on <dir>/on
```

Legacy configs (`keyless-default`, …) strip every `JEV_*` variable, so an exported
JEV setting can never leak into a baseline. `--refresh-cache` makes the ON pass
skip JEV cache reads.

## Safety / authorized-use

Authorized evaluation only. The target set, truth labels, and scorecards stay
**local** (gitignored). The harness never passes `--contribute` and never seeds
any shared corpus. See each `docs/` file for detail.
