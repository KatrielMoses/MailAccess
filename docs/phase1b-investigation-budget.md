# Phase 1B — Investigation budget & completion fix

Makes investigate mode reliably complete within a configurable time budget and
stops it silently failing (exit 3) when the default module set overruns a hard
cap.

## The defect (from Phase 0D)

`investigate` on `lavellenetworks.com` timed out 3/3 with **exit 3**. Two
compounding causes:

1. **Client-side hard cap.** The CLI wait loop had a fixed
   `_MAX_POLL_ATTEMPTS = 60` (60 × 2 s = **120 s**) in the JSON/polling path (and
   a 360 s WebSocket deadline). The eval harness runs `investigate --format json`,
   so it took the 120 s polling path and returned **3** while the server was
   still working.
2. **No server-side budget.** The engine runs `PHASE_DAG` to completion, bounded
   only by per-module timeouts. Heavy username-enumeration modules have timeout
   *floors* (`username_platforms` 200 s, `account_discovery` 180 s) and
   run concurrently in the primary phase, so a footprint-poor corporate target
   drives the primary phase to ~200 s+ — over the 120 s client cap.

Measured: with the fix, `lavellenetworks.com` completes in **~257 s**, exit 0,
320 findings — it was never failing on the server, the client just gave up.

## What changed

### Server-side wall-clock budget
- New `InvestigationBudget` (`backend/core/investigation_budget.py`) — the
  investigate analogue of harvest's `TimeBudget`: a single monotonic deadline
  (harvest's two-track soft/hard model is overkill for one linear phase DAG).
- `InvestigationEngine(budget_seconds=...)` builds the budget at run start and
  threads it through every phase into `run_one_module`.
- In `run_one_module`, each module's effective timeout is
  `min(module_timeout, budget.remaining())`. If the budget can't fit another
  module (`remaining <= min_module_seconds`), the module is **skipped without
  starting**. Either way the module is recorded as **`budget_truncated`**
  (`SKIPPED` if never started, `PARTIAL` if cut short) — no silent drops.
- The investigation still reaches **COMPLETE** (partial), never FAILED, on
  truncation. A real exception is still FAILED.

### Config + flags
- `investigation_budget_seconds` (default **420**), `--budget` CLI flag, and the
  API `budget_seconds` field. `<= 0` = unlimited.
- `investigation_budget_min_module_seconds` (default 2).
- `investigation_fast_modules` — pin a fast primary module set via config (the
  Phase-0 fast-run workaround, persisted). When non-empty and no explicit
  `--modules` is given, the primary phase is restricted to those names.

Why **420 s** default: the slowest baseline target (`lavellenetworks.com`)
completes naturally in ~257 s; 420 s gives ~63% headroom for run-to-run network
variance so the **full default module set completes** on every baseline target
without truncation. The budget is a safety ceiling that only bites pathological
runs, not a target the normal case hits.

### Client wait aligned to the budget
- The CLI derives its wait ceiling from the effective budget:
  `budget + 90 s` margin (finalization / graph enrichment + network), replacing
  both the fixed 120 s poll cap and the 360 s WS deadline. Raising `--budget`
  therefore also lets the client wait longer. `--budget 0` waits up to 1 h.

### Honest partial reporting
- `enrich_report` adds a `budget` block — `truncated`, `truncated_modules`,
  `truncated_count`, `completed_modules`, `completed_count` — derived from the
  per-module `budget_truncated` metadata (no schema change). The one-line
  `summary` appends a truncation note. The CLI table output prints a visible
  "⏱ Time budget reached — N module(s) truncated: …" notice.

### Exit-code semantics (0/1/2/3, unchanged scheme, now honored)
| Code | Meaning |
|---|---|
| 0 | Completed — **including a budget-truncated partial run** |
| 1 | Investigation terminal status `failed` |
| 2 | Invalid input (bad email) |
| 3 | Server unavailable / client gave up waiting (now rare — server enforces the budget) |

The old bug returned **3** for a healthy-but-slow run; it now returns **0**.

## Non-scope (respected)
No module behavior or individual module-timeout *values* changed; no new modules.
Only the overall budget was made coherent and the client wait aligned to it.

## Eval / re-baseline
`eval/harness/run_baseline.py` `--investigate-timeout` raised 240 → **600** so the
subprocess timeout exceeds the CLI wait ceiling (~510 s at the 420 s default) and
never kills a healthy long run. Investigate was re-baselined (`--emails-only`)
into the scorecard — the first intended movement of the reference line — after
this landed.

## Done when — status
- [x] Hardcoded ~120 s completion ceiling removed; replaced by a configurable
      budget (config + `--budget` + API field).
- [x] Budget reached ⇒ partial results with an explicit completed-vs-truncated
      record; no silent drops; no exit 3 on a successful partial.
- [x] Sane default (420 s) lets the default module set complete on all baseline
      targets; fast module set pinnable via `investigation_fast_modules`.
- [x] `lavellenetworks.com` completes exit 0 (~257 s); truncation is reported
      when forced with a low budget (tested); `gate check` green.
