# Phase 5A — Bulk / list harvest mode

The scale phase (Doc-1 #16, Doc-2 C2). The pipeline already harvests one domain →
leads; 5A turns that into a **list of domains → one merged lead list**, in a
single governed, resumable, deduplicated run. This is the difference between a
research toy and a lead pipeline — and it is the workload that generates
verification/calibration volume at scale to feed the Phase-4 promotion gate.

## What shipped

- **`harvest-emails --file domains.csv`** (and `--file -` for stdin). A bulk run
  fans the list through a bounded concurrency governor, writes resumable
  per-domain checkpoints, dedups across the batch via the corpus, and emits **one
  merged, evidence-preserving export**. New flags: `--file`, `--concurrency`,
  `--checkpoint`, `--merged-export`, `--no-resume`.
- **`backend/core/bulk_harvest.py`** — the orchestrator (importable/testable):
  `parse_domain_list`, `BulkCheckpoint`, `run_bulk_harvest`, `BulkHarvestReport`.
- **`cli/harvest_bulk.py`** — the CLI driver: reads the list, resolves the
  per-domain option set *identically* to the single-domain path, renders batch
  progress + a summary table.
- **`corpus_store.known_domains(candidates)`** — a batched, guarded lookup against
  the persistent `domains` projection (the correct "ever-harvested" signal for
  cross-batch dedup; it survives TTL/invalidation, unlike `crawl_snapshots`).
- Config: `bulk_max_concurrent_domains` (default 3), `bulk_checkpoint_dir`,
  `bulk_results_dir`.
- **Live-path deliverability + 4A capture fix** (see "Calibration" below).

## Design decisions (exploration latitude)

- **Per-domain parity is by construction.** Each domain is harvested by the
  *identical* `run_domain_harvest(domain, **options)` coroutine the single-domain
  CLI uses, with identical option kwargs, and its canonical export is written by
  the *identical* `write_harvest_export`. Only the Rich display callbacks are
  omitted (display-only; they cannot change what a domain yields). So a domain in
  a batch yields byte-identical results and per-domain exports to a solo run.
- **Concurrency governor.** A single `asyncio.Semaphore` bounds how many *domains*
  harvest at once (each domain is itself internally two-track concurrent). Modest
  by default so the batch does not self-DoS shared sources — Phase 5B unifies the
  throttle across both transport stacks and adds egress rotation, which is what
  makes 5A trustworthy at real volume.
- **Checkpoint format.** A JSON manifest keyed (by default) by the input-list
  fingerprint (sha256 of the sorted domain set), persisted atomically after every
  domain. Statuses: `pending` / `running` / `done` / `cached` / `skipped` /
  `failed`. Re-running the same file resumes: `done` domains are skipped, and their
  per-domain export is reloaded from disk so the merged export stays **complete**
  across a resume (a full-resume run never overwrites the merged export with an
  empty one). `--no-resume` forces a fresh pass; `--force` re-harvests every
  domain (bypassing the corpus read-first).
- **Merged-export schema.** A distinct document (`kind: "bulk_harvest"`,
  `schema_version: 1`, independent of the per-domain export's `schema_version 2`):
  a per-domain section keeping each domain's **full** rows (evidence intact) plus
  a `contacts` list deduplicated by address across the whole batch — each merged
  contact records the set of `source_domains` it was seen on and the max
  confidence. Deduping never drops evidence.
- **Resilience of the batch itself.** One domain failing (or timing out) is
  isolated — it is marked `failed` and the batch continues; the run only exits
  non-zero if *every* domain failed.

## Governance (inherited, per-run)

Bulk adds no new governance surface — it inherits Phase 2 per run, for free:
`--mode` unions `blocked_modules(mode)` into each domain's `skip_modules`,
`active_mailbox_probing_allowed` disables SMTP in public-business-contact mode,
suppression filters exports at read-time, and every row carries its eligibility
verdict. The active-mode contextvar is set per `run_domain_harvest` call, so the
lawful gate applies independently to each domain in the batch.

## Calibration (4A at volume) — and a live-path fix

5A must "populate the 4A capture." While wiring this up we found the Phase-3C/3D
deliverability grading + Phase-4A feature capture were only invoked from the
legacy `_orchestrate` path — **not** from `run_adaptive_harvest`, the path the CLI
and API actually run. So in the live path deliverability grades came out `None`
and no 4A snapshots were written (for single *or* bulk harvests).

The fix wires the pass into the live adaptive path (`harvest_runner.py::
_grade_leads_and_capture`, called after aggregation on both the normal and
partial-timeout return paths), guarded and skipped for injected-module
test/embedder runs. `run_bulk_harvest` also ensures the DB schema exists before
the batch starts (harvest runs in-process and the corpus only creates tables at
write-back, i.e. end-of-run — so the mid-run capture would otherwise no-op on a
fresh DB). Net effect: single and bulk harvests now both populate deliverability
grades identically (parity preserved), and a bulk run accrues the
`score_feature_snapshots` volume the ≥200-label promotion gate needs.

## Validation (done-when)

- **Unit** — `tests/test_bulk_harvest.py` (10 tests): list parsing
  (dedup/validate/strip), merged + per-domain export, evidence preservation,
  cross-batch contact dedup, concurrency-governor bound, checkpoint resume-skip,
  resume-keeps-merged-export-complete, `--no-resume` re-harvest, isolated per-domain
  failure, guarded `known_domains`, and CLI `--file` dispatch.
- **Real, keyless, isolated** — `eval/harness/bulk_parity.py` proves the done-when
  criteria against live harvests: per-domain parity (solo vs in-batch), one merged
  evidence-preserving export, cross-batch dedup, resumability (re-run skips all,
  completes fast), and 4A capture populated. Run:

      uv run python -m eval.harness.bulk_parity --timeout 240 \
          lavellenetworks.com rootaccess.tech stripe.com

  A single-domain smoke (`rootaccess.tech`) confirmed end-to-end: 45 contacts,
  all graded, 45 4A feature snapshots, merged export + checkpoint written, resume
  skips in 0.1s and keeps the merged export complete.
- **Gate** — `python -m eval.harness.gate check` green (no new test/lint/hang
  failures vs baseline).

## Non-scope

No new discovery (5C) — 5A takes a given domain list. No new sources. Resilience
(CC-first, egress rotation, search failover, unified throttle) is 5B; today's DDG
202 / Common-Crawl-timeout noise a keyless bulk run shows is exactly what 5B
addresses.
