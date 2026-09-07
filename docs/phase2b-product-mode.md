# Phase 2B — Product-mode separation (the governance keystone)

A first-class **product mode** now selects, for every run, a **module
allowlist**, a **retention policy**, and an **export schema**. It is the single
control that lets one engine be both an aggressive security tool *and* a lawful
lead-gen tool without the two capability sets bleeding into each other — the
keystone the rest of Phase 2 (suppression, the lawful-public gate, eligibility,
retention/PROV) hangs off.

## The three modes

- **`security-investigation`** — today's full capability, renamed. Every
  registered module may run. This is the default, and it must show **zero
  regression** vs the post-1B baseline; governance is additive to it.
- **`public-business-contact`** — lead-gen. Only lawfully-published business
  contact sources and authorized user-supplied data. Breach/credential sources,
  account-reset probing, personal-email pivots, private-profile inference, and
  active mailbox probing for growth are not a lawful basis for cold B2B outreach
  and are excluded from its allowlist.
- **`org-authorized-verification`** — verification of contacts on a domain the
  operator is authorized over. The mode selection *is* the operator's
  attestation over the run's target domain (no separate assertion argument). It
  permits active verification against that domain but still excludes all
  breach/credential sources and personal pivots.

## What shipped

`backend/core/product_mode.py` — the single source of truth:

- `ProductMode` (a `str` enum) + `normalize_mode(...)`, which **fails closed**:
  `None` → the default; an *invalid* mode string raises `ValueError` rather than
  silently downgrading to something more permissive.
- An **exhaustive** per-module classification, seeded by composing the existing
  `backend/core/policy.py` sensitivity buckets (`_BREACH_MODULES`,
  `_INFOSTEALER_MODULES`, `_USERNAME_ENUM_MODULES`) rather than inventing a
  parallel taxonomy. `allowed_modes(name)`, `is_module_allowed(name, mode)`, and
  `mode_module_allowlist(mode)` derive each non-security mode's allowlist by
  subtracting named blocked buckets (credential / personal-pivot /
  profile-inference / infra-recon / active-probe). An **unclassified** module is
  denied in the two non-security modes (fail closed) — a safety net, not the
  norm, since the classification is kept exhaustive.
- Retention-policy and export-schema **hooks** (`retention_policy(mode)`,
  `export_schema(mode)`): 2B only establishes that mode *selects* these; the
  retention jobs are 2E and the export eligibility is 2D.

## Mode selection (config → CLI → API)

Threaded end-to-end mirroring the Phase-1B `budget_seconds` idiom (per-run
override else config default):

- Config: `settings.product_mode` (default `security-investigation`), with a
  fail-closed `@field_validator`.
- Investigate: `--mode` (CLI) / `InvestigateRequest.mode` (API) →
  `service.create_investigation(mode=…)` → `InvestigationEngine(mode=…)`, resolved
  once inside `investigate()`. The unauthenticated Maltego route takes the
  server default (a caller cannot pick a mode there, by design).
- Harvest: `--mode` threaded as a race-safe kwarg through `run_harvest_emails` →
  `run_domain_harvest` (no `settings` mutation).

## Mode recorded (run manifest + every observation)

So a fact's collection mode is always known:

- New `mode` columns on `observations`, `investigations`, and `crawl_snapshots`
  (Alembic **0005**, guarded/idempotent add-column, default
  `security-investigation`). The observation stamp is threaded through the single
  ledger choke point `build_observation(...)`; `content_hash` deliberately
  **excludes** mode, so identical evidence hashes identically regardless of the
  mode it was collected under.
- The engine writes `Investigation.mode`; `run_domain_harvest` stamps
  `result.metadata["mode"]`, which `corpus_store` persists to
  `CrawlSnapshot.mode` and the harvest ledger writer carries onto every harvest
  observation.

## Scope

2B is **framework + classification + recording only**. It does not yet block
dispatch — so all three modes currently run the full pipeline and behave
identically, which is why security-investigation is trivially zero-regression.
The dispatch gate that consumes this classification to actually deny a module is
**2C**; suppression is **2A**; the eligibility verdict is **2D**.

## Validation (done-when)

- `tests/test_product_mode.py` (35 assertions): enum/normalize (invalid raises);
  the classification is **exhaustive** against both live registries (every
  investigate `get_all_modules()` name and every harvest `MODULE_*` constant is
  classified); unknown module fails closed; "mode selects allowlist X"
  (breach/personal-pivot/username-enum/reset-carrier absent from the two
  non-security allowlists; lawful-public sources present; `outlook_autodiscover`
  org-only); mode is stamped onto every observation and excluded from the content
  hash; the config validator rejects a bad mode.
- Alembic 0005 applies cleanly across the 0001→0005 chain; the mode columns and
  the `observations.mode` index land; the downgrade round-trip is reversible
  (`tests/test_alembic_migrations.py` updated for the new `investigations.mode`).
- `gate check` green: 0 NEW test / ruff / hung failures vs baseline. (Adding a
  test file raised 4-worker contention and surfaced a latent timing flake,
  `test_slow_module_gets_partial_result`, which passes 9/9 in isolation — added
  to `eval/baseline/known-flaky.txt`, consistent with the Phase-1B/1E flakes.)
