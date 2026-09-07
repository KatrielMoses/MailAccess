# Phase 6 — The Shared Corpus Flywheel

Accuracy and speed compound over time — the moat. Phase 6 is the first phase that
*could* move data beyond the local machine, so the governing principle is
absolute: **private-by-default, publish-never-without-explicit-approval.** The
distribution and contribution paths are built as inert machinery; they publish
only (a) after the infra decision, (b) with explicit per-batch approval, and
(c) restricted to safe, non-contact-level artifacts. Contact-level data always
requires human review. This is a hard governance line, not a toggle.

All work is non-breaking, gate-green, and local/uncommitted. Nothing publishes.

## Local logic (built and active now)

### 6A — Confidence decay in the corpus — `backend/core/corpus_decay.py`
B2B contact data rots ~25–30%/yr (Doc-2 A4). A compounding read-first corpus
would otherwise serve stale-but-fast data at full confidence. Decay is a pure,
explainable transform applied at *serve* time over the `contacts` projection:
`factor = (1 - annual_rot) ** (age_days / 365)`, floored, keyed to
`contacts.last_verified`. A fresh row is unchanged (factor 1.0 → no regression);
an aging row is down-weighted; a row past `corpus_decay_stale_after_days` is
flagged `needs_reverification`. Stored confidence is never mutated (re-verification
restores it) and the parity-preserving crawl reconstruction is untouched. Served
via `read_leads` (`served_confidence_score` + `decay` + `needs_reverification`)
and `read_stale_contacts`.

### 6B — Safe-artifact classification — `backend/core/safe_artifact.py`
Defines, **exhaustively and fail-closed**, what may ever leave the local store.
Every `ArtifactKind` maps to `SHAREABLE` (aggregate, non-contact),
`REVIEW_REQUIRED` (contact-level — never auto-safe), or `NEVER` (internal/raw).
Unknown kind → `NEVER`. Defense in depth: a declared-shareable payload that
actually contains contact PII is downgraded to review-required. `partition_distributable`
is the single eligibility gate 6D/6E consult. The policy suite
(`tests/test_safe_artifact.py`) asserts no unsafe/contact-level artifact is ever
distributable without review.

### 6C — Corpus-derived Bayesian pattern priors — `backend/core/pattern_priors.py`
Aggregates verified per-provider/per-industry email-pattern *distributions* from
the corpus (Doc-2 A5) with Dirichlet smoothing and hierarchical shrinkage toward
the global base rate. Fed into pattern inference as a small bounded nudge through
the signal pool (`emit_corpus_pattern_priors` / `get_corpus_pattern_prior`),
applied in `pattern_and_verify` analogously to the Hunter boost. Privacy-safe:
aggregate distributions only, exported as 6B-shareable `*_PATTERN_PRIOR` artifacts.
Explainable via `PatternPriors.explain`. Beats a uniform predictor on Brier on a
labeled synthetic subset. No-op on an empty corpus.

### 6F — Change intelligence — `backend/core/change_intelligence.py`
Diffs consecutive corpus crawls into first-seen / disappeared / title-change /
verification-drift signals → likely-new-hire (new on-domain address matching the
org pattern) and likely-departure (previously-verified address gone, or
verified→bounced drift). Surfaces "likely stale" (6A) rather than silently
retaining. Read-only, guarded. Exposed at `GET /api/leads/{domain}/changes`.

## Distribution machinery (built now, activated last — INERT)

### 6D — Federated distribution — `backend/core/corpus_distribution.py`
Transport-agnostic core for signed, delta-based, domain-hash-sharded corpus
updates (Doc-2 A2, Doc-1 #15): content-hashed artifact entries, a pluggable
`Signer` (HMAC-SHA256 now, Ed25519 later), stable domain-hash sharding,
added/changed/removed delta computation, and rollback (each manifest names its
parent). Only 6B-safe artifacts are eligible (`build_manifest`,
`build_corpus_manifest`). The concrete network transport is intentionally
unimplemented behind `SyncAdapter`; the default `InertSyncAdapter` publishes
nowhere. `CorpusDistributor.publish` refuses unless the master switch is on AND a
concrete adapter is configured — inert by default.

### 6E — Opt-in contribution — `backend/core/corpus_contribution.py`
Batches a user's 6B-safe findings for upstream submission (Doc-2 A3):
license-gated, contributor-ID-hashed, per-batch/per-window rate-limited.
Contact-level data can never enter a batch without explicit per-batch review (6B
gate). Inert by default — `submit_contribution` refuses without opt-in + master
switch + concrete adapter. Every contribution attempt is written to the 2E
tamper-evident audit chain (`corpus.contribution`), even when inertly blocked.
The policy suite (`tests/test_corpus_contribution.py`) asserts the
no-raw-contact-without-review rule.

## Configuration (all default-safe)

| Setting | Default | Purpose |
|---|---|---|
| `enable_corpus_decay` | `True` | 6A serve-time decay |
| `corpus_decay_annual_rot` / `_min_factor` / `_stale_after_days` | `0.28` / `0.3` / `180` | 6A curve |
| `enable_corpus_pattern_priors` | `True` | 6C prior feed |
| `enable_change_intelligence` | `True` | 6F change signals |
| `enable_corpus_distribution` | **`False`** | 6D master switch (inert) |
| `enable_corpus_contribution` | **`False`** | 6E master switch (inert) |
| `corpus_distribution_shards` | `256` | 6D sharding |
| `corpus_signing_key` | `None` | 6D signing (local key generated if unset) |
| `corpus_contribution_max_per_batch` / `_per_window` / `window_seconds` | `500` / `5` / `3600` | 6E rate limits |

## Policy suites (never baseline these)
`tests/test_safe_artifact.py` and `tests/test_corpus_contribution.py` encode
hard governance invariants — their absence of failure is the guarantee.
