# Phase 1E — Field-level provenance & conflict resolution

When several observations assert different values for the same `(subject, field)`
— e.g. "VP Engineering" vs "Engineer" for one person's title — they now coexist
as dated claims and the *current best* is selected by an explainable, determin­
istic rule. Nothing is overwritten: losing claims stay in the append-only ledger
and are returned alongside the winner, with the selection reasoning recorded.

This must exist before Phase 3 populates rich person fields, or those fields
would clobber each other (the failure mode of cheap contact DBs — Doc-1 #5).

## What shipped

`backend/core/claim_resolver.py` — a generic claim-resolution layer over the 1C
observations ledger:

- `resolve_field(observations, field)` — gather every observation carrying the
  field, group by value, score each, and select the winner; returns a
  `FieldResolution` with the winner **and** all losing candidates (each with its
  observation ids) plus machine- and human-readable reasoning.
- `resolve_subject_field(subject, field)` / `gather_observations(subject)` —
  resolve directly off the ledger.
- `resolve_report_fields(subject)` — resolve the standard report fields
  (`name`, `source_type`, `title`, `company`) for a subject, returning
  `{field: {resolved_value, reasoning, reasoning_data, candidates}}`.

**Surfaced** through the existing report path: `GET /api/report/{id}` now attaches
an additive, fully-guarded `field_provenance` block (the resolved value + "why
this won / what it beat" + the full candidate list). Existing report keys are
untouched; a ledger/resolution failure silently omits the block.

## Design decisions (exploration latitude)

- **Scoring reuses the existing source weighting** — `SOURCE_WEIGHTS` × the
  existing `freshness_factor` recency curve from `email_confidence`. No second
  weighting is invented (the brief's explicit constraint). A claim's score is
  `source_weight × freshness`; source types absent from `SOURCE_WEIGHTS` fall
  back to a small neutral weight so recency/support still decide.
- **Deterministic total order** (reproducible resolution): higher score → more
  recent → higher raw source weight → more supporting observations → lexical
  value. Ties never resolve randomly.
- **Computed on read**, not materialized: the ledger is append-only and a subject
  has few observations, so resolution is a cheap, always-current read-time
  projection with no refresh triggers.
- **Losing claims are retained and queryable** — they remain in the ledger, and
  the `FieldResolution` returns every candidate value with its observation ids,
  so "what it beat" is fully recoverable.

## Applied to fields that exist today
- `name` — pulled from the scattered name-bearing claim keys.
- `source_type` — the email's competing sources (which source is authoritative).
- `title` / `company` accessors are wired now (usually empty until Phase 3) so
  the mechanism is proven before it carries rich person fields.

## Validation (done-when)
- **Synthetic** conflicts resolve deterministically with reasoning and retained
  losers: title resolves by recency (VP Engineering beats a stale Engineer),
  name resolves by source weight (`pgp_uid` 1.0 beats a fresher weak snippet),
  corroboration merges + counts support. (`tests/test_claim_resolver.py`, 14.)
- **Real** multi-source conflict on a baseline target (`katriel@rootaccess.tech`,
  389 ledger observations): `name` resolves across 2 competing values and
  `source_type` across 10 (blackbird beats nexfil/maigret/sherlock by support) —
  deterministic, with recorded reasoning; losing claims retrievable by
  observation id.
- No regression vs baseline; `gate check` green.

## Non-scope (respected)
No new fields to resolve (Phase 3 adds titles/seniority). No calibration of the
selection weights (Phase 4). No UI beyond exposing the resolved value + reasoning
through the existing report path.
