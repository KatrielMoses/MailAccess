# Phase 3A — HarvestedEmail → Lead

Paid lead-gen tools sell *a person*, not a string. The harvest already *collected*
the person signals (Hunter, company-page structured data, LinkedIn SERP, the name
a verified pattern was built from) but they sat untyped inside
`HarvestedEmail.evidence` and never reached a first-class field. 3A promotes them —
resolved through the Phase-1E conflict layer so competing claims don't clobber.

## What shipped

- **`backend/core/lead_person.py`** — `resolve_person_fields(entry, *, mode)`
  builds resolution-ready observation dicts from *this email's own evidence*
  entries and runs each person field through `claim_resolver.resolve_field`
  (Phase 1E), attaching the winner + a provenance link. Fields: `full_name`,
  `first`, `last`, `job_title`, `seniority` (3B), `department`, `linkedin_url`,
  `phone`, `location`.
- **`HarvestedEmail`** gains those typed fields + `person_field_provenance`
  (`domain_harvest_orchestrator.py`). `_apply_person_attribution` runs as a guarded
  post-aggregation pass (additive only — email-only leads are untouched, so yield
  never regresses).
- **`claim_resolver._FIELD_KEYS`** extended additively (`first`/`last`/`department`/
  `linkedin_url`/`phone`/`location`, `source_name` added to `name`).
- **Corpus projection** — the `contacts` table gains the nine person columns +
  `person_field_provenance` (**Alembic 0008**, first migration to touch
  `contacts`); `_refresh_contacts` maps them from the lead.
- **Exports** — a `person` block on every JSON/NDJSON row, `person_*` columns
  appended to CSV, `schema_version` bumped to **2**. All additive: existing
  email-only consumers are unaffected.
- **Read-only Lead API** — `GET /api/leads/{domain}` (+ `/verification-history`)
  over the corpus projection, with `seniority`/`grade`/`has_person` filters
  (`backend/api/routes/leads.py`, `corpus_store.read_leads`). Mounted under
  `/api`, so the Phase-2F auth middleware protects it; per-principal quota applied.

## Design decisions (exploration latitude)

- **In-memory 1E resolution over evidence.** The resolver takes plain dicts, so
  each lead's `evidence[]` is resolved directly — the orchestrator stays pure (no
  DB dependency mid-harvest) while using the *real* conflict layer. The synthetic
  observation id (`ev:<i>`) is the provenance link back to the evidence entry.
- **Evidence-or-null, asserted.** A field is set only when an evidenced claim
  resolves; `_assert_provenance_invariant` scrubs any populated field lacking an
  evidence link or documented derivation. Name halves compose from each other and
  inherit the source's provenance.
- **Mode-aware.** In `public-business-contact`, `phone`/`location` survive only
  when the winning observation traces to a published-business source
  (`_BUSINESS_CONTACT_SOURCES`); otherwise dropped with a recorded
  `suppressed_by_mode` note (defense-in-depth — profile-inference modules don't run
  in public mode anyway).
- **Multi-valued fields** are represented as the resolved scalar winner plus the
  full candidate list in `field_provenance` (losers retained, per 1E).

## Validation (done-when)

- `tests/test_lead_person.py` (8): Hunter promotion; every populated field has an
  evidence link; conflicting titles resolve by recency without clobbering (loser
  retained); public-mode drops non-business phone/location but keeps
  business-sourced location; empty/absent evidence → no fabricated fields.
- `tests/test_lead_export.py` (5): person block + grade in JSON/NDJSON/CSV,
  `schema_version==2`, legacy columns unchanged.
- Migration 0008 applies / downgrades / re-applies cleanly; `contacts` columns
  match the ORM. Cache serializer round-trips the new fields (`fields(HarvestedEmail)`
  is dynamic) — corpus parity preserved.
- Person-field precision is computed in the scorecard against the labelled subset
  (`no_truth`/null until labels land — the honest baseline state).

## Non-scope (respected)

No title→seniority math here beyond calling 3B; no new data sources (Phase 5); no
deliverability (3C+). The email↔person linkage reuses the existing evidence, not
new collection.
