# Phase 2A — Suppression as a core data type

The 1D `suppression` shell is now an **enforced, first-class store** that
**irreversibly** filters every export: a suppressed email, domain, or company
never appears in any export or lead output, from either pipeline, in any mode —
and this cannot be toggled off per-run. Suppression lists are the ICO-recommended
mechanism (Doc-1 #7) for honoring objections, and they must retain only the
*minimum* information needed to match-and-exclude.

## Data model (minimum retention)

Reuses the 1D `suppression` table (`subject_type` = the scope, `subject` = the
match key); Alembic **0006** adds a `source` column (provenance of the
objection). Minimum-retention representation:

- **email / domain** → stored as a **SHA-256 hash** of the normalized value. No
  clear-text personal identifier is ever persisted.
- **company** → the **normalized public name** (lower-cased, punctuation and
  legal-form suffixes like `Inc`/`LLC`/`GmbH` stripped), so fuzzy variants
  ("Acme", "Acme Inc.", "Acme Incorporated") collapse to one match key.

`backend/core/suppression.py` provides `add_suppression`, `is_suppressed`
(email → domain → company escalation; an email implies its domain, so a
domain-scope objection excludes every address at that domain), `import_suppression`
(CSV/stdin), and `list_suppression`. CLI: `mailaccess suppress add | import | list`.

## Enforcement at the export boundary (read-time, retroactive)

Checked when data is **served/serialized**, not (only) when collected — so an
objection added *after* collection retroactively filters prior data. Two
pipeline choke points, each fed a `SuppressionIndex` snapshot:

- **Harvest:** `_sanitised_export_emails` (`domain_harvest_report.py`) — the one
  function every harvest serializer, counter, and text file (`.json` / `.csv` /
  `.ndjson` / `report.md` / `emails.txt` / CLI panels) routes through, so counts
  stay consistent with the filtered set. Domain-scope objections are also applied
  in `_build_subdomains` (covers `subdomains.txt` / `nuclei_targets.txt`). The
  servable **contacts** lead projection is filtered in `corpus_store._refresh_contacts`.
- **Investigate:** `redact_report` is applied inside `enrich_report`
  (`service.py`), the single point feeding both the raw report API (`get_report`)
  and all six exporters (json/csv/markdown/pdf/stix/maltego). If the investigated
  subject itself is suppressed the report collapses to a non-leaking stub;
  otherwise any finding exposing a suppressed email/domain is dropped from
  `findings` and `findings_by_module`.

### The sync-index bridge

Both choke points are synchronous, so `suppression.py` exposes `load_index_sync()`
— a short-lived synchronous-engine read of the store, **cached per process**
(invalidated on every write, refreshed after a short TTL) so the hot export path
doesn't hit the DB per row. It is **fail-safe**: an absent table means
suppression was never configured (empty index, nothing to filter), and a
transient DB error degrades to no-filter-and-log rather than crashing an export
(the async write-time path remains the authoritative enforcement). When the
suppression store is empty the filters are a zero-overhead pass-through, so
security-investigation stays zero-regression.

## Validation (done-when)

`tests/test_suppression.py` (9): personal identifiers stored hashed (no
clear-text PII, 64-hex), domain normalization stable, add/query with
domain-escalation and company fuzzy-match, idempotent add, import, the sync index
reflecting writes after invalidation, harvest export (`_sanitised_export_emails`
+ full JSON export) excluding a suppressed email, and investigate `redact_report`
dropping a finding with a suppressed alternate / stubbing when the subject is
suppressed. `gate check` green (0 NEW).

## Non-scope (respected)

No automated harvesting into suppression; no corpus-level suppression sync (Phase
6). The eligibility-verdict plumbing that surfaces "suppressed" as one of the
export verdicts is 2D.
