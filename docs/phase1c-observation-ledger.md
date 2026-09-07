# Phase 1C — Canonical evidence ledger

Introduces a single immutable observation record as the atomic unit of
everything the tool learns — the substrate both pipelines write to and (from
Phase 1D) every displayed field traces back to.

## What changed

Two new tables (Alembic revision `0003`, additive only — nothing existing is
touched, and `findings` is left exactly as-is):

- **`observations`** — the append-only ledger. One immutable row per public
  observation, from either pipeline, carrying full provenance.
- **`observation_raw_payloads`** — optional, expiry-bound raw evidence bytes,
  off by default.

Both pipelines now **dual-write** observations *alongside* their existing
outputs, which are unchanged:
- **investigate** — the engine writes observations after `_persist`, in its own
  transaction (a ledger failure can never roll back the findings).
- **harvest** — the CLI writes observations at the export boundary (the
  orchestrator stays pure); harvest doesn't run `serve`, so it ensures the
  schema via `init_db` first.

## The observation record (provenance-complete)

| Field | Meaning |
|---|---|
| `subject` / `subject_type` | normalized entity the observation is about (email / domain / username) |
| `claim` (JSON) / `claim_key` | the asserted value/payload + a normalized lookup key |
| `source_type` / `source_url` | the source — drawn from the finding's **existing** `SOURCE_WEIGHTS`/module labels (no parallel taxonomy) |
| `capture_time` | when the evidence was observed |
| `content_hash` | sha256 of the evidence (see below) |
| `extraction_method` / `module_version` | the module + its version |
| `source_policy_status` | populated now (`unreviewed`), enforced in Phase 2 |
| `expires_at` | default TTL (`ledger_default_ttl_days`, 180); per-source-type refinement is Phase 2 |
| `pipeline` / `activity_id` | the run that produced it |

**PROV-DM shape (for the Phase 2 export):** the row is the PROV *entity*;
`activity_id` + `pipeline` + `extraction_method` + `module_version` identify the
*activity* (the module run); `source_type` + `source_url` identify the *agent*
(the source).

## Design decisions (exploration latitude)

- **Content hash** — sha256 of a canonical JSON of the evidentiary core
  `(subject_type, subject, source_type, source_url, extraction_method, claim)`,
  with volatile/run-specific claim keys (timestamps, latencies, ids) stripped
  first. Deterministic, so **identical evidence hashes identically across
  re-runs**, invariant to volatile fields, sensitive to substantive ones. When
  raw evidence bytes are supplied and raw storage is on, the bytes are hashed
  instead.
- **Module version** — a module may declare a `version` attr; otherwise the
  package version (`APP_VERSION`), since modules ship as one versioned package.
- **Identity / dedup** — the ledger is **append-only**: a re-observation is a
  new row (same `content_hash`, new `id`), never a mutation. `content_hash` and
  `claim_key` are indexed for later collation; no dedup on write.
- **Raw payloads** — `content_hash` is always stored; the raw bytes only when
  `ledger_store_raw_payloads` is enabled AND a module supplies them, and are
  expiry-bound.

## Config
- `enable_observation_ledger` (default True) — master switch; the dual-write is
  always fully guarded so a ledger failure can never break a pipeline.
- `ledger_default_ttl_days` (180; `<=0` = no expiry).
- `ledger_store_raw_payloads` (default False).

## Validation (done-when)
- **Real investigate** (`rootaccess.tech`, keyless): exit 0, 327 findings →
  **327 observations (1:1)**, 0 rows missing required provenance, export has no
  observation leakage.
- **Real harvest** (`rootaccess.tech`, keyless): exit 0 → **53 harvest
  observations**, 0 missing provenance, export unchanged.
- Content hash reproducible from a stored claim (stability); append-only proven
  (identical evidence → 2 rows, same hash, distinct ids).
- Existing outputs byte-for-byte unchanged (no report/export/enrich code
  touched; observations are a separate table nothing reads yet).
- `gate check` green (0 NEW test/lint/hang).

## Non-scope (respected)
Report/export still read `findings`, not the ledger (that's 1D). Policy status is
recorded, not enforced (Phase 2). The `findings` table is unchanged.
