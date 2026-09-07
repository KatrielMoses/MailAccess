# Phase 1D — Unified corpus store (the "two worlds" merge)

Replaces the per-domain JSON harvest cache with a single local corpus DB, and
routes harvest through DB-backed **read-first / write-back**. The 1C observations
ledger is the shared source of truth; the corpus tables are read models over it.

## What changed

New corpus tables (Alembic revision `0004`, additive; `findings` and all prior
schema untouched):

| Table | Role |
|---|---|
| `crawl_snapshots` | one row per harvest crawl; holds the full serialized result for **parity-identical, offline read-first** reconstruction (append-only history) |
| `domains` | aggregate projection: one row per known domain |
| `contacts` | aggregate projection: one row per `(domain, email)` — email-centric (person fields are Phase 3); carries `last_verified` for decay |
| `verification_outcomes` | per-contact SMTP/provider verification results |
| `suppression` | **shell** table for schema completeness — enforcement is Phase 2 (nothing reads it) |

`policy_status` / `eligibility_status` columns on `domains`/`contacts` and the
`suppression` table are created now so Phase 2 needs no re-migration.

**Harvest read-first / write-back** (`backend/core/corpus_store.py`, wired into
`run_domain_harvest`):
- **read-first** — a fresh `crawl_snapshots` row reconstructs the result offline
  and instantly; only missing/stale domains run collection.
- **write-back** — a fresh crawl appends a snapshot and refreshes the aggregate
  projections.

The per-domain JSON (`harvest_results.py`) is now only an **export**, not the
source of truth. The old JSON cache (`harvest_cache.py`) is retained (its
serializer is reused, and `--clear-cache`/doctor still touch it for backward
compatibility) but is no longer the harvest read-first source.

## Design decisions (exploration latitude)

- **Projection strategy — maintained tables, not views.** `crawl_snapshots`
  materializes the full result (so read-first is byte-identical and offline);
  `domains`/`contacts`/`verification_outcomes` are maintained aggregates. Per
  domain the projections are a *latest-view* (contacts are replaced on
  re-harvest); the append-only 1C ledger keeps full history. Views couldn't carry
  `last_verified`/derived state or serve offline read-first.
- **Parity is guaranteed by construction.** `crawl_snapshots.result_json` uses
  the *same* serializer the JSON cache used (`harvest_cache._serialize_result`),
  so a corpus read-first hit deserializes to an identical `DomainHarvestResult` —
  same emails, same confidence labels, same evidence links.
- **Corpus key model.** `domains` keyed by normalized domain (unique); `contacts`
  unique on `(domain, email)`; `verification_outcomes` FK → contact (+ email for
  lookup); `crawl_snapshots` keyed by id, indexed by domain.
- **Staleness threshold.** Reuses `harvest_cache_ttl_seconds` (3600s) plus
  version-binding — a snapshot from an older `mailaccess_version` is stale. Same
  semantics as the JSON cache, so behaviour is unchanged; a fresh domain is a
  read-first hit, a stale/missing one re-collects. (Finer per-source incremental
  collection is a future refinement; "missing/stale" is domain-granular here.)
- **Decay readiness (Doc-2 A4).** `contacts.last_verified` is set to the crawl
  time on every write-back; observations carry `capture_time`. Phase 6 layers a
  decay curve on `last_verified` with no schema change.
- **libSQL / embedded-replica readiness.** Left open, not adopted: the corpus is
  ordinary tables on the app's async engine, so a future Phase-6 embedded replica
  can sync them unchanged.
- **Guarding.** Every corpus entry point is fully guarded — a corpus failure
  logs and is swallowed; the harvest and its JSON export are unaffected. A
  read-first hit does not re-write the ledger (append-only) or the corpus.

## Parity harness

`eval/harness/corpus_parity.py` — the concrete non-regression net. For each of
the 3 baseline domains it runs a fresh (DB-backed) harvest and a repeat, and
asserts the repeat is a corpus read-first hit, materially faster, with an
identical email set (and confidence labels) versus the corpus the read-first
reconstructs from. Unit tests (`tests/test_corpus_store.py`) additionally prove
the corpus and legacy JSON reconstructions are byte-identical (emails +
confidence + evidence), projections are populated, staleness is respected,
re-harvest is a latest-view while snapshots append, and the whole path is inert
when disabled.

> Note: like the old JSON-cache path, a read-first hit returns early, so a
> repeat harvest with `--export` does not re-write the export file — pre-existing
> behaviour, preserved. Parity is proven against the corpus (exactly what the
> read-first hit returns).

## Non-scope (respected)
No corpus sync/distribution (Phase 6). No person/lead fields (Phase 3). No
suppression enforcement (Phase 2 — table created, gate not wired). Investigate
report tables unchanged; the investigate path still reads `findings`.

## Done when — status
- [x] Corpus tables created (domains, contacts, verification_outcomes,
      crawl_snapshots, suppression shell, policy/eligibility columns).
- [x] Harvest is DB-backed read-first / write-back; JSON is an export.
- [x] Parity harness proves output equivalence on the 3 baseline domains.
- [x] Repeat harvest is a materially faster read-first hit with identical results.
- [x] `contacts.last_verified` modelled for Phase 6 decay.
- [x] `gate check` green; no regression vs baseline/v0.14.4.
