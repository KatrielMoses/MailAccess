# Phase 2E — Retention, deletion & reproducibility governance

Limits liability on a growing store and makes trust/derivation machine-readable
(Doc-1 #20/#22). Adds expiry, per-record takedown, a tamper-evident audit log,
export watermarking, a reproducible run manifest, and a W3C PROV-DM export.

New tables (Alembic **0007**, guarded/idempotent): `audit_log`, `takedowns`,
`run_manifests`.

## Retention & expiry

`backend/core/retention.py` + `mailaccess retention run [--dry-run]`. Purges
ledger observations and their raw payloads whose `expires_at` has passed (the
per-source TTL set in 1C, governed by the 2B per-mode retention policy). Raw
payloads are removed before their observations (FK order); every purge is audited.

## Per-record deletion / takedown

`backend/core/takedown.py`. The API hard-delete (`DELETE /investigation/{id}`) is
now a **takedown**: it deletes the record, writes a `Takedown` row (minimum-
retention hash), and — crucially — writes a companion **suppression** row so the
subject cannot silently re-enter on a later collection. It cannot be undone
silently: the takedown + suppression persist and the action is audited.

## Tamper-evident audit log

`backend/core/audit_log.py`. A hash chain: each entry stores
`entry_hash = sha256(prev_hash + canonical(seq, action, subject, details,
created_at))`. `verify()` recomputes the chain and reports the first broken
sequence — any mutated row **or a deleted row** (which leaves a sequence gap) is
detected. Timestamps are canonicalized to naive-UTC so an aware write and SQLite's
naive read hash identically. Governance actions logged: suppression add, takedown,
deletion, retention purge, collection (mode-of-collection), export. Verified via
`mailaccess retention verify-audit`.

## Reproducible run manifest + watermarking

`backend/core/run_manifest.py`. A `RunManifest` is persisted with every result —
`app_version`, a `config_fingerprint` (a hash of the behavior-defining settings;
secrets are never stored, only hashed), `module_versions`, `mode`/`source_policy`,
`corpus_version` (the live Alembic revision), and a `seed` — recorded at the end
of both the investigate run (engine) and the harvest run (CLI). The same manifest
shape is embedded as an export **watermark**: `format_harvest_json_export` gains a
top-level `watermark`, and the investigate report gains one in `enrich_report`, so
an artifact always knows which run / mode / policy produced it.

## W3C PROV-DM export

`backend/exporters/prov_exporter.py` — `to_prov(observations)` /
`prov_for_subject(subject)` serialize the 1C ledger to PROV-JSON: each observation
is an **entity**, each run (`activity_id` + pipeline + extraction method + module
version) an **activity**, each source an **agent**, with `wasGeneratedBy` /
`wasAttributedTo` / `wasAssociatedWith` relations and the run manifest attached.
Each entity carries its collection `mode` and `policy_status`, so the evidence
chain — the precondition for sharing anything in Phase 6 — is machine-readable.

## Validation (done-when)

`tests/test_governance.py` (6): the audit chain verifies and detects both a
mutated row and a deleted row (sequence gap); retention purges only the expired
observation (dry-run counts only) and audits the purge; a takedown records the
takedown + a re-collection-blocking suppression + an audit entry; a run manifest
is persisted with all fields incl. the live `corpus_version`; the PROV export has
entities/activities/agents/relations, the attached manifest, and per-entity mode +
policy provenance. Alembic 0007 applies across the 0001→0007 chain (downgrade
round-trip reversible). `gate check` green (0 NEW).

## Non-scope (respected)

No corpus distribution/sync (Phase 6). No multi-tenant identity model beyond what
2F needs.
