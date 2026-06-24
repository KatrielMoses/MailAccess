# MailAccess Architecture

## Components

| Path | Role |
|------|------|
| `backend/` | FastAPI app — investigation engine, REST API, WebSocket |
| `frontend/` | Vite + React + TypeScript SPA |
| `cli/` | Typer CLI (`mailaccess investigate <email>`) |
| `docker/` | Dockerfiles for backend and frontend |
| `docker-compose.yml` | Orchestration (SQLite default; Postgres via `--profile postgres`) |

## Backend Layout

```
backend/
├── main.py          # FastAPI app + CORS + lifespan hook
├── config.py        # Pydantic-settings (loads .env)
├── core/
│   ├── engine.py            # InvestigationEngine — phased execution + streaming queue
│   ├── phases.py            # Ordered primary and post-primary phase DAG
│   ├── aggregator.py        # ResultAggregator — merges module results
│   ├── identity_graph.py    # Cross-platform identity clusters
│   ├── name_consensus.py    # Weighted, fuzzy name synthesis
│   ├── platform_health.py   # SQLite-backed platform probe health
│   ├── avatar_hasher.py     # Perceptual avatar hashing
│   ├── bio_analyzer.py      # Bio phone, email, URL, and aggregator extraction
│   ├── bio_similarity.py    # Fuzzy bio comparison
│   ├── breach_normalizer.py # Canonical breach deduplication
│   ├── credential_risk.py   # Credential-risk scoring and actions
│   ├── platform_dedup.py    # Cross-enumerator profile deduplication
│   ├── enrichment/
│   │   ├── avatar_clusters.py  # Cross-platform avatar clusters
│   │   ├── bio_clusters.py     # Cross-platform bio clusters
│   │   ├── shadow_profiles.py  # Alternate-email profile pairs
│   │   └── temporal_cluster.py # Coordinated signup windows
│   └── scheduler.py         # Scheduler stub — recurring investigations
├── modules/
│   ├── base.py      # BaseModule ABC + ModuleResult dataclass + ModuleStatus enum
│   ├── __init__.py  # Auto-discovery registry
│   └── *.py         # One file per OSINT module
├── api/
│   ├── router.py    # Mounts sub-routers
│   ├── routes/
│   │   ├── investigations.py  # CRUD for investigations
│   │   └── modules.py         # Module listing
│   └── websocket.py           # /ws/investigate streaming endpoint
├── db/
│   ├── database.py  # Engine, session factory, init_db()
│   └── models.py    # Investigation, ModuleRun, Finding (SQLAlchemy 2.0)
└── exporters/
    ├── base.py      # BaseExporter ABC
    └── *.py         # json, csv, pdf, markdown, stix, maltego
```

## Module Contract

All modules live in `backend/modules/` and inherit `BaseModule`:

```python
class MyModule(BaseModule):
    name = "my_module"           # unique slug
    description = "Does X."
    requires_key = True          # skips itself if API key missing

    async def run(self, email: str) -> ModuleResult:
        ...
```

`ModuleResult` carries:
- `status` — `success | partial | failed | skipped`
- `findings` — list of dicts (flexible schema per module)
- `metadata` — supplementary info (timing, API version, etc.)
- `errors` — human-readable error messages

**No registration step needed** — `modules/__init__.py` scans the package at
import time and registers every `BaseModule` subclass with a `name` attribute.

## Investigation Flow

```
POST /api/v1/investigations
  → create Investigation (status=pending) in DB
  → spawn background task: InvestigationEngine.investigate(email)
      → asyncio.Semaphore(max_concurrency) gates parallel module tasks
      → each module runs with asyncio.wait_for(timeout)
      → results pushed to asyncio.Queue as they complete
      → partial results streamed to client via /ws/investigate
      → ModuleRun + Finding records written to DB per result
  → Investigation status → complete (or failed)
```

## Database Models

```
Investigation
  ├── id, email, status, created_at, completed_at
  ├── ModuleRun[]  (one per module per investigation)
  │     id, module_name, status, run_metadata, errors, started_at, finished_at
  └── Finding[]   (one per data point)
        id, module_name, data (JSON), created_at
```

## Export Formats

| Format | Class | MIME |
|--------|-------|------|
| JSON | `JsonExporter` | `application/json` |
| CSV | `CsvExporter` | `text/csv` |
| PDF | `PdfExporter` | `application/pdf` |
| Markdown | `MarkdownExporter` | `text/markdown` |
| STIX 2.1 | `StixExporter` | `application/json` |
| Maltego | `MaltegoExporter` | `application/xml` |

## Reasoning Layer (post-primary pipeline)

After primary collectors complete, `backend/core/engine.py` prepares their
`dict[str, ModuleResult]` output before persistence and reporting. These built-in
components do not fetch primary OSINT records; they correlate, normalize, or score
the findings already collected:

- `backend/core/identity_graph.py` builds confidence-scored identity clusters from
  shared usernames, display names, avatar pHashes, fuzzy bios, account dates, and
  breach signals. It also surfaces shadow-profile pairs.
- `backend/core/platform_health.py` records per-platform probe outcomes in
  `~/.mailaccess/platform_health.db`. Rolling hit rate, fragility, and consecutive
  misses feed back into platform execution so persistently unhealthy probes can be
  skipped or demoted. Inspect or clear records with `mailaccess platform-health`.
- `backend/core/name_consensus.py` combines profile name signals using weighted
  source classes, RapidFuzz matching, temporal decay, Unicode-aware normalization,
  and common-name confidence caps. Its confidence bands are `confirmed`,
  `probable`, `possible`, and `unknown`.
- `backend/core/enrichment/temporal_cluster.py` groups account creation dates into
  coordinated signup windows; `backend/core/enrichment/shadow_profiles.py` finds
  same-name accounts tied to different non-anchor email addresses.
- `backend/core/avatar_hasher.py` computes 64-bit perceptual hashes used by
  `backend/core/enrichment/avatar_clusters.py` to correlate resized or recompressed
  avatars across platforms.

## Enrichment Pass

Before a report is returned or persisted, the engine enriches the prepared results:

- `backend/core/credential_risk.py` emits a 0–100 score, a `LOW`, `MODERATE`,
  `HIGH`, or `CRITICAL` band, the top three score drivers, and recommended analyst
  actions. An infostealer signal enforces a `CRITICAL` floor. Service aliases are
  loaded from the six-category `data/service_categories.yaml` catalog.
- `backend/core/breach_normalizer.py` collapses breach duplicates from HIBP,
  BreachDirectory, `breach_deep`, XposedOrNot, and other breach collectors into
  canonical records with source attribution. Alias lookup is LRU-cached, host
  extraction tolerates embedded whitespace, and generic year/suffix noise is
  stripped before matching.
- `backend/core/bio_analyzer.py` extracts phones, emails, URLs, and links from 25
  supported link-in-bio domains. `backend/core/bio_similarity.py` supplies
  RapidFuzz token-set similarity for cross-platform bio comparison.
- `backend/core/platform_dedup.py` merges WhatsMyName, Maigret, Sherlock, and Nexfil
  findings by normalized profile domain. Corroboration by at least two enumeration
  sources sets `metadata.dual_confirmed: true` and `confidence: "high"`; agreement
  from more than two sources emits a warning for overlap review.

## Phase 6 Components

- `backend/core/enrichment/domain_cluster.py` — infrastructure clustering logic
- `backend/core/enrichment/shadow_profiles.py` — shadow-profile V2 detection
- `backend/core/avatar_hasher.py` — async, thread-wrapped pHash computation
- `backend/core/bio_similarity.py` — cross-platform bio fuzzy matching
- `backend/core/temporal_cluster.py` — temporal event clustering
- `backend/core/demotion_log.py` — JSONL platform-demotion audit log
- `backend/core/_phase_runner.py` — per-module timeout enforcement
- `cli/platform_audit.py` — platform audit CLI command
- `cli/platform_health.py` — health inspection and opt-in `--share` support

## Engine Hardening

- `asyncio.wait_for()` wraps every `module.run()` call.
- Enrichment passes have a 30-second timeout.
- Identity-graph construction uses indexed lookups and bounded large-cluster edges.
- Startup recovery in `backend/db/database.py` fails investigations left running
  for more than 10 minutes.
- Platform-health SQLite calls use async `to_thread` wrappers.
