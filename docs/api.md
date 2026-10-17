<a href="../README.md">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/brand/mailaccess-logo-reversed.svg">
    <img src="../assets/brand/mailaccess-logo.svg" alt="MailAccess" height="28">
  </picture>
</a>

# API Reference

> The CLI (`pip install mailaccess`) wraps this API. All CLI commands call these endpoints.

## Base URL

> **Note:** The `mailaccess harvest-emails` command is **CLI-only in 0.10.2**.
> The underlying `run_domain_harvest()` orchestrator is designed to be
> callable from an API layer in a future release, but no HTTP endpoint
> exists for it yet. Run `mailaccess harvest-emails --help` for the full
> flag list, and see [docs/harvest-emails.md](harvest-emails.md) for
> usage. Proxy routing for `harvest-emails` is also CLI-only: configure it
> with `mailaccess configure proxy ...` and pass `--use-proxies` on the
> command line.

All REST endpoints are prefixed with `/api`. The WebSocket endpoint and Maltego transform server have no prefix.

## Authentication

When `MAILACCESS_API_KEY` is set in `.env`, all `/api/` routes require the header:

```
X-API-Key: <your-key>
```

Requests without a valid key receive `401 {"error": "unauthorized"}`.

`/health` and `/ws/` routes are always unauthenticated. The Maltego transform at `/maltego/` is also exempt — it is designed to be called by the Maltego desktop app on localhost.

---

## REST Endpoints

### `GET /health`

Health check. Always unauthenticated.

**Response `200`**
```json
{
"status": "ok",
  "version": "0.10.2",
  "uptime": 1842.7,
  "modules_loaded": ["hibp", "emailrep", "gravatar", "domain_intel", "social"],
  "db": "connected"
}
```

`version` is read dynamically from the installed package. `uptime` is the
number of seconds since process startup; `db` is `"connected"` or `"error"`.

---

### `POST /api/investigate`

Start an investigation. Returns immediately with an ID — the investigation runs in the background.

**Request**
```json
{
  "email": "user@example.com",
  "modules": ["hibp", "gravatar"],
  "enable_modules": ["breach_deep", "google_account_intel"],
  "force": false
}
```

`modules` is optional. Omit it to run all registered modules. Set `force: true` to bypass the investigation cache and always run a fresh investigation.

`enable_modules` is a list of opt-in module names to enable for this run only. Equivalent to the CLI `-m` flag. Valid values include `breach_deep`, `email_discovery`, and `press_intel`. Pass `["all"]` to enable all opt-in modules.

New modules available in 0.4.0: `breach_deep`, `email_discovery`, `wayback`, `github_commits`. Pass them in the `modules` array to run selectively:

```json
{ "email": "user@example.com", "modules": ["breach_deep"] }
```

**Response `202`** — new investigation started
```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "pending",
  "created_at": "2026-05-19T12:00:00+00:00"
}
```

**Response `200`** — cached result returned (when `ENABLE_INVESTIGATION_CACHE=true` and a complete result exists within the cache window)
```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "complete",
  "cached": true,
  "created_at": "2026-05-19T12:00:00+00:00"
}
```

Connect to `WS /ws/investigate/{id}` immediately after to stream results in real time. The live stream is kept for 5 minutes after a run ends; the saved event log (`GET /api/investigations/{id}/events`) is kept for the report retention.

---

### `GET /api/investigations`

Paginated list of past investigations, newest first.

> **Note:** This endpoint returns `exposure_score` only — a single aggregate number. For per-module status, findings, and metadata, use `GET /api/report/{id}`.

**Query parameters**

| Param | Type | Default | Max |
|-------|------|---------|-----|
| `page` | int | `1` | — |
| `page_size` | int | `20` | `100` |

**Response `200`**
```json
{
  "total": 42,
  "page": 1,
  "page_size": 20,
  "pages": 3,
  "items": [
    {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "email": "user@example.com",
      "status": "complete",
      "exposure_score": 72,
      "created_at": "2026-05-19T12:00:00+00:00",
      "completed_at": "2026-05-19T12:00:15+00:00"
    }
  ]
}
```

`status` values: `pending`, `running`, `complete`, `failed`.

---

### `GET /api/capabilities`

Which paid providers this engine can use: `{"providers": {"ipgeolocation": true, "whoisfreaks": false, "netlas": true}}`. Booleans only, never key values, fragments or quota. `true` means the key is set and the provider is not switched off. A provider that is `false` appears nowhere in a run (events, report, graph, exports, module list), and a run with `no_ipgeo` / `no_whoisfreaks` set treats that provider the same way: no calls, no credits, no cached data.

### `GET /api/report/{id}`

Full investigation report with all module runs and findings.

The response includes `exposure_score` plus the separate credential risk fields:
`credential_risk_score`, `credential_risk_band`, `score_drivers`, and
`recommended_actions`. It also includes Name Consensus fields, the
`defenders_brief` object, platform deduplication stats, and enrichment results:
`infrastructure_clusters`, `shadow_profiles`, and `avatar_clusters`.

**Intended response `200`**
```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "email": "user@example.com",
  "status": "complete",
  "exposure_score": 72,
  "risk_level": "high",
  "confirmed_name": "Jane Doe",
  "name_confidence": "confirmed",
  "name_reasoning": "4 independent sources agree.",
  "name_sources": ["github_user", "gravatar_profile", "pgp_keyserver"],
  "credential_risk_score": 84,
  "credential_risk_band": "CRITICAL",
  "score_drivers": [
    "infostealer hit",
    "multiple high-severity breach findings",
    "reused credentials across sources"
  ],
  "recommended_actions": [
    "Reset affected passwords immediately and revoke active sessions",
    "Review MFA enrollment and strengthen account recovery settings",
    "Prioritize containment and analyst follow-up for exposed credentials"
  ],
  "defenders_brief": {
    "risk_level": "CRITICAL",
    "risk_summary": "Active infostealer infection detected.",
    "top_findings": [
      {
        "title": "Active credential theft",
        "detail": "Infostealer detected via Hudson Rock.",
        "severity": "CRITICAL",
        "remediation": "Rotate credentials immediately."
      }
    ],
    "next_action": "Immediately rotate credentials and enforce hardware MFA.",
    "generated_at": "2026-05-19T12:00:15+00:00"
  },
  "platform_stats": {
    "username_platform_hits": 4,
    "username_hits": 6,
    "dual_confirmed": 2,
    "unique_platforms": 8
  },
  "infrastructure_clusters": [
    {"cluster_id": "infra_8e5bf38c7029", "platforms": ["site-a", "site-b", "site-c"], "shared_subnet": "93.184.216.0/24"}
  ],
  "shadow_profiles": [
    {"shadow_email": "jane.alt@example.net", "shared_name": "Jane Doe", "shared_platforms": ["github", "reddit"]}
  ],
  "avatar_clusters": [
    {"phash": "8f0f0f0f0f0f0f0f", "platforms": ["github", "reddit"], "cluster_size": 2}
  ],
  "summary": "Ran 8 modules (7 successful, 1 failed). Found 14 data points.",
  "created_at": "2026-05-19T12:00:00+00:00",
  "completed_at": "2026-05-19T12:00:15+00:00",
  "module_runs": [
    {
      "id": "a1b2c3d4-...",
      "module_name": "hibp",
      "status": "success",
      "run_metadata": {
        "total_breaches": 3,
        "breach_dates": "2013-10-04 to 2023-01-01",
        "most_critical_breach": "Adobe",
        "all_data_classes": ["Email addresses", "Passwords"]
      },
      "errors": null,
      "started_at": "2026-05-19T12:00:01+00:00",
      "finished_at": "2026-05-19T12:00:02+00:00"
    },
    {
      "id": "d4c3b2a1-...",
      "module_name": "username_platforms",
      "status": "success",
      "run_metadata": {
        "sites_loaded": 4000,
        "wave1_probes": 1500,
        "wave2_probes": 0,
        "catchalls_excluded": 12,
        "platforms_confirmed": 5,
        "platforms_not_found": 1480,
        "platforms_errored": 3,
        "username_variants_used": ["janedoe", "jane.doe", "jane_doe"],
        "dual_confirmed": 2,
        "unique_platforms": 8
      },
      "errors": null,
      "started_at": "2026-05-19T12:00:03+00:00",
      "finished_at": "2026-05-19T12:01:12+00:00"
    }
  ],
  "findings": [
    {
      "id": "f1e2d3c4-...",
      "module_name": "hibp",
      "data": {
        "platform": "HaveIBeenPwned",
        "url": "https://haveibeenpwned.com/PwnedWebsites#Adobe",
        "metadata": {
          "name": "Adobe",
          "domain": "adobe.com",
          "breach_date": "2013-10-04",
          "severity": "critical",
          "data_classes": ["Email addresses", "Passwords", "Password hints"]
        },
        "confidence": "high"
      },
      "created_at": "2026-05-19T12:00:02+00:00"
    }
  ],
  "findings_by_module": {
    "hibp": [{"platform": "HaveIBeenPwned", "...": "..."}]
  },
  "metadata_table": {
    "hibp": {"total_breaches": 3, "breach_dates": "2013-10-04 to 2023-01-01"}
  }
}
```

---

### `GET /api/report/{id}/export`

Export a completed investigation in the requested format as a file download.

**Query parameters**

| Param | Values | Default |
|-------|--------|---------|
| `format` | `json` `csv` `markdown` `pdf` `stix` `maltego` | `json` |

**Response** — binary file with `Content-Disposition: attachment` header.

Filename pattern: `mailaccess_{email}_{id}.{ext}`

| Format | Extension |
|--------|-----------|
| JSON | `.json` |
| CSV | `.csv` |
| Markdown | `.markdown` |
| PDF | `.pdf` |
| STIX 2.1 | `.stix.json` |
| Maltego | `.maltego.csv` |

**Errors**
- `404` — investigation not found
- `501` — format not yet implemented

---

### `GET /api/report/{id}/clusters`

Returns the identity clusters built from cross-module correlation, with confidence scores and reasoning strings.

**Response `200`**
```json
{
  "clusters": [
    {
      "id": "cluster-1",
      "confidence": "high",
      "score": 0.91,
      "reasoning": "Shared username 'janedoe' across GitHub, HackerNews, and Twitter findings",
      "members": [
        {"module": "social", "platform": "GitHub", "username": "janedoe"},
        {"module": "username_platforms", "platform": "HackerNews", "username": "janedoe"}
      ]
    }
  ]
}
```

**Errors**
- `404` — investigation not found or not yet complete

---

### `GET /api/report/{id}/graph`

Returns a D3-compatible graph representation of the identity graph for use in visualization or export.

**Response `200`**
```json
{
  "nodes": [
    {"id": "email:user@example.com", "type": "email", "label": "user@example.com"},
    {"id": "account:github:janedoe", "type": "account", "label": "janedoe", "platform": "GitHub"}
  ],
  "links": [
    {"source": "email:user@example.com", "target": "account:github:janedoe", "confidence": "high"}
  ]
}
```

**Errors**
- `404` — investigation not found or not yet complete

---

### `DELETE /api/investigation/{id}`

Hard-delete an investigation and all associated findings and module runs.

**Response `204`** — no body.

**Errors**
- `404` — investigation not found

---

### `GET /api/modules/`

List all registered modules.

**Response `200`**
```json
[
  {
    "name": "hibp",
    "description": "Check if the email appears in known data breaches via the HIBP v3 API.",
    "requires_key": true
  },
  {
    "name": "emailrep",
    "description": "Query EmailRep.io for reputation score, risk flags, and linked profile data.",
    "requires_key": false
  }
]
```

---

### `POST /maltego/email_investigate`

Maltego TRX local transform. Accepts an XML POST body in the Maltego TRX protocol, runs a full investigation, and returns Maltego entity XML. No API key required.

See [Integrations — Maltego](integrations.md#maltego) for setup instructions.

---

## WebSocket

### `WS /ws/investigate/{id}`

Stream investigation events in real time. Connect immediately after `POST /api/investigate`.

The server pushes one JSON frame per module event, then a final `investigation_complete` frame once all modules have finished and results are persisted to the database.

**Event: `module_start`**
```json
{
  "type": "module_start",
  "module": "hibp",
  "timestamp": "2026-05-19T12:00:01.234567+00:00"
}
```

**Event: `module_result`**
```json
{
  "type": "module_result",
  "module": "hibp",
  "findings": [
    {
      "platform": "HaveIBeenPwned",
      "url": "https://haveibeenpwned.com/PwnedWebsites#Adobe",
      "metadata": {"name": "Adobe", "severity": "critical"},
      "confidence": "high"
    }
  ],
  "status": "success"
}
```

**Event: `module_error`**
```json
{
  "type": "module_error",
  "module": "shodan",
  "error": "SHODAN_API_KEY not set",
  "status": "failed"
}
```

**Event: `investigation_complete`**
```json
{
  "type": "investigation_complete",
  "exposure_score": 72,
  "risk_level": "high"
}
```

Risk level thresholds: `low` (0–20), `medium` (21–50), `high` (51–80), `critical` (81–100).

**Error frame** — sent and socket closed if the investigation ID is not known or the run's live stream is no longer kept (use the event log below instead):
```json
{
  "type": "error",
  "error": "investigation not found or already finished"
}
```

Any number of clients can connect to the same run; each receives the full stream from the start. A failed run ends with `{"type": "investigation_failed", "error": "..."}`.

### `GET /api/investigations/{id}/events?since=N`

The run's saved event log as server-sent events ("show your work"). Same API-key auth as the rest of `/api`. It replays every saved event with `seq > N` (default 0), then follows the run live until `run_done`, then closes. It works after the run has finished (full replay) and for any number of viewers. Each message sets `id: <seq>`, so a reconnecting client resumes with the `Last-Event-ID` header. A `: keep-alive` comment goes out every 15 seconds.

```
id: 12
event: finding
data: {"seq":12,"ts":"2026-10-17T09:30:01.512Z","finding_id":3,"module":"account_discovery",...}
```

`seq` is per run, gap-free from 1. `ts` is UTC with milliseconds. `data` is the event's own fields at the top level plus `seq` and `ts`: there is no `payload` wrapper, and the event type is only on the `event:` line. A `: hb` comment goes out every 15 seconds. Payloads are small: a platform hit is one event, never a whole module result. The full contract, shared with the website, is [dev/SHOW-YOUR-WORK-EVENTS.md](../dev/SHOW-YOUR-WORK-EVENTS.md).

| event | data (besides `seq`, `ts`) |
|---|---|
| `run_started` | `{mode, planned_modules: [{module, phase, technique_id}], total_sources, unavailable: [{module, reason}]}` (first event, before any module starts) |
| `phase_start` / `phase_end` | `{phase, modules}` / `{phase, duration_ms}` |
| `module_start` | `{module, phase, technique_id, technique}` (always sent, including modules skipped for budget) |
| `module_progress` | `{module, checked, total}` (at most 4 per second per module) |
| `finding` | `{finding_id, module, kind, title, value, url, label, trace}` |
| `finding_updated` | `{finding_id, label, trace}` (after dedup or corroboration changes a label) |
| `edge_added` | `{source: {id, type, label}, target: {...}, type, reason, finding_id}` |
| `module_done` | `{module, status, findings_count, duration_ms, skipped_reason}`; `status` is `success`, `empty`, `partial`, `failed` or `skipped`; `skipped_reason` is `budget`, `no_key`, `disabled` or `null` |
| `run_done` | `{status, sources_checked, total_sources, findings, exposure_score}` (a failed run adds `error`) |

`total_sources` counts only the checks that will run; checks that cannot (no key, disabled, nothing to read for this address) are listed in `run_started.unavailable` and are not part of "N of M". `sources_checked` counts checks that finished as `success`, `empty`, `partial` or `failed`. Node types are `email`, `username`, `account`, `name`, `domain`, `breach` and `phone`. `kind` is one of `account`, `username_match`, `name`, `domain`, `breach`, `email`, `phone`, `other`.

`label` answers one question, whether a finding is linked to this person: `username_match` (the username exists on a site, never that this person owns it), `possible` (one signal tied to the email) or `confirmed` (two independent signal types). Records read directly (DNS, WHOIS, the address check) are `null`: they get no badge and their `trace.reason` states what was read. Every finding's `trace` is `{technique_id, technique, signal, derived_from, corroborated_by, independent_signals, reason}`, and the reason names the real site or record. Traces never contain keys, tokens or raw responses. The same `trace` and `label` are saved on each finding in the report (`data.trace`, `data.label`).

`mailaccess harvest-emails --events-jsonl PATH` writes the same events (a harvest streams value-less `candidate` events while it runs and emits `finding` events only from its final result, with `run_done` counts equal to the export; see the event contract) for a harvest, one JSON object per line: the same top-level fields plus `type` (an edge's own `type` is written as `edge_type`).

---

## Exposure Score

The exposure score (0–100) is computed once all modules complete:

| Module category | Weight per finding |
|-----------------|-------------------|
| Breach modules (`hibp`, `emailrep` with breach flag) | ×15 |
| Social presence modules | ×5 |
| All other modules | ×2 |

Score is clamped to 100.
