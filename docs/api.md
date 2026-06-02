# API Reference

> The CLI (`pip install mailaccess`) wraps this API. All CLI commands call these endpoints.

## Base URL

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
  "version": "0.1.0",
  "modules_loaded": ["hibp", "emailrep", "gravatar", "domain_intel", "social"],
  "db": "connected"
}
```

`db` is `"connected"` or `"error"`.

---

### `POST /api/investigate`

Start an investigation. Returns immediately with an ID — the investigation runs in the background.

**Request**
```json
{
  "email": "user@example.com",
  "modules": ["hibp", "gravatar"],
  "enable_modules": ["breach_deep", "ghunt"],
  "force": false
}
```

`modules` is optional. Omit it to run all registered modules. Set `force: true` to bypass the investigation cache and always run a fresh investigation.

`enable_modules` is a list of opt-in module names to enable for this run only. Equivalent to the CLI `-m` flag. Valid values include `breach_deep`, `ghunt`, `email_discovery`, and `press_intel`. Pass `["all"]` to enable all opt-in modules.

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

Connect to `WS /ws/investigate/{id}` immediately after to stream results in real time. The internal queue is discarded after 5 minutes if no WebSocket consumer connects.

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

### `GET /api/report/{id}`

Full investigation report with all module runs and findings.

The response includes `exposure_score` plus the separate credential risk fields: `credential_risk_score`, `credential_risk_band`, `score_drivers`, and `recommended_actions`. v0.7.0 also adds Name Consensus fields and the `defenders_brief` object.

> **Known issue:** The route handler for this endpoint is currently missing in `backend/api/routes/investigations.py` — the response code at lines 80–83 is present but the `@router.get` decorator and function signature are absent, making the endpoint unreachable. Use `GET /api/report/{id}/export?format=json` as a workaround until the route is added.

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
        {"module": "whatsmyname", "platform": "HackerNews", "username": "janedoe"}
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

**Error frame** — sent and socket closed if the investigation ID is not found or the queue has already been consumed:
```json
{
  "type": "error",
  "error": "investigation not found or already streaming"
}
```

If the client disconnects mid-stream, the server drains the internal queue silently so the engine's background task is not blocked.

---

## Exposure Score

The exposure score (0–100) is computed once all modules complete:

| Module category | Weight per finding |
|-----------------|-------------------|
| Breach modules (`hibp`, `emailrep` with breach flag) | ×15 |
| Social presence modules | ×5 |
| All other modules | ×2 |

Score is clamped to 100.
