# Self-Hosting Guide

## CLI-only install (no Docker needed)

```bash
pip install mailaccess

# Option A: auto-start (simplest)
mailaccess investigate you@example.com
# Server starts automatically, runs investigation,
# stops when done.

# Option B: keep server running
mailaccess serve  # in one terminal
mailaccess investigate you@example.com  # in another
```

---

## Requirements

- Docker and Docker Compose v2 (for the container path)
- Python 3.11+ and Node 18+ (for the manual path)
- 512 MB RAM minimum; 1 GB recommended when running all modules concurrently

---

## Docker Compose — Development

```bash
cp .env.example .env
# Edit .env to add any API keys you want
docker compose up
```

- Backend: http://localhost:8000
- Frontend: http://localhost:3000
- Hot-reload is enabled on both services in development mode
- The `./data/` directory is mounted into the container for SQLite persistence

---

## Docker Compose — Production

```bash
cp .env.example .env
# Set MAILACCESS_API_KEY and any module keys
docker compose -f docker-compose.prod.yml up -d
```

Differences from the dev compose file:
- Frontend is built and served by nginx on port 80
- Backend runs without `--reload`
- Healthchecks on all services — frontend waits for backend to be healthy before starting
- `restart: always` on all services

---

## `.env` Reference

Every setting is optional unless marked required.

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/mailaccess.db` | Full SQLAlchemy async connection URL. Leave blank for SQLite. |

### Application

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Enable FastAPI debug mode and verbose tracebacks |
| `LOG_LEVEL` | `INFO` | Python logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated list of allowed CORS origins |
| `MAILACCESS_API_KEY` | _(unset)_ | When set, all `/api/` routes require `X-API-Key: <value>`. Leave blank for open access. |
| `SHOW_DEFENDERS_BRIEF` | `true` | Show Defender's Brief in CLI output. Set `false` to suppress for all investigations. |

### Worker

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CONCURRENT_MODULES` | `10` | Maximum number of modules that run in parallel per investigation |
| `MODULE_TIMEOUT_SECONDS` | `30` | Per-module timeout; modules that exceed this are cancelled and marked `failed` |
| `MODULE_TIMEOUT_OVERRIDES` | `{}` | Per-module timeout overrides as a JSON object (values in seconds). Example: `{"whatsmyname": 120, "account_discovery": 90}` |
| `ENABLE_INVESTIGATION_CACHE` | `true` | Cache complete investigation results; repeated queries within the window return instantly |
| `INVESTIGATION_CACHE_WINDOW_MINUTES` | `30` | How long a cached result is considered fresh (minutes) |

### Modules

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_BREACH_DEEP` | `false` | Opt-in deep breach probe |
| `BREACH_DEEP_LIMIT` | `100` | Sites to probe; max 750 |
| `BREACH_DEEP_FULL` | `false` | Probe all 750 HIBP sites |
| `ENABLE_EMAIL_DISCOVERY` | `true` | Name-to-email dorks |
| `GITHUB_TOKEN` | _(unset)_ | Optional. Required for GitHub commit author-email search. Without it, `github_commits` runs user profile search only. Get at: [github.com/settings/tokens](https://github.com/settings/tokens) |
| `COMPANIES_HOUSE_API_KEY` | _(unset)_ | Optional. UK Companies House officer/address lookup. Free, no CC. Get at: [developer.company-information.service.gov.uk](https://developer.company-information.service.gov.uk) |

MailAccess fetches the HIBP breach corpus on startup and caches it at `data/cache/breach_corpus.json` for 24h. No API key required for this fetch.

The Defender's Brief is generated automatically for every investigation. Suppress it with the CLI `--no-brief` flag or by setting `SHOW_DEFENDERS_BRIEF=false` in `.env`.

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_ENABLED` | `true` | Global toggle for rate limiting |
| `REQUEST_DELAY_MS` | `1000` | Default minimum delay between requests to the same domain (ms) |
| `RATE_LIMIT_OVERRIDES` | `{}` | Per-domain overrides as a JSON object (values in ms). Example: `{"api.github.com": 500, "haveibeenpwned.com": 1500}` |
| `RATE_LIMIT_DELAYS` | `{}` | Legacy per-domain delays in seconds (kept for compatibility). Use `RATE_LIMIT_OVERRIDES` for new configs. |

### Proxy

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | _(unset)_ | Proxy URL for all outbound requests. Examples: `socks5://127.0.0.1:9050` (Tor), `http://user:pass@proxy:8080` |
| `PROXY_ENABLED` | `false` | Set `true` to activate the proxy. The URL is ignored when this is `false`. |

### Webhooks

| Variable | Description |
|----------|-------------|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL for investigation completion notifications |
| `DISCORD_WEBHOOK_URL` | Discord webhook URL |
| `INTEGRATION_WEBHOOK_URL` | Generic HTTP POST endpoint |
| `INTEGRATION_WEBHOOK_SECRET` | Optional HMAC secret for signing webhook payloads |

### API Keys

All API keys are optional. Modules that require a missing key skip themselves with `status: skipped` rather than failing.

| Variable | Used by | Where to get |
|----------|---------|-------------|
| `HIBP_API_KEY` | `hibp` module | https://haveibeenpwned.com/API/Key |
| `SERPAPI_KEY` | `google_dork` module | https://serpapi.com |
| `GITHUB_TOKEN` | `github_commits` module (optional) | https://github.com/settings/tokens |
| `COMPANIES_HOUSE_API_KEY` | `companies_house` module | https://developer.company-information.service.gov.uk |
| `SHODAN_API_KEY` | `domain_intel` (optional), `shodan` module | https://account.shodan.io |
| `EMAILREP_API_KEY` | `emailrep` module (raises rate limit) | https://emailrep.io |
| `HUNTER_IO_API_KEY` | `hunter_io` module | https://hunter.io |
| `VIRUSTOTAL_API_KEY` | Reserved for future module | https://virustotal.com |
| `FULLCONTACT_API_KEY` | Reserved for future module | https://fullcontact.com |
| `CLEARBIT_API_KEY` | Reserved for future module | https://clearbit.com |

---

## Enabling Opt-in Modules

Four modules are opt-in and require explicit enabling per run or via `.env`:

| Module | Description |
|--------|-------------|
| `breach_deep` | Probes 100 breach sites (slow, ~90 s) |
| `ghunt` | Deep Gmail intel (requires one-time `ghunt login` setup) |
| `press_intel` | Press release contact extraction for business domains |
| `email_discovery` | Name → email dorks (requires `SERPAPI_KEY`) |

**Enable for one run** using the `-m` / `--enable` flag:

```bash
mailaccess investigate email -m breach_deep
mailaccess investigate email -m press_intel
mailaccess investigate email -m all
```

**Enable permanently** via `.env`:

```env
ENABLE_BREACH_DEEP=true
```

`-m all` enables all opt-in modules for the current run only.

---

## Module Timeout Overrides

`whatsmyname` and `account_discovery` perform hundreds of HTTP requests per investigation and routinely exceed the default 30-second timeout. Set longer values in `MODULE_TIMEOUT_OVERRIDES` to prevent them from being cancelled early:

```
MODULE_TIMEOUT_OVERRIDES={"whatsmyname": 120, "account_discovery": 90, "username_pivot": 180}
```

Recommended values by connection quality:

| Module | Fast connection | Slow connection |
|--------|----------------|-----------------|
| `whatsmyname` | `120` | `240` |
| `account_discovery` | `90` | `180` |
| `username_pivot` | `180` | `360` |
| `user_scanner` | `180` | `300` |

Modules that hit their timeout return `status: partial` with whatever findings were collected up to that point.

---

## Investigation Cache

When `ENABLE_INVESTIGATION_CACHE=true` (the default), a completed investigation result is cached for `INVESTIGATION_CACHE_WINDOW_MINUTES` minutes. Submitting the same email within that window returns the cached result immediately (`cached: true` in the response) without running the modules again.

To force a fresh run even when a cached result exists:

```bash
# CLI
mailaccess investigate you@example.com --force

# API
POST /api/investigate
{ "email": "you@example.com", "force": true }
```

To disable caching entirely:

```
ENABLE_INVESTIGATION_CACHE=false
```

---

## Switching to PostgreSQL

**Docker Compose:**

Add the following to your `.env`:

```
DATABASE_URL=postgresql+asyncpg://mailaccess:mailaccess@postgres:5432/mailaccess
```

Then start with the `postgres` profile:

```bash
docker compose --profile postgres up
```

The `postgres` service uses `postgres:16-alpine` with a named volume (`postgres_data`) for persistence.

**Manual / external Postgres:**

Set `DATABASE_URL` to any valid `postgresql+asyncpg://` connection string pointing at your database. MailAccess creates tables on startup via `init_db()` — no manual migration step required for a fresh database.

---

## Proxy and Tor

To route all module HTTP requests through Tor:

1. Run a Tor SOCKS5 proxy (the default port is 9050):
   ```bash
   docker run -d -p 9050:9050 dperson/torproxy
   ```

2. Add to `.env`:
   ```
   PROXY_URL=socks5://127.0.0.1:9050
   PROXY_ENABLED=true
   ```

3. Restart MailAccess.

All outbound requests made via `build_client()` (every module) will be routed through the proxy. The `/health` endpoint and database connections are not affected.

> Some APIs (HIBP, SerpAPI) may block Tor exit nodes. Modules that encounter connection errors return `status: partial` or `status: failed` and log the error.

---

## Maltego Transform Import

MailAccess generates a Maltego configuration bundle (`.mtz`) automatically at startup, written to `maltego/MailAccess.mtz`.

### Import steps

1. Start MailAccess (`docker compose up`).
2. The bundle is created at `./maltego/MailAccess.mtz` on the host.
3. Open Maltego Desktop.
4. Go to **Import/Export** → **Import Config**.
5. Select `MailAccess.mtz` and complete the wizard.
6. In the transform settings, confirm the **Transform URL** is set to your MailAccess instance, e.g. `http://localhost:8000/maltego/email_investigate`.
7. Restart Maltego.

The transform accepts a Maltego `EmailAddress` entity and returns entities for each finding (breach records, social profiles, domain data).

> The `/maltego/` endpoint is exempt from API key authentication. If your instance is publicly accessible, restrict it at the network level rather than relying on MailAccess auth.

---

## Manual Installation

### Backend

```bash
cd backend
pip install -e ".[dev]"
cp ../.env.example ../.env
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### CLI

```bash
pip install -e .
mailaccess investigate user@example.com
```
