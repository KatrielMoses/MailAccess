<pre align="center">
███╗   ███╗ █████╗ ██╗██╗      █████╗  ██████╗ ██████╗███████╗███████╗███████╗
████╗ ████║██╔══██╗██║██║     ██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝
██╔████╔██║███████║██║██║     ███████║██║     ██║     █████╗  ███████╗███████╗
██║╚██╔╝██║██╔══██║██║██║     ██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║
██║ ╚═╝ ██║██║  ██║██║███████╗██║  ██║╚██████╗╚██████╗███████╗███████║███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝
</pre>

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](docker-compose.yml)
[![PyPI version](https://img.shields.io/static/v1?label=PyPI&message=0.12.9&color=3775A9&logo=pypi&logoColor=white)](https://pypi.org/project/mailaccess/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/mailaccess)](https://pypi.org/project/mailaccess/)

Self-hostable OSINT platform for investigating email addresses. Fan out across breach databases, social networks, DNS records, and the open web — get back a unified exposure score and structured findings you can export or pipe into Maltego.

Built for security researchers, OSINT analysts, and penetration testers operating under authorization. Read [DISCLAIMER.md](DISCLAIMER.md) before use.

## Install

### CLI only (no Docker)

```bash
pip install 'mailaccess[harvest]'

# Start the backend in a separate terminal before investigating
mailaccess serve
mailaccess investigate you@example.com

# Full stack with Web UI
git clone https://github.com/KatrielMoses/MailAccess
docker compose up -d
```

## Quick Start

```bash
mailaccess investigate you@example.com
mailaccess investigate you@example.com -o report.pdf
mailaccess investigate you@example.com --format jsonl
mailaccess investigate -                        # read email from stdin
mailaccess serve                                # start backend server on :8000
mailaccess keys list
mailaccess keys set HIBP_API_KEY your-key-here
mailaccess modules
mailaccess platform-health                      # inspect noisy/failing probes

# Enable specific opt-in modules for one run
mailaccess investigate email -m breach_deep
mailaccess investigate email -m all
```

![Investigation demo](public/investigation.gif)

## What It Does

- **Identity graph** — cross-platform correlation of accounts, usernames, and signals from each investigation
- **Name Consensus Engine** — confirms real identity from multiple independent name signals with confidence scoring
- **Defender's Brief** — security-manager-ready risk summary with actionable findings and next step
- **Phone number recovery** — pipeline to surface and validate numbers tied to the target
- **Telegram / WhatsApp hints** — lightweight messaging-app footprint checks alongside other modules
- **YAML-driven platform system** — social-style checks defined in `backend/platforms/`; community extensible without new Python for each site
- **Native Maigret engine** — 2500+ platform coverage without a Maigret runtime dependency, including regional, niche, and international platforms not covered by WMN
- **Catch-all detection** — excludes platforms that return false positives for arbitrary usernames before the sweep starts
- **Platform deduplication** — merges WMN and Maigret results by profile URL domain so confirmed platforms are not double-counted
- **Avatar perceptual hashing** — confirms the same person across platforms by image similarity
- **False-positive reduction** — common-name filtering, content-length sanity checks, and multi-language failure signals reduce noisy hits
- **Disposable email detection** — flags disposable domains and downweights affected enumeration findings
- **Bio fuzzy similarity** — links profiles with materially similar free-form bios
- **Platform health** — automatically demotes unreliable platforms and self-heals as reliability changes
- **Platform audit CLI** — inspect platform reliability with `mailaccess platform-audit`
- **Temporal clustering and shadow profiles** — surfaces coordinated signup windows and same-name accounts tied to alternate emails
- **Deep breach mode** — checks top 100 highest-severity breached sites for account existence
- **Historical intelligence** — Wayback Machine archive search + GitHub commit author search
- **Recursive email discovery** — recovers other emails owned by the same person via name correlation
- **Credential Risk Score** — separate 0-100 credential risk signal with LOW / MODERATE / HIGH / CRITICAL banding, top drivers, and recommended next steps
- Concurrent module execution — all modules run in parallel, results stream as they arrive
- WebSocket streaming — partial results arrive in real time without polling
- REST API + web UI + CLI — use whatever interface fits your workflow
- Plugin module system — drop a `.py` file in `backend/modules/` and it auto-registers; no wiring required
- 6 export formats: JSON, CSV, PDF, Markdown, STIX 2.1, Maltego XML
- Maltego local transform server — run investigations directly from the Maltego desktop app
- Webhook notifications — Slack, Discord, or any HTTP endpoint
- Exposure score (0–100) with risk label: low / medium / high / critical
- SQLite by default; PostgreSQL optional via Docker Compose profile
- **Domain Email Harvesting** — given a company domain, discovers associated email addresses via 8 concurrent sources: Common Crawl index, GitHub code/commits, certificate transparency logs, npm/PyPI registries, PGP keyservers, search engine dorking, employee name discovery, and pattern generation with optional SMTP verification. Rivals theHarvester with better confidence scoring, catch-all protection, and Common Crawl exploitation. See [Domain Email Harvesting](#domain-email-harvesting) below.

## Modules

| Module | Coverage | Key Required | Opt-in |
|--------|----------|--------------|--------|
| gravatar | Profile hash lookup | No | No |
| hibp | Breach check | Yes | No |
| breach_deep | Probes top 100 highest-severity breached sites for account existence | No (HIBP corpus fetched automatically) | Yes |
| emailrep | Reputation + blacklist | No | No |
| hudson_rock | Infostealer logs (free) | No | No |
| google_dork | 5 automated dorks | Yes (SerpAPI) | No |
| email_discovery | Recovers other email addresses owned by same person via name dorks | Yes (SERPAPI_KEY) | No |
| domain_intel | Domain + Shodan | No (Shodan optional) | No |
| dns_lookup | MX/SPF/DMARC/DKIM/A/NS extraction | No | No |
| whois_lookup | Domain WHOIS, privacy detection | No | No |
| wayback | Finds historical pages where email appeared publicly via Wayback Machine CDX | No | No |
| github_commits | Finds repos committed to with this email, surfaces real name from git config. Requires GITHUB_TOKEN for commit search; user profile search works without token. | No (GITHUB_TOKEN optional, required for commit search) | No |
| pgp_keyserver | PGP key UID name lookup | No | No |
| orcid_lookup | ORCID researcher identity | No | No |
| hackernews | HackerNews profile name | No | No |
| sec_edgar | SEC EDGAR filing contact extraction | No | No |
| companies_house | UK Companies House officers | Yes (COMPANIES_HOUSE_API_KEY, free) | No |
| press_intel | Press release contact extraction | No | Yes |
| xposedornot | Default-on direct email-to-breach corpus lookup with breach names, data classes, and risk indicators | No | No |
| leakcheck | Default-on public breach corpus lookup with regional coverage and stealer routing | No | No |
| ransomware_intel | Default-on domain victim correlation against ransomware lists; skips free providers | No | No |
| social | 13 platforms via YAML | No | No |
| social_links | Username extraction, feeds pivot | No | No |
| account_discovery | Holehe 120+ platforms | No | Yes |
| user_scanner | 205+ platform vectors | No | Yes |
| whatsmyname | 700+ platforms | No | Yes |
| maigret_platforms | Native Maigret platform engine, 2500+ platforms | No | No (disable via `ENABLE_MAIGRET_PLATFORMS=false`) |
| sherlock_platforms | Sherlock native engine, ~300 platforms | No | No |
| nexfil_platforms | Nexfil native engine, ~300 platforms | No | No |
| blackbird_platforms | Blackbird native engine, social focus | No | No |
| breachdirectory | 2nd breach source | Yes | No |
| username_pivot | WMN via recovered usernames | No | Yes |
| permutation_discovery | 60 email variants | No | Yes |
| phone_intel | Phone validation + WA/TG hints | No | No |
| messaging_hints | Telegram/WhatsApp username check | No | No |
| ghunt | Gmail deep intel | No (setup required) | Yes |
| identity_graph | Cross-platform cluster analysis | No | No (automatic) |
| platform_health | Persistent probe health, fragility, and skip decisions | No | No (automatic) |
| temporal_cluster | Coordinated account-creation windows | No | No (automatic) |
| shadow_profiles | Same-name accounts tied to alternate emails | No | No (automatic) |
| avatar_clusters | Cross-platform perceptual-avatar clusters | No | No (automatic) |
| breach_corpus | Cached and severity-ranked public HIBP breach catalog | No | No (used by `breach_deep`) |
| common_names | Common-name and username false-positive controls | No | No (automatic) |
| disposable_domains | Disposable-email confidence controls | No | No (automatic) |

> 64 modules · 2500+ platforms by default

## Platform Coverage

MailAccess checks usernames derived from the target email across multiple platform databases:

| Source | Platforms | Default |
|--------|-----------|---------|
| WhatsMyName | 700+ | On |
| Holehe | 120+ | On |
| user-scanner | 205+ | On |
| Maigret native engine | 2500+ | On |
| Sherlock native | ~300 | On |
| Nexfil native | ~300 | On |
| Blackbird native | social focus | On |

Total with Maigret enabled: 2500+ unique platforms after deduplication.

Enable Maigret:

```bash
ENABLE_MAIGRET_PLATFORMS=true mailaccess investigate email
```

Enable Maigret + Wave 2, the slower platform sweep:

```bash
ENABLE_MAIGRET_PLATFORMS=true ENABLE_MAIGRET_WAVE2=true mailaccess investigate email
```

The platform database is fetched from Maigret's GitHub repository (MIT licensed) and cached locally for 24 hours. Custom platforms can be added to `data/mailaccess-extra-sites.json` in the same format.

Findings from WMN and Maigret are deduplicated by URL domain. When both tools confirm the same platform, the finding is marked dual-confirmed with high confidence.

| Variable | Module | Key Required | Default | Description |
|----------|--------|--------------|---------|-------------|
| `ENABLE_MAIGRET_PLATFORMS` | `maigret_platforms` | None | `false` | Enable 2500+ platform sweep. Adds ~35-90s. |
| `ENABLE_MAIGRET_WAVE2` | `maigret_platforms` (Wave 2) | None | `false` | Enable slow/fragile platform sweep. Requires `ENABLE_MAIGRET_PLATFORMS=true`. Adds ~90-150s. |
| `MAIGRET_FORCE_{PLATFORM}` | `maigret_platforms` | None | _(unset)_ | Override auto-demotion for one platform. |
| `MAILACCESS_SHARE_HEALTH` | `platform-health` | None | `false` | Opt in to anonymized health sharing; sharing still requires `--share`. |
| `DOMAIN_CLUSTER_CAP` | `domain_cluster` | None | `20` | Maximum domains checked per infrastructure cluster pass. |

## Identity Graph

Every investigation generates a cross-platform identity graph linking accounts by shared usernames, photos, display names, and breach data. View at:

`/investigation/:id/graph`

Export as D3-compatible JSON via `GET /api/report/{id}/graph` or fetch clusters with confidence scores via `GET /api/report/{id}/clusters`.

Findings are automatically grouped into identity clusters with confidence scoring. Use `--show-collisions` to expand low-confidence matches in CLI output.

## Name Consensus Engine

MailAccess collects name signals from every module that returns profile data: GitHub, Gravatar, Keybase, PGP keys, ORCID, LinkedIn, git commits, and more. The Name Consensus Engine synthesizes those signals into a single defensible output:

```text
CONFIRMED IDENTITY
  Name:     Katriel Moses  [CONFIRMED]
  Sources:  GitHub · Gravatar · Keybase · PGP
  Reasoning: 4 independent sources agree.
```

Confidence bands:
- Confirmed: 3+ independent sources, score >= 2.5
- Probable: 2+ sources, score >= 1.5
- Possible: single source, score >= 0.5
- Unknown: no reliable name signals

Role/system email addresses (`noreply@`, `admin@`, `support@`, `info@`, and similar) are automatically detected and skipped.

## Defender's Brief

Every investigation includes a Defender's Brief: a 30-second risk summary designed for security managers, not just analysts.

```text
DEFENDER'S BRIEF
  Risk:    CRITICAL
  Summary: Active infostealer infection detected.
  1. Active credential theft   [CRITICAL]
     Infostealer detected via Hudson Rock.
     -> Rotate credentials immediately.
  2. Email in 8 breaches       [HIGH]
     Spanning 2012-2024.
     -> Audit password reuse.
  3. Real identity confirmed   [HIGH]
     John Doe - 2 independent sources.
     -> Review public profile exposure.
  Next action: Immediately rotate credentials and enforce hardware MFA.
```

Suppress it with `--no-brief`.

## Historical Intelligence

MailAccess searches the Wayback Machine CDX API for archived pages where the email appeared publicly — catching deleted blog posts, old forum signatures, and removed contact pages.

GitHub commit history is searched by author email, revealing repos contributed to, real name from git config, and development activity timeline.

## Deep Breach Mode

Enable with `ENABLE_BREACH_DEEP=true`.

Fetches the full HIBP breach corpus on startup, ranks sites by severity (record count × data class multipliers), then probes the top 100 highest-severity sites for account existence via YAML probes and generic reset-flow inference. Findings show breach name, record count, data classes, and severity — giving analysts a probabilistic credential exposure estimate.

Example output:

```text
⚠ adobe.com    CRITICAL  153M records
  [Passwords, Email, Password hints]
✓ dropbox.com  HIGH       69M records
  [Email, Passwords]
~222M records across 2 breaches potentially include this email's credentials
```

## Pipeline

MailAccess is pipeline-friendly: read target emails from stdin, stream JSONL output, and branch on exit codes in CI/CD scripts.

```bash
# Batch from file
cat emails.txt | mailaccess investigate -

# Stream JSONL
mailaccess investigate you@example.com --format jsonl | jq .

# Filter critical findings
mailaccess investigate you@example.com --format jsonl | jq 'select(.severity=="critical")'
```

**Exit codes:** `0` clean · `1` findings · `2` breaches · `3` error

See [docs/integrations.md](docs/integrations.md#pipeline-integration) for GitHub Actions examples.

---

## Domain Email Harvesting

Given a company domain, MailAccess discovers associated email addresses across
8 concurrent sources. This is a **separate** engine from `investigate` —
domain-centric rather than email-centric, and built to rival or exceed
theHarvester (the most widely used free OSINT email harvesting tool).

Quick start:

```bash
mailaccess harvest-emails --domain example.com
```

With SMTP verification (opt-in):

```bash
mailaccess harvest-emails --domain example.com
```

Export results:

```bash
mailaccess harvest-emails --domain example.com --export results/harvest.json
mailaccess harvest-emails --domain example.com --export results/harvest.csv
mailaccess harvest-emails --domain example.com --export results/harvest.ndjson
```

Key flags:

| Flag | What it does |
|---|---|
| `--domain DOMAIN` | Target domain (required). Rejects free providers. |
| `--no-verify` | Skip the SMTP verification that runs by default. |
| `--use-proxies` | Route the proxy-aware harvest modules through the configured ScrapingAnt transport. |
| `--proxy-fallback-ok` | Allow direct fallback if ScrapingAnt proxy fails. Without this flag, proxy failures raise an error instead of falling back silently. |
| `--lite` | Faster, fewer dork queries per engine. |
| `--timeout SECONDS` | Override the profile default harvest duration. |
| `--export FILE` | Export to JSON, CSV, or NDJSON (inferred from extension). |
| `--min-confidence {high,medium,low}` | Filter by confidence label. |
| `--min-confidence-score FLOAT` | Filter by numeric score (0.0–1.5). |
| `--on-domain-only` | Hide third-party mentions. |
| `--exclude-domain DOMAIN` | Exclude a domain. Repeatable. |
| `--max-cc-records N` | Override Common Crawl record cap (default 100). |

When `--use-proxies` is set, only `email_search_dork` and
`employee_name_discovery` are routed through the configured ScrapingAnt
transport. The other harvest modules stay direct, and SMTP verification is
never proxied. Use `mailaccess configure proxy show` to confirm the active
transport. The deprecated `mailaccess config` alias still works during the
transition, but `configure` is the canonical form.

By default `--use-proxies` uses strict mode: if the proxy fails,
the request is not sent rather than falling back to direct. To allow
direct fallback:
  mailaccess harvest-emails --domain example.com --use-proxies --proxy-fallback-ok

**Sources:** Common Crawl (highest-yield free source, exploited for email
extraction in a way no other tool currently does), GitHub code + commit
authors, certificate transparency logs (CA-attested), npm + PyPI registries,
PGP keyservers, DuckDuckGo + Bing search engine dorking, employee name
discovery (LinkedIn, company pages, SEC EDGAR, press releases,
OpenCorporates), and email pattern generation with optional SMTP
verification.

**Output:** domain-centric, confidence-grouped (HIGH / MEDIUM / LOW), with
rationale chips explaining each score, role accounts listed separately,
subaddress variants collapsed, and RFC 2606 placeholder domains filtered
out.

**Safety:** SMTP verification is opt-in only — never enabled by default,
never enabled by env var alone. Mandatory catch-all detection runs before
any SMTP probe. Hard cap of 100 probes per domain per run.

Full documentation: [docs/harvest-emails.md](docs/harvest-emails.md).

---

## Adding a Platform

No Python required. Drop a YAML file in `backend/platforms/`:

```bash
cp backend/platforms/TEMPLATE.yaml backend/platforms/mysite.yaml
```

Edit fields, submit PR.

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guide.

## Export Formats

| Format | `?format=` value | Use case |
|--------|-----------------|----------|
| JSON | `json` | Programmatic use, archiving |
| CSV | `csv` | Spreadsheet analysis |
| PDF | `pdf` | Human-readable reports |
| Markdown | `markdown` | Wikis, issue trackers |
| STIX 2.1 | `stix` | Threat intelligence platforms |
| Maltego XML | `maltego` | Maltego graph import |

## Integrations

| Integration | How |
|-------------|-----|
| Maltego | Local transform server at `POST /maltego/email_investigate` (no API key required) |
| Slack | Set `SLACK_WEBHOOK_URL` in `.env` |
| Discord | Set `DISCORD_WEBHOOK_URL` in `.env` |
| Generic webhook | `INTEGRATION_WEBHOOK_URL` + optional `INTEGRATION_WEBHOOK_SECRET` (HMAC) |

## Self-Hosting

```bash
cp .env.example .env      # all API keys are optional
docker compose up         # backend :8000  ·  frontend :3000
```

Open **http://localhost:3000** in your browser. Full setup guide: [docs/self-hosting.md](docs/self-hosting.md).

## Platform Health & Self-Healing

MailAccess tracks probe outcomes for every platform it touches in
`~/.mailaccess/platform_health.db`. Phase 6C makes that data visible; Phase
6D makes it actionable. After every investigation, the system:

> **Note:** `mailaccess platform-audit` shows platforms that have been probed
> in your local investigations. This number grows over time. The full platform
> database (2500+) is checked during every investigation regardless of how many
> appear in the health DB.

- **Auto-skips** platforms with > 70% inconclusive probes over the last 30 days
  (only when those probes were collected in the last 14 days — stale stats
  never trigger a re-skip).
- **Auto-demotes** Wave-1 platforms with > 40% inconclusive probes to Wave 2
  for the current investigation.
- **Auto-upgrades** Wave-2 platforms with < 10% inconclusive probes (and recent
  activity) back into Wave 1.

Every auto-action writes a JSONL entry to
`~/.mailaccess/platform_demotion.log` with timestamp, platform, action,
reason, stats, and the env-var override hint.

Platforms are classified as:

- `KEEP` — reliable; no action needed
- `WATCH` — insufficient data
- `DEMOTE` — noisy; moved to Wave 2
- `SKIP` — sustained failure; excluded

### Inspecting auto-actions

```bash
mailaccess platform-audit                 # show SKIP / DEMOTE / KEEP / WATCH per platform
mailaccess platform-audit --recommend-skip   # only SKIP candidates, with override instructions
mailaccess platform-audit --show-demotions   # only platforms that were auto-demoted, with stats + override env-var hints
mailaccess platform-health                # browse raw per-platform stats
```

### Overriding auto-demotion

Every auto-demotion is reversible via env var. The mapping rule: take the
platform name, strip non-alphanumeric characters, uppercase it, and prefix
with `MAIGRET_FORCE_`. So `NoisySite.com` becomes
`MAIGRET_FORCE_NOISYSITECOM`.

For example, override GitHub with `MAIGRET_FORCE_GITHUBCOM=true`.

```bash
# Run with NoisySite.com forced to its native wave, ignoring health stats:
MAIGRET_FORCE_NOISYSITECOM=true mailaccess investigate user@example.com
```

### Community health sharing (opt-in)

You can contribute anonymized platform health stats to a public GitHub Gist:

```bash
mailaccess platform-health --share
```

This is strictly opt-in. The flag is the only way this code path executes
— no background jobs, no scheduled tasks, no automatic upload. The payload
contains platform-level metadata only (hit / miss / inconclusive rates,
average latency, total probes, last probed). No user data, no email
addresses, no investigation targets. Set `MAILACCESS_SHARE_HEALTH=false`
in `.env` (the default) — the env var is documentation only; the CLI
requires the explicit `--share` flag.

## False Positive Control

MailAccess applies multiple layers before accepting platform-enumeration hits:

- Absence strings are applied to every check type, including status-code checks.
- A `200 OK` response under 500 bytes is treated as inconclusive.
- HTML entities are decoded before pattern matching.
- Usernames matching the top-1000 common-name corpus are downweighted without corroboration.
- Failure signals cover English, German, French, Spanish, and Portuguese.
- Catch-all platforms that return hits for non-existent users are excluded.

See [docs/fp-control.md](docs/fp-control.md) for the full control model.

## CLI Reference

| Command | Description |
|---------|-------------|
| `mailaccess investigate <email>` | Run a full investigation against an email address |
| `mailaccess investigate -` | Read target email from stdin |
| `mailaccess harvest-emails --domain <domain>` | Domain email harvesting — 8 concurrent sources, see [Domain Email Harvesting](#domain-email-harvesting) |
| `mailaccess serve` | Start the backend server on :8000 |
| `mailaccess history` | List past investigations |
| `mailaccess keys list` | Show all configured API keys |
| `mailaccess keys set <KEY> <value>` | Set an API key |
| `mailaccess keys unset <KEY>` | Remove an API key |
| `mailaccess configure set-url <url>` | Point the CLI at a MailAccess instance |
| `mailaccess configure proxy show` | Show the active ScrapingAnt proxy transport |
| `mailaccess configure proxy enable residential|datacenter` | Select the ScrapingAnt proxy transport for routed traffic |
| `mailaccess configure proxy disable` | Revert ScrapingAnt proxy routing to the REST API transport |
| `mailaccess modules` | List all available modules |
| `mailaccess commands` | List all CLI commands |
| `mailaccess platform-health` | Inspect, export, or clear persistent platform probe health |
| `mailaccess platform-health --share` | Opt-in: post anonymized platform health stats to a public Gist |
| `mailaccess platform-audit` | Inspect platform reliability, ranked by noise rate |
| `mailaccess platform-audit --show-demotions` | Show only platforms that were auto-demoted in the last 24h, with override env-var instructions |
| `mailaccess platform-audit --recommend-skip` | Show only SKIP candidates, with `MAIGRET_FORCE_<PLATFORM>` override hints |
| `mailaccess investigate <email> -m` / `--enable` | Enable opt-in modules for this run only. Comma-separated or `all`. Example: `-m breach_deep,ghunt` |
| `mailaccess investigate <email> --no-brief` | Suppress Defender's Brief section |

The `--output` / `-o` flag on `investigate` saves the report to a file. The extension determines the format: `.json`, `.csv`, `.pdf`, `.md`, `.stix.json`, `.maltego.csv`.

When a bare filename is given (no directory component), the file is written to the `results/` directory automatically (e.g. `-o report.json` → `results/report.json`). This directory is git-ignored so investigation outputs are never accidentally committed. Absolute or relative paths that include a directory component (e.g. `-o /tmp/report.json`) are written as-is.

## API Keys

| Key | Module | Where to get it | Required? |
|-----|--------|-----------------|-----------|
| `HIBP_API_KEY` | `hibp` | https://haveibeenpwned.com/API/Key | Yes (module skips without it) |
| `SERPAPI_KEY` | `google_dork` | https://serpapi.com | Yes (module skips without it) |
| `SHODAN_API_KEY` | `domain_intel` | https://account.shodan.io | No |
| `EMAILREP_API_KEY` | `emailrep` | https://emailrep.io | No |
| `HUNTER_IO_API_KEY` | `hunter_io` | https://hunter.io | No |
| `GITHUB_TOKEN` | `github_commits` | https://github.com/settings/tokens | No (optional) |
| `COMPANIES_HOUSE_API_KEY` | `companies_house` | https://developer.company-information.service.gov.uk | No (free forever, no CC) |
| `SLACK_WEBHOOK_URL` | Webhooks | https://api.slack.com/messaging/webhooks | No |
| `DISCORD_WEBHOOK_URL` | Webhooks | Discord server settings | No |
| `SCRAPINGANT_API_KEY` | ScrapingAnt (REST API) | https://scrapingant.com/?ref=mzliyzh | No (optional partnership) |
| `SCRAPINGANT_PROXY_RESIDENTIAL_USERNAME` | ScrapingAnt (Residential Proxy) | https://scrapingant.com/?ref=mzliyzh | No |
| `SCRAPINGANT_PROXY_RESIDENTIAL_PASSWORD` | ScrapingAnt (Residential Proxy) | https://scrapingant.com/?ref=mzliyzh | No |
| `SCRAPINGANT_PROXY_DATACENTER_USERNAME` | ScrapingAnt (Datacenter Proxy) | https://scrapingant.com/?ref=mzliyzh | No |
| `SCRAPINGANT_PROXY_DATACENTER_PASSWORD` | ScrapingAnt (Datacenter Proxy) | https://scrapingant.com/?ref=mzliyzh | No |

**ScrapingAnt** (optional, partnership) — Improves reliability of platform checks
and search engine dorking by routing traffic through rotating residential or
datacenter proxies. Off by default.
Sign up: https://scrapingant.com/?ref=mzliyzh

## Changelog

### 0.12.8

- CRITICAL: Fixed the 7-minute idle hang caused by persona-pivot work holding
  track 2 open until the full budget expired.
- CRITICAL: Fixed budget cancellation bypassing module-result recording and
  leaving modules marked `not_started` after they had run.
- CRITICAL: Fixed cross-domain email leakage by always checking the address's
  actual domain instead of trusting the merged `on_domain` flag.
- Runtime policy and calibration skips now record an explicit `SKIPPED` result.
- Off-domain email findings are retained in `shadow_profiles`, not mixed into
  the main organization email list.

### 0.12.7

- Default JSON export to `~/.mailaccess/results/` on every harvest
- Live log file written alongside JSON — `tail -f` for real-time feed
- Auto-cleanup: 50 files per domain max, 30-day retention
- `mailaccess keys test {KEY_NAME}` — validates API key with live call
- Doctor command: per-source health from `platform_health.db`
- Supplementary output files: `subdomains.txt`, `emails.txt`, `cidrs.txt`,
  `nuclei_targets.txt`, `report.md` — all written automatically
- `--no-extras` flag to skip supplementary files
- `--no-export` flag to skip all file output
- All output paths printed at end of every harvest

### 0.12.6

- Result cache: repeat harvests return in under one second from `~/.mailaccess/cache/`.
- Cache TTL defaults to one hour; use `--force`, `--clear-cache`, or `--clear-all-cache` to invalidate it.
- PGP keyservers run three concurrent queries, Common Crawl collections run in batches of three, and crt.sh runs alongside CertSpotter.
- Added no-key HackerTarget subdomain discovery and Shodan InternetDB port, hostname, and CVE enrichment.
- Added RIPE Stat ASN prefix discovery with masscan/nmap-ready CIDR output files.
- Added `mailaccess doctor` diagnostics for installation, backend, configuration, API keys, network access, and cache state.

### 0.12.5

- SMTP verification now runs by default; use `--no-verify` to skip it.
- Catch-all detection is mandatory before probing, with a 10-address cap and one 30-second greylist retry.
- Google and Microsoft 365 MX routes bypass direct SMTP enumeration in favor of provider-aware verification.
- Live progress reports module actions, findings, elapsed time, ETA, and writes a tail-friendly live log.
- Qualified discovered names trigger bounded persona email searches across the public web.
- Personal email candidates are labeled as unverified leads, hidden behind `--show-personal`, and always included in JSON exports.
- Removed the `--verify-smtp` flag (breaking CLI change).

### 0.12.4

- Restored subdomain email extraction and role-account aggregation.
- Added Team Cymru ASN infrastructure aggregation, CLI subdomain/infrastructure panels, and JSON export fields.
- Harvest mode now reports the required optional extra clearly; ML remains opt-in and `investigate` fails fast when the backend is not running.

### 0.12.3

- Added the Subdomain Intelligence discovery, scoring, scraping, signal, budget,
  CLI, export, and regression-test surfaces.
- Added profile-aware subdomain discovery, PTR mining, calibration mode, and
  harvest-diff compatibility for structured subdomain findings.

### 0.12.2

Audit-preparation release for controlled comparison against Blackbird, Holehe,
Maigret, Sherlock, and theHarvester.

- Calibrated active email-existence probes for Spotify, Eventbrite, Chess.com,
  Adobe, and El Mundo against current live response markers.
- Added same-status hit/miss handling for JSON existence APIs.
- Disabled sources that are currently WAF-blocked, stale, or unreliable rather
  than allowing them to generate noisy findings.
- Added explicit audit guidance and result-comparison criteria in
  `docs/release-0.12.2-audit.md`.
- PDF generation is outside the scope of this release.

### 0.12.1

- Added optional cookie/CSRF pre-check negotiation for platform probes.
- Added nine Blackbird email-existence platform definitions.
- PDF exports now include an authorized-research disclaimer and inline avatar thumbnails with failure-safe placeholders.

### 0.12.0

- Optional ML name classifier: `pip install mailaccess[ml]` plus `python -m spacy download en_core_web_md` adds spaCy PERSON NER validation.
- Hybrid heuristic pre-filter + NER pipeline eliminates page-fragment false positives such as "Going Blue Team" and "Cloud Platform".
- First-run `harvest-emails` prompt offers ML install when `ML_NAME_CLASSIFIER=ask`.
- Heuristic fallback is unchanged when ML is absent.
- `ML_NAME_CLASSIFIER` config supports `ask`, `on`, and `off`.

### 0.11.5

- **Adaptive harvest orchestrator** — signal-driven two-track architecture replaces the fixed module sequence. Track 1
  runs guaranteed high-signal page work; Track 2 runs opportunistic modules within the remaining budget.
- **WorkScheduler** — priority queue with dedup and dynamic mid-run work submission shared by both tracks.
- **TimeBudget** — time-based execution control, soft per-module timeouts, and profile-aware defaults.
- **Track1Runner** — guaranteed high-signal paths always execute before opportunistic work.
- **Track2Runner** — opportunistic discovery runs inside the remaining harvest budget.
- **Pagination expansion** — discovered next-page URLs are added back to Track 1 automatically.
- **`--timeout` flag** — explicit harvest duration override for live runs.
- **Budget defaults** — T0=2700s, T1=1200s, T2=600s.
- **INE-style hydration card detection** — `HydrationDataExtractor` now accepts the `__NEXT_DATA__.props.pageProps.instructorsData.cards[]` shape used by INE.com (and similar training platforms). `title` is treated as the instructor's display name and `subtitle` as their role when `title` passes `is_plausible_person_name`, so the standard ≥2-of-4 person heuristic fires on these inverted-shape cards. LinkedIn/Twitter URLs from each card's `references[]` now surface on `PersonHit.bio_url`.
- **Hydration extractor bug fix** — `_string_at(node, _TITLE_KEY)` was being called with a bare string where an iterable of key names is expected, so the `title` role-fallback path silently iterated over the characters of the word "title" and never matched. Now wrapped as `_string_at(node, (_TITLE_KEY,))`; the fallback works as designed.
- **Training vocabulary expansion** — `_TRAINING_RE` in `ContextRouter` extended with cybersecurity-specific signals: `oscp|oswe|osep|giac|pentest(?:ing)?|red\s?team|blue\s?team|cyber\s?range|ctf|capture\s+the\s+flag|dfir|threat\s+hunt|soc\s+analyst|infosec|cybersecurity`. Distinguishes dedicated security training platforms (INE, SANS, TCM Security) from generic e-commerce course sellers.
- **Training candidate paths** — `training_academic` rule gained `/authors, /instructor, /profiles, /people, /meet-the-team, /learning/instructors` alongside the original `/instructors, /faculty, /teachers`. `data/industry_vocabulary.json` `lms` row updated for production parity.
- **Deny list guard** — explicit test confirms `/testimonials, /case-studies, /customers` still fire alongside the training expansion so customer testimonials cannot be mis-harvested as employee pages.
- **Tests** — 6 new tests (`test_ine_style_cards_extracted`, two INE negative guards, `test_cybersec_signals_trigger_training_vertical`, `test_generic_course_vocabulary_still_triggers`, `test_deny_list_still_excludes_testimonials_case_studies_customers`). New fixture: `tests/fixtures/ine_next_data.json`.

### 0.11.4

- Signal pool global wiring: all modules emit signals to shared pool
- Confirmed email pattern propagates to pattern_and_verify before SMTP probing
- Cross-module name/email correlation boosts confidence when same person found by multiple sources
- Pattern inference from confirmed emails: dominant format detected and prioritized
- HTML entity decode pre-filter (u003e leak fixed)
- Asset filename false positive filter (.png, .woff etc. no longer classified as emails)
- Common Crawl strict subdomain filtering
- Hydration extractor, pagination handler, schema content extractor, sitemap router, industry vocabulary router all wired into live harvest path

### 0.11.3

Maintenance / quality release — the headline change is fixing the BUG-1 cluster of stale tests from the 0.11.1 Phase 3 stealth refactor (the dorker tests that the 0.11.2 entry *intended* to delete, but were rewritten instead). No new modules, no public API changes.

- **BUG-1 dorker test rewrite** — `tests/core/test_bing_dorker.py` (5 stale tests) and `tests/core/test_duckduckgo_dorker.py` (5 stale tests) were asserting against the pre-Phase-4 `_MailAccessClient` / `_RoutedMailAccessClient` wrappers, which the dorkers no longer own. Both files were rewritten to inject a `CachedFetch` facade and assert against `CachedResponse` attributes (status, text, headers). 13 new bing tests and 14 new DDG tests now cover the cache-hit dedup, 202/403/429 CAPTCHA blocks, 5xx pass-through, body-marker CAPTCHA detection, 404 graceful-empty, and transport-error swallowing paths. The pure-HTML parser helpers (`_parse_bing_html`, `_parse_ddg_html`) get their own coverage so a parser regression doesn't get masked by a fetch regression.
- **email_search_dork fix** — `tests/modules/test_email_search_dork.py` was calling a `build_dork_queries` stub that didn't accept the Phase-4 `aggressive` kwarg, so the test crashed with `TypeError` instead of exercising the routing logic it claimed to cover. Stub now accepts `aggressive`, plus a new test pins that the value actually reaches the dork-query builder.
- **Shared fetch fixtures** — `tests/_fetch_fixtures.py` is the new home for the `FakeSession` / `make_cached_fetch` / `make_cached_response` / `make_local_fetch` helpers that were previously copy-pasted across the cache, dorker, syndication, sitemap, and pagination test files. `tests/conftest.py` re-exports them as pytest fixtures (`fake_session`, `fetch_cache`, `local_http`, `make_response`). The dorker rewrite is the first consumer; future module tests should request the fixtures rather than rolling their own.
- **Mock-integrity guard test** — `tests/test_no_live_network.py` runs a small AST scan across the test tree: it fails the suite if a test file imports `aiohttp` or `requests` (no in-process mock equivalent — guaranteed live network), or constructs a bare `httpx.AsyncClient()` without a `transport=` kwarg (the most common "I forgot to mock this" shape). The two pre-existing tests that use the `monkeypatch.setattr(client, "get", _fake)` pattern are in the allowlist with a `TODO(BUG-1 follow-up)` to migrate them to `MockTransport` later — that's a separate task.
- **Dead-code audit (conservative pass)** — Audited `backend/modules/` for "legacy list-scraping modules superseded by the PaginationHandler and ContextRouter loops". **Zero deletions**: the only module that does manual list pagination (`wordpress_rest.py`, `for page in range(1, _MAX_PAGES + 1)` over `?page=N`) is still actively wired into the orchestrator and tested; replacing its loop with `PaginationHandler` would require special-casing the 401/403/non-JSON stop conditions that the walker doesn't currently understand. Noted in `docs/enhancement-roadmap.md` as a future refactor target rather than ripping it out without a replacement.

### 0.11.2

This is a maintenance / quality release — no new modules, no new public APIs. Focus is on FP suppression (false-positive killers), leaked-name cleanup, exposure-score correctness, and a critical Wayback hang fix.

- **Test suite fixes (1A–1E)** — Deleted stale tests for the removed private Bing/DDG dorker APIs (`test_bing_dorker.py`, `test_duckduckgo_dorker.py`). Updated the `_patch_fast_success_path` mock signature to accept the post-Phase-4 `lite_mode` / `aggressive` kwargs. Replaced `asyncio.get_event_loop()` (deprecated) with `asyncio.run()` in `test_avatar_hasher.py`. Audited the residential-proxy path against the ScrapingAnt dashboard (already verified live; no change). Fixed the `test_proxy_failure_returns_partial_with_errors` test that was patching the wrong layer — it was patching `httpx.AsyncClient` (`build_client`) but the production path uses `StealthSession` (curl-cffi) when available, so the patch was a silent no-op and the real network was being hit. Now patches `StealthSession.get()` to raise `httpx.ProxyError`, exercising the dorkers' fallback path correctly.
- **Twitter display name cleanup (2A, 2C)** — Twitter / X sometimes concatenates `"(Twitter / X)"` into the display name on a profile lookup, which then bleeds into the confirmed-identity row. Added `clean_twitter_display_name()` in `twitter_profile.py` to strip the suffix on extraction. Added 6 unit tests covering the standard name, the `"(Twitter / X)"` suffix, the bare suffix, leading/trailing whitespace, and the empty / None edge cases.
- **Bio parenthetical @-handle stripping (2B)** — Parenthetical Twitter handles (`@handle`) inside the bio / display name field were being captured by the name consensus layer and bleeding into the confirmed name. Added `@`-handle stripping inside `normalize_name()` in `name_consensus.py`. Added a regression test in `tests/test_name_consensus.py`.
- **Exposure score correctness (3A–3C)** — The CLI summary's `exposure_score_pct` was dividing the executed-attack-surface score by `total_modules` instead of `executed_modules`, dragging LOW coverage runs down to ~0%. Fixed: `service.py` now computes the denominator from executed modules only. Added an engine-level helper `_max_exposure_score_for_executed()` in `engine.py` so other report paths use the same corrected denominator. Updated `render_summary()` in `cli/main.py` to surface the recomputed score alongside the existing personal-email rollup.
- **Wayback hang fix** — `StealthSession.get()` silently drops unknown kwargs, so Wayback's `timeout=12.0` was being stripped and archive.org fetches had **no effective timeout** — a slow CDN edge could deadlock the entire orchestrator. Wrapped the Wayback session call in `asyncio.wait_for(timeout=timeout)` so every archive.org fetch has a hard 12s ceiling regardless of what the session does with kwargs. Audit confirmed this was the only `client.get(... timeout=...)` site that needed the wrap; the three remaining `client.get(timeout=…)` calls in `wayback.py` are on `httpx.AsyncClient`, which honours its own timeout natively.
- **Navigation-graph simulation disabled for archive.org** — `_simulate_navigation()` fires blocking `time.sleep(4–20s)` plus intermediate homepage / parent-path GETs against every target. Archive.org performs no fingerprinting, so the hops are pure overhead on top of an already-slow T0 pacing budget. Added `_skip_nav_sim` field on `StealthSession`; `_build_stealth_session()` in `wayback.py` sets it to `True` after construction. Inter-request pacing (`timing_profile.get_delay()`) is preserved — only the nav-graph hops are skipped.
- **Tests** — 4 new tests (3 in `tests/test_wayback_domain_harvest.py`, 1 in `tests/test_stealth_client.py`) covering the timeout ceiling, the Wayback session-builder flag, the DDG/Bing default (nav-sim still enabled), and the `_skip_nav_sim=True` no-hop behaviour on T0.

### 0.11.1

- Stealth HTTP client (curl-cffi): Chrome TLS/HTTP2 fingerprint, Gaussian timing profiles T0-T5, full Chrome header set with correct Sec-Fetch-* values, referrer chain maintenance
- --stealth flag: T0 Ghost mode (8s mean delay, navigation graph simulation, near-undetectable)
- --fast flag: T4 profile for time-sensitive runs
- Site intelligence rebuild: sitemap discovery, homepage link traversal, finds /leadership.php and any non-standard team page URL
- Structured data extraction: JSON-LD Person, microdata, hCard, DOM team card pattern — replaces body-text name regex entirely
- Multi-collection Common Crawl: 6 collections default (24 in --aggressive), digest dedup, targeted team/contact/leadership URL queries
- Cloudflare data-cfemail decode on all HTML
- Wayback Machine domain-wide sweep: CDX query, archived team/contact/press pages, historical email recovery
- GitHub org members module (no auth required)
- Hunter.io optional source (50/mo free, no CC)
- Google CSE optional search backend (100/day free, replaces broken DDG/Bing)
- Bing Web Search API removed (retired Aug 2025)
- --aggressive mode: maximum coverage, all sources at full depth, shows LOW results

### 0.11.0

- Banner: rewrote the CLI ASCII art from the old heavy block-face to a cleaner wordmark in flat red purple (`#820747`); background is left to the terminal so the banner now reads clearly on any TTY
- Banner: the blocks are no longer a faded multi-row gradient, and the letterforms are no longer carved out as negative space — solid red-purple wordmark on the user's terminal background

### 0.10.9

- Role classifier: short prefixes (3 chars or fewer) are no longer used for partial matching, which fixes false positives where personal emails like `bdennis@`, `devlin@`, and `priya@` were misclassified as role accounts
- Exact and prefix-plus-separator matching remain unchanged, so `bd@`, `it@`, `hr@`, and `bd.team@` still classify as role accounts

### 0.10.8

- Harvest output now renders the `DOMAIN EMAIL HARVEST` header only once
- `role_prefixes.json` and the other referenced `data/` corpora are now included in the wheel for fresh installs
- Generic noun-phrase filtering now rejects business/product fragments like `Education Manufacturing` and `CloudPort Edge`

### 0.10.7

- Packaged `data/` corpora and `backend/platforms/*.yaml` into the wheel so fresh installs no longer crash on missing corpus files
- `mailaccess keys list` now renders both the API Keys table and the ScrapingAnt Keys table
- Domain harvest output no longer double-renders
- Harvest timestamps now normalize consistently instead of truncating to seven characters
- Company-page name extraction now excludes H2/H3 furniture, repeated-token fragments, and company-name self matches
- Name consensus now rejects module artifact tokens like `sec`, `edgar`, and related poison strings
- Summary bar coverage label now says `Coverage` instead of `Risk`
- ScrapingAnt proxy `Last configured` now reads the persisted timestamp correctly

### 0.10.5

- Critical fix: engine no longer crashes when a module returns None instead of ModuleResult
- All modules audited and patched to return proper ModuleResult on all code paths
- Permanent regression guard: test asserts every module returns ModuleResult, never None

### 0.10.4

- Banner color corrected (dark red `#8B0000`, not bright red)
- Banner ScrapingAnt referral link now clickable in supported terminals
- ASCII art cutoff on wide/narrow terminals fixed
- `mailaccess configure proxy` now launches interactive setup wizard when run without subcommand — guides through API key, residential and datacenter credentials, and transport selection in one flow
- Existing `configure proxy show/enable/disable` subcommands unchanged

### 0.10.2

- New command: `mailaccess harvest-emails --domain <domain>` — domain-centric email harvesting
- Eight concurrent source modules for domain email discovery
- Common Crawl Index exploitation for email extraction (highest-yield free source, not used this way by any other tool)
- GitHub commit author discovery (`author:` qualifier)
- Certificate transparency CA-attested email extraction
- npm/PyPI registry package author emails
- PGP keyserver UID extraction
- Employee name discovery (LinkedIn, company pages, SEC EDGAR, press releases, OpenCorporates)
- Email pattern generation (11 standard templates) with pattern propagation optimization
- Optional SMTP RCPT TO verification with mandatory catch-all detection and 100-probe hard cap
- Cross-module confidence scoring with rationale chips
- Role account classification (~150 prefixes)
- Subaddress collapsing (`jane+filter@` = `jane@`)
- RFC 2606 placeholder domain filtering
- CSV/NDJSON/JSON export formats
- Filter flags: `--min-confidence`, `--on-domain-only`, `--exclude-domain`
- Platform audit now shows version in all states

### 0.9.0

**PHASE 1 — False Positive Killers**

- Absence strings applied to `status_code` checks
- Content-length sanity check on 200 responses
- HTML entity decoding before pattern matching
- Common-name filter (1000-entry corpus)
- Multi-language reset signals (DE/FR/ES/PT)
- Disposable-domain detection (15k+ domains)

**PHASE 2 — Reasoning Layer**

- Avatar perceptual hashing (imagehash, Hamming ≤ 5)
- Bio fuzzy matching (RapidFuzz, 25 aggregators)
- Persistent platform health (SQLite, rolling window)
- Temporal clustering and shadow-profile detection
- Name consensus: fuzzy merge, `token_set_ratio`, non-Western Unicode, temporal decay, and high-trust single-word names

**PHASE 3 — Platform Expansion**

- Sherlock native engine (~300 platforms)
- Nexfil native engine (~300 platforms)
- Blackbird native engine (social focus)
- `SOURCE_PRIORITY` dedup hierarchy

**PHASE 4 — Output Hardening**

- Platform dedup strips 21 subdomain prefixes
- Bio aggregator expanded from 7 to 25 domains
- Credential risk uses YAML service categories
- Breach normalizer polish

**PHASE 6 — Feedback Loop**

- Name consensus: fuzzy, temporal, and Unicode handling (6A)
- Domain clustering and shadow profiles V2 (6B)
- Platform audit CLI: `mailaccess platform-audit` (6C)
- Self-healing platform DB: auto-demotion, auto-upgrade, demotion log, and opt-in community sharing (6D)

**ENGINE**

- Per-module asyncio timeout enforcement
- Zombie investigation recovery on startup
- Graph construction optimized for large datasets
- All platform-health calls made async

### 0.8.1
- maigret_platforms now default-on (2500+ platforms checked in every investigation)
- Wave 2 remains opt-in via ENABLE_MAIGRET_WAVE2
- ENABLE_MAIGRET_PLATFORMS=false to disable if investigation speed is a priority

### 0.8.0
- Native Maigret platform engine: 2500+ platforms without Maigret runtime dependency
- Two-wave architecture: Wave 1 is the fast default when enabled; Wave 2 adds slower and more fragile platforms
- Catch-all detection: validates platforms against known-unclaimed usernames before sweep
- Platform deduplication: WMN + Maigret merged by URL domain, dual-confirmed findings marked high confidence
- Custom platform additions via `data/mailaccess-extra-sites.json`
- `ENABLE_MAIGRET_PLATFORMS` env var, default `false`
- `ENABLE_MAIGRET_WAVE2` env var, default `false`
- Platform database auto-refreshed every 24h from Maigret GitHub (MIT licensed)

### 0.7.0
- Name Consensus Engine: synthesizes name signals from all profile modules into Confirmed/Probable/Possible/Unknown with reasoning and source list
- Defender's Brief: risk-first output with top 3 actionable findings and concrete next step. Suppressed with `--no-brief`.
- PGP keyserver: email to UID name lookup via keys.openpgp.org, weight 1.0, highest trust
- ORCID: researcher identity lookup, institutional verified names, weight 0.95
- HackerNews profile: name extraction from about field via Firebase and Algolia APIs
- SEC EDGAR: phone/contact extraction from public filings for business domains, no key
- Companies House UK: officer names and registered address, free key required
- Press intel: press release contact extraction, opt-in via `-m press_intel`
- WHOIS/RDAP phone extraction: surviving post-GDPR registrars now surface phone numbers
- Role/system email detection: `noreply@`, `admin@`, `support@`, and similar addresses skip name inference automatically
- Name shown in summary bar when confirmed/probable

### 0.6.5
- QA pass: cosmetic label fixes, keybase 404
  handling, WebSocket large payload fix
- github_user, twitter_profile, linkedin_snippet
  display names corrected in identity clusters
- Alias normalization original email now passed
  to all profile extraction modules
- Timeline builder wired to all breach sources
- Profile intelligence and PII findings in all
  export formats

### 0.5.3
- Cluster identity analysis no longer shows raw traceback
  on timeout — shows dim fallback message instead
- Hardcoded minimum timeout floors for pip-installed users:
  account_discovery 120s, username_pivot 60s,
  user_scanner 180s, whatsmyname 200s
- .env overrides still win if set higher

### 0.5.2
- Config resilience: CORS_ORIGINS and dict fields now
  accept plain strings, comma-separated values, and
  empty strings without crashing
- No more SettingsError on first run with default .env
- Startup confirmation line shows config parsed correctly

### 0.5.1

- LeakCheck integration: free corpus lookup, covers CIS/regional breaches XposedOrNot misses
- XposedOrNot paste signals surfaced separately from breach signals in CLI and summary bar
- Ransomware domain victim correlation: checks email domain against ransomware victim lists (ransomware.live + ransomlook.io)
- Summary bar now shows three-part breakdown: Breaches: X | Pastes: Y | Stealer: Z
- LeakCheck stealer category correctly routed to stealer signal count not breach count
- Removed legacy credential_risk: null from JSON export

### 0.5.0

- XposedOrNot integration: free direct breach corpus lookup, no API key, default-on, closes ~70-80% of HIBP coverage gap
- Breach normalizer: deduplicates breach findings across all sources into single canonical records with source attribution
- Credential Risk Score: separate 0-100 score with band, top 3 score drivers, and recommended analyst actions. Infostealer hit forces CRITICAL. Surfaces in CLI, UI, all exports, and webhooks.

### 0.4.3

- `github_commits`: returns `PARTIAL` (not `FAILED`) without `GITHUB_TOKEN`, includes setup hint
- `whois_lookup`: IANA-managed domains now parse correctly, timezone-aware datetime fix, richer field extraction (`organisation`, `nserver`, `registered`, `expires`)

### 0.4.2

- Default modules now run without any flags: `whatsmyname`, `account_discovery`, `user_scanner`, `username_pivot`, `permutation_discovery`, `phone_intel`, `messaging_hints`
- `-m` / `--enable` flag for opt-in modules per run (`breach_deep`, `ghunt`, `email_discovery`)
- `-m all` enables all three opt-in modules
- Invalid `-m` module name shows helpful warning

### 0.4.1

- Deep breach mode and email discovery improvements
- Phone extractor false positive fixes carried forward

### 0.4.0

- Deep breach mode: probes top 100 highest-severity breached sites for account existence (opt-in, `ENABLE_BREACH_DEEP=true`)
- Name → email discovery: recovers other email addresses owned by same person via SerpAPI dorks (requires `SERPAPI_KEY`)
- Wayback Machine: CDX search for historical pages where email appeared publicly
- GitHub commit search: author-email search across all public commits, surfaces repos + real name from git config (`GITHUB_TOKEN` optional)
- Breach corpus: auto-fetched from HIBP public API, severity-ranked by record count × data class multipliers, cached 24h

## Troubleshooting

![Troubleshooting demo](public/troubleshoot.gif)

## Links

| | |
|-|-|
| [Self-hosting guide](docs/self-hosting.md) | Docker Compose, `.env` reference, PostgreSQL, proxy/Tor, Maltego setup |
| [Module reference](docs/modules.md) | All modules, findings schema, adding new modules |
| [False-positive controls](docs/fp-control.md) | Common-name, disposable-domain, clustering, health, and scoring controls |
| [API reference](docs/api.md) | REST endpoints, WebSocket events, authentication |
| [Export formats](docs/exports.md) | Supported formats, MIME types, filename conventions |
| [Integrations](docs/integrations.md) | Maltego, Slack, Discord, generic webhooks |
| [Contributing](CONTRIBUTING.md) | Adding modules, adding exporters, code style, PR checklist |
| [PyPI](https://pypi.org/project/mailaccess/) | `pip install mailaccess` |
| [GitHub](https://github.com/YOUR_USERNAME/mailaccess) | Source code, issues, releases |

## License

MIT. All data queried by MailAccess comes from public sources. See [DISCLAIMER.md](DISCLAIMER.md) for authorized use cases and legal responsibility.
