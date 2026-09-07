# Phase 5B — Data-acquisition resilience

The load-bearing half of scale (Doc-2 E1/E2/E3 + the audit's fragility findings).
Bulk (5A) without 5B just gets everything CAPTCHA'd/blocked at volume — a single
static proxy, a Chrome-120 fingerprint hardcoded in one place, a shallow linear
search chain that a Brave block short-circuits, and a rate limiter that covers
only the httpx stack and not the curl-cffi stealth path. 5B fixes the root
causes so 5A is trustworthy at volume.

## What shipped

### 1. Unified throttle across both transport stacks
The shared `DomainRateLimiter` previously governed **only** httpx (via its
`_before_request` hook); the curl-cffi `StealthSession` path — DDG/Bing dorkers,
site discovery, the per-run fetch cache — was uncovered, so a bulk run could
hammer one host across both stacks. `StealthSession.get` now `await`s
`rate_limiter.acquire(host)` before dispatching, so **one per-host throttle
governs both transports** — the root-cause fix for the audit's "rate limiter
doesn't cover the stealth path". (`backend/core/stealth_client.py`,
`backend/core/rate_limiter.py`.)

### 2. Rotating client fingerprints
`backend/core/fingerprints.py` — a pool of internally-consistent desktop
fingerprints where the curl-cffi `impersonate` target, `User-Agent`, and
`sec-ch-ua` client hints all agree on the same browser+version (a mismatch is
*more* detectable than no rotation). Targets are validated against the installed
curl-cffi build at import. The default is byte-identical to the old hardcoded
Chrome-120, so behaviour is unchanged when rotation is off. `StealthSession`
picks a fingerprint per session (so across a bulk run each domain presents a
different one); `harvest_fingerprint_rotation` (default on) toggles it, and the
previously-dead `harvest_impersonate_browser` now *pins* a specific target.

### 3. Egress rotation pool
`backend/core/egress_pool.py` replaces the single static proxy: a BYO /
config-driven (`egress_proxies`) pool that round-robins over healthy endpoints,
evicts one after `egress_max_failures` consecutive failures (benched for
`egress_cooldown_seconds`, then re-admitted on probation), and health-checks via
`health_check()`. Transport-agnostic: httpx consults it through
`ProxyConfig.proxy_url` (which now rotates), and `StealthSession` routes through
`proxies=` — both report success/failure back, so eviction reflects real egress
health across both stacks. A single legacy `proxy_url` folds in as a pool-of-one;
empty means direct egress (no hardcoded paid dependency).

### 4. Search-provider failover chain
`backend/core/search_provider_router.py` — Brave → DDG → Bing with **per-provider
health/backoff**. A hard block (202/403/429/CAPTCHA) benches that provider for
`search_provider_cooldown_seconds` and the router transparently rolls to the
next, instead of the old behaviour where a Brave block short-circuited the whole
chain and a benched provider was re-hit on every call.

### 5. Common-Crawl-first posture (default)
`harvest_runner._seed_priorities(cc_first)` — under `cc_first` (default) the
already-crawled web (Common Crawl + Wayback) is promoted to the guaranteed track
(runs first, reliably) and the live-search dork drops to the search-tier
fallback. Plus a **best-effort skip**: when the cheap (non-search) on-domain
sources have already recorded at least `cc_first_min_emails` on-domain addresses
by the time the live-search dork is pulled, the dork is skipped entirely — it
never touches DDG/Bing. On domains the archive covers early this avoids the
DDG/Bing 202/CAPTCHA walls outright; when the cheap sources under-deliver the
dork runs as the fallback (and its own per-module circuit-breaker already stops
after the first block).

## Config (all defaults preserve or improve current behaviour)

| Setting | Default | Meaning |
|---|---|---|
| `cc_first` | `True` | prefer archive over live search scraping |
| `harvest_fingerprint_rotation` | `True` | rotate the fingerprint pool per session |
| `harvest_impersonate_browser` | `""` | pin a specific fingerprint (disables rotation) |
| `egress_proxies` | `[]` | BYO egress pool (empty = direct) |
| `egress_max_failures` / `egress_cooldown_seconds` | `3` / `300` | eviction policy |
| `egress_health_check_url` | generate_204 | health probe target |
| `search_provider_cooldown_seconds` | `300` | per-provider bench duration |

## Validation (done-when)

- **Unit** — `tests/test_resilience_phase5b.py` (21 tests): default fingerprint
  == legacy Chrome-120; every pool target is curl-cffi-supported; rotation
  on/off/pinned; headers honour the fingerprint; egress round-robin / eviction /
  cooldown / success-reset / all-benched / single-proxy compat / `ProxyConfig`
  routing; search failover rolls past a blocked provider, Brave-block no longer
  short-circuits, benched providers are skipped; the unified throttle acquires
  the shared limiter on the stealth path; CC-first prioritises archive over live
  search (and leaves priorities untouched when off).
- **Real, keyless, isolated** — `eval/harness/resilience_metrics.py` runs each
  domain under the resilient posture vs the legacy (CC-first + rotation off)
  Phase-0D baseline and counts hard-blocks (rate-limit/blocked/CAPTCHA/202),
  asserting the resilient run is **never worse** (≤ baseline). On the baseline
  domains the count is equal, because each search module already circuit-breaks
  after its first block — so per-domain the floor is ~one block per live-search
  module. 5B's reductions compound where they matter: **at volume** (the unified
  throttle stops cross-domain self-DoS escalation, egress rotation spreads load,
  failover keeps working when a provider dies) and on **CC-covered domains**
  (the best-effort skip drops the live-search block entirely). A real bulk smoke
  (`rootaccess.tech`) completed with all 5B defaults on: 45 contacts, all graded,
  45 4A snapshots — residual DDG blocks are absorbed by failover, not fatal.
- **Gate** — `python -m eval.harness.gate check` green (0 new test/lint/hang
  failures vs baseline).

## Non-scope

No paid anti-block service is made mandatory (ScrapingAnt stays optional). No new
data sources. The egress pool and any volume-hosting are BYO/config-driven — no
hardcoded spend.
