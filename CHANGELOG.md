# Changelog

### 0.14.4 (security)

- SECURITY: Deep-breach probes now accept only public clearnet FQDNs from the
  HIBP breach corpus; `.onion`, `.i2p`, IP, and malformed domains are excluded.
- Deep-breach probes do not follow redirects, and the reset-probe request layer
  independently refuses non-clearnet targets.

### 0.14.3

- `mailaccess investigate` now auto-starts the backend when it is not already
  running and terminates that managed server after the investigation.
- The base `mailaccess` install now includes harvest support and PDF export;
  `mailaccess[ml]` remains optional for spaCy-based name classification.
- Self-hosting, README, and doctor guidance now use the single-install flow.

### 0.14.1

- CRITICAL: `subdomain_intel` is hard-cancelled at 30% of the timing-profile budget.
- M365 passive intel runs before `WorkScheduler` starts, outside the discovery budget.
- Breach aggregator now records per-source telemetry and distinguishes empty, partial, failed, and skipped runs.
- IMAP persists both `imap_probe_count` and `imap_checked` for backwards compatibility.
- Email identity enrichment reports PARTIAL/FAILED when its sub-sources fail.

### 0.14.0

- Phase 1: M365 passive intelligence
  (GetUserRealm, IfExistsResult:5 fix, REST Autodiscover, OneDrive probe,
  OpenID preflight)
- Phase 2: Enterprise network intelligence
  (NTLM NetBIOS challenge, Lync/S4B discovery)
- Phase 3: M365 single-probe active intelligence
  (AADSTS error codes, ActiveSync probe, WS-Trust RST2 federated existence)
- Phase 4: IMAP single-probe existence check
- Phase 5: Breach aggregation
  (Scylla.so free, HIBP Pastes, Dehashed, Snusbase)
- Phase 6: Hunter.io full implementation
  (domain search with format inference, email verification, monthly usage
  tracking). The `hunter_io` module now verifies a single address against
  Hunter's email-verifier endpoint on the investigate path and surfaces the
  deliverability verdict + score; the domain-search harvest path maps
  Hunter's 0-100 confidence to `hunter_verified`/`hunter_high`/`hunter_low`
  source weights and feeds `data.pattern` into the format-inference pipeline.
  Free-tier usage is capped independently at 25 domain searches and 25
  verifications per calendar month via a persistent counter in
  `~/.mailaccess/hunter_usage.json` (`hunter_usage_tracking`,
  `hunter_domain_search_limit`, `hunter_verify_limit`); the counters warn at
  two remaining and reset on a month boundary. A 401 latches an
  invalid-key flag that skips all remaining Hunter calls.
- Dehashed auth fix: account login email separate from target email

### Unreleased

- New `enterprise_net_intel` module (Enterprise Network Intelligence — Phase 2):
  two unauthenticated, domain-level passive checks that extract internal
  infrastructure without any auth attempt or lockout risk.
  - NTLM NetBIOS challenge reader (`ntlm_challenge`): POSTs a standard Type-1
    NTLM negotiation to `autodiscover.{domain}` (OWA fallback) and parses the
    server's Type-2 challenge for NetBIOS domain/host, DNS domain/host, and the
    AD forest name.
  - Lync / Skype for Business discovery (`lync_discovery`): probes
    `lyncdiscover.{domain}` (HTTPS then HTTP) and classifies the UC deployment
    (onprem/hybrid/cloud) from the exposed pool FQDNs.
  Both run concurrently under a combined budget (`enterprise_net_intel_budget_seconds`,
  default 15s), gated by `enable_ntlm_challenge` / `enable_lync_discovery`, on
  every domain regardless of provider. Results surface in the JSON export under
  `infrastructure.active_directory` and `infrastructure.unified_communications`.
  Both source types carry weight `0.0` (infrastructure metadata, not email
  existence) in the `infrastructure` confidence family.

### 0.13.5

- SMTP probes now present a realistic per-probe sender derived from the
  target domain (`MAIL FROM: <verify-{uuid8}@{domain}>`, `EHLO mail.{domain}`)
  instead of the `probe@mailaccess.invalid` / `mailaccess-probe.invalid`
  identities that hardened MTAs reject at `MAIL FROM`. Configurable via
  `smtp_probe_domain_pattern` (`target`/`custom`) and `smtp_probe_custom_domain`.
- New `outlook_autodiscover` module: unauthenticated Microsoft Autodiscover v1
  existence probe (`autodiscover_m365`, weight 0.90). Runs first on M365
  domains (faster and unthrottled); `GetCredentialType` only handles addresses
  Autodiscover cannot confirm. Also probes consumer `@outlook.com` /
  `@hotmail.com` / `@live.com` / `@msn.com` addresses on the investigate path.
- SMTP `252` responses are now treated as catch-all hints, not confirmed
  existence (removed from `EXISTS_CODES`); multi-line replies require a proper
  terminating line before a code is treated as final.
- Yahoo verifier posts the full email address (not just the local part), so
  Yahoo-hosted custom domains are tested correctly.
- M365 verifier runs a random-address control probe first and marks the whole
  batch inconclusive when a tenant reports "exists" for everything.
- Confidence model: added `search_snippet_brave`, `pgp_cached`, and
  `npm/pypi/github_maintainer` weights; PGP, GitHub-commit, and
  provider-verified sources no longer decay with age; Common Crawl / search /
  Wayback variants collapse to one corroboration family each (a single page
  indexed by multiple crawlers no longer inflates the multi-source multiplier);
  removed three never-emitted dead booster keys.
- `user_scanner` now preserves per-platform `extras` (bio, display name,
  avatar, location, join date, follower count, website) under
  `metadata.profile_extras`; `pgp_keyserver` surfaces `key_created` and
  `key_age_days`.
- Replaced several silent failure paths with typed/logged outcomes:
  `mx_resolver` logs DNS failures and adds an RFC 5321 A-record implicit-MX
  fallback; `signal_pool` counts background-publish drops; `intelx_lookup`
  surfaces a `rate_limited` status; `platform_executor` logs transport errors.

### 0.13.4

- Passive subdomain sources now write status and result counts incrementally
  into shared harvest context, so soft-timeout and exception exports retain a
  complete `subdomain_intel.sources` table.
- Added explicit source lifecycle telemetry for completed, timed-out,
  rate-limited, killed, in-progress, and not-run sources while preserving the
  existing per-source caps and quorum behavior.
- Harvest status now distinguishes healthy budget saturation
  (`completed_saturated`) from guaranteed-work truncation
  (`partial_timeout`).
- Export sequencing and schema documentation now use the authoritative
  `summary.subdomains_total_including_derived` count.
- Provider verification telemetry separates candidates routed from Gravatar
  or other verifier contacts; Google MX verification remains Gravatar-only.
- M365 provider verification writeback remains sticky and is populated on the
  individual email records.

### 0.13.3

- `email_search_dork` promoted from `PRIORITY_SEARCH` (40) to
  `PRIORITY_HIGH_SIGNAL` (10) — now dispatched alongside `code_and_cert_email`
  and the GitHub modules instead of after 11 higher-priority seeds.
- Shodan + RIPE inline enrichment moved out of `subdomain_intel.run()` into the
  post-harvest tail — removes 30-140s from `subdomain_intel`'s 300s budget
  slice, restoring that time to email discovery modules.
- Net effect: `email_search_dork` gets budget time it was being starved of,
  approaching the v0.12.8 email yield.
- Provider verifier (Google Workspace / M365) now falls back to all on-domain
  candidates when the SMTP-eligible set is empty. PGP signers and other passive
  sources that don't carry `mx_valid` native evidence no longer starve the
  verifier of candidates. `_attach_smtp_email_verification` reaches the provider
  dispatch even when `_collect_smtp_findings` returns nothing.
- The fallback candidate collector gates at MEDIUM+ confidence (CONFIRMED /
  LIKELY / MEDIUM), so weak LOW-confidence guesses are not sent to live
  provider/SMTP probes. Domains with only a MEDIUM signal (e.g. 1 MEDIUM, 0
  LIKELY) now get their candidate verified instead of skipped.
- `provider_verification_provider` and `provider_verification_status` are now
  carried onto the aggregated email record in `_aggregate()` (a verified
  verdict is sticky), and the exporter surfaces them for the Google path — they
  were previously read only from M365 evidence and rendered blank for
  Google-verified emails.

### 0.13.2

- CRITICAL: Provider routing dispatch now wired — `GoogleWorkspaceVerifier`
  and `M365Verifier` are actually called on the primary harvest path (it had
  been short-circuiting to `skipped: provider_specific_verifier` since 0.13.0).
- Google Workspace verifier: SMTP RCPT TO fallback when the gxlu endpoint
  returns 204 (Google patched the endpoint). Gravatar is applied as a
  secondary signal on both the gxlu and SMTP paths.
- PGP graceful degradation: 24h result cache with a freshness penalty, one
  retry with 2s backoff per keyserver, and partial-response preservation on
  timeout (`PGP_CACHE_ENABLED`, `PGP_CACHE_TTL_HOURS`, `PGP_RETRY_ON_FAILURE`).
- `is_provider_verified` and `provider_verification_provider` now populate
  correctly on email records.
- M365 `GetCredentialType` results now surface in the primary harvest output
  (previously only reachable via `low_email_validation`).

### 0.13.1

- JSON export now includes CIDR prefixes in `infrastructure.asns[].prefixes`.
- Added Google Workspace provider-specific verification with Gravatar fallback.
- Verified Google Workspace permutations use `permutation_verified_google` (0.80).
- Added `GOOGLE_WORKSPACE_VERIFIER_ENABLED` for quickly disabling the verifier.

### 0.13.0

- RIPE Stat IP-to-ASN enrichment now produces provider names and announced
  CIDR prefixes in JSON, CLI infrastructure output, and `cidrs.txt`.
- ASN enrichment runs after IP discovery without reducing email discovery
  coverage.
- Final email validation and confidence promotion continue after the discovery
  budget is exhausted, restoring complete harvest output.
- SMTP provider routing and timeout reporting now preserve accurate candidate
  counts in live logs and exports.
- Fixed the Team Cymru origin lookup query and added regression coverage for
  ASN, CIDR, SMTP, and output-quality paths.

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
