# MailAccess Enhancement Roadmap — Phase Plan

> Status: **PLANNED** — not started yet.
> Each phase is independent. Pick and choose. Phases stack logically (do Phase 1 before Phase 2, etc.).

---

## PHASE 1 — False Positive Killers
**Goal:** Cut FP rate from ~30–40% to <5% on common-name usernames.
**Dependency:** None. Start here — biggest ROI for least code.
**Estimated total:** ~200–300 LOC across 4 sub-phases.

---

### Phase 1A — Maigret Detection Hardening
**File:** `backend/core/maigret_detector.py`

- [ ] **1A.1** — Cross-apply `absenceStrs` to `status_code` checks
  - In `detect_hit()`, after `status == 200` returns "hit", add a check against `defn.get("absenceStrs")` from Maigret data
  - If any absence marker found in body → return "miss" instead
  - Test with at least 3 known noisy platforms (e.g. sites that return 200 for any URL)

- [ ] **1A.2** — Add content-length sanity check for status_code hits
  - If `status == 200` and `len(body) < 500` → return "inconclusive" (not enough signal)
  - Make threshold configurable via new `min_response_bytes` field in platform schema

- [ ] **1A.3** — Add HTML entity decoding before pattern matching
  - Import `html` from stdlib
  - In `_detect_message()` and `detect_hit()`, decode body with `html.unescape()` before checking patterns
  - Handles `&#39;`, `&amp;`, `&lt;`, `&gt;`, `&quot;` etc.
  - Test: find a site that returns HTML-encoded failure strings in Maigret data

- [ ] **1A.4** — Add `expected_content_length_min` check
  - For `check_type: body_contains`, if response body is suspiciously short (e.g. < 200 chars), treat as inconclusive
  - Configurable via YAML field `min_content_length: <int>`

---

### Phase 1B — Common-Name FP Filter
**Files:** New file `backend/core/common_names.py`, `backend/core/maigret_platforms.py`, new data file `data/common_names.json`

- [ ] **1B.1** — Build common-names corpus
  - Curate `data/common_names.json` with top personal names from:
    - US SSA top baby names (public domain, all years)
    - US Census surnames (public domain)
    - Wikidata Q5 instances filtered to common first+last name pairs
    - ~10,000–50,000 entries total
  - Format: `{"names": ["john smith", "alex johnson", ...]}` as a set for O(1) lookup
  - Keep file under 2 MB

- [ ] **1B.2** — Build `backend/core/common_names.py`
  - Load corpus on module import with lazy loading (only when `_is_common_name()` first called)
  - `is_common_name(username: str) -> bool` — case-insensitive lookup
  - `is_common_username(username: str) -> bool` — checks if username matches a common name pattern (e.g. "johnsmith", "jsmith", "john.smith")

- [ ] **1B.3** — Integrate into maigret_platforms `_finding()`
  - In `_finding()` in `maigret_platforms.py`, check `is_common_username(variant)`
  - If common and no corroborating signals (avatar match, bio match, domain match) → downgrade to `low` confidence
  - Add `"fp_warning": "common_username_no_corroboration"` to metadata
  - Add `fp_warning` to the CLI output as a subtle indicator

---

### Phase 1C — Multi-Language Reset Signals
**Files:** `backend/core/reset_prober.py`, new `data/reset_signals.json`

- [ ] **1C.1** — Build `data/reset_signals.json`
  - Structure: `{"<lang_code>": {"success": [...], "failure": [...]}}`
  - Languages to cover: EN, RU, ES, FR, DE, PT, ZH, JA, KO, AR, NL, PL, TR, IT, HI
  - Each with 5–10 success and failure phrases
  - Sources: manually curated from known reset flows + Maigret data (absenseStrs/presenseStrs)
  - Document source for each phrase (which platform it was observed on)

- [ ] **1C.2** — Add language detection to `_classify_text()`
  - Import `langdetect` (Apache 2.0, MIT-compatible, no GPL conflict)
  - Detect language from response body (first 500 chars for speed)
  - Fall back to English if detection fails
  - Try signals for detected language first, then English as fallback

- [ ] **1C.3** — Probe all 9 endpoint patterns (not just first 3)
  - Change line 119 from `urls = [...] [:3]` to probe all 9
  - First decisive signal (success or failure) wins — cancel pending tasks
  - Add per-pattern timeout (3s each) so worst case is ~27s, not infinite

- [ ] **1C.4** — Add HTML entity decoding before classification
  - Add `html.unescape(response.text)` before `_classify_text()` call
  - Also decode URL-encoded forms (`%27`, `%20`, etc.)

---

### Phase 1D — Username Permutation Expansion
**Files:** `backend/core/maigret_platforms.py`

- [ ] **1D.1** — Rewrite `_username_variants()` with documented policy
  - Expand from 3 variants to ~25–40
  - Document each variant generation rule with a comment
  - Policy:
    - Original (local part as-is)
    - Dot-removed: `john.doe` → `johndoe`
    - Dot-normalized: `.` → `_`, `.` → `-`, `_` → `.`, `-` → `.`
    - Alphanumeric-only: strip all non-alphanumeric
    - Short combinations: first-initial + lastname, firstname + last-initial, etc.
    - Trailing numbers: `johndoe1`, `johndoe123`, `johndoe01`
    - Domain-aware: if email domain is `github.com`, generate `username` from local-part
    - Drop vowels: `johndoe` → `jnhdd` (less common but catches old accounts)
    - Case variants: rarely needed for username checks but some sites are case-sensitive
  - Return list with dedup (preserve order for determinism)
  - Add upper bound: skip variants < 3 chars or > 30 chars

- [ ] **1D.2** — Document variant coverage in README
  - Add section explaining permutation strategy
  - Show which variants are generated and why

---

## PHASE 2 — Reasoning Layer
**Goal:** Turn raw platform hits into intelligent identity conclusions.
**Dependency:** Phase 1 (especially 1D for variant coverage).
**Estimated total:** ~600–800 LOC across 5 sub-phases.

---

### Phase 2A — Avatar Perceptual Hashing
**Files:** New `backend/core/avatar_hasher.py`, new `backend/core/enrichment/avatar_clusters.py`, integrate into `backend/core/identity_graph.py`

- [ ] **2A.1** — Build `backend/core/avatar_hasher.py`
  - Add `imagehash` + `Pillow` to `pyproject.toml` dependencies
  - `async def fetch_and_phash(avatar_url: str, client: httpx.AsyncClient) -> str | None`
  - Download image, verify it's actually an image (check Content-Type header + PIL can open it)
  - Convert to grayscale, resize to 8×8 for pHash
  - Return hex string of pHash
  - Handle failures gracefully (bad URL, non-image, timeout → None)
  - Add rate limiting: max 20 avatar fetches per domain per run

- [ ] **2A.2** — Build `backend/core/enrichment/avatar_clusters.py`
  - `class AvatarClusterer` — takes list of `(platform, avatar_url)` pairs
  - Groups by Hamming distance ≤ 5 (pHash)
  - Returns clusters: `list[dict(platforms: list, phash: str, cluster_size: int)]`
  - Large clusters (≥ 3 platforms, same pHash) → high-confidence identity signal
  - Cache phashes per URL (in-memory, per-investigation) to avoid re-fetching

- [ ] **2A.3** — Integrate into identity graph
  - In `IdentityGraph.build()`, after building nodes, run `AvatarClusterer`
  - Add new edge type `same_avatar` for platforms sharing a pHash cluster
  - Update `cluster_confidence()` to boost clusters with `same_avatar` edges

- [ ] **2A.4** — Add avatar clustering metadata to findings export
  - In JSON export, add `"avatar_cluster": {"size": 3, "platforms": [...]}` to corroborating findings
  - In CLI summary, show "Avatar confirmed on N platforms" when cluster size ≥ 3

---

### Phase 2B — Bio Text Fuzzy Matching
**Files:** New `backend/core/bio_similarity.py`, new `backend/core/enrichment/bio_clusters.py`, integrate into `backend/core/identity_graph.py`

- [ ] **2B.1** — Build `backend/core/bio_similarity.py`
  - Add `rapidfuzz` to `pyproject.toml` dependencies (MIT, no GPL conflict)
  - `def bio_similarity(text_a: str, text_b: str) -> float` — returns 0.0–100.0
  - Use `rapidfuzz.fuzz.token_set_ratio` (handles word reordering well)
  - Threshold: ≥ 85 = "same person", 70–84 = "possible match", < 70 = different

- [ ] **2B.2** — Build `backend/core/enrichment/bio_clusters.py`
  - `class BioClusterer` — collects all bio texts from platform findings
  - Runs all-pairs comparison (use `rapidfuzz.cdist` for speed on large sets)
  - Clusters by similarity ≥ 85 threshold
  - Returns clusters: `list[dict(platforms: list, similarity_score: float, bio_excerpt: str)]`

- [ ] **2B.3** — Integrate into identity graph
  - Add `same_bio` edge type
  - Update `cluster_confidence()` to boost when same_bio edges present
  - If bio contains identifiable PII (phone, email not in target), extract and add as separate findings

- [ ] **2B.4** — Add bio link extraction cross-check
  - Use existing `bio_link_extractor.py` findings
  - If multiple platforms have links to the same external URL → strong identity signal
  - Integrate into `BioClusterer` as a secondary similarity signal (link overlap)

---

### Phase 2C — Name Consensus Fuzzy + Temporal
**Files:** `backend/core/name_consensus.py`, new `data/common_names.json` (already in Phase 1B)

- [ ] **2C.1** — Unicode-safe canonicalization
  - In `normalize_name()`: use `unicodedata.normalize('NFKC')` for transliteration-aware normalization
  - In `canonical_name()`: strip diacritics with `unidecode` (MIT) so "François" and "Francois" share a canonical form
  - Add `unidecode` to dependencies
  - Test: verify "Müller" and "Muller" cluster together

- [ ] **2C.2** — Replace strict equality with rapidfuzz in `_cluster()`
  - In `_cluster()`, when checking `same = canonical_name(candidate) == canonical_name(str(cluster["name"]))`
  - Replace with: `rapidfuzz.fuzz.ratio(canonical_name(candidate), canonical_name(str(cluster["name"]))) >= 88`
  - This catches "John Smith" vs "John  Smith" (double space) vs "John S. Smith"

- [ ] **2C.3** — Add temporal decay to scoring
  - Extend `NameCandidate` with `seen_at: datetime | None` field
  - In `extract_name_candidates()`: populate `seen_at` from finding metadata if available
  - Add recency factor: `decay = exp(-days_since_seen / (365 * 3))` (3-year half-life)
  - Score contribution = `base_weight × quality_multiplier × decay`
  - Default to current time if `seen_at` not available (for findings without timestamps)

- [ ] **2C.4** — Add common-name corpus penalty
  - Use `backend/core/common_names.py` (Phase 1B)
  - If normalized name is in top-1000 common names → multiply score by 0.4
  - If single-word name and in top-100 common → multiply by 0.2
  - This prevents "John" from inflating name consensus

- [ ] **2C.5** — Add non-Western name support
  - In `PERSON_RE`: replace hard regex with Unicode-aware tokenizer
  - Token: 1–4 alpha sequences, first letter uppercase, rest lowercase
  - Chinese: `normalize()` already handles via NFKC; add explicit test
  - Cyrillic: test "Иван Петров", "Иванов Иван"
  - Arabic: test "محمد علي"
  - Add test cases for each script

---

### Phase 2D — Persistent Platform Health
**Files:** New `backend/core/platform_health.py`, new `backend/core/enrichment/platform_health_enricher.py`

- [ ] **2D.1** — Build `backend/core/platform_health.py`
  - SQLite database at `~/.mailaccess/platform_health.db`
  - Schema: `probe_log(id, platform, domain, outcome, latency_ms, content_length, probed_at)`
  - Key methods:
    - `record_probe(platform, domain, outcome, latency_ms, content_length)` — log every probe
    - `get_hit_rate(platform, window_days=30) -> float` — rolling 30-day hit rate
    - `get_consecutive_misses(platform) -> int` — for skip decision
    - `should_probe(platform) -> bool` — returns False if recent_consecutive_misses ≥ 10
    - `get_fragility_score(platform) -> float 0.0–1.0` — derived from error rate + latency variance
  - Auto-migrate schema on startup

- [ ] **2D.2** — Wire platform health into maigret_platforms
  - Before probing, call `should_probe(platform)` — skip if returns False
  - After each probe, call `record_probe()`
  - Use fragility score in `_wave()` to adjust wave assignment dynamically
  - Add `ENABLE_PLATFORM_HEALTH=false` to disable (for CI/testing)

- [ ] **2D.3** — Wire platform health into reset_prober
  - Track probe outcomes per domain in reset_prober
  - If a domain consistently returns inconclusive, increase delay
  - If a domain has ≥ 10 consecutive misses, skip it in `probe()`

- [ ] **2D.4** — Add `mailaccess platform-health` CLI command
  - `mailaccess platform-health` — show top 20 noisiest platforms (highest inconclusive rate)
  - `mailaccess platform-health --export noise-report.json` — export all platforms with stats
  - `mailaccess platform-health --clear <platform>` — reset health data for a platform

---

### Phase 2E — Creation-Date Clustering + Shadow Profiles
**Files:** New `backend/core/enrichment/temporal_cluster.py`, new `backend/core/enrichment/shadow_profiles.py`

- [ ] **2E.1** — Build `backend/core/enrichment/temporal_cluster.py`
  - Collect `created_at`, `join_date`, `registered`, `registered_at`, `account_created` from all finding metadata
  - Cluster platforms by account creation date: if ≥ 5 accounts created within 60 days of each other → "coordinated signup" signal
  - Score: `cluster_size × time_window_inverse × corroboration_factor`
  - Add as identity graph signal: `same_signup_window` edge type

- [ ] **2E.2** — Build `backend/core/enrichment/shadow_profiles.py`
  - After `permutation_discovery` and `email_discovery` complete
  - Look for: same display name + same city/location + different recovered email → potential shadow profile
  - This catches alt accounts: person creates a throwaway with same name
  - Add as finding type: `"shadow_profile": {"primary_email": "...", "shadow_email": "...", "confidence": "high"}`

---

## PHASE 3 — Free Platform Expansion
**Goal:** Bring total unique platform coverage to 4000–5500.
**Dependency:** None (independent of Phases 1–2).
**Estimated total:** ~500–700 LOC + integration work.

---

### Phase 3A — Sherlock Integration
**Files:** New `backend/modules/sherlock.py`, new `tests/test_sherlock.py`

- [ ] **3A.1** — Add `sherlock-project` to dependencies
  - Add to `pyproject.toml`: `sherlock-project>=0.15`
  - Or wrap via subprocess if library API is unstable

- [ ] **3A.2** — Build `backend/modules/sherlock.py`
  - Follow pattern of `whatsmyname.py` / `user_scanner.py`
  - `SherlockModule(BaseModule)` — runs `sherlock` for each username variant
  - Parse results: `site`, `url_user`, `exists`
  - Normalize findings to match MailAccess schema
  - Add to `MODULE_WEIGHT_MAP` in engine as social weight

- [ ] **3A.3** — Handle Sherlock-specific issues
  - Rate limiting: Sherlock has its own internal delay; respect it
  - Timeout: Sherlock can hang on some sites → enforce 5min max
  - Duplicate with Maigret: use dedup_key() to merge Sherlock hits with existing findings

---

### Phase 3B — Blackbird Integration
**Files:** New `backend/modules/blackbird.py`

- [ ] **3B.1** — Add `blackbird` to dependencies
  - Check if pip package exists; wrap if needed

- [ ] **3B.2** — Build `backend/modules/blackbird.py`
  - ~500 platforms, mostly Discord-adjacent and gaming sites
  - Integrate with dedup_key to avoid double-counting with Maigret/WMN

---

### Phase 3C — Snoop + Nexfil Integration
**Files:** New `backend/modules/snoop.py`, new `backend/modules/nexfil.py`

- [ ] **3C.1** — Snoop integration
  - snoop uses a similar data.json format to Maigret — possible to reuse `maigret_loader`
  - Clone snoop's data.json, filter, merge into MailAccess platform DB
  - Or wrap as module if library API available

- [ ] **3C.2** — Nexfil integration
  - ~350 platforms, focuses on short-form/social platforms
  - Wrap as module following same pattern

---

### Phase 3D — PhoneInfoga Integration
**Files:** New `backend/modules/phoneinfoga.py`

- [ ] **3D.1** — Install PhoneInfoga
  - Go binary; download and cache at first run
  - Check: `which phoneinfoga` or download to `~/.mailaccess/bin/phoneinfoga`

- [ ] **3D.2** — Build `backend/modules/phoneinfoga.py`
  - If phone number found by `phone_intel`, pipe to PhoneInfoga
  - Extract: carrier, location, number type, formats, common platform associations
  - Add as enrichment pass (not primary module)

---

### Phase 3E — IntelligenceX Phonebook (Free Tier)
**Files:** New `backend/modules/intelx_phonebook.py`

- [ ] **3E.1** — Build `backend/modules/intelx_phonebook.py`
  - API: `POST https://free.intelx.io/phonebook/search` → `{term: domain, target: 0, maxresults: 200}`
  - Then: `GET https://free.intelx.io/phonebook/search/result?id={id}&l=200`
  - Returns: email addresses, phone numbers, URLs associated with domain
  - Free: 50 searches/day, no CC required
  - Add to `_SOCIAL_MODULES` as enrichment (doesn't directly hit the target email)

---

### Phase 3F — GitHub Code + Gist Search
**Files:** New `backend/modules/github_code_search.py`

- [ ] **3F.1** — Build `backend/modules/github_code_search.py`
  - Search query: `'{email}' in:file` across public repos
  - Requires `GITHUB_TOKEN` (already in module list as optional)
  - Returns: repo name, file path, line snippet, last modified
  - Extract: other emails in same file (potential associates), usernames, org names
  - Add as enrichment pass — doesn't confirm account existence, enriches context

---

### Phase 3G — Pastebin Search (psbdmp.ws)
**Files:** New `backend/modules/pastebin_search.py`

- [ ] **3G.1** — Build `backend/modules/pastebin_search.py`
  - `GET https://psbdmp.ws/api/search/{email}`
  - Returns: paste ID, title, tags, size, date
  - Add as breach-adjacent signal — paste exposure ≠ breach but relevant
  - No API key required

---

### Phase 3H — theHarvester Integration
**Files:** New `backend/modules/harvester.py`

- [ ] **3H.1** — Build `backend/modules/harvester.py`
  - theHarvester: `mailaccess investigate email@domain.com` style calls
  - Sources: Google, Bing, Baidu, Yandex, Dogpile, etc.
  - Returns: emails, hosts, virtual hosts, banners, operative systems
  - Run for email domain, extract emails + hosts
  - Useful for: mapping organization's external exposure

---

### Phase 3I — Mastodon/Fediverse Discovery
**Files:** New `backend/modules/fediverse_discovery.py`, new `data/fediverse_instances.json`

- [ ] **3I.1** — Curate `data/fediverse_instances.json`
  - List of 100+ public Mastodon/Pleroma/Firefish instances with open registration
  - Each entry: `{instance: "mastodon.social", lookup_url: "https://mastodon.social/api/v1/accounts/lookup?acct={username}"}`
  - Source: instances.social public API (no key)

- [ ] **3I.2** — Build `backend/modules/fediverse_discovery.py`
  - For each username variant, query each instance's lookup API
  - Returns: display name, bio, followers, following, profile URL
  - Integrate as social module (high confidence on hits)

---

## PHASE 4 — Code Refinement
**Goal:** Make the codebase maintainable for a growing team.
**Dependency:** None (can run in parallel with Phases 2–3).
**Estimated total:** ~600–800 LOC refactor.

---

### Phase 4A — Engine Phase Decomposition
**Files:** `backend/core/engine.py`, new `backend/core/phases.py`

- [ ] **4A.1** — Extract `_run_and_persist` into `backend/core/phases.py`
  - Create abstract `class InvestigationPhase(ABC)`:
    - `name: str`
    - `run(investigation_id, email, collected) -> tuple[dict[str, ModuleResult], list[QueueEvent]]`
    - `dependencies: list[str]` (other phase names this depends on)
  - Implement concrete phases:
    - `PrimaryPhase` — runs all enabled modules concurrently
    - `PivotPhase` — runs username_pivot (depends on: PrimaryPhase)
    - `PermutationPhase` — runs permutation_discovery (depends on: PrimaryPhase)
    - `EmailDiscoveryPhase` — runs email_discovery (depends on: PrimaryPhase)
    - `AlternateEmailPhase` — runs alternate_email (depends on: PrimaryPhase)
    - `ProfilePhase` — runs Twitter, LinkedIn, Marketplace (depends on: PrimaryPhase)
    - `PhonePhase` — runs phone_intel + messaging_hints (depends on: PrimaryPhase)
    - `EnrichmentPhase` — runs avatar phash, bio clustering (depends on: ProfilePhase, PhonePhase)
  - `PHASE_DAG: list[InvestigationPhase]` — ordered list executed sequentially

- [ ] **4A.2** — Replace per-phase try/except with helper
  - `async def _run_module(mod, email, collected, timeout) -> ModuleResult`
  - All 8 phase blocks become: `result = await _run_module(cls(), email, collected)`

- [ ] **4A.3** — Move policy constants to `backend/core/policy.py`
  - `_POST_PRIMARY_ONLY`, `_OPT_IN_MAP`, `_MODULE_DEFAULT_TIMEOUTS`, `_MODULE_TIMEOUT_FLOORS`, `_MODULE_WEIGHT_OVERRIDES`, `_CONFIDENCE_MULTIPLIER`, `_MODULE_CAP`, `_WEIGHT_*`
  - Import from `policy` in `engine.py` and `credential_risk.py`

- [ ] **4A.4** — Replace `patch.multiple` hack with proper settings override
  - Create `backend/config.py`: `class InvestigationSettings(Settings)` with a `with_overrides(**kwargs)` method that returns a context manager
  - Remove all `unittest.mock` imports from production code

---

### Phase 4B — Platform Schema Extension
**Files:** `backend/platforms/schema.py`, `backend/core/platform_executor.py`

- [ ] **4B.1** — Add `multi_step` support to `PlatformCheck`
  - New field: `multi_step: list[dict]` where each step has `{url, method, headers, body, extract_fields: list[str]}`
  - `_check_multi_step()` in executor: run each step sequentially, inject extracted fields into context for next step
  - Eliminates `_check_github()` special case

- [ ] **4B.2** — Add `absence_strings` to `PlatformCheck` schema
  - New field: `absence_strings: list[str] | None = None`
  - Used even for `check_type: status_code` (Phase 1A integration point)
  - Document in `TEMPLATE.yaml`

- [ ] **4B.3** — Add `presence_threshold` for body_contains
  - New field: `presence_threshold: float = 1.0` (1.0 = all markers required, 0.5 = any half required, 0.0 = any)
  - Update `_evaluate_success()` to consult this field

- [ ] **4B.4** — Rotate default headers in executor
  - Import `random` from stdlib and `proxy._UA_POOL`
  - Default to `random.choice(_UA_POOL)` instead of hardcoded Windows UA
  - Allow per-platform override via `headers` field in YAML

- [ ] **4B.5** — Add `expected_content_length_min` to schema
  - New field: `min_content_length: int | None = None`
  - In executor: after success check, verify content length
  - Update `TEMPLATE.yaml` with documentation

---

### Phase 4C — Dedup Hardening
**Files:** `backend/core/platform_dedup.py`

- [ ] **4C.1** — Expand subdomain prefix stripping
  - Define `KNOWN_SUBDOMAIN_PREFIXES = {"www", "api", "m", "cdn", "static", "account", "secure", "login", "app", "blog", "community", "help", "support", "store", "shop", "forum", "dev", "stage", "test", "admin", "status"}`
  - In `dedup_key()`: strip any prefix from this set + trailing dot from host before comparing
  - Add test cases for: `m.example.com`, `account.example.com`, `secure.example.com`

- [ ] **4C.2** — Normalize source tag independently from module name
  - In `dedup.py`: when reading findings, call `_normalize_source(finding)` helper
  - `_normalize_source()`: look at `finding.get("metadata", {}).get("source")` first, fall back to module name mapping
  - Add: WMN findings from within `username_pivot` → tag as "wmn", not "username_pivot"
  - Add test: simulate WMN finding inside username_pivot module → verify merges correctly

- [ ] **4C.3** — Add debug output for dedup decisions
  - In `dedupe_key()`: if same domain has > 2 sources, log a warning with sources list
  - This helps spot unexpected source fragmentation

---

### Phase 4D — Bio Aggregator Expansion
**Files:** `backend/core/bio_analyzer.py`

- [ ] **4D.1** — Expand `_AGGREGATOR_DOMAINS` to cover all major aggregators
  - Add: `taplink`, `snipfeed`, `hey.link`, `withkoji`, `stan.store`, `flow.page`, `solo.to`, `carrd.co`, `linkpop.com`, `milkshake.website`, `lnk.bio`, `itsmy.asia`, `hypage.com`, `shorby.com`, `pencilmein.com`, `direct.me`, `cllck.app`, `bio.site`, `linkboss.com`, `tapbio.com`
  - Update `_AGGREGATOR_DOMAINS` set

---

### Phase 4E — Credential Risk Hardening
**Files:** `backend/core/credential_risk.py`, new `data/service_categories.yaml`

- [ ] **4E.1** — Replace substring matching with token matching
  - In `_categorize_service()`: instead of `if token in haystack`, parse URL host into tokens: `host.split(".")`
  - Match on full token: `"stripe"` in `["stripe", "com"]` = match; `"stripe"` not in `["stripy", "com"]` = no match
  - Fixes false matches like `stripey.com`

- [ ] **4E.2** — Move service category tuples to YAML
  - Create `data/service_categories.yaml` with categories, service names, URL patterns
  - Load at module init with `@lru_cache`
  - Replace hardcoded tuples with YAML-loaded dicts

- [ ] **4E.3** — Add score calibration
  - In `_assess()`: `calibrated_score = raw_score × (1 - exp(-breach_count / 5))`
  - Prevents single-breach email from hitting max score

---

### Phase 4F — Breach Normalizer Polish
**Files:** `backend/core/breach_normalizer.py`

- [ ] **4F.1** — Add whitespace check in `_extract_host()`
  - If input has whitespace in a position that suggests it's not a host, return None
  - Add: `if " " in text: return None` at start

- [ ] **4F.2** — Add max iteration cap to `_strip_noise()`
  - Add `max_iterations=3` parameter
  - Prevents infinite loop on malformed inputs

- [ ] **4F.3** — Warn when alias catalog is missing
  - In `resolve_breach_identity()`: if `_ALIAS_PATH` doesn't exist, log a warning
  - Add `warnings.warn()` so analysts know when normalization is degraded

---

## PHASE 5 — Dev Workflow & Testing
**Goal:** Ship CI, coverage gates, and test backfill.
**Dependency:** None (can run parallel to all phases).
**Estimated total:** ~400 LOC + CI setup.

---

### Phase 5A — GitHub Actions CI
**Files:** New `.github/workflows/ci.yml`, `.github/workflows/coverage.yml`

- [ ] **5A.1** — Build `.github/workflows/ci.yml`
  - Trigger: push + PR to main
  - Steps: install Python 3.11+, `pip install -e .[dev]`, run `ruff check`, run `ruff format --check`, run `mypy`, run `pytest -v`
  - Cache: pip, ruff cache
  - Python version matrix: 3.10, 3.11, 3.12

- [ ] **5A.2** — Build `.github/workflows/coverage.yml`
  - Run `pytest --cov=backend --cov-report=term-missing --cov-fail-under=70`
  - Upload to Codecov or coveralls
  - Comment on PR with coverage delta

---

### Phase 5B — Pre-Commit Hooks
**Files:** New `.pre-commit-config.yaml`

- [ ] **5B.1** — Build `.pre-commit-config.yaml`
  - Hooks: `ruff-format`, `ruff`, `mypy`, `detect-secrets` (pre-commit hooks)
  - Exclude: `results/`, `data/cache/`, `node_modules/`, `.venv/`

---

### Phase 5C — Test Backfill (13 gaps)
**Files:** `tests/` — new files for each gap

- [ ] **5C.1** — `tests/test_platform_executor.py`
  - Test each `check_type`: status, body_contains, body_not_contains, json_field
  - Test: `_check_github` with mock httpx responses
  - Test: `_check_duolingo` with mock user data
  - Test: `_check_adobe` with empty list response
  - Test: rate-limited slug handling (spotify, linkedin, patreon)

- [ ] **5C.2** — `tests/test_maigret_detector.py`
  - Test `detect_hit()` matrix: all combinations of status code (200, 404, 403, 429, 503) × check_type (status_code, message, tags, response_url)
  - Test `username_matches_regex()` with various patterns
  - Test `prepare_platform_defn()` for Discourse engine
  - Test `substitute_username()` with nested dicts/lists

- [ ] **5C.3** — `tests/test_platform_dedup.py`
  - Test `dedup_key()` with: `https://example.com`, `https://www.example.com`, `https://m.example.com`, `https://api.example.com`
  - Test: WMN + Maigret finding for same domain → dual_confirmed
  - Test: three sources (WMN, Maigret, username_pivot) for same domain
  - Test: `_finding_sources()` normalization

- [ ] **5C.4** — `tests/test_identity_graph.py`
  - Test: basic build with 3 findings
  - Test: shared username across 3 platforms → one cluster
  - Test: `cluster_confidence()` matrix: no corroboration, username-only, with avatar, with bio
  - Test: `to_d3()` format
  - Test: `to_neo4j_cypher()` output

- [ ] **5C.5** — `tests/test_breach_normalizer.py`
  - Expand existing: test with multiple sources for same breach
  - Test: breach alias canonicalization
  - Test: `is_breach_finding()` for non-breach findings
  - Test: `_strip_noise()` with year suffixes and generic suffixes
  - Test: `_extract_host()` with various input formats

- [ ] **5C.6** — `tests/test_reset_prober.py`
  - Mock httpx responses for each combination: success signal, failure signal, inconclusive, blocked
  - Test: HTML entity decoding in classification
  - Test: first 3 patterns vs all 9 patterns behavior
  - Test: task cancellation on first decisive result

- [ ] **5C.7** — `tests/test_rate_limiter.py`
  - Test: concurrent acquire() for same domain — only one proceeds at a time
  - Test: different domains don't block each other
  - Test: rate limit disabled bypasses all locks
  - Test: per-domain override wins over global default

- [ ] **5C.8** — `tests/test_breach_corpus.py`
  - Test: `_severity_score()` calculation
  - Test: `_severity_label()` thresholds
  - Test: `_site_from_hibp()` with various HIBP API response shapes
  - Test: cache write/read cycle

- [ ] **5C.9** — `tests/test_breach_deep.py`
  - Mock `executor.check()` for YAML-path sites
  - Mock `reset_probe()` for generic reset path
  - Test: findings sorted by severity score descending
  - Test: inconclusive + error states

- [ ] **5C.10** — `tests/test_proxy.py`
  - Test: `random_ua()` returns from pool
  - Test: valid scheme validation (socks5, http, https = ok; ftp = raise)
  - Test: Tor detection

- [ ] **5C.11** — `tests/test_aggregator.py`
  - Test: summary counts (success, partial, failed, skipped)
  - Test: all_findings with mixed module results
  - Test: result dict is properly copied

- [ ] **5C.12** — `tests/test_bio_analyzer.py`
  - Test: phone regex with international formats
  - Test: phone regex with version numbers (should not match)
  - Test: email extraction from bio
  - Test: URL extraction
  - Test: aggregator domain detection
  - Test: dedup of findings

- [ ] **5C.13** — `tests/test_name_consensus.py`
  - Expand existing: test with fuzzy matching (rapidfuzz integration)
  - Test: non-Western names (Chinese, Cyrillic, Arabic)
  - Test: temporal decay with `seen_at` field
  - Test: common-name penalty
  - Test: bot/org detection

---

### Phase 5D — Documentation
**Files:** `docs/`, `CONTRIBUTING.md`

- [ ] **5D.1** — Write `docs/fp-control.md`
  - Document all FP-reduction strategies (cross-referencing Phase 1 work)
  - Explain: why certain platforms are noisy, how to interpret `fp_warning`
  - For analysts who want to understand confidence scores

- [ ] **5D.2** — Update `CONTRIBUTING.md`
  - Add section: "Adding a reasoning module (enrichment pass)"
  - Add section: "Testing guidelines" (pytest patterns, httpx mocking)
  - Update PR checklist with new requirements

- [ ] **5D.3** — Update `README.md` platform count
  - After Phase 3: update from 2500+ to actual number

---

## PHASE 6 — Long-Term
**Goal:** Build the feedback loop that makes the tool get smarter over time.
**Dependency:** Phase 2D (platform health), Phase 5A (CI).
**Estimated total:** Open-ended.

---

### Phase 6A — TF-IDF Display Name Consensus
**Files:** New `backend/core/enrichment/name_tfidf.py`

- [ ] **6A.1** — Build `backend/core/enrichment/name_tfidf.py`
  - Add `scikit-learn` to dependencies (BSD, no conflict)
  - Build TF-IDF vectorizer over all display names
  - Compute cosine similarity matrix across all display names
  - Cluster by similarity ≥ 0.85
  - This catches: "Software Engineer at Acme" vs "Senior Software Engineer" (different titles, same person)

---

### Phase 6B — Domain Clustering + Shadow Profiles
**Files:** New `backend/core/enrichment/domain_cluster.py`

- [ ] **6B.1** — Domain clustering
  - Group platforms by: same registrar, same hosting provider, same WHOIS organization
  - Use `whois_lookup` + `dns_lookup` findings
  - If ≥ 3 platforms share infrastructure → link them in identity graph

- [ ] **6B.2** — Shadow profile detection
  - After email_discovery runs, look for same display name + different email
  - Add as finding type: `"shadow_profile"`

---

### Phase 6C — Platform Audit CLI
**Files:** New `backend/cli/platform_audit.py`, integrate into `cli/main.py`

- [ ] **6C.1** — Build `mailaccess platform-audit` command
  - Reads `~/.mailaccess/platform_health.db`
  - Ranks all platforms by: noise rate (inconclusive / total probes)
  - Shows: platform, total probes, hit rate, inconclusive rate, avg latency, last probed
  - Flags: "recommend skip" for platforms with > 70% inconclusive rate over 100+ probes
  - `mailaccess platform-audit --export audit.json`

---

### Phase 6D — Self-Healing Platform DB
**Files:** `backend/core/maigret_loader.py`, `backend/core/platform_health.py`

- [ ] **6D.1** — Auto-demotion based on health data
  - If platform has < 10% hit rate AND > 50 probes AND > 60% inconclusive → auto-skip in future runs
  - Log demotion event with reason
  - User can override with `MAIGRET_FORCE_<platform>=true`

- [ ] **6D.2** — Auto-upgrade based on health data
  - If platform had 0 inconclusive for 30 days and hit rate > 20% → promote from Wave 2 to Wave 1
  - Log promotion event

- [ ] **6D.3** — Community platform health sharing (opt-in)
  - On opt-in, anonymized platform health stats are submitted to a public JSON endpoint (e.g. a GitHub Gist you maintain)
  - Aggregate across all MailAccess users → more accurate platform health data
  - `mailaccess platform-health --share` (off by default)

---

## EXECUTION ORDER GUIDE

```
START HERE
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  PHASE 1 (FP Killers) — 4 sub-phases, ~300 LOC        │
│  Highest ROI. No dependencies. Do first.                │
│  1A → 1B → 1C → 1D  (can parallelize within phase)   │
└─────────────────────────────────────────────────────────┘
    │
    ├────────────────────────────────────────────────────┐
    │                                                    │
    ▼                                                    ▼
┌──────────────────────┐                   ┌──────────────────────────────┐
│  PHASE 5 (Dev)       │                   │  PHASE 4 (Refinement)       │
│  Can run in parallel │                   │  Can run in parallel         │
│  to any phase.       │                   │  to Phases 2–3.              │
│  Start early so CI   │                   │  4A last (after Phase 2D     │
│  catches issues.      │                   │  for best context).          │
└──────────────────────┘                   └──────────────────────────────┘
    │                                                    │
    └────────────────────────────────────────────────────┘
                        │
                        ▼
              ┌─────────────────────────────┐
              │  PHASE 2 (Reasoning Layer)  │
              │  5 sub-phases, ~700 LOC     │
              │  Depends on Phase 1          │
              │  (especially 1D for variants)│
              │  2A → 2B → 2C → 2D → 2E   │
              └─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  PHASE 3 (Free Expansion) — 9 sub-phases, ~600 LOC    │
│  Independent of Phases 1–2. Can run in parallel.       │
│  Prioritize: 3F (GitHub Code) > 3G (Pastebin) >       │
│  3I (Fediverse) > 3A (Sherlock) > 3E (IntelX)        │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
              ┌─────────────────────────────┐
              │  PHASE 6 (Long-Term)        │
              │  Open-ended. Depends on      │
              │  Phase 2D + Phase 5A.       │
              │  6C first (tooling),        │
              │  then 6A, 6B, 6D.           │
              └─────────────────────────────┘
```

---

## QUICK-START: If you only do 5 things

If bandwidth is limited, do these in order:

1. **Phase 1A** (maigret absence_strings) — ~30 LOC, biggest FP reduction
2. **Phase 1B** (common-name filter) — ~100 LOC, prevents noisy username hits
3. **Phase 1C** (multi-language resets) — ~100 LOC, non-English sites currently invisible
4. **Phase 2D** (platform health) — ~300 LOC, persistent improvement over time
5. **Phase 3F** (GitHub code search) — ~120 LOC, new data source, zero platform cost

These 5 get you 80% of the benefit with ~650 LOC total.
