# Phase 5D — Technographic filtering

The last headline paid-tool filter (Doc-2 C3): "companies on Google Workspace /
HubSpot / Shopify". 5D tags each domain with its tech stack — mail provider, CMS,
analytics/marketing, e-commerce, JS framework — computed **entirely from bytes
MailAccess already downloaded**, and exposes those tags as a filter/export
dimension. No new network requests are introduced.

## What shipped

- **`backend/core/technographics.py`** — a pure detector: `detect_from_html`
  (regex/substring fingerprints over already-fetched markup, no DOM parser),
  `detect(html, mail_provider)` → `Technographics`, `matches_filters` (the
  `dimension=value` AND-filter), `flat_tags`.
- **`ConcurrentFetchCache.peek(url)`** — a cache-ONLY accessor: a hit returns the
  stored response, a miss returns `None` and never fetches. This is the strict
  "no new request" guarantee for reading the homepage bytes.
- **Harvest integration** (`harvest_runner._compute_technographics`) — at
  aggregation, tags are computed from the homepage HTML already in the shared
  fetch cache (via `peek`) + the mail provider the harvest already resolved from
  MX (`ctx.provider_detection`). Attached to `DomainHarvestResult.metadata
  ["technographics"]` on both the normal and partial-timeout paths, guarded, and
  skipped for injected-module test paths.
- **Export dimension** — `format_harvest_json_export` surfaces `technographics`
  at the top level of the per-domain JSON export.
- **Bulk filter** — `harvest-emails --file … --tech cms=shopify --tech
  mail_provider=google` (repeatable, ANDed). The bulk merged export carries each
  domain's `technographics` + a `tech_match` flag, and the merged `contacts` lead
  list is restricted to domains matching all filters (per-domain sections are
  always retained for audit; `stats.domains_matching_tech_filter` reports the
  count).

## Design decisions (exploration latitude)

- **Zero new I/O — from cached bytes only.** Mail provider reuses the MX already
  resolved during the deliverability pass (no new DNS); HTML tags read the
  homepage `ContextRouter` already fetched, via the cache-only `peek` (no new
  HTTP). If neither is available the tags are simply absent.
- **Ruleset + taxonomy.** Five dimensions (`mail_provider`, `cms`, `analytics`,
  `ecommerce`, `framework`), each an ordered list of `(tag, regex)` rules — a page
  can carry several tags. Rules favour *specific* signals (asset URLs, plugin
  paths, generator meta, client-hint tokens) over bare brand words to avoid
  false positives — e.g. `woocommerce` requires a plugin path / WC class, not a
  marketing mention (a real bug caught on stripe.com during validation).
- **Filter semantics.** `dimension=value`, case-insensitive, ANDed; an empty
  filter matches everything; a domain with no technographics fails any non-empty
  filter. Applied to the bulk lead list, so a segment can be narrowed to a stack
  ("Shopify shops on Google Workspace") after harvesting.
- **Where it applies.** Harvested domains (which fetched pages) — discovery (5C)
  has only search snippets, no HTML, so it carries no technographics (staying
  within "no new fetching").

## Validation (done-when)

- **Unit** — `tests/test_technographics.py` (10 tests): stack detection (CMS /
  analytics / ecommerce / framework); bytes + empty input; mail-provider
  normalization; flat tags; filter AND-semantics / case-insensitivity / dict
  input / None; the cache-only `peek` (hit vs miss, no session); and the bulk
  merged-export tech carry + filter (matching domain's contacts only,
  `tech_match` flags, stats).
- **Real, keyless** — a live harvest tags the baseline domains accurately from
  cached bytes and introduces no new fetches: `stripe.com` →
  `mail_provider=google, framework=nextjs`; `rootaccess.tech` →
  `mail_provider=shared_hosting, framework=nextjs`. (The initial `woocommerce`
  false positive on stripe was fixed by tightening the rule.)
- **Gate** — `python -m eval.harness.gate check` green (0 new test/lint/hang
  failures vs baseline).

## Non-scope

No new fetching for fingerprints (cache-only + already-resolved MX). No paid
technographic feeds. Deeper page-body fingerprinting beyond the homepage bytes
already in hand is left for a later iteration.
