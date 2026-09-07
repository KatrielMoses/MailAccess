# Phase 5C — Company discovery pipeline

A new top-of-funnel entry point (Doc-1 #17, Doc-2 C1). Marketers start from a
*segment*, not a domain. `discover --industry --geo --size` converts the product
from "domain → emails" into "segment → lead list" — the actual paid-tool
workflow — built entirely on $0 lawful-public sources, and hands its output
straight to the 5A bulk harvester.

## What shipped

- **`mailaccess discover --industry X [--geo Y] [--size Z] [--limit N] [--mode …]
  [--output FILE] [--json FILE]`** — returns a ranked candidate-domain list; with
  `--output` writes a CSV that `harvest-emails --file` consumes directly.
- **`backend/core/company_discovery.py`** — the pipeline: `DiscoveryQuery`,
  `discover_companies` (injectable sources), `CandidateDomain` / `DiscoveryResult`,
  `discovery_to_csv`, `build_segment_queries`.
- **`cli/discover.py`** — the CLI driver (ranked table + per-stage review line).
- Lawful-gate classification: `company_discovery` added to
  `product_mode._ALL_KNOWN_MODULES` as a lawful-public source (in no blocked
  bucket → allowed in every mode).

## Design decisions (exploration latitude)

- **Discovery confidence is its own claim, never contact confidence.** A company
  being a plausible segment match is a different assertion from an email being
  deliverable (Doc-1 #17). Candidates carry `discovery_confidence` /
  `discovery_confidence_label` (STRONG/MODERATE/WEAK) in dedicated fields; the
  contact-confidence vocabulary (`confidence_score`/`confidence_label`) never
  appears in a discovery record. A test asserts the two are not conflated.
- **Sources / stages.** Each stage is independent and individually reviewable
  (the result retains every stage with its count + any error), and guarded — one
  failing never sinks discovery:
  - **Search dorking** — the primary segment→domain resolver. Short segment dork
    set (industry + geo + size); company domains are taken from organic result
    URLs, excluding an aggregator/social/directory denylist and free providers.
  - **OpenCorporates (free tier)** — corroboration: a discovered domain whose
    name-token matches a registered company in the target jurisdiction gets a
    name-match signal (and a company name).
  - **Common Crawl host index** (optional) — a cheap liveness corroboration for
    the top candidates.
- **Fusion = noisy-OR corroboration.** `1 − Π(1 − wᵢ)` over per-signal weights
  (search rank-tiered, OC name-match, CC presence) — more independent sources and
  higher result positions rank a domain higher, without any single weak source
  dominating.
- **Hands off to 5A.** `discovery_to_csv` writes `domain,company_name,
  discovery_confidence,label,sources`; the first column is the domain, so
  `bulk_harvest.parse_domain_list` (and thus `harvest-emails --file`) consumes it
  directly. No harvesting happens in discovery (non-scope).
- **Lawful gate.** Default mode is `public-business-contact` (lead-gen); a bad
  `--mode` is a hard error. The run records its mode + `policy_status`
  (`lawful-public`), and `is_module_allowed("company_discovery", mode)` holds in
  all three modes because every source is public.

## Validation (done-when)

- **Unit** — `tests/test_company_discovery.py` (12 tests): segment-query build;
  non-company-host + free-provider exclusion; multi-source corroboration boosts
  confidence and records sources; discovery-vs-contact confidence separation;
  ranking by discovery confidence; `--limit`; stages recorded + guarded on
  failure; `company_discovery` allowed in all modes and never in `blocked_modules`;
  default lead-gen mode + lawful-public status; bad-mode raises; and the CSV
  output feeds `parse_domain_list` (the 5C→5A hand-off). CLI `discover --output`
  writes the CSV.
- **Real** — `discover` runs end-to-end offline-graceful: with a flaky/blocked
  search backend it returns 0 candidates cleanly (guarded stages), writing a
  well-formed CSV. With a working search backend (or a Brave key) it returns a
  ranked list.
- **Gate** — `python -m eval.harness.gate check` green; the policy suite
  (`tests/test_product_mode.py`, 35 tests) stays green with the new
  classification.

## Non-scope

No blending of discovery and contact confidence. No harvesting inside discovery
(it hands domains to 5A). Directory/registry deep-crawls and name→domain
reconciliation beyond the OpenCorporates corroboration signal are left for a
later iteration.
