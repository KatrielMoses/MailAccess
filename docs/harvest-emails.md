# `mailaccess harvest-emails`

Domain-centric email discovery for OSINT, pentest, and analyst workflows.
Given a target domain, this command fans out across eight independent
structured sources in parallel, deduplicates the results, scores every
candidate, and renders a triage-ready report.

## Purpose and positioning

`mailaccess harvest-emails` is the **domain-centric** counterpart to
`mailaccess investigate`. They are not interchangeable:

| | `investigate` | `harvest-emails` |
|---|---|---|
| Input | One email address | One domain |
| Output | Profile / breach / contact profile for that address | Every email we can find at that domain, scored by confidence |
| Sources | Account-existence probes + breach correlation + identity graph | Eight structured data sources run in parallel against the domain |
| When to use | You already know an email and want to know who / where | You know an organisation and want a list of who's there |

If you want both — start from a domain, get a list of emails, then drill
into one — run `harvest-emails` first, then `investigate` on each
candidate.

## Quick start

```bash
mailaccess harvest-emails --domain example.com
```

That's it. You'll get a Rich-rendered report with HIGH / MEDIUM / LOW
confidence tiers, a list of role accounts, a list of discovered employee
names (used as pattern-generation seeds), and the per-module status
table.

If you want the proxy-aware modules to use ScrapingAnt, select a transport
first and then add `--use-proxies`:

```bash
mailaccess configure proxy enable residential
mailaccess harvest-emails --domain example.com --use-proxies
```

For a machine-readable export:

```bash
mailaccess harvest-emails --domain example.com --export acme.json
mailaccess harvest-emails --domain example.com --export acme.csv
mailaccess harvest-emails --domain example.com --export acme.ndjson
```

Format is inferred from the extension. Bare filenames (no path) are
routed to `./results/`.

## CLI flags

| Flag | Default | What it does |
|---|---|---|
| `--domain`, `-d` | (required) | Target domain, e.g. `example.com`. Free providers (gmail.com etc.) are rejected. |
| `--verify-smtp` | `false` | **OPT-IN.** Enables SMTP RCPT TO probing for the discovered pattern candidates. Off by default — the only path that turns it on. |
| `--use-proxies` | `false` | Route the proxy-aware harvest modules through the configured ScrapingAnt transport. |
| `--lite` | `false` | Reduces the search-dork module's query count for a faster (lower-yield) run. |
| `--max-cc-records N` | `100` | Overrides the Common Crawl module's per-harvest record cap. |
| `--min-confidence {low,medium,high}` | `low` | Label filter. Show only emails at or above this confidence label. |
| `--min-confidence-score FLOAT` | `0.0` | **Numeric counterpart to `--min-confidence`.** Show only emails whose `confidence_score >= FLOAT` (range 0.0–1.5). `0.0` = show everything. When both filters are set, the more restrictive one wins. |
| `--exclude-domain DOMAIN` | (none) | Hide emails from this domain. Repeatable. Example: `--exclude-domain gmail.com --exclude-domain yahoo.com`. |
| `--on-domain-only` | `false` | Hide third-party mentions. Show only emails whose domain equals the target. |
| `--export FILE` | (none) | Export to JSON / CSV / NDJSON (inferred from extension). |

When `--use-proxies` is set, only `email_search_dork` and
`employee_name_discovery` are routed through the configured ScrapingAnt
transport. `commoncrawl_email`, `code_and_cert_email`, `npm_email`,
`pypi_email`, `pgp_domain_email`, and `pattern_and_verify` stay direct.
SMTP verification is never proxied. Configure the transport with
`mailaccess configure proxy enable residential|datacenter`, inspect it with
`mailaccess configure proxy show`, and revert to the REST API transport with
`mailaccess configure proxy disable`.

### Filter combination example

```bash
# Show only emails with score >= 0.7 AND label >= medium
mailaccess harvest-emails --domain example.com \
    --min-confidence medium \
    --min-confidence-score 0.7
```

The numeric filter is strictly more expressive than the label filter
when used at non-aligned thresholds (e.g. score 0.7 is between MEDIUM
and HIGH).

## Source modules

Eight modules run. Seven run **in parallel** as Phase 1+2 of the
harvest; one (pattern_and_verify) runs after the employee-name
discovery module completes because it consumes those names.

### `commoncrawl_email` — Common Crawl

Queries the Common Crawl URL Index for pages mentioning the target
domain, fetches the matching pages, and extracts every email found.
This is typically the highest-yield source for medium/large orgs.
URLs are capped per harvest (`--max-cc-records`).

### `code_and_cert_email` — GitHub + Certificate Transparency

Three sub-sources:

* **GitHub code search** — every public mention of `@<domain>` in code.
* **GitHub commit authors** — for the repos surfaced by code search,
  walks commit history and collects author emails (highest weight in
  this module).
* **crt.sh + certspotter** — Certificate Transparency logs often include
  email addresses in the issuer / subject fields. Records are fetched
  directly so the email-bearing fields are preserved.

### `email_search_dork` — Search-engine dorking

Runs pre-built dork queries (e.g. `"@example.com"`) against DuckDuckGo
and Bing, parses snippets for emails. `--lite` cuts the query count in
half. Be aware: search engines can rate-limit or CAPTCHA sustained
heavy use.

### `employee_name_discovery` — Employee / executive names

Pulls names from LinkedIn / company about-pages / press / SEC EDGAR.
These names are NOT emails themselves — they seed Phase 3's pattern
generator. They also surface in the CLI's "Discovered names" panel so
you can pivot on a name even when no email pattern matched.

### `npm_email` — npm registry package metadata

Searches `registry.npmjs.org` for packages whose author or maintainer
email matches the target domain. Two sub-sources:

* **Search** — packages whose text mentions the domain string.
* **Direct keyword lookup** — fetches `registry.npmjs.org/<domain-keyword>`
  where the keyword is the domain's SLD (e.g. `stripe` for `stripe.com`).

Strict domain filter is applied — emails whose domain doesn't
*exactly* match the target are dropped. Useful for engineering orgs
that publish internal packages.

### `pypi_email` — PyPI registry package metadata

Same shape as npm_email, against `pypi.org`. Uses the deprecated but
still-working XML-RPC search endpoint plus the JSON API direct-lookup
fallback. Strict domain filter applied.

### `pgp_domain_email` — PGP keyserver UIDs

Searches `keys.openpgp.org` and `keyserver.ubuntu.com` for public PGP
keys whose User ID strings (the `<Name <email>>` block on a key)
contain the target domain. A PGP UID is a deliberate, user-verified
assertion of identity — when this module surfaces a hit, it is
treated as equivalent to a CA-attested email.

**Honest yield expectation:** since `sks-keyservers.net` shut down in
2021 and `keys.openpgp.org` now requires personal email verification
to publish keys, ~99% of historical keys are filtered out by the
upstream keyservers themselves. Realistic yield for tech-heavy domains
is 1-5%. The hits that DO appear are extremely high-confidence.

### `pattern_and_verify` — pattern generation + optional SMTP

Consumes the names from `employee_name_discovery`, generates email
pattern candidates (`first.last@`, `firstl@`, etc.), and probes the
MX for each candidate. With `--verify-smtp`, performs RCPT TO probes
to confirm mailbox existence. Without it, candidates are still listed
but flagged as unverified.

## Confidence scoring

Every email gets a numeric `confidence_score` (0.0–1.5) and a label
(HIGH / MEDIUM / LOW). Scores stack from three signals:

1. **Base weight** — how trustworthy the source type is on its own.
2. **Verification multiplier** — whether another source independently
   confirmed the email.
3. **Freshness decay** — how old the attestation is.

### Source weights

| Source | Weight |
|---|---|
| PGP keyserver UID (deliberate user-verified assertion) | 1.0 |
| CA-attested (crt.sh / certspotter cert subject email) | 1.0 |
| SMTP RCPT TO verified | 1.0 |
| GitHub commit author (`author:` qualifier) | 0.9 |
| Press release or SEC filing | 0.8 |
| Common Crawl hit on 3+ distinct URLs | 0.7 |
| npm or PyPI package author/maintainer | 0.7 |
| GitHub code mention | 0.6 |
| Common Crawl hit on a single URL | 0.5 |
| Permutation verified via SMTP | 0.5 |
| DuckDuckGo search snippet | 0.5 |
| Bing search snippet | 0.4 |
| Permutation on a catch-all domain | 0.2 |
| Permutation unverified | 0.05 |

### Multipliers

Multipliers stack multiplicatively (per-email, not per-source):

| Condition | Multiplier |
|---|---|
| 3+ independent source types confirmed the email | ×1.2 |
| SMTP verified | ×1.4 |
| CA-attested or PGP UID | ×1.5 |

### Freshness decay

Applied to the **oldest** source timestamp:

| Age of oldest attestation | Decay |
|---|---|
| ≤ 90 days | ×1.0 |
| 90–365 days | ×0.85 |
| 1–3 years | ×0.6 |
| > 3 years | ×0.3 |

### Display thresholds

| Score | Label |
|---|---|
| `>= 0.8` | HIGH |
| `>= 0.5` and `< 0.8` | MEDIUM |
| `< 0.5` | LOW |

The final score is capped at **1.5**. Each email is rendered with a
**rationale chip** summarising which weights, multipliers, and freshness
decay contributed — so the score is never a black box.

A typical HIGH-confidence candidate: Common Crawl multi-page hit
(`cc*`) + npm maintainer (`npm`) + recent → score ≈ 0.7 × 1.2 × 1.0 =
0.84 → HIGH.

## SMTP verification

`--verify-smtp` enables RCPT TO probing against the target's MX
servers. This is a **passive** OSINT technique — no email is ever
sent — but it is **detectable** (target mail servers will see your IP
attempting RCPT TO). Anti-spam systems can flag the source IP.

**Opt-in only — never enabled by default, never enabled by env var
alone.** The only path that turns it on is the explicit `--verify-smtp`
flag on a per-invocation basis. The `ENABLE_SMTP_VERIFICATION` env var
exists for documentation and is never read as an enable switch.

**Mandatory catch-all detection.** Before any RCPT TO probing begins,
the orchestrator probes a random UUID address at the target domain. If
the MX returns `250` for that address, the domain is treated as
catch-all and **all SMTP verification is aborted** for the run — every
permutation candidate is tagged `permutation_catchall` instead. If the
catch-all probe itself fails (network error, MX unreachable, hard
reject), verification is also aborted for safety. Catch-all domains
produce floods of false-positive "verified" addresses when probed
naively, so this check is non-negotiable.

Operational ceilings (hard-coded, not configurable):

* Max 100 probes per harvest.
* Max 30 probes per minute.
* `SMTP_PROBE_DELAY_SECONDS` defaults to 2.5s (well under the 30/min
  ceiling).

The default sender address (`probe@mailaccess.invalid`) is a
non-routable `.invalid` domain per RFC 6761 — it cannot be replied
to and cannot accidentally deliver mail.

**Enable only if you understand and accept the operational risk.**

## Rate limiting and runtime estimates

| Module | Approx. wall time | Notes |
|---|---|---|
| `commoncrawl_email` | 10–30s | Scales with `--max-cc-records`. |
| `code_and_cert_email` | 5–15s | With `GITHUB_TOKEN`: faster, higher rate limit. |
| `email_search_dork` | 30–90s | Search engines throttle sustained use; consider `--lite`. |
| `employee_name_discovery` | 5–20s | Mostly LinkedIn / company pages. |
| `npm_email` | 2–5s | 1 req / 2s polite cadence. |
| `pypi_email` | 2–8s | 1 req / 2s polite cadence. |
| `pgp_domain_email` | 2–5s | Two keyservers queried concurrently. |
| `pattern_and_verify` | 5–30s | Network-bound MX probing. |

Phases 1+2 run concurrently, so the wall time is roughly **max(Phase 1)
+ Phase 3**, not the sum. A typical harvest completes in **30s – 2min**
without SMTP, or **2–5min** with SMTP enabled.

## Export formats

### `.json` — full structured export

```json
{
  "schema_version": 1,
  "domain": "example.com",
  "summary": { "total_unique_emails": 42, "high_confidence": 7, ... },
  "emails": [
    {
      "email": "jane.doe@example.com",
      "on_domain": true,
      "is_role": false,
      "confidence_score": 0.84,
      "confidence_label": "HIGH",
      "found_by_modules": ["commoncrawl_email", "npm_email"],
      "confidence_breakdown": { "base_score": 1.2, "multiplier": 1.2, ... },
      "rationale_chip": "(cc*+npm multi-source)",
      "evidence": [...]
    }
  ],
  "module_metadata": { "commoncrawl_email": {...}, ... },
  "discovered_names": [...]
}
```

`schema_version` is preserved for forward compatibility — bump the
floor check in your downstream tool when bumping past 1.

### `.csv` — flat, spreadsheet-friendly

Columns: `email, confidence_label, confidence_score, is_role,
on_domain, is_smtp_verified, is_ca_attested, found_by_modules,
source_count, first_seen_timestamp, subaddress_variants,
rationale_chip`. `found_by_modules` and `subaddress_variants` are
comma-joined.

### `.ndjson` — one email per line

Same per-email structure as the JSON `emails` array, with a synthetic
`domain` field on each line. `schema_version` lives on each row.

## Known limitations

* **Free-provider domains are rejected.** Gmail, Yahoo, Outlook, etc.
  produce noisy / meaningless results because the email and the
  domain are owned by different entities. Pass a corporate domain.
* **WHOIS data is mostly redacted.** Modern WHOIS mostly hides
  registrant emails behind registrar contact forms. Cross-check with
  historical WHOIS or the RDAP protocol when available.
* **PGP yield is low** (~1-5% for tech-heavy domains). The keyservers
  themselves filter ~99% of historical keys post-sks-keyservers.net.
* **Search engines can CAPTCHA.** `--lite` reduces the dork count, but
  sustained heavy use will get your IP throttled.
* **Email pattern coverage is heuristic.** `pattern_and_verify`
  generates candidates from the discovered names. If the org uses an
  unusual pattern (e.g. nickname-based instead of legal-name-based),
  the candidates will miss real addresses.
* **SMTP verification is opt-in.** With it off, permutation candidates
  appear but unverified; with it on, you accept the operational risk.

## Suggested workflow for a typical pentest / OSINT engagement

1. **Reconnaissance** — run `harvest-emails --domain target.com` first.
   Get the broad picture: how many emails, what confidence tier.

2. **Triage** — review the HIGH-confidence list. These are your
   primary targets for phishing pretext, credential stuffing, or
   social engineering.

3. **Pivot** — for any name discovered but not yet matching an email
   pattern, run `investigate` on plausible candidates.

4. **Verify** — for HIGH-confidence candidates you want to confirm
   exist, re-run with `--verify-smtp` (with operational care) to get
   SMTP-verified confirmation.

5. **Export** — drop the results to JSON for downstream tooling
   (Maltego, custom scripts, reporting).

6. **Repeat for related domains** — parent company, subsidiary
   domains, sister brands. The cross-domain aggregation in Phase 3's
   `pattern_and_verify` only runs against the single target domain, so
   related-domain coverage requires separate runs.
