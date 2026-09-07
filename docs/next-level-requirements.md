# MailAccess — Next-Level Requirements Brief
**For:** Solutions Architect (Opus 5)
**From:** Technical Auditor / Growth Engineering
**Date:** 2026-09-05 · **Baseline:** v0.14.4
**Objective:** Move MailAccess from "best-in-class open-source email OSINT" to a tool that rivals **paid lead-gen / marketing-data platforms** (Hunter, Apollo, ZoomInfo, Snov, RocketReach class) — while holding infra spend at ~$0/month.

---

## 0. The strategic reframe (read this first)

Today MailAccess is shaped like a **security OSINT tool**: it goes *one email deep*. Paid lead-gen tools are shaped the opposite way — they go *many emails wide*, and they sell three things we currently do not produce:

1. **A person, not a string.** Every row is `name + title + seniority + company + verified-deliverable email (+ phone/LinkedIn)`. Our harvest emits `HarvestedEmail` (`backend/core/domain_harvest_orchestrator.py:133`) which is rich in *provenance* but carries **no person attribution** — no name, title, seniority, or LinkedIn on the email.
2. **A market segment as the entry point.** Marketers start from *"SaaS companies, Berlin, 50–200 staff,"* not from a known domain. Our `harvest-emails` takes a single `--domain` only (`cli/main.py:852`) — there is no top-of-funnel company discovery and no bulk/list mode.
3. **A deliverability guarantee.** They grade every email Valid / Risky / Catch-all / Invalid so a marketer doesn't burn their sender reputation. We have strong verification primitives but no unified deliverability grade, and SMTP is hard-capped at 10 probes/domain (`backend/core/smtp_verifier.py:62`) — a deliberate safety ceiling that also caps lead-gen throughput.

**The single biggest lever** — and the thing that makes this beatable at $0 — is a **shared, ever-growing corpus** (Pillar A). Every current cache is local and ephemeral (`backend/core/harvest_cache.py` writes one JSON per domain to `~/.mailaccess/cache`; nothing is shared cross-run or cross-host). Paid tools' entire moat is a pre-built database of 100M–275M contacts. We can build a *community-contributed* equivalent that costs us nothing to host and gets better every week. Nobody in open source has done this.

The requirements below are grouped into 9 pillars. Each is tagged **effort** (S/M/L) and 🆕 where the idea is genuinely novel (not something you'll find in any existing tool or article).

---

## Pillar A — The $0 Shared Corpus (the flywheel / the moat) 🆕

> This is the headline. It directly answers "store the corpus of searches so caches bring data quicker, feed it into a local DB, and sync it every week — without paying for infra."

**A1 — Embedded local corpus DB (replace per-domain JSON cache).** *(M)*
Replace the flat per-domain JSON cache with a single local **embedded SQLite/libSQL** store keyed by `(domain, email, source, last_verified)`. Every harvest reads it first (instant, offline) and writes new findings back. This alone turns repeat/adjacent queries from minutes to milliseconds and is the substrate everything else in this pillar sits on.

**A2 — Federated corpus distribution over free CDN.** *(L)* 🆕
Publish a **compressed, sharded, read-only community corpus** (JSONL/Parquet + zstd, sharded by domain-hash prefix) as versioned artifacts on **GitHub Releases** (unlimited free bandwidth) with **Cloudflare R2 (10 GB free) or Turso embedded-replica (5 GB free, microsecond local reads)** as the sync layer. Clients pull deltas on `mailaccess corpus sync`; the corpus ships *with* the tool the way `data/common_names.json` does today, but grows. Result: a first-time user querying `stripe.com` gets instant results someone else already harvested — the paid-tool "we already have this contact" experience, at $0.

**A3 — Opt-in weekly contribution pipeline.** *(M)* 🆕
A background/`--contribute` path that batches a user's *public-source-derived* findings, strips anything not already public, hashes the contributor ID, and submits them weekly (batched PR to a data repo, or append to R2/Turso). This is the "feeds it into our database and sends it every week" mechanic. Contribution is **opt-in, license-gated, and rate-limited**; the corpus README must state the public-source-only + authorized-use policy.

**A4 — Confidence decay in the corpus.** *(S)*
B2B contact data decays ~25–30%/year (people change jobs). Every corpus row carries `last_verified` + a decay curve; stale rows are down-weighted and flagged for re-verification instead of served blind. This is what keeps a *growing* corpus from becoming a *rotting* one — the failure mode of every cheap contact DB.

**A5 — Corpus-derived priors (Bayesian pattern inference).** *(M)* 🆕
Aggregate the corpus into per-provider / per-industry **email-pattern distributions** (e.g. "verified Google-Workspace companies use `{first}` 63% of the time, `{first}.{last}` 24%…"). Feed these as **priors** into the pattern guesser so a guessed address inherits a *calibrated* probability instead of a hand-tuned constant. No vendor publishes this; it's uniquely enabled by owning verification outcomes.

---

## Pillar B — Person-centric lead model (table stakes vs paid)

**B1 — Promote `HarvestedEmail` → `Lead`.** *(M)*
Add first-class person fields to the harvested record: `full_name`, `first`, `last`, `job_title`, `seniority` (IC/manager/director/VP/C-level), `department`, `linkedin_url`, `phone`, `location`. We already extract many of these signals in separate places (`employee_name_discovery.py`, `linkedin_name_discovery.py`, `company_page_names.py`, `name_consensus.py`) — B1 is mostly *wiring existing signals onto the email record* rather than net-new collection.

**B2 — Title & seniority inference.** *(M)*
Classify title → seniority band + department using the existing `industry_vocabulary.json` pattern plus a small role lexicon. Seniority filtering ("only VPs and above") is a primary paid-tool filter and a cheap win once B1 lands.

**B3 — Org-chart reconstruction per domain.** *(M)* 🆕
Cluster a domain's corpus emails by inferred title/seniority into an **auto-generated org chart**. ZoomInfo sells org charts as a premium feature; we can derive a usable one for free from data we already hold. Exportable, and a strong visual differentiator.

---

## Pillar C — Top-of-funnel: niche / industry / geo discovery

**C1 — Company discovery front-end.** *(L)*
New entry point: `mailaccess discover --industry "fintech" --geo "DE" --size 50-200` → a ranked list of candidate company **domains**, before any harvesting. Sources at $0: search-engine dorking (existing `dork_queries.py`), OpenCorporates (free tier), Common Crawl host index, directory/registry crawls, and technographic hints. This converts the product from "domain → emails" to "**market segment → lead list**" — the actual paid-tool workflow.

**C2 — Bulk / list harvest mode.** *(S)*
`harvest-emails --file domains.csv` (and stdin) with a concurrency governor, resumable checkpoints, and one merged export. Straightforward given the pipeline already runs per-domain; it's the difference between a research toy and a lead pipeline.

**C3 — Technographic filtering.** *(M)*
Tag discovered companies with their stack (mail provider via MX — already resolved in `mx_resolver.py`; plus CMS/analytics fingerprints from page HTML we already fetch). Lets marketers target "companies on HubSpot / Shopify / Google Workspace" — a headline Apollo/BuiltWith filter, derived from bytes we already download.

---

## Pillar D — Verification & deliverability at scale

**D1 — Unified deliverability grade.** *(M)*
Collapse our verification signals (MX, SMTP RCPT, catch-all, Google/M365/Yahoo provider verifiers, disposable, role) into one **grade taxonomy: Valid / Risky / Catch-all / Invalid / Unknown**, matching what marketers expect and gate their sends on. We have all the inputs (`smtp_verifier.py`, `google_workspace_verifier.py`, `m365_verifier.py`, `yahoo_verifier.py`, `disposable_domains.py`) — this is fusion + a clear label, not new collection.

**D2 — Catch-all buster via provider side-channels.** *(M)* 🆕
Catch-all domains make SMTP RCPT useless (every address returns 250) — the #1 blind spot marketers pay to solve. For those domains, confirm a mailbox *actually belongs to a person* using provider existence oracles we already partially implement (M365 GetCredentialType/autodiscover, Google, plus presence signals like Gravatar/Slack/Zoom). Generalize `m365_verifier` + `google_workspace_verifier` into a single **catch-all buster** that returns real per-mailbox existence where SMTP can't.

**D3 — Deliverability score without SMTP.** *(S)*
For environments where port 25 is blocked or SMTP is too risky, produce a **probabilistic deliverability score** from MX + SPF/DMARC posture + provider + disposable/role + corpus history — so the tool degrades gracefully instead of going dark. Removes the hard dependency on the 10-probe SMTP path for the common case.

---

## Pillar E — Data-acquisition resilience (stop getting CAPTCHA'd)

**E1 — Common-Crawl-first crawling.** *(M)* 🆕 (as a default posture)
Prefer reading the **already-crawled web** (CC index → `cc_index_client.py`/`cc_page_fetcher.py`) over live-scraping search engines that serve CAPTCHAs (the audit flagged DDG/Bing HTML regex-scraping hitting 202 walls). Live fetch becomes the *fallback*, not the primary. Structurally sidesteps the fragility that caps yield today.

**E2 — Egress rotation pool.** *(M)*
Replace the single static proxy (`proxy.py`) with a rotating pool abstraction (free/self-supplied endpoints, health-checked, auto-evicting dead ones). Pair with rotating, realistic client fingerprints (today's Chrome-120 fingerprint is hardcoded). Raises the ceiling on bulk runs before rate-limits bite.

**E3 — Search-provider failover chain.** *(S)*
Extend `search_provider_router.py` into an explicit priority chain with automatic failover and per-provider health/backoff, so a CAPTCHA on one engine transparently rolls to the next instead of degrading the run.

---

## Pillar F — Self-calibrating scoring (kill the magic constants) 🆕

**F1 — Ground-truth capture.** *(S)*
Every SMTP/provider verification is a free **labeled outcome** (deliverable / bounced / catch-all). Log these against the features that predicted them. Costs nothing; unlocks F2.

**F2 — Calibrated confidence model.** *(M)* 🆕
Replace the hundreds of hand-tuned constants across `email_confidence.py` / `harvest_quality.py` / `name_consensus.py` (the audit's structural weakness #1) with a **tiny calibrated model** (logistic regression / gradient-boosted stump set) trained on F1 labels and shipped as static weights — **no serving infra**. Confidence stops being an arbitrary number and becomes a real *probability of deliverability*. Fed by the Pillar-A corpus, accuracy compounds over time. This is the flywheel applied to *quality*, not just speed — a self-improving scorer no open-source tool has.

---

## Pillar G — Freshness & change intelligence

**G1 — Scheduled re-harvest + monitoring.** *(M)*
Build on `harvest_diff.py` / `harvest_history.py`: watch a domain/list on a schedule and diff results over time.

**G2 — Job-change & new-hire signals.** *(M)* 🆕 (at $0)
From corpus diffs: **new email matching the org pattern = likely new hire**; **address that starts bouncing = likely departure/job change**. "Job-change alerts" is a premium ZoomInfo/UserGems product; corpus diffing gives us a credible version for free. High-value, recurring-use hook.

---

## Pillar H — Enrichment waterfall (BYO-free-tier)

**H1 — Waterfall orchestrator.** *(M)* 🆕 (as packaged)
Formalize the paid-tool "waterfall" pattern: try sources in priority order, stop at first confident hit, fall back for missing fields. We already have the connector shape; H1 is the ordering + stop-early + field-merge policy.

**H2 — Stitch multiple free tiers.** *(S)*
Let users plug in their *own* free-tier keys (Apollo free ~10k credits/mo, Hunter free 25/mo, People Data Labs free 1k/mo, etc.) and have the waterfall spread lookups across them to maximize free monthly yield. No single vendor lets you combine competitors' free tiers — packaging this is itself a differentiator, and it keeps *our* cost at $0.

---

## Pillar I — Hygiene & correctness (minimal, enabling)

**I1 — De-dupe overlapping modules & remove dead code.** *(S)* — audit found `haveibeenpwned.py` stub, duplicate gravatar/npm/pypi/person-pivot pairs, google-dork triplication, 4× subdomain overlap. Reduces maintenance drag on every future change.
**I2 — Real migrations (Alembic).** *(S)* — replace hand-rolled ALTER-TABLE; required before any DB grows (Pillar A) or multi-user (below).
**I3 — Fix `.env.example` Postgres sync driver** and the single-global-API-key bypass — required if this is ever hosted.

---

## Suggested sequencing (dependency-aware)

1. **A1 → A2 → A3 → A4** (corpus substrate + distribution + contribution + decay) — everything else compounds on this.
2. **B1 → B2** and **C2** (person model + bulk) in parallel — fastest path to a recognizably lead-gen product.
3. **D1 → D2 → D3** (deliverability grade) — the trust layer marketers gate on.
4. **F1 → F2** (self-calibrating scoring) — needs A + verification history to shine.
5. **C1, C3, G2, H1/H2, B3** — expansion once the core is a real pipeline.
6. **E1–E3, I1–I3** — resilience/hygiene, landed opportunistically alongside the above.

## The one-sentence pitch for the architect
Turn MailAccess from a one-email-deep OSINT tool into a **market-segment-wide lead engine** whose accuracy and speed **compound weekly** via a community-contributed, decay-aware, $0-hosted corpus — and whose confidence scores are **calibrated against real deliverability outcomes**, not hand-tuned constants.
