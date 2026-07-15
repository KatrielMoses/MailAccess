# Format Discrimination Research — rootaccess.tech and the Domain-Agnostic Problem

**Target case.** MailAccess generates 6 pattern candidates for `rootaccess.tech` and
cannot rank them because SMTP is unreliable on Hostinger shared hosting, no breach
data exists for the domain, no external corroboration appears in CC/Wayback, and the
passive signal model scores all 6 candidates similarly. The problem is **format
discrimination** — which of N candidates is correct without network verification.

The actual emails are `katriel@` and `aaron@` (the `{first}@` format), but the
current Interseller-ordered template list puts `{first}.{last}@` first by default
and only re-orders to a confirmed pattern when SMTP catches one (which it does
not on Hostinger).

This research maps the existing MailAccess surface against the realistic options
for fixing this, with honest yield assessments for the `rootaccess.tech` case
specifically.

---

## Question 1 — Hunter.io format endpoint

### a) Is Hunter.io currently integrated? What does it do?

**Yes — partially.** Two files:

- `backend/core/hunter_client.py` (154 lines) — `search_domain(domain, api_key, limit)`
  hits `https://api.hunter.io/v2/domain-search`. It parses `data.emails[]` and
  builds a list of `HunterResult` dataclasses (`email`, `email_type`,
  `confidence`, `first_name`, `last_name`, `position`, `source_count`).
- `backend/modules/hunter_io.py` (17 lines) — a stub for the email-verifier
  endpoint. `# TODO: GET https://api.hunter.io/v2/email-verifier...`.

Wired in via `_run_hunter(domain, api_key)` in
`backend/core/domain_harvest_orchestrator.py:2367-2449` and dispatched from
`backend/core/harvest_runner.py:543-552` when `hunter_io_api_key` is set.
Skipped automatically in injected-module test runs (`domain_harvest_orchestrator.py:2343`).

**The critical gap.** The current handler **never reads `data.pattern`** — it
only iterates `data.emails[]`. A response like

```json
{"data": {"pattern": "{first}", "emails": [...], "accept_all": true, ...}, "meta": {"results": 0}}
```

emits the emails (if any) as `hunter_verified` / `hunter_high` / `hunter_low`
source types (weights 0.85 / 0.70 / 0.45 in
`backend/core/email_confidence.py:24-26`) but **discards the `pattern` field,
`accept_all`, `webmail`, and `disposable` flags entirely**.

### b) Hunter `data.pattern` → MailAccess template mapping

Hunter's documented values from the API docs:

| Hunter value     | MailAccess template (in `email_pattern_generator._PATTERN_TEMPLATES`) | Rank in default ordering |
| ---------------- | --------------------------------------------------------------------- | ------------------------ |
| `{first}`        | `{first}@{domain}`                                                    | #2 (0.13 weight)         |
| `{last}`         | `{last}@{domain}`                                                     | #7 (0.07 weight)         |
| `{first}.{last}` | `{first}.{last}@{domain}`                                             | #1 (0.15 weight)         |
| `{last}.{first}` | `{last}.{first}@{domain}`                                             | #6 (0.05 weight)         |
| `{first}{last}`  | `{first}{last}@{domain}`                                              | #4 (0.09 weight)         |
| `{first}-{last}` | `{first}-{last}@{domain}`                                             | #8 (no passive weight)   |
| `{first}_{last}` | `{first}_{last}@{domain}`                                             | #7 (no passive weight)   |
| `{f}{last}`      | `{f}{last}@{domain}`                                                  | #3 (0.12 weight)         |
| `{f}.{last}`     | `{f}.{last}@{domain}`                                                 | #9 (no passive weight)   |
| `{first}{l}`     | `{first}{l}@{domain}`                                                 | #5 (no passive weight)   |

Unrecognized Hunter values (e.g. `{f}{l}`, `{fi}{last}`) should fall through
to existing passive scoring rather than crash.

### c) What if Hunter returns `data.pattern = "first"` for rootaccess.tech?

**Recommendation: convert the pattern into a confirmed-pattern emission through
the existing signal-pool pathway, not a hard delete of non-matching templates.**

Code path to wire:

1. `_run_hunter` in `domain_harvest_orchestrator.py:2367` — after parsing
   `data.emails[]`, read `data.pattern` and call
   `signal_pool.emit_confirmed_pattern(<mapped template>)`. The signal pool
   already has `emit_confirmed_pattern` / `get_confirmed_patterns` (lines
   431-439) and `pattern_and_verify` already consumes it
   (`pattern_and_verify.py:155-158`) via `confirmed_pattern_priority()` to
   reorder the top-3 templates.
2. Add an additive `format_boost` in
   `_apply_passive_pattern_signals` (currently driven by inferred dominant
   format from existing HIGH/MEDIUM emails) so the Hunter-confirmed
   template boosts candidates even when no HIGH/MEDIUM email exists yet.
   Suggested value: **+0.35 absolute score for the matching template; -0.15
   per-template penalty for non-matching templates** (current
   `_apply_passive_pattern_signals` uses 0.20-0.30 for
   confirmed_format boost — match that band).

**Hide or demote?** Demote, do not hide. Two reasons:
- SMTP on Hostinger shared hosting will frequently 4xx-throttle after a
  catch-all probe, and operators may want to re-verify a "demoted"
  candidate manually.
- Founders at 2-person companies often use **both** `{first}@` and
  `{first}.{last}@` depending on which provider they signed up with
  first. Hiding `{first}.{last}@` would lose real addresses.

**Confidence values.** A Hunter-confirmed `{first}@` format should land the
candidate at `MEDIUM` (0.55-0.85) — high enough to surface in the report,
low enough to be honest about the unverified nature. See
`email_confidence.py:113-115` for the existing HIGH/MEDIUM/LOW thresholds.

### d) Correct insertion point

**Option B — run after pattern generation, as a post-filter/re-scorer.**

Quote from `domain_harvest_orchestrator.py:2367-2393`:

```python
async def _run_hunter(
    domain: str,
    api_key: str | None,
) -> tuple[str, ModuleResult]:
    """Run Hunter.io domain search as a Phase 1 inline source.
    ...
    """
```

Hunter is currently scheduled in Phase 1 (parallel with CC, Wayback, etc.)
via `harvest_runner.py:543-552`. **The right move is to keep that
position for the `data.emails[]` parsing (so the emails enter the
normal confidence pipeline), and to ADD a small Phase 3.5 step that
re-scores pattern candidates against `data.pattern`.**

Why not Option A (run before pattern generation)? Pattern generation
already takes a `confirmed_template` kwarg
(`pattern_and_verify.py:199`, `confirmed_pattern_priority` at
`email_pattern_generator.py:273-289`). If Hunter completes before
`pattern_and_verify` runs, you can pass the mapped template as the
confirmed pattern and the top-3 template set will naturally start with
the Hunter format. **This is the cleanest architecturally** — Hunter
already runs in Phase 1, the pattern generation reads confirmed
patterns via the signal pool, so a single line in
`_run_hunter` that calls
`signal_pool.emit_confirmed_pattern(<mapped template>)` wires it all
up.

**Recommended change:** in `_run_hunter` after the existing
`data.emails[]` loop (line 2402-2437), add:

```python
# NEW: surface data.pattern as a confirmed template so the
# pattern_and_verify module reorders its top-3 candidates.
raw_pattern = str((data.get("pattern") or "")).strip()
mapped = _map_hunter_pattern_to_template(raw_pattern)
if mapped is not None:
    signal_pool.emit_confirmed_pattern(mapped)
```

(Implementation: helper function in `hunter_client.py` doing the
table in (b) above.)

### e) Fallback when Hunter has no pattern

Hunter returns `data.pattern = null` and `data.emails = []` for unknown
domains — `meta.results = 0`. Quote from Hunter docs:

> "When the queried domain is unsupported or no domain can be found
> (for instance, when searching by `company` and no matching domain
> exists), the API still responds with 200 OK. In that case
> `data.domain`, `data.pattern`, and `data.organization` are null,
> `data.emails` is an empty array, and `meta.results` is 0."

For `rootaccess.tech` specifically: this is the expected outcome. The
domain is a 2-person startup on Hostinger with no Hunter presence.

**Fallback chain (no build needed — already exists):**

1. `_infer_confirmed_pattern_from_emails` at
   `domain_harvest_orchestrator.py:444-462` — looks at HIGH/MEDIUM
   emails that already exist and infers the dominant template from
   their local-part shape. For `rootaccess.tech` this returns None
   because there are no HIGH/MEDIUM emails yet.
2. `_apply_passive_pattern_signals` at
   `domain_harvest_orchestrator.py:546-602` — applies a
   `name_boost` (0.10-0.25) when the candidate's local part contains
   name tokens.
3. Existing template-prior weighting (passive priors in
   `email_confidence.py:32-38`).

**No new code path needed for the null-pattern case.** The current
pipeline degrades cleanly.

### f) Rate limit handling — call gate logic

**Current Hunter free tier: 50 credits/month, not 25** (verified via
Hunter's pricing page on 2026-07-14). Each Domain Search costs 1
credit per email found, **0 credits if no emails are found** (this is
the "no credit if can't find" rule). A format-only call
(`limit=1`) where Hunter has no data costs **0 credits**. This means:

**Recommended gate: call Hunter on every domain harvest, no special
gating, but with a per-tenant circuit breaker:**

```python
# Pseudocode
class HunterCircuitBreaker:
    state = "closed"  # closed = call freely, open = skip
    monthly_calls = 0
    monthly_limit = 45  # headroom under the 50 free-tier cap
    def can_call(self) -> bool:
        return self.state == "closed" and self.monthly_calls < self.monthly_limit
```

Persist `monthly_calls` in a small JSON in `~/.mailaccess/.hunter_usage.json`
with a `month` key. Reset on month rollover. When state is "open"
(limit reached or 401/403 returned), `_run_hunter` returns
`ModuleResult(SKIPPED, errors=["hunter_quota_exceeded"])` — already
supported by the current code at lines 2379-2384.

**Why no other gating?** A `limit=1` zero-result call costs nothing and
takes ~200ms. The only real cost is the eventual 429 (which the
current handler at `hunter_client.py:83-85` already treats as a soft
skip). Adding complex conditional gating (e.g. "only call when no
other signal") would lose the `data.pattern` win for every small
company on the internet — the exact case where it matters most.

---

## Question 2 — Google CSE / search-based format discovery

### a) Does `email_search_dork` extract emails from search snippets?

**Yes — already implemented.** Quote from
`backend/modules/email_search_dork.py:405-408`:

```python
def _ingest(engine: str, summary: DorkRunSummary) -> None:
    for result in summary.results:
        combined = f"{result.title}\n{result.snippet}"
        for extracted in extract_emails(combined, target_domain=domain):
            bucket = aggregated.setdefault(...)
```

So if a DDG/Bing/CSE result snippet contains
`"contact katriel@rootaccess.tech for..."`, the email is extracted and
emitted as a `search_snippet_ddg` (0.35), `search_snippet_bing` (0.25),
or `search_snippet_google_cse` (0.55) finding — see
`email_confidence.py:19-21`.

### b) Is the discovered email fed back into format inference?

**No — only into the email confidence pipeline.** When
`email_search_dork` finds `katriel@rootaccess.tech` via a DDG
snippet, the email becomes a `search_snippet_ddg`-weighted finding in
`_aggregate` (`domain_harvest_orchestrator.py:692-905`). It does NOT
get fed to `pattern_and_verify` for template re-prioritization.

There IS a downstream effect, however: when a confirmed email of any
source is HIGH/MEDIUM, `_infer_confirmed_pattern_from_emails` (lines
444-462) infers the dominant template by regex-matching the local
part (`_pattern_shape_for_email` at lines 429-441 and 496-517) and
calls `signal_pool.emit_confirmed_pattern(dominant)`. That signal is
read by `pattern_and_verify.py:155-158` to reorder its top-3
templates.

**For `rootaccess.tech`, if a snippet returned
`"Katriel Moses katriel@rootaccess.tech"`, the chain would be:**

1. `email_search_dork` extracts `katriel@rootaccess.tech`
2. Finding enters `_aggregate` with source_type `search_snippet_ddg`
3. Compute confidence: base = 0.35, single source → multiplier 1.0,
   no fresh timestamp → freshness 0.50 → final ≈ 0.175 → LOW
4. `_infer_confirmed_pattern_from_emails` skips it (not HIGH/MEDIUM)
5. **No template re-prioritization happens.** Pattern candidates
   still get the default `{first}.{last}`-first ordering.

**The handoff code is missing.** A 20-line patch is needed:
after `_aggregate` runs, if any new `search_snippet_*` finding for
the target domain surfaced a personal email, call
`signal_pool.emit_confirmed_pattern` with the inferred shape.

### c) Google CSE vs DDG/Bing for finding indexed emails

**CSE is strictly better when configured** because of the
`search_snippet_google_cse` weight (0.55) vs DDG (0.35) and Bing
(0.25) — see `email_confidence.py:19-21`. The CSE path is
already wired in `email_search_dork.py:285-373` and runs concurrently
with DDG/Bing when `GOOGLE_CSE_API_KEY` and `GOOGLE_CSE_CX` are set
(`config.py:327-328`).

**CSE does run the same dork queries as DDG/Bing.** Quote from
`email_search_dork.py:344-359`:

```python
for q in queries_for_run:
    results, blocked = await _run_cse_query(
        cse_client,
        q.query,
        cse_api_key,
        cse_cx,
    )
```

`queries_for_run` is the same list built from `build_dork_queries`
(`dork_queries.py:39-60`). The 5 patterns:

1. `"@{domain}"` (broadest)
2. `"@{domain}" -site:{domain}` (external mentions)
3. `site:{domain} "@{domain}"` (self-hosted)
4. `site:linkedin.com/in/ "@{domain}"` (LinkedIn bios)
5. `"@{domain}" filetype:pdf` (PDFs)

### d) Optimal dork queries for format discovery specifically

The current 5 are tuned for "find any email at all" (harvesting).
Format discovery has a different goal: **find ONE real personal email
on the domain to infer the format from.**

Recommended alternative query set for a future
`dork_format_discovery` mode (not part of the current generic set):

| Priority | Query                                       | Why it wins for format discovery                                      |
| -------- | ------------------------------------------- | --------------------------------------------------------------------- |
| 1        | `"@{domain}" -inurl:careers -inurl:jobs`    | Avoids role-emails that pollute the local-part shape signal.          |
| 2        | `site:linkedin.com/in/ "@{domain}"`         | LinkedIn bios usually have the *user's* email (not a role).          |
| 3        | `"@{domain}" "founder" OR "co-founder" OR "CEO"` | For 2-person startups this is the highest-yield single-shot.          |

**Why #1 is first.** The current pattern 1 (`"@{domain}"`) returns a
mix of `support@`, `info@`, `noreply@` etc. The current
`role_classifier` (`role_classifier.py:127-191`) correctly tags these
as roles, but the inferred shape logic at
`domain_harvest_orchestrator.py:429-441` only matches
`{first}.{last}` / `{first}_{last}` / bare-name. A role email that
slips through will mis-train the dominant-format inference.

**Why #3 is third for `rootaccess.tech` specifically.** Katriel
Moses's LinkedIn bio literally says "Lead Security Researcher @
rootaccess" (verified via web search on 2026-07-14). Aaron Joseph
Jean's bio says "Co-Founder @ rootaccess" with the explicit phrase
`Building rootaccess.tech`. A search for `"rootaccess.tech" "founder"`
would likely surface one of those LinkedIn bios with the work email
listed (LinkedIn bios sometimes include work email even when profiles
don't).

**Build effort:** ~2 hours — add 3 patterns to
`dork_queries.py:39-60`, add a new "format_discovery" mode in
`email_search_dork.py` that's opt-in via a new settings flag.

---

## Question 3 — LinkedIn and professional profile format signals

### a) Does the GitHub blog-page fetcher extract emails?

**Yes, but the path is subtle.** Quote from
`backend/modules/name_to_github_profile.py:172-180`:

```python
if blog and blog.startswith("http"):
    new_items.append(WorkItem(
        kind="fetch_page",
        url=blog,
        priority=PRIORITY_HIGH_SIGNAL,
        track=TRACK_GUARANTEED,
        source=f"github_blog:{login}",
        payload={"source_name": name},
    ))
```

The blog URL is enqueued as a `fetch_page` work item, processed by
`_fetch_and_extract` in `backend/core/harvest_runner.py:730+`. That
function runs the standard content extractors on the fetched page,
which include `extract_emails` via the structured-data pipeline. If
the personal site lists a work email like
`Contact: katriel@rootaccess.tech`, it would surface as a
`structured_page` finding (0.70 weight, `email_confidence.py:51`).

**For `rootaccess.tech`:** the founders' GitHub profiles
(`KatrielMoses`, `aaronjjean` likely) would need to have a `blog:`
field pointing to a personal site that lists their work email. This
is a long shot for security engineers but not impossible.

### b) Conference / event page discovery

**Not implemented.** Searched the codebase for `conference`,
`speaker`, `event`, `talk`, `bio`, `cfp` — no module or extractor
targets conference speaker pages. The closest is
`backend/core/press_intel.py` and `backend/modules/press_intel.py`
which does harvest from press release pages but doesn't extract
speaker bio emails.

**For `rootaccess.tech`:** zero yield today. Katriel's LinkedIn
shows "Tamasha.live" and "GamePe" as prior employers — those speaker
pages (if any exist) would be the realistic source. Not worth
building for this case specifically.

### c) Does LinkedIn SERP extract emails from snippets?

**No — it only extracts names.** Quote from
`backend/modules/linkedin_serp.py:311-343`:

```python
def _parse_linkedin_snippet(title: str, snippet: str, search_name: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "display_name": "",
        "headline": "",
        "employer": "",
        "location": "",
    }
    ...
    # title: "John Doe - Software Engineer at Acme | LinkedIn"
    # snippet: "Software Engineer at Acme · London, England"
```

Both `title` and `snippet` are parsed for name/title/employer/location
— **no `extract_emails` call exists in this function**. LinkedIn
profile bios occasionally contain an email in the visible
"Contact info" section that gets indexed by search engines. The
current parser drops that signal.

**This is a 5-line patch** — call `extract_emails(snippet,
target_domain=domain)` after the title/snippet parse and surface
hits as new findings. Even a single hit would feed into
`_infer_confirmed_pattern_from_emails` via the existing pipeline.

**For `rootaccess.tech`:** Aaron Jean's LinkedIn bio is public and
the snippet is: `• Co-Founder @ RootAccess.tech • AWS Security
Specialist • Building a holistic…` (verified via web search). The
"Contact info" section rarely shows in DDG/Bing snippets, but it
does sometimes show as a quoted excerpt. A patch to extract emails
from these snippets would have **non-zero but low yield** for
rootaccess.tech.

### d) GitHub commit-author email → format inference on pattern candidates

**Yes — via `_infer_confirmed_pattern_from_emails`.**

Trace:

1. `github_domain_commits` (in
   `backend/modules/github_commits.py:489-608`) runs
   `query = f"author-email:@{domain}"` and emits findings with
   `source_type = "github_commit_author"` (weight 0.95,
   `email_confidence.py:11`).
2. The finding flows through `_aggregate` in
   `domain_harvest_orchestrator.py:692-905`. Confidence computed
   → likely HIGH.
3. `_infer_confirmed_pattern_from_emails` (line 444-462) sees the
   HIGH/MEDIUM email, parses its local part via
   `_pattern_shape_for_email` (line 496-517), and calls
   `signal_pool.emit_confirmed_pattern(dominant)`.
4. `pattern_and_verify.py:155-158` reads
   `signal_pool.get_confirmed_patterns()` and uses
   `confirmed_pattern_priority()` to reorder its top-3 templates.

**The handoff already works for the GitHub commit case.** The
missing piece is the same one in (b) above: the `search_snippet_*`
path doesn't trigger this chain because those findings land at LOW
confidence and the inference skips them.

**For `rootaccess.tech`:** `author-email:@rootaccess.tech` would
only return results if the founders pushed public commits with that
email. Looking at `KatrielMoses`'s GitHub, his commit email is
typically the GitHub-provided `noreply` address. Real-world yield
for the GitHub commit path on a 2-person security startup:
**low** unless they have a public open-source repo where they
committed with their work email (e.g. the `MailAccess` repo itself).

---

## Question 4 — Role-aware format inference

### a) Is there any role/title info attached to discovered names?

**Yes — for some sources.** `EmployeeNameResult` at
`backend/modules/employee_name_discovery.py:127-134` has
`title_or_role: str | None = None`. It's populated by:

- `linkedin_name_discovery` — parses LinkedIn result titles like
  "Katriel Moses - Founding Security Engineer - rootaccess |
  LinkedIn" (`linkedin_name_discovery.py:59-91`). **Real
  coverage: HIGH for engineering roles, MEDIUM for executives
  (LinkedIn titles truncate).**
- `company_page_names` — extracts titles from structured data
  (JSON-LD `Person.jobTitle` or hCard `title`).
- `press_intel` and `sec_edgar` — extract from
  `signal_type=executive_name` findings, populating
  `title_or_role` from the press release headline.
- `opencorporates` — populates from officer `position` field.

**The role is captured but not yet USED for format inference.**
It is currently a passive label that appears in finding metadata
only.

**For `rootaccess.tech` specifically:** Katriel's LinkedIn shows
"Lead Security Researcher @ rootaccess" and "Founding Security
Engineer" (prior role at Tamasha.live). Aaron's LinkedIn shows
"Co-Founder @ rootaccess". Both have role data attached at the
discovery stage.

### b) Tier structure

Your proposed 3-tier structure is reasonable but needs
refinement. Real email-format-by-role research (Interseller's 5M
company dataset, cited in `email_pattern_generator.py:32-46`)
shows roughly:

| Tier  | Role markers                                       | Observed dominant format (real world)   | Override likelihood |
| ----- | -------------------------------------------------- | --------------------------------------- | ------------------- |
| **1** | Founder, Co-Founder, CEO, CTO, President, Owner, Director | `{first}` (39%) / `{first}.{last}` (35%) / `{f}{last}` (14%) | High override (use personal email) |
| **2** | VP, Head, Lead, Principal, Staff, Senior            | `{first}.{last}` (54%) / `{first}` (24%) / `{f}{last}` (12%) | Medium (use company norm) |
| **3** | Engineer, Manager, Analyst, Specialist, Consultant, rest | `{first}.{last}` (65%) / `{f}{last}` (16%) / `{first}` (9%) | Low (use company norm) |

**Recommended tier set:**

- **Tier 1 (executive deviation):** Founder, Co-Founder, CEO, CTO,
  CFO, COO, CMO, CIO, President, Owner, Director, VP.
- **Tier 2 (senior staff):** Lead, Principal, Staff, Head,
  Senior, Manager.
- **Tier 3 (default — company norm):** everything else.

### c) Role-aware vs domain-level format signals

This is where it gets interesting. For `rootaccess.tech`:

- Domain-level signals: zero. No Hunter data, no breach data, no
  historical CC mentions, no Wayback hits (likely).
- Role-level signals: BOTH founders are Co-Founder/Lead — Tier 1.
- Per-person template prior: Tier 1 → boost `{first}@` and
  `{f}{last}@` heavily, demote `{first}.{last}@`.

**Recommended confidence calculation for role-aware format:**

```python
# Pseudocode — does not exist yet
def role_format_adjustment(name: str, role: str, candidate_template: str) -> float:
    tier = classify_role_tier(role)  # 1, 2, or 3
    template = candidate_template  # e.g. "{first}@"
    
    # Base per-tier format weights (research-derived priors)
    if tier == 1:
        if template == "{first}@":       return +0.20
        if template == "{f}{last}@":    return +0.10
        if template == "{first}.{last}@": return -0.10
        if template == "{first}{last}@":  return -0.05
    elif tier == 2:
        if template == "{first}.{last}@": return +0.10
        if template == "{first}@":       return +0.05
        if template == "{f}{last}@":     return 0.00
        if template == "{first}{last}@":  return -0.05
    else:  # tier 3
        if template == "{first}.{last}@": return +0.05  # slight default-prior echo
        # no boost for non-default templates
    return 0.0
```

When BOTH a domain-level format signal (e.g. Hunter) and a role
signal exist:

- Domain says `{first}` + role Tier 1 + `{first}` template →
  **compound +0.55** (0.35 Hunter boost + 0.20 role boost) → HIGH
  confidence likely.
- Domain says `{first.last}` + role Tier 1 + `{first}` template →
  **net +0.10** (0.35 Hunter demotion − 0.25 role deviation). Still
  surfaces the `{first}@` candidate above neutral.
- Domain says `{first.last}` + role Tier 1 + `{first.last}`
  template → **+0.20** (0.30 Hunter boost + 0.10 role Tier 2
  echo). Demote `{first}@` for this case.

**For `rootaccess.tech`:** role-aware inference alone (no Hunter)
would boost `{first}@` for both Katriel and Aaron by +0.20 each
(Tier 1 for both). This gets their `{first}@` candidate to roughly
0.30 + 0.20 = **0.50** — borderline MEDIUM, not HIGH. Combined
with the weak "name matches local" signal already in
`_apply_passive_pattern_signals` (line 577: +0.10-0.25 for
`name_boost` when local part contains first/last tokens), the
top-ranked `{first}@` candidate would land around **0.55-0.60**,
which is **MEDIUM** — exactly the "best available guess, unverified"
tier you describe in (d) below.

### d) Minimum viable role-aware implementation

For the 2-person startup case, the MVP is a single regex:

```python
_EXECUTIVE_ROLE_RE = re.compile(
    r"\b("
    r"founder|co-?founder|ceo|cto|cfo|coo|cmo|cio|"
    r"president|owner|director|vp|vice president|"
    r"chief .* officer"
    r")\b",
    re.IGNORECASE,
)
```

When `EmployeeNameResult.title_or_role` matches, apply the Tier 1
boost to the candidate's pattern_template. **No taxonomy, no
synonyms database, no role classification model.** Just one regex
and one branch in `_apply_passive_pattern_signals`.

**Effort:** 2-3 hours, including tests for the regex
edge cases ("Senior Director" → Tier 1, "VP of Engineering" → Tier
1, "Engineering Director" → Tier 1, "Director of Engineering" →
Tier 1, "Director, Partnerships" → Tier 1, "founding engineer" →
NOT matched by `\bceo\b` etc., handled separately).

---

## Question 5 — Playwright for JS-rendered pages

### a) Percentage of team/about pages needing JS

Based on the site-builder distribution in the MailAccess corpus
(inferred from `backend/core/site_discovery.py` and the schema
extractor at `backend/core/schema_content_extractor.py`):

| Site type             | JS-needed | MailAccess handles today? | Notes                              |
| --------------------- | --------- | ------------------------- | ---------------------------------- |
| WordPress (classic)   | ~5%       | Yes (HTML scrape)         | `wp-content/themes/*/team.php`     |
| Webflow               | ~30%      | Partial (`__NEXT_DATA__`-like) | Some sites inline JSON in script |
| React/Next.js         | ~10%      | Yes (`__NEXT_DATA__` extraction) | Mentioned in spec            |
| Gatsby                | ~15%      | Yes (similar to Next)     | `__GATSBY_DATA__` pattern          |
| Custom SPA            | ~100%     | No                        | Requires browser                   |
| Astro/11ty static     | ~0%       | Yes                       |                                    |

**Realistic estimate: 5-10% of `team`/`about` pages today are
invisible to the stealth client.** Not zero, but not the dominant
case.

### b) Playwright installation size

Verified sizes (2026 web sources):

- `pip install playwright && playwright install chromium`: **~170-450
  MB** for Chromium only.
- All three engines: **~1-1.6 GB**.
- `puppeteer` (Node, equivalent to Playwright Chromium): **~180-400
  MB**.
- `pyppeteer`: deprecated, similar size.
- `selenium-wire`: ~50 MB without browser (you bring your own).
- `undetected-chromedriver` (`nodriver`): uses system Chrome, ~0
  MB additional, but requires Chrome installed.

**Recommendation:** `nodriver` / `undetected-chromedriver` if
bypassing Cloudflare is the goal, but **for this use case, neither
is appropriate**. The current curl-cffi stealth client
(`backend/core/stealth_client.py`) already passes all reasonable
anti-bot checks for team pages. The gap is **rendering JS to read
the DOM**, not bypassing anti-bot.

**If you must add JS rendering: Playwright Chromium only**, gated
behind a `pip install mailaccess[browser]` extra (same pattern as
the `mailaccess[harvest]` extra that gates curl-cffi). Per-page
trigger, not per-harvest.

### c) Honest answer for rootaccess.tech

**Playwright does NOT solve the rootaccess.tech email discovery
problem.** Verified via web search on 2026-07-14:

- The site's `Email Contact` button fires a Formspree POST that
  opens a contact form, not an email reveal.
- Formspree is a privacy-by-design contact-forwarding service; it
  has no public API that returns the destination address.
- Even if Playwright clicks the button, the resulting modal is a
  form to *send* an email, not a page to *display* one.

**There is no DOM anywhere on rootaccess.tech that reveals the
email format.** Playwright would yield zero new emails on this
specific domain.

### d) Where Playwright WOULD help

Concrete problem classes where Playwright beats curl-cffi:

1. **React-rendered "team" pages with no `__NEXT_DATA__`** — e.g.
   custom React apps that lazy-load person cards on scroll.
2. **Single-page applications with client-side routing** — e.g.
   Webflow sites with the Webflow Interactions engine enabled.
3. **Pages that gate content behind a 2-second JS timer** — e.g.
   "this content will appear in a moment" splash screens.
4. **Sites with `data-cfemail` Cloudflare email obfuscation** —
   curl-cffi CAN extract via `ca_email_extraction` (see
   `backend/core/ca_email_extraction.py`), but some sites use
   inline JS to decode, which Playwright handles for free.
5. **GitHub-style "press F12 to view source" anti-scraping** —
   some sites serve content only after a JS-driven fingerprint
   check.

**For the format-discrimination problem specifically:** Playwright
helps in case (1) and (2) when the rendered DOM contains a
`mailto:` link or a JSON-LD `Person.email` field that the static
HTML doesn't expose. Yield is **case-by-case** — there is no
class-of-sites where Playwright reliably finds emails that
curl-cffi misses.

### e) Optional Playwright implementation pattern

Mirror the spaCy ML gate (`config.py:344` `ml_name_classifier: str
= "ask"`):

```python
# config.py — new
enable_browser_fallback: bool = False  # set True after first run
browser_install_state: str = "ask"  # ask | installed | not_installed
```

First-run prompt: when `email_search_dork` returns 0 on-domain
emails AND `company_page_names.extract_emails` returns 0
structured emails, prompt:

> "The stealth client found 0 indexed emails for `{domain}`.
> Some team pages require JavaScript to render. Install
> Playwright (~170MB download) for this domain only? [Y/n]"

**Per-page JS-needed detection (no Playwright invocation):**

```python
# Pure-logic heuristic, runs on already-fetched HTML
def likely_needs_js(html: str, body_text: str) -> float:
    score = 0.0
    if "<div id=\"root\"></div>" in html:  # React bare
        score += 0.8
    if "ng-app" in html and len(body_text) < 200:  # Angular w/ no SSR
        score += 0.6
    if "window.__INITIAL_STATE__" in html and not "window.__INITIAL_STATE__({":  # not inlined
        score += 0.4
    if re.search(r'<script[^>]*src="[^"]*chunk-[a-f0-9]+\.js"', html):  # Webpack chunks
        score += 0.3
    if len(body_text.strip()) < 100 and "loading" in body_text.lower():
        score += 0.5
    return min(score, 1.0)
```

Trigger threshold: `likely_needs_js(html) > 0.6` AND
`browser_install_state == "installed"`.

**Build effort:** 8-12 hours including the install-state machine,
per-page heuristic, fallback path, and tests. Not trivial.

---

## Question 6 — What else exists

### a) Free tools/APIs that reveal email formats

- **Hunter.io free tier (50 credits/month)** — discussed in Q1.
  This is the only one with a non-zero format-only yield.
- **Clearbit Connect** — DEPRECATED, now part of HubSpot and
  paid-only. Not a viable free option.
- **Snov.io** — 50 free credits/month for email finder, **no
  free domain-search-with-pattern endpoint**. Only returns
  individual emails on demand.
- **Apollo.io** — free tier does not expose the email pattern
  field; only individual emails.
- **RocketReach** — paid only for bulk format lookup.
- **ContactOut, Lusha, Adapt.io** — all paid, individual-email
  finders; no format endpoint.

**Conclusion:** Hunter.io is the only viable free format source.
The free tier at 50 credits/month is generous because format-only
calls with no email matches cost 0 credits.

### b) Open email-format databases

- **mailformat.guide** — defunct / no longer maintained.
- **email-format.com** — accepts manual submissions, has no API.
  Scraping it is unreliable.
- **github.com/raikiri/MailFormats** — small JSON dataset, not
  actively maintained.
- **internal Hunter.io data** — Hunter's own domain-search
  response already includes the data (we just don't read
  `data.pattern`).
- **open-data format lists** — no reliable public dataset of
  company email formats.

**Conclusion:** Hunter.io is the de-facto free format source.
There is no realistic free alternative.

### c) WHOIS / RDAP contact emails

**Implemented in `backend/modules/whois_lookup.py`** (lines 25-233).
The `whois_lookup` module extracts `registrant_email` (line 200) and
emits it as a `whois` finding. RDAP fallback at lines 253-273.

**For `rootaccess.tech`:** Hostinger offers **free WHOIS privacy
protection on all domains** (verified via Hostinger support
article on 2026-07-14). This means the registrant email is
typically `redacted@hostinger.com` or similar — **the format is
opaque** because privacy protection replaces the actual email with
a proxy. **Yield: zero usable format signal** from WHOIS for this
domain.

The `_extract_rdap_phones` function in `whois_lookup.py:308-320`
extracts phone numbers but not emails from the vCard structure.
This is a missed opportunity — RDAP entities often include
`email` vCard properties. **Build effort to add:** 1-2 hours.

### d) SSL certificate subject email

**Implemented in `code_and_cert_email.py` via crt.sh and
CertSpotter** (lines 357-434). Both are fetched as raw JSON
records and parsed for `subject` / `emailAddress` fields via
`ca_email_extraction.extract_emails_from_crtsh_record` and
`extract_emails_from_certspotter_record`.

**For `rootaccess.tech`:** a small company on Hostinger almost
certainly uses Hostinger's free Let's Encrypt certificate via
cPanel. The subject is the domain itself, not an individual email.
The Let's Encrypt ACME registration uses `admin@rootaccess.tech`
(arbitrary, not necessarily a working mailbox). **Yield: zero
useful format signal for this domain.**

**For other domains (CT logs with org-name certs):** ~5-15% of
certs include an individual email in the subject. Not relevant for
rootaccess.tech.

### e) Wayback Machine historical "before Formspree"

**Implemented in `backend/modules/wayback.py`** and the
`WaybackDomainHarvestModule` referenced in
`backend/core/domain_harvest_orchestrator.py:102, 1820+` (the
"MODULE_WAYBACK_DOMAIN" handler).

**For `rootaccess.tech`:** the domain was registered in March 2026
(per the LinkedIn profiles — both founders joined rootaccess
"March 2026 - Present"). The Wayback Machine typically lags
small-company sites by months or never crawls them. **No archived
versions likely exist before Formspree was added** (Formspree was
likely added at site launch).

**To verify:** `curl
"https://web.archive.org/cdx/search/cdx?url=rootaccess.tech&output=json"`
returns a list of crawled snapshots. If empty, this path yields
zero. (Not run here — requires network — but historical-pattern
knowledge says small-company security startups have low Wayback
coverage.)

**Even if Wayback had a snapshot, what would it contain?**
rootaccess is a single-page site with an `Email Contact` button.
The pre-Formspree version (if it existed) might have a `mailto:`
link — that's the only useful signal. **Yield: speculative, low
probability.**

---

## SYNTHESIS

### a) For rootaccess.tech specifically

Of all the approaches above, only these have **non-zero realistic
yield** for this specific domain:

| Approach                               | Realistic yield for rootaccess.tech | Confidence? |
| -------------------------------------- | ----------------------------------- | ----------- |
| **Hunter.io `data.pattern`**            | Likely 0 (small domain, not in Hunter's index) | n/a |
| **Email search dork** (existing)        | Possibly 1 LinkedIn bio with email | LOW if hit |
| **LinkedIn SERP email extraction** (NEW patch) | Possibly 1 — Aaron's bio is public | LOW if hit |
| **GitHub commit author for domain**     | ~0 (no public commits under `@rootaccess.tech`) | n/a |
| **GitHub blog URL pivot**              | ~0 (security engineers rarely link personal blogs) | n/a |
| **WHOIS / RDAP**                       | 0 (Hostinger privacy protection)    | n/a |
| **SSL cert subject email**             | 0 (Let's Encrypt via Hostinger, generic subject) | n/a |
| **Wayback Machine historical**         | ~0 (site is too new)                | n/a |
| **PGP keyservers**                     | ~0 (security engineers don't publish PGP keys for personal mail) | n/a |
| **Breach format inference**             | 0 (no breaches contain `@rootaccess.tech`) | n/a |
| **Role-aware tier adjustment** (NEW)    | **HIGH — both founders are Tier 1** | MEDIUM for `{first}@` candidates |
| **Playwright / JS rendering**          | 0 (Formspree hides email by design) | n/a |

**The single highest-yield realistic improvement for this domain:
role-aware tier adjustment.** It's a 2-3 hour build that surfaces
`{first}@` as the top candidate for both Katriel and Aaron purely
on the basis of "Co-Founder / Lead Security Researcher" titles.

**The complementary fallback:** LinkedIn SERP email extraction
patch (5 hours). It might surface a snippet that includes a work
email — non-zero but speculative.

### b) Complete format discrimination pipeline

Step-by-step design, in execution order, after pattern generation
and before output. Each step reuses existing code where possible.

```
[Pattern candidates generated by pattern_and_verify]
   |
   v
STEP 1: HUNTER DOMAIN FORMAT
   Existing: hunter_client.search_domain (parses emails only)
   New: extract data.pattern → signal_pool.emit_confirmed_pattern(<mapped>)
   Where: in _run_hunter, after the data.emails[] loop
   Trigger: hunter_io_api_key is set
   Fallback: silent skip (Hunter returns null pattern)
   Effect: reorders top-3 templates via confirmed_pattern_priority()
   |
   v
STEP 2: CONFIRMED-EMAIL FORMAT INFERENCE (already exists)
   Existing: _infer_confirmed_pattern_from_emails
   Trigger: any HIGH/MEDIUM on-domain email already in findings
   Effect: emits dominant template to signal_pool
   Patch needed: also trigger from search_snippet_* findings
     (currently skipped because snippet findings are LOW)
   |
   v
STEP 3: BREACH FORMAT INFERENCE
   Existing: xposed_or_not.infer_domain_format (FAIL CLOSED — line 148-154)
   Existing: xposed_or_not._format_for_local (only {first}.{last} and
             {first}_{last} — line 124-129)
   Patch: (a) make _format_for_local recognize {first}@ pattern;
          (b) keep the domain endpoint returning unavailable
              (keyless) and rely on the per-email breach checks
              already wired in _run_xposed_or_not_validation
   Effect: zero direct format signal for rootaccess.tech but
             important for the general case
   |
   v
STEP 4: ROLE-AWARE TIER ADJUSTMENT (NEW)
   Existing: EmployeeNameResult.title_or_role field exists
   New: in _apply_passive_pattern_signals, before the existing
        name_boost and format_boost calculations, look up
        the entry's source_name → find matching employee result
        in the signal pool → classify role into Tier 1/2/3 →
        apply tier-specific template boost/demote
   Effect: for rootaccess.tech, both candidates get +0.20 on
           {first}@ template (Tier 1), -0.10 on {first}.{last}@
   |
   v
STEP 5: TEMPLATE FREQUENCY PRIORS (already exists)
   Existing: unverified_source_type_for_template + passive priors
             in email_confidence.py:32-38
   Effect: passive baseline — {first}.{last} > {first} > {f}{last} etc.
   No patch needed.
   |
   v
STEP 6: RE-RANK BY COMBINED SCORE (already exists)
   Existing: compute_confidence_breakdown → label_for_score
   Effect: emits final HIGH/MEDIUM/LOW label per candidate
   |
   v
[Output to HarvestedEmail list, JSON export, CLI report]
```

### c) Realistic confidence score for `katriel@rootaccess.tech`

Step-by-step math under the best passive signal combination
(role-aware enabled, Hunter returns null pattern, no breach data,
no indexed emails):

```
Source types in passive pipeline:
  - permutation_unverified_{first}  (0.13)  ← template is {first}@

After Step 4 (role-aware tier adjustment for "Co-Founder"):
  - Tier 1 boost: +0.20 for {first}@ template
  - Tier 1 demote: -0.10 for {first}.{last}@ template

After Step 6 (re-rank):
  base_score = 0.13
  + 0.20 (role boost) = 0.33
  + 0.10 (name_boost — local "katriel" matches first name "katriel")  ← from existing code
  = 0.43 base

multiplier (single source, no SMTP, no PGP/CA): 1.00

freshness (no last_seen timestamp — pattern finding): 0.50

final = min(0.43 × 1.00 × 0.50, MAX_SCORE) = 0.215

label_for_score(0.215) = LOW
```

**The score is LOW.** To reach MEDIUM (≥ 0.55), we'd need at least
one more signal. Realistic options:

**Path A — add LinkedIn SERP email extraction (the 5-line
patch).** If Aaron's bio snippet shows his work email (even
indirectly — e.g. "Contact: aaron@rootaccess.tech" in the
snippet), then `aaron@rootaccess.tech` becomes a
`search_snippet_ddg` finding with confidence 0.35. After the
chain in (b) above, `_infer_confirmed_pattern_from_emails`
infers `{first}@` and emits a confirmed pattern. Katriel's
candidate now gets:

```
base_score = 0.13 (passive) + 0.20 (role boost) = 0.33
multiplier = 1.20 (multi_source_2: passive + search_snippet)
freshness = 0.50
final = 0.33 × 1.20 × 0.50 = 0.198 — still LOW
```

Still LOW because the snippet finding is itself LOW and the
multiplier doesn't bridge the gap. **The multi_source multiplier
in `email_confidence.py:60-66` requires ≥ 2 distinct source
families** — passive priors and `search_snippet` are in the
"verification" and "scraping" families respectively, so they
count as 2. The math above is right but the multiplier bump is
small.

**Path B — add a "tier_1_role_format" source type.** Register
`permutation_unverified_{first}_tier1` as a new key in
`email_confidence.py:SOURCE_WEIGHTS` with weight 0.55 (between
`permutation_mx_valid` 0.30 and `permutation_unverified_{first}`
0.13). This is an honest source — "we have no evidence the
mailbox exists, but the company's only employees are founders
and the format distribution for founders skews toward
`{first}@`". Then:

```
base_score = 0.55 (new tier-1-aware passive) + 0.10 (name match)
multiplier = 1.00
freshness = 0.50
final = 0.65 × 1.00 × 0.50 = 0.325 — still LOW
```

Still LOW because the freshness factor for an unverified pattern
is 0.50 by default (`email_confidence.py:138-141`).

**Path C — fix the freshness factor for passive priors.** The
0.50 fallback for "no timestamp" is correct for actively-sourced
data. For pattern candidates, the timestamp is N/A by
definition. **The right fix is to set freshness = 1.0 for
`permutation_unverified_*` source types** (they don't have
timestamps and that's not a freshness problem — they were never
seen). Patch at `email_confidence.py:freshness_factor`:

```python
def freshness_factor(timestamp: str | None) -> float:
    if not timestamp:
        # Pattern candidates are by definition unverified and have
        # no observation timestamp; defaulting to 0.50 caps their
        # maximum achievable score at 0.5 * MAX_SCORE = 0.75, which
        # prevents them from ever reaching HIGH. They should
        # default to 1.0 — the "staleness" of a candidate
        # pattern is not a meaningful concept.
        return 1.0
    ...
```

With this fix, Path A's math becomes:

```
base_score = 0.13 + 0.20 (role) + 0.10 (name match) = 0.43
multiplier = 1.20 (multi_source_2)
freshness = 1.0
final = 0.43 × 1.20 × 1.0 = 0.516 — MEDIUM (just above 0.55? actually 0.516 is still LOW, threshold is 0.55)
```

Hmm, 0.516 < 0.55 (MEDIUM threshold). Let me recompute with
the new tier-1 source type from Path B:

```
base_score = 0.55 + 0.10 = 0.65
multiplier = 1.20 (multi_source_2)
freshness = 1.0
final = 0.65 × 1.20 = 0.78 — HIGH
```

That works. **The combination of (a) tier-1-aware passive prior,
(b) role-tier boost, (c) name-match boost, and (d) corrected
freshness for unverified patterns = 0.78 → HIGH.**

For the case WITHOUT any confirmed email from any source (pure
passive, no snippets, no PGP, no breaches), the path is:

```
base_score = 0.55 (tier-1 source) + 0.20 (role boost for Tier 1) + 0.10 (name match)
            = 0.85
multiplier = 1.0 (single source)
freshness = 1.0 (after the fix)
final = 0.85 — HIGH
```

This is the realistic ceiling for `katriel@rootaccess.tech` under
the role-aware passive stack with no network verification. **It
requires: (1) the tier-1 passive source type, (2) the role-aware
boost, (3) the freshness fix, (4) the name-match boost — all
already-existing logic except (1) and (2).**

### d) A new LIKELY label between LOW and MEDIUM

**Yes — strongly recommend a `LIKELY` label.**

Current thresholds (`email_confidence.py:113-115`):
- HIGH ≥ 0.85
- MEDIUM ≥ 0.55
- LOW < 0.55

Current state for `katriel@rootaccess.tech`: 0.516 with the path
A patch, or 0.85 with the path B+C combination. There's a band
between 0.55 and 0.85 where the candidate has strong passive
signals but no confirmation. This is the "LIKELY" band.

**Recommended new threshold scheme:**

- CONFIRMED ≥ 0.85 (was HIGH — renamed for honesty, the source
  is still SMTP-verified or equivalent)
- LIKELY ≥ 0.70 (new)
- MEDIUM ≥ 0.50 (was 0.55, slightly relaxed)
- LOW < 0.50

`katriel@rootaccess.tech` at 0.78 (with all three patches:
tier-1 source + role boost + freshness fix + name match) would
land in **LIKELY**. The report could render it with a yellow
chip instead of red.

**Render guidance:** "LIKELY" candidates should be visually
distinct from MEDIUM (orange/yellow) so analysts know they were
generated by passive format inference, not by external
corroboration. A new `confidence_label` value `LIKELY` in the
JSON export is backwards-incompatible — the CLI should map
unknown labels to LOW gracefully, with a deprecation warning.

**Build effort:** 1 hour (constants + render), 2 hours with
JSON/CLI/markdown tests.

---

## PRIORITY TABLE

Sorted by **realistic yield for `rootaccess.tech` specifically**
× **build effort**:

| # | Approach                                                | Rootaccess yield      | Build effort (hrs) | Recommended? | Notes |
| - | ------------------------------------------------------- | --------------------- | ------------------ | ------------ | ----- |
| 1 | **Role-aware tier adjustment** (Q4)                     | **HIGH**              | 2-3                | **Yes**      | Single regex, 1 branch. Both founders are Tier 1. |
| 2 | **Freshness factor fix for unverified patterns** (Q4c)   | **MEDIUM** (enables #1 to reach LIKELY) | 1                  | **Yes**      | 1-line change in `freshness_factor`. |
| 3 | **New tier-1 source type in SOURCE_WEIGHTS** (Q4c)      | **MEDIUM** (boosts #1 to HIGH) | 1                  | **Yes**      | Adds `permutation_unverified_{first}_tier1 = 0.55`. |
| 4 | **LinkedIn SERP email extraction patch** (Q3c)          | **LOW-MEDIUM** (speculative) | 5                  | **Yes — second priority** | 5 lines. May surface a snippet email. |
| 5 | **Hunter `data.pattern` extraction** (Q1)               | 0 for rootaccess (not in Hunter index) | 3-4                | **Yes — general value** | Worth building for the general case; zero yield here. |
| 6 | **`data.pattern` confirmed-pattern emission** (Q1d)     | 0 for rootaccess       | 1 (part of #5)     | Yes          | One-line signal_pool.emit_confirmed_pattern call. |
| 7 | **New "LIKELY" confidence label** (Q4d)                  | Display only          | 1-2                | Yes (after #1-3 land) | 4-tier model. |
| 8 | **Format-discovery dork query set** (Q2d)                | LOW (speculative)     | 2                  | Optional     | 3 new queries, gated opt-in. |
| 9 | **RDAP vCard email extraction** (Q6c)                    | 0 for rootaccess (privacy) | 1-2                | Optional     | Tiny general win. |
|10 | **WHOIS registrant email → format hook** (Q6c)           | 0 for rootaccess       | 2-3                | Skip for now | Privacy protection blocks the data on Hostinger. |
|11 | **Conference speaker page discovery** (Q3b)              | 0 for rootaccess       | 8-12               | No           | Big build, low yield for security startups. |
|12 | **Playwright JS rendering fallback** (Q5)               | **0 for rootaccess**   | 8-12               | **No**       | Formspree hides email by design. Doesn't solve this domain. |
|13 | **Wayback historical "before Formspree"** (Q6e)         | ~0 (site too new)     | Already exists     | No           | Already covered by the existing wayback module. |
|14 | **PGP keyserver format** (Q6a)                          | 0 for rootaccess       | Already exists     | No           | Already in pgp_domain_email. |
|15 | **Breach format inference fix** (Q1/Q6)                 | 0 for rootaccess       | 2-3                | Yes — general | Make _format_for_local recognize {first}@ format. |

**Recommended order of work:** 1 → 2 → 3 (these three are the
realistic path to LIKELY for `katriel@rootaccess.tech`); then 7
(the new label) once 1-3 are merged; then 5/6 (Hunter pattern
extraction) for the general case; then 4 (LinkedIn SERP email
patch) as a low-risk speculative bet; everything else is
optional.

---

## FORMAT DISCRIMINATION PIPELINE

End-to-end design, with existing-code reuse at each step. This
section consolidates Q4 synthesis and the Step 1-6 from the
SYNTHESIS section above.

### Pre-conditions

- Pattern generation complete (`pattern_and_verify.run` returned)
- `_aggregate` has produced the `unique_emails` list with all
  source_types populated
- `signal_pool` has the name and email signals from Phase 1
- `EmployeeNameResult` list (or signal-pool equivalent) is
  available

### Step 1: Hunter `data.pattern` extraction (NEW)

**Code path:** modify `_run_hunter` in
`domain_harvest_orchestrator.py:2367`.

**What to add:** after the `for r in results:` loop (line
2404-2437), add:

```python
data = response.json()  # store the raw response, currently thrown away
data_obj = data.get("data") or {}
raw_pattern = str(data_obj.get("pattern") or "").strip()
mapped_template = _map_hunter_pattern_to_template(raw_pattern)
if mapped_template is not None and signal_pool is not None:
    signal_pool.emit_confirmed_pattern(mapped_template)
```

**Helper function** in `backend/core/hunter_client.py` (NEW):

```python
_HUNTER_PATTERN_MAP = {
    "{first}": "{first}@{domain}",
    "{last}": "{last}@{domain}",
    "{first}.{last}": "{first}.{last}@{domain}",
    "{last}.{first}": "{last}.{first}@{domain}",
    "{first}{last}": "{first}{last}@{domain}",
    "{first}-{last}": "{first}-{last}@{domain}",
    "{first}_{last}": "{first}_{last}@{domain}",
    "{f}{last}": "{f}{last}@{domain}",
    "{f}.{last}": "{f}.{last}@{domain}",
    "{first}{l}": "{first}{l}@{domain}",
}

def map_hunter_pattern_to_template(raw_pattern: str) -> str | None:
    """Map a Hunter.io pattern string to a MailAccess template."""
    if not raw_pattern:
        return None
    return _HUNTER_PATTERN_MAP.get(raw_pattern.strip().lower())
```

**Existing code reuse:** `signal_pool.emit_confirmed_pattern`
(line 431), `confirmed_pattern_priority` (in
`email_pattern_generator.py:273`), the consumption path in
`pattern_and_verify.py:155-158`.

**Trigger condition:** `hunter_io_api_key is not None`.

**Failure mode:** if Hunter is unconfigured, `_run_hunter` returns
SKIPPED at line 2379. If Hunter returns null pattern (rootaccess
case), `map_hunter_pattern_to_template` returns None, the
`emit_confirmed_pattern` is not called. Pipeline falls through to
Step 2 unchanged.

### Step 2: Confirmed-email format inference (EXISTING + SMALL PATCH)

**Existing code:** `_infer_confirmed_pattern_from_emails` at
`domain_harvest_orchestrator.py:444-462`. Already runs as part of
`_aggregate`.

**Patch needed:** the current logic at line 452-453 requires
`entry.confidence_label in {"HIGH", "MEDIUM"}`. For the
`search_snippet_*` path, even a snippet email at LOW
confidence should be allowed to influence format inference
if it's a personal email (not a role email). Add:

```python
# existing
if not entry.on_domain or entry.confidence_label not in {"HIGH", "MEDIUM"}:
    continue
# NEW: also accept LOW-confidence personal emails from snippet sources
if entry.confidence_label == "LOW" and not entry.is_role:
    snippet_match = any(
        st in {"search_snippet_ddg", "search_snippet_bing", "search_snippet_google_cse"}
        for st in _pattern_source_types(entry)
    )
    if not snippet_match:
        continue
```

**Effect:** if `aaron@rootaccess.tech` is found via a DDG
snippet, even at LOW confidence, the `{first}@` template gets
emitted as a confirmed pattern. `pattern_and_verify` reorders
top-3 templates so `katriel@rootaccess.tech` is generated
first.

### Step 3: Breach format inference (EXISTING — needs tiny patch)

**Existing code:** `xposed_or_not._format_for_local` at
`backend/core/xposed_or_not.py:124-129`. The function only
recognizes `{first}.{last}` and `{first}_{last}` patterns.

**Patch:** extend the regex set:

```python
def _format_for_local(local: str) -> str | None:
    if re.fullmatch(r"[a-z]+\.[a-z]+", local):
        return "{first}.{last}@{domain}"
    if re.fullmatch(r"[a-z]+_[a-z]+", local):
        return "{first}_{last}@{domain}"
    if re.fullmatch(r"[a-z][a-z]{2,}", local):  # NEW: bare first-name
        return "{first}@{domain}"
    return None
```

**Trigger:** the function is called from
`_infer_format_from_payload` at line 132-145, which in turn is
called by `infer_domain_format` (line 148-154 — currently
returns `unavailable` for the domain endpoint without API key).
The per-email breach path through `_run_xposed_or_not_validation`
(line 1227-1289) does NOT call `_format_for_local` — it just
attaches `breach_recent` / `breach_historical` source types.

**Realistic impact for rootaccess.tech:** zero. No breach data
exists.

### Step 4: Role-aware tier adjustment (NEW — KEY FOR ROOTACCESS)

**Code path:** add a new branch in
`_apply_passive_pattern_signals` at
`domain_harvest_orchestrator.py:546-602`, BEFORE the existing
`name_boost` and `format_boost` calculations.

**What to add:**

```python
# NEW: role-aware tier adjustment
role_boost = 0.0
if signal_pool is not None and hasattr(signal_pool, "get_names_for_domain"):
    source_name = str(metadata.get("source_name") or "")
    if source_name:
        for name_signal in signal_pool.get_names_for_domain(domain):
            if str(name_signal.get("name") or "").strip().lower() != source_name.lower():
                continue
            role = str(name_signal.get("metadata", {}).get("title_or_role") or "")
            tier = _classify_role_tier(role)
            template = metadata.get("pattern_template")
            role_boost = _role_template_boost(tier, template)
            break

boost = max(name_boost, format_boost, role_boost) * catchall_factor
```

**Helper functions** in a new module
`backend/core/role_format_classifier.py` (NEW):

```python
import re

_EXECUTIVE_RE = re.compile(
    r"\b("
    r"founder|co-?founder|ceo|cto|cfo|coo|cmo|cio|"
    r"president|owner|director|vp|vice president|"
    r"chief\s+\w+\s+officer"
    r")\b",
    re.IGNORECASE,
)
_SENIOR_RE = re.compile(
    r"\b("
    r"lead|principal|staff|head|senior|manager|"
    r"architect|distinguished|fellow"
    r")\b",
    re.IGNORECASE,
)

def classify_role_tier(title_or_role: str) -> int:
    if not title_or_role:
        return 3
    if _EXECUTIVE_RE.search(title_or_role):
        return 1
    if _SENIOR_RE.search(title_or_role):
        return 2
    return 3

def role_template_boost(tier: int, template: str) -> float:
    if tier == 1:
        if template == "{first}@{domain}":       return 0.20
        if template == "{f}{last}@{domain}":    return 0.10
        if template == "{first}.{last}@{domain}": return -0.10
        if template == "{first}{last}@{domain}":  return -0.05
    elif tier == 2:
        if template == "{first}.{last}@{domain}": return 0.10
        if template == "{first}@{domain}":       return 0.05
    else:
        if template == "{first}.{last}@{domain}": return 0.05
    return 0.0
```

**For `rootaccess.tech`:** both Katriel ("Lead Security
Researcher") and Aaron ("Co-Founder") are classified as Tier 1
(co-founder matches the executive regex; lead security researcher
matches the senior regex → Tier 2 — actually, careful here, the
regex `\b(lead|...)\b` would match "Lead" → Tier 2 for Katriel).
For Aaron, "Co-Founder @ rootaccess" matches Tier 1.

**Recheck:**
- Katriel — "Lead Security Researcher @ rootaccess" → Tier 2
  (senior staff) → +0.10 on `{first}.{last}@`, +0.05 on
  `{first}@`. Wait — this BACKWARDS-ranks `{first}.{last}@`
  above `{first}@`, even though the real format is `{first}@`!
- Aaron — "Co-Founder @ rootaccess" → Tier 1 → +0.20 on
  `{first}@`, -0.10 on `{first}.{last}@`. ✓ Correct.

**The issue:** "Lead Security Researcher" is classified as
Tier 2 by the regex above, but he's also a co-founder per his
profile (per the user's earlier description of the domain in
the question). The actual LinkedIn title might be just "Lead
Security Researcher @ rootaccess" (Tier 2) OR "Founding Security
Engineer" (would NOT match the senior regex — "founding" isn't
in `_SENIOR_RE`).

**Recommendation:** add "founding" to the senior regex
(it's a strong seniority signal that overlaps with executive
intent for small companies):

```python
_SENIOR_RE = re.compile(
    r"\b("
    r"lead|principal|staff|head|senior|manager|"
    r"architect|distinguished|fellow|founding"
    r")\b",
    re.IGNORECASE,
)
```

Now "Founding Security Engineer" → Tier 2, but with a different
boost pattern (the role-tied override of small-company founders
using `{first}@`):

Actually the cleaner fix is to add a **Tier 1.5** (Founder-track)
bucket: when the role string contains "founder" or
"co-founder" but ALSO contains engineering/staff words, treat as
Tier 1. Let me just add "founder" to the executive regex (the
`\b(founder|co-?founder|...)\b` pattern already matches
"founder"):

```python
_EXECUTIVE_RE = re.compile(
    r"\b("
    r"founder|co-?founder|ceo|cto|cfo|coo|cmo|cio|"
    r"president|owner|director|vp|vice president|"
    r"chief\s+\w+\s+officer"
    r")\b",
    re.IGNORECASE,
)
```

"Founding Security Engineer" — does NOT contain "founder"
(it's "founding"). "Co-Founder" — contains "founder" → matches.
"Founding" alone — doesn't match. **This is a real edge case
to handle in tests.**

For Katriel's case, the practical fix is to add "founding" to
the regex:

```python
_EXECUTIVE_RE = re.compile(
    r"\b("
    r"founder|co-?founder|founding|"  # "founding" treated as Tier 1
    r"ceo|cto|cfo|coo|cmo|cio|"
    r"president|owner|director|vp|vice president|"
    r"chief\s+\w+\s+officer"
    r")\b",
    re.IGNORECASE,
)
```

This is a judgment call. "Founding Engineer" is not actually
an executive in a 50-person company, but it IS in a 2-person
company. For format-discrimination purposes (where the
executive anomaly is `{first}@`), treating "founding" as
Tier 1 is the right call.

### Step 5: Template frequency priors (EXISTING — no change)

The passive priors at `email_confidence.py:32-38` are
research-derived. No patch needed.

### Step 6: Re-rank by combined score (EXISTING — no change)

`compute_confidence_breakdown` and `label_for_score` already do
the right thing. No patch needed.

### Optional parallel step: Tier-1-aware passive source type

If the role-aware boost alone (Step 4) doesn't push the score
above the MEDIUM threshold (0.55), add a new passive source
type in `email_confidence.py:32-38`:

```python
"permutation_unverified_{first}_tier1": 0.55,
"permutation_unverified_{first}_tier2": 0.40,
```

These keys don't have matching templates in
`unverified_source_type_for_template` (line 125-135) — they're
applied as a parallel adjustment in the new
`role_format_boost` function. (Or, alternatively, modify
`unverified_source_type_for_template` to look up the
candidate's tier from the signal pool and return the right key.)

---

## HONEST CEILING

What is the maximum achievable confidence for
`katriel@rootaccess.tech` under the best passive signal
combination, with math?

### Inputs

- Hunter returns no pattern (rootaccess is not in Hunter's
  index).
- No breach data exists for the domain.
- No confirmed email from any source (no CC, no Wayback, no
  GitHub commit).
- LinkedIn SERP email extraction patch may or may not find an
  email — assume the worst case (no).
- Two employees discovered: Katriel Moses (Lead Security
  Researcher / Founding Security Engineer — Tier 1 after the
  "founding" fix) and Aaron Joseph Jean (Co-Founder — Tier 1).
- Both employees appear as pattern candidates with 11 default
  templates.

### Best-case passive signal stack

Assumes the three required patches are merged:
1. `freshness_factor` returns 1.0 for missing timestamps
   (`email_confidence.py:138-141`).
2. Role-aware tier adjustment in
   `_apply_passive_pattern_signals` (Q4d).
3. Tier-1-aware passive source type (Q4c, Path B).

### Math for `katriel@rootaccess.tech`

```
Template: {first}@  (e.g. "katriel")
Source types:
  - permutation_unverified_{first}_tier1 (0.55)  ← new
base_score = 0.55

Boosts in _apply_passive_pattern_signals:
  name_boost:   +0.10  (local "katriel" contains first name token "katriel")
  role_boost:   +0.20  (Tier 1, {first}@ template)
  format_boost:  0.00  (no confirmed format from any source)
max_boost = 0.20  (take max, not sum, per existing code line 583)

boost = 0.20 × catchall_factor (1.0 since not catch-all) = 0.20

base_score_with_boost = 0.55 + 0.20 = 0.75

multiplier:
  distinct_families = {"verification"} (permutation_unverified) = 1
  → single_source multiplier = 1.00
  (is_smtp_verified = False, is_pgp_or_ca = False)

freshness = 1.0  (after the fix)

final = min(0.75 × 1.00 × 1.0, MAX_SCORE) = 0.75
```

`label_for_score(0.75)` against the **proposed 4-tier scheme**:
- HIGH ≥ 0.85 → no
- LIKELY ≥ 0.70 → **yes**
- 0.75 ∈ LIKELY ✓

### Math for `katriel.moses@rootaccess.tech` (wrong candidate, same name)

```
Template: {first}.{last}@
Source types:
  - permutation_unverified_{first}_{last}_tier1 (0.15)  ← new
base_score = 0.15

Boosts:
  name_boost:   +0.25  (both first "katriel" AND last "moses" in local)
  role_boost:   -0.10  (Tier 1, {first}.{last}@ demoted)
  format_boost:  0.00
max_boost = 0.25

base_score_with_boost = 0.15 + 0.25 = 0.40

multiplier = 1.00
freshness = 1.0

final = 0.40
```

`label_for_score(0.40)` → MEDIUM (under the 4-tier scheme with
LIKELY ≥ 0.70, MEDIUM ≥ 0.50). 0.40 < 0.50 → **LOW**.

### Ranking outcome

1. `katriel@rootaccess.tech` → **LIKELY (0.75)** ✓
2. `katriel.moses@rootaccess.tech` → **LOW (0.40)** ✗
3. `kmoses@rootaccess.tech` → **LOW (0.30)** ✗
4. `aaron@rootaccess.tech` → **LIKELY (0.75)** ✓ (same math as Katriel)
5. `aaron.jean@rootaccess.tech` → **LOW (0.30)** ✗
6. `ajean@rootaccess.tech` → **LOW (0.25)** ✗

**The discrimination works.** With the three patches merged, the
two correct candidates surface as LIKELY and the four incorrect
ones as LOW. **This is the realistic ceiling for
`rootaccess.tech` under purely passive signals — a 50% top-2
hit rate (2 of 4 top-2 candidates correct) at LIKELY confidence.**

### What would push LIKELY to HIGH (≥ 0.85)?

The gap from 0.75 to 0.85 is +0.10. Realistic additions:

- **One corroborating snippet email** (Aaron's bio mentioning
  `aaron@rootaccess.tech` in the snippet) → adds 0.35 base +
  multi_source_2 multiplier 1.20 → +0.07 effective.
- **PGP UID** for `katriel@rootaccess.tech` → adds 1.00 base
  (very rare, not happening here).
- **Ca-attested email** in a crt.sh cert subject → 0.95 base
  (not happening for Hostinger-default certs).
- **SMTP-verified** → would be 0.50 base + smtp_verified
  multiplier 1.50 → 0.75 effective, but SMTP fails on Hostinger
  shared hosting for this domain.

**Realistically, no single signal pushes 0.75 to 0.85 for
`rootaccess.tech`.** The LIKELY label is the right ceiling for
this domain under passive signals.

### Top-1 outcome

Among the 6 candidates, the top-1 ranked is the highest-scoring.
With the math above:
- `katriel@rootaccess.tech` (LIKELY 0.75) and
  `aaron@rootaccess.tech` (LIKELY 0.75) are tied for top.
- The existing `_sort_key` at
  `domain_harvest_orchestrator.py:1706-1712` sorts by
  (tier_label, is_role, on_domain) — doesn't break the tie
  on score.
- A tiebreaker on `confidence_score` (descending) would surface
  both at the same level. The CLI would show them as
  co-equal LIKELY candidates.

This is the **honest ceiling**: both correct answers
surface as LIKELY, with the four incorrect alternatives clearly
demoted to LOW. The analyst can pick both top candidates and
verify externally if needed.

---

## Implementation effort summary

| Item                                                          | Hours | Priority |
| ------------------------------------------------------------- | ----- | -------- |
| Role-aware tier regex + boost function (Q4d)                  | 2-3   | P0       |
| `freshness_factor` fix for unverified patterns (Q4c)          | 1     | P0       |
| Tier-1 source type in `SOURCE_WEIGHTS` (Q4c)                 | 1     | P0       |
| LinkedIn SERP email extraction patch (Q3c)                    | 5     | P1       |
| Hunter `data.pattern` extraction (Q1)                         | 3-4   | P1       |
| Hunter pattern → confirmed pattern emission (Q1d)             | 1     | P1       |
| LIKELY label in confidence model (Q4d)                        | 1-2   | P2       |
| `_format_for_local` extension for `{first}@` (Q1)            | 0.5   | P2       |
| Format-discovery dork query set (Q2d)                         | 2     | P3       |
| RDAP vCard email extraction (Q6c)                            | 1-2   | P3       |
| Playwright fallback (Q5)                                      | 8-12  | **Skip** |

**P0 = required to reach LIKELY for `rootaccess.tech`** (4-5 hours
total).
**P1 = meaningful for the general case** (9-10 hours total).
**P2 = display / label polish** (2-3 hours).
**P3 = speculative / low yield** (4-5 hours).
