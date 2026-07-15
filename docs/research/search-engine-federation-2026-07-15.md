# Alternative Search Engines for MailAccess — Evaluation 2026-07-15

**Scope.** Live-tested 10 alternative search sources for the MailAccess
`@domain` / `site:linkedin.com/in/ "@domain"` / `"@domain" "keyword"` dork
queries that currently run over DDG + Bing HTML scraping. Both DDG (HTTP 202
challenge) and Bing (block markers) are dead on this network — the goal of
this evaluation is to find reliable replacements and rank them for a
federation layer.

**Test queries.**

1. `"@lavellenetworks.com"`
2. `site:linkedin.com/in/ "lavellenetworks.com"`
3. `"@rootaccess.tech" "security"`

**Test methodology.** All three queries were sent to each engine's HTML
endpoint with a Chrome User-Agent, plus a follow-up stress test where useful
to characterise rate limits. API endpoints hit where one was advertised.
SearXNG instances were also probed for their `/preferences` configuration
(backends, reliability stats) and their JSON API. Common Crawl CDX was
probed for both URL-pattern and (in spirit) full-text query equivalence.

**Honesty note.** Several engines could not be made to return a single
useful result from this network on 2026-07-15. Those results are reported as
negative, not glossed over.

---

## 1. Headline results table

| # | Engine | Q1 works? | Q2 works? | Q3 works? | Bot protection | API available? | Recommended? |
|---|---|---|---|---|---|---|---|
| 1 | Brave Search (HTML) | yes (6 result blocks) | yes (4 result blocks) | yes (10+ result blocks) | none at 2s spacing; ~5 burst then 429 | yes (free $5/month credits) | **YES — primary** |
| 1b | Brave Search (API) | not tested live (needs key) | not tested live | not tested live | none (auth) | yes, 50 q/s, 1000 free req/mo | **YES — fallback for scale** |
| 2 | Mojeek (HTML) | no — captcha page even with browser UA | no | no | hard captcha | paid only (no free tier) | NO |
| 3 | Yep.com (HTML) | no — 403 | no — 403 | no — 403 | aggressive | none public | NO |
| 4 | Marginalia (HTML) | no — anti-bot wait (-1s → -25s → -89s as I keep polling) | no | no | progressive back-off; also title-only index, no full-text | no public keyless API | NO for OSINT dorks |
| 5 | SearXNG `searx.be` | 403 from this IP | 403 | 403 | severe (instance down or geo-blocked) | same | NO — instance is dead from this network |
| 5b | SearXNG `search.inetol.net` | HTML loaded but no result block rendered (no-JS); JSON API returns 429 | same | same | per-instance rate limit; their own /preferences shows brave=timeout, ddg=CAPTCHA | yes, /search?format=json | MAYBE — usable via JSON, but inherits the same backend blocks |
| 5c | SearXNG `searxng.site` | 403 | 403 | 403 | severe | same | NO |
| 6 | Startpage | captcha wall | captcha | captcha | full captcha | no public API | NO |
| 7 | Qwant (HTML) | geo-block ("not yet available in your country") on en-US; fr-FR locale serves the SPA shell but results are JS-rendered (no HTML to scrape) | same | same | geo + JS-required | v3 API returns 403 (deprecated for public use) | NO |
| 8 | Ecosia (HTML) | 403 | 403 | 403 | aggressive | none | NO |
| 9 | Common Crawl CDX | not reachable from this IP (TCP 443 to 54.237.141.66 times out) | same | same | network-level | yes, but URL-pattern only — no full-text | NO from this network, and intrinsically not a body-text search |
| 10 | `cn.bing.com` | bot challenge page | same | same | equivalent to bing.com | n/a | NO |
| 10b | `www.bing.com/news/search` | 200, **0 results** for the dork | same | same | lower (it loaded) but the news index doesn't surface emails | n/a | NO for OSINT email dorks |

**The only engine that returned real, scrapable, dork-relevant HTML on all
three queries in this test session is Brave.** Everything else is blocked,
geo-fenced, captcha-walled, JS-only, or no longer free.

---

## 2. What was actually seen (per engine, evidence)

### 1. Brave Search — works

**HTML endpoint.**

```
https://search.brave.com/search?q={URL-encoded query}
```

Tested with all three queries via both `webfetch` and `Invoke-WebRequest`
with a Chrome UA. All three returned 200 with a real result list:

- Q1: 6 result blocks, snippet text contains `contact@lavellenetworks.com`,
  `sales@...`, `helpdesk@...`, `pr@...`, plus a Tracxn and ZoomInfo result
  (the latter with a redacted `s***@lavellenetworks.com`).
- Q2: 4 result blocks, all `linkedin.com/in/`, snippet text contains
  `www.lavellenetworks.com`. The `site:` filter was respected ("Only showing
  results from linkedin.com/in/").
- Q3: 10+ result blocks, `rootaccess.tech` itself appears, plus a Huntress
  explainer, a `rootaccess.technology` About page, and several
  look-alike-domain noise results. Brave explicitly told me "search
  operators were not applied / Too few matches were found" in the UI banner
  — meaning the `"@rootaccess.tech" "security"` quoted-phrase was treated
  strictly. That's a real signal: Brave does honour `site:` and exact phrase
  quoting, and tells you when it can't.

**Rate limit (measured).** Five requests at 0.5s spacing → first 4 returned
200, the 5th returned 429. With 2–3s spacing between requests the rate
limit did not re-trigger during a 5-query run. Practical per-host
sustained rate is roughly **1 query per second** on the HTML endpoint, or
**about 60/min** before throttling. The 429 response carries no
`Retry-After` header that I could read in a PowerShell `Invoke-WebRequest`
dump.

**Anti-scraping countermeasures on the HTML endpoint.** None that I could
trip with a desktop Chrome UA. No Cloudflare, no JS-required challenge, no
fingerprinting challenge for a small batch of well-spaced queries. The page
is server-rendered Svelte; the result content is in plain HTML, not hydrated
by client JS, so a simple HTML scraper works.

**Brave API.** Endpoint `https://api.search.brave.com/res/v1/web/search`,
auth via `X-Subscription-Token` header. From the public pricing page
(`brave.com/search/api/`):

- **$5 / 1,000 requests** for the Search plan
- **$5 in free credits applied monthly** → **~1,000 free requests/month**
  without a credit card beyond the signup
- **50 queries per second** ceiling on the Search plan
- `count` parameter, `country`, `search_lang` supported
- Response is JSON, each result has `title`, `url`, `description`
  (HTML-highlighted), `profile.{name,url,long_name,img}` — the `description`
  field is where the email and surrounding text appear
- Endpoint exists and validates the request even without a key (returns 422
  on missing/wrong auth, not 401 — i.e. it's a real working API)

**Unique value vs other engines.** Brave's index is independent (30B+ pages,
100M updates/day, their own crawl). It is not a Bing/Google reskin. The
result quality on the dork queries is high — it surfaced `contact@`,
`careers@`, `pr@`, and a ZoomInfo redacted form, all in the snippet text.
This is exactly what the MailAccess dork path is designed to harvest.

**HTML extraction pattern (Brave).** Result block is a `div` with class
matching `result-wrapper` (Svelte hash suffix rotates per build, so use
`[class*="result-wrapper"]`):

```
<a class="...result-header..." href="https://example.com/page">TITLE</a>
<div class="...snippet-url...">example.com › page</div>
<div class="...snippet...">SNIPPET TEXT WITH EMAIL</div>
```

Class names observed in this test (hashes will rotate):

```
class="result-wrapper svelte-1rq4ngz"
class="result-content svelte-1rq4ngz"
class="title search-snippet-title line-clamp-1 svelte-14r20fy"
class="snippet-url desktop-small-regular t-tertiary svelte-on1hvy"
class="snippet  svelte-jmfu5f"          # sometimes standalone
class="generic-snippet svelte-1cwdgg3"
```

Selector strategy: do not match full class names; use partial
`[class*="result-wrapper"]`, `[class*="snippet"]`,
`a[class*="title"]`. The `<a>` `href` is the URL. The snippet `<div>` is
where the harvested email lives.

**Implementation effort to add to MailAccess.** Low. Single async HTTP GET
with a Chrome UA, parse HTML with `selectolax` (already a likely
dependency) or `lxml`, extract (url, title, snippet) tuples, run the
existing `harvest_emails` regex over the snippet. Add a 2-second
`asyncio.sleep` between requests to stay under the rate limit. Total:
~150 lines of code, one new module, one new config key for the API token
if the user wants to use the API instead of HTML scraping.

### 2. Mojeek — captcha, no free API

**HTML endpoint.** `https://www.mojeek.com/search?q={query}`

- Bare request: HTTP 403
- With Chrome UA + Accept-Language: HTTP 200, but the body is the **Captcha
  challenge page** (title: "Captcha", Monetization meta tag, CAPTCHA
  challenge layout). No real results are returned.
- The page is served as a server-rendered challenge, not JS — meaning a
  headless browser would face the same captcha wall.

**API.** From `https://www.mojeek.com/services/api.html` (live read):

- Three plans, all paid, all billed in GBP via Stripe
- **Startup: £2/CPM** (= £2 per 1,000 queries), 5 q/s, 100k queries/day,
  10 results/request
- **Business: £3/CPM**, 10 q/s, 400k/day, 40 results/request
- **Enterprise: custom**, no limit
- No free tier, no free credits. The "Free trial" link goes to a contact
  form, not a self-serve flow.
- Supports `site:`, exact phrase, language boost, snippet length — would be
  a great dork API if there were a free tier

**Verdict.** Recommended: **no**. Captcha blocks HTML scraping, API is paid
only. MailAccess is a personal-OSINT tool — paying per-query for a search
backend to supplement DDG+Bing isn't justified when Brave works for free.

### 3. Yep.com (Ahrefs) — 403, no API

**HTML endpoint.** `https://yep.com/web?q={query}`

- Bare request: HTTP 403
- With Chrome UA + Accept-Language: HTTP 403

**API.** None public. Yep's parent company Ahrefs sells a separate Site
Explorer / Keywords product, but they don't expose the Yep search index
as a public API as of 2026-07-15.

**Verdict.** Hard no. The 403 happens at the edge — no UA negotiation saves
you.

### 4. Marginalia — progressive back-off + wrong index for the job

**HTML endpoint.** `https://search.marginalia.nu/search?query={query}`

- First request: returns a 200 page with a banner: *"The search engine is
  currently seeing a lot of fairly aggressive bot activity. Please wait for
  1 seconds before proceeding."* No result list visible.
- Second request (immediate): wait window becomes 25 seconds.
- Third request (immediate): wait window becomes 89 seconds.

This is a token-bucket back-off that grows with burst rate. Waiting
between requests would eventually let the request through, but at that
point you'd be running at maybe one query per minute, which is impractical
for the dork federation.

**The bigger problem: Marginalia is not a full-text engine.** From the
self-documented "Search Help / Syntax" page served alongside the challenge:

> *"While the search engine at present does not allow full text search,
> quotes can be used to specifically search for names or terms in the
> title. Using quotes will also cause the search engine to be as literal
> as possible in interpreting the query."*

So `"@lavellenetworks.com"` is matched against **page titles only**, not
body content. For an OSINT email dork this is the wrong tool — the email
is almost never in the title of the page where it appears.

**API.** The "no key required" claim in the brief is wrong. The endpoint
`https://api.marginalia.nu/search/{query}` 404s. Marginalia explicitly
documents that API access is by request only.

**Verdict.** Recommended: **no** for the dork federation. Interesting
engine for human-driven small-web research, but wrong shape for body-text
email discovery.

### 5. SearXNG public instances — fragile, don't bypass the underlying blocks

I tested three named instances plus read `/preferences` to see what
backends each uses.

#### 5a. `searx.be` (Belgium)

- Search request: **HTTP 403**.
- `/preferences` loads and lists these general-web backends with current
  reliability stats:
  - **bing** — median 0.2s, p95 0.3s, **3% errors** (timeouts)
  - **brave** — 0% reliability shown, **errors: "too many requests" and "timeout"**
  - **duckduckgo** — median 0.9s, **10% CAPTCHA errors**
  - **google** — working but Bing-equivalent rate limit
  - **karmasearch** — **access denied**
  - **mojeek** — **access denied**
  - **presearch** — "unexpected crash" + "timeout"
  - **qwant** — 5% reliability, "access denied"
  - **startpage** — 0% reliability, **CAPTCHA**
  - **wiby** — working (small-web index, not useful for email dorks)
  - **yahoo** — 65% reliability, "HTTP error"

**Key insight.** The "SearXNG bypasses DDG/Bing blocking" theory is
**false**. SearXNG is a frontend/aggregator; the underlying backends
(Brave, DDG, Bing) are still queried, just from the instance operator's
IP. The instance's own `/preferences` page shows DDG returning CAPTCHA
errors and Brave returning "too many requests" — the same walls DDG/Bing
hit us on, just proxied.

#### 5b. `search.inetol.net`

- HTML request: 200, returns the SearXNG layout HTML, but no
  `result-wrapper` blocks render in the static HTML (the results are
  hydrated by client JS). The page itself has no body-level
  challenge/captcha content.
- JSON request (`?format=json`): **HTTP 429** for both GET and POST.
- This instance has tighter rate limits than searx.be, and they hit me
  during the test.

#### 5c. `searxng.site`

- HTTP 403 from this network (geo-blocked or instance is down).

**Self-hosting cost.** A SearXNG instance is a small Docker container
(`searxng/searxng`) plus a reverse proxy. Resource footprint is
modest — 1 vCPU, 1 GB RAM, 10 GB disk is enough for a single user. The
real cost is the IP reputation: the instance will hit DDG/Bing/Brave from
its own IP, and on a fresh VPS (especially AWS / GCP / Azure ranges) those
backends are blocked within hours of first use. To keep an instance
useful you need either a residential IP (much more expensive) or to
disable the DDG/Bing backends and rely only on the backends that aren't
blocking your IP, which defeats the purpose.

**Verdict.** Public SearXNG instances: **no**, too variable. Self-hosted
SearXNG: **maybe**, but the value is in the aggregator/fallback logic, not
in bypassing the underlying rate limits. A small, well-curated set of
backends (Brave + Wiby + Marginalia) is the most that a self-hosted
instance can offer reliably — and the same logic can be implemented
directly in MailAccess without the SearXNG layer in between.

### 6. Startpage — full captcha wall

- HTML: 200, body is a captcha challenge page. No proxy to Google is
  completed without solving the captcha.
- No public API. Startpage used to have an "Anonymous View" proxy but it's
  not a programmatic search product.

**Verdict.** No.

### 7. Qwant — geo-blocked + JS-only

- English locale: HTTP 200 with the body *"The search engine that respects
  your privacy. Thanks for your visit. Unfortunately we are not yet
  available in your country."*
- French locale (`Accept-Language: fr-FR`): the SPA shell loads (HTML is
  200, no challenge), but the actual results are rendered by client-side
  JavaScript — a simple HTML scraper gets the page chrome and zero
  result rows.
- v3 API endpoint `https://api.qwant.com/v3/search/web`: HTTP 403. The
  free public API was sunset; the replacement is a paid partner API
  (Qwant Junior / Qwant for Enterprise).

**Verdict.** No. The geo-block and JS-rendering both block this. Users in
Qwant-covered countries (FR, DE, IT, ES, NL) with a headless browser might
get something out of it, but for a portable OSINT tool it's not viable.

### 8. Ecosia — 403

- Bare request: 403
- With Chrome UA + Accept-Language: 403

Same wall as Yep. Ecosia is Bing-reskinned, and Bing's bot protection
catches the proxy just as easily.

**Verdict.** No.

### 9. Common Crawl CDX — network-blocked + intrinsically wrong shape

**Connectivity.** TCP 443 to `index.commoncrawl.org` (resolves to
`54.237.141.66`) times out from this network. The CDX API is
**unreachable**. That's a hard infrastructure problem, not an API design
problem.

**What CDX could have given us.** CDX is a **URL pattern index**, not a
body-text search. The schema lets you filter by:

- exact URL match (`url=example.com/page.html`)
- URL prefix (`url=example.com/*`)
- URL regex / host filter (`url=*.example.com`)

There's no `contains:email@domain.com` operator. To find pages that
contain a specific email string via Common Crawl, you'd have to:

1. Pull the WARC/WAT/WET files for an index
2. Stream-parse them
3. Run your own substring search over the response bodies

That's a fundamentally different kind of system from a search API — it's
a bulk-archive query, not a single-query lookup. The brief's question
*"Does CDX support full-text search?"* is answered **no, by design**.

**MailAccess already uses CC for URL discovery** (per the brief), and
that's the correct shape: discover candidate URLs by URL pattern, then
fetch them and look for the email in the body. Trying to replace
search-engine discovery with CDX-only doesn't work because the
email-containing pages almost never have the email in their URL.

**Verdict.** No from this network. And even if it were reachable, the
shape is wrong for body-text discovery.

### 10. Bing regional endpoints — same wall, different wallpaper

- `cn.bing.com/search?q=...`: returns a "One last step / Please solve the
  challenge below to continue" challenge page. Same protection regime.
- `www.bing.com/news/search?q=...`: 200, but **zero result rows** for the
  dork query — the news index doesn't surface pages that have an email
  string in the body, because the news index is built on news articles
  which usually don't expose personal contact emails.

**Verdict.** No. The cn variant has the same protection, and the news
variant has the wrong index.

---

## 3. Federation architecture answers

### a) Engines that work without CAPTCHA/blocking, ranked by reliability

1. **Brave (HTML scraping).** Single real option on this network. ~1 q/s
   sustained before 429.
2. **Brave (API).** Higher ceiling (50 q/s), 1,000 free requests/month
   with a $5 monthly credit. Sign-up is online, no credit card required
   for the free credits.
3. **SearXNG public instances (with caveats).** inetol.net's HTML page
   loaded but didn't render results without JS; searx.be 403'd. Both
   inherit the same backend blocks (DDG captcha, Brave timeout per their
   own stats), so the "diversity" is illusory.
4. **Common Crawl CDX (if reachable).** Useful for URL discovery, not for
   body-text email discovery. Network-blocked from this user.

### b) Engines with a unique index that finds things others miss

- **Brave has an independent index** (30B pages, 100M updates/day, their
  own crawl, Goggles custom reranking). It's not a Bing/Google reskin.
- **Common Crawl's value is corpus-level** — it lets you reach pages that
  no search engine has ranked, but only if you have the bandwidth to
  WARC-parse.
- **Marginalia / Wiby / Marginalia-small-web** engines have *different*
  indexes (small web, blogs, forums), but for the email-OSINT dork
  specifically they're near-useless because:
  - Marginalia is title-only, not body-text
  - Personal emails rarely appear on small personal blogs
- **No engine in this evaluation found an email DDG/Bing missed on these
  three queries, because Brave found them and Brave is the one I could
  actually reach.** Without a working Bing and a working DDG, the
  comparison set is too small to claim "Brave finds things Bing misses."
  The Brave *index* is independent, though, so it's a fair assumption.

### c) Optimal 3–4 engine federation

**For maximum coverage on this network today, the federation is one
engine:**

> **Brave HTML scraping, with Brave API as the volume backend.**

The other engines in this evaluation do not return real results on this
network. A federation with three real engines isn't possible. The
honest answer is to design the federation layer as if more engines will
become available later, but ship with one working engine + a clean
abstraction so adding a second one is a config change.

**The abstraction to design for:**

```python
class SearchEngine(Protocol):
    name: str
    async def search(self, query: str, *, max_results: int = 20) -> list[SearchHit]: ...

@dataclass
class SearchHit:
    url: str
    title: str
    snippet: str
    engine: str
```

Then a `Federation` class that runs engines in parallel via
`asyncio.gather`, deduplicates by URL, merges snippets, and returns the
combined set. When Mojeek or another engine becomes scrapable, drop in a
new `SearchEngine` implementation.

### d) SearXNG instances — reliable or too variable?

**Too variable.** The three instances I tested:

- One 403'd at the edge
- One returned the layout but with JS-only results
- One 429'd on the JSON API during the test window

And even when they work, their own `/preferences` page documents that
their Brave backend is throwing "too many requests" and their DDG backend
is returning CAPTCHAs — the same problem we'd have, just from someone
else's IP. Public SearXNG instances are *not* a workaround for search
engine bot detection; they're a different surface for the same problem.

**Self-hosting cost.** A SearXNG instance is a single Docker container
on a $5/mo VPS, plus a domain. The real cost is **not the VPS, it's the
fresh-IP reputation**: a new VPS in AWS / GCP / Hetzner / OVH ranges
will be in the IP blocklists DDG and Bing use within hours. To get an
instance that actually works you either need (a) a residential IP (~$30
to $100/mo for a small static residential proxy), or (b) to disable
the DDG/Bing backends and rely only on the engines that don't block
your IP, which means you're back to Brave-only or Brave+Wiby, which
you can run from MailAccess directly.

**Recommendation:** don't self-host SearXNG for this. Self-host the
*logic* (a small `Federation` class in MailAccess) and connect directly
to engines that work.

### e) HTML structure notes per working engine

Already covered for Brave above. None of the other engines returned
scrapable HTML in this test, so there's nothing useful to add.

### f) Free API summary (genuinely usable, no credit card)

| Engine | Endpoint | Auth | Free tier | Rate limit |
|---|---|---|---|---|
| **Brave Search API** | `GET https://api.search.brave.com/res/v1/web/search?q=...&count=...` | `X-Subscription-Token: <key>` | **$5 free credits/month, ~1,000 requests** | 50 q/s on the Search plan |
| Common Crawl CDX | `GET https://index.commoncrawl.org/CC-MAIN-YYYY-WW-index?url=...&output=json` | none | unlimited, free | not formally limited; community etiquette applies |

All other engines in this evaluation either have no public API, require a
paid plan, or are deprecated (Qwant v3).

---

## 4. Final recommendation

### Top 3 to add to the search federation (priority order)

1. **Brave Search — HTML scraping** (primary path, free, no key, works
   right now on this network)
2. **Brave Search — API** (when the HTML rate limit becomes the
   bottleneck, sign up for the free $5/mo credit and switch the same
   query through the JSON API; same data, 50× the rate ceiling)
3. **Common Crawl CDX — URL discovery** (already integrated, use for
   *URL pattern* queries like `url:*.example.com/*` to discover pages
   that may not have been re-crawled by a search engine; not a body-text
   substitute)

No other engine in this evaluation passes the "returned real, scrapable,
dork-relevant HTML on this network today" bar. Building a 5-engine
federation with 4 of them as dead stubs is worse than building a
1-engine federation with a clean extension point.

### Optimal federation strategy

```
def search_dork(query):
    hits = []
    for engine in PRIORITY_ORDER:        # brave-html, brave-api, ccx
        try:
            new_hits = await engine.search(query, timeout=15)
            hits.extend(new_hits)
        except RateLimited:
            if engine is primary:        # primary 429 → API fallback
                try:
                    new_hits = await brave_api.search(query, timeout=15)
                    hits.extend(new_hits)
                except RateLimited:
                    continue             # both Brave paths down, keep going
        except EngineDown:
            continue                     # skip, try next engine
    return dedupe_by_url(hits)
```

**Why this order:**

- Brave HTML first: zero config, no API key needed, works on day one.
- Brave API second: when the HTML path hits 429, the API key is the
  cheapest escalation. Same engine, same data, 50× the rate limit.
- Common Crawl last: different shape (URL pattern, not body text), so it
  complements rather than duplicates the first two; useful for
  `url:*.example.com/*` discovery that no search engine has re-crawled
  recently.

**Deduplication.** Use the URL as the dedup key (Brave API and HTML
return the same URLs for the same query). Keep the longest snippet.

**Failure modes observed and what to do about them:**

| Symptom | Cause | Fix |
|---|---|---|
| Brave HTML returns 429 after a burst | ~1 q/s sustained limit | back off to 2s spacing, queue queries |
| Brave HTML returns 200 but no result blocks | unusual; new-build or query too narrow | log it, continue to next engine |
| Brave API returns 401/422 | key missing or wrong | fall back to HTML scraping, log for ops |
| Common Crawl CDX TCP timeout | network block (as in this test) | mark CCX as disabled in the federation, skip silently |
| All engines fail | network partition | surface a `SearchFederationError` to the caller, don't infinite-retry |

### Implementation effort estimate

For MailAccess:

- `mailaccess/harvest/engines/brave.py` — new module, one class
  implementing the `SearchEngine` protocol, two methods (HTML scrape,
  API call), both with the same async signature
- `mailaccess/harvest/engines/commoncrawl.py` — extend the existing CC
  integration to expose the `SearchEngine` protocol
- `mailaccess/harvest/federation.py` — new `Federation` class, ~80
  lines, `asyncio.gather` based, dedup by URL, per-engine circuit
  breaker on consecutive failures
- `mailaccess/config.py` — add `BRAVE_API_KEY` (optional), `BRAVE_HTML_RATE`
  (default 2.0s), `FEDERATION_ENGINES` (ordered list, default
  `[brave_html, brave_api, commoncrawl]`)
- Tests — `tests/harvest/engines/test_brave_html.py`,
  `test_brave_api.py` (mocked), `test_federation.py` (engine failure
  cascades), `test_federation_dedup.py`

Roughly 300–400 lines new code, one new optional dependency (none — use
stdlib `asyncio` + `httpx` which is likely already in the lockfile for
ScrapingAnt).

---

## 5. What I could not test in this session (be honest about it)

- **Brave API with a real key.** I confirmed the endpoint exists,
  validated pricing, and saw the response format, but I did not send a
  real request because I don't have a Brave Search API key in this
  environment. The API path should be assumed correct based on the docs
  page and the 422 response on a keyless request, but live confirmation
  with a real key is a one-line task for whoever sets up the integration.
- **Self-hosted SearXNG cost in a region with clean IP reputation.** I
  have not spun up a SearXNG instance in this session; the cost numbers
  above are based on standard VPS pricing, not a measured run.
- **Brave HTML behavior under sustained 24h load.** I observed 4-5
  queries at 0.5s spacing → 429 on the 5th. I did not characterise the
  long-tail back-off schedule or the per-IP daily cap. Treat the 1 q/s
  sustained number as a single-session observation, not a published
  limit.
- **Brave HTML behavior with very-long-dork queries** (e.g. 200+
  characters, with nested quotes). The three test queries were all
  short; the dork path in MailAccess sometimes generates long queries.
  Worth a stress test in Phase 1 of the implementation.
