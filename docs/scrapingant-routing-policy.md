# ScrapingAnt Routing Policy

> **Scope — what ScrapingAnt is not.**
> ScrapingAnt is not used as a Tor substitute and is never used to obscure
> investigator identity. Tor routing (when configured) is completely separate
> and unaffected by ScrapingAnt settings. ScrapingAnt is reserved for clearnet
> HTTP calls that benefit from IP diversity or browser-like fingerprints. All
> .onion and Tor-routed traffic bypasses ScrapingAnt entirely.

ScrapingAnt is reserved for call sites where the proxy or browser-like request
path materially improves the result. Use call-site granularity: a module can
mix direct and routed traffic when different clients hit different targets.

Route through ScrapingAnt (`zone="platforms"` or `zone="dorking"`) when any of
these are true:

- The target returns HTML whose meaningful content requires JavaScript rendering.
- The target has aggressive anti-bot or IP-based rate limiting, and the response
  carries useful signal.
- The target needs browser-like request fingerprinting that `httpx` cannot
  reasonably reproduce.

Use plain `build_client()` with no zone when all of these are true:

- The target returns JSON or plain text where the response body is the signal.
- No JavaScript rendering is needed for the response to be useful.
- Direct `httpx` access is permissive enough in practice.
- The response is small, structured, and not worth proxying.

Edge cases:

- A small JSON API behind Cloudflare or strict IP rate limits can still keep a
  zone. The proxy benefit is IP access, not rendering.
- A profile-page HTML endpoint that works reliably with direct `httpx` should
  drop the zone.
- Same module, two traffic types means two decisions. Audit the call site, not
  the module name.

## Transport Modes

| Transport | Host | Auth | Settings used | Billing | Best for |
| --- | --- | --- | --- | --- | --- |
| rest_api | api.scrapingant.com/v2/extended | x-api-key query param | scrapingant_api_key | API credits (Enthusiast) | Simple JSON/HTML, no proxy-IP-sensitive targets |
| residential_proxy | residential.scrapingant.com:8080 | HTTP Basic (dashboard user/pass) | scrapingant_proxy_residential_username, scrapingant_proxy_residential_password | GB (Micro) | Anti-bot bypass on residential-IP-blocked targets |
| datacenter_proxy | datacenter.scrapingant.com:8080 | HTTP Basic (dashboard user/pass) | scrapingant_proxy_datacenter_username, scrapingant_proxy_datacenter_password | GB | High-throughput, lower cost than residential |

Transport is selected at runtime. `investigate` can choose per run with
`--use-scraping-api`, `--use-proxies --proxy-type residential`, or
`--use-proxies --proxy-type datacenter`. `harvest-emails` uses
`--use-proxies` and follows the ScrapingAnt transport configured by
`mailaccess configure proxy enable residential|datacenter`; use
`mailaccess configure proxy show` to confirm the active transport and
`mailaccess configure proxy disable` to return to the REST API transport.

## Zone 2 Audited Call Sites

| Module | Function | Call | Target URL pattern | Decision | Reason |
| --- | --- | ---: | --- | --- | --- |
| backend/modules/alternate_email.py | run | 2 | https://www.gravatar.com/{hash}.json | DROP | Gravatar permutation checks are direct JSON/HEAD traffic. |
| backend/modules/breach_deep.py | run | 1 | mixed account-existence/profile endpoints | KEEP | Mixed public probes have anti-bot and fingerprint variance. |
| backend/modules/code_and_cert_email.py | run | 2 | https://crt.sh/?q=%.{domain}&output=json | DROP | crt.sh returns JSON certificate records. |
| backend/modules/code_and_cert_email.py | run | 3 | https://api.certspotter.com/v1/issuances?... | DROP | CertSpotter returns JSON certificate records. |
| backend/modules/commoncrawl_email.py | run | 1 | Common Crawl index plus page fetches | DROP | Index is JSON and fetched pages do not require browser rendering. |
| backend/modules/domain_harvester.py | run | 1 | crt.sh/certspotter/bufferover/run/threatminer collectors | DROP | Subdomain collectors use structured public endpoints. |
| backend/modules/employee_name_discovery.py | _linkedin | 1 | LinkedIn and search-result HTML | KEEP | LinkedIn/search HTML benefits from proxy and browser-like access. |
| backend/modules/employee_name_discovery.py | _company_pages | 1 | public company pages | KEEP | Company-page HTML can have anti-bot variance. |
| backend/modules/fediverse_discovery.py | run | 1 | WebFinger/nodeinfo/instance APIs | DROP | Fediverse discovery uses JSON endpoints. |
| backend/modules/gravatar.py | _run_for_email | 1 | https://www.gravatar.com/{hash}.json | DROP | Gravatar profile data is JSON and avatar fetches are simple. |
| backend/modules/gravatar_lookup.py | run | 1 | https://www.gravatar.com/{hash}.json | DROP | Gravatar lookup endpoint returns JSON. |
| backend/modules/hackernews.py | run | 1 | HN Firebase and Algolia APIs | DROP | Hacker News lookups return JSON. |
| backend/modules/hudson_rock.py | run | 1 | /search-by-email | DROP | Hudson Rock OSINT endpoint returns JSON. |
| backend/modules/hudson_rock.py | search_by_domain | 1 | /search-by-domain | DROP | Hudson Rock domain endpoint returns JSON. |
| backend/modules/hudson_rock.py | search_by_username | 1 | /search-by-username | DROP | Hudson Rock username endpoint returns JSON. |
| backend/modules/keybase.py | run | 1 | https://keybase.io/_/api/1.0/user/lookup.json | DROP | Keybase public lookup API returns JSON. |
| backend/modules/linkedin_serp.py | _ddg_search | 1 | https://html.duckduckgo.com/html/ | KEEP | DuckDuckGo HTML SERP benefits from anti-bot/rate-limit routing. |
| backend/modules/marketplace_profile.py | run | 1 | Etsy/eBay profile HTML | KEEP | Marketplace profile HTML benefits from browser-like access. |
| backend/modules/messaging_hints.py | run | 1 | t.me and wa.me landing pages | DROP | Landing pages are static enough for direct `httpx`. |
| backend/modules/npm_discovery.py | run | 1 | registry.npmjs.org | DROP | npm registry endpoints return JSON. |
| backend/modules/npm_email.py | run | 1 | registry.npmjs.org | DROP | npm registry domain-harvest endpoints return JSON. |
| backend/modules/opencorporates.py | run | 1 | api.opencorporates.com | DROP | OpenCorporates API returns JSON. |
| backend/modules/orcid_lookup.py | run | 1 | pub.orcid.org/v3.0 | DROP | ORCID public API returns JSON. |
| backend/modules/pastebin_search.py | run | 1 | https://psbdmp.ws/api/v3/search/{email} | DROP | psbdmp search returns JSON. |
| backend/modules/pgp_domain_email.py | run | 1 | keys.openpgp.org and keyserver.ubuntu.com | DROP | PGP sources are JSON, text, or static HKP HTML. |
| backend/modules/pgp_keyserver.py | run | 1 | OpenPGP by-email and Ubuntu HKP | DROP | Keyserver responses are key text or static HKP HTML. |
| backend/modules/phone_intel.py | run | 1 | apilayer validate, wa.me, t.me | DROP | Structured validation plus static landing pages do not need proxying. |
| backend/modules/press_intel.py | run | 1 | DuckDuckGo HTML and press-release pages | KEEP | Search and press pages benefit from anti-bot/rate-limit routing. |
| backend/modules/pypi_discovery.py | run | 1 | PyPI search HTML and package JSON | KEEP | PyPI search is HTML; package JSON shares this call-site client. |
| backend/modules/pypi_email.py | run | 1 | PyPI XML-RPC and JSON APIs | DROP | Domain-harvest endpoints are structured. |
| backend/modules/ransomware_intel.py | run | 1 | ransomware feed API | DROP | Feed endpoint returns JSON. |
| backend/modules/sec_edgar.py | run | 1 | SEC submissions API | DROP | SEC submissions endpoint returns JSON. |
| backend/modules/social.py | run | 1 | social platform profile pages | KEEP | Profile HTML can require rendered or anti-bot access. |
| backend/modules/wayback.py | run | 1 | Wayback CDX API | DROP | CDX endpoint returns JSON. |
| backend/modules/whois_lookup.py | _fetch_rdap | 1 | RDAP endpoint | DROP | RDAP endpoint returns JSON. |
