THINGS TO DO (by volume)
1. Hunter.io Domain Search — GET https://api.hunter.io/v2/domain-search — 50 searches/month on free plan, no CC; free plan capped at 10 emails per domain. Dimmo + 2
pythonimport httpx
r = httpx.get("https://api.hunter.io/v2/domain-search",
              params={"domain": "lavellenetworks.com", "api_key": KEY})
emails = [e["value"] for e in r.json()["data"]["emails"]]
2. Serper.dev (Google dorking, real Google index) — POST https://google.serper.dev/search — 2,500 free one-time queries, no CC. Best near-unlimited Google option; nothing free is truly >10k/mo without CC. SourceForgeSerper
pythonimport httpx, re
r = httpx.post("https://google.serper.dev/search",
               headers={"X-API-KEY": KEY, "Content-Type": "application/json"},
               json={"q": '"@lavellenetworks.com"', "num": 100})
emails = set(re.findall(r"[\w.+-]+@lavellenetworks\.com", r.text))
3. Snov.io Domain Search — OAuth POST /v1/oauth/access_token → GET /v2/domain-emails-with-info — 50 credits/month on Trial, 1 credit = 50 emails per domain batch. Snov.io
pythontok = httpx.post("https://api.snov.io/v1/oauth/access_token",
    data={"grant_type":"client_credentials","client_id":CID,"client_secret":CS}).json()["access_token"]
r = httpx.get("https://api.snov.io/v2/domain-emails-with-info",
    params={"domain":"lavellenetworks.com","limit":100,"access_token":tok})
4. Skrapp.io — GET https://api.skrapp.io/api/v3/profile/domain-search — header X-Access-Key, ~100 free/mo.
5. crt.sh — GET https://crt.sh/?q=%25.lavellenetworks.com&output=json — unlimited, no key. Subdomains + occasional emailAddress CN; expands attack surface for steps 1–2.
THINGS NOT TO DO

Intelligence X phonebook — POST /phonebook/search is only available to paid users. Public API keys discontinued. Free key on free.intelx.io only reaches /intelligent/search (returns leak file refs, no parsed emails). Skip it. IntelxGitHub
Dehashed / LeakCheck / Snusbase / IntelligenceSecurity — all paid subscriptions, no usable free tier.
BreachDirectory — RapidAPI "free" plan requires CC on file.
SerpAPI — only 100 free searches/month; Serper beats it. Scrape.do
Scraping google.com directly — CAPTCHA within ~5 requests/IP.
verifications.io — defunct; was a leak source, never had a public API.
Hunter /v2/email-count — free + no auth, but returns counts only, not addresses.