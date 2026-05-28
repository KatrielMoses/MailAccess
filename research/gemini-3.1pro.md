THINGS TO DO
1. Intelligence X (Phonebook API)

Status: 50 searches/day. Requires free account API key. Hits the restricted free.intelx.io instance.
Code:
python


import httpx
headers = {"x-key": "YOUR_FREE_KEY"}
# 1. Start search
search = httpx.post("https://free.intelx.io/phonebook/search", headers=headers, json={"term": "example.com", "maxresults": 1000}).json()
# 2. Fetch results
results = httpx.get(f"https://free.intelx.io/phonebook/search/result?id={search['id']}", headers=headers).json()
2. Serper.dev (Google Dorking)

Status: 2,500 free queries on sign-up (no CC). Best commercial Google SERP API for "@example.com" dorking.
Code:
python


import httpx
headers = {"X-API-KEY": "YOUR_KEY", "Content-Type": "application/json"}
results = httpx.post("https://google.serper.dev/search", headers=headers, json={"q": '”@example.com”'}).json()
3. Public SearxNG Instances (Unlimited Dorking)

Status: >10,000 queries possible. Free, no key, no CC. Bypasses Google CAPTCHAs by leveraging proxy nodes. Must rotate public instance URLs if rate-limited.
Code:
python


import httpx
# Append &format=json for raw API response
results = httpx.get("https://searx.be/search?q=\"@example.com\"&format=json").json()
emails = [res.get('content') for res in results.get('results', [])]
THINGS NOT TO DO
LeakCheck Public API: Do not use for domains. The free tier only allows querying specific usernames/emails, not wildcard domain searches.
Snov.io API: Do not attempt. API access is completely disabled on the free Trial tier (requires manual support approval for testing).
Dehashed / Skrapp: Do not use for free automated OSINT. Dehashed has no free API tier; Skrapp heavily restricts API bulk domain queries on free plans.
Verifications.io: Dead end. Database was seized/offline.
Scraping Google Directly: Do not use httpx on google.com. Will result in instant IP bans and CAPTCHAs.