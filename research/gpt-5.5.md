THINGS TO DO

Common Crawl: GET /collinfo.json, GET /{idx}-index, GET data.commoncrawl.org/{filename}; headers User-Agent, Range; params url=*.domain/*&output=json&filter=mime:text/html.
r=httpx.get(f"https://index.commoncrawl.org/{idx}-index",params={"url":f"*.{d}/*","output":"json","filter":"mime:text/html"})
GitHub code search: GET https://api.github.com/search/code; headers Authorization: Bearer TOKEN, Accept: application/vnd.github.text-match+json; params q='"@domain.com" in:file',per_page=100.
r=httpx.get("https://api.github.com/search/code",headers=h,params={"q":f'"@{d}" in:file',"per_page":100})
Google CSE: GET https://customsearch.googleapis.com/customsearch/v1; params key,cx,q,num,start; use “search entire web”.
r=httpx.get("https://customsearch.googleapis.com/customsearch/v1",params={"key":K,"cx":CX,"q":f'"@{d}"',"num":10})
Intelligence X Phonebook: yes usable free API; key required; free.intelx.io; limits: 200 results/bucket, 5 concurrent, 1-min timeout, 3-min result retention; daily credits shown in account.
s=httpx.post("https://free.intelx.io/phonebook/search",headers={"X-Key":K},params={"term":d,"target":0,"maxresults":200,"timeout":60,"media":0}).json()
r=httpx.get("https://free.intelx.io/phonebook/search/result",headers={"X-Key":K},params={"id":s["id"],"l":200})
Hunter: GET https://api.hunter.io/v2/domain-search; params domain,api_key,limit,offset; free = 50 credits, free users capped to first 10.
r=httpx.get("https://api.hunter.io/v2/domain-search",params={"domain":d,"api_key":K,"limit":10})
THINGS NOT TO DO

Verifications.io: defunct since 2019; no API.
DeHashed: paid/API credits; no free no-card domain API.
Snov.io: free count endpoint only; email API needs credits/test access/demo.
BreachDirectory/LeakCheck/Skrapp/Snusbase: not free no-card high-volume domain email sources.
SerpAPI/Serper/SearchApi/DataForSEO/Oxylabs: no free >10k/month Google-index tier; SerpAPI 250/mo, Serper 2,500 trial, SearchApi 100 trial, DataForSEO $1 credit.