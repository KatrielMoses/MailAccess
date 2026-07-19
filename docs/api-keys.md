# API Keys


| Key | Module | Where to get it | Required? |
|-----|--------|-----------------|-----------|
| `HIBP_API_KEY` | `hibp` | https://haveibeenpwned.com/API/Key | Yes (module skips without it) |
| `SERPAPI_KEY` | `google_dork` | https://serpapi.com | Yes (module skips without it) |
| `SHODAN_API_KEY` | `domain_intel` | https://account.shodan.io | No |
| `EMAILREP_API_KEY` | `emailrep` | https://emailrep.io | No |
| `HUNTER_IO_API_KEY` | `hunter_io` | https://hunter.io | No |
| `GITHUB_TOKEN` | `github_commits` | https://github.com/settings/tokens | No (optional) |
| `COMPANIES_HOUSE_API_KEY` | `companies_house` | https://developer.company-information.service.gov.uk | No (free forever, no CC) |
| `SLACK_WEBHOOK_URL` | Webhooks | https://api.slack.com/messaging/webhooks | No |
| `DISCORD_WEBHOOK_URL` | Webhooks | Discord server settings | No |
| `SCRAPINGANT_API_KEY` | ScrapingAnt (REST API) | https://scrapingant.com/?ref=mzliyzh | No (optional partnership) |
| `SCRAPINGANT_PROXY_RESIDENTIAL_USERNAME` | ScrapingAnt (Residential Proxy) | https://scrapingant.com/?ref=mzliyzh | No |
| `SCRAPINGANT_PROXY_RESIDENTIAL_PASSWORD` | ScrapingAnt (Residential Proxy) | https://scrapingant.com/?ref=mzliyzh | No |
| `SCRAPINGANT_PROXY_DATACENTER_USERNAME` | ScrapingAnt (Datacenter Proxy) | https://scrapingant.com/?ref=mzliyzh | No |
| `SCRAPINGANT_PROXY_DATACENTER_PASSWORD` | ScrapingAnt (Datacenter Proxy) | https://scrapingant.com/?ref=mzliyzh | No |

**ScrapingAnt** (optional, partnership) — Improves reliability of platform checks
and search engine dorking by routing traffic through rotating residential or
datacenter proxies. Off by default.
Sign up: https://scrapingant.com/?ref=mzliyzh

