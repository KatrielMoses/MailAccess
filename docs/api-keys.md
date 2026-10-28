<a href="../README.md">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="../assets/brand/mailaccess-logo-reversed.svg">
    <img src="../assets/brand/mailaccess-logo.svg" alt="MailAccess" height="28">
  </picture>
</a>

# API Keys

Every key is optional. 70 of the 82 modules need no key at all. A module whose
key is missing is skipped, and the run continues without it.

Set a key with `mailaccess keys set <NAME> <value>` (stored in
`~/.mailaccess/.env`), check them with `mailaccess keys list`, test one with
`mailaccess keys test <NAME>` and remove one with `mailaccess keys unset <NAME>`.
For a server, put the same names in `.env` (see [self-hosting.md](self-hosting.md)).

## Your MailAccess key

| Key | Used by | How to get it |
|-----|---------|---------------|
| `MAILACCESS_KEY` | Your MailAccess account key (free or Pro). `harvest-emails` adds the MailAccess Index with it: 5 harvests a day and 30 a month on free, more on Pro. | Run `mailaccess login` (email code, or `--google`). It writes the key to `~/.mailaccess/.env`. `mailaccess logout` removes it. |
| `MAILACCESS_PRO_KEY` | The paid key for the business-contact corpus (`--mode public-business-contact`, `--company`). | Shown once at checkout, and at mailaccess.pro/platform/api-keys. `mailaccess keys set MAILACCESS_PRO_KEY <key>`. |

## Data source keys

| Key | Module | Where to get it | Required? |
|-----|--------|-----------------|-----------|
| `HIBP_API_KEY` | `hibp`, HIBP pastes in `breach_aggregator` | https://haveibeenpwned.com/API/Key | Yes for `hibp` (skips without it) |
| `SERPAPI_KEY` | `google_dork`, `email_discovery`, `linkedin_serp` | https://serpapi.com | Yes for `google_dork` (skips without it) |
| `BREACHDIRECTORY_API_KEY` | `breachdirectory` | https://rapidapi.com (BreachDirectory API) | Yes for `breachdirectory` |
| `INTELX_API_KEY` | `intelx_lookup` | https://intelx.io/signup (free tier) | Yes for `intelx_lookup` |
| `DEHASHED_API_KEY`, `SNUSBASE_API_KEY` | `breach_aggregator` | https://dehashed.com, https://snusbase.com | No (each source skips without its key) |
| `SHODAN_API_KEY` | `shodan`, `domain_intel` | https://account.shodan.io | Yes for `shodan` |
| `EMAILREP_API_KEY` | `emailrep` | https://emailrep.io | No |
| `HUNTER_IO_API_KEY` | `hunter_io` | https://hunter.io | Yes for `hunter_io` |
| `NETLAS_API_KEY` | `netlas_email_footprint`, `netlas_org_surface`, subdomain enumeration | [netlas.io](https://netlas.io) | Yes for the Netlas modules |
| `IPGEOLOCATION_API_KEY` | `ip_intel` (IP geolocation and threat intel) | [ipgeolocation.io](https://ipgeolocation.io/?utm_source=github&utm_medium=referral&utm_campaign=mailaccess) | Yes for `ip_intel` |
| `WHOISFREAKS_API_KEY` | `whoisfreaks_intel` (WHOIS history, reverse WHOIS, dated subdomains) | [whoisfreaks.com](https://whoisfreaks.com/?utm_source=github&utm_medium=referral&utm_campaign=mailaccess) | Yes for `whoisfreaks_intel` |
| `OXYLABS_SEARCH_TOKEN` | `social_discovery` (Instagram, Facebook and LinkedIn profiles) | https://oxylabs.io (Web Search API) | Yes for `social_discovery` |
| `GITHUB_TOKEN` | `github_commits` | https://github.com/settings/tokens | No (raises the rate limit) |
| `COMPANIES_HOUSE_API_KEY` | `companies_house` | https://developer.company-information.service.gov.uk | Yes for `companies_house` (free, no card) |
| `GOOGLE_CSE_API_KEY`, `GOOGLE_CSE_CX` | `email_search_dork` | https://programmablesearchengine.google.com | No |

Netlas, ipgeolocation.io and WhoisFreaks also have their own commands:
`mailaccess netlas set-key|test|status|enable|disable`, and the same for
`mailaccess ipgeo` and `mailaccess whoisfreaks`.

## Google profile enrichment (operator credential)

`google_account_intel` always returns the MX and domain signal with no
credential. Profile name and photo enrichment needs an operator Google
account, stored as `GOOGLE_MASTER_TOKEN` and `GOOGLE_MASTER_EMAIL`. Set both
with `mailaccess google-auth --email <operator-account>` and follow the
prompt. Without them, enrichment returns nothing. Use a dedicated account you
control, never a subject's account.

## Notifications

| Key | Used by | Where to get it |
|-----|---------|-----------------|
| `SLACK_WEBHOOK_URL` | Webhooks | https://api.slack.com/messaging/webhooks |
| `DISCORD_WEBHOOK_URL` | Webhooks | Discord server settings |

## Proxy routing (optional)

| Key | Used by |
|-----|---------|
| `SCRAPINGANT_API_KEY` | ScrapingAnt REST API transport |
| `SCRAPINGANT_PROXY_RESIDENTIAL_USERNAME`, `SCRAPINGANT_PROXY_RESIDENTIAL_PASSWORD` | ScrapingAnt residential proxy |
| `SCRAPINGANT_PROXY_DATACENTER_USERNAME`, `SCRAPINGANT_PROXY_DATACENTER_PASSWORD` | ScrapingAnt datacenter proxy |

ScrapingAnt routes platform checks and search dorking through rotating
residential or datacenter proxies. Off by default. Manage it with
`mailaccess configure proxy enable residential|datacenter` and
`mailaccess configure proxy disable`. For other proxy providers, see
`EGRESS_PROXIES` in [self-hosting.md](self-hosting.md). Proxy partners are
listed on [sponsors.md](sponsors.md).
