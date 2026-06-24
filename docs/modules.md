# Module Reference

MailAccess ships 55 modules covering 2500+ platforms. Modules are auto-discovered from `backend/modules/` at startup. Each module runs concurrently with all others, subject to `MAX_CONCURRENT_MODULES` and `MODULE_TIMEOUT_SECONDS`.

A module marked **key required** skips itself with `status: skipped` when its API key is absent — it does not cause the investigation to fail.

---

## `pgp_keyserver`

Search public PGP keyservers for keys tied to the target email and extract real names from UID packets.

| | |
|--|--|
| **Requires key** | No |
| **Default** | On |
| **Rate limit** | 1 request / second |
| **Name weight** | 1.00 |
| **Hit rate** | ~8-12% for technical/developer targets |
| **Status** | Implemented |

Checks `keys.openpgp.org` first, then falls back to `keyserver.ubuntu.com` when no OpenPGP.org key is found. A missing key returns `success` with no findings.

**Finding schema:**
```json
{
  "platform": "pgp_keyserver",
  "profile_url": "https://keys.openpgp.org/search?q=jane@example.com",
  "confidence": "high",
  "metadata": {
    "uid_name": "Jane Doe",
    "uid_email": "jane@example.com",
    "key_id": "ABCDEF1234567890",
    "key_fingerprint": "0123456789ABCDEF0123456789ABCDEF12345678",
    "key_created": "2022-01-01",
    "key_algorithm": "RSAEncryptOrSign",
    "source": "openpgp",
    "all_uids": ["Jane Doe <jane@example.com>"]
  }
}
```

`uid_name` feeds the Name Consensus Engine as a cryptographic source with weight `1.00`.

**Finding fields:** `uid_name`, `key_id`, `key_fingerprint`, `key_created`, `key_algorithm`, `source`, `all_uids`.

---

## `orcid_lookup`

Search public ORCID records for researcher identities tied to the target email.

| | |
|--|--|
| **Requires key** | No |
| **Default** | On |
| **Rate limit** | 2 requests / second |
| **Name weight** | 0.95 |
| **Hit rate** | ~5% for researchers and academics |
| **Status** | Implemented |

Uses the unauthenticated ORCID public API to search by email, then fetches each matching `/person` record. Biography text is scanned for phone numbers and additional email addresses.

**Finding schema:**
```json
{
  "platform": "orcid_profile",
  "profile_url": "https://orcid.org/0000-0000-0000-0000",
  "confidence": "high",
  "metadata": {
    "orcid_id": "0000-0000-0000-0000",
    "given_name": "Jane",
    "family_name": "Doe",
    "full_name": "Jane Doe",
    "credit_name": null,
    "biography": "Researcher biography...",
    "researcher_urls": ["https://example.edu/~jane"],
    "additional_emails": ["jane@university.edu"]
  }
}
```

Additional public emails are emitted as `alternate_email` findings. `full_name` or `credit_name` feeds the Name Consensus Engine as an institutional source with weight `0.95`.

**Finding fields:** `orcid_id`, `given_name`, `family_name`, `full_name`, `credit_name`, `biography`, `researcher_urls`, `additional_emails`.

---

## `hackernews`

Check Hacker News profiles for usernames derived from the target email local-part.

| | |
|--|--|
| **Requires key** | No |
| **Default** | On |
| **Rate limit** | 1 request / second per username |
| **Name weight** | 0.35 |
| **Status** | Implemented |

Checks up to three username variants against the Firebase Hacker News API and falls back to Algolia user lookup. Profile `about` text is scanned for names, emails, phones, and linked URLs.

**Finding schema:**
```json
{
  "platform": "hackernews_profile",
  "profile_url": "https://news.ycombinator.com/user?id=janedoe",
  "confidence": "medium",
  "metadata": {
    "username": "janedoe",
    "about": "I'm Jane Doe...",
    "karma": 1200,
    "member_since": "2018-04-10",
    "extracted_name": "Jane Doe",
    "linked_urls": ["https://github.com/janedoe"]
  }
}
```

`extracted_name` feeds the Name Consensus Engine as a social source with weight `0.35`.

**Finding fields:** `username`, `about`, `karma`, `member_since`, `extracted_name`, `linked_urls`.

---

## `xposedornot`

Query XposedOrNot's public breach corpus for direct email-to-breach associations.

| | |
|--|--|
| **Requires key** | No |
| **Default** | On |
| **Rate limit** | 1 request / second |
| **Status** | Implemented |

This module is free and does not require any API key. It calls both public XposedOrNot endpoints:
- `GET /v1/check-email/{email}` for the direct breach association lookup
- `GET /v1/breach-analytics?email={email}` for per-breach metadata and risk context

It returns one finding per breach with canonical breach name, exposed data classes, and risk indicators. Findings are normalized later with other breach sources, so the same breach from XposedOrNot and HIBP becomes a single canonical finding with `sources` attribution.

**Finding shape:**
```json
{
  "platform": "XposedOrNot",
  "source": "xposedornot",
  "confidence": "high",
  "severity": "critical",
  "metadata": {
    "breach_name": "SweClockers",
    "breach_id": "SweClockers",
    "domain": "sweclockers.com",
    "breached_date": "2015-01-01",
    "industry": "Electronics",
    "exposed_records": 254967,
    "data_classes": ["Email addresses", "Usernames", "Passwords"],
    "risk": "critical",
    "risk_indicators": {
      "password_risk": "hardtocrack",
      "searchable": true,
      "verified": true,
      "sensitive": false
    },
    "direct_match": true,
    "source_module": "xposedornot"
  }
}
```

**Module metadata:**
```json
{
  "breaches_found": 2,
  "direct_breaches": ["SweClockers", "Tesco"],
  "analytics_breaches": ["SweClockers", "Tesco"],
  "all_data_classes": ["Email addresses", "Passwords", "Usernames"],
  "risk_label": "Low",
  "risk_score": 3,
  "yearwise_details": {
    "y2015": 1,
    "y2020": 0
  },
  "direct_response": {},
  "analytics_response": {}
}
```

Rate-limit responses return `status: partial` with a retry hint.

---

## `leakcheck`

Query LeakCheck's public breach corpus for direct email-to-breach associations.

| | |
|--|--|
| **Requires key** | No |
| **Default** | On |
| **Rate limit** | 1 request / 2 seconds |
| **Status** | Implemented |

This module is free and does not require any API key. It calls the public LeakCheck endpoint:
- `GET https://leakcheck.io/api/public?check={email}`

It returns one finding per breach with the breach name. Findings are normalized later with other breach sources, so the same breach from LeakCheck, XposedOrNot and HIBP becomes a single canonical finding with `sources` attribution. Regional breach lists that XposedOrNot misses are still surfaced here, and generic source labels are routed to the stealer signal path instead of the breach count.

**Finding shape:**
```json
{
  "platform": "000webhost",
  "source": "leakcheck",
  "confidence": "high",
  "severity": "medium",
  "breach_name": "000webhost",
  "metadata": {
    "breach_name": "000webhost",
    "source_module": "leakcheck"
  }
}
```

**Module metadata:**
```json
{
  "email": "test@example.com",
  "sources_found": 1,
  "breach_names": ["000webhost"]
}
```

Rate-limit responses return `status: partial` with a clear message.

---

## `ransomware_intel`

Check whether the email domain appears in ransomware victim lists.

| | |
|--|--|
| **Requires key** | No |
| **Default** | On |
| **Scope** | Domain-level signal |
| **Status** | Implemented |

This module is free, requires no API key, and skips free email providers. It correlates the target domain against ransomware victim lists sourced from `ransomware.live` and `ransomlook.io`.

**Finding shape:**
```json
{
  "platform": "RansomwareIntel",
  "source": "ransomware_intel",
  "signal_type": "ransomware_victim_domain",
  "confidence": "medium",
  "severity": "high",
  "metadata": {
    "domain": "example.com",
    "group_name": "Example Gang",
    "attack_date": "2025-01-01",
    "note": "Domain-level victim signal"
  }
}
```

**Module metadata:**
```json
{
  "domain_checked": "example.com",
  "victim_found": true,
  "ransomware_group": "Example Gang",
  "attack_date": "2025-01-01",
  "is_free_provider": false
}
```

---

## `hibp`

Check if the email address appears in known data breaches via the HaveIBeenPwned v3 API.

| | |
|--|--|
| **Requires key** | Yes — `HIBP_API_KEY` |
| **Status** | Implemented |

**Findings schema (one per breach):**
```json
{
  "platform": "HaveIBeenPwned",
  "url": "https://haveibeenpwned.com/PwnedWebsites#Adobe",
  "metadata": {
    "name": "Adobe",
    "domain": "adobe.com",
    "breach_date": "2013-10-04",
    "description": "...",
    "data_classes": ["Email addresses", "Passwords"],
    "is_sensitive": false,
    "is_verified": true,
    "pwn_count": 152445165,
    "severity": "critical"
  },
  "confidence": "high"
}
```

Severity is derived from `data_classes`: `critical` if passwords or financial data are present, `high` if phone numbers or addresses, `medium` otherwise.

**Module metadata:**
```json
{
  "total_breaches": 3,
  "breach_dates": "2013-10-04 to 2023-01-01",
  "most_critical_breach": "Adobe",
  "all_data_classes": ["Email addresses", "Passwords"]
}
```

---

## `emailrep`

Query EmailRep.io for a reputation score, risk flags, and linked profiles.

| | |
|--|--|
| **Requires key** | No (a key raises the rate limit — set `EMAILREP_API_KEY` if querying at volume) |
| **Status** | Implemented |

**Findings schema (one finding per investigation):**
```json
{
  "platform": "emailrep",
  "confidence": "high",
  "severity": "high",
  "metadata": {
    "reputation": "high",
    "suspicious": false,
    "references": 12,
    "blacklisted": false,
    "malicious_activity": false,
    "credentials_leaked": true,
    "data_breach": true,
    "last_seen": "2024-01-15",
    "spam": false,
    "free_provider": true,
    "disposable": false,
    "profiles": ["twitter", "linkedin"]
  }
}
```

---

## `gravatar`

Look up Gravatar and Libravatar profiles linked to the email address.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

The email is hashed with MD5 (Gravatar standard). If a profile exists, the finding includes the display name, thumbnail URL, and any linked third-party accounts the user has added to their Gravatar profile.

**Findings schema:**
```json
{
  "platform": "Gravatar",
  "url": "https://www.gravatar.com/abc123",
  "metadata": {
    "display_name": "Jane Doe",
    "thumbnail_url": "https://www.gravatar.com/avatar/abc123",
    "profile_url": "https://www.gravatar.com/abc123",
    "accounts": [...],
    "location": "San Francisco",
    "verified_accounts": [...]
  },
  "confidence": "high"
}
```

A Libravatar finding (confidence `low`) is added if an avatar is hosted there.

---

## `google_dork`

Run Google dork queries via SerpAPI to surface public mentions of the email address.

| | |
|--|--|
| **Requires key** | Yes — `SERPAPI_KEY` |
| **Status** | Implemented |

Runs 5 dork templates concurrently:
- `site:linkedin.com "{email}"`
- `site:github.com "{email}"`
- `"{email}" site:pastebin.com`
- `"{email}" filetype:pdf OR filetype:csv OR filetype:xlsx`
- `intext:"{email}" -site:linkedin.com -site:github.com`

Up to 5 results per dork are returned as findings with platform inferred from the URL.

**Module metadata:**
```json
{
  "total_results_found": 8,
  "dorks_run": 5,
  "dorks_with_hits": 3
}
```

---

## `email_discovery`

Post-primary module that dorks for other email addresses owned by the same person, using real names recovered by GHunt, Gravatar, WHOIS, breach metadata, social findings, or EmailRep.

| | |
|--|--|
| **Gate** | `ENABLE_EMAIL_DISCOVERY=true` (default) |
| **Requires key** | Yes - `SERPAPI_KEY` |
| **Runs** | Post-primary; needs a name from primary modules |
| **Skips** | Automatically if no name was recovered |
| **Status** | Implemented |

Enabled by default (`ENABLE_EMAIL_DISCOVERY=true`) and self-gating: it skips when `SERPAPI_KEY` is missing or no usable real name was recovered. It does not recursively investigate discovered addresses.

For up to 3 recovered names, it runs these SerpAPI dorks concurrently:
- `"{full_name}" "@gmail.com" OR "@outlook.com" OR "@yahoo.com" OR "@protonmail.com"`
- `"{full_name}" "email" OR "contact" -site:linkedin.com -site:facebook.com`
- `"{full_name}" "@" filetype:pdf OR filetype:csv`
- `site:linkedin.com "{full_name}" "{domain}"` for corporate target domains only

**Finding example:**
```json
{
  "platform": "email_discovery",
  "profile_url": "https://docs.example.com/team",
  "confidence": "high",
  "metadata": {
    "discovered_email": "jane.doe@example.net",
    "source_name": "Jane Doe",
    "source_url": "https://docs.example.com/team",
    "snippet": "contact Jane at jane.doe@example.net",
    "dork_used": "contact_terms"
  }
}
```

**Finding fields:** `discovered_email`, `source_name`, `source_url`, `snippet`, `dork_used`.

**Module metadata:**
```json
{
  "names_searched": 1,
  "dorks_run": 4,
  "emails_discovered": 1,
  "discovered_emails": ["jane.doe@example.net"]
}
```

Metadata fields: `names_searched`, `dorks_run`, `emails_discovered`, `discovered_emails`.

---

## `wayback`

Search the Internet Archive Wayback Machine CDX API for archived pages mentioning the email address, then enrich the top results with archived page title and nearby context.

| | |
|--|--|
| **Gate** | None; always runs |
| **Requires key** | No |
| **Status** | Implemented |

This module runs a bounded CDX search and fetches archived page content for only the top 5 pages to avoid hammering Wayback. A `429` from the archive returns `status: partial`.

**Findings schema (one per archived page):**
```json
{
  "platform": "wayback_machine",
  "profile_url": "https://web.archive.org/web/20190101120000/https://example.com/contact",
  "confidence": "high",
  "metadata": {
    "original_url": "https://example.com/contact",
    "archive_date": "2019-01-01",
    "page_title": "Contact",
    "context_snippet": "...contact jane@example.com for...",
    "original_domain": "example.com",
    "years_ago": 7
  }
}
```

**Finding fields:** `original_url`, `archive_date`, `page_title`, `context_snippet`, `original_domain`, `years_ago`.

**Module metadata:**
```json
{
  "pages_found": 4,
  "earliest_mention": "2019-01-01",
  "latest_mention": "2023-06-15",
  "unique_domains": ["example.com", "forum.example.net"],
  "oldest_domain": "example.com"
}
```

Metadata fields: `pages_found`, `earliest_mention`, `latest_mention`, `unique_domains`, `oldest_domain`.

---

## `github_commits`

Search public GitHub commits for the target email as an author, plus a GitHub user search fallback for public profile emails.

| | |
|--|--|
| **Gate** | None; always runs |
| **Requires key** | No (`GITHUB_TOKEN` optional for higher rate limits) |
| **Status** | Implemented |

> **GITHUB_TOKEN is required for commit author-email search.** Without it the module returns `PARTIAL` and runs the user profile search fallback only. Set via:
> ```
> mailaccess keys set GITHUB_TOKEN your-token
> ```

Unauthenticated requests are limited to 10 req/min. With `GITHUB_TOKEN`, the limit rises to 30 req/min.

**Commit finding schema:**
```json
{
  "platform": "github_commit",
  "profile_url": "https://github.com/owner/repo/commit/abc1234...",
  "confidence": "high",
  "metadata": {
    "repo": "owner/repo",
    "repo_url": "https://github.com/owner/repo",
    "commit_sha": "abc1234",
    "commit_message": "Fix authentication bug",
    "author_name": "Jane Doe",
    "commit_date": "2022-03-10T12:34:56Z",
    "repo_stars": 142,
    "repo_language": "Python"
  }
}
```

**Finding fields:** `repo`, `repo_url`, `commit_sha`, `commit_message`, `author_name`, `commit_date`, `repo_stars`, `repo_language`.

**GitHub user finding schema:**
```json
{
  "platform": "github_user",
  "profile_url": "https://github.com/janedoe",
  "confidence": "high",
  "metadata": {
    "login": "janedoe",
    "name": "Jane Doe",
    "bio": "Security engineer",
    "public_repos": 24,
    "followers": 180,
    "avatar_url": "https://avatars.githubusercontent.com/u/..."
  }
}
```

**Module metadata:**
```json
{
  "commits_found": 3,
  "repos_contributed_to": ["owner/repo"],
  "real_name_from_git": "Jane Doe",
  "earliest_commit": "2021-11-01T09:00:00Z",
  "latest_commit": "2023-04-12T18:30:00Z",
  "primary_language": "Python",
  "github_user_found": true
}
```

Metadata fields: `commits_found`, `repos_contributed_to`, `real_name_from_git`, `earliest_commit`, `latest_commit`, `primary_language`, `github_user_found`.

---

## `domain_intel`

WHOIS registration data, DNS security signals (SPF / DMARC / MX), website presence, and optionally Shodan host data for the email's domain.

| | |
|--|--|
| **Requires key** | No (Shodan lookup is added automatically when `SHODAN_API_KEY` is set) |
| **Status** | Implemented |

Skips free email providers (Gmail, Outlook, ProtonMail, etc.) — these are not worth querying for domain ownership.

Runs four checks concurrently: WHOIS, DNS, website HTTP fetch, and (if a Shodan key is present) Shodan subdomain and port data.

**Findings:** One finding per check (`whois`, `dns`, `website`, `shodan`), each with `platform` set to the check name.

**DNS finding example:**
```json
{
  "platform": "dns",
  "confidence": "high",
  "metadata": {
    "mx_records": ["aspmx.l.google.com"],
    "mx_provider": "google",
    "spf_record": "v=spf1 include:_spf.google.com ~all",
    "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "has_spf": true,
    "has_dmarc": true,
    "a_records": ["93.184.216.34"],
    "ns_records": ["ns1.example.com"]
  }
}
```

---

## `dns_lookup`

Real DNS resolution for the email's domain: MX, SPF, DMARC, DKIM, A, and NS records. Always runs — no API key required and no opt-in flag.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

**Findings schema:**
```json
{
  "platform": "dns_lookup",
  "confidence": "high",
  "metadata": {
    "mx_records": ["aspmx.l.google.com"],
    "mx_provider": "google",
    "spf_record": "v=spf1 include:_spf.google.com ~all",
    "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "dkim_record": "v=DKIM1; k=rsa; p=...",
    "has_spf": true,
    "has_dmarc": true,
    "has_dkim": true,
    "a_records": ["93.184.216.34"],
    "ns_records": ["ns1.example.com"]
  }
}
```

---

## `whois_lookup`

Full WHOIS registration data for the email's domain. Skips free email providers (Gmail, Outlook, ProtonMail, etc.) and detects privacy-shield registrations.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

> **Supports IANA-managed domains** via raw socket fallback to `whois.iana.org`. Returns `PARTIAL` if the primary parser fails but the fallback succeeds. Only `FAILED` on a network error.

**Findings schema:**
```json
{
  "platform": "whois_lookup",
  "confidence": "high",
  "metadata": {
    "registrar": "Namecheap, Inc.",
    "registered": "2015-03-12",
    "expires": "2027-03-12",
    "updated": "2024-01-05",
    "name_servers": ["ns1.example.com"],
    "privacy_protected": false,
    "registrant_org": "Acme Corp",
    "registrant_country": "US"
  }
}
```

When the domain uses a privacy shield, `privacy_protected` is `true` and registrant fields are omitted.

RDAP vCards and raw WHOIS registrant fields are also scanned for registrant phone numbers on non-free-provider domains. The most useful post-GDPR registrars and TLDs are `.io`, `.co.uk`, `.de`, `.com.au`, `.ca`, and `.nz`. The module returns `PARTIAL` if RDAP returns phone data but WHOIS is privacy-protected.

**Phone finding schema:**
```json
{
  "platform": "whois_phone",
  "signal_type": "phone_number",
  "confidence": "medium",
  "metadata": {
    "phone": "+14155550123",
    "source": "rdap",
    "registrar": "Example Registrar",
    "domain": "example.com"
  }
}
```

---

## `press_intel`

Opt-in search of public press release archives for contact phones tied to a business email domain. Skips free email providers.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented, opt-in (`-m press_intel`) |

Searches DuckDuckGo HTML results for PR Newswire, Business Wire, and GlobeNewswire mentions of the domain, then fetches up to three press releases and extracts contact-block phone numbers.

**Findings schema:**
```json
{
  "platform": "press_release",
  "signal_type": "phone_number",
  "confidence": "medium",
  "metadata": {
    "phone": "+14155550123",
    "contact_name": "Media Contact Jane Doe",
    "source_url": "https://www.prnewswire.com/news-releases/example.html",
    "press_release_title": "Example Corp Announces ..."
  }
}
```

**Finding fields:** `phone`, `contact_name`, `source_url`, `press_release_title`.

---

## `sec_edgar`

Searches SEC EDGAR full-text filings for phone numbers near the email domain. Skips free email providers.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Fetches up to three filing documents from EDGAR search results and scans paragraphs containing the target domain.

**Findings schema:**
```json
{
  "platform": "sec_edgar",
  "signal_type": "phone_number",
  "confidence": "medium",
  "metadata": {
    "phone": "+14155550123",
    "company_name": "EXAMPLE CORP",
    "filing_type": "10-K",
    "filing_url": "https://www.sec.gov/Archives/...",
    "context": "Investor relations example.com +1 415 555 0123"
  }
}
```

---

## `companies_house`

Looks up UK company registration data from Companies House. Requires `COMPANIES_HOUSE_API_KEY` and skips free email providers.

| | |
|--|--|
| **Requires key** | Yes (`COMPANIES_HOUSE_API_KEY`) |
| **Default** | Runs when key set or for `.co.uk` / `.uk` domains |
| **Status** | Implemented |

The API key is free and does not require a credit card. Set it in `.env` to enable the module.

**Findings schema:**
```json
{
  "platform": "companies_house",
  "signal_type": "company_registration",
  "confidence": "medium",
  "metadata": {
    "company_name": "Example Ltd",
    "company_number": "12345678",
    "registered_address": "1 Example Street, London, EC1A 1BB",
    "officers": [{"name": "JANE DOE", "role": "director"}],
    "company_status": "active"
  }
}
```

**Finding fields:** `company_name`, `company_number`, `registered_address`, `officers`, `company_status`.

---

## `social`

Check account existence across 13 social and productivity platforms.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Platforms checked: GitHub, Duolingo, Spotify, Gravatar (linked accounts), Adobe, Patreon, Snapchat, Skype / Microsoft, Zoom, Dropbox, Apple ID, LinkedIn, Discord.

Detection methods vary by platform — some use public search APIs (GitHub), others infer existence from password-reset or registration flows. Confidence is `high` for direct API matches and `medium` / `low` for inferred results.

**Finding example:**
```json
{
  "platform": "GitHub",
  "profile_url": "https://github.com/janedoe",
  "metadata": {
    "login": "janedoe",
    "name": "Jane Doe",
    "bio": "...",
    "location": "San Francisco",
    "public_repos": 24,
    "followers": 180
  },
  "confidence": "high"
}
```

> LinkedIn, Snapchat, and several others aggressively block automated requests. These findings carry `medium` or `low` confidence and may be absent entirely when the platform changes its behavior.

---

## `social_links`

Derives username variations from the target email (local part, display names from prior findings) and feeds them into `username_pivot`. Also probes links extracted from social profile bios and cross-references them across modules.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Runs in the primary phase alongside other modules. Findings are username candidates — they are not independent confirmations but signals passed to `username_pivot` for validation.

**Module metadata:**
```json
{
  "usernames_derived": ["janedoe", "jane.doe", "jdoe"],
  "source_modules": ["gravatar", "social"],
  "links_extracted": 3
}
```

---

## `account_discovery`

Check account existence across 120+ platforms powered by [Holehe](https://github.com/megadose/holehe).

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Platform coverage is dynamic — as Holehe adds new platforms upstream, this module picks them up automatically on the next install. See the [Holehe repository](https://github.com/megadose/holehe) for the current full platform list.

Enable via `ENABLE_ACCOUNT_DISCOVERY=true` (opt-in — runs 120+ probes, expect 30–60 s per investigation).

**Finding example (account confirmed):**
```json
{
  "platform": "twitter",
  "profile_url": "https://twitter.com",
  "metadata": {
    "email_recovery": "j***@gmail.com",
    "high_value": true
  },
  "confidence": "high",
  "source": "account_discovery"
}
```

Findings with `email_recovery` or `phone_hint` in metadata are flagged `high_value: true` — these reveal partial contact details useful for cross-module correlation.

**Module metadata:**
```json
{
  "platforms_checked": 124,
  "platforms_confirmed": 3,
  "platforms_rate_limited": 2,
  "platforms_not_found": 119,
  "holehe_version": "1.61"
}
```

---

## `whatsmyname`

Username enumeration across 700+ platforms via the [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) dataset.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Opt-in (`ENABLE_WHATSMYNAME=true`) because the sweep fires one HTTP request per platform and takes 60–90 seconds. The dataset is fetched from GitHub on first run and cached locally at `data/cache/wmn-data.json` for 24 hours.

**Finding example (account confirmed):**
```json
{
  "platform": "HackerNews",
  "profile_url": "https://news.ycombinator.com/user?id=janedoe",
  "metadata": { "category": "tech" },
  "confidence": "high"
}
```

**Module metadata:**
```json
{
  "total_platforms_checked": 800,
  "platforms_confirmed": 4,
  "platforms_not_found": 705,
  "platforms_errored": 3,
  "wmn_version": "1.4.0"
}
```

---

## `maigret_platforms`

Native platform checking engine using Maigret's MIT-licensed platform database. It checks 2500+ platforms via MailAccess's own `httpx` engine, with no Maigret runtime dependency.

| | |
|--|--|
| **Requires key** | No |
| **Default** | On |
| **Disable** | `ENABLE_MAIGRET_PLATFORMS=false` (only if investigation speed is a priority) |
| **Wave 2** | `ENABLE_MAIGRET_WAVE2=true` for additional slower and more fragile platforms |
| **Runtime** | ~35-90s for Wave 1, plus ~90-150s for Wave 2 |
| **Platform database** | Fetched from Maigret GitHub and cached 24h at `~/.mailaccess/cache/maigret-data.json` |
| **Custom additions** | `data/mailaccess-extra-sites.json` |
| **Status** | Implemented, opt-in |

Wave 1 covers roughly 1500 fast and reliable platforms: `status_code` checks, no bot protection, and higher Alexa rank. Wave 2 adds roughly 1000 slower, protected, regional, or message-based platforms.

Before the sweep, MailAccess validates the top 50 `status_code` platforms against known-unclaimed usernames. Sites that return hits for non-existent users are treated as catch-alls and excluded from results.

**Phase 6D auto-demotion / auto-upgrade** — before each investigation, the
module consults `platform_health.get_skip_set()`, `get_demote_set()`, and
`get_upgrade_set()` to apply self-healing adjustments based on rolling probe
stats:

- **Skip**: a platform in the skip set is excluded entirely from the current
  investigation's probe queue. The platform is *not* permanently disabled —
  it is re-evaluated next investigation.
- **Demote**: a Wave-1 platform in the demote set is routed to Wave 2 for the
  current investigation.
- **Upgrade**: a Wave-2 platform in the upgrade set is routed to Wave 1 for
  the current investigation.

Every applied action is logged to `~/.mailaccess/platform_demotion.log` and
surfaced in `mailaccess platform-audit` output as `[AUTO-DEMOTED]`. To force
a specific platform to run in its native wave regardless of health stats, set
`MAIGRET_FORCE_<PLATFORM>=true` (mapping rule: strip non-alphanumerics,
uppercase, prefix with `MAIGRET_FORCE_`).

Username variants used by default:
- raw local-part, such as `katriel.moses`
- separators stripped, such as `katrielmoses`
- underscore separator, such as `katriel_moses`

**Finding schema:**
```json
{
  "platform": "Example",
  "profile_url": "https://example.com/katriel.moses",
  "username": "katriel.moses",
  "confidence": "high",
  "tags": ["social"],
  "check_type": "status_code",
  "wave": 1,
  "alexa_rank": 12345,
  "dual_confirmed": true,
  "sources": ["wmn", "maigret"]
}
```

**Module metadata:**
```json
{
  "sites_loaded": 2500,
  "wave1_probes": 1500,
  "wave2_probes": 0,
  "catchalls_excluded": 12,
  "platforms_confirmed": 5,
  "platforms_not_found": 1480,
  "platforms_errored": 3,
  "username_variants_used": ["katriel.moses", "katrielmoses", "katriel_moses"],
  "dual_confirmed": 2,
  "unique_platforms": 5
}
```

Finding fields: `platform`, `profile_url`, `username`, `confidence`, `tags`, `check_type`, `wave`, `alexa_rank`, `dual_confirmed`, `sources`.

---

## `sherlock_platforms`

Native Sherlock platform engine covering approximately 300 platforms. It uses
a loader-and-detector pattern with no Sherlock runtime dependency, requires no
API key, runs by default, and has `SOURCE_PRIORITY` 4.

## `nexfil_platforms`

Native Nexfil platform engine covering approximately 300 platforms. It uses a
loader-and-detector pattern with no Nexfil runtime dependency, requires no API
key, runs by default, and has `SOURCE_PRIORITY` 4.

## `blackbird_platforms`

Native Blackbird platform engine focused on social platforms. It uses a
loader-and-detector pattern with no Blackbird runtime dependency, requires no
API key, runs by default, and has `SOURCE_PRIORITY` 4.

## Platform Deduplication

When multiple modules find the same platform, MailAccess deduplicates by normalized profile URL domain, such as `github.com`, not by display name.

Rules:
- Same domain from WMN + Maigret becomes one finding with `sources: ["wmn", "maigret"]` and `confidence: "high"`
- Same domain from any two modules is merged
- `api.*` subdomains are canonicalized to the root domain, such as `api.github.com` to `github.com`

Metadata reported per investigation:
- `wmn_hits`: raw WMN platform count
- `maigret_hits`: raw Maigret platform count
- `dual_confirmed`: platforms found by both
- `unique_platforms`: deduplicated count used in the headline

### Platform Dedup Priority

When engines overlap, the lowest priority number supplies the canonical finding:

| Priority | Source | Reason |
|----------|--------|--------|
| 0 | `whatsmyname`, `wmn` | Most strictly vetted |
| 1 | `holehe` | Registration-probe accuracy |
| 2 | `user_scanner` | Solid coverage |
| 3 | `maigret`, `maigret_platforms` | Broad but less vetted |
| 4 | `sherlock`, `nexfil`, `blackbird` | Newest additions |
| 99 | `unknown` | Default fallback |

---

## `user_scanner`

Email registration probes across 205+ platforms via the [user-scanner](https://pypi.org/project/user-scanner/) package.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Opt-in (`ENABLE_USER_SCANNER=true`) because a full sweep can take several minutes. Set `user_scanner` in `MODULE_TIMEOUT_OVERRIDES` (default 180s in `.env.example`).

**Finding example (account confirmed):**
```json
{
  "platform": "Instagram",
  "profile_url": "https://instagram.com",
  "metadata": {
    "category": "Social",
    "reason": "",
    "source": "user_scanner"
  },
  "confidence": "high"
}
```

**Module metadata:**
```json
{
  "platforms_checked": 205,
  "platforms_confirmed": 4,
  "platforms_not_registered": 198,
  "user_scanner_version": "1.3.6"
}
```

---

## `username_pivot`

Post-primary phase: collects up to five unique usernames from primary findings (email local-part, metadata usernames, slugified display names) and re-runs the WhatsMyName dataset for each. Skips platforms already confirmed by the `whatsmyname` module.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Opt-in (`ENABLE_USERNAME_PIVOT=true`). Runs after primary modules complete and before `permutation_discovery`. Reuses the cached WMN dataset at `data/cache/wmn-data.json`.

**Finding example:**
```json
{
  "platform": "GitHub",
  "profile_url": "https://github.com/katriel_moses",
  "metadata": {
    "matched_username": "katriel_moses",
    "category": "dev",
    "source": "username_pivot"
  },
  "confidence": "medium"
}
```

**Module metadata:**
```json
{
  "usernames_pivoted": ["katriel.moses", "katriel_moses"],
  "platforms_checked": 1600,
  "platforms_confirmed": 2,
  "wmn_version": "1.4.0"
}
```

---

## `breachdirectory`

Search breach records for the target email via the [BreachDirectory RapidAPI](https://rapidapi.com/rohan-patra/api/breachdirectory).

| | |
|--|--|
| **Requires key** | Yes — `BREACHDIRECTORY_API_KEY` |
| **Status** | Implemented |

One finding per unique breach source. Passwords and hashes are never stored in full — only a two-character hint (e.g. `pa***`) when a password field is present.

**Finding example:**
```json
{
  "platform": "Collection1",
  "metadata": {
    "breach_source": "Collection1",
    "has_password_hash": true,
    "password_hint": "pa***"
  },
  "confidence": "high",
  "severity": "critical"
}
```

**Module metadata:**
```json
{
  "total_records_found": 3,
  "sources_list": ["Collection1", "LinkedIn"],
  "has_plaintext_hashes": false
}
```

---

## `hudson_rock`

Check if the email address appears in infostealer credential logs via the Hudson Rock Cavalier API.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Always-on (no opt-in). The API is free and returns a 404 when the email is clean. Rate limits return `status: partial`.

Returns one summary finding (infection counts, stealer families) and one finding per compromised domain credential.

**Finding example (clean):** empty findings list, `status: success`.

**Finding example (infected):**
```json
{
  "platform": "hudson_rock",
  "metadata": {
    "total_infections": 2,
    "stealer_families": ["RedLine", "Vidar"],
    "first_seen": "2023-04-10",
    "last_seen": "2024-01-22",
    "exposed_corporate_services": 1,
    "exposed_user_services": 4
  },
  "confidence": "high",
  "severity": "critical"
}
```

Per-domain findings (one per compromised service credential):
```json
{
  "platform": "github.com",
  "url": "https://github.com",
  "metadata": {
    "source": "infostealer_log",
    "stealer_family": "RedLine",
    "date_compromised": "2023-04-10",
    "high_value": true
  },
  "confidence": "high"
}
```

**Module metadata:**
```json
{
  "is_infostealer_victim": true,
  "total_infections": 2,
  "total_exposed_services": 5,
  "all_compromised_domains": ["github.com", "..."]
}
```

---

## `permutation_discovery`

Post-primary-phase orchestrator: if any upstream module recovered a real name (from Gravatar, HIBP breach data, GHunt, etc.), generates up to 60 email permutations and probes each with HIBP and Hudson Rock to find related accounts.

| | |
|--|--|
| **Requires key** | No (HIBP key enables breach-check sub-probes) |
| **Status** | Implemented |

Opt-in (`ENABLE_PERMUTATION_DISCOVERY=true`) because it adds 30–60 seconds and up to 120 extra API calls. Skips automatically if no name was recovered. The original email address is never re-checked.

**Finding example (match):**
```json
{
  "platform": "permutation_match",
  "metadata": {
    "matched_email": "jane.doe@outlook.com",
    "source_module": "hibp",
    "match_type": "breach",
    "breach_count": 2
  },
  "confidence": "medium"
}
```

**Module metadata:**
```json
{
  "names_found": ["Jane Doe"],
  "permutations_checked": 60,
  "related_emails_found": true,
  "matched_emails": ["jane.doe@outlook.com"]
}
```

---

## `ghunt`

Extract deep Google account intelligence via [GHunt](https://github.com/mxrch/GHunt): GAIA ID, display name, profile photo, YouTube channel, public Drive files, Maps review history, and active Google services.

| | |
|--|--|
| **Requires key** | Yes — `GHUNT_CREDS_PATH` (session credentials from `ghunt login`) |
| **Status** | Implemented |

Opt-in (`ENABLE_GHUNT=true`). Runs only against `@gmail.com`, `@googlemail.com`, and domains whose MX records route through Google (Google Workspace). All other domains are skipped immediately.

Requires the `ghunt` extra: `pip install "mailaccess[ghunt]"` and a one-time `ghunt login`. See [docs/ghunt-setup.md](ghunt-setup.md).

**Finding example:**
```json
{
  "platform": "google_account",
  "profile_url": "https://plus.google.com/123456789",
  "metadata": {
    "gaia_id": "123456789",
    "display_name": "Jane Doe",
    "account_creation_date": "2011-03-15",
    "profile_photo_url": "https://lh3.googleusercontent.com/...",
    "custom_profile_photo": true,
    "youtube_channel_url": "https://www.youtube.com/channel/...",
    "maps_reviews_count": 12,
    "public_drive_files": 3,
    "google_services_active": ["YouTube", "Maps", "Drive"],
    "possible_location_hint": "London, Shoreditch"
  },
  "confidence": "high"
}
```

---

## `phone_intel`

Validates phone numbers recovered from primary module findings and probes WhatsApp/Telegram registration hints.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Runs in the **post-primary** phase when `ENABLE_PHONE_INTEL=true` (default) and at least one phone number was extracted from prior findings. Skips with `status: skipped` when no phones are found.

Phone numbers are never stored in full in findings — only masked values (e.g. `+1234***7890`).

**Findings schema (validation):**
```json
{
  "platform": "phone_validation",
  "metadata": {
    "phone_number": "+1234***7890",
    "valid": true,
    "country": "United States",
    "carrier": "Verizon",
    "line_type": "mobile",
    "platform_hint": "numverify"
  },
  "confidence": "high"
}
```

**Findings schema (WhatsApp / Telegram — experimental):**
```json
{
  "platform": "whatsapp",
  "profile_url": "https://wa.me/15551234567",
  "metadata": {
    "phone_number": "+1555***4567",
    "experimental": true,
    "platform_hint": "possible_registration"
  },
  "confidence": "low"
}
```

**Module metadata:**
```json
{
  "phones_processed": 2,
  "phones_found": 3
}
```

---

## `messaging_hints`

Best-effort Telegram username checks during the primary gather phase. Optional WhatsApp hints when phone numbers are available.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Enabled by default (`ENABLE_MESSAGING_HINTS=true`). Rate-limited to **3 Telegram username checks** per investigation. Signal has no public lookup API — noted in module metadata as `signal_checkable: false`.

**Findings schema:**
```json
{
  "platform": "telegram",
  "profile_url": "https://t.me/username",
  "metadata": {
    "username": "jane.doe",
    "display_name": "Jane Doe",
    "photo_url": "https://...",
    "check_type": "username",
    "experimental": true
  },
  "confidence": "low"
}
```

**Module metadata:**
```json
{
  "telegram_checks": 3,
  "whatsapp_checks": 0,
  "signal_checkable": false
}
```

---

## `breach_deep`

Probes account existence on the top 100 HIBP-ranked breached sites from the public HIBP breach corpus.

| | |
|--|--|
| **Gate** | `ENABLE_BREACH_DEEP=false` (opt-in) |
| **Requires key** | None; HIBP corpus is public |
| **Timeout** | 90s default; set in `MODULE_TIMEOUT_OVERRIDES` |
| **Status** | Implemented |

On startup MailAccess fetches `https://haveibeenpwned.com/api/v3/breaches` and caches it for 24 hours at `data/cache/breach_corpus.json`. Breaches are ranked by `PwnCount` multiplied by high-impact data classes: passwords, credit cards, financial data, and phone numbers. By default the module checks the top 100 ranked domains.

Enable with `ENABLE_BREACH_DEEP=true`, run once with `mailaccess investigate user@example.com --modules breach_deep`, or tune:

```env
BREACH_DEEP_LIMIT=100
BREACH_DEEP_FULL=false
```

Known local YAML probes are reused first (`adobe`, `spotify`, `dropbox`, `github`, `discord`, `linkedin`, `zoom`, `skype`, `apple`, `patreon`). Other domains use bounded generic password-reset inference against the first three common reset endpoints with an 8 second per-site timeout and concurrency capped at 30.

Out of scope: credential verification, password hash lookup, dark web queries, and breach-dataset contents. This module only infers account existence on breached domains.

**Findings schema:**
```json
{
  "platform": "adobe.com",
  "url": "https://adobe.com",
  "confidence": "high",
  "severity": "critical",
  "source": "breach_deep",
  "metadata": {
    "breach_name": "Adobe",
    "breach_date": "2013-10-04",
    "pwn_count": 152445165,
    "data_classes": ["Email addresses", "Password hints", "Passwords", "Usernames"],
    "severity_label": "critical",
    "severity_score": 457335495.0,
    "probe_method": "yaml",
    "implication": "Credentials from this account may be in publicly available breach datasets"
  }
}
```

**Finding fields:** `breach_name`, `breach_date`, `pwn_count`, `data_classes`, `severity_label`, `probe_method`, `implication`.

**Module metadata:**
```json
{
  "sites_checked": 100,
  "sites_confirmed": 8,
  "critical_hits": 2,
  "high_hits": 6,
  "total_records_potentially_exposed": 534000000,
  "top_breach": "LinkedIn"
}
```

Metadata fields: `sites_checked`, `sites_confirmed`, `critical_hits`, `high_hits`, `total_records_potentially_exposed`, `top_breach`.

Note: uses YAML probes for known platforms and generic reset-flow inference for unknown domains.

---

## `domain_harvester`

Multi-source domain email harvesting for custom domains. Core sources require no
API key and the module runs by default for custom-domain investigations.

## `fediverse_discovery`

Discovers Fediverse and ActivityPub profiles. It requires no API key and runs by default.

## `github_code_search`

Searches public GitHub code and commits for the target email. `GITHUB_TOKEN` is
optional but improves the rate limit; the module runs by default.

## `gravatar_lookup`

Performs extended Gravatar profile extraction. It requires no API key and runs by default.

## `intelx_lookup`

Queries the IntelligenceX free tier. It requires no key for free-tier access and runs by default.

## `pastebin_search`

Searches paste data through `psbdmp.ws`. It requires no API key and runs by default.

## `name_consensus` (built-in)

Not a standalone module: this is a core engine in `backend/core/` that runs after all modules complete. It reads name signals from profile, key, researcher, social, package, and commit findings, then emits one defensible identity result for the report and CLI.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Automatic after collection |
| **Status** | Implemented |

Sources include:
- `github_user`
- `gravatar_profile`
- `keybase_profile`
- `twitter_profile`
- `linkedin_snippet`
- `pgp_keyserver`
- `orcid_profile`
- `hackernews_profile`
- `pypi_discovery`
- `npm_discovery`
- Git commit author names

The engine outputs `confirmed_name`, `name_confidence`, `name_reasoning`, and `name_sources`. Role/system email addresses such as `noreply@`, `admin@`, `support@`, `postmaster@`, and `notifications@` are automatically skipped so service accounts do not receive inferred identities.

Candidate names are Unicode-normalized and clustered with RapidFuzz so minor
spelling and transliteration differences can corroborate one another. Timestamped
signals receive temporal decay, while Cyrillic, Arabic, CJK, Devanagari, and other
Unicode names remain eligible. Common-name matches are capped to avoid overconfident
identity claims.

**Result schema:**
```json
{
  "confirmed_name": "Jane Doe",
  "name_confidence": "probable",
  "confidence_score": 2.18,
  "name_sources": ["github_profile", "orcid_profile"],
  "name_source_classes": ["developer", "institutional"],
  "name_reasoning": "GitHub Profile, Orcid Profile support this name across 2 independent source classes.",
  "conflicting_names": []
}
```

**Result fields:** `confirmed_name`, `name_confidence`, `confidence_score`,
`name_sources`, `name_source_classes`, `name_reasoning`, `conflicting_names`.

No standalone `ModuleResult` metadata is emitted. Implementation settings:
```json
{
  "fuzzy_threshold": 88,
  "temporal_decay_time_constant_days": 1095,
  "confidence_bands": ["confirmed", "probable", "possible", "unknown"]
}
```

---

## `identity_graph` (built-in)

Not a standalone module — the identity graph is built automatically after all primary and post-primary modules complete. It cross-references findings by shared usernames, profile photos, display names, and breach data to produce confidence-scored identity clusters.

Perceptual-avatar clusters add `same_avatar` edges, fuzzy bio clusters add
`same_bio` edges, and coordinated account dates add `same_signup_window` edges.
The graph also surfaces shadow-profile pairs when the same multi-token display name
appears under different non-anchor email addresses.

| | |
|--|--|
| **Requires key** | No |
| **Opt-in** | No — always runs |
| **Status** | Implemented |

The graph is available at:
- CLI: displayed automatically (use `--show-collisions` to expand low-confidence clusters)
- Web UI: `/investigation/:id/graph`
- API: `GET /api/report/{id}/clusters` (clusters) and `GET /api/report/{id}/graph` (D3 nodes/links)

**Cluster schema:**
```json
{
  "id": "cluster-1",
  "confidence": "high",
  "score": 0.91,
  "reasoning": "Shared username 'janedoe' across GitHub, HackerNews, and Twitter findings",
  "members": [
    {"module": "social", "platform": "GitHub", "username": "janedoe"},
    {"module": "whatsmyname", "platform": "HackerNews", "username": "janedoe"}
  ]
}
```

**Cluster fields:** `confidence`, `label`, `reasoning`, `findings`,
`finding_count`, `is_collision`.

**Graph schema (D3 endpoint):**
```json
{
  "nodes": [
    {"id": "platform:github", "type": "platform", "label": "github", "degree": 4}
  ],
  "links": [
    {"source": "platform:github", "target": "platform:twitter", "type": "same_avatar"}
  ]
}
```

---

## `platform_health` (built-in)

Persists platform probe outcomes and feeds rolling health decisions back into the
enumeration and reset-probe paths.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Automatic; inspect with `mailaccess platform-health` |
| **Status** | Implemented |

Records live in `~/.mailaccess/platform_health.db`. A platform is skipped after 10
consecutive misses, or after at least 30 probes in 30 days with a hit rate below
0.05. Set `MAILACCESS_DISABLE_HEALTH=1` to bypass decisions without deleting
history.

The self-healing selectors are `get_skip_set()`, `get_demote_set()`, and
`get_upgrade_set()`. Enumerators use `should_probe_async()` and
`record_probe_async()` so SQLite work does not block the event loop.

**Finding schema (health row):**
```json
{
  "platform": "reset_prober:example.com",
  "total_probes": 42,
  "hits": 1,
  "misses": 36,
  "inconclusive": 5,
  "hit_rate": 0.024,
  "fragility": 0.31,
  "consecutive_misses": 11,
  "window_days": 30,
  "first_seen": "2026-05-01T09:00:00+00:00",
  "last_seen": "2026-06-22T10:30:00+00:00"
}
```

**Finding fields:** `platform`, `total_probes`, `hits`, `misses`, `inconclusive`,
`hit_rate`, `fragility`, `consecutive_misses`, `window_days`, `first_seen`,
`last_seen`.

**Module metadata (enumerator integration):**
```json
{
  "health_tracked": 2180,
  "health_skipped": 14,
  "auto_demoted_skipped": 5,
  "auto_demoted_to_wave2": 12,
  "auto_upgraded_to_wave1": 3,
  "auto_demotion_overrides": {
    "NoisySite.com": "MAIGRET_FORCE_NOISYSITECOM"
  }
}
```

### Phase 6D audit trail

Every auto-demotion / auto-upgrade event appends one JSONL line to
`~/.mailaccess/platform_demotion.log`:

```json
{"timestamp": "2026-06-24T10:00:00Z", "platform": "NoisySite.com", "action": "skip",
 "reason": "inconclusive_rate=0.82, probes=134",
 "stats": {"inconclusive_rate": 0.82, "hit_rate": 0.08, "total_probes": 134},
 "reversible_via": "MAIGRET_FORCE_NOISYSITECOM"}
```

The log is the user-visible audit trail behind
`mailaccess platform-audit --show-demotions`.

### Phase 6D.3 community health sharing (opt-in)

```bash
mailaccess platform-health --share
```

Posts anonymized platform stats (hit / miss / inconclusive rates, average
latency, total probes, last probed) to a public GitHub Gist. **Strictly
opt-in**: the `--share` flag is the only way this code path runs. No
background-job sharing, no scheduled sharing, no auto-share on investigation
completion. The payload contains platform-level metadata only — no user
data, no email addresses, no investigation targets, no finding content.

---

## `temporal_cluster` (built-in)

Clusters account creation dates into coordinated signup windows and adds temporal
corroboration to the identity graph.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Automatic during identity-graph construction |
| **Status** | Implemented |

The default window is 60 days and the default minimum cluster size is five.

**Finding schema:**
```json
{
  "platforms": ["github", "reddit", "twitter", "steam", "discord"],
  "earliest": "2026-01-02T00:00:00+00:00",
  "latest": "2026-02-10T00:00:00+00:00",
  "span_days": 39,
  "cluster_size": 5,
  "score": 1.0
}
```

**Finding fields:** `platforms`, `earliest`, `latest`, `span_days`,
`cluster_size`, `score`.

No standalone `ModuleResult` metadata is emitted. Implementation defaults:
```json
{
  "window_days": 60,
  "min_cluster_size": 5
}
```

---

## `shadow_profiles` (built-in)

Finds same-name accounts associated with different non-anchor email addresses.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Automatic during identity-graph construction |
| **Status** | Implemented |

Two or more normalized display-name tokens are required. Matching usernames raise
confidence to `high`; display-name-only pairs remain `medium`.

V2 is gated on a non-null `confirmed_name` and requires at least two platforms
shared with the primary identity. V1 and V2 findings are rendered in the
`IDENTITY ANALYSIS` section.

**Finding schema:**
```json
{
  "primary_email": "jane@gmail.com",
  "primary_platform": "twitter",
  "shadow_email": "jane@proton.me",
  "shadow_platform": "steam",
  "display_name": "Jane Doe",
  "shared_username": "janedoe",
  "confidence": "high"
}
```

**Finding fields:** `primary_email`, `primary_platform`, `shadow_email`,
`shadow_platform`, `display_name`, `shared_username`, `confidence`.

No standalone `ModuleResult` metadata is emitted. Implementation defaults:
```json
{
  "min_name_token_count": 2,
  "anchor_email_excluded": true
}
```

---

## `avatar_clusters` (built-in)

Groups cross-platform avatar observations by exact URL or perceptual-hash
similarity.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Automatic during identity-graph construction |
| **Status** | Implemented |

`backend/core/avatar_hasher.py` normalizes images to 8x8 grayscale pHashes. The
clusterer accepts a maximum Hamming distance of five and omits singletons.
This default-on post-primary enrichment is bounded to 20 avatar fetches per
domain per run and feeds its clusters into the identity graph.

**Finding schema:**
```json
{
  "phash": "8f0f0f0f0f0f0f0f",
  "platforms": ["github", "twitter", "reddit"],
  "cluster_size": 3
}
```

**Finding fields:** `phash`, `platforms`, `cluster_size`.

No standalone `ModuleResult` metadata is emitted. Implementation limits:
```json
{
  "max_hamming_distance": 5,
  "max_avatar_urls_per_client": 20
}
```

---

## `domain_cluster` (post-primary, Phase 6B.1)

Group platform domains by shared registrar + /24 IP subnet.  Emits an
`infrastructure_correlation` finding whenever three or more platforms share
the same registrar AND /24 subnet.  The identity graph picks the clusters up
as `shared_infrastructure` edges (weight 0.4) so they also surface in
`cluster_confidence`.

| | |
|--|--|
| **Requires key** | No |
| **Default** | On (toggle via `ENABLE_DOMAIN_CLUSTER=false`) |
| **Scope** | Post-primary; needs platform findings from primary phase |
| **Cap** | `DOMAIN_CLUSTER_CAP` (default 20) — bounds WHOIS fan-out |
| **Status** | Implemented |

Free email providers (Gmail, Twitter, GitHub, Reddit, etc.) are excluded at
the domain level so a handful of random public-service findings do not
collapse into a meaningless cluster.

**Algorithm:**
1. Walk every primary-module finding, extract the platform's domain from
   `profile_url` / `metadata.domain` / `metadata.breach_domain`.
2. For each unique domain, run a short WHOIS lookup and a DNS-A query
   (4-second per-call timeout).
3. Group domains by `(registrar, /24 subnet)` and emit a cluster when the
   union of platforms tied to the group is ≥ 3.
4. Confidence scales with cluster size: 3 platforms → 0.5, capped at 0.9
   (infrastructure is corroborating, never confirmatory).

**Finding schema:**
```json
{
  "platform": "infra_cluster",
  "signal_type": "infrastructure_correlation",
  "confidence": "medium",
  "metadata": {
    "cluster_id": "infra_8e5bf38c7029",
    "platforms": ["twitter", "reddit", "blog_site"],
    "domains": ["twitter.com", "reddit.com", "blog.example.com"],
    "shared_registrar": "namecheap, inc.",
    "shared_subnet": "93.184.216.0/24",
    "shared_ip_subnet": "93.184.216.0/24",
    "platform_count": 3,
    "cluster_confidence": 0.5,
    "signal": "3 platforms share registrar 'namecheap, inc.' and /24 subnet 93.184.216.0/24"
  }
}
```

**Finding fields:** `cluster_id`, `platforms`, `domains`, `shared_registrar`,
`shared_subnet`, `shared_ip_subnet`, `platform_count`, `cluster_confidence`,
`signal`.

**Module metadata:**
```json
{
  "domains_looked_up": 8,
  "platforms_seen": 12,
  "domains_with_registrar": 7,
  "domains_with_ip": 6,
  "clusters_emitted": 1,
  "cap": 20,
  "truncated": false
}
```

Skip conditions: no platforms with parseable domains, free-provider-only
investigation, or `ENABLE_DOMAIN_CLUSTER=false`.

Graph integration: the identity-graph builder adds a `shared_infrastructure`
edge between every pair of member platforms in each cluster (weight 0.4,
weaker than `shared_username` / `same_avatar`).  `cluster_confidence` then
applies a 1.10× boost at 3+ member platforms and 1.15× at 5+.

---

## `shadow_profile_v2` (built-in, Phase 6B.2)

Extension to the Phase 2E `shadow_profile` detector.  V1 grouped findings by
display name and emitted any pair with different non-anchor emails; V2 adds
two new constraints to cut the false-positive rate:

1. The primary investigation's `name_consensus.confirmed_name` must be
   non-null.  Role / unknown identities skip V2 entirely.
2. The alternate email must share at least **2 platforms** with the
   primary investigation (configurable via `min_shared_platforms`).
3. The alternate email must have at least one finding whose display name
   normalises to the primary's confirmed name.

V2 is additive: V1 still runs unchanged for analysts who want the looser
signal.

| | |
|--|--|
| **Requires key** | No |
| **Default** | Always on (V1 + V2 together) |
| **Status** | Implemented |

**Finding schema (V2):**
```json
{
  "primary_email": "john@acmecorp.com",
  "shadow_email": "alt@gmail.com",
  "shared_name": "John Doe",
  "name_confidence": "confirmed",
  "shared_platforms": ["twitter", "steam", "github"],
  "platform_overlap_count": 3
}
```

The V2 finding appears in `graph.shadow_findings` with
`type: "shadow_profile_v2"` so consumers can distinguish it from V1.  V2
findings are sorted by `platform_overlap_count` descending — the strongest
alternate identity surfaces first.

CLI integration: the `IDENTITY ANALYSIS` section renders a
`SHADOW PROFILES (N found)` block when any V1 or V2 finding is present.
Each line reads:

```
─── SHADOW PROFILES ──────────────────────────
  Possible alternate identity detected:
    alt@gmail.com shares name "John Doe" and 3 platforms with john@acmecorp.com
    Confidence: MEDIUM
```

V2 implementation lives in
`backend/core/enrichment/shadow_profiles.py::ShadowProfileDetector.find_shadow_v2_pairs`.
The identity-graph builder calls it from `IdentityGraph.build(...)` after
V1.

Implementation defaults:
```json
{
  "min_shared_platforms": 2,
  "v1_anchor_excluded": true,
  "v2_requires_name_consensus": true
}
```

---

## `breach_corpus` (built-in cache)

Fetches and severity-ranks the public HIBP breach catalog used by `breach_deep`.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | On first `breach_deep` corpus access |
| **Status** | Implemented |

The response is cached for 24 hours at `data/cache/breach_corpus.json`. Severity is
`pwn_count` multiplied by 3 for passwords, 2 for credit cards, 2 for financial
data, and 1.5 for phone numbers.

**Finding schema (corpus record):**
```json
{
  "domain": "example.com",
  "breach_name": "Example",
  "breach_date": "2024-01-12",
  "pwn_count": 12000000,
  "data_classes": ["Email addresses", "Passwords"],
  "severity_score": 36000000.0,
  "severity_label": "high"
}
```

**Finding fields:** `domain`, `breach_name`, `breach_date`, `pwn_count`,
`data_classes`, `severity_score`, `severity_label`.

**Module metadata (`breach_deep` consumer):**
```json
{
  "sites_checked": 100,
  "sites_confirmed": 8,
  "top_breach": "Example"
}
```

---

## `common_names` (built-in filter)

Loads `data/common_names.json` to reduce confidence from common display names and
usernames that lack independent corroboration.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Automatic during name consensus and enumeration |
| **Status** | Implemented |

Common full-name tokens cap name-consensus confidence; common enumerator usernames
are reduced to `low` confidence.

**Finding schema:**
```json
{
  "username": "john.smith",
  "confidence": "low",
  "metadata": {
    "fp_warnings": ["common_username_no_corroboration"]
  }
}
```

**Finding fields:** `username`, `confidence`, `metadata.fp_warnings`.

No standalone `ModuleResult` metadata is emitted. Filter configuration:
```json
{
  "corpus": "data/common_names.json",
  "warning": "common_username_no_corroboration"
}
```

---

## `disposable_domains` (built-in filter)

Loads `data/disposable_domains.json` and downweights enumerator findings tied to a
known disposable email domain.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Automatic during preflight and enumeration |
| **Status** | Implemented |

The preflight credibility layer exposes `is_disposable`; affected enumerator
findings use `metadata.fp_warnings` rather than a separate top-level flag.

**Finding schema:**
```json
{
  "username": "analyst@mailinator.com",
  "confidence": "low",
  "metadata": {
    "fp_warnings": ["disposable_email_domain"]
  }
}
```

**Finding fields:** `username`, `confidence`, `metadata.fp_warnings`.

No standalone `ModuleResult` metadata is emitted. Filter configuration:
```json
{
  "corpus": "data/disposable_domains.json",
  "warning": "disposable_email_domain"
}
```

---

## `reset_prober` (built-in helper)

Classifies generic password-reset responses for breached domains that have no
dedicated YAML probe.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Called by `breach_deep` |
| **Status** | Implemented |

It tries nine bounded endpoint patterns with JSON and form bodies, decodes HTML
entities and URL encoding, and applies the multilingual corpus in
`data/reset_signals.json`. `true` means a success signal, `false` means an explicit
failure signal, and `null` means blocked, absent, unhealthy, or inconclusive.

**Finding schema (probe result):**
```json
true
```

**Finding values:** `true` (success signal), `false` (failure signal), `null`
(blocked, unavailable, unhealthy, or inconclusive).

**Module metadata (`breach_deep` consumer):**
```json
{
  "probe_method": "generic_reset"
}
```

---

## `maigret_detector` (built-in helper)

Applies Maigret `status_code`, message, and response-URL rules with redirect and
regex safeguards.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Called by `maigret_platforms` |
| **Status** | Implemented |

`backend/modules/maigret_platforms.py` also validates the top 50 eligible
status-code sites against their known-unclaimed usernames before the main sweep.

**Finding schema (`maigret_platforms`):**
```json
{
  "platform": "GitHub",
  "profile_url": "https://github.com/janedoe",
  "username": "janedoe",
  "confidence": "high",
  "metadata": {
    "check_type": "message",
    "source": "maigret",
    "wave": 1,
    "dual_confirmed": false
  }
}
```

**Finding fields:** `platform`, `profile_url`, `username`, `confidence`,
`metadata.check_type`, `metadata.source`, `metadata.wave`,
`metadata.dual_confirmed`.

**Module metadata (`maigret_platforms`):**
```json
{
  "platforms_confirmed": 14,
  "platforms_inconclusive": 9,
  "catch_all_skipped": 3,
  "regex_skipped": 21
}
```

---

## `sherlock_detector` (built-in helper)

Hardens Sherlock hit detection across status-code, message, response-URL, and JSON
rules with WAF awareness.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Called by `sherlock_platforms` |
| **Status** | Implemented |

**Finding schema (`sherlock_platforms`):**
```json
{
  "platform": "sherlock:GitHub",
  "profile_url": "https://github.com/janedoe",
  "username": "janedoe",
  "confidence": "medium",
  "metadata": {
    "error_type": "status_code",
    "source": "sherlock",
    "wave": 1,
    "waf_protected": false,
    "dual_confirmed": false
  }
}
```

**Finding fields:** `platform`, `profile_url`, `username`, `confidence`,
`metadata.error_type`, `metadata.source`, `metadata.wave`,
`metadata.waf_protected`, `metadata.dual_confirmed`.

**Module metadata (`sherlock_platforms`):**
```json
{
  "platforms_confirmed": 8,
  "platforms_inconclusive": 5,
  "catch_all_skipped": 2,
  "health_skipped": 4
}
```

---

## `blackbird_detector` (built-in helper)

Hardens Blackbird-style detection using distinct existing/missing status markers,
optional response markers, POST bodies, and username cleaning.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Called by `blackbird_platforms` |
| **Status** | Implemented |

**Finding schema (`blackbird_platforms`):**
```json
{
  "platform": "blackbird:Example",
  "profile_url": "https://example.com/janedoe",
  "username": "janedoe",
  "confidence": "high",
  "metadata": {
    "source": "blackbird",
    "wave": 1,
    "method": "GET",
    "waf_protected": false,
    "e_code": 200,
    "m_code": 404
  }
}
```

**Finding fields:** `platform`, `profile_url`, `username`, `confidence`,
`metadata.source`, `metadata.wave`, `metadata.method`,
`metadata.waf_protected`, `metadata.e_code`, `metadata.m_code`.

**Module metadata (`blackbird_platforms`):**
```json
{
  "platforms_confirmed": 11,
  "platforms_inconclusive": 7,
  "health_skipped": 3,
  "fragile_demoted": 6
}
```

---

## `platform_dedup` (built-in)

Merges cross-enumerator findings by normalized profile URL domain before report
persistence.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Automatic after collection |
| **Status** | Implemented |

Known host prefixes are stripped before grouping. At least two independent
enumeration sources set `metadata.dual_confirmed: true` and raise confidence to
`high`; more than two sources emit a warning for overlap review.

**Finding schema:**
```json
{
  "profile_url": "https://github.com/janedoe",
  "confidence": "high",
  "sources": ["maigret", "sherlock"],
  "metadata": {
    "dual_confirmed": true,
    "alternate_urls": ["https://www.github.com/janedoe"]
  }
}
```

**Finding fields:** `profile_url`, `confidence`, `sources`,
`metadata.dual_confirmed`, `metadata.alternate_urls`.

**Module metadata:**
```json
{
  "wmn_hits": 12,
  "maigret_hits": 14,
  "dual_confirmed": 5,
  "unique_platforms": 21
}
```

---

## `breach_normalizer` (built-in)

Collapses duplicate breach events into canonical records with complete source
attribution.

| | |
|--|--|
| **Requires key** | No |
| **Execution** | Automatic before scoring, graphing, and persistence |
| **Status** | Implemented |

The alias catalog at `data/breach_aliases.json` is LRU-cached. Host extraction
tolerates whitespace inside URLs, while years and generic breach suffixes are
removed before canonical matching.

**Finding schema:**
```json
{
  "platform": "LinkedIn",
  "breach_name": "LinkedIn",
  "breach_id": "linkedin",
  "confidence": "high",
  "severity": "high",
  "sources": ["hibp", "xposedornot"],
  "metadata": {
    "canonical_breach_id": "linkedin",
    "canonical_breach_name": "LinkedIn",
    "source_breach_names": ["LinkedIn", "LinkedIn2016"],
    "source_modules": ["hibp", "xposedornot"]
  }
}
```

**Finding fields:** `platform`, `breach_name`, `breach_id`, `confidence`,
`severity`, `sources`, `metadata.canonical_breach_id`,
`metadata.canonical_breach_name`, `metadata.source_breach_names`,
`metadata.source_modules`.

No standalone `ModuleResult` metadata is emitted. Normalized finding metadata:
```json
{
  "canonical_breach_id": "linkedin",
  "canonical_breach_name": "LinkedIn",
  "source_modules": ["hibp", "xposedornot"]
}
```

---

## Adding a Module

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-module) for the full interface contract.
