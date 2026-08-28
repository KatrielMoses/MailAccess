<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/mailaccess-logo-reversed.svg">
  <img src="assets/brand/mailaccess-logo.svg" alt="MailAccess" height="36">
</picture>

# Sponsor MailAccess

**MailAccess is a self-hostable OSINT platform for investigating email addresses** — used by OSINT practitioners, penetration testers, and security researchers to fan out across breach corpora, 2,500+ social platforms, DNS/mail infrastructure, and the open web.

---

## Audience

| Metric | Current |
|---|---|
| GitHub stars | 1,000+ |
| PyPI downloads | 50,000+ |
| Independent security audits | 3 |
| Sister tool — VoidAccess | 650+ stars |
| Primary users | OSINT analysts, red teams / pentesters, security researchers, threat intel |

_Figures reviewed and updated each quarter. Live counts: [PyPI](https://pypi.org/project/mailaccess/) · [GitHub](https://github.com/KatrielMoses/MailAccess)._

---

## Why This Works: The Funnel

**We sell high-intent referral traffic, not a logo on a README.**

MailAccess is a data-fusion tool. It is *most* useful when the operator plugs in commercial data sources — proxies, breach corpora, IP reputation, email verification. That creates a natural, repeated moment of purchase intent inside the product itself.

The flow:

1. An analyst runs an investigation and hits a module that needs a commercial provider.
2. The CLI tells them exactly which key is missing:
   ```
   mailaccess keys set HIBP_API_KEY <your-key>
   ```
3. Our docs and CLI output route them **directly to the sponsor's signup page** for that category — at the moment they have already decided they need the capability.

The user isn't browsing. They are mid-investigation, blocked on a missing key, actively looking for a provider. That is the highest-converting traffic a data vendor can buy — and it is category-exclusive, so there is no comparison shopping in the moment.

Touchpoints in the funnel: `docs/api-keys.md`, `docs/self-hosting.md`, `docs/modules.md`, the `mailaccess keys` CLI surface, module skip messages, and the hosted dashboard's integrations panel.

---

## Categories

One vendor per category. Exclusive for the duration of the sponsorship.

| # | Category | Status | Current partner | Integration surface |
|---|---|---|---|---|
| 1 | **Proxies / Residential IPs** | 🔴 TAKEN | **ScrapingAnt** | `SCRAPINGANT_API_KEY`, residential + datacenter proxy routing |
| 2 | **Breach / Compromised-Credential Data** | 🟢 OPEN | — | `breach_aggregator` module (`DEHASHED_API_KEY`, `SNUSBASE_API_KEY` slots) |
| 3 | **IP Intelligence** | 🟢 OPEN | — | `domain_intel` / enterprise network intel modules |
| 4 | **Email / Identity Verification** | 🟢 OPEN | — | SMTP + deliverability verification pipeline |

**3 of 4 slots are currently open.** Current partners: [docs/sponsors.md](docs/sponsors.md).

---

## What a Sponsor Gets

- **Logo + link in the README** — above the fold, in the sponsors block.
- **Logo + link across the docs** — including `docs/api-keys.md`, the page every user lands on when configuring integrations.
- **CLI banner placement** — your name appears in the tool operators run daily.
- **Hosted dashboard placement** — logo + link in the integrations panel.
- **Named as the recommended provider for your category** — your signup URL is the one we point users to when a module needs that capability.
- **Category exclusivity** — no competing vendor occupies your slot while the sponsorship is active.
- **Referral / affiliate links honored** — we use your tracking URL so you can attribute conversions.

---

## Pricing

**$150–220 / month**, or annual equivalent (**~$2,000 / year**).

- One tier. One vendor per category.
- Rate within the band is set by category and placement scope.
- Annual is preferred and discounted relative to monthly.

---

## Contact

**sponsors@rootaccess.tech**

Invoicing, custom terms, purchase orders, and annual contracts are available on request. Tell us your category and preferred start date and we'll send a placement mockup and an invoice.
