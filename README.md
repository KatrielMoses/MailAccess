<p align="center">
  <img src="assets/terminal-banner.svg" alt="mailaccess" width="640">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-0D0D0D.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%2B-0D0D0D.svg" alt="Python 3.10+"></a>
  <a href="docker-compose.yml"><img src="https://img.shields.io/badge/Docker-Compose-0D0D0D.svg" alt="Docker Compose"></a>
  <a href="https://pypi.org/project/mailaccess/"><img src="https://img.shields.io/static/v1?label=PyPI&message=0.17.6&color=8A1C2B&logo=pypi&logoColor=white" alt="PyPI version"></a>
  <a href="https://pepy.tech/projects/mailaccess"><img src="https://img.shields.io/pepy/dt/mailaccess?color=8A1C2B&amp;label=downloads" alt="PyPI downloads"></a>
</p>

<p align="center">
  <a href="https://mailaccess.pro"><b>mailaccess.pro</b></a>
  &nbsp;·&nbsp; <a href="docs/modules.md">Docs</a>
  &nbsp;·&nbsp; <a href="https://pypi.org/project/mailaccess/">PyPI</a>
  &nbsp;·&nbsp; <a href="CHANGELOG.md">Changelog</a>
</p>

Self-hostable OSINT platform for investigating email addresses. Fan out across breach databases, social networks, DNS records, and the open web, then get back a unified exposure score and structured findings you can export or pipe into Maltego.

Built for security researchers, OSINT analysts, and penetration testers operating under authorization. Read [DISCLAIMER.md](DISCLAIMER.md) before use.

## Install

```bash
pip install mailaccess
mailaccess investigate you@example.com
```

The CLI auto-starts and stops the backend for each investigation. Use
`mailaccess serve` when you want a persistent server, or install
`mailaccess[ml]` for optional spaCy-based name classification.

Full install options (Docker, persistent server, self-hosting) in [docs/self-hosting.md](docs/self-hosting.md).

## Quick Start

```bash
mailaccess investigate you@example.com
mailaccess investigate you@example.com -o report.pdf
mailaccess harvest-emails --domain company.com
mailaccess harvest-emails --domain company.com --export harvest.csv
mailaccess find-email --name "Jane Doe" --domain company.com
mailaccess keys set HIBP_API_KEY your-key
mailaccess pro
mailaccess upgrade
mailaccess serve
```

Pipeline, stdin, JSONL, and CI examples in [docs/integrations.md](docs/integrations.md#pipeline-integration).

## What It Does

- **Identity graph:** cross-platform correlation of accounts, usernames, names, avatars, breach data, and profile links. View it at `/investigation/:id/graph` or export with `GET /api/report/{id}/graph`.
- **Name Consensus Engine:** synthesizes independent name signals into confirmed, probable, possible, or unknown identity bands.
- **Defender's Brief:** security-manager-ready risk summary with prioritized findings and a concrete next action.
- **Credential Risk Score:** separate 0-100 credential exposure band with top drivers and recommended next steps.
- **Domain email harvesting:** `harvest-emails` discovers organization addresses across Common Crawl, GitHub, CT logs, registries, keyservers, dorks, employee pages, and patterns. *(Pro adds the decision-makers behind the domain.)*
- **Company email patterns:** `find-email` turns a name plus an employer domain into one honestly-graded likely address, offline from a bundled 384K-domain pattern index. Microsoft 365 mailboxes are verified where the provider allows.
- **5,000+ platform corpus:** a native username-platform engine over a MailAccess-verified corpus of 5,000+ platform definitions, with two-marker detection and zero runtime dependencies. Plus a native account-existence engine covering 250+ email-checkable services, and native Google-account intelligence.
- **Deep breach mode:** probes the highest-severity breach corpus for account-existence risk.
- **6 export formats:** JSON, CSV, PDF, Markdown, STIX 2.1, and Maltego XML.

## MailAccess Pro

**Your free harvest finds the addresses that are public. It does not find the people who make the decisions.**

The names that matter, heads of security, procurement, and engineering, rarely show up in Common Crawl, CT logs, or a GitHub commit. MailAccess Pro closes that gap. Add a Pro key and any lead-gen harvest is enriched with real business contacts, each carrying **name, role, company, email, and LinkedIn**, aggregated from publicly-available and third-party commercial sources. One command turns a bare domain into a working outreach list:

```text
$ mailaccess harvest-emails --domain acme.com
  312 addresses found

$ mailaccess harvest-emails --domain acme.com --mode public-business-contact
  312 found · 968 available with Pro
  ──────────────────────────────────────────────────────────────────
  Dana Reed    VP Security           Acme   dana.reed@acme.com   in/danareed
  Sam Okoye    Head of Procurement   Acme   s.okoye@acme.com     in/samokoye
  Priya Nair   Director, Platform    Acme   priya@acme.com       in/priyanair
  … 653 more business contacts (name, role, company, email, LinkedIn)
```

Why teams upgrade:

- **See the gap before you pay.** Every free harvest prints the exact number of extra contacts Pro would add for that domain. No guessing, no vague multiplier.
- **Coverage the open web cannot give you.** Reach the budget-owners and inboxes that public crawling misses entirely.
- **Company-name resolution.** Skip the domain lookup: `--company "Stripe"` resolves it for you.
- **Founder pricing: $19/mo for the first 100 seats.** Locked for life, limited seats remaining. Run `mailaccess pro` for live availability.

Corpus contacts are live-only: they render in their own Pro surface and never touch your exports, local database, or history. If the service is unreachable, the harvest shows the full open result. Without a key, nothing changes.

[Start with Pro →](https://mailaccess.pro/pricing?src=readme) · [how it works](docs/modules.md#mailaccess-pro-corpus-lead-enrichment)

## Staying Up To Date

MailAccess checks PyPI for a newer release (cached, best-effort, never blocking) and
prints an upgrade hint after a command when you're behind. Update in place with:

```bash
mailaccess upgrade
```

Silence the check with `MAILACCESS_NO_UPDATE_CHECK=1`. Prefer email? [Get release notes in your inbox](https://mailaccess.pro/updates?src=readme).

## Modules

75 modules over a 5,000+ platform corpus. Investigations probe a bounded, evidence-first wave of the highest-signal platforms (~700 vetted by default) rather than the whole corpus. Full module reference in [docs/modules.md](docs/modules.md).

## API Keys

Most modules work with zero keys. Optional keys unlock more coverage. Full list in [docs/api-keys.md](docs/api-keys.md).

## Export Formats

Save reports as JSON, CSV, PDF, Markdown, STIX 2.1, or Maltego XML with `-o`. Full export reference in [docs/exports.md](docs/exports.md).

## Self-Hosting

Run the CLI locally or launch the full web stack with Docker Compose. Full guide in [docs/self-hosting.md](docs/self-hosting.md).

## Sponsors

MailAccess is free and MIT licensed. Sponsors keep the corpus and infrastructure running.

<!-- Sponsor logos are rendered here. -->

[Sponsor this project →](https://mailaccess.pro/sponsors?src=readme)

## Links

| | |
|-|-|
| [Self-hosting guide](docs/self-hosting.md) | Docker Compose, `.env` reference, PostgreSQL, proxy/Tor, Maltego setup |
| [Module reference](docs/modules.md) | All modules, findings schema, adding new modules |
| [False-positive controls](docs/fp-control.md) | Common-name, disposable-domain, clustering, health, and scoring controls |
| [API reference](docs/api.md) | REST endpoints, WebSocket events, authentication |
| [Export formats](docs/exports.md) | Supported formats, MIME types, filename conventions |
| [Integrations](docs/integrations.md) | Maltego, Slack, Discord, generic webhooks |
| [Brand assets](docs/brand.md) | Logo lockups, palette, typography, clearspace, downloadable SVGs |
| [Contributing](CONTRIBUTING.md) | Adding modules, adding exporters, code style, PR checklist |

## License

MIT. All data queried by MailAccess comes from public sources. See [DISCLAIMER.md](DISCLAIMER.md) for authorized use cases and legal responsibility.

---

If MailAccess saved you time, a ⭐ on GitHub helps other researchers find it.
