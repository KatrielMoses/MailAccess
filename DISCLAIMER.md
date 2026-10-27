# Disclaimer

## Intended Use

MailAccess is designed for:

- **Security research** — investigating the exposure of your own or client-authorized addresses
- **OSINT investigations** — open-source intelligence gathering in professional or journalistic contexts
- **Penetration testing** — with explicit written authorization from the target organization
- **Personal exposure audits** — checking your own email addresses against breach databases and public sources

## Where the Data Comes From

By default, MailAccess reads public, logged-out sources: web pages, public APIs, DNS and WHOIS records, certificate logs, public code hosts and breach notification services. Account checks use each site's public sign-up, sign-in or lookup pages, the same pages anyone can open. Checks that could make a site send the person a password-reset message are off unless you turn them on (`ENABLE_FORGOT_PASSWORD_PROBES`).

Some features use more than that, and only when they are set up:

- **Provider keys you add.** Optional providers (for example breach databases, Netlas, ipgeolocation.io, WhoisFreaks, Oxylabs and Hunter) answer with their own data under their own terms. You are responsible for following those terms.
- **Google profile enrichment.** With an operator Google credential, MailAccess signs in as that operator account to read the name and photo Google shows for an address. It never signs in as anyone else.
- **The hosted service at mailaccess.pro** also uses MailAccess's own index of addresses found in public web crawls, and MailAccess Pro adds business contacts from public and third-party commercial sources.

MailAccess does not exploit vulnerabilities, get around CAPTCHAs or bot checks, or access anyone else's accounts, messages or private data.

## Not a Hacking Tool

MailAccess is not designed or intended for:

- Unauthorized access to accounts, systems, or private data
- Surveillance, stalking, or targeted harassment of individuals
- Aggregating personal data about individuals without their consent or a lawful basis
- Any activity that violates the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, GDPR, or equivalent laws in your jurisdiction

## User Responsibility

By using MailAccess you accept sole legal and ethical responsibility for how you deploy and use it. The authors provide this software as-is, without warranty of any kind. If you are unsure whether a particular use is lawful in your jurisdiction, consult a qualified attorney before proceeding.

Misuse of this tool may violate federal, state, or local laws. The project maintainers are not liable for any misuse or damage arising from use of this software.
