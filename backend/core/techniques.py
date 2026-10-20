"""Technique catalogue: one plain-English line per technique, for the live run view
and every finding's ``trace``.

Each entry is ``module name -> (technique_id, line)``. A line is written for a
newcomer (no jargon, under 90 characters) and says what the engine is doing right
now, e.g. "Looking for this email in public code commits." Modules without an entry
fall back to a rewrite of their own ``description``.
"""

from __future__ import annotations

import re

_MAX_LINE = 89

TECHNIQUES: dict[str, tuple[str, str]] = {
    # Accounts and usernames
    "account_discovery": (
        "email_registration_check",
        "Checking which sites have an account registered to this email.",
    ),
    "browser_account_probe": (
        "sign_in_flow_probe",
        "Asking sign-in and password-reset pages whether they know this email.",
    ),
    "username_platforms": (
        "username_sweep",
        "Checking whether this username exists on 5,000+ sites.",
    ),
    "username_pivot": (
        "username_pivot",
        "Trying usernames found so far on hundreds more sites.",
    ),
    "fediverse_discovery": (
        "fediverse_webfinger",
        "Asking Mastodon and other Fediverse servers about this username.",
    ),
    "social": ("social_account_check", "Checking social networks for an account with this email."),
    "social_links": ("social_link_search", "Looking for social profiles linked to this email."),
    "hackernews": ("hackernews_profile", "Looking for a Hacker News profile with this username."),
    "twitter_profile": ("twitter_profile", "Reading the public X/Twitter profile for a found username."),
    "linkedin_serp": ("linkedin_search", "Searching LinkedIn for the name found so far."),
    "linkedin_brightdata": ("linkedin_profile", "Reading the LinkedIn profile that matches this person."),
    "marketplace_profile": ("marketplace_profile", "Reading Etsy and eBay profiles for a found username."),
    "messaging_hints": ("messaging_hints", "Checking Telegram and WhatsApp for a found username or phone."),
    "phone_intel": ("phone_check", "Checking phone numbers found so far."),
    "permutation_discovery": ("email_permutation", "Trying likely variants of this email address."),
    # Email-tied profiles and public records
    "gravatar": ("gravatar_profile", "Looking up the public Gravatar profile for this email."),
    "gravatar_lookup": ("gravatar_profile", "Looking up the public Gravatar profile for this email."),
    "github_commits": ("public_commit_search", "Looking for this email in public code commits."),
    "github_domain_commits": (
        "public_commit_search",
        "Looking for people from this domain in public code commits.",
    ),
    "github_code_search": ("public_code_search", "Searching public code and gists for this email."),
    "github_org_members": ("github_org_members", "Listing public members of the company's GitHub org."),
    "name_to_github_profile": ("github_name_search", "Looking for a GitHub profile matching the name found."),
    "keybase": ("keybase_lookup", "Looking up Keybase profiles and their verified proofs."),
    "pgp_keyserver": ("pgp_key_lookup", "Searching public PGP key servers for this email."),
    "pgp_domain_email": ("pgp_key_lookup", "Searching public PGP key servers for this domain's emails."),
    "google_account_intel": (
        "provider_account_intel",
        "Checking whether this is a Google account and reading its public profile.",
    ),
    "outlook_autodiscover": (
        "provider_account_intel",
        "Asking Microsoft whether this Outlook or Hotmail mailbox exists.",
    ),
    "m365_active_intel": ("provider_account_intel", "Asking Microsoft 365 whether this mailbox exists."),
    "m365_passive_intel": ("provider_account_intel", "Reading public Microsoft 365 settings for this domain."),
    "imap_existence": ("provider_account_intel", "Checking whether the mail server accepts this mailbox."),
    "emailrep": ("email_reputation", "Checking this email's public reputation score."),
    "email_identity_enrichment": ("identity_enrichment", "Adding public profile details to emails found."),
    "orcid_lookup": ("orcid_lookup", "Searching public ORCID researcher records."),
    "npm_discovery": ("package_registry", "Looking for npm packages published with this email."),
    "pypi_discovery": ("package_registry", "Looking for PyPI packages published with this email."),
    "npm_email": ("package_registry", "Reading npm package authors for this domain's emails."),
    "pypi_email": ("package_registry", "Reading PyPI package authors for this domain's emails."),
    "package_ecosystems": ("package_registry", "Reading RubyGems and Packagist maintainers for this domain."),
    "public_forge": ("public_forge", "Reading public GitLab projects and commits for this domain."),
    "wordpress_rest": ("wordpress_authors", "Listing public WordPress authors on this domain's site."),
    "alternate_email": ("alternate_email", "Looking for other email addresses of the same person."),
    "email_discovery": ("email_web_search", "Searching the web for other emails tied to the name found."),
    "persona_email_pivot": ("email_web_search", "Searching the web for this person's other emails."),
    "person_email_pivot": ("email_web_search", "Searching for public emails of the people found."),
    # Breaches and leaks
    "hibp": ("breach_lookup", "Searching known data breaches for this email."),
    "haveibeenpwned": ("breach_lookup", "Searching known data breaches for this email."),
    "breachdirectory": ("breach_lookup", "Searching a breach directory for this email."),
    "breach_aggregator": ("breach_lookup", "Combining breach records for this email from several sources."),
    "breach_deep": ("breach_account_check", "Checking for accounts on the sites this email was breached on."),
    "xposedornot": ("breach_lookup", "Searching the XposedOrNot breach list for this email."),
    "leakcheck": ("breach_lookup", "Searching LeakCheck's public breach list for this email."),
    "intelx_lookup": ("leak_search", "Searching leaks, pastes and dark-web dumps for this email."),
    "hudson_rock": ("infostealer_lookup", "Checking infostealer malware logs for this email."),
    "pastebin_search": ("paste_search", "Searching public paste sites for this email."),
    "ransomware_intel": ("ransomware_listing", "Checking ransomware leak sites for this email's domain."),
    # Web search and archives
    "google_dork": ("web_search", "Searching the web for pages that mention this email."),
    "email_search_dork": ("web_search", "Searching the web for this domain's email addresses."),
    "wayback": ("web_archive", "Searching old copies of web pages for this email."),
    "wayback_domain_harvest": ("web_archive", "Reading archived copies of this domain's pages for emails."),
    "commoncrawl_email": ("web_archive", "Reading Common Crawl's copies of this domain's pages for emails."),
    "public_surface_sweeper": ("public_pages", "Reading this domain's contact and support pages."),
    "syndication_feed_sweeper": ("public_pages", "Reading this domain's RSS and Atom feeds for authors."),
    "security_txt": ("public_pages", "Reading this domain's security.txt for contact emails."),
    "press_intel": ("press_search", "Searching press releases for contacts at this domain."),
    "sec_edgar": ("company_filings", "Searching SEC filings for contacts at this domain."),
    "code_and_cert_email": ("code_and_certificates", "Searching public code and TLS certificates for emails."),
    "employee_name_discovery": ("employee_names", "Finding names of people who work at this domain."),
    "pattern_and_verify": ("email_pattern", "Guessing this company's email format and checking it."),
    # Domain and infrastructure
    "email_credibility": ("email_credibility", "Checking the email is well-formed, real and not disposable."),
    "domain_resolution": ("domain_resolution", "Checking whether this email's domain exists."),
    "dns_lookup": ("dns_records", "Reading the mail and security DNS records for this domain."),
    "whois_lookup": ("whois_record", "Reading who registered this email's domain."),
    "domain_intel": ("domain_profile", "Reading this domain's registration, DNS and website details."),
    "domain_harvester": ("subdomain_search", "Listing subdomains of this email's domain."),
    "subdomain_intel": ("subdomain_search", "Listing subdomains of this domain."),
    "hackertarget_hosts": ("subdomain_search", "Listing hosts for this domain from HackerTarget."),
    "domain_cluster": ("shared_infrastructure", "Grouping found sites that share hosting or registrar."),
    "companies_house": ("company_registry", "Looking up UK company records for this domain."),
    "opencorporates": ("company_registry", "Looking up company records for this domain."),
    "shodan": ("internet_scan_data", "Checking internet scan data for this domain's servers."),
    "shodan_internetdb": ("internet_scan_data", "Checking open ports and known flaws on found servers."),
    "ripe_stat_asn": ("network_ranges", "Listing the network ranges owned by found networks."),
    "enterprise_net_intel": ("network_ranges", "Reading this company's network ownership records."),
    "ip_intel": ("ip_enrichment", "Looking up the location and owner of found IP addresses."),
    "hunter_io": ("email_deliverability", "Checking whether this email can receive mail."),
    "whoisfreaks_intel": (
        "whois_history",
        "Finding domains registered with this email and their past owners.",
    ),
    "whoisfreaks_history": ("whois_history", "Reading this domain's past WHOIS owners."),
    "netlas_email_footprint": ("internet_scan_data", "Finding where this email appears in internet scans."),
    "netlas_org_surface": ("internet_scan_data", "Reading this company's internet-facing servers."),
    "netlas_responses": ("internet_scan_data", "Searching internet scan responses for this domain's emails."),
    "netlas_certs": ("code_and_certificates", "Searching TLS certificates for this domain's emails."),
    "netlas_whois": ("whois_record", "Reading registration records for this domain's emails."),
}

_TRAILING_NOISE = re.compile(
    r"\s*(?:Enable|Disable|Set|Requires|Runs)\b[^.]*\.?\s*$", flags=re.IGNORECASE
)


def _rewrite_description(description: str) -> str:
    """First sentence of a module description, without setup hints or jargon."""
    text = " ".join(str(description or "").split())
    text = re.sub(r"\([^)]*\)", "", text)
    sentence = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
    sentence = _TRAILING_NOISE.sub("", sentence).strip(" .—-")
    if not sentence:
        return ""
    if len(sentence) > _MAX_LINE - 1:
        sentence = sentence[: _MAX_LINE - 2].rsplit(" ", 1)[0].rstrip(",;:") + "…"
        return sentence
    return sentence + "."


def _module_description(module_name: str) -> str:
    try:
        from ..modules import get_all_modules

        for cls in get_all_modules():
            if cls.name == module_name:
                return str(getattr(cls, "description", "") or "")
    except Exception:
        return ""
    return ""


def technique_for(module_name: str) -> tuple[str, str]:
    """``(technique_id, plain-English line)`` for a module. Never empty."""
    entry = TECHNIQUES.get(module_name)
    if entry is not None:
        return entry
    line = _rewrite_description(_module_description(module_name))
    if not line:
        line = f"Running the {module_name.replace('_', ' ')} check."[:_MAX_LINE]
    return (module_name, line)


def technique_line(module_name: str) -> str:
    return technique_for(module_name)[1]


def technique_id(module_name: str) -> str:
    return technique_for(module_name)[0]
