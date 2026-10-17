"""Shared WHOIS junk filters (privacy proxies, redaction, registrar desks).

Used by the Netlas WHOIS path and the WhoisFreaks integration so there is one
definition of what counts as a real registrant contact.
"""

from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$")

#: Privacy-proxy / redaction services. Matched on the email's domain or any
#: parent of it (``contact.whoisguard.com`` → ``whoisguard.com``).
WHOIS_PROXY_DOMAINS = frozenset(
    {
        "whoisguard.com",
        "withheldforprivacy.com",
        "privacyprotect.org",
        "domainsbyproxy.com",
        "contactprivacy.com",
        "privacyguardian.org",
        "whoisprivacyprotect.com",
        "whoisprivacycorp.com",
        "domainprivacygroup.com",
        "perfectprivacy.com",
        "privacy.link",
        "whoisproxy.com",
        "registrarsafe.com",
        "identity-protect.org",
        "anonymize.com",
        "proxy.dreamhost.com",
        "protecteddomainservices.com",
        "whoisprotection.cc",
        "privatewho.is",
        "redacted.com",
    }
)
#: Redaction tokens in any local part (a plain ``gdpr@`` / ``privacy@`` on the
#: target is a real data-protection mailbox and is kept).
_REDACTION_RE = re.compile(
    r"redact|withheld|masked|not[._-]?disclosed|data[._-]?protected|"
    r"whois[._-]?(?:privacy|guard|proxy|protect)|privacy[._-]?(?:protect|proxy|service)"
)
_OFF_TARGET_DOMAIN_MARKERS = re.compile(r"privacy|proxy|redact|withheld|anonymi[sz]")
#: Registrar boilerplate desks — dropped unless on the target domain itself.
_REGISTRAR_LOCALPARTS = frozenset({"abuse", "noc", "hostmaster", "domains", "domain", "whois"})


def _domain_and_parents(domain: str) -> list[str]:
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def whois_junk_reason(
    email: str, domain: str, *, registrar_domains: set[str] | frozenset[str] = frozenset()
) -> str | None:
    """Why *email* is privacy-proxy / registrar boilerplate (``None`` = keep).

    Addresses on the target *domain* itself are only dropped for explicit
    redaction tokens — a real ``abuse@target`` or ``privacy@target`` is a
    genuine role mailbox, not registrar noise.
    """
    from .disposable_domains import is_disposable_domain

    value = str(email or "").strip().lower()
    if not _EMAIL_RE.match(value):
        return "not_an_email"
    local, host = value.rsplit("@", 1)
    on_target = host == domain or host.endswith("." + domain)
    if _REDACTION_RE.search(local):
        return "redacted"
    if on_target:
        return None
    if any(parent in WHOIS_PROXY_DOMAINS for parent in _domain_and_parents(host)):
        return "privacy_proxy"
    if _OFF_TARGET_DOMAIN_MARKERS.search(host):
        return "privacy_proxy"
    if any(parent in registrar_domains for parent in _domain_and_parents(host)):
        return "registrar"
    if local in _REGISTRAR_LOCALPARTS:
        return "registrar"
    if is_disposable_domain(host):
        return "disposable"
    return None


_PRIVACY_ORG_RE = re.compile(
    r"redact|withheld|not[\s._-]?disclosed|data[\s._-]?protected|privacy|private\s+registration|"
    r"registration\s+private|domains?\s+by\s+proxy|whois[\s._-]?(?:guard|proxy|protect)|"
    r"identity[\s._-]?protect|contact\s+privacy|proxy\s+service|anonymi[sz]|"
    r"^(?:n/?a|none|null|-+|\.+|unknown|see\s+privacyguardian\.org)$"
)


def is_privacy_org(name: str | None) -> bool:
    """True when a registrant name/company is a privacy service or placeholder."""
    value = str(name or "").strip().lower()
    return not value or bool(_PRIVACY_ORG_RE.search(value))
