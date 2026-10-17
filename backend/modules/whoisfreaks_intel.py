"""WhoisFreaks (BYOK): domains owned by this email, and pre-redaction owners of its domain."""

from __future__ import annotations

import time

from ..core.enrichment_store import has_whoisfreaks_cache, netlas_refresh
from ..core.whoisfreaks_data import history_contacts, lookup, reverse_domains
from .base import BaseModule, ModuleResult, ModuleStatus
from .domain_intel import _FREE_PROVIDERS

#: Stays under the module's 60s timeout so a rate-limited bucket skips cleanly.
_DEADLINE_SECONDS = 50.0


def email_domain(email: str) -> str | None:
    """The email's domain when it is a non-webmail (own) domain, else ``None``."""
    domain = email.rsplit("@", 1)[-1].strip().lower()
    return domain if domain and domain not in _FREE_PROVIDERS else None


async def has_cached_lookup(email: str) -> bool:
    """True when either lookup this module makes is already cached."""
    if await has_whoisfreaks_cache("reverse_email", email):
        return True
    domain = email_domain(email)
    return bool(domain and await has_whoisfreaks_cache("history", domain))


class WhoisFreaksIntelModule(BaseModule):
    name = "whoisfreaks_intel"
    description = (
        "Domains registered with this email and pre-redaction WHOIS owners via WhoisFreaks."
    )
    email_linked = False

    async def run(self, email: str, collected: dict | None = None) -> ModuleResult:
        refresh = netlas_refresh()
        deadline = time.monotonic() + _DEADLINE_SECONDS
        findings: list[dict] = []
        complete = True

        owned = await lookup(
            "reverse_email", email, max_pages=1, refresh=refresh, deadline=deadline
        )
        complete = complete and owned.complete
        domains = reverse_domains(owned.rows)
        total = owned.total if owned.total is not None else len(domains)
        for item in domains:
            findings.append(
                {
                    "platform": "whoisfreaks_reverse_email",
                    "confidence": "none",
                    "email_linked": True,
                    "metadata": {
                        "domain": item["domain"],
                        "company": item["company"],
                        "registrant_name": item["registrant_name"],
                        "created": item["created"],
                        "updated": item["updated"],
                        "expires": item["expires"],
                        "total_matches": total,
                    },
                }
            )

        domain = email_domain(email)
        owners = 0
        if domain:
            hist = await lookup(
                "history", domain, max_pages=1, refresh=refresh, deadline=deadline
            )
            complete = complete and hist.complete
            for contact in history_contacts(hist.rows, domain):
                owners += 1
                registrar = contact["registrar"]
                roles = contact["roles"]
                findings.append(
                    {
                        "platform": "whoisfreaks_whois_history",
                        "confidence": "none",
                        "email_linked": False,
                        "metadata": {
                            "email": contact["email"],
                            "name": contact["name"],
                            "company": contact["company"],
                            "role": roles[0] if len(roles) == 1 else roles,
                            "country": contact["country"],
                            "first_seen": contact["first_seen"],
                            "last_seen": contact["last_seen"],
                            "registrar": registrar,
                            "domain": domain,
                        },
                    }
                )

        if findings:
            status = ModuleStatus.SUCCESS
        else:
            status = ModuleStatus.SUCCESS_EMPTY if complete else ModuleStatus.SKIPPED
        return ModuleResult(
            status,
            findings=findings,
            metadata={
                "domains_owned": len(domains),
                "historical_owners": owners,
                "complete": complete,
            },
        )
