"""Provider classification from MX evidence.

This is intentionally heuristic metadata, not an identity claim. The
selector uses only the lowest-priority (primary) MX records and keeps an
``unknown`` fallback for unusual routing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from .mx_resolver import MXRecord


class MailProvider(str, Enum):
    M365 = "m365"
    GOOGLE = "google"
    YAHOO = "yahoo"
    PROTON = "proton"
    ZOHO = "zoho"
    FASTMAIL = "fastmail"
    SHARED_HOSTING = "shared_hosting"
    SELF_HOSTED = "self_hosted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProviderDetection:
    provider: MailProvider
    primary_mx: str | None
    matched_mx_hosts: tuple[str, ...]
    reason: str


def detect_provider_from_mx(
    mx_records: list[MXRecord],
    *,
    target_domain: str = "",
    ptr_hosts: tuple[str, ...] = (),
) -> ProviderDetection:
    ordered = sorted(mx_records, key=lambda item: (item.priority, item.host))
    hosts = tuple(str(item.host).strip().lower().rstrip(".") for item in ordered if item.host)
    primary = hosts[0] if hosts else None
    if not hosts:
        return ProviderDetection(MailProvider.UNKNOWN, None, (), "no_mx_records")

    def any_host(*needles: str) -> bool:
        return any(any(needle in host for needle in needles) for host in hosts)

    domain_key = target_domain.strip().lower().rstrip(".")
    shared_hosts = tuple(host.strip().lower().rstrip(".") for host in ptr_hosts if host)
    is_shared_hosting = (
        any_host("mx1.hostinger.com", "mx2.hostinger.com", "mailstore1.secureserver.net")
        or any(re.fullmatch(r"box\d+\.bluehost\.com", host) for host in hosts)
        or any_host("plesk")
        or any("plesk" in host for host in shared_hosts)
    )

    if is_shared_hosting:
        provider = MailProvider.SHARED_HOSTING
    elif any_host(".mail.protection.outlook.com", ".outlook.com"):
        provider = MailProvider.M365
    elif any_host("aspmx.l.google.com", ".googlemail.com"):
        provider = MailProvider.GOOGLE
    elif any_host(".yahoodns.net", ".mail.yahoo.com"):
        provider = MailProvider.YAHOO
    elif any_host("protonmail.ch", "protonmail.com"):
        provider = MailProvider.PROTON
    elif any_host("zoho.com", "zoho.eu", "zohomail.com"):
        provider = MailProvider.ZOHO
    elif any_host("messagingengine.com", "fastmail.com"):
        provider = MailProvider.FASTMAIL
    elif target_domain and any(host == target_domain or host.endswith("." + target_domain) for host in hosts):
        provider = MailProvider.SELF_HOSTED
    else:
        provider = MailProvider.UNKNOWN
    return ProviderDetection(provider, primary, hosts, "mx_pattern")
