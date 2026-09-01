"""Validation helpers for domains that may be used as network targets."""

from __future__ import annotations

import ipaddress
import re

_PUBLIC_CLEARNET_FQDN = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_NON_PUBLIC_SUFFIXES = (".onion", ".i2p", ".local", ".internal", ".localhost")


def is_public_clearnet_domain(value: str) -> bool:
    """Return whether *value* is a plain, public clearnet FQDN.

    This deliberately performs no DNS lookup.  It prevents untrusted domain
    corpus values from becoming network targets while avoiding DNS-triggered
    side effects during corpus ingestion.
    """
    domain = value.strip().lower()
    if (
        not domain
        or "://" in domain
        or any(character in domain for character in (":", "/", "?", "#"))
        or domain.endswith(_NON_PUBLIC_SUFFIXES)
        or domain == "localhost"
    ):
        return False

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        return False

    return _PUBLIC_CLEARNET_FQDN.fullmatch(domain) is not None
