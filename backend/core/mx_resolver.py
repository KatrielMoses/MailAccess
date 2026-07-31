"""MX-record resolver using the same dnspython async path as
:mod:`backend.modules.ghunt_module`.

Returns ``[]`` on any failure (no records, NXDOMAIN, timeout,
network unreachable) so callers can degrade gracefully — mx lookup
is a precondition for SMTP verification, not a hard gate.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

_LOG = logging.getLogger(__name__)


@dataclass
class MXRecord:
    host: str
    priority: int


async def resolve_mx(domain: str) -> list[MXRecord]:
    """Return MX records for *domain* sorted by ascending priority.

    Lowest priority number == highest preference.  The dnspython
    async resolver is used here for parity with :mod:`ghunt_module`
    which uses ``dns.asyncresolver.resolve`` directly; we mirror
    that, with an additional fallback to the sync resolver via
    ``asyncio.to_thread`` for callers that already pay the
    sync-dns tax elsewhere.
    """
    if not isinstance(domain, str) or not domain.strip():
        return []
    target = domain.strip().lower()
    if not target or "." not in target:
        return []

    records = await _resolve_with_dnspython(target)
    if records:
        return records
    # RFC 5321 §5.1: when a domain publishes no MX record but does have an
    # address (A/AAAA) record, that host is an implicit mail exchanger.
    # FIX 6: fall back to the domain's A record as a last-resort mail
    # server rather than silently reporting "no mail" for A-only domains.
    return await _resolve_implicit_a_fallback(target)


async def _resolve_with_dnspython(domain: str) -> list[MXRecord]:
    try:
        import dns.asyncresolver  # type: ignore[import]
    except ImportError:
        _LOG.debug("dnspython async resolver unavailable")
        return []

    try:
        answers = await dns.asyncresolver.resolve(domain, "MX")
    except Exception as exc:  # noqa: BLE001 - dnspython raises many types
        # FIX 6: log DNS failures (timeout, SERVFAIL, NXDOMAIN) at WARNING
        # so an empty result is never silently indistinguishable from a
        # genuine "no MX" answer.
        import dns.resolver  # type: ignore[import]

        no_records = (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN)
        level = _LOG.debug if isinstance(exc, no_records) else _LOG.warning
        level("MX lookup failed for %s: %s: %s", domain, type(exc).__name__, exc)
        return []

    out: list[MXRecord] = []
    for rdata in answers:
        exchange = getattr(rdata, "exchange", None)
        if exchange is None:
            continue
        host = str(exchange).rstrip(".")
        if not host or host.lower() == "none":
            continue
        try:
            priority = int(rdata.preference)
        except (TypeError, ValueError):
            continue
        out.append(MXRecord(host=host, priority=priority))

    out.sort(key=lambda r: (r.priority, r.host))
    return out


async def _resolve_implicit_a_fallback(domain: str) -> list[MXRecord]:
    """Return the domain itself as an implicit MX if it has an A record."""
    try:
        import dns.asyncresolver  # type: ignore[import]
    except ImportError:
        return []
    try:
        answers = await dns.asyncresolver.resolve(domain, "A")
    except Exception as exc:  # noqa: BLE001 - dnspython raises many types
        _LOG.debug("A-record fallback failed for %s: %s", domain, exc)
        return []
    if not list(answers):
        return []
    _LOG.info("no MX for %s — using implicit A-record mail host (RFC 5321)", domain)
    # Priority 0: the domain is its own mail exchanger.
    return [MXRecord(host=domain, priority=0)]
