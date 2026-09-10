"""MX-record resolver using the dnspython async path.

Returns ``[]`` on any failure (no records, NXDOMAIN, timeout,
network unreachable) so callers can degrade gracefully — mx lookup
is a precondition for SMTP verification, not a hard gate.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

_LOG = logging.getLogger(__name__)


@dataclass
class MXRecord:
    host: str
    priority: int


class MxStatus(str, Enum):
    """R4 (S4) — provider availability is DISTINCT from target evidence.

    * ``RESOLVED`` — usable mail host(s) found (MX, or implicit A/AAAA per RFC 5321).
    * ``NO_MAIL`` — RFC 7505 null MX (``MX 0 .``): the domain EXPLICITLY accepts no
      mail. Authoritative negative — do NOT fall through to A/AAAA.
    * ``NO_RECORDS`` — authoritative absence: no MX and no A/AAAA. Definitive.
    * ``TEMPORARY_ERROR`` — DNS timeout / SERVFAIL / resolver unavailable. UNKNOWN,
      never a definitive "no mail"; callers must NOT mark contacts Invalid on this.
    """

    RESOLVED = "resolved"
    NO_MAIL = "no_mail"
    NO_RECORDS = "no_records"
    TEMPORARY_ERROR = "temporary_error"


@dataclass
class MXResolution:
    status: MxStatus
    records: list[MXRecord] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return bool(self.records)

    @property
    def is_definitive_no_mail(self) -> bool:
        """True only when we KNOW there is no mail (never on a transient error)."""
        return self.status in (MxStatus.NO_MAIL, MxStatus.NO_RECORDS)


async def resolve_mx(domain: str) -> list[MXRecord]:
    """Backward-compatible list view: the usable MX records (empty on none).

    Prefer :func:`resolve_mx_typed` when the caller must distinguish a DNS
    failure (unknown) from an authoritative "no mail" answer (definitive)."""
    return (await resolve_mx_typed(domain)).records


async def resolve_mx_typed(domain: str) -> MXResolution:
    """Resolve mail hosts for *domain* with a TYPED outcome (see :class:`MxStatus`).

    A DNS timeout/SERVFAIL yields ``TEMPORARY_ERROR`` (unknown), never an empty
    "no mail" — so a blip can't mark every contact Invalid. A null MX (RFC 7505)
    yields ``NO_MAIL`` and does NOT fall through to A/AAAA.
    """
    if not isinstance(domain, str) or not domain.strip():
        return MXResolution(MxStatus.NO_RECORDS)
    target = domain.strip().lower()
    if not target or "." not in target:
        return MXResolution(MxStatus.NO_RECORDS)

    mx = await _resolve_mx_records(target)
    if mx.status is MxStatus.NO_MAIL:
        return mx  # RFC 7505 explicit no-mail — never falls through to A/AAAA
    if mx.records:
        return mx  # RESOLVED
    # No usable MX — either authoritative absence (NO_RECORDS) OR a temporary MX
    # error. Try the RFC 5321 §5.1 implicit A/AAAA fallback in BOTH cases: if the
    # domain has an address record we have a mail host regardless of the MX
    # lookup outcome (an MX blip must not deny a real implicit-MX host).
    fallback = await _resolve_implicit_addr_fallback(target)
    if fallback.status is MxStatus.RESOLVED:
        return fallback
    # No address host either. If EITHER lookup was a transient failure the true
    # status is UNKNOWN (we cannot assert "no mail"); otherwise it is an
    # authoritative absence.
    if (
        mx.status is MxStatus.TEMPORARY_ERROR
        or fallback.status is MxStatus.TEMPORARY_ERROR
    ):
        return MXResolution(MxStatus.TEMPORARY_ERROR)
    return MXResolution(MxStatus.NO_RECORDS)


def _is_null_mx(answers: object) -> bool:
    """RFC 7505: a single ``MX 0 .`` record means the domain accepts no mail."""
    records = list(answers)  # type: ignore[arg-type]
    if len(records) != 1:
        return False
    exchange = getattr(records[0], "exchange", None)
    return exchange is not None and str(exchange).rstrip(".") == ""


async def _resolve_mx_records(domain: str) -> MXResolution:
    try:
        import dns.asyncresolver  # type: ignore[import]
    except ImportError:
        # Resolver missing → we cannot decide; that is UNKNOWN, not "no mail".
        _LOG.debug("dnspython async resolver unavailable")
        return MXResolution(MxStatus.TEMPORARY_ERROR)

    import dns.resolver  # type: ignore[import]

    try:
        answers = await dns.asyncresolver.resolve(domain, "MX")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
        # Authoritative "no MX record here" — the domain exists but publishes no
        # MX. Callers try the A/AAAA fallback next.
        _LOG.debug("no MX for %s: %s", domain, type(exc).__name__)
        return MXResolution(MxStatus.NO_RECORDS)
    except Exception as exc:  # noqa: BLE001 - timeout / SERVFAIL / NoNameservers / …
        _LOG.warning(
            "MX lookup TEMPORARY failure for %s: %s: %s", domain, type(exc).__name__, exc
        )
        return MXResolution(MxStatus.TEMPORARY_ERROR)

    if _is_null_mx(answers):
        _LOG.debug("null MX (RFC 7505) for %s — domain accepts no mail", domain)
        return MXResolution(MxStatus.NO_MAIL)

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
    # An answer that parsed to zero usable hosts (all root/none) is not a
    # transient error but has no mail host — treat as authoritative absence.
    return MXResolution(MxStatus.RESOLVED if out else MxStatus.NO_RECORDS, out)


async def _resolve_implicit_addr_fallback(domain: str) -> MXResolution:
    """Return the domain as an implicit MX if it has an A OR AAAA record.

    A/AAAA both count (RFC 5321 §5.1 — the address record makes the host an
    implicit mail exchanger). A transient failure on BOTH lookups is UNKNOWN,
    not "no mail"."""
    try:
        import dns.asyncresolver  # type: ignore[import]
    except ImportError:
        return MXResolution(MxStatus.TEMPORARY_ERROR)

    import dns.resolver  # type: ignore[import]

    transient = False
    for rrtype in ("A", "AAAA"):
        try:
            answers = await dns.asyncresolver.resolve(domain, rrtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue  # authoritative absence for this type
        except Exception as exc:  # noqa: BLE001 - timeout / SERVFAIL / …
            _LOG.debug("%s fallback TEMPORARY failure for %s: %s", rrtype, domain, exc)
            transient = True
            continue
        if list(answers):
            _LOG.info(
                "no MX for %s — using implicit %s-record mail host (RFC 5321)",
                domain,
                rrtype,
            )
            return MXResolution(MxStatus.RESOLVED, [MXRecord(host=domain, priority=0)])
    # No address record found. If a lookup failed transiently we cannot be sure.
    return MXResolution(
        MxStatus.TEMPORARY_ERROR if transient else MxStatus.NO_RECORDS
    )
