"""Enterprise network intelligence — Phase 2 (two passive checks).

Two additive, unauthenticated passive checks that extract internal Active
Directory and unified-communications infrastructure from network responses
that any client can elicit.  Neither check authenticates, sends mail, nor
risks account lockout: the NTLM check reads the *challenge* the server hands
out before any credential is supplied, and the Lync check is a plain GET.

Both checks are domain-level — they run once per domain, regardless of the
detected mail provider, during the harvest infrastructure-enrichment phase.

* :func:`check_ntlm_challenge`  — Check 1. Sends an unauthenticated Type-1
  NTLM negotiation to the Autodiscover endpoint (OWA as a fallback) and
  parses the internal AD metadata out of the server's Type-2 challenge.
* :func:`check_lync_discovery`  — Check 2. Probes the ``lyncdiscover``
  autodiscovery endpoint (HTTPS then HTTP) and classifies the unified-
  communications deployment from the FQDNs it exposes.

:func:`run_enterprise_net_intel` runs both concurrently under a combined
wall-clock budget and returns a single :class:`EnterpriseNetIntelResult`.

Confidence contribution (mirrored in
:data:`backend.core.email_confidence.SOURCE_WEIGHTS`):

* ``ntlm_challenge``  → 0.0  (infrastructure metadata, not email existence)
* ``lync_discovery``  → 0.0  (infrastructure metadata, not email existence)
"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..core.http_client import build_client

_LOG = logging.getLogger(__name__)

# Source-type identifiers mirrored in email_confidence.SOURCE_WEIGHTS.
SOURCE_NTLM = "ntlm_challenge"
SOURCE_LYNC = "lync_discovery"

#: Standard unauthenticated Type-1 NTLM negotiation blob. Every NTLM client
#: sends this exact handshake to begin negotiation — it carries no
#: credentials and is always identical.
_TYPE1_NTLM_B64 = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="

#: Minimal Autodiscover XML envelope POSTed alongside the Type-1 handshake.
_AUTODISCOVER_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    "<Autodiscover "
    'xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/'
    'requestschema/2006">'
    "<Request>"
    "<EMailAddress>probe@example.com</EMailAddress>"
    "<AcceptableResponseSchema>"
    "http://schemas.microsoft.com/exchange/autodiscover/outlook/"
    "responseschema/2006a"
    "</AcceptableResponseSchema>"
    "</Request>"
    "</Autodiscover>"
)

# NTLM TargetInfo (AV_PAIR) attribute identifiers.
_MSV_AV_EOL = 0x0000
_MSV_AV_NB_COMPUTER_NAME = 0x0001
_MSV_AV_NB_DOMAIN_NAME = 0x0002
_MSV_AV_DNS_COMPUTER_NAME = 0x0003
_MSV_AV_DNS_DOMAIN_NAME = 0x0004
_MSV_AV_DNS_TREE_NAME = 0x0005


# ===========================================================================
# CHECK 1 — NTLM NetBIOS challenge reader
# ===========================================================================
@dataclass
class ActiveDirectoryIntel:
    """Internal AD metadata extracted from an NTLM Type-2 challenge."""

    netbios_domain: str | None = None
    netbios_host: str | None = None
    dns_domain: str | None = None
    dns_host: str | None = None
    ad_forest: str | None = None
    endpoint: str | None = None
    error: str | None = None
    source_type: str = SOURCE_NTLM

    def is_populated(self) -> bool:
        return any(
            (
                self.netbios_domain,
                self.netbios_host,
                self.dns_domain,
                self.dns_host,
                self.ad_forest,
            )
        )


def _read_u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _read_u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _decode_utf16(raw: bytes) -> str | None:
    """Decode a UTF-16LE AV-pair value, returning ``None`` when empty."""
    try:
        text = raw.decode("utf-16-le")
    except (UnicodeDecodeError, ValueError):
        return None
    cleaned = text.replace("\x00", "").strip()
    return cleaned or None


def _parse_av_pairs(data: bytes, start: int, length: int) -> dict[int, str]:
    """Parse the TargetInfo attribute-value pairs into ``{AvId: value}``."""
    pairs: dict[int, str] = {}
    if start <= 0 or start >= len(data):
        return pairs
    end = start + length if length else len(data)
    end = min(end, len(data))
    cursor = start
    while cursor + 4 <= end:
        av_id = _read_u16(data, cursor)
        av_len = _read_u16(data, cursor + 2)
        cursor += 4
        if av_id == _MSV_AV_EOL:
            break
        if av_len < 0 or cursor + av_len > end:
            break
        value = _decode_utf16(data[cursor : cursor + av_len])
        cursor += av_len
        if value is not None:
            pairs.setdefault(av_id, value)
    return pairs


def parse_ntlm_type2(challenge_b64: str) -> ActiveDirectoryIntel:
    """Parse a base64 NTLM Type-2 challenge into :class:`ActiveDirectoryIntel`.

    The AD metadata lives in the TargetInfo AV pairs; the TargetName field is
    used as a best-effort NetBIOS-domain fallback when the AV pair is absent.
    Any structural problem is reported via ``error`` rather than raised.
    """
    intel = ActiveDirectoryIntel()
    try:
        # binascii.Error subclasses ValueError, so this covers malformed input.
        data = base64.b64decode(challenge_b64 or "", validate=False)
    except (ValueError, TypeError):
        intel.error = "invalid_base64"
        return intel
    # Header is 48 bytes up to and including the TargetInfoFields buffer.
    if len(data) < 48 or data[:8] != b"NTLMSSP\x00":
        intel.error = "invalid_signature"
        return intel
    if _read_u32(data, 8) != 0x00000002:
        intel.error = "not_type2"
        return intel

    # TargetName security buffer (bytes 12-19): best-effort NetBIOS fallback.
    target_name: str | None = None
    tn_len = _read_u16(data, 12)
    tn_off = _read_u32(data, 16)
    if tn_len and 0 < tn_off and tn_off + tn_len <= len(data):
        target_name = _decode_utf16(data[tn_off : tn_off + tn_len])

    # TargetInfo security buffer (bytes 40-47) — the authoritative AV pairs.
    ti_len = _read_u16(data, 40)
    ti_off = _read_u32(data, 44)
    av = _parse_av_pairs(data, ti_off, ti_len)

    intel.netbios_domain = av.get(_MSV_AV_NB_DOMAIN_NAME) or target_name
    intel.netbios_host = av.get(_MSV_AV_NB_COMPUTER_NAME)
    intel.dns_domain = av.get(_MSV_AV_DNS_DOMAIN_NAME)
    intel.dns_host = av.get(_MSV_AV_DNS_COMPUTER_NAME)
    intel.ad_forest = av.get(_MSV_AV_DNS_TREE_NAME)
    if not intel.is_populated():
        intel.error = "no_target_info"
    return intel


def _extract_ntlm_challenge(response: Any) -> str | None:
    """Pull the base64 Type-2 blob out of a ``WWW-Authenticate: NTLM`` header."""
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        raw = headers.get("WWW-Authenticate")
    except (AttributeError, TypeError):
        raw = None
    if not raw:
        return None
    # A header line can carry several comma-separated challenges
    # (e.g. ``Negotiate, NTLM <blob>``); a base64 blob never contains a comma.
    for part in str(raw).split(","):
        token = part.strip()
        if token.upper().startswith("NTLM "):
            blob = token[5:].strip()
            if blob:
                return blob
    return None


async def check_ntlm_challenge(
    domain: str,
    *,
    timeout_seconds: float = 10.0,
) -> ActiveDirectoryIntel:
    """Check 1 — read internal AD metadata from an NTLM Type-2 challenge.

    POSTs an unauthenticated Type-1 handshake to the Autodiscover endpoint;
    when that yields no NTLM challenge the OWA auth endpoint is tried as a
    fallback.  No credentials are supplied and no authentication completes.
    On any exception or a response without an NTLM challenge the endpoint is
    skipped (no retry).
    """
    cleaned = (domain or "").strip().lower().rstrip(".")
    intel = ActiveDirectoryIntel()
    if not cleaned or "." not in cleaned:
        intel.error = "invalid_domain"
        return intel

    endpoints = (
        f"https://autodiscover.{cleaned}/autodiscover/autodiscover.xml",
        f"https://mail.{cleaned}/owa/auth.owa",
    )
    headers = {
        "Authorization": f"NTLM {_TYPE1_NTLM_B64}",
        "Content-Type": "text/xml",
    }
    timeout = max(float(timeout_seconds), 1.0)
    last_error: str | None = None
    for url in endpoints:
        try:
            async with build_client(
                timeout=timeout, follow_redirects=False
            ) as client:
                response = await client.post(
                    url, headers=headers, content=_AUTODISCOVER_BODY
                )
        except Exception as exc:  # noqa: BLE001 - skip endpoint, try fallback
            last_error = f"{type(exc).__name__}: {exc}"
            _LOG.debug("ntlm_challenge %s failed: %s", url, exc)
            continue
        challenge = _extract_ntlm_challenge(response)
        if challenge is None:
            last_error = f"no_challenge_http_{getattr(response, 'status_code', None)}"
            continue
        parsed = parse_ntlm_type2(challenge)
        parsed.endpoint = url
        if parsed.is_populated():
            return parsed
        last_error = parsed.error or "empty_challenge"
    intel.error = last_error or "no_challenge"
    return intel


# ===========================================================================
# CHECK 2 — Lync / Skype for Business discovery
# ===========================================================================
@dataclass
class UnifiedCommsIntel:
    """Unified-communications deployment metadata from ``lyncdiscover``."""

    # onprem | hybrid | cloud | unknown
    deployment_type: str = "unknown"
    pool_fqdn: str | None = None
    server_fqdns: list[str] = field(default_factory=list)
    is_teams: bool = False
    is_lync: bool = False
    error: str | None = None
    source_type: str = SOURCE_LYNC

    def is_populated(self) -> bool:
        return bool(self.server_fqdns)


def _host_from_url(value: Any) -> str | None:
    """Extract a bare FQDN from an href/URL (or a raw host string)."""
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    parsed = urlparse(candidate if "//" in candidate else f"//{candidate}")
    host = parsed.hostname
    return host.strip().lower().rstrip(".") if host else None


def _extract_lync_fqdns(response: Any) -> list[str]:
    """Collect FQDNs from the JSON ``_links`` body and the server header."""
    fqdns: list[str] = []
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001 - non-JSON body is expected sometimes
        payload = None
    if isinstance(payload, dict):
        links = payload.get("_links")
        if isinstance(links, dict):
            for key in ("self", "user", "xframe"):
                entry = links.get(key)
                if isinstance(entry, dict):
                    host = _host_from_url(entry.get("href"))
                    if host:
                        fqdns.append(host)

    headers = getattr(response, "headers", None)
    if headers is not None:
        try:
            header_fqdn = headers.get("X-MS-Server-Fqdn")
        except (AttributeError, TypeError):
            header_fqdn = None
        host = _host_from_url(header_fqdn) or (
            str(header_fqdn).strip().lower() if header_fqdn else None
        )
        if host:
            fqdns.append(host)

    # De-duplicate while preserving discovery order.
    seen: set[str] = set()
    ordered: list[str] = []
    for fqdn in fqdns:
        if fqdn not in seen:
            seen.add(fqdn)
            ordered.append(fqdn)
    return ordered


def _classify_deployment(fqdns: list[str]) -> UnifiedCommsIntel:
    """Classify a UC deployment from the FQDNs the discovery endpoint reveals."""
    intel = UnifiedCommsIntel(server_fqdns=list(fqdns))
    if not fqdns:
        return intel
    intel.pool_fqdn = fqdns[0]
    lowered = [f.lower() for f in fqdns]
    intel.is_lync = any("lync" in f for f in lowered)
    intel.is_teams = any("teams" in f for f in lowered)
    has_online = any("online" in f for f in lowered)
    if intel.is_lync and has_online:
        # Cloud infrastructure fronting on-prem Lync naming — hybrid.
        intel.deployment_type = "hybrid"
    elif has_online:
        intel.deployment_type = "cloud"
    elif intel.is_lync:
        intel.deployment_type = "onprem"
    else:
        # A custom FQDN with no cloud markers is an on-prem deployment.
        intel.deployment_type = "onprem"
    return intel


async def check_lync_discovery(
    domain: str,
    *,
    timeout_seconds: float = 8.0,
) -> UnifiedCommsIntel:
    """Check 2 — probe ``lyncdiscover.{domain}`` for UC infrastructure.

    Tries HTTPS first, then HTTP (some on-prem deployments only serve HTTP).
    An NXDOMAIN / connection error or an empty response is skipped
    gracefully.
    """
    cleaned = (domain or "").strip().lower().rstrip(".")
    intel = UnifiedCommsIntel()
    if not cleaned or "." not in cleaned:
        intel.error = "invalid_domain"
        return intel

    urls = (
        f"https://lyncdiscover.{cleaned}",
        f"http://lyncdiscover.{cleaned}",
    )
    timeout = max(float(timeout_seconds), 1.0)
    last_error: str | None = None
    for url in urls:
        try:
            async with build_client(
                timeout=timeout, follow_redirects=True
            ) as client:
                response = await client.get(url)
        except Exception as exc:  # noqa: BLE001 - skip, try HTTP fallback
            last_error = f"{type(exc).__name__}: {exc}"
            _LOG.debug("lync_discovery %s failed: %s", url, exc)
            continue
        fqdns = _extract_lync_fqdns(response)
        if not fqdns:
            last_error = f"no_fqdns_http_{getattr(response, 'status_code', None)}"
            continue
        return _classify_deployment(fqdns)
    intel.error = last_error or "no_deployment"
    return intel


# ===========================================================================
# EXECUTION — both checks concurrently under a combined budget
# ===========================================================================
@dataclass
class EnterpriseNetIntelResult:
    domain: str
    active_directory: ActiveDirectoryIntel | None = None
    unified_communications: UnifiedCommsIntel | None = None
    budget_exceeded: bool = False

    def to_infrastructure_dict(self) -> dict[str, Any]:
        """Serialise for the JSON export under ``infrastructure.*``."""
        ad = self.active_directory
        uc = self.unified_communications
        return {
            "active_directory": {
                "netbios_domain": ad.netbios_domain if ad else None,
                "netbios_host": ad.netbios_host if ad else None,
                "dns_domain": ad.dns_domain if ad else None,
                "dns_host": ad.dns_host if ad else None,
                "ad_forest": ad.ad_forest if ad else None,
                "status": "found" if (ad and ad.is_populated()) else "not_found",
                "endpoint": ad.endpoint if ad else None,
                "error": ad.error if ad else None,
                "source_type": SOURCE_NTLM,
            },
            "unified_communications": {
                "deployment_type": uc.deployment_type if uc else "unknown",
                "pool_fqdn": uc.pool_fqdn if uc else None,
                "server_fqdns": list(uc.server_fqdns) if uc else [],
                "is_teams": bool(uc.is_teams) if uc else False,
                "is_lync": bool(uc.is_lync) if uc else False,
                "status": "found" if (uc and uc.is_populated()) else "not_found",
                "error": uc.error if uc else None,
                "source_type": SOURCE_LYNC,
            },
            "budget_exceeded": self.budget_exceeded,
        }


async def run_enterprise_net_intel(
    domain: str,
    *,
    enable_ntlm: bool = True,
    enable_lync: bool = True,
    ntlm_timeout_seconds: float = 10.0,
    lync_timeout_seconds: float = 8.0,
    budget_seconds: float = 15.0,
) -> EnterpriseNetIntelResult:
    """Run both passive checks concurrently under one wall-clock budget.

    The two checks run via :func:`asyncio.gather` and the whole block is
    bounded by ``budget_seconds``; exceeding the budget flags
    ``budget_exceeded`` and returns whatever (possibly empty) result is
    available.  Each check also carries its own per-request timeout.
    """
    cleaned = (domain or "").strip().lower().rstrip(".")
    result = EnterpriseNetIntelResult(domain=cleaned)

    async def _run_ntlm() -> ActiveDirectoryIntel | None:
        if not enable_ntlm:
            return None
        return await check_ntlm_challenge(
            cleaned, timeout_seconds=ntlm_timeout_seconds
        )

    async def _run_lync() -> UnifiedCommsIntel | None:
        if not enable_lync:
            return None
        return await check_lync_discovery(
            cleaned, timeout_seconds=lync_timeout_seconds
        )

    try:
        ad, uc = await asyncio.wait_for(
            asyncio.gather(_run_ntlm(), _run_lync()),
            timeout=max(float(budget_seconds), 1.0),
        )
        result.active_directory = ad
        result.unified_communications = uc
    except (TimeoutError, asyncio.TimeoutError):
        _LOG.debug("enterprise net intel exceeded its %.1fs budget", budget_seconds)
        result.budget_exceeded = True
    except Exception as exc:  # noqa: BLE001 - additive enrichment only
        _LOG.debug("enterprise net intel failed: %s", exc)
    return result


__all__ = [
    "ActiveDirectoryIntel",
    "UnifiedCommsIntel",
    "EnterpriseNetIntelResult",
    "SOURCE_NTLM",
    "SOURCE_LYNC",
    "parse_ntlm_type2",
    "check_ntlm_challenge",
    "check_lync_discovery",
    "run_enterprise_net_intel",
]
