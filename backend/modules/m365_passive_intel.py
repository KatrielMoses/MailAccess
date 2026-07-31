"""Microsoft 365 passive intelligence — Phase 1 (five unauthenticated checks).

Five additive, unauthenticated passive checks against Microsoft
infrastructure.  None authenticate, none send mail, and none risk account
lockout.  They enrich provider detection with tenant intelligence and add
independent existence signals that corroborate the Autodiscover /
GetCredentialType probes already wired into the harvest pipeline.

The five checks (see the module functions):

* :func:`openid_preflight`      — Check 5. One probe per *domain*.  Runs
  FIRST: a 400 means on-premises Exchange (no cloud tenant), so the
  cloud-only checks are pointless and are skipped.
* :func:`get_user_realm_xml`    — Check 1. GetUserRealm (``getuserrealm.srf``
  XML variant).  Classifies the tenant (managed / federated / unknown) and
  extracts the ADFS ``AuthURL`` for a federated tenant.  The ADFS URL is
  stashed on :class:`M365PassiveContext` for Phase 3 (WS-Trust) to consume.
* :func:`onedrive_probe`        — Check 4. SharePoint personal-site probe.
  A provisioned OneDrive answers 302/401/403; an absent one answers 404.

Checks 2 (``IfExistsResult:5``) and 3 (REST Autodiscover) live with the
verifiers they patch — :mod:`backend.core.m365_verifier` and
:mod:`backend.modules.outlook_autodiscover` respectively — because they are
edits to existing probes rather than new standalone checks.

:func:`run_m365_passive_intel` ties Checks 5, 1 and 4 together in the spec's
execution order and returns a single :class:`M365PassiveResult`.

Confidence contribution (mirrored in
:data:`backend.core.email_confidence.SOURCE_WEIGHTS`):

* ``onedrive_probe``    → 0.80  (independent existence signal)
* ``m365_getuserrealm`` → 0.0   (tenant intelligence, not existence)
* ``openid_preflight``  → 0.0   (infrastructure signal, not existence)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote
from xml.etree import ElementTree as ET

from ..core.http_client import build_client

_LOG = logging.getLogger(__name__)

# Source-type identifiers mirrored in email_confidence.SOURCE_WEIGHTS.
SOURCE_OPENID = "openid_preflight"
SOURCE_GETUSERREALM = "m365_getuserrealm"
SOURCE_ONEDRIVE = "onedrive_probe"

#: Matches an Entra tenant GUID inside the OpenID issuer / token_endpoint.
_TENANT_GUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


# ---------------------------------------------------------------------------
# Shared context — Phase 3 (WS-Trust) reads ``adfs_url`` from here.
# ---------------------------------------------------------------------------
@dataclass
class M365PassiveContext:
    """Mutable per-domain context threaded across the passive checks.

    ``adfs_url`` is the single field Phase 3 depends on: when the tenant is
    federated, GetUserRealm surfaces the ADFS ``AuthURL`` and it is stored
    here so the WS-Trust module can consume it without re-probing.
    """

    domain: str
    is_cloud: bool | None = None
    tenant_id: str | None = None
    tenant_type: str | None = None
    adfs_url: str | None = None


# ===========================================================================
# CHECK 5 — OpenID configuration preflight (runs first, per domain)
# ===========================================================================
@dataclass
class OpenIdPreflightResult:
    domain: str
    is_cloud: bool | None = None
    tenant_id: str | None = None
    issuer: str | None = None
    token_endpoint: str | None = None
    # cloud | on_premises | inconclusive
    status: str = "inconclusive"
    http_status: int | None = None
    error: str | None = None
    source_type: str = SOURCE_OPENID


def _extract_tenant_id(*candidates: str | None) -> str | None:
    """Pull the tenant GUID out of an issuer / token_endpoint URL."""
    for candidate in candidates:
        if not candidate:
            continue
        match = _TENANT_GUID_RE.search(candidate)
        if match:
            return match.group(0)
    return None


async def openid_preflight(
    domain: str,
    *,
    timeout_seconds: float = 8.0,
) -> OpenIdPreflightResult:
    """Check 5 — probe the tenant's OpenID configuration.

    * ``200`` → domain is cloud-hosted O365. Parse ``issuer``,
      ``token_endpoint`` and derive ``tenant_id``.
    * ``400`` → on-premises Exchange (no cloud tenant); the caller should
      skip the cloud-only checks.
    * otherwise → inconclusive; the caller proceeds anyway.
    """
    cleaned = (domain or "").strip().lower().rstrip(".")
    result = OpenIdPreflightResult(domain=cleaned)
    if not cleaned or "." not in cleaned:
        result.error = "invalid_domain"
        return result
    url = (
        f"https://login.microsoftonline.com/{quote(cleaned)}"
        "/.well-known/openid-configuration"
    )
    try:
        async with build_client(timeout=max(float(timeout_seconds), 1.0)) as client:
            response = await client.get(url, headers={"Accept": "application/json"})
    except Exception as exc:  # noqa: BLE001 - surface as inconclusive
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    result.http_status = response.status_code
    if response.status_code == 400:
        result.is_cloud = False
        result.status = "on_premises"
        return result
    if response.status_code != 200:
        result.error = f"http_{response.status_code}"
        return result
    try:
        payload: dict[str, Any] = response.json()
    except Exception as exc:  # noqa: BLE001
        result.error = f"invalid_json:{exc}"
        return result
    result.is_cloud = True
    result.status = "cloud"
    result.issuer = _string_or_none(payload.get("issuer"))
    result.token_endpoint = _string_or_none(payload.get("token_endpoint"))
    result.tenant_id = _extract_tenant_id(result.issuer, result.token_endpoint)
    return result


# ===========================================================================
# CHECK 1 — GetUserRealm (getuserrealm.srf XML variant), per email
# ===========================================================================
@dataclass
class GetUserRealmResult:
    email: str
    domain: str
    # managed | federated | unknown
    tenant_type: str = "unknown"
    adfs_url: str | None = None
    federation_brand: str | None = None
    domain_name: str | None = None
    # managed | federated | unknown | inconclusive
    status: str = "inconclusive"
    http_status: int | None = None
    error: str | None = None
    source_type: str = SOURCE_GETUSERREALM


async def get_user_realm_xml(
    email: str,
    *,
    timeout_seconds: float = 10.0,
) -> GetUserRealmResult:
    """Check 1 — classify the tenant via the GetUserRealm XML endpoint.

    ``NameSpaceType`` drives the classification:

    * ``Managed``   → cloud-only O365 tenant.
    * ``Federated`` → on-premises ADFS / third-party IdP; ``AuthURL`` is the
      ADFS endpoint, stashed for Phase 3.
    * ``Unknown``   → domain is not on M365.
    """
    cleaned = (email or "").strip().lower()
    domain = cleaned.rsplit("@", 1)[-1] if "@" in cleaned else ""
    result = GetUserRealmResult(email=cleaned, domain=domain)
    if "@" not in cleaned or not domain:
        result.error = "invalid_email"
        return result
    url = (
        "https://login.microsoftonline.com/getuserrealm.srf"
        f"?login={quote(cleaned)}&xml=1"
    )
    try:
        async with build_client(timeout=max(float(timeout_seconds), 1.0)) as client:
            response = await client.get(url, headers={"Accept": "application/xml"})
    except Exception as exc:  # noqa: BLE001 - surface as inconclusive
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    result.http_status = response.status_code
    if response.status_code != 200:
        result.error = f"http_{response.status_code}"
        return result
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as exc:
        result.error = f"invalid_xml:{exc}"
        return result

    namespace_type = (_findtext(root, "NameSpaceType") or "Unknown").strip()
    result.adfs_url = _string_or_none(_findtext(root, "AuthURL"))
    result.federation_brand = _string_or_none(_findtext(root, "FederationBrandName"))
    result.domain_name = _string_or_none(_findtext(root, "DomainName"))

    normalized = namespace_type.lower()
    if normalized == "managed":
        result.tenant_type = "managed"
        result.status = "managed"
    elif normalized == "federated":
        result.tenant_type = "federated"
        result.status = "federated"
    else:
        result.tenant_type = "unknown"
        result.status = "unknown"
    return result


# ===========================================================================
# CHECK 4 — OneDrive personal-site probe, per email
# ===========================================================================
@dataclass
class OneDriveProbeResult:
    email: str
    provisioned: bool | None = None
    # provisioned | absent | inconclusive
    status: str = "inconclusive"
    probe_url: str | None = None
    http_status: int | None = None
    error: str | None = None
    source_type: str = SOURCE_ONEDRIVE


def tenant_from_domain(domain: str) -> str:
    """Derive a best-effort SharePoint tenant name from a domain.

    Strips the TLD and uses the left-most label (``contoso.com`` →
    ``contoso``).  Callers should prefer the authoritative tenant name from
    GetUserRealm / OpenID when one is available.
    """
    cleaned = (domain or "").strip().lower().rstrip(".")
    if not cleaned:
        return ""
    labels = [label for label in cleaned.split(".") if label]
    return labels[0] if labels else cleaned


def _derive_onedrive_url(email: str, tenant: str) -> str:
    """Build the SharePoint personal-site URL for *email* under *tenant*."""
    local_part, _, domain = email.partition("@")
    fmt_user = local_part.replace(".", "_").replace("-", "_")
    domain_underscored = domain.replace(".", "_")
    return (
        f"https://{tenant}-my.sharepoint.com/personal/"
        f"{fmt_user}_{domain_underscored}/_layouts/15/onedrive.aspx"
    )


async def onedrive_probe(
    email: str,
    *,
    tenant: str | None = None,
    timeout_seconds: float = 8.0,
) -> OneDriveProbeResult:
    """Check 4 — probe the derived SharePoint personal site.

    No auth headers, no redirect following:

    * ``302`` / ``401`` / ``403`` → OneDrive provisioned (mailbox exists).
    * ``404``                     → not provisioned (absent / not enabled).
    * timeout / error             → inconclusive.
    """
    cleaned = (email or "").strip().lower()
    result = OneDriveProbeResult(email=cleaned)
    if "@" not in cleaned:
        result.error = "invalid_email"
        return result
    domain = cleaned.rsplit("@", 1)[-1]
    resolved_tenant = (tenant or tenant_from_domain(domain)).strip().lower()
    if not resolved_tenant:
        result.error = "no_tenant"
        return result
    url = _derive_onedrive_url(cleaned, resolved_tenant)
    result.probe_url = url
    try:
        async with build_client(
            timeout=max(float(timeout_seconds), 1.0), follow_redirects=False
        ) as client:
            response = await client.get(url)
    except Exception as exc:  # noqa: BLE001 - surface as inconclusive
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    result.http_status = response.status_code
    if response.status_code in (302, 401, 403):
        result.provisioned = True
        result.status = "provisioned"
    elif response.status_code == 404:
        result.provisioned = False
        result.status = "absent"
    else:
        result.status = "inconclusive"
        result.error = f"http_{response.status_code}"
    return result


# ===========================================================================
# EXECUTION ORDER — ties Checks 5, 1, 4 together
# ===========================================================================
@dataclass
class M365PassiveResult:
    domain: str
    openid: OpenIdPreflightResult | None = None
    realm: GetUserRealmResult | None = None
    onedrive: list[OneDriveProbeResult] = field(default_factory=list)
    skipped_cloud_checks: bool = False
    context: M365PassiveContext | None = None

    def to_infrastructure_dict(self) -> dict[str, Any]:
        """Serialise for the JSON export under ``infrastructure.m365_tenant``."""
        openid = self.openid
        realm = self.realm
        return {
            "is_cloud": None if openid is None else openid.is_cloud,
            "tenant_id": None if openid is None else openid.tenant_id,
            "tenant_type": None if realm is None else realm.tenant_type,
            "adfs_url": None if realm is None else realm.adfs_url,
            "federation_brand": None if realm is None else realm.federation_brand,
            "skipped_cloud_checks": self.skipped_cloud_checks,
            "openid_status": None if openid is None else openid.status,
            "realm_status": None if realm is None else realm.status,
            "onedrive": [
                {
                    "email": probe.email,
                    "status": probe.status,
                    "http_status": probe.http_status,
                }
                for probe in self.onedrive
            ],
        }


async def run_m365_passive_intel(
    domain: str,
    emails: list[str] | None = None,
    *,
    ctx: M365PassiveContext | None = None,
    openid_timeout_seconds: float = 8.0,
    realm_timeout_seconds: float = 10.0,
    onedrive_timeout_seconds: float = 8.0,
    max_onedrive_probes: int = 25,
) -> M365PassiveResult:
    """Run the passive checks in the spec's execution order.

    1. :func:`openid_preflight` (Check 5) FIRST. On ``on_premises`` the
       cloud-only checks (GetUserRealm, OneDrive) are skipped.
    2. :func:`get_user_realm_xml` (Check 1) — stashes the ADFS ``AuthURL``
       on ``ctx`` for Phase 3.
    3. :func:`onedrive_probe` (Check 4) — one probe per email, capped.
    """
    cleaned_domain = (domain or "").strip().lower().rstrip(".")
    context = ctx or M365PassiveContext(domain=cleaned_domain)
    cleaned_emails = [
        e.strip().lower() for e in (emails or []) if isinstance(e, str) and "@" in e
    ]
    result = M365PassiveResult(domain=cleaned_domain, context=context)

    # 1. Preflight FIRST — an on-premises tenant skips the cloud checks.
    openid = await openid_preflight(
        cleaned_domain, timeout_seconds=openid_timeout_seconds
    )
    result.openid = openid
    context.is_cloud = openid.is_cloud
    context.tenant_id = openid.tenant_id
    if openid.status == "on_premises":
        result.skipped_cloud_checks = True
        return result

    # 2. GetUserRealm — classify the tenant and stash the ADFS URL.
    probe_email = cleaned_emails[0] if cleaned_emails else f"probe@{cleaned_domain}"
    realm = await get_user_realm_xml(
        probe_email, timeout_seconds=realm_timeout_seconds
    )
    result.realm = realm
    context.adfs_url = realm.adfs_url
    context.tenant_type = realm.tenant_type

    # 3. OneDrive — one probe per email, using the GetUserRealm domain name
    #    as the tenant when it looks usable, else derived from the domain.
    tenant = tenant_from_domain(cleaned_domain)
    limit = max(0, int(max_onedrive_probes))
    for email in cleaned_emails[:limit]:
        result.onedrive.append(
            await onedrive_probe(
                email, tenant=tenant, timeout_seconds=onedrive_timeout_seconds
            )
        )
    return result


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _string_or_none(value: Any) -> str | None:
    return str(value) if isinstance(value, str) and value.strip() else None


def _findtext(root: ET.Element, tag: str) -> str | None:
    """Find *tag* as a direct-or-nested child, namespace-insensitive."""
    direct = root.findtext(tag)
    if direct is not None:
        return direct
    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1]
        if local == tag and element.text is not None:
            return element.text
    return None


__all__ = [
    "M365PassiveContext",
    "M365PassiveResult",
    "OpenIdPreflightResult",
    "GetUserRealmResult",
    "OneDriveProbeResult",
    "SOURCE_OPENID",
    "SOURCE_GETUSERREALM",
    "SOURCE_ONEDRIVE",
    "openid_preflight",
    "get_user_realm_xml",
    "onedrive_probe",
    "run_m365_passive_intel",
    "tenant_from_domain",
]
