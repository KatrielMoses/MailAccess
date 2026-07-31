"""Microsoft 365 active intelligence — Phase 3 (single-probe account state).

Three checks that send **exactly one** probe per account, each carrying a
deliberately invalid credential, to extract account-state telemetry from the
provider's own error responses.  No password spraying, no repeated attempts:
the module enforces a hard, per-process, per-account one-probe guard at the
module level (:func:`_guard_one_probe`) — not at the caller, not configurable.
At one attempt per account there is no lockout risk.

The three checks are mutually exclusive per email — the most appropriate one
runs, never all three (see :func:`select_active_check` / :func:`run_m365_active_intel`):

* :func:`probe_aadsts`     — Check 1. ROPC token request against
  ``login.microsoftonline.com``; the ``AADSTS`` code in the error decodes to a
  precise account state.  Highest signal; preferred for cloud/managed tenants.
* :func:`probe_wstrust`    — Check 3. WS-Trust RST2 against a federated
  tenant's ADFS ``AuthURL`` (surfaced by Phase 1 GetUserRealm).  Runs only when
  an ADFS URL is known.
* :func:`probe_activesync` — Check 2. ActiveSync ``OPTIONS`` probe against
  on-prem / hybrid Exchange.  A timing + header heuristic; the fallback when
  the cloud checks are unavailable.

Confidence contribution (mirrored in
:data:`backend.core.email_confidence.SOURCE_WEIGHTS`):

* ``aadsts_probe``     → 0.90  (direct AADSTS decode)
* ``wstrust_probe``    → 0.85  (federated authentication attempt)
* ``activesync_probe`` → 0.65  (timing heuristic, less definitive)
"""

from __future__ import annotations

import base64
import logging
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any

from ..core.http_client import build_client

_LOG = logging.getLogger(__name__)

# Source-type identifiers mirrored in email_confidence.SOURCE_WEIGHTS.
SOURCE_AADSTS = "aadsts_probe"
SOURCE_ACTIVESYNC = "activesync_probe"
SOURCE_WSTRUST = "wstrust_probe"

# Microsoft's own public client ID (Azure PowerShell). Widely used by every
# O365 enumeration tool; public, first-party, and accepted for ROPC.
_MS_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/token"

#: ActiveSync timing threshold. A response slower than this suggests the server
#: performed a mailbox lookup (account exists); a fast reject suggests none.
_ACTIVESYNC_SLOW_MS = 200.0

#: Matches an AADSTS error code anywhere in the token error body.
_AADSTS_RE = re.compile(r"AADSTS\d+")


# ---------------------------------------------------------------------------
# HARD REQUIREMENT — one-probe guard (module level, not configurable)
# ---------------------------------------------------------------------------
#: Every account normalised to lowercase that has already been probed this
#: process.  Never probe the same account twice, regardless of which check.
_PROBED_ACCOUNTS: set[str] = set()


def _guard_one_probe(email: str) -> bool:
    """Return ``True`` the first time *email* is seen, ``False`` thereafter.

    Enforced at the module level so no caller can bypass it.  Every check
    calls this first; a ``False`` result means the account was already probed
    this process and the check must return an inconclusive result immediately.
    """
    normalized = email.strip().lower()
    if normalized in _PROBED_ACCOUNTS:
        return False  # already probed, skip
    _PROBED_ACCOUNTS.add(normalized)
    return True


# ---------------------------------------------------------------------------
# AADSTS code table — Check 1
# ---------------------------------------------------------------------------
AADSTS_CODES: dict[str, dict[str, Any]] = {
    "AADSTS50126": {
        "status": "exists",
        "detail": "valid_credential_wrong_password",
        "confidence": 0.90,
    },
    "AADSTS50034": {
        "status": "not_found",
        "detail": "account_does_not_exist",
        "confidence": 0.95,
    },
    "AADSTS50057": {
        "status": "exists",
        "detail": "account_disabled",
        "confidence": 0.90,
    },
    "AADSTS50053": {
        "status": "exists",
        "detail": "account_locked",
        "confidence": 0.90,
    },
    "AADSTS50076": {
        "status": "exists",
        "detail": "mfa_required",
        "confidence": 0.92,
    },
    "AADSTS53003": {
        "status": "exists",
        "detail": "conditional_access_block",
        "confidence": 0.90,
    },
    "AADSTS50158": {
        "status": "exists",
        "detail": "external_security_challenge",
        "confidence": 0.85,
    },
    "AADSTS700016": {
        "status": "exists",
        "detail": "app_not_found_in_tenant",
        "confidence": 0.80,
    },
    "AADSTS50014": {
        "status": "exists",
        "detail": "max_session_length_exceeded",
        "confidence": 0.85,
    },
}


# ---------------------------------------------------------------------------
# result type
# ---------------------------------------------------------------------------
@dataclass
class ActiveProbeResult:
    """Outcome of a single active probe against one account."""

    email: str
    # aadsts | activesync | wstrust | none
    check: str
    # exists | not_found | inconclusive
    status: str = "inconclusive"
    detail: str | None = None
    confidence: float = 0.0
    source_type: str | None = None
    http_status: int | None = None
    aadsts_code: str | None = None
    elapsed_ms: float | None = None
    error: str | None = None

    @property
    def exists(self) -> bool | None:
        if self.status == "exists":
            return True
        if self.status == "not_found":
            return False
        return None


def _inconclusive(
    email: str, check: str, *, error: str | None = None, http_status: int | None = None
) -> ActiveProbeResult:
    return ActiveProbeResult(
        email=email,
        check=check,
        status="inconclusive",
        error=error,
        http_status=http_status,
    )


# ===========================================================================
# CHECK 1 — AADSTS error-code decoding (ROPC token request)
# ===========================================================================
async def probe_aadsts(
    email: str,
    *,
    timeout_seconds: float = 10.0,
) -> ActiveProbeResult:
    """Check 1 — decode the ``AADSTS`` code from a single ROPC token error.

    Sends one password-grant token request with an invalid password. The
    response is always an error; the ``AADSTS`` code in ``error_description``
    decodes to a precise account state via :data:`AADSTS_CODES`.

    * ``429``                       → inconclusive (rate limited).
    * AADSTS code not in the table  → inconclusive.
    * network error                 → inconclusive.
    """
    cleaned = (email or "").strip().lower()
    if "@" not in cleaned:
        return _inconclusive(cleaned, "aadsts", error="invalid_email")
    if not _guard_one_probe(cleaned):
        return _inconclusive(cleaned, "aadsts", error="already_probed")

    body = {
        "grant_type": "password",
        "client_id": _MS_CLIENT_ID,
        "username": cleaned,
        "password": f"invalid_{uuid.uuid4()}",
        "resource": "https://graph.microsoft.com",
    }
    try:
        async with build_client(timeout=max(float(timeout_seconds), 1.0)) as client:
            response = await client.post(
                _TOKEN_URL,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except Exception as exc:  # noqa: BLE001 - surface as inconclusive
        return _inconclusive(cleaned, "aadsts", error=f"{type(exc).__name__}: {exc}")

    if response.status_code == 429:
        _LOG.debug("AADSTS probe rate-limited (429) for %s", cleaned)
        return _inconclusive(cleaned, "aadsts", error="rate_limited", http_status=429)

    code = _extract_aadsts_code(response)
    if code is None or code not in AADSTS_CODES:
        return _inconclusive(
            cleaned, "aadsts", error=f"unmapped_code:{code}", http_status=response.status_code
        )

    mapping = AADSTS_CODES[code]
    return ActiveProbeResult(
        email=cleaned,
        check="aadsts",
        status=mapping["status"],
        detail=mapping["detail"],
        confidence=float(mapping["confidence"]),
        source_type=SOURCE_AADSTS,
        http_status=response.status_code,
        aadsts_code=code,
    )


def _extract_aadsts_code(response: Any) -> str | None:
    """Pull the first ``AADSTS`` code out of a token error response."""
    description = ""
    try:
        payload = response.json()
        if isinstance(payload, dict):
            description = str(payload.get("error_description") or "")
    except Exception:  # noqa: BLE001 - fall back to raw text
        description = ""
    if not description:
        description = getattr(response, "text", "") or ""
    match = _AADSTS_RE.search(description)
    return match.group(0) if match else None


# ===========================================================================
# CHECK 2 — ActiveSync OPTIONS probe (on-prem / hybrid Exchange)
# ===========================================================================
def _activesync_hosts(domain: str, mail_host: str | None) -> list[str]:
    """Return candidate ActiveSync hosts in priority order."""
    hosts: list[str] = []
    if mail_host:
        hosts.append(mail_host.strip().lower())
    cleaned_domain = (domain or "").strip().lower().rstrip(".")
    if cleaned_domain:
        for prefix in ("mail", "autodiscover"):
            candidate = f"{prefix}.{cleaned_domain}"
            if candidate not in hosts:
                hosts.append(candidate)
    return hosts


def _interpret_activesync(
    status_code: int, headers: dict[str, str], elapsed_ms: float
) -> tuple[str, str | None]:
    """Map an ActiveSync OPTIONS response to ``(status, detail)``."""
    lower = {k.lower(): (v or "") for k, v in headers.items()}
    if status_code == 403:
        return "exists", "access_denied"
    if status_code == 200:
        return "exists", "activesync_ok"
    if status_code == 404:
        # ActiveSync not enabled on this host — says nothing about the account.
        return "inconclusive", "activesync_not_enabled"
    if status_code == 401:
        www_auth = lower.get("www-authenticate", "")
        if "basic" not in www_auth.lower() and "ntlm" not in www_auth.lower():
            return "inconclusive", "unexpected_challenge"
        if "x-ms-credential-service" in lower:
            return "exists", "credential_service_header"
        if elapsed_ms >= _ACTIVESYNC_SLOW_MS:
            return "exists", "slow_mailbox_lookup"
        return "not_found", "fast_reject"
    return "inconclusive", f"http_{status_code}"


async def probe_activesync(
    email: str,
    *,
    domain: str | None = None,
    mail_host: str | None = None,
    timeout_seconds: float = 10.0,
) -> ActiveProbeResult:
    """Check 2 — single ActiveSync ``OPTIONS`` probe with an invalid credential.

    The ``{mail_host}`` is, in priority order: the NTLM host from Phase 2 (if
    supplied), ``mail.{domain}``, then ``autodiscover.{domain}``.  Response
    interpretation is a timing + header heuristic (see
    :func:`_interpret_activesync`).
    """
    cleaned = (email or "").strip().lower()
    if "@" not in cleaned:
        return _inconclusive(cleaned, "activesync", error="invalid_email")
    if not _guard_one_probe(cleaned):
        return _inconclusive(cleaned, "activesync", error="already_probed")

    resolved_domain = (domain or cleaned.rsplit("@", 1)[-1]).strip().lower()
    hosts = _activesync_hosts(resolved_domain, mail_host)
    if not hosts:
        return _inconclusive(cleaned, "activesync", error="no_host")

    host = hosts[0]
    url = f"https://{host}/Microsoft-Server-ActiveSync"
    token = base64.b64encode(
        f"{cleaned}:invalid_{uuid.uuid4()}".encode()
    ).decode("ascii")
    headers = {
        "Authorization": f"Basic {token}",
        "MS-ASProtocolVersion": "14.1",
        "User-Agent": "Apple-iPhone9C1/1602.92",
    }
    start = time.perf_counter()
    try:
        async with build_client(
            timeout=max(float(timeout_seconds), 1.0), follow_redirects=False
        ) as client:
            response = await client.request("OPTIONS", url, headers=headers)
    except Exception as exc:  # noqa: BLE001 - surface as inconclusive
        return _inconclusive(cleaned, "activesync", error=f"{type(exc).__name__}: {exc}")
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    status, detail = _interpret_activesync(
        response.status_code, dict(response.headers), elapsed_ms
    )
    result = ActiveProbeResult(
        email=cleaned,
        check="activesync",
        status=status,
        detail=detail,
        http_status=response.status_code,
        elapsed_ms=round(elapsed_ms, 2),
    )
    if status != "inconclusive":
        result.source_type = SOURCE_ACTIVESYNC
        result.confidence = 0.65
    return result


# ===========================================================================
# CHECK 3 — WS-Trust RST2 federated existence (ADFS)
# ===========================================================================
def _build_rst2_envelope(email: str, adfs_url: str) -> str:
    """Return a WS-Trust RST2 SOAP envelope with an invalid UsernameToken."""
    message_id = f"urn:uuid:{uuid.uuid4()}"
    password = f"invalid_{uuid.uuid4()}"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:a="http://www.w3.org/2005/08/addressing"'
        ' xmlns:o="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-wssecurity-secext-1.0.xsd">'
        "<s:Header>"
        "<a:Action s:mustUnderstand=\"1\">"
        "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>"
        f"<a:MessageID>{message_id}</a:MessageID>"
        "<a:ReplyTo><a:Address>"
        "http://www.w3.org/2005/08/addressing/anonymous"
        "</a:Address></a:ReplyTo>"
        f"<a:To s:mustUnderstand=\"1\">{adfs_url}</a:To>"
        "<o:Security s:mustUnderstand=\"1\">"
        "<o:UsernameToken>"
        f"<o:Username>{email}</o:Username>"
        f"<o:Password>{password}</o:Password>"
        "</o:UsernameToken>"
        "</o:Security>"
        "</s:Header>"
        "<s:Body>"
        '<trust:RequestSecurityToken'
        ' xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust">'
        '<wsp:AppliesTo'
        ' xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">'
        "<a:EndpointReference>"
        "<a:Address>urn:federation:MicrosoftOnline</a:Address>"
        "</a:EndpointReference></wsp:AppliesTo>"
        "<trust:RequestType>"
        "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue"
        "</trust:RequestType>"
        "</trust:RequestSecurityToken>"
        "</s:Body>"
        "</s:Envelope>"
    )


def _interpret_wstrust(text: str) -> tuple[str, str | None]:
    """Map a WS-Trust SOAP response body to ``(status, detail)``."""
    lowered = text.lower()
    if "throttlingexception" in lowered:
        return "inconclusive", "throttled"
    if "user does not exist" in lowered or "unknown user" in lowered:
        return "not_found", "user_not_found"
    if "failedauthentication" in lowered:
        return "exists", "authentication_attempted"
    if "requestsecuritytokenresponse" in lowered and "fault" not in lowered:
        return "exists", "token_issued"
    return "inconclusive", "unrecognised_fault"


async def probe_wstrust(
    email: str,
    adfs_url: str | None,
    *,
    timeout_seconds: float = 10.0,
) -> ActiveProbeResult:
    """Check 3 — WS-Trust RST2 existence probe against a federated ADFS.

    Runs only when *adfs_url* is known (surfaced by Phase 1 GetUserRealm and
    stashed on the passive context).  With no ADFS URL the check is skipped
    entirely and returns an inconclusive result without consuming the probe
    guard.

    * SOAP ``FailedAuthentication``     → account exists.
    * ``user does not exist`` fault     → not found.
    * ``ThrottlingException``           → inconclusive.
    """
    cleaned = (email or "").strip().lower()
    if "@" not in cleaned:
        return _inconclusive(cleaned, "wstrust", error="invalid_email")
    if not adfs_url:
        # Skip entirely — do not consume the one-probe guard.
        return _inconclusive(cleaned, "wstrust", error="no_adfs_url")
    if not _guard_one_probe(cleaned):
        return _inconclusive(cleaned, "wstrust", error="already_probed")

    envelope = _build_rst2_envelope(cleaned, adfs_url)
    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "SOAPAction": "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue",
    }
    try:
        async with build_client(timeout=max(float(timeout_seconds), 1.0)) as client:
            response = await client.post(adfs_url, content=envelope, headers=headers)
    except Exception as exc:  # noqa: BLE001 - surface as inconclusive
        return _inconclusive(cleaned, "wstrust", error=f"{type(exc).__name__}: {exc}")

    status, detail = _interpret_wstrust(getattr(response, "text", "") or "")
    result = ActiveProbeResult(
        email=cleaned,
        check="wstrust",
        status=status,
        detail=detail,
        http_status=response.status_code,
    )
    if status != "inconclusive":
        result.source_type = SOURCE_WSTRUST
        result.confidence = 0.85
    return result


# ===========================================================================
# EXECUTION ORDER — mutually-exclusive check selection
# ===========================================================================
_CLOUD_PROVIDERS = {"m365", "cloud", "managed"}


def select_active_check(provider: Any, adfs_url: str | None) -> str:
    """Choose the single most appropriate check for an account.

    * a known ADFS URL (federated tenant) → ``"wstrust"``.
    * an M365 / cloud / managed tenant    → ``"aadsts"`` (highest signal).
    * everything else (on-prem, hybrid, unknown) → ``"activesync"``.
    """
    if adfs_url:
        return "wstrust"
    provider_value = getattr(provider, "value", provider)
    if str(provider_value or "").strip().lower() in _CLOUD_PROVIDERS:
        return "aadsts"
    return "activesync"


async def run_active_probe(
    email: str,
    check: str,
    *,
    adfs_url: str | None = None,
    mail_host: str | None = None,
    domain: str | None = None,
    timeout: float = 10.0,
) -> ActiveProbeResult:
    """Run one explicitly-selected active check for *email*.

    Thin dispatch used by the harvest pipeline, which selects *check* up front
    via :func:`select_active_check`.  The chosen probe still enforces the
    module-level one-probe guard.
    """
    cleaned = (email or "").strip().lower()
    if check == "aadsts":
        return await probe_aadsts(cleaned, timeout_seconds=timeout)
    if check == "wstrust":
        return await probe_wstrust(cleaned, adfs_url, timeout_seconds=timeout)
    if check == "activesync":
        return await probe_activesync(
            cleaned, domain=domain, mail_host=mail_host, timeout_seconds=timeout
        )
    return _inconclusive(cleaned, check or "none", error="unknown_check")


async def run_m365_active_intel(
    email: str,
    *,
    provider: Any = None,
    adfs_url: str | None = None,
    mail_host: str | None = None,
    domain: str | None = None,
    enable_aadsts: bool = True,
    enable_activesync: bool = True,
    enable_wstrust: bool = True,
    timeout_seconds: float = 10.0,
) -> ActiveProbeResult:
    """Run the single most appropriate active check for *email*.

    The checks are mutually exclusive — exactly one runs per email, gated
    after the provider is known.  The selected check enforces the module-level
    one-probe guard, so the same account is never probed twice per process.
    """
    cleaned = (email or "").strip().lower()
    if "@" not in cleaned:
        return _inconclusive(cleaned, "none", error="invalid_email")

    check = select_active_check(provider, adfs_url)
    if check == "wstrust":
        if not enable_wstrust:
            return _inconclusive(cleaned, "wstrust", error="disabled")
        return await probe_wstrust(cleaned, adfs_url, timeout_seconds=timeout_seconds)
    if check == "aadsts":
        if not enable_aadsts:
            return _inconclusive(cleaned, "aadsts", error="disabled")
        return await probe_aadsts(cleaned, timeout_seconds=timeout_seconds)
    if not enable_activesync:
        return _inconclusive(cleaned, "activesync", error="disabled")
    return await probe_activesync(
        cleaned, domain=domain, mail_host=mail_host, timeout_seconds=timeout_seconds
    )


__all__ = [
    "AADSTS_CODES",
    "ActiveProbeResult",
    "SOURCE_AADSTS",
    "SOURCE_ACTIVESYNC",
    "SOURCE_WSTRUST",
    "probe_aadsts",
    "probe_activesync",
    "probe_wstrust",
    "select_active_check",
    "run_active_probe",
    "run_m365_active_intel",
]
