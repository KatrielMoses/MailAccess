"""Phase 7B — People Data Labs person-enrichment connector (BYO key).

PDL returns *aggregated / data-broker* person data. That makes it a personal
pivot under Phase 2B: it is classified in ``_PERSONAL_PIVOT_BLOCKED`` and so is
allowed **only** in security-investigation mode — the waterfall will not call it
in public-business-contact or org-authorized-verification mode, and this client
refuses as defense-in-depth. A data-broker key does not buy a way around the
lawful gate.

BYO key (``pdl_api_key``), monthly free tier budgeted via :mod:`provider_budget`.
Same error contract as the other connectors (401/403 latch, 429 skip,
network/timeout → ``None``, never raises, 15s timeout). The email is sent in a
POST body with the key in the ``X-Api-Key`` header — never in a URL query
string.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

import httpx

from ..config import settings
from . import provider_budget
from .enrichment_base import EnrichmentResult
from .product_mode import get_active_mode, is_module_allowed

_LOG = logging.getLogger(__name__)

PROVIDER = "pdl"
SOURCE_TYPE = "pdl"
POLICY_MODULE = "pdl"

_ENRICH_URL = "https://api.peopledatalabs.com/v5/person/enrich"
_TIMEOUT = 15.0

_KEY_INVALID = False
_KEY_INVALID_LOCK = threading.Lock()


def _mark_key_invalid() -> None:
    global _KEY_INVALID
    with _KEY_INVALID_LOCK:
        if not _KEY_INVALID:
            _LOG.warning("PDL API key rejected (401/403); skipping PDL for this process.")
        _KEY_INVALID = True


def key_invalid() -> bool:
    with _KEY_INVALID_LOCK:
        return _KEY_INVALID


def reset_key_invalid_for_tests() -> None:
    global _KEY_INVALID
    with _KEY_INVALID_LOCK:
        _KEY_INVALID = False


def _monthly_limit() -> int:
    return int(getattr(settings, "pdl_monthly_limit", 0) or 0)


def _enabled() -> bool:
    return bool(getattr(settings, "enable_pdl", False)) and bool(
        getattr(settings, "pdl_api_key", None)
    )


def _normalize(data: dict[str, Any], likelihood: Any) -> EnrichmentResult:
    fields: dict[str, str] = {}

    def _put(key: str, value: Any) -> None:
        if isinstance(value, str) and value.strip():
            fields[key] = value.strip()

    _put("full_name", data.get("full_name"))
    _put("first", data.get("first_name"))
    _put("last", data.get("last_name"))
    _put("job_title", data.get("job_title"))
    _put("linkedin_url", data.get("linkedin_url"))
    _put("company", data.get("job_company_name"))
    _put("location", data.get("location_name"))
    _put("phone", data.get("mobile_phone"))
    if "phone" not in fields:
        phones = data.get("phone_numbers")
        if isinstance(phones, list) and phones and isinstance(phones[0], str):
            _put("phone", phones[0])

    # PDL likelihood is 1..10; map to a 0..1 confidence.
    try:
        conf = max(0.0, min(1.0, float(likelihood) / 10.0))
    except (TypeError, ValueError):
        conf = 0.5 if fields else 0.0
    return EnrichmentResult(
        provider=PROVIDER,
        source_type=SOURCE_TYPE,
        fields=fields,
        confidence=conf if fields else 0.0,
        source_url=data.get("linkedin_url") if isinstance(data.get("linkedin_url"), str) else None,
        raw=None,
    )


async def enrich(
    email: str, *, full_name: str | None = None, domain: str | None = None
) -> EnrichmentResult | None:
    """Enrich *email* via PDL Person Enrich. Returns ``None`` on any miss.

    Skips when disabled, keyless, invalid-key latched, budget exhausted, or
    disallowed in the active mode (PDL is security-only).
    """
    if not _enabled() or key_invalid():
        return None
    if not is_module_allowed(POLICY_MODULE, get_active_mode()):
        return None
    if not provider_budget.reserve(PROVIDER, _monthly_limit()):
        return None

    key = str(getattr(settings, "pdl_api_key"))
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _ENRICH_URL,
                headers={"X-Api-Key": key, "Content-Type": "application/json"},
                json={"email": email, "min_likelihood": 2},
            )
    except (httpx.HTTPError, OSError):
        return None

    if resp.status_code in (401, 403):
        _mark_key_invalid()
        return None
    if resp.status_code == 429:
        _LOG.warning("PDL rate-limited (429); skipping.")
        return None
    # PDL returns 404 when no person matches — a normal miss, not an error.
    if resp.status_code != 200:
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    result = _normalize(data, payload.get("likelihood"))
    return result if result.has_fields() else None
