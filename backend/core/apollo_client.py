"""Phase 7B — Apollo.io people-enrichment connector (BYO key).

Apollo's People Match endpoint returns *published business contact* data
(name, title, company, LinkedIn, work location) for a queried email. The
operator supplies their own free-tier key (``apollo_api_key``); MailAccess
never ships one. Monthly usage is budgeted through :mod:`provider_budget` so a
free tier is never silently overrun, and the connector is classified
lawful-public under Phase 2B (allowed in every product mode).

Error-handling contract (mirrors ``hunter_client``): HTTP 401/403 latches an
invalid-key flag once and skips every subsequent call for the process life;
429 is logged and skipped; any network/timeout error returns ``None`` and never
raises. Timeout is 15s. The BYO key is sent in the ``X-Api-Key`` header — never
in a URL query string.
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

PROVIDER = "apollo"
#: Evidence ``source_type`` + canonical policy-module name (see product_mode).
SOURCE_TYPE = "apollo"
POLICY_MODULE = "apollo"

_MATCH_URL = "https://api.apollo.io/v1/people/match"
_TIMEOUT = 15.0

_KEY_INVALID = False
_KEY_INVALID_LOCK = threading.Lock()


def _mark_key_invalid() -> None:
    global _KEY_INVALID
    with _KEY_INVALID_LOCK:
        if not _KEY_INVALID:
            _LOG.warning("Apollo API key rejected (401/403); skipping Apollo for this process.")
        _KEY_INVALID = True


def key_invalid() -> bool:
    with _KEY_INVALID_LOCK:
        return _KEY_INVALID


def reset_key_invalid_for_tests() -> None:
    global _KEY_INVALID
    with _KEY_INVALID_LOCK:
        _KEY_INVALID = False


def _monthly_limit() -> int:
    return int(getattr(settings, "apollo_monthly_limit", 0) or 0)


def _enabled() -> bool:
    return bool(getattr(settings, "enable_apollo", False)) and bool(
        getattr(settings, "apollo_api_key", None)
    )


def _normalize(person: dict[str, Any]) -> EnrichmentResult:
    fields: dict[str, str] = {}

    def _put(key: str, value: Any) -> None:
        if isinstance(value, str) and value.strip():
            fields[key] = value.strip()

    _put("full_name", person.get("name"))
    _put("first", person.get("first_name"))
    _put("last", person.get("last_name"))
    _put("job_title", person.get("title"))
    _put("linkedin_url", person.get("linkedin_url"))
    org = person.get("organization")
    if isinstance(org, dict):
        _put("company", org.get("name"))
    # Apollo splits work location across city/state/country.
    loc = ", ".join(
        p for p in (person.get("city"), person.get("state"), person.get("country"))
        if isinstance(p, str) and p.strip()
    )
    if loc:
        fields["location"] = loc
    # Apollo returns a business phone only when present and unlocked.
    phones = person.get("phone_numbers")
    if isinstance(phones, list):
        for ph in phones:
            if isinstance(ph, dict):
                _put("phone", ph.get("raw_number") or ph.get("sanitized_number"))
                if "phone" in fields:
                    break

    return EnrichmentResult(
        provider=PROVIDER,
        source_type=SOURCE_TYPE,
        fields=fields,
        # Apollo returns a match only when it is confident; treat a returned
        # person record with fields as a confident business-data hit.
        confidence=0.75 if fields else 0.0,
        source_url=fields.get("linkedin_url"),
        raw=None,
    )


async def enrich(
    email: str, *, full_name: str | None = None, domain: str | None = None
) -> EnrichmentResult | None:
    """Enrich *email* via Apollo People Match. Returns ``None`` on any miss.

    Skips (returns ``None``) when disabled, keyless, invalid-key latched, budget
    exhausted, or disallowed in the active product mode.
    """
    if not _enabled() or key_invalid():
        return None
    # Defense-in-depth: the waterfall already gates on mode, but refuse here too.
    if not is_module_allowed(POLICY_MODULE, get_active_mode()):
        return None
    if not provider_budget.reserve(PROVIDER, _monthly_limit()):
        return None

    key = str(getattr(settings, "apollo_api_key"))
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _MATCH_URL,
                headers={"X-Api-Key": key, "Content-Type": "application/json"},
                json={"email": email},
            )
    except (httpx.HTTPError, OSError):
        return None

    if resp.status_code in (401, 403):
        _mark_key_invalid()
        return None
    if resp.status_code == 429:
        _LOG.warning("Apollo rate-limited (429); skipping.")
        return None
    if resp.status_code != 200:
        return None
    try:
        payload = resp.json()
    except ValueError:  # includes json.JSONDecodeError
        return None
    person = payload.get("person") if isinstance(payload, dict) else None
    if not isinstance(person, dict):
        return None
    result = _normalize(person)
    return result if result.has_fields() else None
