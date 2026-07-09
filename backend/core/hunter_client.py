"""Hunter.io domain-search integration.

0.11.1 Phase 4 — optional Hunter.io domain search integration.
50 credits/month free, no CC required.  Only active when
``HUNTER_IO_API_KEY`` is set in the environment.

Rate limit: 1 req/sec.  On 401/403 logs a helpful message and
returns an empty list (graceful degradation).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

import httpx

_LOG = logging.getLogger(__name__)

_CSE_URL = "https://api.hunter.io/v2/domain-search"


@dataclass
class HunterResult:
    """One email record returned by the Hunter.io domain-search endpoint."""

    email: str
    email_type: str  # "personal" | "generic"
    confidence: int  # Hunter's 0-100 score
    first_name: str | None
    last_name: str | None
    position: str | None
    source_count: int


async def search_domain(
    domain: str,
    api_key: str,
    limit: int = 10,
) -> list[HunterResult]:
    """Search Hunter.io for email addresses matching *domain*.

    Parameters
    ----------
    domain:
        Target domain, e.g. ``"example.com"``.
    api_key:
        Hunter.io API key.  Retrieve from hunter.io → API.
    limit:
        Maximum number of results to request (Hunter caps at 100).

    Returns
    -------
    A list of :class:`HunterResult`.  Returns an empty list on any
    error (401/403 quota error, network failure, etc.) so callers
    never crash on missing or invalid credentials.
    """
    if not api_key:
        return []
    if not domain:
        return []

    params = {
        "domain": domain,
        "api_key": api_key,
        "limit": min(int(limit), 100),
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(_CSE_URL, params=params)

            if response.status_code in (401, 403):
                _LOG.warning(
                    "Hunter API key invalid or expired (HTTP %s). "
                    "Check your key at hunter.io.",
                    response.status_code,
                )
                return []

            if response.status_code == 429:
                _LOG.warning("Hunter monthly quota exhausted (HTTP 429).")
                return []

            if response.status_code != 200:
                _LOG.warning(
                    "Hunter API returned HTTP %s for domain=%r",
                    response.status_code,
                    domain,
                )
                return []

        # Rate limit: 1 req/sec.
        await asyncio.sleep(1.0)

    except httpx.TimeoutException:
        _LOG.warning("Hunter API timed out for domain=%r", domain)
        return []
    except Exception as exc:
        _LOG.warning("Hunter API network error for domain=%r: %s", domain, exc)
        return []

    try:
        data = response.json()
    except Exception as exc:
        _LOG.warning("Hunter API returned unparseable JSON for domain=%r: %s", domain, exc)
        return []

    emails_raw: list[dict[str, Any]] = data.get("data", {}).get("emails", [])
    results: list[HunterResult] = []

    for entry in emails_raw:
        email = str(entry.get("value") or "").strip()
        if not email or "@" not in email:
            continue
        results.append(
            HunterResult(
                email=email,
                email_type=str(entry.get("type") or "generic"),
                confidence=int(entry.get("confidence") or 0),
                first_name=str(entry.get("first_name") or "") or None,
                last_name=str(entry.get("last_name") or "") or None,
                position=str(entry.get("position") or "") or None,
                source_count=int(
                    sum(1 for s in (entry.get("sources") or []) if isinstance(s, dict))
                ),
            )
        )

    return results


def hunter_confidence_score(hunter_confidence: int) -> float:
    """Map Hunter.io's 0-100 confidence to a MailAccess source weight.

    0.11.1 Phase 4.
    """
    if hunter_confidence >= 90:
        return 0.85  # hunter_verified
    if hunter_confidence >= 70:
        return 0.70  # hunter_high
    return 0.45  # hunter_low


def hunter_source_type(hunter_confidence: int) -> str:
    """Return the :data:`email_confidence.SOURCE_WEIGHTS` key for a
    Hunter confidence score."""
    if hunter_confidence >= 90:
        return "hunter_verified"
    if hunter_confidence >= 70:
        return "hunter_high"
    return "hunter_low"
