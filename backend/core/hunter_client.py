"""Hunter.io domain-search integration.

0.11.1 Phase 4 — optional Hunter.io domain search integration.
50 credits/month free, no CC required.  Only active when
``HUNTER_IO_API_KEY`` is set in the environment.

Rate limit: 1 req/sec.  On 401/403 logs a helpful message and
returns an empty list (graceful degradation).

P1 (Phase 3 workstream): the integration also surfaces
``data.pattern`` — Hunter's most-common email pattern for the
domain — and applies a monthly usage circuit breaker capped at
:data:`HUNTER_MONTHLY_CAP` calls per calendar month.  The
breaker is persisted to a tiny JSON file in
:data:`HUNTER_USAGE_PATH` so the limit survives process restarts
within the same month.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

_LOG = logging.getLogger(__name__)

_CSE_URL = "https://api.hunter.io/v2/domain-search"

# P1: monthly usage circuit breaker.  Hunter's free tier is
# 50 credits/month, so we cap at 45 (5-call safety margin for
# retries triggered by transient transport errors).  The cap is
# intentionally conservative — running out of credits mid-batch
# silently breaks every downstream Hunter call.
HUNTER_MONTHLY_CAP: int = 45

#: File path for the persistent monthly-call counter.  Resolved
#: lazily on first read so tests can monkeypatch the env var.
HUNTER_USAGE_PATH: str = "~/.mailaccess/hunter_usage.json"

# Maps Hunter's short-form pattern strings (e.g. ``"{first}.{last}"``)
# to a full MailAccess template (with the ``@{domain}`` suffix).
# Unknown patterns fall back to ``None`` so callers can detect them.
_HUNTER_PATTERN_MAP: dict[str, str] = {
    "{first}.{last}": "{first}.{last}@{domain}",
    "{first}": "{first}@{domain}",
    "{f}{last}": "{f}{last}@{domain}",
    "{first}{last}": "{first}{last}@{domain}",
    "{first}{l}": "{first}{l}@{domain}",
    "{last}.{first}": "{last}.{first}@{domain}",
    "{last}": "{last}@{domain}",
    "{first}_{last}": "{first}_{last}@{domain}",
    "{first}-{last}": "{first}-{last}@{domain}",
    "{f}.{last}": "{f}.{last}@{domain}",
    "{last}{f}": "{last}{f}@{domain}",
}


def map_hunter_pattern(hunter_pattern: str | None) -> str | None:
    """Map a Hunter ``data.pattern`` value to a MailAccess template.

    Returns ``None`` for missing, empty, or unrecognised patterns.
    Unknown patterns log a debug-level message so the operator can
    extend :data:`_HUNTER_PATTERN_MAP` if Hunter adds new variants.
    """
    if not hunter_pattern:
        return None
    cleaned = str(hunter_pattern).strip()
    if not cleaned:
        return None
    mapped = _HUNTER_PATTERN_MAP.get(cleaned)
    if mapped is None:
        _LOG.debug(
            "hunter_client: unrecognised Hunter pattern %r; "
            "add to _HUNTER_PATTERN_MAP to enable boost",
            cleaned,
        )
    return mapped


class HunterCircuitOpen(Exception):
    """Raised internally when the monthly cap is reached.

    The public :func:`search_domain` catches this and returns an
    empty list — callers never see the exception.  The class is
    exported for tests that need to assert the breaker fired.
    """


@dataclass
class _HunterUsage:
    """Persistent monthly-call counter payload."""

    year_month: str
    calls: int = 0

    def reset_for(self, year_month: str) -> None:
        self.year_month = year_month
        self.calls = 0


# Single lock for the in-process counter; the on-disk JSON is the
# authoritative cross-process source.
_HUNTER_USAGE_LOCK = threading.Lock()
_HUNTER_USAGE_PATH_OVERRIDE: str | None = None


def _resolve_usage_path() -> Path:
    """Return the active path for the usage JSON file."""
    override = _HUNTER_USAGE_OVERRIDE_PATH or _HUNTER_USAGE_PATH_OVERRIDE
    raw = os.environ.get("MAILACCESS_HUNTER_USAGE_PATH") or override
    return Path(os.path.expanduser(raw or HUNTER_USAGE_PATH))


# Set via :func:`set_hunter_usage_path_for_tests` to redirect the
# usage file into a temp dir.  This is read in :func:`_resolve_usage_path`.
_HUNTER_USAGE_OVERRIDE_PATH: str | None = None


def set_hunter_usage_path_for_tests(path: str | None) -> None:
    """Test-only: redirect the Hunter usage counter to *path*.

    Pass ``None`` to clear the override and revert to the env-var
    / default resolution.
    """
    global _HUNTER_USAGE_PATH_OVERRIDE
    _HUNTER_USAGE_PATH_OVERRIDE = path


def _read_usage() -> _HunterUsage:
    """Read the persistent usage counter; never raises."""
    path = _resolve_usage_path()
    current_ym = datetime.now(timezone.utc).strftime("%Y-%m")
    if not path.exists():
        return _HunterUsage(year_month=current_ym)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        _LOG.warning(
            "Hunter usage file unreadable (%s); resetting to %s",
            exc,
            current_ym,
        )
        return _HunterUsage(year_month=current_ym)
    if not isinstance(payload, dict):
        return _HunterUsage(year_month=current_ym)
    ym = str(payload.get("year_month") or "")
    calls_raw = payload.get("calls", 0)
    try:
        calls = max(0, int(calls_raw))
    except (TypeError, ValueError):
        calls = 0
    if ym != current_ym:
        return _HunterUsage(year_month=current_ym)
    return _HunterUsage(year_month=ym, calls=calls)


def _write_usage(usage: _HunterUsage) -> None:
    """Persist *usage* atomically; never raises."""
    path = _resolve_usage_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _LOG.warning("Hunter usage dir creation failed: %s", exc)
        return
    # Atomic write via tempfile+os.replace so a partial file never
    # corrupts the counter.
    try:
        fd, tmp = tempfile.mkstemp(prefix="hunter-usage-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(
                    {"year_month": usage.year_month, "calls": usage.calls},
                    fh,
                )
            os.replace(tmp, path)
        except OSError:
            # Best-effort cleanup if the rename fails.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as exc:
        _LOG.warning("Hunter usage file write failed: %s", exc)


def hunter_calls_this_month() -> int:
    """Return the current month's persisted call count.

    Read-only; does not advance the counter.  Useful for telemetry
    and tests.
    """
    with _HUNTER_USAGE_LOCK:
        return _read_usage().calls


def hunter_circuit_open() -> bool:
    """Return True if the monthly cap has been hit."""
    with _HUNTER_USAGE_LOCK:
        return _read_usage().calls >= HUNTER_MONTHLY_CAP


def _reserve_hunter_call() -> bool:
    """Increment the monthly call counter; return False when capped.

    The reservation is durable (written to disk) so a process crash
    does not free a slot the breaker had already counted.  Callers
    MUST treat a ``False`` return as "do not call the API".
    """
    with _HUNTER_USAGE_LOCK:
        current_ym = datetime.now(timezone.utc).strftime("%Y-%m")
        usage = _read_usage()
        if usage.year_month != current_ym:
            usage.reset_for(current_ym)
        if usage.calls >= HUNTER_MONTHLY_CAP:
            return False
        usage.calls += 1
        _write_usage(usage)
        return True


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
    # P1: Hunter's most-common email pattern for the domain (raw
    # short form, e.g. ``"{first}.{last}"``).  ``None`` when the
    # API did not include ``data.pattern`` for this query.
    pattern: str | None = None
    # P1: Hunter's short-form pattern mapped to a full MailAccess
    # template (with ``@{domain}`` suffix).  ``None`` when no
    # mapping applies.  See :func:`map_hunter_pattern`.
    pattern_template: str | None = field(default=None, repr=False)


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

    # P1: monthly usage circuit breaker.  Reserve a slot up front
    # so a process crash mid-request still consumes the call —
    # Hunter counts every API hit regardless of success.
    if not _reserve_hunter_call():
        _LOG.warning(
            "Hunter monthly cap reached (%d calls); skipping API call for %r",
            HUNTER_MONTHLY_CAP,
            domain,
        )
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
    # P1: pull `data.pattern` once per response — Hunter returns the
    # same value for every email in the batch.  Keep the raw short
    # form (e.g. ``"{first}.{last}"``) on each result for audit, and
    # expose the mapped full template for downstream boosts.
    raw_pattern = data.get("data", {}).get("pattern")
    raw_pattern_str = str(raw_pattern).strip() if raw_pattern else ""
    if not raw_pattern_str or raw_pattern_str.lower() == "null":
        raw_pattern_str = ""
    mapped_template = map_hunter_pattern(raw_pattern_str) if raw_pattern_str else None
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
                pattern=raw_pattern_str or None,
                pattern_template=mapped_template,
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
