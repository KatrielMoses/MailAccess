"""Hunter.io integration — domain search + email verification.

Phase 6 (0.14.0) — the full Hunter.io integration.  Two capabilities:

* **Domain search** (:func:`search_domain`) — the harvest path.  Finds
  known emails for a target domain, maps Hunter's 0-100 confidence to a
  MailAccess source weight, and surfaces ``data.pattern`` (Hunter's
  dominant email format) for the format-inference pipeline.
* **Email verification** (:func:`verify_email`) — the investigate path.
  Verifies a single address against Hunter's database and maps the
  ``result``/``score`` pair to a MailAccess confidence.

Free tier: 25 domain searches / month and 25 verifications / month, no
CC required.  Both are counted independently against a persistent monthly
circuit breaker stored in :data:`HUNTER_USAGE_PATH`
(``~/.mailaccess/hunter_usage.json``) so the caps survive process restarts
within the same calendar month.  The counters reset automatically on a
month boundary.

Error handling contract (both capabilities): on HTTP 401 the key is logged
as invalid exactly once and an internal flag skips every subsequent call
for the life of the process; on 429 the rate limit is logged and the call
is skipped; on any network/transport error or timeout an empty result is
returned and never raised.  Timeout is 15s.
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

from ..config import settings

_LOG = logging.getLogger(__name__)

_DOMAIN_SEARCH_URL = "https://api.hunter.io/v2/domain-search"
_EMAIL_VERIFIER_URL = "https://api.hunter.io/v2/email-verifier"

#: 15s per-request timeout (Phase 6 contract).
_HUNTER_TIMEOUT: float = 15.0

#: File path for the persistent monthly-usage counter.  Resolved lazily
#: on first read so tests can monkeypatch the env var / override.
HUNTER_USAGE_PATH: str = "~/.mailaccess/hunter_usage.json"

#: Backward-compatible alias for the domain-search monthly cap.  The
#: authoritative limits now live in settings
#: (``hunter_domain_search_limit`` / ``hunter_verify_limit``); this
#: constant is retained for callers that surface a cap in telemetry.
HUNTER_MONTHLY_CAP: int = 25

# Maps Hunter's short-form pattern strings (e.g. ``"first.last"`` or the
# already-braced ``"{first}.{last}"``) to a full MailAccess template
# (with the ``@{domain}`` suffix).  Unknown patterns fall back to ``None``
# so callers can detect them.
_HUNTER_PATTERN_MAP: dict[str, str] = {
    "first.last": "{first}.{last}@{domain}",
    "first": "{first}@{domain}",
    "flast": "{f}{last}@{domain}",
    "firstlast": "{first}{last}@{domain}",
    "firstl": "{first}{l}@{domain}",
    "last.first": "{last}.{first}@{domain}",
    "last": "{last}@{domain}",
    "first_last": "{first}_{last}@{domain}",
    "first-last": "{first}-{last}@{domain}",
    "f.last": "{f}.{last}@{domain}",
    "lastf": "{last}{f}@{domain}",
    # Braced variants — Hunter occasionally returns the template already
    # in ``{first}.{last}`` form.
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

    Handles both Hunter's bare short forms (``"first.last"``) and the
    braced form (``"{first}.{last}"``).  Returns ``None`` for missing,
    empty, or unrecognised patterns.
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


# ---------------------------------------------------------------------------
# Invalid-key latch: on the first 401, log once and skip every remaining
# Hunter call for the life of the process.
# ---------------------------------------------------------------------------

_HUNTER_KEY_INVALID = False
_HUNTER_KEY_INVALID_LOCK = threading.Lock()


def _mark_key_invalid() -> None:
    global _HUNTER_KEY_INVALID
    with _HUNTER_KEY_INVALID_LOCK:
        if not _HUNTER_KEY_INVALID:
            _LOG.warning("Hunter.io API key invalid.")
        _HUNTER_KEY_INVALID = True


def hunter_key_invalid() -> bool:
    """Return True once a 401 has latched the invalid-key flag."""
    with _HUNTER_KEY_INVALID_LOCK:
        return _HUNTER_KEY_INVALID


def reset_hunter_key_state_for_tests() -> None:
    """Test-only: clear the latched invalid-key flag."""
    global _HUNTER_KEY_INVALID
    with _HUNTER_KEY_INVALID_LOCK:
        _HUNTER_KEY_INVALID = False


# ---------------------------------------------------------------------------
# Persistent monthly usage counter.
# ---------------------------------------------------------------------------


class HunterCircuitOpen(Exception):
    """Raised internally when a monthly cap is reached.

    The public entry points catch this and return empty results — callers
    never see the exception.  Exported for tests that assert the breaker
    fired.
    """


@dataclass
class _HunterUsage:
    """Persistent monthly-usage payload.

    Schema (``~/.mailaccess/hunter_usage.json``)::

        {
          "month": "2026-07",
          "domain_searches": 12,
          "email_verifications": 8,
          "last_reset": "2026-07-01T00:00:00Z"
        }
    """

    month: str
    domain_searches: int = 0
    email_verifications: int = 0
    last_reset: str = ""

    def reset_for(self, month: str) -> None:
        self.month = month
        self.domain_searches = 0
        self.email_verifications = 0
        self.last_reset = f"{month}-01T00:00:00Z"


_HUNTER_USAGE_LOCK = threading.Lock()
_HUNTER_USAGE_PATH_OVERRIDE: str | None = None


def set_hunter_usage_path_for_tests(path: str | None) -> None:
    """Test-only: redirect the Hunter usage counter to *path*.

    Pass ``None`` to clear the override and revert to env-var / default
    resolution.
    """
    global _HUNTER_USAGE_PATH_OVERRIDE
    _HUNTER_USAGE_PATH_OVERRIDE = path


def _resolve_usage_path() -> Path:
    """Return the active path for the usage JSON file."""
    raw = os.environ.get("MAILACCESS_HUNTER_USAGE_PATH") or _HUNTER_USAGE_PATH_OVERRIDE
    return Path(os.path.expanduser(raw or HUNTER_USAGE_PATH))


def _current_month() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _read_usage() -> _HunterUsage:
    """Read the persistent usage counter; never raises.

    Resets in-memory when the persisted month differs from the current
    calendar month (the on-disk file is left untouched until the next
    write reserves a slot).
    """
    path = _resolve_usage_path()
    current = _current_month()
    fresh = _HunterUsage(month=current, last_reset=f"{current}-01T00:00:00Z")
    if not path.exists():
        return fresh
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        _LOG.warning("Hunter usage file unreadable (%s); resetting to %s", exc, current)
        return fresh
    if not isinstance(payload, dict):
        return fresh
    month = str(payload.get("month") or "")
    if month != current:
        # Month boundary crossed — start fresh for the new month.
        return fresh

    def _as_int(value: Any) -> int:
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return 0

    return _HunterUsage(
        month=month,
        domain_searches=_as_int(payload.get("domain_searches")),
        email_verifications=_as_int(payload.get("email_verifications")),
        last_reset=str(payload.get("last_reset") or f"{month}-01T00:00:00Z"),
    )


def _write_usage(usage: _HunterUsage) -> None:
    """Persist *usage* atomically; never raises."""
    path = _resolve_usage_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _LOG.warning("Hunter usage dir creation failed: %s", exc)
        return
    try:
        fd, tmp = tempfile.mkstemp(prefix="hunter-usage-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "month": usage.month,
                        "domain_searches": usage.domain_searches,
                        "email_verifications": usage.email_verifications,
                        "last_reset": usage.last_reset,
                    },
                    fh,
                )
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as exc:
        _LOG.warning("Hunter usage file write failed: %s", exc)


def hunter_usage_snapshot() -> dict[str, Any]:
    """Return the current month's persisted usage; read-only."""
    with _HUNTER_USAGE_LOCK:
        usage = _read_usage()
    return {
        "month": usage.month,
        "domain_searches": usage.domain_searches,
        "email_verifications": usage.email_verifications,
        "last_reset": usage.last_reset,
    }


def _domain_search_limit() -> int:
    return int(getattr(settings, "hunter_domain_search_limit", HUNTER_MONTHLY_CAP))


def _verify_limit() -> int:
    return int(getattr(settings, "hunter_verify_limit", HUNTER_MONTHLY_CAP))


def _tracking_enabled() -> bool:
    return bool(getattr(settings, "hunter_usage_tracking", True))


def reserve_domain_search() -> bool:
    """Reserve one domain-search slot; return False when the cap is hit.

    Warns when two-or-fewer searches remain; skips (returns False, logs
    "monthly quota exhausted") once the limit is reached.  Durable — the
    increment is written to disk before returning so a crash does not free
    a counted slot.  When usage tracking is disabled the call always
    succeeds and nothing is counted.
    """
    if not _tracking_enabled():
        return True
    limit = _domain_search_limit()
    with _HUNTER_USAGE_LOCK:
        current = _current_month()
        usage = _read_usage()
        if usage.month != current:
            usage.reset_for(current)
        if usage.domain_searches >= limit:
            _LOG.warning("Hunter.io: monthly quota exhausted.")
            return False
        usage.domain_searches += 1
        _write_usage(usage)
        remaining = limit - usage.domain_searches
    if 0 <= remaining <= 2:
        _LOG.warning(
            "Hunter.io: %d domain search%s remaining this month. Upgrade at hunter.io.",
            remaining,
            "" if remaining == 1 else "es",
        )
    return True


def reserve_verification() -> bool:
    """Reserve one email-verification slot; return False when capped.

    Same durability and warn/skip semantics as :func:`reserve_domain_search`,
    enforced against the independent ``email_verifications`` counter.
    """
    if not _tracking_enabled():
        return True
    limit = _verify_limit()
    with _HUNTER_USAGE_LOCK:
        current = _current_month()
        usage = _read_usage()
        if usage.month != current:
            usage.reset_for(current)
        if usage.email_verifications >= limit:
            _LOG.warning("Hunter.io: monthly quota exhausted.")
            return False
        usage.email_verifications += 1
        _write_usage(usage)
        remaining = limit - usage.email_verifications
    if 0 <= remaining <= 2:
        _LOG.warning(
            "Hunter.io: %d email verification%s remaining this month. Upgrade at hunter.io.",
            remaining,
            "" if remaining == 1 else "s",
        )
    return True


# Backward-compatible shims for pre-Phase-6 callers ------------------------


def _reserve_hunter_call() -> bool:
    """Deprecated alias — reserves a domain-search slot."""
    return reserve_domain_search()


def hunter_calls_this_month() -> int:
    """Return this month's domain-search count (legacy telemetry helper)."""
    with _HUNTER_USAGE_LOCK:
        return _read_usage().domain_searches


def hunter_circuit_open() -> bool:
    """Return True if the domain-search monthly cap has been reached."""
    if not _tracking_enabled():
        return False
    with _HUNTER_USAGE_LOCK:
        return _read_usage().domain_searches >= _domain_search_limit()


# ---------------------------------------------------------------------------
# Capability 1 — domain search.
# ---------------------------------------------------------------------------


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
    department: str | None = None
    linkedin: str | None = None
    sources: list[str] = field(default_factory=list)
    # Hunter's most-common email pattern for the domain (raw short form,
    # e.g. ``"first.last"``).  ``None`` when the API omitted it.
    pattern: str | None = None
    # ``pattern`` mapped to a full MailAccess template (with ``@{domain}``
    # suffix).  ``None`` when no mapping applies.
    pattern_template: str | None = field(default=None, repr=False)
    organization: str | None = None


async def search_domain(
    domain: str,
    api_key: str,
    limit: int = 100,
) -> list[HunterResult]:
    """Search Hunter.io for personal email addresses on *domain*.

    Returns an empty list on any error (401/403/429, network failure,
    timeout, capped quota) so callers never crash.  Requests only
    ``type=personal`` records, up to 100 per call.
    """
    if not api_key or not domain:
        return []
    if hunter_key_invalid():
        return []

    if not reserve_domain_search():
        return []

    params = {
        "domain": domain,
        "api_key": api_key,
        "limit": min(int(limit), 100),
        "type": "personal",
    }

    try:
        async with httpx.AsyncClient(timeout=_HUNTER_TIMEOUT) as client:
            response = await client.get(_DOMAIN_SEARCH_URL, params=params)

        if response.status_code in (401, 403):
            _mark_key_invalid()
            return []
        if response.status_code == 429:
            _LOG.warning("Hunter.io rate limited (HTTP 429); skipping.")
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

    body: dict[str, Any] = data.get("data") if isinstance(data.get("data"), dict) else {}
    emails_raw: list[dict[str, Any]] = body.get("emails") or []
    organization = str(body.get("organization") or "") or None

    # Hunter returns the same ``pattern`` for every email in the batch.
    raw_pattern = body.get("pattern")
    raw_pattern_str = str(raw_pattern).strip() if raw_pattern else ""
    if not raw_pattern_str or raw_pattern_str.lower() == "null":
        raw_pattern_str = ""
    mapped_template = map_hunter_pattern(raw_pattern_str) if raw_pattern_str else None

    results: list[HunterResult] = []
    for entry in emails_raw:
        if not isinstance(entry, dict):
            continue
        email = str(entry.get("value") or "").strip()
        if not email or "@" not in email:
            continue
        sources = [
            str(s.get("uri") or s.get("domain") or "").strip()
            for s in (entry.get("sources") or [])
            if isinstance(s, dict)
        ]
        sources = [s for s in sources if s]
        results.append(
            HunterResult(
                email=email,
                email_type=str(entry.get("type") or "generic"),
                confidence=int(entry.get("confidence") or 0),
                first_name=str(entry.get("first_name") or "") or None,
                last_name=str(entry.get("last_name") or "") or None,
                position=str(entry.get("position") or "") or None,
                department=str(entry.get("department") or "") or None,
                linkedin=str(entry.get("linkedin") or "") or None,
                source_count=len(sources),
                sources=sources,
                pattern=raw_pattern_str or None,
                pattern_template=mapped_template,
                organization=organization,
            )
        )

    return results


def hunter_confidence_score(hunter_confidence: int) -> float:
    """Map Hunter.io's 0-100 confidence to a MailAccess source weight."""
    if hunter_confidence >= 90:
        return 0.85  # hunter_verified
    if hunter_confidence >= 70:
        return 0.70  # hunter_high
    return 0.45  # hunter_low


def hunter_source_type(hunter_confidence: int) -> str:
    """Return the ``email_confidence.SOURCE_WEIGHTS`` key for a Hunter score."""
    if hunter_confidence >= 90:
        return "hunter_verified"
    if hunter_confidence >= 70:
        return "hunter_high"
    return "hunter_low"


# ---------------------------------------------------------------------------
# Capability 2 — email verification.
# ---------------------------------------------------------------------------


@dataclass
class HunterVerifyResult:
    """Structured result of a Hunter.io email-verifier lookup."""

    email: str
    result: str  # "deliverable" | "undeliverable" | "risky" | "unknown"
    score: int  # 0-100
    regexp: bool = False
    gibberish: bool = False
    disposable: bool = False
    webmail: bool = False
    mx_records: bool = False
    smtp_server: bool = False
    smtp_check: bool = False
    block: bool = False
    sources: list[str] = field(default_factory=list)

    # MailAccess mapping (populated by :meth:`to_mailaccess`).
    @property
    def mailaccess(self) -> tuple[float | None, str | None, str]:
        """Return ``(confidence, source_type, verification_status)``.

        ``verification_status`` is one of ``"verified"`` (a usable finding),
        ``"not_found"`` (undeliverable), or ``"inconclusive"`` (unknown).
        """
        state = (self.result or "").strip().lower()
        if state == "deliverable":
            if self.score >= 80:
                return 0.85, "hunter_verified", "verified"
            return 0.70, "hunter_high", "verified"
        if state == "risky":
            return 0.45, "hunter_low", "verified"
        if state == "undeliverable":
            return None, None, "not_found"
        return None, None, "inconclusive"


async def verify_email(email: str, api_key: str) -> HunterVerifyResult | None:
    """Verify *email* against Hunter.io's email-verifier endpoint.

    Returns a :class:`HunterVerifyResult` on success, or ``None`` on any
    error (missing key, latched-invalid key, 401/403/429, network failure,
    timeout, capped quota, unparseable body).  Never raises.
    """
    if not api_key or not email:
        return None
    if hunter_key_invalid():
        return None

    if not reserve_verification():
        return None

    params = {"email": email, "api_key": api_key}

    try:
        async with httpx.AsyncClient(timeout=_HUNTER_TIMEOUT) as client:
            response = await client.get(_EMAIL_VERIFIER_URL, params=params)

        if response.status_code in (401, 403):
            _mark_key_invalid()
            return None
        if response.status_code == 429:
            _LOG.warning("Hunter.io rate limited (HTTP 429); skipping.")
            return None
        if response.status_code != 200:
            _LOG.warning(
                "Hunter email-verifier returned HTTP %s for email=%r",
                response.status_code,
                email,
            )
            return None
    except httpx.TimeoutException:
        _LOG.warning("Hunter email-verifier timed out for email=%r", email)
        return None
    except Exception as exc:
        _LOG.warning("Hunter email-verifier network error for email=%r: %s", email, exc)
        return None

    try:
        data = response.json()
    except Exception as exc:
        _LOG.warning("Hunter email-verifier unparseable JSON for email=%r: %s", email, exc)
        return None

    body: dict[str, Any] = data.get("data") if isinstance(data.get("data"), dict) else {}
    if not body:
        return None

    def _as_bool(value: Any) -> bool:
        return bool(value) if not isinstance(value, str) else value.strip().lower() == "true"

    sources = [
        str(s.get("uri") or s.get("domain") or "").strip()
        for s in (body.get("sources") or [])
        if isinstance(s, dict)
    ]
    sources = [s for s in sources if s]

    try:
        score = max(0, min(100, int(body.get("score") or 0)))
    except (TypeError, ValueError):
        score = 0

    return HunterVerifyResult(
        email=str(body.get("email") or email),
        result=str(body.get("result") or "unknown").strip().lower(),
        score=score,
        regexp=_as_bool(body.get("regexp")),
        gibberish=_as_bool(body.get("gibberish")),
        disposable=_as_bool(body.get("disposable")),
        webmail=_as_bool(body.get("webmail")),
        mx_records=_as_bool(body.get("mx_records")),
        smtp_server=_as_bool(body.get("smtp_server")),
        smtp_check=_as_bool(body.get("smtp_check")),
        block=_as_bool(body.get("block")),
        sources=sources,
    )
