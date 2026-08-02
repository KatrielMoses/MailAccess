"""Phase 5 — breach aggregation across four sources.

Four independent breach sources, each an ``async`` function that never
raises and always returns a (possibly empty) list of :class:`BreachFinding`:

* **Scylla.so**   — free, no key (``scylla_breach``).
* **HIBP Pastes** — requires ``HIBP_API_KEY`` (``hibp_paste``).
* **Dehashed**    — paid, requires ``DEHASHED_API_KEY`` (``dehashed_breach``).
* **Snusbase**    — paid, requires ``SNUSBASE_API_KEY`` (``snusbase_breach``).

:func:`run_breach_aggregator` fans the configured sources out concurrently
and folds their partial results together — a single failing source never
stops the others.

Privacy contract
----------------

Plaintext passwords, hashes and salts are **never** surfaced anywhere.
Every source only records *boolean existence flags*
(``has_plaintext_password`` / ``has_hash``) plus non-secret corroborating
fields (breach source name, username, IP).  The CLI helper
(:meth:`BreachFinding.cli_summary`) narrows that further to breach source
name, date and a ``has_password_data`` boolean.  JSON export
(:meth:`BreachFinding.to_finding`) stores the full record under
``metadata.breach_data`` — again, only flags, never the secret value.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..config import APP_VERSION
from ..config import settings as _global_settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

if TYPE_CHECKING:
    from ..config import Settings

logger = logging.getLogger(__name__)

_STANDARD_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# One-shot "key absent" log guards so a disabled source logs exactly once.
_HIBP_PASTE_WARNED = False


def _set_source_telemetry(
    telemetry: dict[str, Any] | None,
    status: str,
    *,
    http_status: int | None = None,
    error: str | None = None,
) -> None:
    """Update an optional per-source telemetry record without affecting APIs."""
    if telemetry is None:
        return
    telemetry["status"] = status
    if http_status is not None:
        telemetry["http_status"] = http_status
    if error is not None:
        telemetry["error"] = error


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


@dataclass
class BreachFinding:
    """One breach record from one source.

    Only privacy-safe fields are retained.  ``has_plaintext_password`` and
    ``has_hash`` are booleans derived from the raw record; the raw secret
    values are deliberately discarded at parse time and never stored.
    """

    platform: str
    source_type: str
    confidence: float
    breach_source: str | None = None
    has_plaintext_password: bool = False
    has_hash: bool = False
    has_name: bool = False
    has_address: bool = False
    has_phone: bool = False
    username: str | None = None
    ip_address: str | None = None
    # HIBP paste-specific fields.
    paste_source: str | None = None
    paste_id: str | None = None
    paste_date: str | None = None
    email_count_in_paste: int | None = None
    breach_date: str | None = None

    def _breach_data(self) -> dict[str, Any]:
        """Privacy-safe record stored under ``metadata.breach_data``."""
        record: dict[str, Any] = {
            "breach_source": self.breach_source,
            "has_plaintext_password": self.has_plaintext_password,
            "has_hash": self.has_hash,
        }
        if self.has_name:
            record["has_name"] = True
        if self.has_address:
            record["has_address"] = True
        if self.has_phone:
            record["has_phone"] = True
        if self.username is not None:
            record["username"] = self.username
        if self.ip_address is not None:
            record["ip_address"] = self.ip_address
        if self.paste_source is not None:
            record["paste_source"] = self.paste_source
        if self.paste_id is not None:
            record["paste_id"] = self.paste_id
        if self.paste_date is not None:
            record["paste_date"] = self.paste_date
        if self.email_count_in_paste is not None:
            record["email_count_in_paste"] = self.email_count_in_paste
        return record

    def to_finding(self) -> dict[str, Any]:
        """Render the pipeline / JSON-export finding dict.

        The ``metadata.breach_source`` key ensures the Defender's Brief
        breach-normaliser recognises this as a breach finding.  The full
        (password-free) record lives under ``metadata.breach_data``.
        """
        metadata: dict[str, Any] = {
            "source": self.source_type,
            "source_type": self.source_type,
            "breach_source": self.breach_source,
            "has_plaintext_password": self.has_plaintext_password,
            "has_hash": self.has_hash,
            "breach_data": [self._breach_data()],
        }
        if self.breach_date is not None:
            metadata["breach_date"] = self.breach_date
        if self.paste_date is not None:
            metadata["paste_date"] = self.paste_date
            metadata.setdefault("breach_date", self.paste_date)
        if self.paste_source is not None:
            metadata["paste_source"] = self.paste_source
        if self.paste_id is not None:
            metadata["paste_id"] = self.paste_id
        if self.email_count_in_paste is not None:
            metadata["email_count_in_paste"] = self.email_count_in_paste
        return {
            "platform": self.platform,
            "source_type": self.source_type,
            "confidence": self.confidence,
            "metadata": metadata,
        }

    def cli_summary(self) -> dict[str, Any]:
        """Privacy-narrowed summary for CLI output.

        Shows only breach source name, date, and whether password data was
        present.  Never exposes passwords, hashes, salts, usernames or IPs.
        """
        return {
            "breach_source": self.breach_source or self.paste_source,
            "date": self.breach_date or self.paste_date,
            "has_password_data": bool(self.has_plaintext_password or self.has_hash),
        }


# ---------------------------------------------------------------------------
# Small parse helpers
# ---------------------------------------------------------------------------


def _truthy_str(value: Any) -> str | None:
    """Return a non-empty stripped string or ``None``."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _has_value(item: dict[str, Any], *keys: str) -> bool:
    """True if any of *keys* is present and non-empty in *item*."""
    return any(_truthy_str(item.get(key)) for key in keys)


# ---------------------------------------------------------------------------
# SOURCE 1 — Scylla.so (free, no key)
# ---------------------------------------------------------------------------


async def search_scylla(
    email: str,
    *,
    timeout: float = 10.0,
    telemetry: dict[str, Any] | None = None,
) -> list[BreachFinding]:
    """Query Scylla.so for breach records mentioning *email*.

    Never raises.  Returns ``[]`` on 429, network error, or malformed data.
    """
    url = "https://scylla.so/search"
    params = {"q": f'email:"{email}"'}
    headers = {"User-Agent": _STANDARD_UA, "Accept": "application/json"}
    try:
        async with build_client(timeout=timeout) as client:
            res = await client.get(url, params=params, headers=headers)
        if res.status_code == 429:
            _set_source_telemetry(telemetry, "rate_limited", http_status=429)
            logger.warning("scylla_breach: rate limited (429); returning empty")
            return []
        if res.status_code != 200:
            _set_source_telemetry(telemetry, "error", http_status=res.status_code)
            logger.debug("scylla_breach: unexpected status %s", res.status_code)
            return []
        data = res.json()
    except Exception as exc:  # noqa: BLE001 — sources must never raise
        _set_source_telemetry(telemetry, "error", error=str(exc))
        logger.debug("scylla_breach: error, returning empty (%s)", exc)
        return []

    if not isinstance(data, list):
        _set_source_telemetry(telemetry, "error", error="malformed_response")
        return []

    findings: list[BreachFinding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        # Scylla nests the interesting bits under "fields" on some
        # deployments and flattens them on others — read both.
        fields = item.get("fields") if isinstance(item.get("fields"), dict) else {}
        merged: dict[str, Any] = {**fields, **item}
        findings.append(
            BreachFinding(
                platform="scylla.so",
                source_type="scylla_breach",
                confidence=0.55,
                breach_source=(
                    _truthy_str(merged.get("breach_source"))
                    or _truthy_str(merged.get("source"))
                    or _truthy_str(merged.get("database_name"))
                ),
                has_plaintext_password=_has_value(merged, "password"),
                has_hash=_has_value(merged, "hash", "hashed_password"),
                has_name=_has_value(merged, "name"),
                username=_truthy_str(merged.get("username")),
                ip_address=_truthy_str(merged.get("ip_address") or merged.get("ip")),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# SOURCE 2 — HIBP Pastes (HIBP key required)
# ---------------------------------------------------------------------------


async def search_hibp_pastes(
    email: str,
    api_key: str | None,
    *,
    timeout: float = 10.0,
    telemetry: dict[str, Any] | None = None,
) -> list[BreachFinding]:
    """Query the HIBP paste-account endpoint for *email*.

    Requires an HIBP key.  Returns ``[]`` when the key is absent (logged
    once), on 404 (no pastes), on 401 (invalid key, logged), and on any
    error.
    """
    global _HIBP_PASTE_WARNED
    if not api_key:
        _set_source_telemetry(telemetry, "skipped", error="missing_api_key")
        if not _HIBP_PASTE_WARNED:
            logger.info("HIBP_API_KEY not set — paste lookup disabled.")
            _HIBP_PASTE_WARNED = True
        return []

    url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "User-Agent": f"MailAccess-{APP_VERSION}",
    }
    try:
        async with build_client(timeout=timeout, follow_redirects=True) as client:
            res = await client.get(url, headers=headers)
        if res.status_code == 404:
            return []
        if res.status_code == 401:
            _set_source_telemetry(telemetry, "error", http_status=401)
            logger.warning("hibp_paste: HIBP API key invalid (401).")
            return []
        if res.status_code == 429:
            _set_source_telemetry(telemetry, "rate_limited", http_status=429)
            logger.warning("hibp_paste: rate limited (429); returning empty")
            return []
        if res.status_code != 200:
            _set_source_telemetry(telemetry, "error", http_status=res.status_code)
            logger.debug("hibp_paste: unexpected status %s", res.status_code)
            return []
        data = res.json()
    except Exception as exc:  # noqa: BLE001
        _set_source_telemetry(telemetry, "error", error=str(exc))
        logger.debug("hibp_paste: error, returning empty (%s)", exc)
        return []

    if not isinstance(data, list):
        _set_source_telemetry(telemetry, "error", error="malformed_response")
        return []

    findings: list[BreachFinding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        paste_source = _truthy_str(item.get("Source"))
        email_count = item.get("EmailCount")
        try:
            email_count_int = int(email_count) if email_count is not None else None
        except (TypeError, ValueError):
            email_count_int = None
        findings.append(
            BreachFinding(
                platform="haveibeenpwned.com",
                source_type="hibp_paste",
                confidence=0.50,
                paste_source=paste_source,
                breach_source=_truthy_str(item.get("Title")) or paste_source,
                paste_id=_truthy_str(item.get("Id")),
                paste_date=_truthy_str(item.get("Date")),
                email_count_in_paste=email_count_int,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# SOURCE 3 — Dehashed (paid key required)
# ---------------------------------------------------------------------------


async def search_dehashed(
    email: str,
    api_key: str | None,
    *,
    timeout: float = 15.0,
    telemetry: dict[str, Any] | None = None,
) -> list[BreachFinding]:
    """Query Dehashed for breach entries mentioning *email*.

    Requires a paid key.  Returns ``[]`` when the key is absent, on 401
    (invalid key, logged), on 429 (rate limited, logged), and on error.
    """
    if not api_key:
        _set_source_telemetry(telemetry, "skipped", error="missing_api_key")
        return []

    url = "https://api.dehashed.com/search"
    params = {"query": f'email:"{email}"'}
    # NOTE: Dehashed Basic auth is base64(account_email:api_key), where the
    # account login email is the account holder's — NOT the target being
    # searched. Fall back to key-only auth when no account email is set.
    account_email = _global_settings.dehashed_account_email or api_key
    token = base64.b64encode(f"{account_email}:{api_key}".encode()).decode()
    headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
    try:
        async with build_client(timeout=timeout) as client:
            res = await client.get(url, params=params, headers=headers)
        if res.status_code == 401:
            _set_source_telemetry(telemetry, "error", http_status=401)
            logger.warning("dehashed_breach: Dehashed API key invalid.")
            return []
        if res.status_code == 429:
            _set_source_telemetry(telemetry, "rate_limited", http_status=429)
            logger.warning("dehashed_breach: rate limited (429); returning empty")
            return []
        if res.status_code != 200:
            _set_source_telemetry(telemetry, "error", http_status=res.status_code)
            logger.debug("dehashed_breach: unexpected status %s", res.status_code)
            return []
        data = res.json()
    except Exception as exc:  # noqa: BLE001
        _set_source_telemetry(telemetry, "error", error=str(exc))
        logger.debug("dehashed_breach: error, returning empty (%s)", exc)
        return []

    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        _set_source_telemetry(telemetry, "error", error="malformed_response")
        return []

    findings: list[BreachFinding] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        findings.append(
            BreachFinding(
                platform="dehashed.com",
                source_type="dehashed_breach",
                confidence=0.70,
                breach_source=_truthy_str(entry.get("database_name")),
                has_plaintext_password=_has_value(entry, "password"),
                has_hash=_has_value(entry, "hashed_password", "hash"),
                has_name=_has_value(entry, "name"),
                has_address=_has_value(entry, "address"),
                has_phone=_has_value(entry, "phone"),
                username=_truthy_str(entry.get("username")),
                ip_address=_truthy_str(entry.get("ip_address")),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# SOURCE 4 — Snusbase (paid key required)
# ---------------------------------------------------------------------------


async def search_snusbase(
    email: str,
    api_key: str | None,
    *,
    timeout: float = 15.0,
    telemetry: dict[str, Any] | None = None,
) -> list[BreachFinding]:
    """Query Snusbase for breach entries mentioning *email*.

    Requires a paid key.  Returns ``[]`` when the key is absent, on 401
    (invalid key, logged), and on error.
    """
    if not api_key:
        _set_source_telemetry(telemetry, "skipped", error="missing_api_key")
        return []

    url = "https://api.snusbase.com/data/search"
    headers = {"Auth": api_key, "Content-Type": "application/json"}
    body = {"terms": [email], "types": ["email"], "wildcard": False}
    try:
        async with build_client(timeout=timeout) as client:
            res = await client.post(url, headers=headers, json=body)
        if res.status_code == 401:
            _set_source_telemetry(telemetry, "error", http_status=401)
            logger.warning("snusbase_breach: Snusbase API key invalid.")
            return []
        if res.status_code == 429:
            _set_source_telemetry(telemetry, "rate_limited", http_status=429)
            logger.warning("snusbase_breach: rate limited (429); returning empty")
            return []
        if res.status_code != 200:
            _set_source_telemetry(telemetry, "error", http_status=res.status_code)
            logger.debug("snusbase_breach: unexpected status %s", res.status_code)
            return []
        data = res.json()
    except Exception as exc:  # noqa: BLE001
        _set_source_telemetry(telemetry, "error", error=str(exc))
        logger.debug("snusbase_breach: error, returning empty (%s)", exc)
        return []

    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(data, dict) or not isinstance(results, list | dict):
        _set_source_telemetry(telemetry, "error", error="malformed_response")
        return []
    # Snusbase returns results either as a flat list or as a mapping of
    # database-name -> [entries]; normalise both into a flat entry list.
    entries: list[dict[str, Any]] = []
    if isinstance(results, list):
        entries = [e for e in results if isinstance(e, dict)]
    elif isinstance(results, dict):
        for db_name, rows in results.items():
            if not isinstance(rows, list):
                continue
            for row in rows:
                if isinstance(row, dict):
                    row.setdefault("_db", db_name)
                    entries.append(row)

    findings: list[BreachFinding] = []
    for entry in entries:
        findings.append(
            BreachFinding(
                platform="snusbase.com",
                source_type="snusbase_breach",
                confidence=0.68,
                breach_source=_truthy_str(entry.get("_db")),
                has_plaintext_password=_has_value(entry, "password"),
                has_hash=_has_value(entry, "hash"),
                has_name=_has_value(entry, "name"),
                username=_truthy_str(entry.get("username")),
                ip_address=_truthy_str(entry.get("lastip")),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def _run_breach_source(
    source: str,
    func: Any,
    args: tuple[Any, ...],
    *,
    timeout: float,
    telemetry: dict[str, Any],
) -> list[BreachFinding]:
    started = time.perf_counter()
    try:
        kwargs: dict[str, Any] = {"timeout": timeout}
        try:
            accepted = inspect.signature(func).parameters
            accepts_telemetry = "telemetry" in accepted or any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in accepted.values()
            )
        except (TypeError, ValueError):
            accepts_telemetry = True
        if accepts_telemetry:
            kwargs["telemetry"] = telemetry
        result = await func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - one source cannot stop others
        _set_source_telemetry(telemetry, "error", error=str(exc))
        logger.debug("breach source %s raised: %s", source, exc)
        result = []

    if not isinstance(result, list):
        _set_source_telemetry(telemetry, "error", error="invalid_result")
        result = []
    if telemetry.get("status") == "not_run":
        telemetry["status"] = "success"
    telemetry["checked"] = 1
    telemetry["hits"] = len(result)
    telemetry["duration_seconds"] = round(time.perf_counter() - started, 3)
    telemetry.setdefault("http_status", None)
    telemetry.setdefault("error", None)
    return result


async def run_breach_aggregator(
    email: str,
    settings: Settings | None = None,
    *,
    telemetry: dict[str, dict[str, Any]] | None = None,
) -> list[BreachFinding]:
    """Run every configured breach source concurrently for *email*.

    A source is included only when its enabling condition holds:

    * Scylla    — ``settings.enable_scylla``
    * HIBP paste — ``settings.hibp_api_key and settings.enable_hibp_pastes``
    * Dehashed  — ``settings.dehashed_api_key``
    * Snusbase  — ``settings.snusbase_api_key``

    Sources never raise; any that do are dropped and the remaining
    partial results are still returned.
    """
    settings = settings or _global_settings
    cleaned = (email or "").strip().lower()
    if not cleaned or "@" not in cleaned:
        return []

    timeout = float(getattr(settings, "breach_aggregator_timeout", 15.0))
    source_telemetry = telemetry if telemetry is not None else {}
    for source in ("scylla", "hibp_paste", "dehashed", "snusbase"):
        source_telemetry.setdefault(
            source,
            {
                "status": "not_run",
                "checked": 0,
                "hits": 0,
                "http_status": None,
                "duration_seconds": 0.0,
                "error": None,
            },
        )

    tasks: list[Any] = []
    if getattr(settings, "enable_scylla", False):
        tasks.append(
            _run_breach_source(
                "scylla",
                search_scylla,
                (cleaned,),
                timeout=min(timeout, 10.0),
                telemetry=source_telemetry["scylla"],
            )
        )
    else:
        source_telemetry["scylla"]["status"] = "skipped"
    if getattr(settings, "hibp_api_key", None) and getattr(
        settings, "enable_hibp_pastes", False
    ):
        tasks.append(
            _run_breach_source(
                "hibp_paste",
                search_hibp_pastes,
                (cleaned, settings.hibp_api_key),
                timeout=min(timeout, 10.0),
                telemetry=source_telemetry["hibp_paste"],
            )
        )
    else:
        source_telemetry["hibp_paste"]["status"] = "skipped"
    if getattr(settings, "dehashed_api_key", None):
        tasks.append(
            _run_breach_source(
                "dehashed",
                search_dehashed,
                (cleaned, settings.dehashed_api_key),
                timeout=timeout,
                telemetry=source_telemetry["dehashed"],
            )
        )
    else:
        source_telemetry["dehashed"]["status"] = "skipped"
    if getattr(settings, "snusbase_api_key", None):
        tasks.append(
            _run_breach_source(
                "snusbase",
                search_snusbase,
                (cleaned, settings.snusbase_api_key),
                timeout=timeout,
                telemetry=source_telemetry["snusbase"],
            )
        )
    else:
        source_telemetry["snusbase"]["status"] = "skipped"

    if not tasks:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[BreachFinding] = []
    for result in results:
        if isinstance(result, BaseException):
            logger.debug("breach source raised, skipping: %s", result)
            continue
        findings.extend(result)
    return findings


def select_confirmed_emails(emails: Any) -> list[Any]:
    """Return only SMTP- or provider-verified emails from *emails*.

    Used by the harvest path so breach aggregation runs exclusively on
    confirmed mailboxes, never on unverified pattern candidates.  Accepts
    :class:`~backend.core.domain_harvest_orchestrator.HarvestedEmail`
    records or any object exposing ``is_smtp_verified`` /
    ``is_provider_verified``.
    """
    confirmed = []
    for entry in emails or []:
        if getattr(entry, "is_smtp_verified", False) or getattr(
            entry, "is_provider_verified", False
        ):
            confirmed.append(entry)
    return confirmed


async def enrich_confirmed_emails(
    emails: Any,
    settings: Settings | None = None,
    *,
    max_emails: int = 25,
    telemetry_by_email: dict[str, dict[str, dict[str, Any]]] | None = None,
) -> dict[str, list[BreachFinding]]:
    """Run breach aggregation for every confirmed email in *emails*.

    Returns a mapping of ``email -> [BreachFinding]``.  Only confirmed
    mailboxes are probed; the number probed is capped by *max_emails*.
    """
    settings = settings or _global_settings
    confirmed = select_confirmed_emails(emails)[: max(0, max_emails)]
    if not confirmed:
        return {}

    addresses = [getattr(e, "email", str(e)) for e in confirmed]
    async def _run_address(address: str) -> list[BreachFinding]:
        telemetry: dict[str, dict[str, Any]] = {}
        if telemetry_by_email is not None:
            telemetry_by_email[address] = telemetry
        try:
            accepted = inspect.signature(run_breach_aggregator).parameters
        except (TypeError, ValueError):
            accepted = {}
        if "telemetry" in accepted:
            return await run_breach_aggregator(
                address,
                settings,
                telemetry=telemetry,
            )
        return await run_breach_aggregator(address, settings)

    results = await asyncio.gather(
        *(_run_address(addr) for addr in addresses),
        return_exceptions=True,
    )
    enrichment: dict[str, list[BreachFinding]] = {}
    for addr, result in zip(addresses, results):
        if isinstance(result, BaseException):
            logger.debug("breach enrichment failed for %s: %s", addr, result)
            continue
        if result:
            enrichment[addr] = result
    return enrichment


# ---------------------------------------------------------------------------
# Pipeline module wrapper (investigate path)
# ---------------------------------------------------------------------------


class BreachAggregatorModule(BaseModule):
    """Post-primary breach aggregation module for the investigate pipeline."""

    name = "breach_aggregator"
    description = (
        "Aggregates breach records for an email across Scylla.so, HIBP pastes, "
        "Dehashed and Snusbase. Password/hash existence is recorded as boolean "
        "flags only — plaintext secrets are never stored or displayed."
    )
    requires_key = False
    priority = 60

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        del force
        telemetry: dict[str, dict[str, Any]] = {}
        try:
            try:
                accepted = inspect.signature(run_breach_aggregator).parameters
            except (TypeError, ValueError):
                accepted = {}
            if "telemetry" in accepted:
                breach_findings = await run_breach_aggregator(
                    email,
                    _global_settings,
                    telemetry=telemetry,
                )
            else:
                breach_findings = await run_breach_aggregator(email, _global_settings)
        except Exception as exc:  # noqa: BLE001 — module must never crash the phase
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"breach_aggregator: {exc}"],
                metadata={"sources": telemetry},
            )

        findings = [bf.to_finding() for bf in breach_findings]
        sources_with_password = sum(
            1 for bf in breach_findings if bf.has_plaintext_password or bf.has_hash
        )
        metadata: dict[str, Any] = {
            "total_breach_records": len(breach_findings),
            "sources_with_password_data": sources_with_password,
            "source_types": sorted({bf.source_type for bf in breach_findings}),
            "sources": telemetry,
        }
        attempted = [
            source
            for source in telemetry.values()
            if source.get("status") not in {"skipped", "not_run"}
        ]
        rate_limited = any(
            source.get("status") == "rate_limited" for source in attempted
        )
        failed = any(source.get("status") == "error" for source in attempted)
        if not telemetry:
            # Compatibility path for legacy test doubles/integrations that
            # still provide only the original list-returning API.
            status = ModuleStatus.SUCCESS if breach_findings else ModuleStatus.SKIPPED
        elif not attempted:
            status = ModuleStatus.SKIPPED
        elif rate_limited:
            status = ModuleStatus.PARTIAL
        elif breach_findings:
            status = ModuleStatus.SUCCESS
        elif all(source.get("status") == "success" for source in attempted):
            status = ModuleStatus.SUCCESS_EMPTY
        elif failed and all(source.get("status") == "error" for source in attempted):
            status = ModuleStatus.FAILED
        else:
            status = ModuleStatus.PARTIAL
        return ModuleResult(
            status=status,
            findings=findings,
            metadata=metadata,
        )
