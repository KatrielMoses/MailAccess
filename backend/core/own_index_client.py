"""Client for the MailAccess Index: our own index of emails on the public web.

The index is a separate private service (built from Common Crawl and GH Archive).
It exists for the engine only when BOTH ``MAILACCESS_INDEX_URL`` and
``MAILACCESS_INDEX_KEY`` are set, the same rule as the other key-gated providers,
and a per-run ``--no-own-index`` turns it fully off (no calls, no events).

Every failure (bad key, rejected domain, bad input, timeout, unreachable service,
unexpected shape) is "no results": nothing here ever raises into a harvest. The
key travels only in the ``X-Index-Key`` header and is never logged.
"""

from __future__ import annotations

import logging
import re
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

from ..config import settings

_LOG = logging.getLogger(__name__)
_NO_OWN_INDEX: ContextVar[bool] = ContextVar("mailaccess_no_own_index", default=False)

TECHNIQUE_ID = "own_index"
# Catalogue lines end with a full stop (techniques.py convention).
TECHNIQUE_LINE = "Looking up our own index of the public web."
OLDER_SOURCE_LABEL = "older source"

_CRAWL_ID = re.compile(r"CC-MAIN-(\d{4})-(\d{2})", re.IGNORECASE)
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def set_no_own_index(value: bool):
    return _NO_OWN_INDEX.set(bool(value))


def own_index_configured(cfg: Any = None) -> bool:
    """Both the URL and the key are set (the module exists for this engine)."""
    cfg = cfg if cfg is not None else settings
    url = str(getattr(cfg, "mailaccess_index_url", "") or "").strip()
    key = str(getattr(cfg, "mailaccess_index_key", "") or "").strip()
    return bool(url and key)


def own_index_active(*, no_own_index: bool | None = None, cfg: Any = None) -> bool:
    """Configured, not persistently disabled, and not opted out for this run."""
    cfg = cfg if cfg is not None else settings
    off = _NO_OWN_INDEX.get() if no_own_index is None else bool(no_own_index)
    return own_index_configured(cfg) and not (getattr(cfg, "own_index_disabled", False) or off)


@dataclass
class IndexAnswer:
    """``status``: ok | empty | error | skipped. ``error`` is a short code only."""

    status: str
    emails: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0
    build_id: str | None = None
    pages: int = 0
    truncated: bool = False
    error: str | None = None
    http_status: int | None = None


_ERROR_CODES = {401: "bad_key", 422: "domain_rejected", 400: "invalid_input"}


class OwnIndexClient:
    """Thin async client. Methods return ``(status, data)`` and never raise."""

    def __init__(self, base_url: str | None = None, key: str | None = None) -> None:
        self.base_url = str(base_url or settings.mailaccess_index_url or "").strip().rstrip("/")
        self._key = str(key or settings.mailaccess_index_key or "").strip()
        self.calls = 0

    def _timeout(self, deadline: float | None) -> float | None:
        per_request = max(0.1, float(getattr(settings, "own_index_timeout_seconds", 10.0)))
        if deadline is None:
            return per_request
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        return min(per_request, left)

    async def _get(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        deadline: float | None = None,
    ) -> tuple[str, Any, int | None]:
        timeout = self._timeout(deadline)
        if timeout is None:
            return "skipped", None, None
        self.calls += 1
        try:
            response = await client.get(
                f"{self.base_url}{path}",
                params=params or None,
                headers={"X-Index-Key": self._key, "Accept": "application/json"},
                timeout=timeout,
            )
        except httpx.TimeoutException:
            return "timeout", None, None
        except Exception as exc:  # noqa: BLE001 - never raise; never log the key
            _LOG.info("MailAccess Index unreachable (%s)", type(exc).__name__)
            return "unreachable", None, None
        code = response.status_code
        if code != 200:
            return _ERROR_CODES.get(code, f"http_{code}"), None, code
        try:
            return "ok", response.json(), code
        except ValueError:
            return "bad_response", None, code

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(follow_redirects=False)

    async def domain_emails(
        self,
        domain: str,
        *,
        limit: int | None = None,
        max_emails: int | None = None,
        deadline: float | None = None,
    ) -> IndexAnswer:
        """All emails for ``domain``, following ``next_cursor`` up to ``max_emails``."""
        page_limit = int(limit or getattr(settings, "own_index_page_limit", 500) or 500)
        cap = int(max_emails or getattr(settings, "own_index_max_emails", 2000) or 2000)
        path = f"/v1/index/domain/{quote(domain.strip().lower(), safe='')}"
        out: list[dict[str, Any]] = []
        answer = IndexAnswer(status="empty")
        cursor: str | None = None
        try:
            async with self._client() as client:
                while True:
                    params: dict[str, Any] = {"limit": min(page_limit, max(1, cap - len(out)))}
                    if cursor:
                        params["cursor"] = cursor
                    status, data, code = await self._get(client, path, params, deadline=deadline)
                    if status != "ok" or not isinstance(data, dict):
                        if not out:
                            return IndexAnswer(
                                status="skipped" if status == "skipped" else "error",
                                error=status if status != "ok" else "bad_response",
                                http_status=code,
                            )
                        # Keep the pages already answered; note the cut.
                        answer.truncated = True
                        answer.error = status if status != "ok" else "bad_response"
                        break
                    answer.pages += 1
                    answer.build_id = str(data.get("build_id") or "") or answer.build_id
                    try:
                        answer.total = int(data.get("total") or 0)
                    except (TypeError, ValueError):
                        answer.total = 0
                    rows = data.get("emails")
                    for row in rows if isinstance(rows, list) else []:
                        if isinstance(row, dict) and isinstance(row.get("email"), str):
                            out.append(row)
                            if len(out) >= cap:
                                break
                    cursor = data.get("next_cursor") or None
                    if len(out) >= cap:
                        answer.truncated = bool(cursor) or answer.total > len(out)
                        break
                    if not cursor or not isinstance(cursor, str):
                        break
        except Exception as exc:  # noqa: BLE001
            _LOG.info("MailAccess Index lookup failed (%s)", type(exc).__name__)
            if not out:
                return IndexAnswer(status="error", error="client_error")
        answer.emails = out
        answer.status = "ok" if out else "empty"
        return answer

    async def email(self, email: str, *, deadline: float | None = None) -> tuple[str, Any]:
        """One email with ALL its sources (not used by the harvest module)."""
        async with self._client() as client:
            status, data, _ = await self._get(
                client, f"/v1/index/email/{quote(email.strip().lower(), safe='')}",
                deadline=deadline,
            )
        return status, data

    async def coverage(self, domain: str, *, deadline: float | None = None) -> tuple[str, Any]:
        async with self._client() as client:
            status, data, _ = await self._get(
                client, f"/v1/index/coverage/{quote(domain.strip().lower(), safe='')}",
                deadline=deadline,
            )
        return status, data

    async def health(self, *, deadline: float | None = None) -> tuple[str, Any]:
        async with self._client() as client:
            status, data, _ = await self._get(client, "/health", deadline=deadline)
        return status, data


# --------------------------------------------------------------------- findings
def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text[:10])
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def crawl_label(crawl: Any, fetch_time: Any = None) -> str:
    """``CC-MAIN-2026-39`` -> ``Sep 2026`` (the month of that crawl week).

    Falls back to the source's fetch month, then to the raw crawl name.
    """
    match = _CRAWL_ID.search(str(crawl or ""))
    if match:
        year, week = int(match.group(1)), int(match.group(2))
        try:
            monday = date.fromisocalendar(year, max(1, min(week, 53)), 1)
            return f"{_MONTHS[monday.month - 1]} {monday.year}"
        except ValueError:
            pass
    fetched = _parse_time(fetch_time)
    if fetched is not None:
        return f"{_MONTHS[fetched.month - 1]} {fetched.year}"
    return str(crawl or "").strip() or "unknown"


def is_older_source(
    last_seen: Any, *, now: datetime | None = None, months: int | None = None
) -> bool:
    seen = _parse_time(last_seen)
    if seen is None:
        return False
    now = now or datetime.now(timezone.utc)
    if months is None:
        months = int(getattr(settings, "own_index_older_source_months", 24))
    return seen < now - timedelta(days=round(months * 30.4375))


def _on_domain(email: str, domain: str) -> bool:
    host = email.rsplit("@", 1)[-1].strip().lower()
    target = domain.strip().lower()
    return host == target or host.endswith("." + target)


def build_finding(
    row: dict[str, Any], domain: str, *, now: datetime | None = None
) -> dict[str, Any] | None:
    """One index row -> one harvest finding (same shape the other sources return)."""
    from .email_confidence import compute_confidence_breakdown, label_for_score

    email = str(row.get("email") or "").strip().lower()
    if "@" not in email:
        return None
    sources = [s for s in (row.get("sources") or []) if isinstance(s, dict)]
    top = sources[0] if sources else {}
    url = str(top.get("url") or "")
    crawls = [str(c) for c in (row.get("crawls") or []) if c]
    label = crawl_label(top.get("crawl") or (crawls[-1] if crawls else None), top.get("fetch_time"))
    try:
        source_count = int(row.get("source_count") or len(sources) or 0)
    except (TypeError, ValueError):
        source_count = len(sources)
    first_seen = row.get("first_seen")
    last_seen = row.get("last_seen")
    kind = str(row.get("kind") or "").lower() or None
    automated = kind == "automated"
    older = is_older_source(last_seen, now=now)
    # Score with the existing tiers, no new weights: a web page from the crawl
    # scores like Common Crawl (high density at 3+ pages), a GH Archive commit
    # like a public commit author.
    from_commits = str(top.get("source") or "").lower() == "gha"
    if from_commits:
        source_type = "github_commit_author"
    elif source_count >= 3:
        source_type = "common_crawl_high_density"
    else:
        source_type = "common_crawl_single"
    ci = compute_confidence_breakdown(
        source_types=[source_type],
        is_smtp_verified=False,
        is_ca_attested=False,
        oldest_timestamp=first_seen if isinstance(first_seen, str) else None,
        last_seen_timestamp=last_seen if isinstance(last_seen, str) else None,
    )
    signal = f"Found on {url} in the {label} crawl" if url else f"Found in the {label} crawl"
    trace: dict[str, Any] = {
        "technique_id": TECHNIQUE_ID,
        "technique": TECHNIQUE_LINE,
        "signal": signal,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "source_count": source_count,
        "label": OLDER_SOURCE_LABEL if older else None,
        "kind": kind,
        "automated": automated,
    }
    local = email.rsplit("@", 1)[0]
    return {
        "platform": "own_index",
        "profile_url": url,
        "username": local,
        "confidence": label_for_score(ci.score).lower(),
        "signal_source": "own_index",
        "trace": trace,
        "metadata": {
            "email": email,
            "on_domain": _on_domain(email, domain),
            "source_type": source_type,
            "provenance": "public_source",
            "own_index": True,
            "index_kind": kind,
            "automated": automated,
            "is_automated": automated,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "first_seen_timestamp": first_seen,
            "last_seen_timestamp": last_seen,
            "source_count": source_count,
            "crawls": crawls,
            "index_sources": sources[:3],
            "source_url": url or None,
            "source_urls": [str(s.get("url")) for s in sources[:3] if s.get("url")],
            "source_text_snippet": str(top.get("snippet") or "")[:200] or None,
            "older_source": older,
            "age_label": OLDER_SOURCE_LABEL if older else None,
            "trace": trace,
            "confidence_score": round(ci.score, 4),
            "confidence_breakdown": ci.breakdown,
        },
    }


# ------------------------------------------------------------ off for this run
def holds_own_index_data(result: Any) -> bool:
    """True when a stored harvest carries rows from the MailAccess Index."""
    modules = getattr(result, "module_results", None) or {}
    if TECHNIQUE_ID in modules:
        return True
    for lead in getattr(result, "unique_emails", None) or []:
        if TECHNIQUE_ID in (getattr(lead, "found_by_modules", None) or []):
            return True
    return False


def strip_own_index_leads(leads: list[Any]) -> list[Any]:
    """Leads without any MailAccess Index evidence (for a run where it is off).

    A lead found only by the index is dropped; a lead also found by another
    source keeps that source and loses the index evidence.
    """
    from dataclasses import replace

    out: list[Any] = []
    for lead in leads or []:
        modules = list(getattr(lead, "found_by_modules", None) or [])
        if TECHNIQUE_ID not in modules:
            out.append(lead)
            continue
        kept_modules = [m for m in modules if m != TECHNIQUE_ID]
        evidence = [
            ev for ev in (getattr(lead, "evidence", None) or [])
            if not (isinstance(ev, dict) and ev.get("module") == TECHNIQUE_ID)
        ]
        if not kept_modules or not evidence:
            continue
        try:
            out.append(replace(lead, found_by_modules=kept_modules, evidence=evidence))
        except Exception:  # noqa: BLE001 - never serve an unfiltered lead
            continue
    return out


def strip_own_index_blobs(blobs: list[tuple[Any, Any]]) -> list[tuple[Any, Any]]:
    """Historical store blobs with the MailAccess Index rows removed."""
    from types import SimpleNamespace

    return [
        (stamp, SimpleNamespace(unique_emails=strip_own_index_leads(
            getattr(blob, "unique_emails", None) or []
        )))
        for stamp, blob in blobs or []
    ]
