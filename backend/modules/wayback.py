"""Wayback Machine module — single-email investigation + domain-mode harvest.

This module carries TWO public surfaces:

* :class:`WaybackModule` — the 0.10.0 single-email investigation mode
  ("given an email, find every public Wayback snapshot that mentions
  it").  Unchanged in Phase 3.

* :class:`WaybackDomainHarvestModule` and :func:`harvest_domain_emails`
  — added in 0.11.1 Phase 3 for *domain* harvesting.  Given a corporate
  domain, walk the Wayback CDX index for high-signal URLs (about /
  team / leadership / press / news / *.pdf), fetch the snapshots via
  :class:`backend.core.stealth_client.StealthSession`, decode
  Cloudflare-obfuscation, extract emails + structured-person records,
  and return deduped findings.
"""

from __future__ import annotations

import asyncio
import html
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import settings
from ..core.cf_decode import cf_decode
from ..core.concurrent_fetch_cache import CachedFetch
from ..core.email_extraction import extract_emails
from ..core.http_client import build_client
from ..core.stealth_client import (
    StealthSession,
    resolve_timing_profile,
)
from ..core.structured_data_extractor import extract_people
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_CDX_URL = "https://web.archive.org/cdx/search/cdx"
_CDX_LIMIT = 20
_PAGE_FETCH_LIMIT = 5

# Per-fetch ceiling for Wayback domain harvest — bound to keep one
# corporate harvest from spending an entire operator budget on a
# single domain.  Configurable via ``settings.wayback_max_urls``.
_DEFAULT_DOMAIN_URL_CAP = 100
_DOMAIN_TARGETED_LIMIT = 200
_DOMAIN_BROAD_LIMIT = 500
_DOMAIN_FETCH_CONCURRENCY = 4
_DOMAIN_FETCH_TIMEOUT = 12.0

# High-signal URL paths the CDX query targets.  Same shape as
# :data:`backend.core.cc_index_client._HIGH_SIGNAL_PATH_REGEX` so
# both archive sources stay aligned on the same priority taxonomy.
_DOMAIN_HIGH_SIGNAL_REGEX = (
    "(team|about|contact|leadership|people|staff|board|press|news|pdf)"
)


# ----------------------------------------------------------------------
# Shared CDX helpers
# ----------------------------------------------------------------------
def _parse_cdx_rows(data: object) -> list[dict[str, str]]:
    if not isinstance(data, list) or not data:
        return []
    headers = data[0]
    if not isinstance(headers, list):
        return []

    rows: list[dict[str, str]] = []
    for raw_row in data[1:]:
        if not isinstance(raw_row, list):
            continue
        row = {
            str(key): str(value)
            for key, value in zip(headers, raw_row, strict=False)
            if value is not None
        }
        if row.get("original") and row.get("timestamp"):
            rows.append(row)
    return rows


def _archive_date(timestamp: str) -> str:
    try:
        parsed = datetime.strptime(timestamp[:14], "%Y%m%d%H%M%S")
        return parsed.replace(tzinfo=timezone.utc).date().isoformat()
    except ValueError:
        return timestamp


def _years_ago(archive_date: str) -> int:
    try:
        year = datetime.fromisoformat(archive_date).year
    except ValueError:
        return 0
    return max(datetime.now(timezone.utc).year - year, 0)


def _page_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return html.unescape(title)


def _snippet(text: str, email: str, radius: int = 100) -> str:
    plain = re.sub(r"<script\b[^>]*>.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    plain = re.sub(r"<[^>]+>", " ", plain)
    plain = html.unescape(re.sub(r"\s+", " ", plain)).strip()
    index = plain.lower().find(email.lower())
    if index < 0:
        return ""
    start = max(index - radius, 0)
    end = min(index + len(email) + radius, len(plain))
    prefix = "..." if start else ""
    suffix = "..." if end < len(plain) else ""
    return f"{prefix}{plain[start:end].strip()}{suffix}"


async def _run_cdx_query(
    client: httpx.AsyncClient,
    params: dict[str, Any],
    *,
    timeout: float = 10.0,
) -> tuple[list[dict[str, str]], str | None, bool, bool]:
    """Run one CDX query; return ``(rows, error, partial, rate_limited)``."""
    try:
        response = await client.get(_CDX_URL, params=params, timeout=timeout)
    except httpx.TimeoutException:
        return [], "Wayback CDX query timed out", True, False
    except Exception as exc:
        return [], f"Wayback CDX query failed: {exc}", True, False
    if response.status_code == 429:
        return [], "Wayback Machine rate-limited CDX search", True, True
    if response.status_code != 200:
        return [], f"Wayback CDX returned {response.status_code}", True, False
    try:
        rows = _parse_cdx_rows(response.json())
    except Exception:
        return [], "Wayback CDX returned unparseable JSON", True, False
    return rows, None, False, False


# ----------------------------------------------------------------------
# WaybackEmailResult — domain-mode return type
# ----------------------------------------------------------------------
@dataclass
class WaybackEmailResult:
    """One email discovered through a Wayback snapshot.

    Fields mirror the legacy single-email discovery shape so the
    domain-mode module can reuse the same downstream finding renderer.
    """

    email: str
    archived_url: str
    snapshot_timestamp: str
    confidence: float = 0.40
    is_historical: bool = True
    person_name: str | None = None
    person_title: str | None = None
    source: str = "wayback_archive"


# ----------------------------------------------------------------------
# Domain-mode URL scoring (reused by tests + the harvest function)
# ----------------------------------------------------------------------
def _score_domain_url(url: str) -> float:
    """Higher = more valuable to scan first.

    The score blends two signals:

    * Path-segment match against :data:`_DOMAIN_HIGH_SIGNAL_REGEX`'s
      keywords.  Each keyword hit contributes 1 point.
    * Filename suffix — ``.pdf`` adds 0.5 because PDFs frequently
      carry contact details inside the body.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return 0.0
    path = (parsed.path or "").lower()
    if not path:
        return 0.0
    keywords = _DOMAIN_HIGH_SIGNAL_REGEX.strip("()").split("|")
    score = 0.0
    for kw in keywords:
        if kw == "pdf":
            continue
        # Match the keyword as a path segment so ``/team.html`` scores
        # but ``/steamed-hams`` does not (the latter contains the
        # substring "team" without being a team page).
        if re.search(rf"(?:^|/){re.escape(kw)}(?:/|\.|$)", path):
            score += 1.0
    if path.endswith(".pdf"):
        score += 0.5
    return score


def _score_and_rank(
    rows: Iterable[dict[str, str]],
    *,
    cap: int,
) -> list[tuple[dict[str, str], float]]:
    """Score every CDX row, sort, take top *cap*.

    Sort key: ``score DESC, timestamp DESC``.  Timestamp tiebreak puts
    the freshest snapshot first so the freshness factor is least
    punishing when an address is on both old and recent snapshots.
    """
    scored: list[tuple[dict[str, str], float]] = []
    for row in rows:
        url = row.get("original", "")
        ts = row.get("timestamp", "")
        if not url or not ts:
            continue
        score = _score_domain_url(url)
        scored.append((row, score))
    # Sort by descending score; tiebreak by descending timestamp so
    # freshest wins.  Python's tuple comparison handles it cleanly.
    scored.sort(
        key=lambda pair: (
            -pair[1],
            -(int(pair[0].get("timestamp", "0") or "0") or 0),
        )
    )
    return scored[: max(0, int(cap))]


# ----------------------------------------------------------------------
# Wayback fetch layer (used by harvest_domain_emails)
# ----------------------------------------------------------------------
async def _safe_session_get(session: Any, url: str) -> Any:
    """Call ``session.get(url)`` tolerating both async + sync shapes.

    Both :class:`backend.core.stealth_client.StealthSession` (async
    façade over a sync ``curl-cffi`` session) and
    :class:`httpx.AsyncClient` are accepted.  This helper is now
    timeout-less — callers that need a ceiling wrap it in
    :func:`asyncio.wait_for` (see :func:`_fetch_wayback_snapshot`).

    Wayback fix: ``StealthSession.get()`` used to receive a
    ``timeout=`` kwarg that it silently dropped (the inner sync
    curl-cffi call has no timeout, so the request would hang forever
    on a slow archive.org CDN node). Wrapping with
    :func:`asyncio.wait_for` puts the deadline on the *coroutine*,
    which both StealthSession and httpx.AsyncClient honour.
    """
    return await session.get(url)


async def _fetch_wayback_snapshot(
    session: Any,
    original_url: str,
    timestamp: str,
    *,
    timeout: float = _DOMAIN_FETCH_TIMEOUT,
) -> tuple[str | None, str | None, bool]:
    """Fetch one Wayback snapshot; return ``(html, error, rate_limited)``.

    The Wayback URL embeds the snapshot timestamp + the ``id_`` flag
    — the ``id_`` suffix is critical: omitting it returns Wayback
    toolbar-injected HTML with a navigation overlay.  ``session`` can
    be any object exposing ``async get(url)`` (StealthSession and
    httpx.AsyncClient both qualify).

    Wayback fix: the whole call is wrapped in :func:`asyncio.wait_for`
    so every archive.org fetch has a hard ``timeout`` ceiling
    regardless of whether the underlying session honours a
    ``timeout=`` kwarg.
    """
    wayback_url = f"https://web.archive.org/web/{timestamp}id_/{original_url}"
    try:
        # Wayback fix: hard ceiling on the coroutine — works for both
        # ``httpx.AsyncClient`` (which has its own internal timeout) and
        # ``StealthSession`` (which silently drops unknown kwargs).
        # The previous inner-try / TypeError-fallback was unreachable
        # from this code path: kwargs leaked past ``_safe_session_get``
        # but were then dropped inside the session call. Now we put
        # the deadline where it always matters — on the awaitable.
        response = await asyncio.wait_for(
            _safe_session_get(session, wayback_url),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return None, "Wayback fetch timed out", False
    except httpx.TimeoutException:
        # Defense-in-depth: even with ``wait_for``, some httpx
        # code paths raise this; map it to the same contract.
        return None, "Wayback fetch timed out", False
    except Exception as exc:
        return None, f"Wayback fetch failed: {exc}", False

    status = int(getattr(response, "status_code", 0) or 0)
    if status == 429:
        # Honour Retry-After when the server supplied one.  We sleep at
        # most 5 seconds — long enough to be polite without blowing
        # out the orchestrator's overall budget.
        retry_after = (
            getattr(response, "headers", {}).get("Retry-After", "0")
            if hasattr(response, "headers")
            else "0"
        )
        try:
            wait = float(retry_after)
        except (TypeError, ValueError):
            wait = 0.0
        if 0 < wait <= 5:
            await asyncio.sleep(wait)
        return None, "Wayback Machine rate-limited archived page fetch", True
    if status >= 400:
        return None, f"Wayback returned {status}", False

    try:
        text = str(response.text or "")
    except Exception:
        return None, "Wayback response text could not be decoded", False
    return text or None, None, False


async def _harvest_one(
    session: Any,
    row: dict[str, str],
    *,
    domain: str,
    semaphore: asyncio.Semaphore,
) -> tuple[list[WaybackEmailResult], list[Any], str | None, bool]:
    """Process one CDX row: fetch + extract + decode Cloudflare."""
    original_url = row.get("original", "")
    timestamp = row.get("timestamp", "")
    wayback_url = f"https://web.archive.org/web/{timestamp}id_/{original_url}"

    async with semaphore:
        html_body, error, rate_limited = await _fetch_wayback_snapshot(
            session, original_url, timestamp
        )

    if html_body is None:
        return [], [], error, rate_limited

    decoded = cf_decode(html_body)
    emails_found: list[WaybackEmailResult] = []
    for extracted in extract_emails(decoded, target_domain=domain):
        emails_found.append(
            WaybackEmailResult(
                email=extracted.email,
                archived_url=wayback_url,
                snapshot_timestamp=timestamp,
            )
        )
    people: list[Any] = []
    # Pass the ORIGINAL URL as page_url so the structured extractor's
    # ``worksFor`` + ``_page_on_domain`` checks land on the right host
    # (the Wayback prefix would otherwise defeat both filters).
    try:
        people = extract_people(
            decoded, original_url, domain, is_team_page=False
        )
    except Exception as exc:  # noqa: BLE001 — defensive
        _LOG.debug("wayback: extract_people failed on %s: %s", wayback_url, exc)
    # Attach any structured-person record to the matching email
    # (when the JSON-LD / mailto extracted the same address).
    by_email = {result.email: result for result in emails_found}
    for person in people:
        if getattr(person, "email", None) and person.email in by_email:
            by_email[person.email].person_name = getattr(person, "name", None)
            by_email[person.email].person_title = getattr(person, "title", None)
        elif getattr(person, "email", None) and "@" in person.email:
            emails_found.append(
                WaybackEmailResult(
                    email=person.email,
                    archived_url=wayback_url,
                    snapshot_timestamp=timestamp,
                    person_name=getattr(person, "name", None),
                    person_title=getattr(person, "title", None),
                )
            )
        elif getattr(person, "name", None):
            # Track non-email person records as metadata-only — they
            # don't add a WaybackEmailResult entry by themselves but
            # we surface them via the ``people`` list for debug.
            pass
    return emails_found, people, None, rate_limited


# ----------------------------------------------------------------------
# Public entry — domain-mode harvest
# ----------------------------------------------------------------------
async def harvest_domain_emails(
    domain: str,
    session: Any,
    *,
    aggressive: bool = False,
    cdx_client: httpx.AsyncClient | None = None,
) -> list[WaybackEmailResult]:
    """Walk the Wayback CDX index for *domain* and extract emails.

    Steps:

    1. CDX discovery — two parallel queries:

       * Broad sweep: ``url=*.{domain}/*`` deduped by
         ``collapse=urlkey:digest``.
       * Targeted sweep: ``url={domain}/(team|about|contact|...)/*``
         (no limit — these pages are few and all high-value).

       ``aggressive=True`` removes the ``limit`` cap on the broad
       query and extends the targeted query with year-bounded
       sub-queries going back 5 years.

    2. Score every result against high-signal URLs and PDFs, sort by
       ``score DESC, timestamp DESC``, take the top
       ``wayback_max_urls`` (100 in aggressive mode).

    3. Fetch each archived page in parallel (4 concurrent) via the
       caller-supplied session (the spec mandates
       :class:`backend.core.stealth_client.StealthSession` — but the
       function accepts any session with ``async get(url)``).  Honours
       ``Retry-After`` on ``429``.

    4. On each fetched page: run ``cf_decode`` (Phase 3),
       ``extract_emails`` (regex), and ``extract_people``
       (Phase 2).  Emit one :class:`WaybackEmailResult` per
       email×archive combo with provenance attached.

    Returns a deduplicated list of :class:`WaybackEmailResult` ordered
    by ``email`` (stable).  When the session signals a 429 the harvest
    gracefully degrades — already-fetched results are returned.

    Parameters
    ----------
    domain:
        Target domain (e.g. ``"example.com"``).
    session:
        Async HTTP session used for Wayback snapshot fetches —
        :class:`backend.core.stealth_client.StealthSession` in
        production; any object exposing ``async get(url)`` works.
    aggressive:
        Opt-in flag for low-recall-but-coverage-heavy harvests.
    cdx_client:
        Optional pre-built ``httpx.AsyncClient`` used for the CDX
        discovery calls.  When ``None`` (the production default) the
        harvest builds its own short-lived client.  Tests inject one
        wired to ``httpx.MockTransport`` so they can stub the CDX
        JSON without needing the Wayback CDX endpoint.
    """
    cleaned = (domain or "").strip().lower()
    if not cleaned or "." not in cleaned:
        return []

    # 1. CDX discovery — broad + targeted in parallel.
    cap = int(
        getattr(settings, "wayback_max_urls", _DEFAULT_DOMAIN_URL_CAP)
        or _DEFAULT_DOMAIN_URL_CAP
    )
    if aggressive:
        cap = max(cap, _DEFAULT_DOMAIN_URL_CAP)

    broad_params: dict[str, Any] = {
        "url": f"*.{cleaned}/*",
        "output": "json",
        "limit": str(_DOMAIN_BROAD_LIMIT),
        "fl": "timestamp,original,statuscode,mimetype,digest",
        "filter": ["statuscode:200", "mimetype:text/html"],
        "collapse": "urlkey:digest",
    }
    if aggressive:
        # Strip the limit entirely.
        broad_params.pop("limit", None)

    targeted_params: dict[str, Any] = {
        "url": f"{cleaned}/{_DOMAIN_HIGH_SIGNAL_REGEX}/*",
        "output": "json",
        "limit": str(_DOMAIN_TARGETED_LIMIT),
        "fl": "timestamp,original,statuscode,mimetype,digest",
        "filter": ["statuscode:200", "mimetype:text/html"],
        "collapse": "urlkey:digest",
    }
    if aggressive:
        # Extend back 5 years by adding a ``from=``/``to=`` pair of
        # year-bounded sub-queries.  Wayback CDX supports
        # ``from=YYYY`` / ``to=YYYY`` filters.
        current_year = datetime.now(timezone.utc).year
        targeted_params["from"] = str(current_year - 5)
        targeted_params["to"] = str(current_year)

    rows: list[dict[str, str]] = []
    try:
        if cdx_client is not None:
            broad, err1, _p1, _rl1 = await _run_cdx_query(cdx_client, broad_params)
            targeted, err2, _p2, _rl2 = await _run_cdx_query(cdx_client, targeted_params)
            if err1 or err2:
                _LOG.debug(
                    "wayback domain harvest CDX errors: %s / %s", err1, err2
                )
            rows = list(broad) + list(targeted)
        else:
            async with httpx.AsyncClient(
                headers={"User-Agent": "MailAccess/wayback"}
            ) as client:
                broad, err1, _p1, _rl1 = await _run_cdx_query(client, broad_params)
                targeted, err2, _p2, _rl2 = await _run_cdx_query(client, targeted_params)
                if err1 or err2:
                    _LOG.debug(
                        "wayback domain harvest CDX errors: %s / %s", err1, err2
                    )
                rows = list(broad) + list(targeted)
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("wayback domain harvest CDX failed: %s", exc)
        return []

    # 2. Rank.
    ranked = _score_and_rank(rows, cap=cap)
    if not ranked:
        return []

    # 3. Fetch all snapshots concurrently, bounded.
    semaphore = asyncio.Semaphore(_DOMAIN_FETCH_CONCURRENCY)
    tasks = [
        _harvest_one(session, row, domain=cleaned, semaphore=semaphore)
        for row, _score in ranked
    ]
    outcomes = await asyncio.gather(*tasks, return_exceptions=True)

    # 4. Aggregate + dedupe by email (keep most recent snapshot).
    by_email: dict[str, WaybackEmailResult] = {}
    for outcome in outcomes:
        if isinstance(outcome, BaseException):
            continue
        emails_found, _people, _err, _rl = outcome
        for result in emails_found:
            existing = by_email.get(result.email)
            if existing is None or result.snapshot_timestamp > existing.snapshot_timestamp:
                by_email[result.email] = result

    return sorted(by_email.values(), key=lambda r: r.email)


# ============================================================
# Legacy single-email WaybackModule (unchanged in Phase 3)
# ============================================================
class WaybackModule(BaseModule):
    name = "wayback"
    description = (
        "Search the Internet Archive Wayback Machine for historical public mentions "
        "of an email address."
    )
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        errors: list[str] = []
        partial = False

        try:
            # scrapingant: dropped in S5 audit (Wayback CDX endpoint returns JSON).
            async with build_client(follow_redirects=True) as client:
                rows, cdx_errors, cdx_partial = await self._search_cdx(client, email)
                errors.extend(cdx_errors)
                partial = partial or cdx_partial

                findings: list[dict] = []
                seen: set[tuple[str, str]] = set()
                for row in rows[:_CDX_LIMIT]:
                    original_url = row.get("original", "")
                    timestamp = row.get("timestamp", "")
                    key = (original_url, timestamp)
                    if not original_url or not timestamp or key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._base_finding(email, original_url, timestamp))

                for finding in findings[:_PAGE_FETCH_LIMIT]:
                    meta = finding["metadata"]
                    archived_url = str(finding["profile_url"])
                    page_error, was_rate_limited = await self._enrich_page(
                        client, email, archived_url, meta
                    )
                    if page_error:
                        errors.append(page_error)
                    partial = partial or was_rate_limited
                    original_lower = str(meta["original_url"]).lower()
                    if meta.get("context_snippet") and email.lower() not in original_lower:
                        finding["confidence"] = "medium"

        except httpx.TimeoutException:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["Wayback Machine request timed out"],
            )
        except Exception as exc:
            return ModuleResult(status=ModuleStatus.FAILED, errors=[str(exc)])

        archive_dates = [
            str(f["metadata"].get("archive_date"))
            for f in findings
            if isinstance(f.get("metadata"), dict) and f["metadata"].get("archive_date")
        ]
        domains = [
            str(f["metadata"].get("original_domain"))
            for f in findings
            if isinstance(f.get("metadata"), dict) and f["metadata"].get("original_domain")
        ]
        oldest_domain = ""
        if findings:
            oldest = min(findings, key=lambda f: str(f.get("metadata", {}).get("archive_date", "")))
            oldest_domain = str(oldest.get("metadata", {}).get("original_domain") or "")

        status = ModuleStatus.SUCCESS
        if partial:
            status = ModuleStatus.PARTIAL
        elif errors and findings:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "pages_found": len(findings),
                "earliest_mention": min(archive_dates) if archive_dates else "",
                "latest_mention": max(archive_dates) if archive_dates else "",
                "unique_domains": sorted(set(domains)),
                "oldest_domain": oldest_domain,
            },
            errors=errors,
        )

    async def _search_cdx(
        self, client: httpx.AsyncClient, email: str
    ) -> tuple[list[dict[str, str]], list[str], bool]:
        searches = [
            {
                "url": f"*{email}*",
                "output": "json",
                "limit": str(_CDX_LIMIT),
                "fl": "original,timestamp,statuscode,mimetype",
                "filter": ["statuscode:200"],
                "collapse": "urlkey",
            },
            {
                "url": "*",
                "output": "json",
                "limit": "10",
                "fl": "original,timestamp",
                "filter": [f"original:.*{re.escape(email)}.*"],
            },
        ]
        rows: list[dict[str, str]] = []
        errors: list[str] = []
        partial = False

        for params in searches:
            try:
                response = await client.get(_CDX_URL, params=params, timeout=10.0)
            except httpx.TimeoutException:
                errors.append("Wayback CDX query timed out")
                partial = True
                continue
            except Exception as exc:
                errors.append(f"Wayback CDX query failed: {exc}")
                partial = True
                continue

            if response.status_code == 429:
                errors.append("Wayback Machine rate-limited CDX search")
                partial = True
                continue
            if response.status_code != 200:
                errors.append(f"Wayback CDX returned {response.status_code}")
                partial = True
                continue
            try:
                rows.extend(_parse_cdx_rows(response.json()))
            except Exception:
                errors.append("Wayback CDX returned unparseable JSON")
                partial = True

        deduped: dict[tuple[str, str], dict[str, str]] = {}
        for row in rows:
            deduped.setdefault((row.get("original", ""), row.get("timestamp", "")), row)
        return list(deduped.values())[:_CDX_LIMIT], errors, partial

    def _base_finding(self, email: str, original_url: str, timestamp: str) -> dict:
        archive_date = _archive_date(timestamp)
        parsed = urlparse(original_url)
        domain = parsed.hostname or parsed.netloc or ""
        archive_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
        email_in_url = email.lower() in original_url.lower()
        return {
            "platform": "wayback_machine",
            "profile_url": archive_url,
            "confidence": "high" if email_in_url else "medium",
            "metadata": {
                "original_url": original_url,
                "archive_date": archive_date,
                "page_title": "",
                "context_snippet": "",
                "original_domain": domain,
                "years_ago": _years_ago(archive_date),
            },
        }

    async def _enrich_page(
        self,
        client: httpx.AsyncClient,
        email: str,
        archived_url: str,
        metadata: dict,
    ) -> tuple[str | None, bool]:
        try:
            response = await client.get(archived_url, timeout=8.0)
        except httpx.TimeoutException:
            return f"Archived page fetch timed out: {archived_url}", False
        except Exception as exc:
            return f"Archived page fetch failed: {exc}", False

        if response.status_code == 429:
            return "Wayback Machine rate-limited archived page fetch", True
        if response.status_code >= 400:
            return f"Archived page returned {response.status_code}: {archived_url}", False

        text = response.text
        metadata["page_title"] = _page_title(text)
        metadata["context_snippet"] = _snippet(text, email)
        return None, False


# ============================================================
# Phase 3 — domain-mode module class for the orchestrator
# ============================================================
def _build_stealth_session() -> StealthSession | None:
    """Build a StealthSession with the operator's pacing profile.

    Returns ``None`` when ``curl-cffi`` is not installed — the
    :class:`WaybackDomainHarvestModule` will fall back to an httpx
    client instead of crashing the harvest.

    Wayback fix: archive.org performs no fingerprinting, so the
    navigation-graph simulation (intermediate homepage + parent-path
    GETs) is pure overhead on top of an already-slow T0/T1 blocking
    ``time.sleep`` call. We disable navigation simulation here while
    keeping the operator's pacing profile intact — so the inter-
    request pacing delay still applies, but no extra blocking
    requests fire on top of it.
    """
    try:
        profile_name = str(getattr(settings, "harvest_timing_profile", "t5") or "t5")
        session = StealthSession(timing_profile=resolve_timing_profile(profile_name))
        # Wayback fix: skip the navigation-graph simulation against
        # archive.org. The operator's pacing profile (delay budget) is
        # unchanged — only the intermediate hop GETs are suppressed.
        session._skip_nav_sim = True
        return session
    except ImportError:
        return None
    except Exception:  # noqa: BLE001
        return None


class WaybackDomainHarvestModule(BaseModule):
    """Domain-mode Wayback Machine harvest (Phase 3 of 0.11.1).

    Slots into the orchestrator's Phase 1 alongside
    :class:`backend.modules.commoncrawl_email.CommonCrawlEmailModule`.
    Pass a :class:`backend.core.stealth_client.StealthSession` to
    :meth:`set_session`; when no session is injected one is built
    internally with the operator's configured pacing profile (defaults
    to ``t5`` so test runs don't block on real pacing).
    """

    name = "wayback_domain_harvest"
    description = (
        "Domain-wide Wayback Machine email harvest — sweeps CDX for high-signal "
        "URLs, fetches archived pages, extracts emails + person records."
    )
    requires_key = False
    default_enabled = False  # Opt-in via domain harvest mode

    def __init__(self, session: Any | None = None) -> None:
        super().__init__()
        self._session: Any = session
        self._owns_session = session is None
        # 0.11.1 Phase 3 cache: when set by the orchestrator, Wayback
        # routes every page fetch through this facade instead of its
        # own self._session.  ``aclose`` is suppressed in that mode
        # because the cache owns teardown for the whole run.
        self._fetch: CachedFetch | None = None

    def set_session(self, session: Any) -> None:
        """Inject a session (used by orchestrator wiring)."""
        if self._owns_session and self._session is not None:
            close_session(self._session)
        self._session = session
        self._owns_session = False

    async def aclose(self) -> None:
        if self._fetch is not None:
            # Cache owns teardown; never close it from here.
            return
        if self._owns_session and self._session is not None:
            close_session(self._session)
            self._session = None

    async def run(
        self,
        target: str,
        *,
        aggressive: bool | None = None,
        max_urls: int | None = None,
        fetch: CachedFetch | None = None,
        signal_pool: Any | None = None,
        **_unused: Any,
    ) -> ModuleResult:  # type: ignore[override]
        """Harvest emails for *target* (a domain) via Wayback CDX.

        ``aggressive`` and ``max_urls`` are threaded through as kwargs so
        the orchestrator's signature-aware runner can pass them without
        touching the legacy ``run(email)`` contract for the original
        single-email module.

        ``fetch`` (0.11.1 Phase 3): when supplied by the orchestrator,
        Wayback routes its archive.org page fetches through the per-run
        :class:`CachedFetch` cache instead of building its own
        ``StealthSession``.  Same URL across runs / modules collapses
        to a single archive.org request.
        """
        if not getattr(settings, "enable_wayback_harvest", True):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=(
                    "wayback_domain_harvest disabled — set "
                    "ENABLE_WAYBACK_HARVEST=true to enable"
                ),
            )

        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["wayback_domain_harvest: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        effective_aggressive = bool(aggressive) if aggressive is not None else bool(
            getattr(settings, "harvest_aggressive", False)
        )

        # 0.11.1 Phase 3 cache: when ``fetch`` is provided, store it
        # and use it as the "session" for helper calls.  CachedFetch
        # exposes the same ``async get(url)`` shape as StealthSession,
        # so the existing helpers consume it transparently.  We do NOT
        # call _build_stealth_session when fetch is provided — the
        # cache already owns a session for the run, and a second
        # StealthSession would defeat the point of dedup.
        if fetch is not None:
            self._fetch = fetch
            transport: Any = fetch
        elif self._session is None:
            # Resolve a session: caller-supplied, then stealth-built,
            # then httpx fallback (when curl-cffi isn't installed).
            transport = _build_stealth_session() or build_client(follow_redirects=True)
            self._session = transport
            self._owns_session = True
        else:
            transport = self._session

        cap = int(
            max_urls
            if max_urls is not None
            else getattr(settings, "wayback_max_urls", _DEFAULT_DOMAIN_URL_CAP)
            or _DEFAULT_DOMAIN_URL_CAP
        )
        if cap <= 0:
            cap = _DEFAULT_DOMAIN_URL_CAP

        try:
            results = await harvest_domain_emails(
                domain,
                transport,
                aggressive=effective_aggressive,
            )
        except Exception as exc:  # noqa: BLE001 — defensive
            _LOG.warning("wayback_domain_harvest catastrophic: %s", exc)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"wayback_domain_harvest: {exc}"],
                metadata={"domain": domain},
            )

        if not results:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=[],
                metadata={
                    "domain": domain,
                    "records_fetched": 0,
                    "emails_found": 0,
                    "wayback_coverage": "none",
                },
            )

        findings = [self._render_finding(r, domain) for r in results]

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "domain": domain,
                "records_fetched": cap,
                "emails_found": len(results),
                "aggressive": effective_aggressive,
                "wayback_coverage": ("high" if len(results) >= 25 else "low"),
            },
        )

    @staticmethod
    def _render_finding(result: WaybackEmailResult, domain: str) -> dict[str, Any]:
        """Convert a :class:`WaybackEmailResult` into a finding dict.

        ``metadata`` carries enough downstream signals:

        * ``email`` — the canonical address (downstream dedup key).
        * ``on_domain`` — whether the address domain equals *domain*.
        * ``source_type`` — ``"wayback_archive"`` so the email-
          confidence aggregator weights it alongside Common Crawl.
        * ``archived_url`` + ``snapshot_timestamp`` — provenance for
          analysts and the freshness-factor input.
        * ``is_historical`` — True; the orchestrator uses freshness as
          the penalty, this is the source-semantics marker.
        * ``oldest_timestamp`` — set so ``_aggregate`` picks the
          snapshot up as the freshness input.  Same value for
          ``oldest`` and ``newest`` (one snapshot, one email).
        """
        local_part = result.email.split("@", 1)[0]
        on_domain = bool(result.email.endswith("@" + domain))
        snapshot_iso = _archive_date(result.snapshot_timestamp)
        return {
            "platform": "wayback_domain_harvest",
            "profile_url": result.archived_url,
            "username": local_part,
            "confidence": "medium",
            "metadata": {
                "email": result.email,
                "on_domain": on_domain,
                "source_type": "wayback_archive",
                "source_urls": [result.archived_url],
                "archived_url": result.archived_url,
                "snapshot_timestamp": result.snapshot_timestamp,
                "oldest_timestamp": result.snapshot_timestamp,
                "newest_timestamp": result.snapshot_timestamp,
                "archive_date": snapshot_iso,
                "is_historical": True,
                "person_name": result.person_name,
                "person_title": result.person_title,
                "local_part": local_part,
                "confidence_score": result.confidence,
            },
        }


def close_session(session: Any) -> None:
    """Best-effort close for either a StealthSession or an httpx client."""
    if session is None:
        return
    close = getattr(session, "close", None) or getattr(session, "aclose", None)
    if close is None:
        return
    try:
        result = close()
        if hasattr(result, "__await__"):
            # httpx.AsyncClient.aclose returns a coroutine — drain it.
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = None
            if loop and loop.is_running():
                # Caller is in an async context; schedule the drain.
                loop.create_task(result)
            else:
                asyncio.run(result)
    except Exception:  # noqa: BLE001 — best-effort
        pass


__all__ = [
    "WaybackEmailResult",
    "WaybackModule",
    "WaybackDomainHarvestModule",
    "harvest_domain_emails",
]
