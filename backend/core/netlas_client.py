"""Netlas.io integration — BYOK client shared by the Netlas features (F1–F7).

* **F1 — subdomain enumeration** (:func:`fetch_subdomains` /
  :func:`search_subdomains`): one cheap ``domains_count`` call to size the
  job, then one capped ``domains/download`` call (a JSON array). At most one count
  + one download per harvest is the credit guardrail.
* **F2 — WHOIS contact emails** (:func:`fetch_whois` / :func:`whois_domain`):
  exactly one ``whois_domains`` search for the apex domain; contact emails are
  junk-filtered (privacy proxies, redaction markers, registrar desks) and the
  registrant organization is returned as metadata only.
* **F3 — certificate emails + SANs** (:func:`fetch_certificates` /
  :func:`certificates`): exactly one ``certs/download`` request (Netlas' tight
  3 req/min lane) bounded to ``doc_cap`` documents; subject/SAN emails become
  leads, in-scope SAN hosts feed subdomain harvest, and sister registrable
  domains are recorded as F5 seeds (never from shared CDN certificates).
* **F4 — emails from indexed HTTP responses + FTP banners**
  (:func:`fetch_response_emails` / :func:`response_emails`): one domain-wide
  query — 1 count + at most 1 download bounded to ``resp_cap`` docs, projected
  to Netlas' pre-extracted ``*.contacts.email`` fields (no bodies). Every lead
  carries the URL it was published at.
* **F5 - related-domain discovery** (:func:`fetch_related_domains` /
  :func:`related_domains`): pivots off the org (WHOIS registrant org,
  shared non-cloud NS / MX, shared analytics-tracker IDs) plus the F3
  sister-SAN seeds, to rank the orgs *other* domains. Bounded; never
  harvests them (that is opt-in expansion).
* **F6 - reverse email footprint** (:func:`fetch_email_footprint`): the
  investigate-side half - 3 bounded lookups for one exact address
  (responses/banners, certificates, reverse-WHOIS) showing where it
  appears online. Reverse-WHOIS domains are a strong ownership signal.
* **F7 - org attack-surface context** (:func:`fetch_org_surface`): the
  email domains org posture - subdomains, exposed login/admin panels,
  open ports/services, and known CVEs. Light = 2 calls (host posture +
  one responses query); deep (opt-in) adds F1 subdomain enumeration.

Routing rule — the ONE place every Netlas feature checks
(:func:`netlas_active`): Netlas is active iff ``netlas_api_key`` is set AND
``netlas_disabled`` is false AND the run did not pass ``--no-netlas``.

Error handling contract (mirrors ``hunter_client``): nothing here raises.
401, a JSON 403, or the 400 "API key not found" error (bad key) latches an
invalid-key flag for the life of the process; 402 or the JSON ``daily_request_limit_exceeded`` error latches a
quota flag; a plain-text 403 is Netlas' CDN edge blocking this network (not a
key problem); 429 is retried once honouring ``Retry-After`` (capped); any
other status / network error / timeout returns an empty result. Every failure
is logged and reported in the result's ``status`` so callers can show a
one-line note.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import httpx

from ..config import settings

_LOG = logging.getLogger(__name__)

NETLAS_BASE_URL = "https://app.netlas.io"
_DOMAINS_COUNT_URL = f"{NETLAS_BASE_URL}/api/domains_count/"
_DOMAINS_DOWNLOAD_URL = f"{NETLAS_BASE_URL}/api/domains/download/"

#: Where the first-run hint sends operators for a free key.
NETLAS_SIGNUP_URL = "https://app.netlas.io/registration/"

#: Longest ``Retry-After`` we will sleep for on a 429 before giving up.
_MAX_RETRY_AFTER_SECONDS = 10.0
#: Retries on 429 only (a throttled request is not billed).
_MAX_429_RETRIES = 1

# Result statuses.
STATUS_OK = "ok"
STATUS_EMPTY = "empty"
STATUS_INVALID_KEY = "invalid_key"
STATUS_QUOTA = "quota_exhausted"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_ERROR = "error"
STATUS_BLOCKED = "blocked"
STATUS_INACTIVE = "inactive"
#: A source hit the F6 internal deadline: it answered nothing (or partially) but did
#: NOT fail — deliberately not in FAILURE_STATUSES.
STATUS_TRUNCATED = "truncated"

#: Statuses that mean "Netlas could not help this run" — the caller falls back
#: to native discovery and shows a dim one-line note.
FAILURE_STATUSES = frozenset(
    {STATUS_INVALID_KEY, STATUS_QUOTA, STATUS_RATE_LIMITED, STATUS_ERROR, STATUS_BLOCKED}
)


# ---------------------------------------------------------------------------
# Routing predicate.
# ---------------------------------------------------------------------------


#: Per-run ``--no-netlas`` for the investigate path, set once at the start of an
#: investigation (``set_no_netlas``) and inherited by the concurrent module
#: tasks. The harvest path passes ``no_netlas`` explicitly instead.
_NO_NETLAS_VAR: ContextVar[bool] = ContextVar("mailaccess_no_netlas", default=False)


def set_no_netlas(value: bool):
    """Set the current context's ``--no-netlas`` flag; returns the reset token."""
    return _NO_NETLAS_VAR.set(bool(value))


#: Per-run ``--org-surface-deep`` (F7), same contextvar mechanism as no_netlas.
_ORG_SURFACE_DEEP_VAR: ContextVar[bool] = ContextVar(
    "mailaccess_org_surface_deep", default=False
)


def set_org_surface_deep(value: bool):
    """Set the current context's F7 deep-mode flag; returns the reset token."""
    return _ORG_SURFACE_DEEP_VAR.set(bool(value))


def org_surface_deep() -> bool:
    return _ORG_SURFACE_DEEP_VAR.get()


def netlas_active(*, no_netlas: bool | None = None, cfg: Any | None = None) -> bool:
    """Return True iff Netlas may be called for this run.

    Key set AND not persistently disabled AND not opted out per-run. ``no_netlas``
    defaults to the per-run context flag (investigate) when not passed explicitly
    (harvest). Every Netlas feature (F1–F7) must gate on this — never on the key.
    """
    if no_netlas is None:
        no_netlas = _NO_NETLAS_VAR.get()
    if no_netlas:
        return False
    source = cfg if cfg is not None else settings
    if bool(getattr(source, "netlas_disabled", False)):
        return False
    return bool(str(getattr(source, "netlas_api_key", "") or "").strip())


def netlas_hint_message() -> str:
    """The one-time first-run nudge shown when an in-scope task runs keyless."""
    return (
        "Runs better with a free Netlas.io key — works without it too. "
        f"Set up: {NETLAS_SIGNUP_URL} then `mailaccess netlas set-key <KEY>`."
    )


#: Marker written after the first-run hint is shown, so it prints once.
NETLAS_HINT_MARKER = "~/.mailaccess/.netlas_hint_shown"

_NOTE_REASONS = {
    STATUS_INVALID_KEY: "key rejected",
    STATUS_QUOTA: "out of credits",
    STATUS_RATE_LIMITED: "rate limited",
    STATUS_ERROR: "unreachable",
    STATUS_BLOCKED: "blocked this network (HTTP 403 at the edge)",
    "timeout": "timed out",
}


def netlas_run_note(meta: Any) -> str | None:
    """One-line, user-facing note for a run's Netlas outcome (``None`` = quiet).

    *meta* is the ``netlas`` block ``subdomain_intel`` stamps on its metadata.
    Failures say we fell back to native discovery; a capped download says how
    much was left on the table.
    """
    if not isinstance(meta, dict):
        return None
    status = str(meta.get("status") or "")
    reason = _NOTE_REASONS.get(status)
    if reason:
        return f"Netlas {reason} — continued with native sources only."
    notes: list[str] = []
    if meta.get("capped"):
        notes.append(
            f"Netlas: {meta.get('total')} subdomains known, harvested the first "
            f"{meta.get('cap')} (raise NETLAS_SUBDOMAIN_CAP to widen)."
        )
    if meta.get("cert_hosts_over_cap"):
        notes.append(
            f"Netlas: {meta['cert_hosts_over_cap']} certificate hostnames were over the "
            "shared NETLAS_SUBDOMAIN_CAP and not harvested."
        )
    if meta.get("resp_capped"):
        notes.append(
            f"Netlas: {meta.get('total')} matching web responses, scanned the first "
            f"{meta.get('resp_cap')} (raise NETLAS_RESP_CAP to widen)."
        )
    if meta.get("docs_capped"):
        notes.append(
            f"Netlas: certificate search hit the {meta.get('doc_cap')}-document cap "
            "(raise NETLAS_CERT_DOC_CAP to widen)."
        )
    return " ".join(notes) or None


# ---------------------------------------------------------------------------
# Process-lifetime latches (bad key / out of credits) — after the first hit,
# skip every remaining call instead of burning requests (matters for bulk).
# ---------------------------------------------------------------------------

_LATCH_LOCK = threading.Lock()
_KEY_INVALID = False
_QUOTA_EXHAUSTED = False


def _latch(kind: str) -> None:
    global _KEY_INVALID, _QUOTA_EXHAUSTED
    with _LATCH_LOCK:
        if kind == STATUS_INVALID_KEY:
            if not _KEY_INVALID:
                _LOG.warning("Netlas.io API key rejected (HTTP 401/403); skipping Netlas.")
            _KEY_INVALID = True
        elif kind == STATUS_QUOTA:
            if not _QUOTA_EXHAUSTED:
                _LOG.warning("Netlas.io credits exhausted (HTTP 402); skipping Netlas.")
            _QUOTA_EXHAUSTED = True


def _latched_status() -> str | None:
    with _LATCH_LOCK:
        if _KEY_INVALID:
            return STATUS_INVALID_KEY
        if _QUOTA_EXHAUSTED:
            return STATUS_QUOTA
    return None


def reset_netlas_state_for_tests() -> None:
    """Test-only: clear the invalid-key / quota latches."""
    global _KEY_INVALID, _QUOTA_EXHAUSTED
    with _LATCH_LOCK:
        _KEY_INVALID = False
        _QUOTA_EXHAUSTED = False


# ---------------------------------------------------------------------------
# HTTP plumbing.
# ---------------------------------------------------------------------------


def _headers(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}", "Accept": "application/json"}


def _timeout() -> float:
    try:
        return max(1.0, float(getattr(settings, "netlas_timeout_seconds", 30.0)))
    except (TypeError, ValueError):
        return 30.0


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return 1.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None


#: Netlas' JSON error ``type`` for the plan's daily request allowance.
_DAILY_LIMIT_TYPE = "daily_request_limit_exceeded"


def _error_type(response: httpx.Response) -> str | None:
    """Netlas API errors are JSON with a ``type``; edge (Cloudflare) blocks are not."""
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001 - non-JSON body (or not yet read)
        return None
    if isinstance(payload, dict):
        kind = payload.get("type") or payload.get("detail")
        return str(kind) if kind else ""
    return ""


def _is_daily_limit(response: httpx.Response) -> bool:
    return _error_type(response) == _DAILY_LIMIT_TYPE


_BAD_KEY_MARKERS = ("invalid authorization credentials", "api key not found", "invalid api key")


def _is_bad_key(response: httpx.Response) -> bool:
    """Live Netlas rejects an unknown key with HTTP **400** and
    ``{"detail": "Request had invalid authorization credentials: API key not found"}``."""
    kind = (_error_type(response) or "").lower()
    return any(marker in kind for marker in _BAD_KEY_MARKERS)


def _status_for(response: httpx.Response) -> str:
    """Map a non-200 response to a result status (latching where needed).

    A plain-text 403 comes from Netlas' CDN edge (e.g. Cloudflare 1006 — the
    caller's IP is blocked), not the API, so it is NOT reported as a bad key.
    The daily request allowance is credit exhaustion whatever the status code.
    """
    code = response.status_code
    kind = _error_type(response)
    if code == 402 or kind == _DAILY_LIMIT_TYPE:
        _latch(STATUS_QUOTA)
        return STATUS_QUOTA
    if code == 401 or (code == 403 and kind is not None) or _is_bad_key(response):
        _latch(STATUS_INVALID_KEY)
        return STATUS_INVALID_KEY
    if code == 403:
        return STATUS_BLOCKED
    if code == 429:
        return STATUS_RATE_LIMITED
    return STATUS_ERROR


async def _wait_for_429(
    response: httpx.Response,
    attempt: int,
    *,
    max_delay: float = _MAX_RETRY_AFTER_SECONDS,
) -> bool:
    """Sleep per ``Retry-After`` and return True when a retry is allowed."""
    if attempt >= _MAX_429_RETRIES or _is_daily_limit(response):
        return False
    delay = _retry_after(response)
    if delay is None or delay > max_delay:
        return False
    await asyncio.sleep(delay)
    return True


# ---------------------------------------------------------------------------
# F1 — subdomain enumeration.
# ---------------------------------------------------------------------------


@dataclass
class NetlasSubdomainResult:
    """Outcome of one subdomain enumeration (hosts plus why/why-not)."""

    hosts: list[str] = field(default_factory=list)
    status: str = STATUS_EMPTY
    #: Netlas' total count for the query (``None`` when the count call failed).
    total: int | None = None
    #: True when ``total`` exceeded the cap and the download was truncated.
    capped: bool = False
    cap: int = 0
    #: HTTP requests actually sent (429 retries included).
    calls: int = 0
    error: str | None = None


def _normalize_host(value: Any, domain: str) -> str | None:
    host = str(value or "").strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host or host == domain or not host.endswith("." + domain):
        return None
    return host


def _host_from_record(record: Any) -> Any:
    if not isinstance(record, dict):
        return None
    data = record.get("data")
    if isinstance(data, dict) and data.get("domain"):
        return data.get("domain")
    return record.get("domain")


def _download_records(body: str) -> list[Any]:
    """Records from a ``domains/download`` body.

    Live Netlas returns ``application/json``: ONE pretty-printed array, a record
    per line with trailing commas — so per-line parsing loses all but the last
    record. Parse the whole document first; fall back to NDJSON (the SDK's
    other documented shape) line by line.
    """
    text = body.strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except ValueError:
        records: list[Any] = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
        return records
    return payload if isinstance(payload, list) else [payload]


def _query(domain: str) -> str:
    return f"domain:*.{domain}"


async def _get_json(
    client: httpx.AsyncClient,
    url: str,
    params: dict[str, Any],
    key: str,
    result: Any,
    label: str,
) -> Any | None:
    """GET *url* (one 429 retry); on failure set ``result.status``/``error``."""
    attempt = 0
    while True:
        result.calls += 1
        response = await client.get(url, params=params, headers=_headers(key))
        if response.status_code == 200:
            break
        if response.status_code == 429 and await _wait_for_429(response, attempt):
            attempt += 1
            continue
        result.status = _status_for(response)
        result.error = f"{label} HTTP {response.status_code}"
        return None
    try:
        return response.json()
    except Exception as exc:  # noqa: BLE001 - malformed body is just a failure
        result.status = STATUS_ERROR
        result.error = f"{label} unparseable: {exc}"
        return None


async def _count(
    client: httpx.AsyncClient, domain: str, key: str, result: NetlasSubdomainResult
) -> int | None:
    payload = await _get_json(
        client, _DOMAINS_COUNT_URL, {"q": _query(domain)}, key, result, "domains_count"
    )
    if payload is None:
        return None
    try:
        return max(0, int(payload.get("count") or 0))
    except Exception as exc:  # noqa: BLE001 - malformed body is just a failure
        result.status = STATUS_ERROR
        result.error = f"domains_count unparseable: {exc}"
        return None


async def _post_download(
    client: httpx.AsyncClient,
    url: str,
    payload: dict[str, Any],
    key: str,
    result: Any,
    label: str,
    *,
    max_retry_after: float = _MAX_RETRY_AFTER_SECONDS,
) -> list[Any] | None:
    """POST a ``*/download/`` request (one 429 retry) and return its records.

    On failure sets ``result.status`` / ``result.error`` and returns ``None``.
    """
    attempt = 0
    while True:
        result.calls += 1
        async with client.stream("POST", url, json=payload, headers=_headers(key)) as response:
            raw = await response.aread()
            if response.status_code == 429 and await _wait_for_429(
                response, attempt, max_delay=max_retry_after
            ):
                attempt += 1
                continue
            if response.status_code != 200:
                result.status = _status_for(response)
                result.error = f"{label} HTTP {response.status_code}"
                return None
            return _download_records(raw.decode("utf-8", errors="replace"))


async def _download(
    client: httpx.AsyncClient,
    domain: str,
    key: str,
    size: int,
    result: NetlasSubdomainResult,
) -> list[str] | None:
    payload = {
        "q": _query(domain),
        "fields": ["domain"],
        "source_type": "include",
        "size": int(size),
    }
    records = await _post_download(
        client, _DOMAINS_DOWNLOAD_URL, payload, key, result, "domains/download"
    )
    if records is None:
        return None
    hosts: dict[str, None] = {}
    for item in records:
        host = _normalize_host(_host_from_record(item), domain)
        if host:
            hosts.setdefault(host, None)
    return list(hosts)[: int(size)]


async def fetch_subdomains(
    domain: str,
    key: str | None,
    *,
    cap: int | None = None,
) -> NetlasSubdomainResult:
    """Enumerate ``*.{domain}`` via Netlas: 1 count call + 1 download call.

    Never raises. Returns hosts lowercased, deduped, restricted to real
    subdomains of *domain*, and truncated to *cap* (``capped`` is set when
    Netlas had more than the cap). A zero count skips the download entirely.
    """
    domain = str(domain or "").strip().lower().rstrip(".")
    limit = int(cap if cap is not None else getattr(settings, "netlas_subdomain_cap", 500))
    result = NetlasSubdomainResult(cap=max(0, limit))
    key = str(key or "").strip()
    if not domain or "." not in domain or not key or limit <= 0:
        result.status = STATUS_INACTIVE
        return result
    latched = _latched_status()
    if latched:
        result.status = latched
        result.error = "latched from an earlier response"
        return result

    try:
        async with httpx.AsyncClient(timeout=_timeout(), follow_redirects=False) as client:
            total = await _count(client, domain, key, result)
            if total is None:
                _LOG.warning("Netlas subdomain count failed for %s: %s", domain, result.error)
                return result
            result.total = total
            if total == 0:
                result.status = STATUS_EMPTY
                return result
            result.capped = total > limit
            if result.capped:
                _LOG.warning(
                    "Netlas: %s has %d subdomains; harvesting the first %d "
                    "(raise NETLAS_SUBDOMAIN_CAP to widen).",
                    domain, total, limit,
                )
            hosts = await _download(client, domain, key, min(total, limit), result)
    except httpx.TimeoutException:
        result.status = STATUS_ERROR
        result.error = "timeout"
        _LOG.warning("Netlas subdomain enumeration timed out for %s", domain)
        return result
    except Exception as exc:  # noqa: BLE001 - never raise into the harvest
        result.status = STATUS_ERROR
        result.error = str(exc) or exc.__class__.__name__
        _LOG.warning("Netlas subdomain enumeration failed for %s: %s", domain, exc)
        return result

    if hosts is None:
        _LOG.warning("Netlas subdomain download failed for %s: %s", domain, result.error)
        return result
    result.hosts = hosts
    result.status = STATUS_OK if hosts else STATUS_EMPTY
    return result


async def search_subdomains(domain: str, key: str | None, *, cap: int) -> list[str]:
    """Return Netlas-known subdomains of *domain* (``[]`` on any failure)."""
    return (await fetch_subdomains(domain, key, cap=cap)).hosts


# ---------------------------------------------------------------------------
# F2 — WHOIS contact emails (apex domain only, exactly one call).
# ---------------------------------------------------------------------------

_WHOIS_DOMAINS_URL = f"{NETLAS_BASE_URL}/api/whois_domains/"

#: Contact blocks of a parsed WHOIS record (``/api/mapping/whois_domains/``).
#: ``registrar`` is deliberately absent — it only ever holds the registrar's
#: own abuse desk.
WHOIS_CONTACT_ROLES = ("registrant", "administrative", "technical", "billing")

_EMAIL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$")

#: Privacy-proxy / redaction services. Matched on the email's domain or any
#: parent of it (``contact.whoisguard.com`` → ``whoisguard.com``).
WHOIS_PROXY_DOMAINS = frozenset(
    {
        "whoisguard.com",
        "withheldforprivacy.com",
        "privacyprotect.org",
        "domainsbyproxy.com",
        "contactprivacy.com",
        "privacyguardian.org",
        "whoisprivacyprotect.com",
        "whoisprivacycorp.com",
        "domainprivacygroup.com",
        "perfectprivacy.com",
        "privacy.link",
        "whoisproxy.com",
        "registrarsafe.com",
        "identity-protect.org",
        "anonymize.com",
        "proxy.dreamhost.com",
        "protecteddomainservices.com",
        "whoisprotection.cc",
        "privatewho.is",
        "redacted.com",
    }
)
#: Redaction tokens in any local part (a plain ``gdpr@`` / ``privacy@`` on the
#: target is a real data-protection mailbox and is kept).
_REDACTION_RE = re.compile(
    r"redact|withheld|masked|not[._-]?disclosed|data[._-]?protected|"
    r"whois[._-]?(?:privacy|guard|proxy|protect)|privacy[._-]?(?:protect|proxy|service)"
)
_OFF_TARGET_DOMAIN_MARKERS = re.compile(r"privacy|proxy|redact|withheld|anonymi[sz]")
#: Registrar boilerplate desks — dropped unless on the target domain itself.
_REGISTRAR_LOCALPARTS = frozenset({"abuse", "noc", "hostmaster", "domains", "domain", "whois"})


@dataclass
class WhoisEmail:
    email: str
    roles: list[str] = field(default_factory=list)


@dataclass
class NetlasWhoisResult:
    """Outcome of one WHOIS lookup: kept emails, org, and what was dropped."""

    emails: list[WhoisEmail] = field(default_factory=list)
    organization: str | None = None
    #: ``(email, reason)`` for every contact address filtered as junk.
    dropped: list[tuple[str, str]] = field(default_factory=list)
    status: str = STATUS_EMPTY
    calls: int = 0
    error: str | None = None
    record: dict[str, Any] | None = None


def _domain_and_parents(domain: str) -> list[str]:
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def _registrar_domains(record: dict[str, Any]) -> set[str]:
    registrar = record.get("registrar")
    out: set[str] = set()
    if not isinstance(registrar, dict):
        return out
    email = str(registrar.get("email") or "").strip().lower()
    if "@" in email:
        out.add(email.rsplit("@", 1)[1])
    url = str(registrar.get("referral_url") or registrar.get("url") or "").strip().lower()
    host = re.sub(r"^[a-z]+://", "", url).split("/", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    if "." in host:
        out.add(host)
    return out


def whois_junk_reason(
    email: str, domain: str, *, registrar_domains: set[str] | frozenset[str] = frozenset()
) -> str | None:
    """Why *email* is privacy-proxy / registrar boilerplate (``None`` = keep).

    Addresses on the target *domain* itself are only dropped for explicit
    redaction tokens — a real ``abuse@target`` or ``privacy@target`` is a
    genuine role mailbox, not registrar noise.
    """
    from .disposable_domains import is_disposable_domain

    value = str(email or "").strip().lower()
    if not _EMAIL_RE.match(value):
        return "not_an_email"
    local, host = value.rsplit("@", 1)
    on_target = host == domain or host.endswith("." + domain)
    if _REDACTION_RE.search(local):
        return "redacted"
    if on_target:
        return None
    if any(parent in WHOIS_PROXY_DOMAINS for parent in _domain_and_parents(host)):
        return "privacy_proxy"
    if _OFF_TARGET_DOMAIN_MARKERS.search(host):
        return "privacy_proxy"
    if any(parent in registrar_domains for parent in _domain_and_parents(host)):
        return "registrar"
    if local in _REGISTRAR_LOCALPARTS:
        return "registrar"
    if is_disposable_domain(host):
        return "disposable"
    return None


def extract_whois_contacts(record: dict[str, Any] | None, domain: str) -> NetlasWhoisResult:
    """Pull contact emails + registrant org from a parsed Netlas WHOIS record.

    Field paths (confirmed against ``/api/mapping/whois_domains/``):
    ``{registrant,administrative,technical,billing}.email`` and
    ``registrant.organization``. Emails are lowercased, deduped (roles merged)
    and junk-filtered; the org name is metadata only, never a lead.
    """
    result = NetlasWhoisResult(record=record)
    if not isinstance(record, dict):
        return result
    domain = str(domain or "").strip().lower()
    registrars = _registrar_domains(record)
    kept: dict[str, WhoisEmail] = {}
    dropped: dict[str, str] = {}
    for role in WHOIS_CONTACT_ROLES:
        block = record.get(role)
        if not isinstance(block, dict):
            continue
        raw = block.get("email")
        values = raw if isinstance(raw, list) else [raw]
        for value in values:
            email = str(value or "").strip().lower().strip("<>").rstrip(".")
            if not email:
                continue
            reason = whois_junk_reason(email, domain, registrar_domains=registrars)
            if reason:
                dropped.setdefault(email, reason)
                continue
            kept.setdefault(email, WhoisEmail(email=email)).roles.append(role)
    result.emails = list(kept.values())
    result.dropped = sorted(dropped.items())
    registrant = record.get("registrant")
    org = registrant.get("organization") if isinstance(registrant, dict) else None
    org = " ".join(str(org or "").split())
    if org and not _REDACTION_RE.search(org.lower()) and "privacy" not in org.lower():
        result.organization = org
    return result


def _pick_record(payload: Any, domain: str) -> dict[str, Any] | None:
    """The newest WHOIS record for exactly *domain* from a search payload."""
    items = payload.get("items") if isinstance(payload, dict) else None
    records = [
        item.get("data")
        for item in items or []
        if isinstance(item, dict) and isinstance(item.get("data"), dict)
    ]
    exact = [
        r for r in records
        if str(r.get("domain") or r.get("extracted_domain") or "").lower() == domain
    ]
    pool = exact or records
    if not pool:
        return None
    return max(pool, key=lambda r: str(r.get("@timestamp") or r.get("last_updated") or ""))


async def fetch_whois(domain: str, key: str | None) -> NetlasWhoisResult:
    """One ``whois_domains`` search for the apex *domain*; never raises."""
    domain = str(domain or "").strip().lower().rstrip(".")
    probe = NetlasWhoisResult()
    key = str(key or "").strip()
    if not domain or "." not in domain or not key:
        probe.status = STATUS_INACTIVE
        return probe
    latched = _latched_status()
    if latched:
        probe.status = latched
        probe.error = "latched from an earlier response"
        return probe
    try:
        async with httpx.AsyncClient(timeout=_timeout(), follow_redirects=False) as client:
            payload = await _get_json(
                client,
                _WHOIS_DOMAINS_URL,
                {"q": f"domain:{domain}"},
                key,
                probe,
                "whois_domains",
            )
    except httpx.TimeoutException:
        probe.status, probe.error = STATUS_ERROR, "timeout"
        _LOG.warning("Netlas WHOIS timed out for %s", domain)
        return probe
    except Exception as exc:  # noqa: BLE001 - never raise into the harvest
        probe.status, probe.error = STATUS_ERROR, str(exc) or exc.__class__.__name__
        _LOG.warning("Netlas WHOIS failed for %s: %s", domain, exc)
        return probe
    if payload is None:
        _LOG.warning("Netlas WHOIS failed for %s: %s", domain, probe.error)
        return probe
    result = extract_whois_contacts(_pick_record(payload, domain), domain)
    result.calls = probe.calls
    result.status = STATUS_OK if result.record is not None else STATUS_EMPTY
    return result


# ---------------------------------------------------------------------------
# F3 — certificate emails + SAN hostnames (exactly one cert request per run).
# ---------------------------------------------------------------------------

_CERTS_DOWNLOAD_URL = f"{NETLAS_BASE_URL}/api/certs/download/"

#: Certificates are Netlas' tight lane (3 req/min): honour a Retry-After up to
#: a full rate window instead of the 10s used for the 60/min endpoints.
_CERT_MAX_RETRY_AFTER_SECONDS = 65.0

#: Leaf-certificate fields (confirmed against ``/api/mapping/certs/``). The
#: issuer's ``email_address`` is the CA's own, so it is never requested.
CERT_FIELDS = (
    "certificate.names",
    "certificate.subject.email_address",
    "certificate.extensions.subject_alt_name.dns_names",
    "certificate.extensions.subject_alt_name.email_addresses",
    "certificate.extensions.subject_alt_name.directory_names.email_address",
    "certificate.validity.end",
    "last_updated",
)

#: Names that mark a shared / multi-tenant certificate (CDN or hosting
#: platform). Their other SANs are unrelated customers, not sister domains.
_SHARED_CERT_MARKERS = (
    "cloudflaressl.com",
    "cloudflare-dns.com",
    "fastly.net",
    "edgekey.net",
    "akamaiedge.net",
    "incapsula.com",
    "sucuri.net",
    "kinsta.cloud",
    "wpengine.com",
    "herokuapp.com",
    "azurewebsites.net",
    "cloudfront.net",
    "netlify.app",
    "vercel.app",
    "github.io",
    "shopify.com",
    "myshopify.com",
    "squarespace.com",
    "wixsite.com",
)
#: More distinct other registrable domains than this on one cert → shared.
SHARED_CERT_DOMAIN_LIMIT = 20
#: Cap on recorded sister-domain seeds (F5 decides what to do with them).
RELATED_SEED_LIMIT = 50

#: Certificate-authority domains — boilerplate, never a target contact.
CA_EMAIL_DOMAINS = frozenset(
    {
        "digicert.com", "sectigo.com", "comodo.com", "comodoca.com", "letsencrypt.org",
        "globalsign.com", "godaddy.com", "entrust.net", "entrust.com", "geotrust.com",
        "thawte.com", "rapidssl.com", "verisign.com", "symantec.com", "identrust.com",
        "buypass.no", "certum.pl", "ssl.com", "zerossl.com", "trustwave.com",
        "actalis.it", "harica.gr", "swisssign.com", "quovadisglobal.com",
    }
)
_CERT_BOILERPLATE_LOCALPARTS = frozenset(
    {"ssl", "certs", "certificates", "certadmin", "pki", "webmaster", "postmaster"}
)


@dataclass
class CertEmail:
    email: str
    fields: list[str] = field(default_factory=list)
    certs: int = 0
    last_seen: str | None = None


@dataclass
class NetlasCertResult:
    """Outcome of the one certificate download for a run."""

    emails: list[CertEmail] = field(default_factory=list)
    #: SAN / CN hostnames that are real subdomains of the target.
    in_scope_hosts: list[str] = field(default_factory=list)
    #: Sister registrable domains → number of (non-shared) certs co-listing them.
    related_domains: dict[str, int] = field(default_factory=dict)
    dropped: list[tuple[str, str]] = field(default_factory=list)
    docs: int = 0
    doc_cap: int = 0
    #: True when the download returned ``doc_cap`` documents (likely truncated).
    capped: bool = False
    shared_certs: int = 0
    status: str = STATUS_EMPTY
    calls: int = 0
    error: str | None = None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def _dig(record: Any, *path: str) -> Any:
    node = record
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def cert_junk_reason(email: str, domain: str) -> str | None:
    """WHOIS junk rules plus CA boilerplate (``None`` = keep)."""
    reason = whois_junk_reason(email, domain)
    if reason:
        return reason
    local, host = email.rsplit("@", 1)
    if host == domain or host.endswith("." + domain):
        return None
    if any(parent in CA_EMAIL_DOMAINS for parent in _domain_and_parents(host)):
        return "certificate_authority"
    if local in _CERT_BOILERPLATE_LOCALPARTS:
        return "boilerplate"
    return None


def _is_hostname(name: str) -> bool:
    """A DNS name, not an IP address (certs often list IP SANs: ``10.0.0.1``)."""
    import ipaddress

    value = name.strip().lstrip("*.").strip("[]")
    if not value or "." not in value:
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    return value.rsplit(".", 1)[-1].isalpha()


def _is_shared_cert(names: list[str], domain: str) -> bool:
    from .company_discovery import _registrable_domain

    lowered = [n.lower().lstrip("*.") for n in names]
    if any(n == m or n.endswith("." + m) for n in lowered for m in _SHARED_CERT_MARKERS):
        return True
    others = {_registrable_domain(n) for n in lowered if n} - {domain}
    return len(others) > SHARED_CERT_DOMAIN_LIMIT


def extract_cert_intel(records: list[Any], domain: str, *, doc_cap: int = 0) -> NetlasCertResult:
    """Emails, in-scope SAN hosts and sister-domain seeds from cert documents.

    * Emails: subject ``emailAddress`` + rfc822Name SANs (+ SAN directory-name
      emails), junk-filtered (WHOIS rules + CA boilerplate).
    * Hosts: dNSName SANs / CN that are subdomains of *domain* (wildcards
      collapse to their base: ``*.eng.x.com`` → ``eng.x.com``).
    * Sister domains: other registrable domains on the same cert — recorded as
      F5 seeds only, and never from shared CDN / multi-tenant certificates.
    """
    from .company_discovery import _registrable_domain

    domain = str(domain or "").strip().lower()
    result = NetlasCertResult(docs=len(records), doc_cap=doc_cap)
    result.capped = bool(doc_cap) and len(records) >= doc_cap
    emails: dict[str, CertEmail] = {}
    dropped: dict[str, str] = {}
    hosts: dict[str, None] = {}
    related: dict[str, int] = {}
    for item in records:
        data = item.get("data") if isinstance(item, dict) else None
        if not isinstance(data, dict):
            continue
        cert = data.get("certificate") if isinstance(data.get("certificate"), dict) else {}
        san = _dig(cert, "extensions", "subject_alt_name") or {}
        names = _as_list(cert.get("names")) + _as_list(_dig(san, "dns_names"))
        lowered = {
            n.strip().lower().rstrip(".") for n in names if n and n.strip() and _is_hostname(n)
        }
        # Only documents that really carry the target (full-text search is loose).
        if not any(n.lstrip("*.") == domain or n.endswith("." + domain) for n in lowered):
            continue
        seen = str(data.get("last_updated") or _dig(cert, "validity", "end") or "") or None
        for name in lowered:
            host = _normalize_host(name, domain)
            if host:
                hosts.setdefault(host, None)
        if _is_shared_cert(sorted(lowered), domain):
            result.shared_certs += 1
        else:
            for other in {_registrable_domain(n.lstrip("*.")) for n in lowered} - {domain, ""}:
                if "." in other:
                    related[other] = related.get(other, 0) + 1
        sources = (
            ("subject.email_address", _as_list(_dig(cert, "subject", "email_address"))),
            ("san.email_addresses", _as_list(_dig(san, "email_addresses"))),
            ("san.directory_names.email_address",
             [e for d in (_dig(san, "directory_names") or []) if isinstance(d, dict)
              for e in _as_list(d.get("email_address"))]),
        )
        for field_name, values in sources:
            for value in values:
                email = value.strip().lower().strip("<>").rstrip(".")
                if not email:
                    continue
                reason = cert_junk_reason(email, domain)
                if reason:
                    dropped.setdefault(email, reason)
                    continue
                entry = emails.setdefault(email, CertEmail(email=email))
                if field_name not in entry.fields:
                    entry.fields.append(field_name)
                entry.certs += 1
                if seen and (entry.last_seen is None or seen > entry.last_seen):
                    entry.last_seen = seen
    result.emails = list(emails.values())
    result.in_scope_hosts = list(hosts)
    result.related_domains = dict(
        sorted(related.items(), key=lambda kv: (-kv[1], kv[0]))[:RELATED_SEED_LIMIT]
    )
    result.dropped = sorted(dropped.items())
    return result


def _cert_query(domain: str) -> str:
    # Full-text on ``certificate.names`` hits the index directly; a leading
    # wildcard (``*.domain``) makes Netlas time out (HTTP 504 after 90s, live).
    return f'certificate.names:"{domain}"'


async def fetch_certificates(
    domain: str, key: str | None, *, doc_cap: int | None = None
) -> NetlasCertResult:
    """Exactly one ``certs/download`` request for the apex *domain*; never raises."""
    domain = str(domain or "").strip().lower().rstrip(".")
    cap = int(doc_cap if doc_cap is not None else getattr(settings, "netlas_cert_doc_cap", 1000))
    probe = NetlasCertResult(doc_cap=max(0, cap))
    key = str(key or "").strip()
    if not domain or "." not in domain or not key or cap <= 0:
        probe.status = STATUS_INACTIVE
        return probe
    latched = _latched_status()
    if latched:
        probe.status, probe.error = latched, "latched from an earlier response"
        return probe
    timeout = max(1.0, float(getattr(settings, "netlas_cert_timeout_seconds", 150.0) or 150.0))
    payload = {
        "q": _cert_query(domain),
        "fields": list(CERT_FIELDS),
        "source_type": "include",
        "size": cap,
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            records = await _post_download(
                client,
                _CERTS_DOWNLOAD_URL,
                payload,
                key,
                probe,
                "certs/download",
                max_retry_after=_CERT_MAX_RETRY_AFTER_SECONDS,
            )
    except httpx.TimeoutException:
        probe.status, probe.error = STATUS_ERROR, "timeout"
        _LOG.warning("Netlas certificate download timed out for %s", domain)
        return probe
    except Exception as exc:  # noqa: BLE001 - never raise into the harvest
        probe.status, probe.error = STATUS_ERROR, str(exc) or exc.__class__.__name__
        _LOG.warning("Netlas certificate download failed for %s: %s", domain, exc)
        return probe
    if records is None:
        _LOG.warning("Netlas certificate download failed for %s: %s", domain, probe.error)
        return probe
    result = extract_cert_intel(records, domain, doc_cap=cap)
    result.calls = probe.calls
    result.status = STATUS_OK if result.docs else STATUS_EMPTY
    if result.capped:
        _LOG.warning(
            "Netlas: %s returned %d certificate documents (doc cap); SAN/email "
            "extraction is bounded to them (raise NETLAS_CERT_DOC_CAP to widen).",
            domain, result.docs,
        )
    return result


async def certificates(
    domain: str, key: str | None, *, doc_cap: int
) -> dict[str, Any] | None:
    """Summary of the cert intel for *domain* (``None`` on any failure)."""
    outcome = await fetch_certificates(domain, key, doc_cap=doc_cap)
    if outcome.status not in (STATUS_OK, STATUS_EMPTY):
        return None
    return {
        "emails": [e.email for e in outcome.emails],
        "in_scope_hosts": list(outcome.in_scope_hosts),
        "related_domains": dict(outcome.related_domains),
        "docs": outcome.docs,
        "capped": outcome.capped,
        "shared_certs": outcome.shared_certs,
    }


# ---------------------------------------------------------------------------
# F4 — emails from indexed HTTP responses + FTP banners (1 count + 1 download).
# ---------------------------------------------------------------------------

_RESPONSES_COUNT_URL = f"{NETLAS_BASE_URL}/api/responses_count/"
_RESPONSES_DOWNLOAD_URL = f"{NETLAS_BASE_URL}/api/responses/download/"

#: Projection (confirmed against ``/api/mapping/responses/``). Netlas already
#: extracts page/banner emails into ``*.contacts.email``, so no response body
#: is ever downloaded — only the short FTP banner, as a backup.
RESPONSE_FIELDS = (
    "host",
    "uri",
    "port",
    "protocol",
    "http.contacts.email",
    "ftp.contacts.email",
    "ftp.banner",
    "last_updated",
    "@timestamp",
)

SOURCE_RESPONSE = "response"
SOURCE_FTP_BANNER = "ftp_banner"
#: URLs remembered per email (the first one is the lead's ``source_url``).
_MAX_URLS_PER_EMAIL = 10


@dataclass
class ResponseEmail:
    email: str
    source: str  # "response" | "ftp_banner"
    source_url: str
    urls: list[str] = field(default_factory=list)
    on_target_host: bool = True
    last_seen: str | None = None


@dataclass
class NetlasResponseResult:
    """Outcome of the one domain-wide response query for a run."""

    emails: list[ResponseEmail] = field(default_factory=list)
    dropped: list[tuple[str, str]] = field(default_factory=list)
    #: Netlas' count of matching documents (``None`` when the count failed).
    total: int | None = None
    docs: int = 0
    resp_cap: int = 0
    capped: bool = False
    status: str = STATUS_EMPTY
    calls: int = 0
    error: str | None = None


def _response_query(domain: str) -> str:
    """ONE domain-wide query: the target's own hosts that carry extracted
    emails, plus any indexed page/banner publishing an ``@domain`` address.

    ``target.domain`` is a wildcard-type field, so ``*.domain`` is cheap here
    (unlike the certificate index).
    """
    on_hosts = f"(target.domain:*.{domain} OR target.domain:{domain})"
    has_email = "(http.contacts.email:* OR ftp.contacts.email:*)"
    return (
        f"({on_hosts} AND {has_email})"
        f" OR http.contacts.email:*@{domain} OR ftp.contacts.email:*@{domain}"
    )


def _clean_mention(value: str) -> str | None:
    """Validate one mention with the native extractor (placeholders, asset
    false positives like ``logo@2x.png``, garbage) — ``None`` = junk."""
    from .email_extraction import extract_emails

    found = extract_emails(str(value or ""))
    return found[0].email.lower() if found else None


def extract_response_emails(records: list[Any], domain: str) -> NetlasResponseResult:
    """Emails (with source URLs) from Netlas response documents.

    Pages on the target's own hosts contribute every valid email (off-domain
    ones are kept-but-tagged); pages elsewhere contribute only ``@domain``
    addresses — their other addresses are someone else's contacts.
    """
    domain = str(domain or "").strip().lower()
    result = NetlasResponseResult(docs=len(records))
    kept: dict[tuple[str, str], ResponseEmail] = {}
    dropped: dict[str, str] = {}
    for item in records:
        data = item.get("data") if isinstance(item, dict) else None
        if not isinstance(data, dict):
            continue
        host = str(data.get("host") or "").strip().lower().rstrip(".")
        protocol = str(data.get("protocol") or "").lower()
        port = data.get("port")
        uri = str(data.get("uri") or "").strip()
        if not uri and host:
            scheme = protocol or "http"
            uri = f"{scheme}://{host}" + (f":{port}" if port else "") + "/"
        on_host = host == domain or host.endswith("." + domain)
        is_ftp = protocol == "ftp" or isinstance(data.get("ftp"), dict)
        source = SOURCE_FTP_BANNER if is_ftp else SOURCE_RESPONSE
        seen = str(data.get("last_updated") or data.get("@timestamp") or "") or None
        raw: list[str] = []
        raw += _as_list(_dig(data, "http", "contacts", "email"))
        raw += _as_list(_dig(data, "ftp", "contacts", "email"))
        banner = _dig(data, "ftp", "banner")
        if isinstance(banner, str) and banner:
            from .email_extraction import extract_emails

            raw += [e.email for e in extract_emails(banner)]
        for value in raw:
            email = _clean_mention(value)
            if not email:
                dropped.setdefault(str(value).strip().lower(), "invalid_or_placeholder")
                continue
            mail_host = email.rsplit("@", 1)[1]
            on_domain = mail_host == domain or mail_host.endswith("." + domain)
            if not on_host and not on_domain:
                continue  # third-party page: not our contact, not junk either
            reason = whois_junk_reason(email, domain)
            if reason:
                dropped.setdefault(email, reason)
                continue
            entry = kept.get((email, source))
            if entry is None:
                entry = kept[(email, source)] = ResponseEmail(
                    email=email, source=source, source_url=uri, on_target_host=on_host
                )
            if uri and uri not in entry.urls and len(entry.urls) < _MAX_URLS_PER_EMAIL:
                entry.urls.append(uri)
            entry.on_target_host = entry.on_target_host or on_host
            if seen and (entry.last_seen is None or seen > entry.last_seen):
                entry.last_seen = seen
    result.emails = list(kept.values())
    result.dropped = sorted(dropped.items())
    return result


async def fetch_response_emails(
    domain: str, key: str | None, *, resp_cap: int | None = None
) -> NetlasResponseResult:
    """1 ``responses_count`` + at most 1 bounded ``responses/download``; never raises."""
    domain = str(domain or "").strip().lower().rstrip(".")
    cap = int(resp_cap if resp_cap is not None else getattr(settings, "netlas_resp_cap", 2000))
    result = NetlasResponseResult(resp_cap=max(0, cap))
    key = str(key or "").strip()
    if not domain or "." not in domain or not key or cap <= 0:
        result.status = STATUS_INACTIVE
        return result
    latched = _latched_status()
    if latched:
        result.status, result.error = latched, "latched from an earlier response"
        return result
    query = _response_query(domain)
    try:
        async with httpx.AsyncClient(timeout=_timeout(), follow_redirects=False) as client:
            payload = await _get_json(
                client, _RESPONSES_COUNT_URL, {"q": query}, key, result, "responses_count"
            )
            if payload is None:
                _LOG.warning("Netlas response count failed for %s: %s", domain, result.error)
                return result
            try:
                total = max(0, int(payload.get("count") or 0))
            except Exception:  # noqa: BLE001
                result.status, result.error = STATUS_ERROR, "responses_count unparseable"
                return result
            result.total = total
            if total == 0:
                result.status = STATUS_EMPTY
                return result
            result.capped = total > cap
            records = await _post_download(
                client,
                _RESPONSES_DOWNLOAD_URL,
                {
                    "q": query,
                    "fields": list(RESPONSE_FIELDS),
                    "source_type": "include",
                    "size": min(total, cap),
                },
                key,
                result,
                "responses/download",
            )
    except httpx.TimeoutException:
        result.status, result.error = STATUS_ERROR, "timeout"
        _LOG.warning("Netlas response download timed out for %s", domain)
        return result
    except Exception as exc:  # noqa: BLE001 - never raise into the harvest
        result.status, result.error = STATUS_ERROR, str(exc) or exc.__class__.__name__
        _LOG.warning("Netlas response download failed for %s: %s", domain, exc)
        return result
    if records is None:
        _LOG.warning("Netlas response download failed for %s: %s", domain, result.error)
        return result
    extracted = extract_response_emails(records[: cap], domain)
    extracted.total, extracted.resp_cap, extracted.capped = total, cap, result.capped
    extracted.calls = result.calls
    extracted.status = STATUS_OK if extracted.docs else STATUS_EMPTY
    if result.capped:
        _LOG.warning(
            "Netlas: %s has %d matching responses; scanned the first %d "
            "(raise NETLAS_RESP_CAP to widen).", domain, total, cap,
        )
    return extracted


async def response_emails(
    domain: str, key: str | None, *, resp_cap: int
) -> list[dict[str, Any]] | None:
    """``[{email, source_url, protocol}]`` for *domain* (``None`` on any failure)."""
    outcome = await fetch_response_emails(domain, key, resp_cap=resp_cap)
    if outcome.status not in (STATUS_OK, STATUS_EMPTY):
        return None
    return [
        {"email": e.email, "source_url": e.source_url, "protocol": e.source}
        for e in outcome.emails
    ]


# ---------------------------------------------------------------------------
# F5 — related-domain discovery (pivots off the org / infrastructure).
# ---------------------------------------------------------------------------

_DOMAINS_SEARCH_DOWNLOAD_URL = f"{NETLAS_BASE_URL}/api/domains/download/"
_WHOIS_DOWNLOAD_URL = f"{NETLAS_BASE_URL}/api/whois_domains/download/"
_RESPONSES_DOWNLOAD_URL_F5 = _RESPONSES_DOWNLOAD_URL

#: Pivot strengths (higher = stronger evidence the domain is the same org).
PIVOT_STRENGTH = {
    "whois_org": 3,
    "analytics_google": 3,
    "analytics_facebook": 3,
    "cert_san": 3,
    "shared_mx": 2,
    "shared_ns": 2,
}

#: A pivot value matching more than this many domains is shared infrastructure
#: (a cloud NS, a provider MX), not an org signal — skip it.
_PIVOT_MAX_MATCHES = 400
#: How many distinct values of a volume-prone pivot (NS / MX / tracker) to try.
_PIVOT_VALUE_LIMIT = 2

#: Shared DNS / mail / tracking infrastructure — a value whose registrable
#: domain is here is multi-tenant, so pivoting on it finds other tenants, not
#: the same org. (NS/MX also get the _PIVOT_MAX_MATCHES count guard as a net.)
_SHARED_INFRA_DOMAINS = frozenset(
    {
        # DNS
        "azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info",
        "awsdns-01.com", "awsdns-01.net", "awsdns-01.org", "awsdns-01.co.uk",
        "cloudflare.com", "cloudflare.net", "ns.cloudflare.com", "googledomains.com",
        "google.com", "domaincontrol.com", "registrar-servers.com", "dnsmadeeasy.com",
        "nsone.net", "ultradns.com", "ultradns.net", "ultradns.org", "ultradns.info",
        "dns.he.net", "name-services.com", "worldnic.com", "dreamhost.com",
        "wordpress.com", "wpengine.com", "squarespacedns.com", "shopify.com",
        "akam.net", "akamai.net", "edgekey.net", "fastly.net", "gandi.net",
        "ovh.net", "hostgator.com", "bluehost.com", "godaddy.com", "1and1.com",
        "ionos.com", "digitalocean.com", "linode.com", "vultr.com", "qwest.net",
        # Mail
        "outlook.com", "protection.outlook.com", "mail.protection.outlook.com",
        "google.com.", "googlemail.com", "l.google.com", "aspmx.l.google.com",
        "pphosted.com", "mimecast.com", "messagelabs.com", "proofpoint.com",
        "barracudanetworks.com", "mailgun.org", "sendgrid.net", "zoho.com",
        "secureserver.net", "emailsrvr.com", "fireeyecloud.com", "mxrecord.io",
    }
)


def _is_shared_infra(host: str) -> bool:
    host = str(host or "").strip().lower().rstrip(".")
    if not host:
        return True
    parents = _domain_and_parents(host)
    return any(p in _SHARED_INFRA_DOMAINS for p in parents)


@dataclass
class RelatedDomain:
    domain: str
    score: int = 0
    #: Each pivot that matched this domain → its evidence detail.
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class NetlasRelatedResult:
    """Ranked related domains plus per-pivot telemetry."""

    related: list[RelatedDomain] = field(default_factory=list)
    pivots: dict[str, dict[str, Any]] = field(default_factory=dict)
    cap: int = 0
    status: str = STATUS_EMPTY
    calls: int = 0
    error: str | None = None


def _dedupe_candidate(host: str, target: str) -> str | None:
    """A pivot hit, reduced to a registrable domain that is not the target."""
    from .company_discovery import _registrable_domain

    reg = _registrable_domain(str(host or "").strip().lower().lstrip("*.").rstrip("."))
    if not reg or "." not in reg or reg == target or reg.endswith("." + target):
        return None
    return reg


async def _domains_field(
    client: httpx.AsyncClient, domain: str, key: str, result: Any
) -> dict[str, Any]:
    """The target's own ``domains`` row (ns / mx), best-effort."""
    records = await _post_download(
        client,
        _DOMAINS_SEARCH_DOWNLOAD_URL,
        {"q": f"domain:{domain}", "fields": ["domain", "ns", "mx"],
         "source_type": "include", "size": 1},
        key, result, "domains(self)",
    )
    for item in records or []:
        data = item.get("data") if isinstance(item, dict) else None
        if isinstance(data, dict) and str(data.get("domain", "")).lower() == domain:
            return data
    return (records[0].get("data") if records and isinstance(records[0], dict) else {}) or {}


async def _self_trackers(
    client: httpx.AsyncClient, domain: str, key: str, result: Any
) -> dict[str, list[str]]:
    """The target's own analytics / pixel tracker IDs, best-effort."""
    records = await _post_download(
        client,
        _RESPONSES_DOWNLOAD_URL_F5,
        {"q": f"(target.domain:*.{domain} OR target.domain:{domain}) AND "
              f"(http.tracker.google_analytics:* OR http.tracker.facebook_pixel:*)",
         "fields": ["http.tracker.google_analytics", "http.tracker.facebook_pixel"],
         "source_type": "include", "size": 20},
        key, result, "responses(self-trackers)",
    )
    ga: dict[str, None] = {}
    fb: dict[str, None] = {}
    for item in records or []:
        tr = _dig(item.get("data") if isinstance(item, dict) else None, "http", "tracker") or {}
        for v in _as_list(tr.get("google_analytics")):
            ga.setdefault(v, None)
        for v in _as_list(tr.get("facebook_pixel")):
            fb.setdefault(v, None)
    return {"google": list(ga), "facebook": list(fb)}


async def _run_pivot(
    client: httpx.AsyncClient,
    key: str,
    result: NetlasRelatedResult,
    *,
    pivot: str,
    index: str,
    query: str,
    field_path: tuple[str, ...],
    cap: int,
    detail: dict[str, Any],
    count_guard: bool,
) -> list[str]:
    """One pivot query → registrable domains. Count-guarded when asked."""
    count_url = f"{NETLAS_BASE_URL}/api/{index}_count/"
    download_url = f"{NETLAS_BASE_URL}/api/{index}/download/"
    if count_guard:
        payload = await _get_json(client, count_url, {"q": query}, key, result, f"{pivot} count")
        if payload is None:
            return []
        try:
            total = int(payload.get("count") or 0)
        except (TypeError, ValueError):
            total = 0
        result.pivots.setdefault(pivot, {}).setdefault("matches", 0)
        result.pivots[pivot]["matches"] += total
        if total == 0 or total > _PIVOT_MAX_MATCHES:
            result.pivots[pivot].setdefault("skipped", []).append(
                {**detail, "matches": total, "reason": "too_broad" if total else "no_match"}
            )
            return []
    records = await _post_download(
        client, download_url,
        {"q": query, "fields": list(field_path[:1]) or ["domain"],
         "source_type": "include", "size": cap},
        key, result, f"{pivot} download",
    )
    hosts: list[str] = []
    for item in records or []:
        data = item.get("data") if isinstance(item, dict) else None
        value = _dig(data, *field_path) if isinstance(data, dict) else None
        for host in _as_list(value):
            hosts.append(host)
    return hosts


async def fetch_related_domains(
    domain: str,
    key: str | None,
    *,
    seeds: dict[str, Any] | None = None,
    cap: int | None = None,
) -> NetlasRelatedResult:
    """Discover the org's other domains via WHOIS-org / NS / MX / analytics
    pivots plus the F3 sister-SAN seeds. Bounded; never raises; never harvests.
    """
    domain = str(domain or "").strip().lower().rstrip(".")
    seeds = seeds or {}
    limit = int(cap if cap is not None else getattr(settings, "netlas_related_cap", 50))
    result = NetlasRelatedResult(cap=max(0, limit))
    key = str(key or "").strip()
    if not domain or "." not in domain or not key or limit <= 0:
        result.status = STATUS_INACTIVE
        return result
    latched = _latched_status()
    if latched:
        result.status, result.error = latched, "latched from an earlier response"
        return result

    candidates: dict[str, RelatedDomain] = {}

    def _add(host: str, pivot: str, detail: dict[str, Any]) -> None:
        reg = _dedupe_candidate(host, domain)
        if not reg:
            return
        entry = candidates.get(reg)
        if entry is None:
            entry = candidates[reg] = RelatedDomain(domain=reg)
        if not any(e.get("pivot") == pivot for e in entry.evidence):
            entry.evidence.append({"pivot": pivot, **detail})
            entry.score += PIVOT_STRENGTH.get(pivot, 1)

    # Seed pivot (0 calls): F3 sister-domain SANs already in hand.
    for seed in seeds.get("cert_sans") or []:
        sd = seed.get("domain") if isinstance(seed, dict) else seed
        _add(str(sd or ""), "cert_san", {"certs": seed.get("certs") if isinstance(seed, dict) else None})

    try:
        async with httpx.AsyncClient(timeout=_timeout(), follow_redirects=False) as client:
            # WHOIS org pivot (F2 seed). Exact phrase on the analyzed field, then
            # verify each hit's org equals the seed before trusting it.
            org = " ".join(str(seeds.get("org") or "").split())
            if org and len(org) >= 3 and "privacy" not in org.lower():
                records = await _post_download(
                    client, _WHOIS_DOWNLOAD_URL,
                    {"q": f'registrant.organization:"{org}"',
                     "fields": ["domain", "registrant.organization"],
                     "source_type": "include", "size": limit},
                    key, result, "whois_org download",
                )
                matched = 0
                for item in records or []:
                    data = item.get("data") if isinstance(item, dict) else {}
                    cand_org = " ".join(str(_dig(data, "registrant", "organization") or "").split())
                    if cand_org.lower() == org.lower():
                        _add(str(data.get("domain") or ""), "whois_org", {"org": org})
                        matched += 1
                result.pivots["whois_org"] = {"org": org, "verified_matches": matched}

            # NS / MX pivots — read the target's own row, skip shared infra.
            self_row = await _domains_field(client, domain, key, result)
            for pivot, values in (("shared_ns", _as_list(self_row.get("ns"))),
                                  ("shared_mx", _as_list(self_row.get("mx")))):
                tried = 0
                for value in values:
                    if tried >= _PIVOT_VALUE_LIMIT:
                        break
                    v = value.strip().lower().rstrip(".")
                    field = "ns" if pivot == "shared_ns" else "mx"
                    if _is_shared_infra(v):
                        result.pivots.setdefault(pivot, {}).setdefault("skipped", []).append(
                            {field: v, "reason": "shared_infra"}
                        )
                        continue
                    tried += 1
                    for host in await _run_pivot(
                        client, key, result, pivot=pivot, index="domains",
                        query=f'{field}:"{v}"', field_path=("domain",), cap=limit,
                        detail={field: v}, count_guard=True,
                    ):
                        _add(host, pivot, {field: v})

            # Analytics pivots — the target's own tracker IDs → sites sharing them.
            trackers = await _self_trackers(client, domain, key, result)
            for kind, ids in (("analytics_google", trackers["google"]),
                              ("analytics_facebook", trackers["facebook"])):
                tfield = ("http.tracker.google_analytics" if kind == "analytics_google"
                          else "http.tracker.facebook_pixel")
                for tid in ids[:_PIVOT_VALUE_LIMIT]:
                    for host in await _run_pivot(
                        client, key, result, pivot=kind, index="responses",
                        query=f"{tfield}:{tid}", field_path=("target", "domain"), cap=limit,
                        detail={"tracker_id": tid}, count_guard=True,
                    ):
                        _add(host, kind, {"tracker_id": tid})
    except httpx.TimeoutException:
        result.status, result.error = STATUS_ERROR, "timeout"
        _LOG.warning("Netlas related-domain discovery timed out for %s", domain)
        return result
    except Exception as exc:  # noqa: BLE001 - never raise into the harvest
        result.status, result.error = STATUS_ERROR, str(exc) or exc.__class__.__name__
        _LOG.warning("Netlas related-domain discovery failed for %s: %s", domain, exc)
        return result

    ranked = sorted(candidates.values(), key=lambda r: (-r.score, r.domain))[:limit]
    result.related = ranked
    # A hard failure latched mid-run still returns seeds; a clean run with no
    # hits is "empty", otherwise "ok".
    latched_after = _latched_status()
    if latched_after and not ranked:
        result.status, result.error = latched_after, result.error or "latched mid-discovery"
    else:
        result.status = STATUS_OK if ranked else STATUS_EMPTY
    return result


async def related_domains(
    domain: str, key: str | None, *, seeds: dict[str, Any] | None = None, cap: int
) -> list[dict[str, Any]] | None:
    """``[{domain, score, evidence}]`` ranked (``None`` on hard failure)."""
    outcome = await fetch_related_domains(domain, key, seeds=seeds, cap=cap)
    if outcome.status in FAILURE_STATUSES:
        return None
    return [
        {"domain": r.domain, "score": r.score, "evidence": r.evidence}
        for r in outcome.related
    ]


# ---------------------------------------------------------------------------
# F6 — reverse email footprint (investigate): where one address appears.
# ---------------------------------------------------------------------------

#: Per-source caps for the footprint (brief): responses / certs / whois domains.
FOOTPRINT_RESPONSE_CAP = 100
FOOTPRINT_CERT_CAP = 50
FOOTPRINT_WHOIS_CAP = 50


@dataclass
class FootprintResponse:
    source_url: str
    protocol: str


@dataclass
class FootprintCert:
    names: list[str]
    last_seen: str | None = None


@dataclass
class FootprintWhoisDomain:
    domain: str
    roles: list[str] = field(default_factory=list)


@dataclass
class NetlasFootprintResult:
    """Where one exact address appears: responses, certs, reverse-WHOIS."""

    responses: list[FootprintResponse] = field(default_factory=list)
    certs: list[FootprintCert] = field(default_factory=list)
    whois_domains: list[FootprintWhoisDomain] = field(default_factory=list)
    #: Per-source status so the caller can note partial degradations.
    statuses: dict[str, str] = field(default_factory=dict)
    calls: int = 0
    #: True when a source returned exactly its cap (more may exist).
    capped: dict[str, bool] = field(default_factory=dict)
    error: str | None = None
    #: Scratch slot written by ``_post_download`` on a non-200; read back into
    #: ``statuses[name]`` per source. Never the aggregate (use ``overall_status``).
    status: str = ""
    #: Sources cut short by the internal deadline (partial, not failed).
    truncated: list[str] = field(default_factory=list)

    def overall_status(self) -> str:
        """OK if any source answered; else the first failure / truncated / empty."""
        vals = set(self.statuses.values())
        if STATUS_OK in vals:
            return STATUS_OK
        for s in (STATUS_INVALID_KEY, STATUS_QUOTA, STATUS_RATE_LIMITED,
                  STATUS_BLOCKED, STATUS_ERROR):
            if s in vals:
                return s
        if vals == {STATUS_INACTIVE}:
            return STATUS_INACTIVE
        if STATUS_TRUNCATED in vals:
            return STATUS_TRUNCATED
        return STATUS_EMPTY

    @property
    def total_appearances(self) -> int:
        return len(self.responses) + len(self.certs) + len(self.whois_domains)


async def fetch_email_footprint(email: str, key: str | None) -> NetlasFootprintResult:
    """Exactly 3 bounded lookups (responses, certs, reverse-WHOIS) for *email*.

    Never raises. Each source is independent; a failure in one leaves the
    others intact. A latched bad-key / quota short-circuits the rest.
    """
    result = NetlasFootprintResult()
    email = str(email or "").strip().lower()
    key = str(key or "").strip()
    if not email or "@" not in email or not key:
        result.statuses = {s: STATUS_INACTIVE for s in ("responses", "certs", "whois")}
        return result

    # Escape any lucene-special chars in the address for a safe phrase query.
    def _q(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    e = _q(email)
    cert_timeout = max(1.0, float(getattr(settings, "netlas_cert_timeout_seconds", 150.0) or 150.0))
    deadline = max(
        1.0, float(getattr(settings, "netlas_footprint_deadline_seconds", 25.0) or 25.0)
    )
    t0 = time.monotonic()

    def _remaining() -> float:
        return deadline - (time.monotonic() - t0)

    async def _source(
        name: str, index: str, query: str, fields: list[str], cap: int,
        *, timeout: float, max_retry_after: float, max_budget: float | None = None,
    ) -> list[Any] | None:
        latched = _latched_status()
        if latched:
            result.statuses[name] = latched
            return None
        budget = _remaining() if max_budget is None else min(_remaining(), max_budget)
        if budget < 0.5:
            result.statuses[name] = STATUS_TRUNCATED
            result.truncated.append(name)
            return None
        # Per-source scratch: the three lookups run concurrently, so they must not
        # share ``result.status`` / ``result.error`` (``_post_download`` writes them).
        scratch = SimpleNamespace(calls=0, status="", error=None)
        t_src = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=min(timeout, budget + 1.0), follow_redirects=False
            ) as client:
                records = await asyncio.wait_for(
                    _post_download(
                        client, f"{NETLAS_BASE_URL}/api/{index}/download/",
                        {"q": query, "fields": fields, "source_type": "include", "size": cap},
                        key, scratch, f"{name} download", max_retry_after=max_retry_after,
                    ),
                    timeout=budget,
                )
        except (asyncio.TimeoutError, httpx.TimeoutException) as exc:
            # Ran out of the deadline: partial, NOT a failure.
            _LOG.warning(
                "Netlas footprint %s truncated (%s) after %.1fs of %.1fs budget",
                name, exc.__class__.__name__, time.monotonic() - t_src, budget,
            )
            result.statuses[name] = STATUS_TRUNCATED
            result.truncated.append(name)
            return None
        except Exception as exc:  # noqa: BLE001
            result.statuses[name], result.error = STATUS_ERROR, str(exc) or exc.__class__.__name__
            return None
        finally:
            result.calls += scratch.calls
        if records is None:
            result.statuses[name] = scratch.status or STATUS_ERROR
            result.error = result.error or scratch.error
            return None
        records = records[:cap]  # caps are strict
        result.statuses[name] = STATUS_OK if records else STATUS_EMPTY
        result.capped[name] = len(records) >= cap
        return records

    # Reverse-WHOIS (the strongest signal) goes first, alone: it is fast, and it
    # doubles as the key/quota canary — a latched 401/402/429 short-circuits the
    # other two. Its budget is capped so a hang can't eat the whole deadline.
    # Certs (routinely ~19s) and responses (the fan-out risk) are independent, so
    # they then run concurrently under the SAME deadline: neither can starve the
    # other, and each keeps whatever it returned.
    whois_recs = await _source(
        "whois", "whois_domains",
        f'registrant.email:"{e}" OR administrative.email:"{e}" OR technical.email:"{e}"',
        ["domain", "registrant.email", "administrative.email", "technical.email"],
        FOOTPRINT_WHOIS_CAP, timeout=_timeout(), max_retry_after=_MAX_RETRY_AFTER_SECONDS,
        max_budget=deadline * 0.4,
    )
    cert_recs, resp_recs = await asyncio.gather(
        _source(
            "certs", "certs",
            f'certificate.subject.email_address:"{e}" OR '
            f'certificate.extensions.subject_alt_name.email_addresses:"{e}"',
            ["certificate.names", "certificate.validity.end", "last_updated"],
            FOOTPRINT_CERT_CAP,
            timeout=cert_timeout, max_retry_after=_CERT_MAX_RETRY_AFTER_SECONDS,
        ),
        _source(
            "responses", "responses",
            f'http.contacts.email:"{e}" OR ftp.contacts.email:"{e}"',
            ["host", "uri", "protocol"], FOOTPRINT_RESPONSE_CAP,
            timeout=_timeout(), max_retry_after=_MAX_RETRY_AFTER_SECONDS,
        ),
    )
    result.truncated.sort(key=("whois", "certs", "responses").index)

    # 1. Reverse-WHOIS: domains where the address is a registration contact.
    recs = whois_recs
    seen_domains: dict[str, FootprintWhoisDomain] = {}
    for item in recs or []:
        data = item.get("data") if isinstance(item, dict) else None
        if not isinstance(data, dict):
            continue
        dom = str(data.get("domain") or "").strip().lower().rstrip(".")
        if not dom:
            continue
        roles = [
            role for role, path in (
                ("registrant", ("registrant", "email")),
                ("administrative", ("administrative", "email")),
                ("technical", ("technical", "email")),
            )
            if email in [str(v).strip().lower() for v in _as_list(_dig(data, *path))]
        ]
        entry = seen_domains.get(dom)
        if entry is None:
            entry = seen_domains[dom] = FootprintWhoisDomain(domain=dom)
        for r in roles:
            if r not in entry.roles:
                entry.roles.append(r)
    result.whois_domains = list(seen_domains.values())

    # 2. Certificates.
    recs = cert_recs
    for item in recs or []:
        cert = _dig(item.get("data") if isinstance(item, dict) else None, "certificate") or {}
        names = [n for n in _as_list(cert.get("names")) if n]
        seen = str(item.get("data", {}).get("last_updated")
                   or _dig(cert, "validity", "end") or "") or None
        if names:
            result.certs.append(FootprintCert(names=names, last_seen=seen))

    # 3. Responses / FTP banners (the fan-out risk).
    recs = resp_recs
    for item in recs or []:
        data = item.get("data") if isinstance(item, dict) else None
        if not isinstance(data, dict):
            continue
        host = str(data.get("host") or "").strip().lower()
        proto = str(data.get("protocol") or "").lower()
        uri = str(data.get("uri") or "").strip() or (
            f"{proto or 'http'}://{host}/" if host else ""
        )
        if uri:
            result.responses.append(FootprintResponse(source_url=uri, protocol=proto or "http"))
    return result


# ---------------------------------------------------------------------------
# F7 — org attack-surface context (investigate): posture around the domain.
# ---------------------------------------------------------------------------

#: Per-source caps for the org-surface context (brief).
ORG_SURFACE_SERVICE_CAP = 100
ORG_SURFACE_CVE_CAP = 50

#: Title / path tokens that mark an exposed login / admin / management panel.
_PANEL_TOKENS = (
    "login", "log in", "sign in", "signin", "admin", "administrator", "dashboard",
    "portal", "webmail", "owa", "roundcube", "horde", "cpanel", "plesk", "phpmyadmin",
    "adminer", "wp-admin", "wp-login", "jenkins", "grafana", "kibana", "citrix",
    "vpn", "remote access", "rdweb", "management console", "control panel",
    "gitlab", "sonarqube", "pgadmin", "manager login",
)
_PANEL_PATHS = (
    "/login", "/admin", "/wp-admin", "/wp-login", "/user/login", "/signin",
    "/dashboard", "/portal", "/webmail", "/owa", "/phpmyadmin", "/manager",
    "/jenkins", "/grafana", "/.git", "/console",
)


def _looks_like_panel(title: str, uri: str) -> str | None:
    """Return the matched panel keyword, or ``None``."""
    t = (title or "").lower()
    u = (uri or "").lower()
    for token in _PANEL_TOKENS:
        if token in t:
            return token
    for path in _PANEL_PATHS:
        if path in u:
            return path.lstrip("/")
    return None


@dataclass
class OrgPanel:
    source_url: str
    title: str
    matched: str
    port: int | None = None


@dataclass
class OrgService:
    host: str
    port: int | None
    protocol: str
    product: str | None = None


@dataclass
class OrgCve:
    name: str
    severity: str | None = None
    base_score: float | None = None
    host: str | None = None


@dataclass
class NetlasOrgSurfaceResult:
    """Org posture around a domain: subdomains, panels, services, CVEs."""

    subdomain_count: int | None = None
    #: Full subdomain list only in deep mode (F1 enumeration).
    subdomains: list[str] = field(default_factory=list)
    ports: list[dict[str, Any]] = field(default_factory=list)
    software: list[str] = field(default_factory=list)
    related_domains_count: int | None = None
    panels: list[OrgPanel] = field(default_factory=list)
    services: list[OrgService] = field(default_factory=list)
    cves: list[OrgCve] = field(default_factory=list)
    statuses: dict[str, str] = field(default_factory=dict)
    calls: int = 0
    deep: bool = False
    capped: dict[str, bool] = field(default_factory=dict)
    error: str | None = None
    status: str = ""  # scratch for _post_download / _get_json

    def overall_status(self) -> str:
        vals = set(self.statuses.values())
        if STATUS_OK in vals:
            return STATUS_OK
        for s in (STATUS_INVALID_KEY, STATUS_QUOTA, STATUS_RATE_LIMITED,
                  STATUS_BLOCKED, STATUS_ERROR):
            if s in vals:
                return s
        if vals == {STATUS_INACTIVE}:
            return STATUS_INACTIVE
        return STATUS_EMPTY


_HOST_URL = f"{NETLAS_BASE_URL}/api/host/"

ORG_SURFACE_FIELDS = (
    "host", "port", "protocol", "uri", "http.title", "http.status_code",
    "http.server", "cve.name", "cve.severity", "cve.base_score",
)


async def _org_host_posture(
    client: httpx.AsyncClient, domain: str, key: str, result: NetlasOrgSurfaceResult
) -> None:
    """GET /api/host/{domain}/ — ports / software / related-domain count."""
    result.calls += 1
    try:
        resp = await client.get(
            f"{_HOST_URL}{domain}/", headers=_headers(key), follow_redirects=True
        )
    except Exception as exc:  # noqa: BLE001
        result.statuses["host"], result.error = STATUS_ERROR, str(exc)
        return
    if resp.status_code != 200:
        result.statuses["host"] = _status_for(resp)
        return
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        result.statuses["host"] = STATUS_ERROR
        return
    if not isinstance(data, dict):
        result.statuses["host"] = STATUS_EMPTY
        return
    ports = data.get("ports")
    if isinstance(ports, list):
        result.ports = [p for p in ports if isinstance(p, (dict, int, str))][:50]
    names: dict[str, None] = {}
    for sw in data.get("software") or []:
        for tag in (sw.get("tag") if isinstance(sw, dict) else None) or []:
            name = tag.get("fullname") or tag.get("name") if isinstance(tag, dict) else None
            if name:
                names.setdefault(str(name), None)
    result.software = list(names)[:40]
    rc = data.get("related_domains_count")
    result.related_domains_count = int(rc) if isinstance(rc, (int, float)) else None
    result.statuses["host"] = STATUS_OK


async def _org_responses(
    client: httpx.AsyncClient, domain: str, key: str, result: NetlasOrgSurfaceResult
) -> None:
    """One bounded responses query → panels, services, CVEs."""
    query = f"target.domain:*.{domain} OR target.domain:{domain}"
    records = await _post_download(
        client, _RESPONSES_DOWNLOAD_URL,
        {"q": query, "fields": list(ORG_SURFACE_FIELDS), "source_type": "include",
         "size": ORG_SURFACE_SERVICE_CAP},
        key, result, "org responses",
    )
    if records is None:
        result.statuses["responses"] = result.status or STATUS_ERROR
        return
    result.statuses["responses"] = STATUS_OK if records else STATUS_EMPTY
    result.capped["responses"] = len(records) >= ORG_SURFACE_SERVICE_CAP
    seen_cve: dict[str, OrgCve] = {}
    for item in records:
        data = item.get("data") if isinstance(item, dict) else None
        if not isinstance(data, dict):
            continue
        host = str(data.get("host") or "").strip().lower()
        proto = str(data.get("protocol") or "").lower()
        port = data.get("port")
        http = data.get("http") if isinstance(data.get("http"), dict) else {}
        uri = str(data.get("uri") or "").strip() or (
            f"{proto or 'http'}://{host}" + (f":{port}" if port else "") + "/"
        )
        title = str(http.get("title") or "").strip()
        result.services.append(OrgService(
            host=host, port=port if isinstance(port, int) else None,
            protocol=proto, product=str(http.get("server") or "") or None,
        ))
        matched = _looks_like_panel(title, uri)
        if matched:
            result.panels.append(OrgPanel(
                source_url=uri, title=title, matched=matched,
                port=port if isinstance(port, int) else None,
            ))
        cve = data.get("cve")
        for c in (cve if isinstance(cve, list) else [cve] if cve else []):
            if not isinstance(c, dict):
                continue
            name = str(c.get("name") or "").strip()
            if not name or name in seen_cve:
                continue
            seen_cve[name] = OrgCve(
                name=name, severity=(str(c.get("severity")) if c.get("severity") else None),
                base_score=(float(c["base_score"]) if isinstance(c.get("base_score"), (int, float)) else None),
                host=host or None,
            )
    # Strongest CVEs first, capped.
    ranked = sorted(
        seen_cve.values(), key=lambda x: (-(x.base_score or 0.0), x.name)
    )
    result.capped["cves"] = len(ranked) > ORG_SURFACE_CVE_CAP
    result.cves = ranked[:ORG_SURFACE_CVE_CAP]
    # Subdomain count (light) — distinct hosts seen; deep mode overrides below.
    if result.subdomain_count is None:
        result.subdomain_count = len({s.host for s in result.services if s.host})


async def fetch_org_surface(
    domain: str, key: str | None, *, deep: bool = False
) -> NetlasOrgSurfaceResult:
    """Org attack-surface context for *domain*. Light = 2 calls; deep adds F1
    subdomain enumeration (≤500). Never raises.
    """
    domain = str(domain or "").strip().lower().rstrip(".")
    result = NetlasOrgSurfaceResult(deep=deep)
    key = str(key or "").strip()
    if not domain or "." not in domain or not key:
        result.statuses = {"host": STATUS_INACTIVE, "responses": STATUS_INACTIVE}
        return result
    latched = _latched_status()
    if latched:
        result.statuses = {"host": latched, "responses": latched}
        result.error = "latched from an earlier response"
        return result
    try:
        async with httpx.AsyncClient(timeout=_timeout(), follow_redirects=False) as client:
            await _org_host_posture(client, domain, key, result)
            if not _latched_status():
                await _org_responses(client, domain, key, result)
            else:
                result.statuses.setdefault("responses", _latched_status())
    except httpx.TimeoutException:
        result.statuses.setdefault("responses", STATUS_ERROR)
        result.error = "timeout"
    except Exception as exc:  # noqa: BLE001 - never raise into investigate
        result.statuses.setdefault("responses", STATUS_ERROR)
        result.error = str(exc) or exc.__class__.__name__

    if deep and not _latched_status():
        sub = await fetch_subdomains(domain, key, cap=getattr(settings, "netlas_subdomain_cap", 500))
        result.calls += sub.calls
        result.statuses["subdomains"] = sub.status
        if sub.hosts:
            result.subdomains = list(sub.hosts)
            result.subdomain_count = len(sub.hosts)
            result.capped["subdomains"] = sub.capped
    return result


# ---------------------------------------------------------------------------
# Key check (``mailaccess netlas test``) — one authenticated profile request,
# no search credits spent.
# ---------------------------------------------------------------------------

_PROFILE_URL = f"{NETLAS_BASE_URL}/api/users/current/"


@dataclass
class NetlasKeyCheck:
    status: str = STATUS_INACTIVE
    calls: int = 0
    error: str | None = None


async def check_key(key: str | None) -> NetlasKeyCheck:
    """Verify *key* against Netlas' profile endpoint; never raises."""
    check = NetlasKeyCheck()
    key = str(key or "").strip()
    if not key:
        return check
    try:
        async with httpx.AsyncClient(timeout=_timeout(), follow_redirects=False) as client:
            payload = await _get_json(client, _PROFILE_URL, {}, key, check, "users/current")
    except httpx.TimeoutException:
        check.status, check.error = STATUS_ERROR, "timeout"
        return check
    except Exception as exc:  # noqa: BLE001
        check.status, check.error = STATUS_ERROR, str(exc) or exc.__class__.__name__
        return check
    if payload is not None:
        check.status = STATUS_OK
    return check


async def whois_domain(domain: str, key: str | None) -> dict[str, Any] | None:
    """Return the parsed WHOIS record for *domain* (``None`` on any failure)."""
    return (await fetch_whois(domain, key)).record


__all__ = [
    "FAILURE_STATUSES",
    "NETLAS_SIGNUP_URL",
    "NetlasSubdomainResult",
    "NetlasCertResult",
    "NetlasResponseResult",
    "NetlasRelatedResult",
    "NetlasFootprintResult",
    "fetch_email_footprint",
    "NetlasOrgSurfaceResult",
    "fetch_org_surface",
    "set_no_netlas",
    "set_org_surface_deep",
    "org_surface_deep",
    "RelatedDomain",
    "fetch_related_domains",
    "related_domains",
    "extract_response_emails",
    "fetch_response_emails",
    "response_emails",
    "NetlasWhoisResult",
    "WhoisEmail",
    "certificates",
    "extract_cert_intel",
    "fetch_certificates",
    "extract_whois_contacts",
    "fetch_subdomains",
    "fetch_whois",
    "whois_domain",
    "whois_junk_reason",
    "netlas_active",
    "netlas_hint_message",
    "reset_netlas_state_for_tests",
    "search_subdomains",
]
