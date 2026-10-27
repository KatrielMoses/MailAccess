"""Cache-first WhoisFreaks lookups and response normalisation.

Reads are always served from ``whoisfreaks_cache``; the network is touched only
for a missing/expired page, or when the run passed ``refresh``. A page that
answers cleanly is cached on its own, so a partially paginated lookup keeps what
it got. Errors, timeouts and rate-limit skips write nothing.
"""

from __future__ import annotations

import asyncio
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import timedelta
from itertools import zip_longest
from typing import Any

from ..config import settings
from . import whoisfreaks_client as client
from .enrichment_store import (
    _now,
    load_whoisfreaks_page,
    whoisfreaks_query_key,
    write_whoisfreaks_page,
)
from .whois_filters import is_privacy_org, whois_junk_reason

_ROLES = (
    ("registrant_contact", "registrant"),
    ("administrative_contact", "admin"),
    ("technical_contact", "tech"),
)


@dataclass
class Lookup:
    """Rows from every page that answered, plus how the lookup went."""

    rows: list[dict] = field(default_factory=list)
    total: int | None = None
    pages: int = 0
    fetched: int = 0
    complete: bool = True
    from_cache: bool = False


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _rows_key(kind: str) -> str:
    return "subdomains" if kind == "subdomains" else "whois_domains_historical"


def _page_rows(kind: str, payload: dict) -> list:
    if kind == "live":  # one record, not a list
        return [payload] if payload else []
    return list(payload.get(_rows_key(kind)) or [])


def _total_pages(kind: str, payload: dict, page_rows: int) -> int | None:
    if kind == "reverse_company" or kind == "reverse_email":
        return _int(payload.get("total_Pages"))
    if kind == "subdomains":
        return _int(payload.get("total_pages"))
    total = _int(payload.get("total_records"))
    return None if total is None or not page_rows else -(-total // page_rows)


def _total_records(kind: str, payload: dict) -> int | None:
    key = "total_Result" if kind.startswith("reverse") else "total_records"
    return _int(payload.get(key))


_INFLIGHT: dict[tuple, asyncio.Task] = {}
#: Pages already bought under ``--refresh`` in the current harvest (None outside one).
_REFRESHED: ContextVar[set | None] = ContextVar("mailaccess_wf_refreshed", default=None)


def begin_refresh_scope() -> Any:
    """Start a per-run set so a ``--refresh`` buys each page once. Returns the token."""
    return _REFRESHED.set(set())


async def _fetch_and_store(
    kind: str, query: str, page: int, deadline: float | None, no_wf: bool | None
) -> client.WFResult:
    result = await getattr(client, kind)(query, page, deadline=deadline, no_whoisfreaks=no_wf)
    if result.clean:  # only data or a clean 404/403 empty is ever cached
        await write_whoisfreaks_page(kind, query, page, result.data or {}, result.status == "empty")
    return result


async def _shared_fetch(
    kind: str, query: str, page: int, deadline: float | None, no_wf: bool | None
) -> client.WFResult:
    """One network fetch per (lookup, page), shared by concurrent callers.

    The fetch runs as its own task and callers wait on it through ``shield``, so
    cancelling a caller (a timed-out ``subdomain_intel``) never cancels the fetch:
    it finishes and lands in the cache for the next reader.
    """
    ident = (id(asyncio.get_running_loop()), kind, whoisfreaks_query_key(kind, query), page)
    task = _INFLIGHT.get(ident)
    if task is None or task.done():
        task = asyncio.ensure_future(_fetch_and_store(kind, query, page, deadline, no_wf))
        _INFLIGHT[ident] = task
        task.add_done_callback(lambda _t, i=ident: _INFLIGHT.pop(i, None))
    return await asyncio.shield(task)


async def lookup(
    kind: str,
    query: str,
    *,
    max_pages: int,
    refresh: bool = False,
    deadline: float | None = None,
    no_whoisfreaks: bool | None = None,
    cache_only: bool = False,
) -> Lookup:
    """Fetch up to ``max_pages`` pages of one lookup, cache-first.

    ``cache_only`` never touches the network (and so never spends credits).
    """
    out = Lookup()
    # Off (no key, disabled, or the per-run flag) is fully off: no call, and no cached
    # answers either, so nothing from this provider reaches the run.
    if not client.whoisfreaks_active(no_whoisfreaks=no_whoisfreaks):
        out.complete = False
        return out
    ttl = timedelta(days=max(0, int(settings.whoisfreaks_refresh_ttl_days)))
    active = not cache_only
    page_size = 0
    refreshed = _REFRESHED.get()
    for page in range(1, max(1, max_pages) + 1):
        stored = await load_whoisfreaks_page(kind, query, page)
        fresh = stored is not None and _now() - stored["fetched_at"] < ttl
        page_id = (kind, whoisfreaks_query_key(kind, query), page)
        # --refresh buys a page once per run, however many steps ask for it.
        force = refresh and active and not (refreshed is not None and page_id in refreshed)
        if stored is not None and fresh and not force:
            payload, empty = stored["payload"], stored["empty"]
            out.from_cache = True
        elif active:
            result = None
            if deadline is None or time.monotonic() < deadline:
                result = await _shared_fetch(kind, query, page, deadline, no_whoisfreaks)
            if result is None or not result.clean:
                out.complete = False
                if stored is None:
                    break
                # A skipped or failed refresh must not leave a keyed run with less
                # than a keyless one: serve the copy we already hold, marked incomplete.
                payload, empty = stored["payload"], stored["empty"]
                out.from_cache = True
                out.rows.extend(
                    r for r in ([] if empty else _page_rows(kind, payload)) if isinstance(r, dict)
                )
                if page == 1:
                    out.total = _total_records(kind, payload)
                break
            payload, empty = (result.data or {}), result.status == "empty"
            out.fetched += 1
            if refreshed is not None:
                refreshed.add(page_id)
        else:
            # No key: serve whatever is cached (even expired); otherwise the
            # page was never answered.
            if stored is None:
                out.complete = False
                break
            payload, empty = stored["payload"], stored["empty"]
            out.from_cache = True
        out.pages += 1
        rows = [] if empty else _page_rows(kind, payload)
        if page == 1:
            out.total = _total_records(kind, payload)
            page_size = len(rows)
        out.rows.extend(r for r in rows if isinstance(r, dict))
        total_pages = _total_pages(kind, payload, page_size)
        if kind == "live" or empty or not rows or (
            total_pages is not None and page >= total_pages
        ):
            break
    return out


# ---- normalisation -------------------------------------------------------


def _clean(value: Any) -> str | None:
    text = " ".join(str(value or "").split())
    return text or None


def _registrar_domains(row: dict) -> set[str]:
    registrar = row.get("domain_registrar")
    out: set[str] = set()
    if isinstance(registrar, dict):
        email = str(registrar.get("email_address") or "").strip().lower()
        if "@" in email:
            out.add(email.rsplit("@", 1)[1])
        site = str(registrar.get("website_url") or "").strip().lower()
        host = site.split("://", 1)[-1].split("/", 1)[0].removeprefix("www.")
        if "." in host:
            out.add(host)
    return out


def history_contacts(rows: list[dict], domain: str) -> list[dict]:
    """One entry per distinct real contact email across all snapshots."""
    domain = domain.lower().rstrip(".")
    found: dict[str, dict] = {}
    for row in rows:
        stamp = _clean(row.get("query_time")) or _clean(row.get("update_date"))
        registrar = (row.get("domain_registrar") or {}).get("registrar_name") if isinstance(
            row.get("domain_registrar"), dict
        ) else None
        registrar_domains = _registrar_domains(row)
        for block, role in _ROLES:
            contact = row.get(block)
            if not isinstance(contact, dict):
                continue
            email = str(contact.get("email_address") or "").strip().lower()
            if not email or whois_junk_reason(email, domain, registrar_domains=registrar_domains):
                continue
            name, company = _clean(contact.get("name")), _clean(contact.get("company"))
            item = found.setdefault(
                email,
                {
                    "email": email,
                    "name": None,
                    "company": None,
                    "roles": [],
                    "country": None,
                    "first_seen": stamp,
                    "last_seen": stamp,
                    "registrar": None,
                },
            )
            if role not in item["roles"]:
                item["roles"].append(role)
            item["name"] = item["name"] or (None if is_privacy_org(name) else name)
            item["company"] = item["company"] or (None if is_privacy_org(company) else company)
            item["country"] = item["country"] or _clean(contact.get("country_code"))
            if stamp:
                if not item["first_seen"] or stamp < item["first_seen"]:
                    item["first_seen"] = stamp
                if not item["last_seen"] or stamp >= item["last_seen"]:
                    item["last_seen"] = stamp
                    item["registrar"] = _clean(registrar) or item["registrar"]
            item["registrar"] = item["registrar"] or _clean(registrar)
    return sorted(found.values(), key=lambda c: (c["first_seen"] or "", c["email"]))


def history_seeds(rows: list[dict], domain: str) -> tuple[list[str], list[str]]:
    """Real registrant companies and emails (any domain) from history rows."""
    companies: dict[str, None] = {}
    for row in rows:
        contact = row.get("registrant_contact")
        company = _clean(contact.get("company")) if isinstance(contact, dict) else None
        if company and not is_privacy_org(company):
            companies.setdefault(company, None)
    emails = [
        c["email"] for c in history_contacts(rows, domain) if "registrant" in c["roles"]
    ]
    return list(companies), emails


def reverse_domains(rows: list[dict], *, exclude: str | None = None) -> list[dict]:
    """Distinct domains from reverse WHOIS mini rows, newest registrations first."""
    skip = (exclude or "").lower().rstrip(".")
    out: dict[str, dict] = {}
    for row in rows:
        name = str(row.get("domain_name") or "").strip().lower().rstrip(".")
        if not name or name == skip or name in out:
            continue
        out[name] = {
            "domain": name,
            "company": _clean(row.get("company_name")),
            "registrant_name": _clean(row.get("name")),
            "email": _clean(row.get("email")),
            "created": _clean(row.get("create_date")),
            "updated": _clean(row.get("update_date")),
            "expires": _clean(row.get("expiry_date")),
        }
    return list(out.values())


def subdomain_dates(rows: list[dict], domain: str) -> dict[str, dict]:
    """host -> {first_seen, last_seen, inactive_from} for hosts under *domain*."""
    domain = domain.lower().rstrip(".")
    out: dict[str, dict] = {}
    for row in rows:
        host = str(row.get("subdomain") or "").strip().lower().rstrip(".")
        if not host or not host.endswith("." + domain):  # the apex is not a subdomain
            continue
        out.setdefault(
            host,
            {
                "first_seen": _clean(row.get("first_seen")),
                "last_seen": _clean(row.get("last_seen")),
                "inactive_from": _clean(row.get("inactive_from")),
            },
        )
    return out


# ---- harvest helpers -----------------------------------------------------


def wf_deadline(seconds: float) -> float:
    return time.monotonic() + max(0.0, seconds)


def is_on_domain(email: str, domain: str) -> bool:
    host = email.rsplit("@", 1)[-1].lower()
    return host == domain or host.endswith("." + domain)


def reverse_seeds(
    domain: str,
    *,
    free_org: str | None,
    history_rows: list[dict],
    extra_orgs: list[str | None] = (),
    cap: int,
) -> list[tuple[str, str]]:
    """``[("company"|"email", value)]``, at most *cap*, companies and emails interleaved.

    Companies come from the target's free WHOIS and the history registrant rows;
    emails are real historical registrant addresses on any domain. Privacy
    organisations, proxies and registrar mailboxes never become seeds.
    """
    # History names are the full legal registrant ("Stripe, LLC") and match more
    # precisely than a free-WHOIS org, so they go first.
    hist_companies, hist_emails = history_seeds(history_rows, domain)
    companies: dict[str, None] = {}
    for org in (*hist_companies, free_org, *extra_orgs):
        text = _clean(org)
        if text and not is_privacy_org(text):
            companies.setdefault(text, None)
    # One seed per core name: "...India Pvt. Ltd." and "...India Limited" are the same
    # company, so they must not double the pivot credit or the spend.
    seen: set[str] = set()
    ordered_companies = []
    for company in companies:
        norm = core_name(company) or " ".join(company.lower().split())
        if norm not in seen:
            seen.add(norm)
            ordered_companies.append(company)
    seeds: list[tuple[str, str]] = []
    for pair in zip_longest(ordered_companies, hist_emails):
        for kind, value in zip(("company", "email"), pair):
            if value:
                seeds.append((kind, value))
    return seeds[: max(0, cap)]


async def related_candidates(
    domain: str,
    seeds: list[tuple[str, str]],
    *,
    via: dict[str, str] | None = None,
    refresh: bool = False,
    deadline: float | None = None,
    no_whoisfreaks: bool | None = None,
) -> tuple[dict[str, list[dict]], dict[str, dict], dict]:
    """Reverse-WHOIS the seeds. Returns ``(evidence_by_domain, pivots, telemetry)``.

    A company seed whose core name has two or more words is searched broadly
    (``exact=false``) and filtered back to rows whose own core name matches, so
    "Acme Widgets India Pvt. Ltd." also finds "Acme Widgets India Limited"
    domains. A one-word core is searched exactly: a broad search on it is noise.
    ``via`` maps a company to the sibling domain whose live WHOIS revealed it.
    """
    from .netlas_client import _dedupe_candidate

    via = via or {}
    evidence: dict[str, list[dict]] = {}
    pivots: dict[str, dict] = {}
    telemetry = {"complete": True, "fetched": 0, "from_cache": False, "variant_searches": 0}
    pages = max(1, int(settings.whoisfreaks_reverse_pages))
    company_seeds = [v for k, v in seeds if k == "company"]
    email_seeds = [v for k, v in seeds if k == "email"]
    seed_cores = {core_name(v) for v in company_seeds} - {""}
    variant_on = bool(getattr(settings, "whoisfreaks_variant_search", True))
    #: Every row any WhoisFreaks search returned this run, by registrable domain.
    seen_rows: dict[str, dict] = {}

    def add(reg: str, pivot: str, label: str, value: str, row: dict, *, matched: bool) -> bool:
        entry = {"pivot": pivot, label: value}
        if row["created"]:
            entry["created"] = row["created"]
        # Owner confirmed: the row's own company is a seed company (core name).
        entry["owner_confirmed"] = core_name(row["company"]) in seed_cores
        if matched and row["company"]:
            entry["matched_name"] = row["company"]
        if label == "company" and value in via:
            entry["via_sibling"] = via[value]
        entries = evidence.setdefault(reg, [])
        if any(e.get("pivot") == pivot and e.get(label) == value for e in entries):
            return False
        entries.append(entry)
        return True

    for kind, value in seeds:
        core = core_name(value) if kind == "company" else ""
        broad = kind == "company" and variant_on and len(core.split()) >= 2
        is_company = kind == "company"
        pivot, label = ("whois_company", "company") if is_company else ("whois_email", "email")
        # The exact search always runs; a multi-word company ALSO gets one broad search
        # (page 1 only), so a broad page full of other companies can't hide exact matches.
        exact_kind = "reverse_company" if is_company else "reverse_email"
        searches = [(exact_kind, value, pages, False)]
        if broad:
            searches.append(("reverse_company_broad", core.title(), 1, True))
        matched = 0
        total = None
        for fetch_kind, query, max_pages, is_broad in searches:
            found = await lookup(
                fetch_kind,
                query,
                max_pages=max_pages,
                refresh=refresh,
                deadline=deadline,
                no_whoisfreaks=no_whoisfreaks,
            )
            telemetry["complete"] = telemetry["complete"] and found.complete
            telemetry["fetched"] += found.fetched
            telemetry["from_cache"] = telemetry["from_cache"] or found.from_cache
            telemetry["variant_searches"] += 1 if is_broad else 0
            total = found.total if total is None else total
            for row in reverse_domains(found.rows, exclude=domain):
                # Broad search: keep only rows registered to the same company core.
                if is_broad and core_name(row["company"]) != core:
                    continue
                reg = _dedupe_candidate(row["domain"], domain)
                if not reg:
                    continue
                seen_rows.setdefault(reg, row)
                matched += add(reg, pivot, label, value, row, matched=is_broad)
        pivots[pivot] = {
            **pivots.get(pivot, {}),
            label: value,
            "matches": total,
            "verified_matches": matched,
            **({"variant_search": True} if broad else {}),
            **({"via_sibling": via[value]} if kind == "company" and value in via else {}),
        }
    # Credit pivots by what each row says, not by which search returned it. Only rows
    # a WhoisFreaks search returned this run are considered (never Netlas rows).
    emails = {e.lower(): e for e in email_seeds}
    for reg, row in seen_rows.items():
        if core_name(row["company"]) in seed_cores:
            for value in company_seeds:
                if core_name(value) == core_name(row["company"]):
                    add(reg, "whois_company", "company", value, row, matched=True)
        if (row["email"] or "").lower() in emails:
            add(reg, "whois_email", "email", emails[row["email"].lower()], row, matched=False)
    for pivot, label in (("whois_company", "company"), ("whois_email", "email")):
        if pivot in pivots:
            pivots[pivot]["verified_matches"] = sum(
                1 for entries in evidence.values() for e in entries if e.get("pivot") == pivot
            )
    return evidence, pivots, telemetry


async def has_harvest_cache(domain: str) -> bool:
    """True when a harvest lookup for *domain* (its history) is already cached."""
    from .enrichment_store import has_whoisfreaks_cache

    return await has_whoisfreaks_cache("history", domain)


async def cached_subdomain_dates(domain: str) -> dict[str, dict]:
    """Dated hosts for *domain* straight from the cache; never fetches."""
    found = await lookup(
        "subdomains",
        domain,
        max_pages=max(1, int(settings.whoisfreaks_subdomain_pages)),
        cache_only=True,
    )
    return subdomain_dates(found.rows, domain)


def apply_subdomain_dates(
    findings_by_module: dict[str, list[dict]], dates: dict[str, dict]
) -> tuple[set[str], int]:
    """Stamp dates onto existing subdomain records in place.

    Returns ``(hosts already present, records dated)``. A record WhoisFreaks knows
    also gains ``whoisfreaks`` in its ``discovery_method``.
    """
    known: set[str] = set()
    dated = 0
    for findings in findings_by_module.values():
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            host = finding.get("subdomain")
            if not isinstance(host, str) or not host.strip():
                continue
            host = host.strip().lower()
            known.add(host)
            stamp = dates.get(host)
            if not stamp:
                continue
            changed = False
            for key in ("first_seen", "last_seen", "inactive_from"):
                if stamp.get(key) and not finding.get(key):
                    finding[key] = stamp[key]
                    changed = True
            methods = finding.get("discovery_method")
            if isinstance(methods, list) and "whoisfreaks" not in methods:
                finding["discovery_method"] = sorted({*methods, "whoisfreaks"})
            dated += changed
    return known, dated


# ---- real company names when the target's own WHOIS is redacted --------------

_LEGAL_SUFFIXES = frozenset(
    {
        "private", "pvt", "limited", "ltd", "llc", "inc", "incorporated", "corp",
        "corporation", "co", "company", "gmbh", "plc", "pty", "llp", "lp", "sa", "bv",
        "ag", "nv", "srl", "sarl", "oy", "ab", "as", "kg", "sas", "spa", "bhd", "sdn",
        "pte", "kk", "ug", "ou",
    }
)
#: Sibling TLDs probed (a free DNS check) when no real company is known.
SIBLING_TLDS = (
    "com", "net", "org", "io", "co", "ai", "in", "co.in", "co.uk", "de", "fr", "com.au", "ca",
)


def core_name(name: str | None) -> str:
    """Company name without punctuation, a leading "the" and trailing legal suffixes.

    "Northwind Networks India Pvt. Ltd." and "Northwind Networks India Limited" both
    give ``northwind networks india``; "Stripe, LLC" gives ``stripe``. Suffix words
    are only stripped from the END, so "AB Networks India Ltd" stays distinct from
    "Networks India Ltd" and "The Co-operative Bank" keeps its words.
    """
    text = "".join(c if c.isalnum() else " " for c in str(name or "").lower())
    tokens = text.split()
    if tokens and tokens[0] == "the" and len(tokens) > 1:
        tokens = tokens[1:]
    while tokens and tokens[-1] in _LEGAL_SUFFIXES:
        tokens.pop()
    return " ".join(tokens)


def live_company(payload: dict | None) -> str | None:
    """The registrant company in a live WHOIS payload, privacy services dropped."""

    def find(node: Any) -> dict | None:
        if isinstance(node, dict):
            contact = node.get("registrant_contact")
            if isinstance(contact, dict):
                return contact
            for value in node.values():
                hit = find(value)
                if hit:
                    return hit
        elif isinstance(node, list):
            for value in node:
                hit = find(value)
                if hit:
                    return hit
        return None

    contact = find(payload or {})
    company = _clean(contact.get("company")) if contact else None
    return None if not company or is_privacy_org(company) else company


async def _exists(name: str) -> bool:
    """Free DNS existence check: an NS answer (or any non-NXDOMAIN) means registered."""
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = resolver.timeout = 3.0
    try:
        await resolver.resolve(name, "NS")
        return True
    except (dns.resolver.NoAnswer, dns.resolver.YXDOMAIN):
        return True  # the name exists, it just has no NS at this exact name
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
        return False
    except Exception:  # noqa: BLE001 - a probe never raises
        return False


async def sibling_domains(domain: str, *, limit: int) -> list[str]:
    """Existing ``<label>.<tld>`` siblings of *domain*, in SIBLING_TLDS order."""
    domain = domain.lower().rstrip(".")
    label = domain.split(".", 1)[0]
    candidates = [f"{label}.{tld}" for tld in SIBLING_TLDS if f"{label}.{tld}" != domain]
    flags = await asyncio.gather(*(_exists(name) for name in candidates))
    return [name for name, ok in zip(candidates, flags) if ok][: max(0, limit)]


async def sibling_company_seeds(
    domain: str,
    *,
    refresh: bool = False,
    deadline: float | None = None,
    no_whoisfreaks: bool | None = None,
) -> dict[str, str]:
    """``{company: sibling_domain}`` from live WHOIS of up to N existing siblings."""
    limit = int(getattr(settings, "whoisfreaks_sibling_lookups", 3))
    if limit <= 0:
        return {}
    found: dict[str, str] = {}
    seen_cores: set[str] = set()
    for sibling in await sibling_domains(domain, limit=limit):
        if deadline is not None and time.monotonic() >= deadline:
            break
        live = await lookup(
            "live",
            sibling,
            max_pages=1,
            refresh=refresh,
            deadline=deadline,
            no_whoisfreaks=no_whoisfreaks,
        )
        company = live_company(live.rows[0] if live.rows else None)
        if company and core_name(company) not in seen_cores:
            seen_cores.add(core_name(company))
            found.setdefault(company, sibling)
    return found
