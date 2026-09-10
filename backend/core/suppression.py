"""Phase 2A — suppression as a first-class, enforced data type.

A suppression record marks a subject (an email, a domain, or a company) that
must **never** appear in any export or lead output, in any mode. ICO guidance
(Doc-1 #7) recommends suppression lists and requires them to retain only the
*minimum* information needed to honor an objection — so personal identifiers
(email, domain) are stored **hashed**, never in the clear. Company names are
public business identifiers and are stored normalized so fuzzy variants
("Acme", "Acme Inc.", "Acme Incorporated") still match-and-exclude.

Enforcement lives at the export boundary (see ``export_filter``): a suppressed
subject is filtered out of every export format in both pipelines, and this
cannot be toggled off per-run. Suppression is also queryable during resolution
and is surfaced as an eligibility verdict in 2D.

Reuses the 1D ``suppression`` shell table (``subject_type`` = the scope,
``subject`` = the stored match key). 2A adds a ``source`` column (Alembic 0006).
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import create_engine, inspect, select

from ..db.database import AsyncSessionLocal, init_db
from ..db.models import Suppression


class SuppressionUnavailable(RuntimeError):
    """The suppression store could not be read.

    R2 (S1): suppression is a hard policy gate. When the store cannot be read,
    a serving boundary MUST fail **closed** — return an unavailable/error
    response — rather than emit unfiltered data. An *absent* table is NOT an
    error (suppression has simply never been configured → an empty index); only
    a genuine read failure raises this.
    """


class SuppressionScope(str, Enum):
    EMAIL = "email"
    DOMAIN = "domain"
    COMPANY = "company"


# Company-name suffixes stripped during normalization so legal-form variants of
# the same company collapse to one match key.
_COMPANY_SUFFIXES = {
    "inc",
    "incorporated",
    "llc",
    "l.l.c",
    "ltd",
    "limited",
    "corp",
    "corporation",
    "co",
    "company",
    "gmbh",
    "ag",
    "plc",
    "sa",
    "srl",
    "bv",
    "pty",
    "group",
    "holdings",
}


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def normalize_domain(value: str) -> str:
    d = (value or "").strip().lower()
    if d.startswith("http://"):
        d = d[7:]
    elif d.startswith("https://"):
        d = d[8:]
    if d.startswith("www."):
        d = d[4:]
    return d.split("/", 1)[0].rstrip(".")


def normalize_company(value: str) -> str:
    text = (value or "").strip().lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    tokens = [t for t in text.split() if t and t not in _COMPANY_SUFFIXES]
    return " ".join(tokens)


def domain_of(email: str) -> str:
    email = normalize_email(email)
    return email.split("@", 1)[1] if "@" in email else ""


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def match_key(scope: SuppressionScope, raw_value: str) -> str:
    """The stored, minimum-retention key for a subject.

    Email/domain → a SHA-256 of the normalized value (no clear-text PII). Company
    → the normalized public name (fuzzy variants collapse to one key).
    """
    if scope is SuppressionScope.EMAIL:
        return _hash(normalize_email(raw_value))
    if scope is SuppressionScope.DOMAIN:
        return _hash(normalize_domain(raw_value))
    return normalize_company(raw_value)


@dataclass(frozen=True)
class SuppressionHit:
    """Why a subject is suppressed — the minimum needed to explain the exclusion."""

    scope: SuppressionScope
    reason: str | None
    source: str | None


@dataclass(frozen=True)
class SuppressionIndex:
    """An in-memory snapshot of the suppression store, for O(1) export filtering.

    Loaded once (async) then applied synchronously, so synchronous exporters can
    enforce suppression without a DB round-trip per row.
    """

    email_hashes: frozenset[str]
    domain_hashes: frozenset[str]
    company_norms: frozenset[str]
    _meta: dict[str, tuple[str | None, str | None]]

    def hit(
        self,
        *,
        email: str | None = None,
        domain: str | None = None,
        company: str | None = None,
    ) -> SuppressionHit | None:
        """Return the first matching suppression, escalating email → domain →
        company. An email implies its domain, so a domain-scope suppression also
        excludes every address at that domain."""
        if email:
            key = match_key(SuppressionScope.EMAIL, email)
            if key in self.email_hashes:
                return self._as_hit(SuppressionScope.EMAIL, key)
            implied = domain_of(email)
            if implied:
                dkey = match_key(SuppressionScope.DOMAIN, implied)
                if dkey in self.domain_hashes:
                    return self._as_hit(SuppressionScope.DOMAIN, dkey)
        if domain:
            dkey = match_key(SuppressionScope.DOMAIN, domain)
            if dkey in self.domain_hashes:
                return self._as_hit(SuppressionScope.DOMAIN, dkey)
        if company:
            ckey = match_key(SuppressionScope.COMPANY, company)
            if ckey and ckey in self.company_norms:
                return self._as_hit(SuppressionScope.COMPANY, ckey)
        return None

    def is_suppressed(self, **kwargs: str | None) -> bool:
        return self.hit(**kwargs) is not None

    def _as_hit(self, scope: SuppressionScope, key: str) -> SuppressionHit:
        reason, source = self._meta.get(f"{scope.value}:{key}", (None, None))
        return SuppressionHit(scope=scope, reason=reason, source=source)


async def load_index() -> SuppressionIndex:
    """Load the whole suppression store into an in-memory index (one query).

    R2 (S1): fail closed. ``init_db`` creates the table if absent, so any error
    reaching here is a genuine store failure and is surfaced as
    :class:`SuppressionUnavailable` for the caller to fail closed on, never
    swallowed into an empty (no-filter) index.
    """
    try:
        await init_db()  # harvest skips serve/init_db; ensure the table exists
        async with AsyncSessionLocal() as session:
            rows = (await session.execute(select(Suppression))).scalars().all()
    except Exception as exc:
        raise SuppressionUnavailable(
            "suppression store unavailable (async load)"
        ) from exc
    email_hashes: set[str] = set()
    domain_hashes: set[str] = set()
    company_norms: set[str] = set()
    meta: dict[str, tuple[str | None, str | None]] = {}
    for row in rows:
        scope = str(row.subject_type)
        key = str(row.subject)
        if scope == SuppressionScope.EMAIL.value:
            email_hashes.add(key)
        elif scope == SuppressionScope.DOMAIN.value:
            domain_hashes.add(key)
        elif scope == SuppressionScope.COMPANY.value:
            company_norms.add(key)
        else:
            continue
        meta[f"{scope}:{key}"] = (row.reason, getattr(row, "source", None))
    return SuppressionIndex(
        email_hashes=frozenset(email_hashes),
        domain_hashes=frozenset(domain_hashes),
        company_norms=frozenset(company_norms),
        _meta=meta,
    )


_EMPTY_INDEX = SuppressionIndex(
    email_hashes=frozenset(),
    domain_hashes=frozenset(),
    company_norms=frozenset(),
    _meta={},
)

# Process-level cache for the synchronous export-path loader. Invalidated on
# every write (add/import) in this process; also refreshed after a short TTL so
# a long-running server picks up out-of-band changes.
_SYNC_CACHE: dict[str, object] = {"t": 0.0, "index": None}
_SYNC_TTL_SECONDS = 30.0


def _sync_database_url() -> str:
    from ..config import settings

    url = settings.database_url
    for async_driver in ("+aiosqlite", "+asyncpg", "+aiomysql", "+aiopg", "+asyncmy"):
        url = url.replace(async_driver, "")
    return url


def _read_index_sync() -> SuppressionIndex:
    """Read the suppression store via a short-lived synchronous engine.

    Fail-closed on real errors (raises), but an absent table means suppression
    has simply never been configured — return an empty index (nothing to filter).
    """
    engine = create_engine(_sync_database_url())
    try:
        if "suppression" not in inspect(engine).get_table_names():
            return _EMPTY_INDEX
        with engine.connect() as conn:
            rows = conn.execute(
                select(
                    Suppression.subject_type,
                    Suppression.subject,
                    Suppression.reason,
                    Suppression.source,
                )
            ).all()
    finally:
        engine.dispose()
    email_hashes: set[str] = set()
    domain_hashes: set[str] = set()
    company_norms: set[str] = set()
    meta: dict[str, tuple[str | None, str | None]] = {}
    for subject_type, subject, reason, source in rows:
        scope, key = str(subject_type), str(subject)
        if scope == SuppressionScope.EMAIL.value:
            email_hashes.add(key)
        elif scope == SuppressionScope.DOMAIN.value:
            domain_hashes.add(key)
        elif scope == SuppressionScope.COMPANY.value:
            company_norms.add(key)
        else:
            continue
        meta[f"{scope}:{key}"] = (reason, source)
    return SuppressionIndex(
        email_hashes=frozenset(email_hashes),
        domain_hashes=frozenset(domain_hashes),
        company_norms=frozenset(company_norms),
        _meta=meta,
    )


def load_index_sync() -> SuppressionIndex:
    """The suppression index for synchronous export/serialize code paths.

    Cached per-process (invalidated on write, refreshed after a short TTL) so the
    hot export path does not hit the DB per row while still reflecting new
    objections promptly.
    """
    now = time.monotonic()
    cached = _SYNC_CACHE["index"]
    if cached is not None and (now - float(_SYNC_CACHE["t"])) < _SYNC_TTL_SECONDS:
        return cached  # type: ignore[return-value]
    try:
        index = _read_index_sync()
    except Exception as exc:
        # R2 (S1): FAIL CLOSED. A read failure here is indistinguishable from
        # "nothing suppressed" if we degrade to an empty index, so a suppressed
        # subject would leak into the export. A within-TTL cache was already
        # returned above; reaching here means we have no trustworthy view of the
        # store, so we refuse rather than emit unfiltered data. The caller (a
        # serving boundary) turns this into an unavailable/error response.
        import logging

        logging.getLogger(__name__).exception("suppression sync index read failed")
        raise SuppressionUnavailable(
            "suppression store unavailable (read-time)"
        ) from exc
    _SYNC_CACHE["t"] = now
    _SYNC_CACHE["index"] = index
    return index


def invalidate_sync_cache() -> None:
    _SYNC_CACHE["t"] = 0.0
    _SYNC_CACHE["index"] = None


async def is_suppressed(
    *,
    email: str | None = None,
    domain: str | None = None,
    company: str | None = None,
) -> SuppressionHit | None:
    """Query the store for a single subject (loads the index)."""
    index = await load_index()
    return index.hit(email=email, domain=domain, company=company)


async def add_suppression(
    *,
    email: str | None = None,
    domain: str | None = None,
    company: str | None = None,
    reason: str | None = None,
    source: str = "manual",
) -> int:
    """Add suppression record(s). Exactly the provided scopes are added; a value
    that is already suppressed at the same scope is skipped (idempotent)."""
    await init_db()
    added = 0
    pairs: list[tuple[SuppressionScope, str]] = []
    if email:
        pairs.append((SuppressionScope.EMAIL, email))
    if domain:
        pairs.append((SuppressionScope.DOMAIN, domain))
    if company:
        pairs.append((SuppressionScope.COMPANY, company))
    if not pairs:
        return 0
    async with AsyncSessionLocal() as session:
        async with session.begin():
            for scope, raw in pairs:
                key = match_key(scope, raw)
                if not key:
                    continue
                exists = (
                    await session.execute(
                        select(Suppression.id).where(
                            Suppression.subject_type == scope.value,
                            Suppression.subject == key,
                        )
                    )
                ).first()
                if exists:
                    continue
                session.add(
                    Suppression(
                        subject_type=scope.value,
                        subject=key,
                        reason=reason,
                        source=source,
                    )
                )
                added += 1
    if added:
        invalidate_sync_cache()
    return added


async def import_suppression(rows: Iterable[dict]) -> int:
    """Bulk-import suppression records from parsed CSV/stdin rows.

    Each row may carry any of ``email``/``domain``/``company`` plus optional
    ``reason``/``source``. Returns the number of new records added.
    """
    total = 0
    for row in rows:
        total += await add_suppression(
            email=row.get("email"),
            domain=row.get("domain"),
            company=row.get("company"),
            reason=row.get("reason"),
            source=row.get("source") or "import",
        )
    return total


def _iter_strings(obj: object):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, list | tuple):
        for v in obj:
            yield from _iter_strings(v)


def _looks_like_domain(text: str) -> bool:
    return (
        "." in text
        and "@" not in text
        and " " not in text.strip()
        and len(text) <= 253
    )


#: Explicit company/organization field names checked for company-scope
#: suppression on structured rows (leads, verification, change signals). Company
#: matching is exact on the *whole* normalized field value, never a substring, so
#: it cannot accidentally match arbitrary free text.
_COMPANY_FIELD_KEYS = (
    "company",
    "company_name",
    "organization",
    "organisation",
    "org",
    "org_name",
    "employer",
)


#: Email / domain extractors so an identifier EMBEDDED in free text (timeline
#: details, source URLs, bios) is caught, not only a string that is exactly the
#: identifier. Matching is still precise: an extracted token only matters if it
#: hashes to a suppressed subject, so free text never accidentally matches.
_EMBEDDED_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_EMBEDDED_DOMAIN_RE = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
)


def _string_leaks(s: str, index: SuppressionIndex) -> bool:
    # Fast path: the string IS the identifier (structured field values).
    if "@" in s and index.hit(email=s):
        return True
    if _looks_like_domain(s) and index.hit(domain=s):
        return True
    # Embedded identifiers in free text / URLs. index.hit(email=...) escalates
    # to the address's domain, so a domain-scope objection is honoured too.
    if index.email_hashes or index.domain_hashes:
        for match in _EMBEDDED_EMAIL_RE.findall(s):
            if index.hit(email=match):
                return True
        if index.domain_hashes:
            for match in _EMBEDDED_DOMAIN_RE.findall(s):
                if index.hit(domain=match):
                    return True
    return False


def _object_leaks(obj: object, index: SuppressionIndex) -> bool:
    """True if *obj* (any nested structure) exposes a suppressed email or domain.

    Email/domain are precise identifiers (checked by hash), so this scan is safe
    to run over arbitrary nested content (findings, graph nodes, timeline events,
    bios) — free text never matches unless it contains a real suppressed subject.
    """
    return any(_string_leaks(s, index) for s in _iter_strings(obj))


def _row_leaks(row: object, index: SuppressionIndex) -> bool:
    """Row-level leak check: precise email/domain scan plus a company-scope check
    on explicit company/org fields (structured lead/verification/change rows)."""
    if _object_leaks(row, index):
        return True
    if index.company_norms and isinstance(row, dict):
        for key in _COMPANY_FIELD_KEYS:
            value = row.get(key)
            if isinstance(value, str) and index.hit(company=value):
                return True
    return False


# Back-compat alias for the original findings-only helper name.
_finding_leaks = _object_leaks


def _index_is_empty(index: SuppressionIndex) -> bool:
    return not (index.email_hashes or index.domain_hashes or index.company_norms)


def filter_findings(
    findings: list, index: SuppressionIndex | None = None
) -> list:
    """Drop findings that expose a suppressed subject. Fail-closed via the index
    loader (raises :class:`SuppressionUnavailable` when the store is unreadable).

    Used by boundaries that build derived views (graph/clusters) straight from
    findings, so redaction happens at the source rather than post-hoc.
    """
    if index is None:
        index = load_index_sync()
    if _index_is_empty(index):
        return list(findings)
    return [f for f in findings if not _object_leaks(f, index)]


def filter_rows(rows: list, index: SuppressionIndex | None = None) -> list:
    """Drop structured rows (leads / verification history / change signals) that
    expose a suppressed subject. Fail-closed via the index loader."""
    if index is None:
        index = load_index_sync()
    if _index_is_empty(index):
        return list(rows)
    return [r for r in rows if not _row_leaks(r, index)]


def subject_suppressed(
    index: SuppressionIndex,
    *,
    email: str | None = None,
    domain: str | None = None,
    company: str | None = None,
) -> bool:
    """Whether the primary investigated subject is itself suppressed (so the
    whole response must reduce to a non-leaking stub)."""
    return index.hit(email=email, domain=domain, company=company) is not None


def _redact_d3_graph(graph: dict, index: SuppressionIndex) -> dict:
    """Drop graph nodes that leak a suppressed subject and any incident links."""
    nodes = graph.get("nodes")
    if isinstance(nodes, list):
        kept: list = []
        dropped_ids: set = set()
        for node in nodes:
            if isinstance(node, dict) and _object_leaks(node, index):
                nid = node.get("id")
                if nid is not None:
                    dropped_ids.add(nid)
                continue
            kept.append(node)
        graph["nodes"] = kept
        links = graph.get("links")
        if isinstance(links, list):
            graph["links"] = [
                link
                for link in links
                if not (
                    isinstance(link, dict)
                    and (
                        link.get("source") in dropped_ids
                        or link.get("target") in dropped_ids
                        or _object_leaks(link, index)
                    )
                )
            ]
    return graph


def redact_field_provenance(
    provenance: dict, index: SuppressionIndex | None = None
) -> dict:
    """Drop provenance entries that expose a suppressed subject.

    ``field_provenance`` is attached to the report AFTER redaction, so it needs
    its own pass. Fail-closed via the index loader."""
    if not isinstance(provenance, dict):
        return provenance
    if index is None:
        index = load_index_sync()
    if _index_is_empty(index):
        return provenance
    return {k: v for k, v in provenance.items() if not _object_leaks(v, index)}


def redact_graph(graph: dict, index: SuppressionIndex | None = None) -> dict:
    """Public entry: drop suppressed nodes (and incident links) from a D3 graph.

    Used by the graph route for the persisted ``graph_data`` path (which bypasses
    the report redactor). Fail-closed via the index loader."""
    if index is None:
        index = load_index_sync()
    if _index_is_empty(index):
        return graph
    return _redact_d3_graph(graph, index)


def redact_report(data: dict, index: SuppressionIndex | None = None) -> dict:
    """Filter suppressed subjects out of an enriched investigate report.

    If the investigated subject itself is suppressed the report is reduced to a
    non-leaking stub; otherwise any finding — and any embedded graph node,
    timeline event, or module row — that exposes a suppressed email or domain is
    dropped. Applied at ``enrich_report`` so the raw report API and all six
    exporters share one read-time filter. Fail-closed: if the store is
    unreadable, :func:`load_index_sync` raises and the boundary refuses rather
    than returning an unfiltered report.
    """
    if index is None:
        index = load_index_sync()
    if _index_is_empty(index):
        return data  # nothing suppressed — zero-overhead, zero-regression path
    primary = data.get("canonical_email") or data.get("email")
    if isinstance(primary, str) and index.hit(email=primary):
        return {
            "id": data.get("id"),
            "email": None,
            "suppressed": True,
            "findings": [],
            "findings_by_module": {},
        }
    if isinstance(data.get("findings"), list):
        data["findings"] = [
            f for f in data["findings"] if not _object_leaks(f, index)
        ]
    fbm = data.get("findings_by_module")
    if isinstance(fbm, dict):
        data["findings_by_module"] = {
            module: (
                [f for f in items if not _object_leaks(f, index)]
                if isinstance(items, list)
                else items
            )
            for module, items in fbm.items()
        }
    # Derived report views must be redacted too (a report can embed its own
    # graph / timeline built from the raw findings).
    graph_data = data.get("graph_data")
    if isinstance(graph_data, dict):
        data["graph_data"] = _redact_d3_graph(graph_data, index)
    timeline = data.get("timeline")
    if isinstance(timeline, list):
        data["timeline"] = [e for e in timeline if not _object_leaks(e, index)]
    return data


async def list_suppression() -> list[dict]:
    """List suppression records (minimum-retention view — keys are hashes for
    email/domain, normalized names for company)."""
    await init_db()
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(select(Suppression))).scalars().all()
    return [
        {
            "scope": r.subject_type,
            "key": r.subject,
            "reason": r.reason,
            "source": getattr(r, "source", None),
        }
        for r in rows
    ]
