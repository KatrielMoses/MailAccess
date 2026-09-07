"""Phase 1D — unified corpus store: DB-backed read-first / write-back for harvest.

Replaces the per-domain JSON harvest cache (``harvest_cache.py``) as the source
of truth. A harvest now:

* **reads the corpus first** — a fresh ``crawl_snapshots`` row reconstructs a
  parity-identical :class:`DomainHarvestResult` offline, instantly;
* runs collection only when the domain is missing/stale;
* **writes back** — a new crawl snapshot plus refreshed aggregate projections
  (``domains`` / ``contacts`` / ``verification_outcomes``).

The full result is stored verbatim in ``crawl_snapshots.result_json`` using the
same serializer the JSON cache used, so read-first output is byte-identical to
the old path — the concrete parity guarantee. The aggregate projections are
maintained (materialized latest-view) tables: per domain they reflect the latest
crawl, while the append-only 1C observations ledger keeps full history. The
per-domain JSON is now only an export (``harvest_results.py``), not a cache.

libSQL / embedded-replica readiness (Phase 6): these are ordinary tables on the
app's async engine, so a future embedded replica can sync them unchanged — no
adoption here.

Every entry point is fully guarded by callers; a corpus failure must never break
a harvest (the JSON export still lands).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from ..config import APP_VERSION, settings
from .domain_harvest_orchestrator import DomainHarvestResult
from .harvest_cache import _deserialize_result, _parse_timestamp, _serialize_result

logger = logging.getLogger(__name__)

# The in-process harvest path skips the server lifespan (which awaits init_db()),
# so the DB schema may not exist yet when the first corpus op runs on a cold DB
# (BUG-5: "no such table: crawl_snapshots"). init_db() runs Alembic migrations on
# every call, so we gate it behind a process-level flag: migrate once, then this
# is a cheap no-op on the per-lead read paths.
_SCHEMA_READY = False


async def _ensure_schema() -> None:
    """Idempotently ensure the corpus schema exists before a harvest DB op.

    Runs the migrations at most once per process (the server path already did
    this via its lifespan; the in-process harvest path had not)."""
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    from ..db.database import init_db

    await init_db()
    _SCHEMA_READY = True


def normalize_domain(domain: str) -> str:
    return str(domain).strip().lower().rstrip(".")


def _ttl_seconds() -> int:
    return int(getattr(settings, "harvest_cache_ttl_seconds", 3600))


def _corpus_enabled() -> bool:
    return bool(getattr(settings, "harvest_cache_enabled", True))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return _parse_timestamp(value)
        except (ValueError, TypeError):
            return None
    return None


def _snapshot_is_fresh(mailaccess_version: str, harvested_at: datetime, ttl: int) -> bool:
    if mailaccess_version != APP_VERSION:
        return False
    if ttl <= 0:
        return False
    age = (_now() - harvested_at).total_seconds()
    return age < ttl


async def read_fresh_crawl(domain: str) -> DomainHarvestResult | None:
    """Read-first: return the latest *fresh* crawl for ``domain``, else None.

    Reconstructs the full result from ``result_json`` and stamps the cache
    fields exactly as the old JSON cache did, so the returned result is
    parity-identical to a JSON-cache hit.
    """
    if not _corpus_enabled():
        return None
    try:
        from sqlalchemy import desc, select

        from ..db.database import AsyncSessionLocal
        from ..db.models import CrawlSnapshot

        await _ensure_schema()  # harvest skips serve/init_db; ensure schema before the read
        normalized = normalize_domain(domain)
        ttl = _ttl_seconds()
        async with AsyncSessionLocal() as session:
            row = (
                await session.execute(
                    select(CrawlSnapshot)
                    .where(CrawlSnapshot.domain == normalized)
                    .order_by(desc(CrawlSnapshot.harvested_at))
                    .limit(1)
                )
            ).scalar_one_or_none()
        if row is None:
            return None
        harvested_at = row.harvested_at
        if harvested_at.tzinfo is None:
            harvested_at = harvested_at.replace(tzinfo=timezone.utc)
        if not _snapshot_is_fresh(row.mailaccess_version, harvested_at, ttl):
            return None
        result = _deserialize_result(dict(row.result_json))
        result.from_cache = True
        result.cached_at = harvested_at.isoformat().replace("+00:00", "Z")
        result.cache_age_seconds = max(0.0, (_now() - harvested_at).total_seconds())
        return result
    except Exception:
        logger.exception("Corpus read-first failed for %s; will collect fresh", domain)
        return None


async def write_back(domain: str, result: DomainHarvestResult) -> None:
    """Persist a fresh crawl: a new snapshot + refreshed projections.

    Never called for a read-first hit (nothing new collected), so it does not
    duplicate snapshots. Fully guarded.
    """
    if not _corpus_enabled() or getattr(result, "from_cache", False):
        return
    try:
        from ..db.database import AsyncSessionLocal, init_db

        await init_db()  # harvest skips serve/init_db; ensure schema exists
        normalized = normalize_domain(domain)
        harvested_at = _parse_dt(getattr(result, "completed_at", None)) or _now()
        async with AsyncSessionLocal() as session:
            async with session.begin():
                snapshot_id = await _insert_snapshot(session, normalized, result, harvested_at)
                await _upsert_domain(session, normalized, result, harvested_at, snapshot_id)
                await _refresh_contacts(session, normalized, result, harvested_at)
    except Exception:
        logger.exception("Corpus write-back failed for %s (harvest unaffected)", domain)


async def _insert_snapshot(
    session: Any, domain: str, result: DomainHarvestResult, harvested_at: datetime
) -> str:
    from ..db.models import CrawlSnapshot

    snapshot = CrawlSnapshot(
        domain=domain,
        harvested_at=harvested_at,
        duration_seconds=float(getattr(result, "duration_seconds", 0.0) or 0.0),
        mailaccess_version=APP_VERSION,
        ttl_seconds=_ttl_seconds(),
        total_unique_emails=int(getattr(result, "total_unique_emails", 0) or 0),
        high_confidence_count=int(getattr(result, "high_confidence_count", 0) or 0),
        likely_confidence_count=int(getattr(result, "likely_confidence_count", 0) or 0),
        medium_confidence_count=int(getattr(result, "medium_confidence_count", 0) or 0),
        low_confidence_count=int(getattr(result, "low_confidence_count", 0) or 0),
        catchall_detected=getattr(result, "catchall_detected", None),
        confirmed_pattern=getattr(result, "confirmed_pattern", None),
        mode=str(
            (getattr(result, "metadata", None) or {}).get("mode")
            or "security-investigation"
        ),
        result_json=_serialize_result(result),
    )
    session.add(snapshot)
    await session.flush()
    return snapshot.id


async def _upsert_domain(
    session: Any,
    domain: str,
    result: DomainHarvestResult,
    harvested_at: datetime,
    snapshot_id: str,
) -> None:
    from sqlalchemy import select

    from ..db.models import Domain

    row = (
        await session.execute(select(Domain).where(Domain.domain == domain))
    ).scalar_one_or_none()
    total = int(getattr(result, "total_unique_emails", 0) or 0)
    high = int(getattr(result, "high_confidence_count", 0) or 0)
    catchall = getattr(result, "catchall_detected", None)
    now = _now()
    if row is None:
        session.add(
            Domain(
                domain=domain,
                first_harvested_at=harvested_at,
                last_harvested_at=harvested_at,
                last_crawl_snapshot_id=snapshot_id,
                total_emails=total,
                high_confidence_count=high,
                catchall_detected=catchall,
                created_at=now,
                updated_at=now,
            )
        )
    else:
        row.last_harvested_at = harvested_at
        row.last_crawl_snapshot_id = snapshot_id
        row.total_emails = total
        row.high_confidence_count = high
        row.catchall_detected = catchall
        row.updated_at = now


async def _refresh_contacts(
    session: Any, domain: str, result: DomainHarvestResult, harvested_at: datetime
) -> None:
    """Maintained latest-view: replace this domain's contacts + verifications."""
    from sqlalchemy import delete, select

    from ..db.models import Contact, VerificationOutcome

    # Clear the prior projection for this domain (children first for the FK).
    prior_ids = (
        await session.execute(select(Contact.id).where(Contact.domain == domain))
    ).scalars().all()
    if prior_ids:
        await session.execute(
            delete(VerificationOutcome).where(VerificationOutcome.contact_id.in_(prior_ids))
        )
    await session.execute(delete(Contact).where(Contact.domain == domain))

    # Phase 2A — the contacts table is the servable lead projection; a suppressed
    # subject must never land in it.
    from .suppression import load_index_sync

    suppression = load_index_sync()

    now = _now()
    for email in getattr(result, "unique_emails", None) or []:
        address = getattr(email, "email", None)
        if not isinstance(address, str) or not address:
            continue
        if suppression.is_suppressed(email=address):
            continue
        contact = Contact(
            email=address,
            domain=domain,
            on_domain=bool(getattr(email, "on_domain", True)),
            is_role=bool(getattr(email, "is_role", False)),
            confidence_label=getattr(email, "confidence_label", None),
            confidence_score=getattr(email, "confidence_score", None),
            source_count=int(getattr(email, "source_count", 0) or 0),
            found_by_modules=list(getattr(email, "found_by_modules", None) or []),
            first_seen=_parse_dt(getattr(email, "first_seen_timestamp", None)),
            last_seen=_parse_dt(getattr(email, "last_seen_timestamp", None)),
            last_verified=harvested_at,  # freshness of our knowledge (decay input)
            # Phase 3A person fields (evidence-or-null; the HarvestedEmail carries
            # None when nothing resolved, so email-only leads project cleanly).
            full_name=getattr(email, "full_name", None),
            first_name=getattr(email, "first", None),
            last_name=getattr(email, "last", None),
            job_title=getattr(email, "job_title", None),
            seniority=getattr(email, "seniority", None),
            department=getattr(email, "department", None),
            linkedin_url=getattr(email, "linkedin_url", None),
            phone=getattr(email, "phone", None),
            location=getattr(email, "location", None),
            person_field_provenance=dict(getattr(email, "person_field_provenance", None) or {})
            or None,
            # Phase 3C/3D deliverability (populated once those passes run).
            deliverability_score=getattr(email, "deliverability_score", None),
            deliverability_grade=getattr(email, "deliverability_grade", None),
            created_at=now,
            updated_at=now,
        )
        session.add(contact)
        await session.flush()
        for outcome in _verification_outcomes(email, domain, contact.id, harvested_at):
            session.add(VerificationOutcome(**outcome))


def _verification_outcomes(
    email: Any, domain: str, contact_id: str, harvested_at: datetime
) -> list[dict[str, Any]]:
    address = getattr(email, "email", "")
    outcomes: list[dict[str, Any]] = []
    if getattr(email, "is_smtp_verified", False):
        outcomes.append(
            {
                "contact_id": contact_id,
                "email": address,
                "domain": domain,
                "method": "smtp",
                "status": "verified",
                "provider": None,
                "verified_at": harvested_at,
            }
        )
    if getattr(email, "is_provider_verified", False):
        outcomes.append(
            {
                "contact_id": contact_id,
                "email": address,
                "domain": domain,
                "method": "provider",
                "status": str(getattr(email, "provider_verification_status", None) or "verified"),
                "provider": getattr(email, "provider_verification_provider", None),
                "verified_at": harvested_at,
            }
        )
    return outcomes


def _contact_to_dict(row: Any) -> dict[str, Any]:
    """Serialise a Contact ORM row into the servable Lead shape."""
    def _iso(dt: Any) -> str | None:
        return dt.isoformat() if isinstance(dt, datetime) else None

    # Phase 6A — decay the *served* confidence by the row's age since last
    # verification (additive; stored confidence_score is left untouched so a
    # re-verification restores full strength). Fresh rows get factor 1.0.
    from .corpus_decay import decay_view

    decay = decay_view(row.confidence_score, row.last_verified)

    return {
        "email": row.email,
        "domain": row.domain,
        "on_domain": row.on_domain,
        "is_role": row.is_role,
        "confidence_label": row.confidence_label,
        "confidence_score": row.confidence_score,
        # Phase 6A decay (served confidence + freshness flag), additive.
        "served_confidence_score": decay["served_confidence_score"],
        "decay": {
            "factor": decay["decay_factor"],
            "age_days": decay["age_days"],
            "annual_rot": decay["annual_rot"],
            "reason": decay["reason"],
        },
        "needs_reverification": decay["needs_reverification"],
        "source_count": row.source_count,
        "found_by_modules": list(row.found_by_modules or []),
        "first_seen": _iso(row.first_seen),
        "last_seen": _iso(row.last_seen),
        "last_verified": _iso(row.last_verified),
        "person": {
            "full_name": row.full_name,
            "first": row.first_name,
            "last": row.last_name,
            "job_title": row.job_title,
            "seniority": row.seniority,
            "department": row.department,
            "linkedin_url": row.linkedin_url,
            "phone": row.phone,
            "location": row.location,
            "field_provenance": dict(row.person_field_provenance or {}),
        },
        "deliverability_score": row.deliverability_score,
        "deliverability_grade": row.deliverability_grade,
        "policy_status": row.policy_status,
    }


async def read_leads(
    domain: str,
    *,
    seniority: str | None = None,
    grade: str | None = None,
    has_person: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Read-only servable Lead projection for a domain, with lead-gen filters.

    Returns ``{domain, total, limit, offset, leads: [...]}``. Fully guarded — a
    corpus failure returns an empty result rather than raising into the API.
    Suppression is enforced at write time (``_refresh_contacts`` never inserts a
    suppressed subject), so no read-time filtering is needed for that."""
    empty = {"domain": normalize_domain(domain), "total": 0, "limit": limit,
             "offset": offset, "leads": []}
    if not _corpus_enabled():
        return empty
    try:
        from sqlalchemy import func, select

        from ..db.database import AsyncSessionLocal
        from ..db.models import Contact

        normalized = normalize_domain(domain)
        conditions = [Contact.domain == normalized]
        if seniority:
            conditions.append(Contact.seniority == seniority)
        if grade:
            conditions.append(Contact.deliverability_grade == grade)
        if has_person is True:
            conditions.append(Contact.full_name.isnot(None))
        elif has_person is False:
            conditions.append(Contact.full_name.is_(None))

        async with AsyncSessionLocal() as session:
            total = (
                await session.execute(
                    select(func.count()).select_from(Contact).where(*conditions)
                )
            ).scalar_one()
            rows = (
                await session.execute(
                    select(Contact)
                    .where(*conditions)
                    .order_by(Contact.confidence_score.desc().nullslast(), Contact.email)
                    .limit(max(1, min(int(limit), 1000)))
                    .offset(max(0, int(offset)))
                )
            ).scalars().all()
        return {
            "domain": normalized,
            "total": int(total or 0),
            "limit": limit,
            "offset": offset,
            "leads": [_contact_to_dict(r) for r in rows],
        }
    except Exception:
        logger.exception("read_leads failed for %s", domain)
        return empty


async def read_stale_contacts(
    *, domain: str | None = None, limit: int = 500
) -> list[dict[str, Any]]:
    """Corpus rows aged past the decay staleness threshold (Phase 6A).

    Surfaces the contacts that should be *re-verified* rather than served at full
    confidence, newest-verified first. Read-only, guarded → [] on failure. 6F
    consumes this as the "likely stale" change signal.
    """
    from .corpus_decay import is_stale

    if not _corpus_enabled():
        return []
    try:
        from sqlalchemy import desc, select

        from ..db.database import AsyncSessionLocal
        from ..db.models import Contact

        conditions = []
        if domain:
            conditions.append(Contact.domain == normalize_domain(domain))
        async with AsyncSessionLocal() as session:
            rows = (
                await session.execute(
                    select(Contact)
                    .where(*conditions)
                    .order_by(desc(Contact.last_verified))
                    .limit(max(1, min(int(limit), 5000)))
                )
            ).scalars().all()
        stale = [r for r in rows if is_stale(r.last_verified)]
        return [_contact_to_dict(r) for r in stale]
    except Exception:
        logger.exception("read_stale_contacts failed")
        return []


async def read_verification_history(
    *, email: str | None = None, domain: str | None = None, limit: int = 200
) -> list[dict[str, Any]]:
    """Verification-outcome history for an email or domain (newest first).

    Phase 3C consumes this as a deliverability signal (has this address/domain
    verified before, and how recently). Guarded → [] on failure."""
    if not _corpus_enabled() or (not email and not domain):
        return []
    try:
        from sqlalchemy import desc, select

        from ..db.database import AsyncSessionLocal
        from ..db.models import VerificationOutcome

        await _ensure_schema()  # cold-harvest guard: read-first may be skipped (--force)
        conditions = []
        if email:
            conditions.append(VerificationOutcome.email == str(email).strip().lower())
        if domain:
            conditions.append(VerificationOutcome.domain == normalize_domain(domain))
        async with AsyncSessionLocal() as session:
            rows = (
                await session.execute(
                    select(VerificationOutcome)
                    .where(*conditions)
                    .order_by(desc(VerificationOutcome.verified_at))
                    .limit(max(1, min(int(limit), 1000)))
                )
            ).scalars().all()
        return [
            {
                "email": r.email,
                "domain": r.domain,
                "method": r.method,
                "status": r.status,
                "provider": r.provider,
                "verified_at": r.verified_at.isoformat()
                if isinstance(r.verified_at, datetime)
                else None,
            }
            for r in rows
        ]
    except Exception:
        logger.exception("read_verification_history failed")
        return []


async def invalidate(domain: str) -> None:
    """Drop the read-first source (crawl snapshots) for a domain, forcing a fresh
    re-collection on the next harvest. Aggregate projections are left in place
    (they refresh on the next harvest). Guarded."""
    try:
        from sqlalchemy import delete

        from ..db.database import AsyncSessionLocal
        from ..db.models import CrawlSnapshot

        normalized = normalize_domain(domain)
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(
                    delete(CrawlSnapshot).where(CrawlSnapshot.domain == normalized)
                )
    except Exception:
        logger.exception("Corpus invalidate failed for %s", domain)


async def invalidate_all() -> None:
    """Drop every crawl snapshot (all domains' read-first sources). Guarded."""
    try:
        from sqlalchemy import delete

        from ..db.database import AsyncSessionLocal
        from ..db.models import CrawlSnapshot

        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(delete(CrawlSnapshot))
    except Exception:
        logger.exception("Corpus invalidate_all failed")


async def list_domains() -> list[str]:
    """Known domains in the corpus (for diagnostics). Guarded → [] on failure."""
    try:
        from sqlalchemy import select

        from ..db.database import AsyncSessionLocal
        from ..db.models import Domain

        async with AsyncSessionLocal() as session:
            rows = (
                await session.execute(select(Domain.domain).order_by(Domain.domain))
            ).scalars().all()
        return [str(r) for r in rows]
    except Exception:
        return []


async def known_domains(candidates: list[str]) -> set[str]:
    """Return the subset of ``candidates`` ever harvested (Phase 5A dedup).

    Keys off the ``domains`` aggregate projection, which persists past a crawl
    snapshot's TTL and survives ``invalidate()`` — so it is the correct
    "have we ever seen this domain?" signal for cross-batch deduplication,
    unlike the freshness-bound ``crawl_snapshots`` that ``read_fresh_crawl``
    consults. A single batched ``IN`` query keeps a large list cheap.

    Guarded → empty set on any failure (a corpus outage must never make a bulk
    run skip domains it should harvest; failing "open" re-harvests, never drops).
    """
    normalized = {normalize_domain(d) for d in candidates if d and d.strip()}
    if not normalized:
        return set()
    try:
        from sqlalchemy import select

        from ..db.database import AsyncSessionLocal
        from ..db.models import Domain

        async with AsyncSessionLocal() as session:
            rows = (
                await session.execute(
                    select(Domain.domain).where(Domain.domain.in_(normalized))
                )
            ).scalars().all()
        return {str(r) for r in rows}
    except Exception:
        logger.debug("Corpus known_domains lookup failed", exc_info=True)
        return set()
