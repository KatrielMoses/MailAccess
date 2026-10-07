"""Engine-local Netlas enrichment store (F8).

A read/merge-policy layer over the stores that already exist — no new database.
The non-negotiable split (brief + design decisions, see memory ``netlas-f8-design``):

* **The store READ is unconditional** — it runs with or without a key and must
  never sit behind :func:`netlas_client.netlas_active`. Every run serves the
  deduped union of the current result and all historical, scope-compatible,
  dated blobs. (Cache model: the native read-first still decides whether to run
  modules / fetch; this merge is the universal final step on every path.)
* **The Netlas FETCH is key- *and* TTL-gated** (:func:`should_fetch_netlas`): a
  keyed run only calls Netlas for a subject not enriched within
  ``netlas_refresh_ttl_days``.
* **Append only on a keyed fetch** — a no-key / native-only run reads but never
  writes a Netlas blob (``mark_blob_netlas_enriched``).
* **Mode/scope-scoped** — only blobs collected under the same product mode (and
  a compatible scope signature) are merged, so security-mode enrichment never
  leaks into a public-mode response.
* **Never-raise** — any store error is logged and the caller falls back to the
  native result, exit 0.

F8a is the harvest half (subject = normalized domain, over ``crawl_snapshots``).
F8b (investigate) lives in :mod:`backend.core.enrichment_store` too — see the
investigate section below.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import settings

logger = logging.getLogger(__name__)


def _enabled() -> bool:
    return bool(getattr(settings, "enrichment_store_enabled", True))


def _ttl() -> timedelta:
    try:
        return timedelta(days=max(0, int(getattr(settings, "netlas_refresh_ttl_days", 30))))
    except (TypeError, ValueError):
        return timedelta(days=30)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


#: Metadata key for F8's **key-independent** scope signature (the run's scope
#: with the ``netlas`` flag stripped). A keyed and a keyless run of the same
#: domain/mode/flags share this, so a keyless run can serve a keyed run's
#: enrichment blobs — the whole point of the store.
ENRICHMENT_SCOPE_KEY = "enrichment_scope"


def enrichment_scope(request_scope_kwargs: dict[str, Any]) -> str:
    """The key-independent scope signature for the enrichment store."""
    from .corpus_store import scope_signature

    kwargs = dict(request_scope_kwargs)
    kwargs["netlas"] = False  # key-independent: keyed and keyless share one scope
    return _strip_app_version(scope_signature(**kwargs))


def _strip_app_version(scope: str) -> str:
    """Drop ``app_version`` from a scope signature.

    Enrichment blobs are "kept forever": a release bump must not orphan them
    (``scope_signature`` embeds the version for native read-first freshness,
    which is the wrong gate for the enrichment store).
    """
    import json as _json

    try:
        data = _json.loads(scope)
    except Exception:  # noqa: BLE001
        return scope
    if not isinstance(data, dict) or "app_version" not in data:
        return scope
    data.pop("app_version")
    return _json.dumps(data, sort_keys=True, separators=(",", ":"))


def _blob_scope_compatible(result_json: dict, expected: str | None) -> bool:
    """Whether a stored blob may be merged for a run carrying *expected* scope.

    ``None`` → always (callers that don't scope). A blob stamped with its own
    ``enrichment_scope`` must match exactly. A legacy/native blob without one is
    merged only when its product mode matches — mode-safe (no cross-mode leak,
    the Q2 guarantee) without discarding pre-F8 history.
    """
    if expected is None:
        return True
    meta = result_json.get("metadata") or {}
    stored = meta.get(ENRICHMENT_SCOPE_KEY)
    if isinstance(stored, str) and stored:
        return _strip_app_version(stored) == _strip_app_version(expected)
    import json as _json

    try:
        expected_mode = _json.loads(expected).get("mode")
    except Exception:  # noqa: BLE001
        return False
    return bool(expected_mode) and meta.get("mode") == expected_mode


# ===========================================================================
# F8a — harvest (subject = normalized domain)
# ===========================================================================


async def load_harvest_blobs(domain: str, *, scope: str | None) -> list[tuple[datetime, Any]]:
    """All scope-compatible harvest snapshots for *domain*, newest first.

    Each entry is ``(harvested_at, DomainHarvestResult)``. Scope-compatibility
    (mode + coverage envelope) reuses the same gate as read-first, so a
    different-mode or narrower crawl is never merged in. Never raises → ``[]``.
    """
    if not _enabled():
        return []
    try:
        from sqlalchemy import desc, select

        from ..db.database import AsyncSessionLocal
        from ..db.models import CrawlSnapshot
        from .corpus_store import (
            _ensure_schema,
            normalize_domain,
            sanitize_for_persistence,
        )
        from .harvest_cache import _deserialize_result

        await _ensure_schema()
        normalized = normalize_domain(domain)
        async with AsyncSessionLocal() as session:
            rows = (
                await session.execute(
                    select(CrawlSnapshot)
                    .where(CrawlSnapshot.domain == normalized)
                    .order_by(desc(CrawlSnapshot.harvested_at))
                )
            ).scalars().all()
        blobs: list[tuple[datetime, Any]] = []
        for row in rows:
            result_json = dict(row.result_json or {})
            if not _blob_scope_compatible(result_json, scope):
                continue
            result = sanitize_for_persistence(_deserialize_result(result_json))
            blobs.append((_aware(row.harvested_at) or _now(), result))
        return blobs
    except Exception:
        logger.exception("Enrichment store: harvest load failed for %s", domain)
        return []


async def should_fetch_netlas(domain: str, *, scope: str | None, refresh: bool = False) -> bool:
    """Whether a keyed Netlas fetch should run for *domain* this execution.

    ``True`` iff there is no scope-compatible Netlas-enriched blob, or the newest
    one is older than the refresh TTL, or ``refresh`` forces it. The key gate is
    the caller's (``netlas_active``); this is only the 30-day clock. Never raises
    → ``True`` (fail toward collecting, which is the pre-F8 behavior).
    """
    if refresh:
        return True
    if not _enabled():
        return True
    try:
        from sqlalchemy import desc, select

        from ..db.database import AsyncSessionLocal
        from ..db.models import CrawlSnapshot
        from .corpus_store import _ensure_schema, normalize_domain

        await _ensure_schema()
        normalized = normalize_domain(domain)
        async with AsyncSessionLocal() as session:
            rows = (
                await session.execute(
                    select(CrawlSnapshot)
                    .where(
                        CrawlSnapshot.domain == normalized,
                        CrawlSnapshot.netlas_enriched.is_(True),
                    )
                    .order_by(desc(CrawlSnapshot.netlas_fetched_at))
                )
            ).scalars().all()
        cutoff = _now() - _ttl()
        for row in rows:
            if not _blob_scope_compatible(dict(row.result_json or {}), scope):
                continue
            fetched = _aware(row.netlas_fetched_at) or _aware(row.harvested_at)
            if fetched is not None and fetched >= cutoff:
                return False  # fresh enrichment already on record
            break  # newest compatible blob is stale → fetch
        return True
    except Exception:
        logger.exception("Enrichment store: should_fetch check failed for %s", domain)
        return True


def merge_dedupe_harvest(current: Any, blobs: list[tuple[datetime, Any]]) -> Any:
    """Serve ``dedupe(current ∪ all historical blobs)`` for a harvest.

    Dedupe key = email (subaddress-normalized). The richest record wins (highest
    confidence), sources/URLs are unioned, and first/last-seen dates span all
    sightings. An email present only in a historical blob (not re-found this run)
    is annotated ``enriched_from_store`` + ``enriched_at=<capture date>`` and
    kept at its original provenance (we never relabel a native hit as Netlas).
    Never raises → returns *current* unchanged on error.
    """
    if not _enabled() or current is None:
        return current
    try:
        from .email_extraction import subaddress_key

        merged: dict[str, Any] = {}
        order: list[str] = []

        def _key(email: str) -> str:
            try:
                return subaddress_key(email)
            except Exception:
                return (email or "").strip().lower()

        for lead in getattr(current, "unique_emails", None) or []:
            k = _key(lead.email)
            if k not in merged:
                merged[k] = lead
                order.append(k)

        for captured_at, blob in blobs:
            stamp = captured_at.isoformat().replace("+00:00", "Z")
            for lead in getattr(blob, "unique_emails", None) or []:
                k = _key(lead.email)
                existing = merged.get(k)
                if existing is None:
                    enriched = replace(
                        lead,
                        first_seen_timestamp=lead.first_seen_timestamp or stamp,
                        last_seen_timestamp=lead.last_seen_timestamp or stamp,
                    )
                    _annotate_enriched(enriched, stamp)
                    merged[k] = enriched
                    order.append(k)
                else:
                    _fold_into(existing, lead)

        if len(merged) == len(getattr(current, "unique_emails", None) or []):
            # Nothing new from history — avoid rebuilding counts needlessly.
            return current
        return _rebuild_result(current, [merged[k] for k in order])
    except Exception:
        logger.exception("Enrichment store: harvest merge failed; serving native result")
        return current


def _annotate_enriched(lead: Any, stamp: str) -> None:
    """Mark a lead that was served from the store, not re-found this run."""
    try:
        lead.served_from_store = True  # type: ignore[attr-defined]
        lead.enriched_at = stamp  # type: ignore[attr-defined]
        bd = dict(lead.confidence_breakdown or {})
        bd["enriched_from_store"] = stamp
        lead.confidence_breakdown = bd
        if "netlas.io" not in lead.found_by_modules:
            # Record the store as a provenance source without erasing the original.
            lead.found_by_modules = [*lead.found_by_modules, "netlas.io"]
    except Exception:  # noqa: BLE001 - annotation must never break a merge
        pass


def _fold_into(keep: Any, other: Any) -> None:
    """Union an older sighting into the kept (fresh) record."""
    try:
        urls = list(keep.aggregated_source_urls)
        for u in other.aggregated_source_urls or []:
            if u and u not in urls:
                urls.append(u)
        keep.aggregated_source_urls = urls
        mods = list(keep.found_by_modules)
        for m in other.found_by_modules or []:
            if m and m not in mods:
                mods.append(m)
        keep.found_by_modules = mods
        # Span the sighting window across both records.
        for attr, pick in (("first_seen_timestamp", min), ("last_seen_timestamp", max)):
            a, b = getattr(keep, attr), getattr(other, attr)
            vals = [v for v in (a, b) if v]
            if vals:
                setattr(keep, attr, pick(vals))
    except Exception:  # noqa: BLE001
        pass


def _rebuild_result(current: Any, leads: list[Any]) -> Any:
    """A copy of *current* with the merged lead set and recomputed tier counts."""
    from dataclasses import replace as _replace

    def _count(label: str) -> int:
        return sum(1 for e in leads if str(e.confidence_label).upper() == label)

    likely = _count("LIKELY")
    return _replace(
        current,
        unique_emails=leads,
        total_unique_emails=len(leads),
        high_confidence_count=_count("CONFIRMED") + likely,
        likely_confidence_count=likely,
        medium_confidence_count=likely + _count("MEDIUM"),
        low_confidence_count=_count("LOW"),
        role_account_count=sum(1 for e in leads if e.is_role),
        personal_email_count=sum(1 for e in leads if not e.is_role),
    )


async def mark_blob_netlas_enriched(domain: str, *, scope: str | None) -> None:
    """Tag the newest matching snapshot as a Netlas-enrichment blob.

    Called only after a keyed Netlas fetch actually ran this execution, right
    after ``write_back`` appended the fresh snapshot. Sets ``netlas_enriched`` +
    ``netlas_fetched_at`` so the refresh clock counts it. Never raises.
    """
    if not _enabled():
        return
    try:
        from sqlalchemy import desc, select

        from ..db.database import AsyncSessionLocal
        from ..db.models import CrawlSnapshot
        from .corpus_store import normalize_domain

        normalized = normalize_domain(domain)
        async with AsyncSessionLocal() as session:
            async with session.begin():
                rows = (
                    await session.execute(
                        select(CrawlSnapshot)
                        .where(CrawlSnapshot.domain == normalized)
                        .order_by(desc(CrawlSnapshot.harvested_at))
                        .limit(5)
                    )
                ).scalars().all()
                for row in rows:
                    if _blob_scope_compatible(dict(row.result_json or {}), scope):
                        row.netlas_enriched = True
                        row.netlas_fetched_at = _now()
                        break
    except Exception:
        logger.exception("Enrichment store: could not mark blob for %s", domain)



def fetch_answered(statuses: dict[str, Any] | None) -> bool:
    """Whether a keyed Netlas fetch actually *answered* (success, possibly empty).

    The empty-result marker may only latch when Netlas answered cleanly: at least
    one source ``ok``/``empty`` and NO source failed (401/400/402/429/network).
    A transient failure must never latch a 30-day "checked, nothing there".
    """
    from .netlas_client import FAILURE_STATUSES, STATUS_EMPTY, STATUS_OK

    vals = {str(v) for v in (statuses or {}).values()}
    if not vals or vals & set(FAILURE_STATUSES):
        return False
    return bool(vals & {STATUS_OK, STATUS_EMPTY})


def harvest_netlas_answered(result: Any) -> bool:
    """Whether the harvest's keyed Netlas fetch (F1-F4) answered without failure."""
    statuses: dict[str, Any] = {}
    mr = getattr(result, "module_results", None) or {}
    for name in ("netlas_responses", "netlas_whois_emails", "netlas_cert"):
        meta = getattr(mr.get(name), "metadata", None) or {}
        st = (meta.get("netlas") or {}).get("status")
        if st:
            statuses[name] = st
    sub = getattr(mr.get("subdomain_intel"), "metadata", None) or {}
    st = ((sub.get("sources") or {}).get("netlas") or {}).get("status")
    if st:
        statuses["subdomains"] = st
    return fetch_answered(statuses)


__all__ = [
    "ENRICHMENT_SCOPE_KEY",
    "enrichment_scope",
    "load_harvest_blobs",
    "should_fetch_netlas",
    "merge_dedupe_harvest",
    "mark_blob_netlas_enriched",
    "fetch_answered",
    "harvest_netlas_answered",
]


# ===========================================================================
# F8b — investigate (subject = normalized email)
# ===========================================================================

from contextvars import ContextVar  # noqa: E402

#: The investigate-side Netlas modules (F6/F7). Only THESE findings are unioned
#: from history — native investigate output is never re-served (design Q3).
NETLAS_INVESTIGATE_MODULES = ("netlas_email_footprint", "netlas_org_surface")

#: Per-run ``--refresh`` (force a fetch past the 30-day gate), set at the start
#: of an investigation (same mechanism as ``set_no_netlas``).
_REFRESH_VAR: ContextVar[bool] = ContextVar("mailaccess_netlas_refresh", default=False)


def set_netlas_refresh(value: bool):
    """Set the current context's ``--refresh`` flag; returns the reset token."""
    return _REFRESH_VAR.set(bool(value))


def netlas_refresh() -> bool:
    return _REFRESH_VAR.get()


def normalize_investigate_subject(email: str) -> str:
    return str(email or "").strip().lower()


def finding_identity(data: dict) -> str:
    """Stable identity for an investigate finding (dedupe key).

    platform+handle · breach name · footprint/source URL · cve · domain — the
    first that applies, so the same public fact from two runs collapses to one.
    """
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    for key in ("source_url", "cve", "registered_domain", "certificate_names",
                "breach_name", "email"):
        v = meta.get(key)
        if isinstance(v, list):
            v = "|".join(str(x) for x in v)
        if v:
            return f"{meta.get('netlas_signal') or data.get('platform') or ''}:{v}".lower()
    platform = str(data.get("platform") or meta.get("source") or "")
    handle = str(meta.get("handle") or meta.get("username") or meta.get("summary") or "")
    return f"{platform}:{handle}".lower()


async def load_investigate_findings(email: str, module_name: str) -> list[tuple[datetime, dict]]:
    """Prior Netlas findings for *email* from *module_name*, newest first, deduped.

    Unconditional (key-independent). Only the two F6/F7 modules are eligible.
    Never raises → ``[]``.
    """
    if not _enabled() or module_name not in NETLAS_INVESTIGATE_MODULES:
        return []
    try:
        from sqlalchemy import desc, select

        from ..db.database import AsyncSessionLocal
        from ..db.models import Finding, Investigation

        subject = normalize_investigate_subject(email)
        async with AsyncSessionLocal() as session:
            rows = (
                await session.execute(
                    select(Finding.data, Finding.created_at)
                    .join(Investigation, Finding.investigation_id == Investigation.id)
                    .where(
                        Finding.module_name == module_name,
                        (Investigation.canonical_email == subject)
                        | (Investigation.email == subject),
                    )
                    .order_by(desc(Finding.created_at))
                )
            ).all()
        seen: dict[str, tuple[datetime, dict]] = {}
        for data, created_at in rows:
            if not isinstance(data, dict):
                continue
            if data.get("served_from_store"):
                continue  # an earlier run's served OUTPUT row, not store content
            ident = finding_identity(data)
            if ident not in seen:  # newest wins (ordered desc)
                seen[ident] = (_aware(created_at) or _now(), data)
        return list(seen.values())
    except Exception:
        logger.exception("Enrichment store: investigate load failed for %s", email)
        return []


async def should_fetch_investigate(email: str, module_name: str, *, refresh: bool = False) -> bool:
    """Whether *module_name* should fetch Netlas for *email* this run (30-day clock)."""
    if refresh:
        return True
    if not _enabled():
        return True
    try:
        from sqlalchemy import desc, select

        from ..db.database import AsyncSessionLocal
        from ..db.models import Finding, Investigation, ModuleRun

        subject = normalize_investigate_subject(email)
        async with AsyncSessionLocal() as session:
            frows = (
                await session.execute(
                    select(Finding.data, Finding.created_at)
                    .join(Investigation, Finding.investigation_id == Investigation.id)
                    .where(
                        Finding.module_name == module_name,
                        (Investigation.canonical_email == subject)
                        | (Investigation.email == subject),
                    )
                    .order_by(desc(Finding.created_at))
                )
            ).all()
            # Newest REAL (fetched) finding: served output rows must not restart
            # the 30-day clock.
            newest = next(
                (
                    c
                    for d, c in frows
                    if not (isinstance(d, dict) and d.get("served_from_store"))
                ),
                None,
            )
            # Empty-result marker: a clean keyed fetch that found nothing writes no
            # finding, so its ModuleRun (``netlas_fetched``) is the 30-day clock.
            runs = (
                await session.execute(
                    select(ModuleRun.run_metadata, ModuleRun.finished_at)
                    .join(Investigation, ModuleRun.investigation_id == Investigation.id)
                    .where(
                        ModuleRun.module_name == module_name,
                        (Investigation.canonical_email == subject)
                        | (Investigation.email == subject),
                    )
                    .order_by(desc(ModuleRun.finished_at))
                    .limit(50)
                )
            ).all()
        for meta, finished in runs:
            if isinstance(meta, dict) and meta.get("netlas_fetched") and finished is not None:
                if newest is None or (_aware(finished) or _now()) > (_aware(newest) or _now()):
                    newest = finished
                break  # newest-first: the first marker is the latest one
        if newest is None:
            return True
        return (_aware(newest) or _now()) < (_now() - _ttl())
    except Exception:
        logger.exception("Enrichment store: investigate fetch-check failed for %s", email)
        return True


def serve_from_store(stored: list[tuple[datetime, dict]]) -> list[dict]:
    """Annotate stored investigate findings as served-from-store (no key needed).

    Each is tagged ``served_from_store`` so (a) exports show provenance and
    (b) the engine skips RE-persisting it — a no-key run reads but never writes.
    """
    out: list[dict] = []
    for captured_at, data in stored:
        stamp = captured_at.isoformat().replace("+00:00", "Z")
        f = dict(data)
        meta = dict(f.get("metadata") or {})
        meta["served_from_store"] = True
        meta["enriched_at"] = stamp
        meta.setdefault("source", "netlas")
        meta["grade"] = "public source"
        f["metadata"] = meta
        f["served_from_store"] = True
        out.append(f)
    return out


def merge_investigate(fresh: list[dict], stored: list[tuple[datetime, dict]]) -> list[dict]:
    """Union fresh findings with stored-only ones (deduped by identity).

    Fresh findings are kept as-is (they will be persisted). Stored findings not
    re-found this run are appended, annotated + tagged ``served_from_store`` so
    the engine does not re-write them.
    """
    fresh_ids = {finding_identity(f) for f in fresh}
    extra = [(c, d) for c, d in stored if finding_identity(d) not in fresh_ids]
    return [*fresh, *serve_from_store(extra)]


__all__ += [  # noqa: F821
    "NETLAS_INVESTIGATE_MODULES",
    "set_netlas_refresh",
    "netlas_refresh",
    "finding_identity",
    "load_investigate_findings",
    "should_fetch_investigate",
    "serve_from_store",
    "merge_investigate",
]
