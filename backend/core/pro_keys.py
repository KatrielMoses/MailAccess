"""0.17.0 Phase 1 — the MailAccess Pro entitlement store.

Billing (Phase 5, Stripe webhooks) issues keys later; Phase 1 needs a place to
validate a presented Pro key against. Keys are stored **hashed** (SHA-256), never
in the clear, so a database dump can never leak a live credential.

The public surface is deliberately tiny and stable so Phase 5 is a drop-in
replacement of the *population* path (``add_pro_key`` → Stripe webhook) with no
change to the *validation* path (``validate_pro_key``):

* ``validate_pro_key(key)`` — True iff an ``active`` row exists whose hash matches.
* ``add_pro_key(key, notes=...)`` — insert (idempotent per hash); manual admin.
* ``deactivate_pro_key(key)`` / ``list_pro_keys()`` — operator management.

``validate_pro_key`` fails **closed**: any store error returns ``False`` (the
route turns an absent/invalid entitlement into a uniform 401), never True.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from sqlalchemy import delete, select, update

from ..db.database import AsyncSessionLocal, init_db
from ..db.models import ProKey

_VALID_STATUSES = frozenset({"active", "suspended", "revoked"})

_LOG = logging.getLogger(__name__)


def hash_key(key: str) -> str:
    """The stored match key for a raw Pro key. Never store/log the raw key."""
    return hashlib.sha256((key or "").encode("utf-8")).hexdigest()


def _is_sha256_hex(digest: str) -> bool:
    """Whether *digest* is a well-formed 64-char SHA-256 hex string (case-insensitive)."""
    return (
        isinstance(digest, str)
        and len(digest) == 64
        and all(c in "0123456789abcdef" for c in digest.lower())
    )


def _is_expired(expires_at: datetime | None) -> bool:
    """Whether an expiry has passed. ``None`` never expires. Naive datetimes are
    treated as UTC (SQLite may drop tzinfo on round-trip)."""
    if expires_at is None:
        return False
    exp = expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp <= datetime.now(timezone.utc)


async def validate_pro_key(key: str | None) -> bool:
    """Whether *key* corresponds to an ``active`` entitlement row.

    Fails closed: an empty key, a missing table, or any store error returns
    ``False`` rather than raising, so the caller can render a uniform 401 without
    leaking whether a key exists-but-inactive vs. never-existed.

    P2(d) — the absent-key path does the SAME work as a supplied-but-invalid one
    (hash + a store lookup against the resulting digest), so the two are not timing-
    distinguishable. The absent path still fails closed regardless of the lookup.
    """
    # Hash unconditionally (empty string for an absent key), then run the SAME store
    # lookup, so an absent key is not conspicuously faster than a supplied one.
    digest = hash_key(key or "")
    try:
        await init_db()  # ensure the pro_keys table exists (harvest/CLI paths)
        async with AsyncSessionLocal() as session:
            row = (
                await session.execute(select(ProKey).where(ProKey.key_hash == digest))
            ).scalar_one_or_none()
    except Exception:  # pragma: no cover - defensive: fail closed on store error
        _LOG.exception("pro-key validation failed; denying (fail-closed)")
        return False
    if not key or row is None:
        return False  # absent key always fails closed, even on a freak hash hit
    # Authoritative access decision: only an ``active`` (not suspended/revoked) and
    # not-yet-expired row grants access. ``status`` and ``expires_at`` are honored
    # here so an admin suspend/revoke and a test key's 30-day cap take effect at the
    # CLI/`/v1/enrich` boundary, not only in the website.
    if getattr(row, "status", "active") != "active" or not row.active:
        return False
    return not _is_expired(row.expires_at)


async def add_pro_key(key: str, *, notes: str | None = None, active: bool = True) -> bool:
    """Insert an entitlement for *key* (stored hashed). Idempotent per hash.

    Returns True if a new row was created, False if the hash already existed (in
    which case ``active``/``notes`` are left untouched — use
    :func:`deactivate_pro_key` to revoke). Phase 5 replaces this call site with a
    Stripe webhook; the interface stays put.
    """
    if not key:
        raise ValueError("refusing to add an empty Pro key")
    digest = hash_key(key)
    await init_db()
    async with AsyncSessionLocal() as session:
        async with session.begin():
            exists = (
                await session.execute(
                    select(ProKey.id).where(ProKey.key_hash == digest)
                )
            ).first()
            if exists:
                return False
            session.add(ProKey(key_hash=digest, active=active, notes=notes))
    return True


async def deactivate_pro_key(key: str) -> bool:
    """Revoke an entitlement (``active=False``, ``status='revoked'``). Returns True
    if a row changed."""
    if not key:
        return False
    digest = hash_key(key)
    await init_db()
    async with AsyncSessionLocal() as session:
        async with session.begin():
            result = await session.execute(
                update(ProKey)
                .where(ProKey.key_hash == digest)
                .values(active=False, status="revoked")
            )
    return bool(result.rowcount)


async def add_pro_key_hash(
    digest: str,
    *,
    notes: str | None = None,
    expires_at: datetime | None = None,
) -> bool:
    """Insert an entitlement by its precomputed SHA-256 hash (the raw key never
    transits). Used by the internal provisioning bridge (§ pro_internal route) so
    the website's key store and THIS validation store stay in sync.

    Idempotent per hash. Returns True if a new row was created. If the hash already
    exists it is (re)activated — ``status='active'`` — and ``expires_at``/``notes``
    are refreshed when supplied (a re-provision of a previously-suspended/revoked
    or renewed subscription), returning False (not newly created).
    """
    if not _is_sha256_hex(digest):
        raise ValueError("key_hash must be a 64-char SHA-256 hex digest")
    d = digest.lower()
    await init_db()
    async with AsyncSessionLocal() as session:
        async with session.begin():
            existing = (
                await session.execute(select(ProKey).where(ProKey.key_hash == d))
            ).scalar_one_or_none()
            if existing is not None:
                existing.status = "active"
                existing.active = True
                if expires_at is not None:
                    existing.expires_at = expires_at
                if notes is not None:
                    existing.notes = notes
                return False
            session.add(
                ProKey(
                    key_hash=d,
                    active=True,
                    status="active",
                    expires_at=expires_at,
                    notes=notes,
                )
            )
    return True


async def set_pro_key_status_hash(digest: str, status: str) -> bool:
    """Set an entitlement's lifecycle status by hash (``suspended``/``revoked`` to
    cut access, ``active`` to restore). Keeps ``active`` mirrored. Returns True if a
    row changed. Suspend is reversible; revoke is a permanent admin decision."""
    if status not in _VALID_STATUSES:
        raise ValueError(f"status must be one of {sorted(_VALID_STATUSES)}")
    if not _is_sha256_hex(digest):
        return False
    d = digest.lower()
    await init_db()
    async with AsyncSessionLocal() as session:
        async with session.begin():
            result = await session.execute(
                update(ProKey)
                .where(ProKey.key_hash == d)
                .values(status=status, active=(status == "active"))
            )
    return bool(result.rowcount)


async def delete_pro_key_hash(digest: str) -> bool:
    """Hard-delete an entitlement row by hash. Returns True if a row was removed."""
    if not _is_sha256_hex(digest):
        return False
    d = digest.lower()
    await init_db()
    async with AsyncSessionLocal() as session:
        async with session.begin():
            result = await session.execute(delete(ProKey).where(ProKey.key_hash == d))
    return bool(result.rowcount)


async def deactivate_pro_key_hash(digest: str) -> bool:
    """Revoke an entitlement by its SHA-256 hash (compat shim → status='revoked')."""
    return await set_pro_key_status_hash(digest, "revoked")


async def list_pro_keys() -> list[dict]:
    """List entitlements (hash prefix + status only — never a raw key)."""
    await init_db()
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(select(ProKey))).scalars().all()
    return [
        {
            "key_hash_prefix": r.key_hash[:12],
            "active": r.active,
            "status": getattr(r, "status", "active"),
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "notes": r.notes,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
