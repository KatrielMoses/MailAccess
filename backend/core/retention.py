"""Phase 2E — retention & expiry.

Purges expired ledger observations and their raw payloads, honoring each
observation's ``expires_at`` (set from the per-source TTL in 1C, which the 2B
per-mode retention policy governs). Every purge is written to the tamper-evident
audit log. Exposed as ``mailaccess retention run``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import delete, func, select

from ..db.database import AsyncSessionLocal, init_db
from ..db.models import Investigation, Observation, ObservationRawPayload, RunEvent
from . import audit_log

logger = logging.getLogger(__name__)


async def _count_expired(session, model, now: datetime) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(model)
                .where(model.expires_at.is_not(None), model.expires_at < now)
            )
        ).scalar_one()
    )


async def purge_run_events(session, now: datetime, *, dry_run: bool = False) -> int:
    """Delete saved run events for runs older than the report retention of their mode."""
    from datetime import timedelta

    from .product_mode import ProductMode, retention_policy

    total = 0
    for mode in ProductMode:
        ttl = retention_policy(mode).ttl_days
        if ttl <= 0:
            continue
        cutoff = now - timedelta(days=ttl)
        old_runs = select(Investigation.id).where(
            Investigation.mode == mode.value, Investigation.created_at < cutoff
        )
        count = int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(RunEvent)
                    .where(RunEvent.investigation_id.in_(old_runs))
                )
            ).scalar_one()
        )
        total += count
        if count and not dry_run:
            await session.execute(
                delete(RunEvent).where(RunEvent.investigation_id.in_(old_runs))
            )
    return total


async def run_retention(*, dry_run: bool = False, now: datetime | None = None) -> dict:
    """Purge observations and raw payloads whose ``expires_at`` has passed.

    Returns a summary. With ``dry_run`` it only counts. Raw payloads are purged
    first (child rows), then observations.
    """
    await init_db()
    now = now or datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        async with session.begin():
            raw_expired = await _count_expired(session, ObservationRawPayload, now)
            obs_expired = await _count_expired(session, Observation, now)
            if not dry_run:
                if raw_expired:
                    await session.execute(
                        delete(ObservationRawPayload).where(
                            ObservationRawPayload.expires_at.is_not(None),
                            ObservationRawPayload.expires_at < now,
                        )
                    )
                if obs_expired:
                    # Purge raw payloads of the observations being deleted first
                    # (FK), then the observations themselves.
                    expiring_ids = (
                        await session.execute(
                            select(Observation.id).where(
                                Observation.expires_at.is_not(None),
                                Observation.expires_at < now,
                            )
                        )
                    ).scalars().all()
                    if expiring_ids:
                        await session.execute(
                            delete(ObservationRawPayload).where(
                                ObservationRawPayload.observation_id.in_(expiring_ids)
                            )
                        )
                    await session.execute(
                        delete(Observation).where(
                            Observation.expires_at.is_not(None),
                            Observation.expires_at < now,
                        )
                    )
    async with AsyncSessionLocal() as session:
        async with session.begin():
            events_expired = await purge_run_events(session, now, dry_run=dry_run)
    summary = {
        "run_events_purged": 0 if dry_run else events_expired,
        "run_events_expired": events_expired,
        "observations_purged": 0 if dry_run else obs_expired,
        "raw_payloads_purged": 0 if dry_run else raw_expired,
        "observations_expired": obs_expired,
        "raw_payloads_expired": raw_expired,
        "dry_run": dry_run,
    }
    if not dry_run and (obs_expired or raw_expired or events_expired):
        await audit_log.append(audit_log.ACTION_RETENTION_PURGE, details=summary)
    return summary
