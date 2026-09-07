"""Phase 2E — a tamper-evident audit log of governance actions.

Integrity is a hash chain: each entry stores ``entry_hash = sha256(prev_hash +
canonical(payload))`` where the payload is the entry's own (seq, action, subject,
details, created_at). Any later mutation or deletion of a row breaks the chain
from that point on, which :func:`verify` detects. Appends are best-effort — a
logging failure must never break the governance action being recorded.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select

from ..db.database import AsyncSessionLocal, init_db
from ..db.models import AuditLogEntry

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64

# Canonical governance action names.
ACTION_SUPPRESSION_ADD = "suppression.add"
ACTION_TAKEDOWN = "record.takedown"
ACTION_DELETION = "record.deletion"
ACTION_RETENTION_PURGE = "retention.purge"
ACTION_COLLECTION = "run.collection"
ACTION_EXPORT = "export.emit"


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _canonical_ts(value: datetime) -> str:
    # Canonical, tz-stable timestamp string. The DB backend (SQLite) returns
    # naive datetimes even for tz-aware columns, so an aware write and a naive
    # read must hash identically: normalize both to naive-UTC microsecond form.
    ts = value
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")


def _entry_hash(
    prev_hash: str,
    *,
    seq: int,
    action: str,
    subject: str | None,
    details: dict | None,
    created_at: datetime,
) -> str:
    payload = _canonical(
        {
            "seq": seq,
            "action": action,
            "subject": subject,
            "details": details,
            "created_at": _canonical_ts(created_at),
        }
    )
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


async def append(
    action: str, *, subject: str | None = None, details: dict | None = None
) -> bool:
    """Append one governance action to the chain. Best-effort: returns False and
    logs on any failure rather than raising into the caller."""
    try:
        await init_db()
        async with AsyncSessionLocal() as session:
            async with session.begin():
                last = (
                    await session.execute(
                        select(AuditLogEntry).order_by(AuditLogEntry.seq.desc()).limit(1)
                    )
                ).scalar_one_or_none()
                seq = 0 if last is None else int(last.seq) + 1
                prev_hash = GENESIS_HASH if last is None else str(last.entry_hash)
                created_at = datetime.now(timezone.utc)
                entry_hash = _entry_hash(
                    prev_hash,
                    seq=seq,
                    action=action,
                    subject=subject,
                    details=details,
                    created_at=created_at,
                )
                session.add(
                    AuditLogEntry(
                        seq=seq,
                        action=action,
                        subject=subject,
                        details=details,
                        prev_hash=prev_hash,
                        entry_hash=entry_hash,
                        created_at=created_at,
                    )
                )
        return True
    except Exception:
        logger.exception("audit_log append failed for action %s", action)
        return False


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    entries: int
    broken_at_seq: int | None  # first seq whose hash/link does not verify


async def verify() -> ChainVerification:
    """Recompute the chain and confirm every link. A mutated or deleted row
    surfaces as ``ok=False`` with the first broken sequence number."""
    await init_db()
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(select(AuditLogEntry).order_by(AuditLogEntry.seq.asc()))
        ).scalars().all()
    prev_hash = GENESIS_HASH
    for i, row in enumerate(rows):
        # Sequence must be contiguous (a deleted row leaves a gap).
        if int(row.seq) != i:
            return ChainVerification(False, len(rows), int(row.seq))
        expected = _entry_hash(
            prev_hash,
            seq=int(row.seq),
            action=str(row.action),
            subject=row.subject,
            details=row.details,
            created_at=row.created_at,
        )
        if expected != str(row.entry_hash) or str(row.prev_hash) != prev_hash:
            return ChainVerification(False, len(rows), int(row.seq))
        prev_hash = str(row.entry_hash)
    return ChainVerification(True, len(rows), None)


async def count() -> int:
    await init_db()
    async with AsyncSessionLocal() as session:
        return int(
            (await session.execute(select(func.count()).select_from(AuditLogEntry))).scalar_one()
        )
