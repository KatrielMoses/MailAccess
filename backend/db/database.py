from __future__ import annotations

import re
from collections.abc import AsyncGenerator
from pathlib import Path

from sqlalchemy import func, inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import settings
from .models import Base

engine = create_async_engine(settings.database_url, echo=settings.debug)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


def _ensure_db_dir() -> None:
    """Create parent directory for SQLite databases if it doesn't exist."""
    m = re.search(r"sqlite(?:\+\w+)?:///(.+)", settings.database_url)
    if m:
        Path(m.group(1)).parent.mkdir(parents=True, exist_ok=True)


def _migrate_add_graph_data(sync_conn) -> None:
    """Add graph_data JSON column to investigations if missing (existing DBs)."""
    inspector = inspect(sync_conn)
    if "investigations" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("investigations")}
    if "graph_data" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN graph_data JSON")
        )


def _migrate_add_credential_risk_score(sync_conn) -> None:
    """Add credential_risk_score column to investigations if missing."""
    inspector = inspect(sync_conn)
    if "investigations" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("investigations")}
    if "credential_risk_score" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN credential_risk_score INTEGER")
        )


def _migrate_add_canonical_email(sync_conn) -> None:
    """Add canonical_email column to investigations if missing."""
    inspector = inspect(sync_conn)
    if "investigations" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("investigations")}
    if "canonical_email" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN canonical_email VARCHAR")
        )


def _migrate_add_timeline_json(sync_conn) -> None:
    """Add timeline_json column to investigations if missing."""
    inspector = inspect(sync_conn)
    if "investigations" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("investigations")}
    if "timeline_json" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN timeline_json JSON")
        )


def _migrate_add_defenders_brief(sync_conn) -> None:
    """Add defenders_brief_json column to investigations if missing."""
    inspector = inspect(sync_conn)
    if "investigations" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("investigations")}
    if "defenders_brief_json" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN defenders_brief_json JSON")
        )


def _migrate_add_name_consensus(sync_conn) -> None:
    """Add name consensus columns to investigations if missing."""
    inspector = inspect(sync_conn)
    if "investigations" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("investigations")}
    if "confirmed_name" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN confirmed_name VARCHAR")
        )
    if "name_confidence" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN name_confidence VARCHAR")
        )
    if "name_reasoning" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN name_reasoning VARCHAR")
        )
    if "name_sources" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN name_sources JSON")
        )


def _migrate_add_recovery_fields(sync_conn) -> None:
    """Add investigation lifecycle fields used by startup recovery."""
    inspector = inspect(sync_conn)
    if "investigations" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("investigations")}
    if "started_at" not in columns:
        sync_conn.execute(
            text("ALTER TABLE investigations ADD COLUMN started_at DATETIME")
        )
    if "error" not in columns:
        sync_conn.execute(text("ALTER TABLE investigations ADD COLUMN error VARCHAR"))


async def init_db() -> None:
    """Create all tables if they don't exist. Called once at app startup."""
    _ensure_db_dir()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_migrate_add_graph_data)
        await conn.run_sync(_migrate_add_credential_risk_score)
        await conn.run_sync(_migrate_add_canonical_email)
        await conn.run_sync(_migrate_add_timeline_json)
        await conn.run_sync(_migrate_add_defenders_brief)
        await conn.run_sync(_migrate_add_name_consensus)
        await conn.run_sync(_migrate_add_recovery_fields)
    await _clean_stale_investigations()


async def _clean_stale_investigations() -> None:
    """Mark zombie investigations (stuck in RUNNING for >10 min) as FAILED.

    Called on every server startup to prevent stale investigation records from
    accumulating in the database after crashes or hangs.
    """
    from .models import Investigation, InvestigationStatus

    stale_threshold_minutes = 10
    async with AsyncSessionLocal() as session:
        async with session.begin():
            from datetime import datetime, timedelta, timezone
            from sqlalchemy import update

            cutoff = datetime.now(timezone.utc) - timedelta(minutes=stale_threshold_minutes)
            result = await session.execute(
                update(Investigation)
                .where(
                    Investigation.status == InvestigationStatus.RUNNING,
                    func.coalesce(
                        Investigation.started_at,
                        Investigation.created_at,
                    ) < cutoff,
                )
                .values(
                    status=InvestigationStatus.FAILED,
                    error="Recovered: server restart",
                    completed_at=datetime.now(timezone.utc),
                )
            )
            if result.rowcount > 0:
                import logging
                logging.getLogger(__name__).warning(
                    "Cleaned %d stale zombie investigation(s) on startup.", result.rowcount
                )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a scoped async DB session."""
    async with AsyncSessionLocal() as session:
        yield session
