from __future__ import annotations

import re
from collections.abc import AsyncGenerator
from pathlib import Path

from sqlalchemy import inspect, text
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


async def init_db() -> None:
    """Create all tables if they don't exist. Called once at app startup."""
    _ensure_db_dir()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_migrate_add_graph_data)
        await conn.run_sync(_migrate_add_credential_risk_score)
        await conn.run_sync(_migrate_add_canonical_email)
        await conn.run_sync(_migrate_add_timeline_json)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a scoped async DB session."""
    async with AsyncSessionLocal() as session:
        yield session
