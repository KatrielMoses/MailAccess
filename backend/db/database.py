from __future__ import annotations

import re
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import func, inspect
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import settings

if TYPE_CHECKING:
    from alembic.config import Config

engine = create_async_engine(settings.database_url, echo=settings.debug)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

# Alembic migration environment lives beside this module (backend/db/migrations).
_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def _ensure_db_dir() -> None:
    """Create parent directory for SQLite databases if it doesn't exist."""
    m = re.search(r"sqlite(?:\+\w+)?:///(.+)", settings.database_url)
    if m:
        Path(m.group(1)).parent.mkdir(parents=True, exist_ok=True)


def _alembic_config(connection: Connection) -> Config:
    """Build an Alembic Config bound to a live (sync) connection.

    Constructed programmatically with an absolute ``script_location`` rather than
    read from ``alembic.ini`` so it is independent of the current working
    directory (investigate/harvest runs can execute under an isolated cwd). The
    shared connection is what lets migrations run on the app's async engine via
    ``run_sync`` without a second engine or a nested event loop.
    """
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    cfg.attributes["connection"] = connection
    return cfg


def _apply_migrations(connection: Connection) -> None:
    """Bring the database up to the head revision (runs inside ``run_sync``)."""
    from alembic import command

    cfg = _alembic_config(connection)
    tables = set(inspect(connection).get_table_names())

    if "alembic_version" not in tables and "investigations" in tables:
        # Pre-Alembic database: the tables already exist from the legacy
        # create_all + ADD COLUMN startup path. Stamp it at the baseline so
        # 0001's create_table is skipped; the guarded 0002 then reconciles any
        # missing enrichment columns / indexes idempotently up to head.
        command.stamp(cfg, "0001")

    command.upgrade(cfg, "head")


async def init_db() -> None:
    """Apply schema migrations, then recover zombie investigations.

    Replaces the former ``create_all`` + hand-rolled ``ALTER TABLE`` startup
    sequence with versioned Alembic migrations. A fresh database is built from
    the ``0001`` baseline forward; an existing (pre-Alembic) v0.14.x database is
    stamped and reconciled to head — both converge on the same schema.
    """
    _ensure_db_dir()
    # engine.begin() (not connect()): we introspect the connection to decide
    # whether to stamp a pre-Alembic DB, which autobegins a transaction in
    # SQLAlchemy 2.0. begin() owns that transaction and commits it on exit, so
    # Alembic's writes (the version table + DDL) are durably committed; a bare
    # connect() would leave them to be rolled back at context exit.
    async with engine.begin() as conn:
        await conn.run_sync(_apply_migrations)
    await _clean_stale_investigations()


async def _clean_stale_investigations() -> None:
    """Mark zombie investigations (stuck in RUNNING for >10 min) as FAILED.

    Called on every server startup to prevent stale investigation records from
    accumulating in the database after crashes or hangs.

    Multi-process caveat: this is a best-effort startup sweep with a 10-minute
    grace window. Under a future multi-process deployment two workers could both
    run it, but the ``UPDATE`` is idempotent (it only ever flips RUNNING ->
    FAILED for rows past the cutoff) so a double run is harmless. It does *not*
    guard against a healthy long-running investigation on another live worker;
    tightening that (e.g. an owner/heartbeat column) is deferred, not solved
    here.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import update

    from .models import Investigation, InvestigationStatus

    stale_threshold_minutes = 10
    async with AsyncSessionLocal() as session:
        async with session.begin():
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
