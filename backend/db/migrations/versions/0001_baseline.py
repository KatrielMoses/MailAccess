"""baseline: core investigations / module_runs / findings schema

Revision ID: 0001
Revises:
Create Date: 2026-09-05

Captures the MailAccess schema as it existed *before* the hand-rolled startup
``ALTER TABLE … ADD COLUMN`` sequence that lived in ``backend/db/database.py``
(the ``_migrate_add_*`` helpers). Those incremental columns are versioned
separately in revision ``0002`` — so this baseline plus ``0002`` reproduces the
full v0.14.4 schema exactly, while giving a real, reversible split to test
downgrades against.

Fresh databases run this ``upgrade()`` to create the core tables. Pre-existing
(pre-Alembic) databases are *stamped* at this revision by ``init_db`` instead of
re-running it — their tables already exist — and then reconciled forward by
``0002``.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Matches SQLAlchemy's SAEnum(InvestigationStatus): stores the member *names*,
# create_constraint=False (no CHECK on SQLite; a native ENUM type on Postgres).
_STATUS_ENUM = sa.Enum(
    "PENDING",
    "RUNNING",
    "COMPLETE",
    "FAILED",
    name="investigationstatus",
    create_constraint=False,
)


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("status", _STATUS_ENUM, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exposure_score", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_investigations_email", "investigations", ["email"])

    op.create_table(
        "module_runs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("investigation_id", sa.String(), nullable=False),
        sa.Column("module_name", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("run_metadata", sa.JSON(), nullable=True),
        sa.Column("errors", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_module_runs_investigation_id", "module_runs", ["investigation_id"])
    op.create_index("ix_module_runs_module_name", "module_runs", ["module_name"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("investigation_id", sa.String(), nullable=False),
        sa.Column("module_name", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_investigation_id", "findings", ["investigation_id"])
    op.create_index("ix_findings_module_name", "findings", ["module_name"])


def downgrade() -> None:
    op.drop_index("ix_findings_module_name", table_name="findings")
    op.drop_index("ix_findings_investigation_id", table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_module_runs_module_name", table_name="module_runs")
    op.drop_index("ix_module_runs_investigation_id", table_name="module_runs")
    op.drop_table("module_runs")

    op.drop_index("ix_investigations_email", table_name="investigations")
    op.drop_table("investigations")

    # Postgres materialises the enum as a standalone type; drop it too so the
    # downgrade is a clean round-trip. No-op on SQLite (enum is just VARCHAR).
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        _STATUS_ENUM.drop(bind, checkfirst=True)
