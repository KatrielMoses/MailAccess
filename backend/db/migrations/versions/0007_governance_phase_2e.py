"""retention, takedown, audit log & run manifest (phase 2e)

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-06

Phase 2E — retention, deletion & reproducibility governance. Adds three tables:

* ``audit_log`` — a tamper-evident hash chain of governance actions;
* ``takedowns`` — per-record deletions/takedowns (recorded so a re-collection
  can be suppressed);
* ``run_manifests`` — the reproducible per-run manifest (config/module versions,
  mode, corpus version, seed) underpinning the W3C PROV export.

Additive only, guarded/idempotent creates (skip a table that already exists),
consistent with the Phase 1A stamp-and-reconcile model.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEXES: dict[str, tuple[tuple[str, str, bool], ...]] = {
    "audit_log": (("ix_audit_log_seq", "seq", True), ("ix_audit_log_action", "action", False)),
    "takedowns": (("ix_takedowns_subject", "subject", False),),
    "run_manifests": (("ix_run_manifests_run_id", "run_id", False),),
}
_CREATE_ORDER = ("audit_log", "takedowns", "run_manifests")


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _indexes(table: str) -> None:
    for name, column, unique in _INDEXES[table]:
        op.create_index(name, table, [column], unique=unique)


def _create_audit_log() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("prev_hash", sa.String(), nullable=False),
        sa.Column("entry_hash", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_takedowns() -> None:
    op.create_table(
        "takedowns",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("subject_type", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("removed_ref", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_run_manifests() -> None:
    op.create_table(
        "run_manifests",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("pipeline", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("app_version", sa.String(), nullable=False),
        sa.Column("config_fingerprint", sa.String(), nullable=True),
        sa.Column("module_versions", sa.JSON(), nullable=True),
        sa.Column("source_policy", sa.String(), nullable=True),
        sa.Column("corpus_version", sa.String(), nullable=True),
        sa.Column("seed", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


_CREATORS = {
    "audit_log": _create_audit_log,
    "takedowns": _create_takedowns,
    "run_manifests": _create_run_manifests,
}


def upgrade() -> None:
    existing = _existing_tables()
    for table in _CREATE_ORDER:
        if table not in existing:
            _CREATORS[table]()
            _indexes(table)


def downgrade() -> None:
    existing = _existing_tables()
    for table in reversed(_CREATE_ORDER):
        if table in existing:
            for name, _column, _unique in _INDEXES[table]:
                op.drop_index(name, table_name=table)
            op.drop_table(table)
