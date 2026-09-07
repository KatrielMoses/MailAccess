"""lead person fields + deliverability (phase 3)

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-06

Phase 3 — turn the ``contacts`` projection from an email row into a servable
*Lead*. Adds:

* Phase 3A person fields — ``full_name``, ``first_name``, ``last_name``,
  ``job_title``, ``seniority``, ``department``, ``linkedin_url``, ``phone``,
  ``location`` (each evidence-or-null) plus ``person_field_provenance`` (JSON: the
  per-field evidence link the 1E resolver produced).
* Phase 3C/3D deliverability — ``deliverability_score`` (Float) and
  ``deliverability_grade`` (String).

This is the FIRST migration to add columns to ``contacts`` (created whole in
0004). All columns are nullable/additive — existing rows and any create_all-built
pre-Alembic DB read back correctly. Guarded/idempotent (add a column/index only
if absent), consistent with the Phase 1A stamp-and-reconcile model. ``seniority``,
``department`` and ``deliverability_grade`` are indexed — they are the primary
lead-filter dimensions.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "contacts"

# (column, sqlalchemy type, index_name-or-None)
_COLUMNS: tuple[tuple[str, sa.types.TypeEngine, str | None], ...] = (
    ("full_name", sa.String(), None),
    ("first_name", sa.String(), None),
    ("last_name", sa.String(), None),
    ("job_title", sa.String(), None),
    ("seniority", sa.String(), "ix_contacts_seniority"),
    ("department", sa.String(), "ix_contacts_department"),
    ("linkedin_url", sa.String(), None),
    ("phone", sa.String(), None),
    ("location", sa.String(), None),
    ("person_field_provenance", sa.JSON(), None),
    ("deliverability_score", sa.Float(), None),
    ("deliverability_grade", sa.String(), "ix_contacts_deliverability_grade"),
)


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def _indexes(table: str) -> set[str]:
    return {ix["name"] for ix in sa.inspect(op.get_bind()).get_indexes(table)}


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if _TABLE not in _existing_tables():
        return
    existing = _columns(_TABLE)
    for name, coltype, _ in _COLUMNS:
        if name not in existing:
            op.add_column(_TABLE, sa.Column(name, coltype, nullable=True))
    existing_idx = _indexes(_TABLE)
    for name, _, index_name in _COLUMNS:
        if index_name and index_name not in existing_idx:
            op.create_index(index_name, _TABLE, [name], unique=False)


def downgrade() -> None:
    if _TABLE not in _existing_tables():
        return
    existing_idx = _indexes(_TABLE)
    for name, _, index_name in reversed(_COLUMNS):
        if index_name and index_name in existing_idx:
            op.drop_index(index_name, table_name=_TABLE)
    existing = _columns(_TABLE)
    # SQLite < 3.35 needs batch mode for drop_column.
    with op.batch_alter_table(_TABLE) as batch:
        for name, _, _idx in reversed(_COLUMNS):
            if name in existing:
                batch.drop_column(name)
