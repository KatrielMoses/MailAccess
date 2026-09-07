"""product mode (phase 2b)

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-06

Phase 2B — product-mode separation (the governance keystone). Records the
collection *product mode* of every run so a fact's collection mode is always
known:

* ``observations.mode`` — the mode each ledger observation was collected under
  (indexed; excluded from ``content_hash`` so identical evidence hashes the same
  regardless of mode);
* ``investigations.mode`` — the mode an investigation was run under (run
  manifest);
* ``crawl_snapshots.mode`` — the mode a harvest crawl was run under (run
  manifest).

Additive only. All three default to ``"security-investigation"`` (today's
behavior, renamed) so existing rows and any create_all-built pre-Alembic DB are
backfilled correctly. Guarded/idempotent: a column is added only if absent,
consistent with the Phase 1A stamp-and-reconcile model.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DEFAULT = "security-investigation"
# (table, column, add_index) — the mode column lands on each of these.
_MODE_COLUMNS: tuple[tuple[str, str, bool], ...] = (
    ("observations", "mode", True),
    ("investigations", "mode", False),
    ("crawl_snapshots", "mode", False),
)
_INDEX_NAME = "ix_observations_mode"


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    tables = _existing_tables()
    for table, column, add_index in _MODE_COLUMNS:
        if table not in tables:
            # Table itself absent (partial/older DB) — the create migration owns
            # the column; nothing to add here.
            continue
        if column not in _columns(table):
            op.add_column(
                table,
                sa.Column(
                    column,
                    sa.String(),
                    nullable=False,
                    server_default=_DEFAULT,
                ),
            )
        if add_index:
            existing_idx = {
                ix["name"] for ix in sa.inspect(op.get_bind()).get_indexes(table)
            }
            if _INDEX_NAME not in existing_idx:
                op.create_index(_INDEX_NAME, table, [column], unique=False)


def downgrade() -> None:
    tables = _existing_tables()
    for table, column, add_index in reversed(_MODE_COLUMNS):
        if table not in tables:
            continue
        if add_index:
            existing_idx = {
                ix["name"] for ix in sa.inspect(op.get_bind()).get_indexes(table)
            }
            if _INDEX_NAME in existing_idx:
                op.drop_index(_INDEX_NAME, table_name=table)
        if column in _columns(table):
            op.drop_column(table, column)
