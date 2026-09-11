"""contact verification status (0.16.0 phase 4)

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-11

0.16.0 Phase 4 — wire the corpus company email-pattern inference through to the
servable Lead. A pattern email is an *inference*, never a confirmed address, so
it carries ``verification="unverified"``; the eligibility gate reads that to cap
the lead at REVIEW (a learned-pattern guess is never a ready-to-send lead on its
own). The ``contacts`` projection dropped this signal — this migration adds one
nullable ``verification`` column so it survives into ``read_leads`` / ``/api/leads``.

``NULL`` (the default, and the value for every observed address) means "no
verification claim asserted" — the eligibility gate stays inert and the lead's
verdict is decided by confidence + grade exactly as before (zero regression).

Additive + guarded/idempotent (add the column only if absent), consistent with
the 0008 column-add pattern; existing rows and any create_all-built pre-Alembic
DB read back correctly.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "contacts"
_COLUMN = "verification"


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if _TABLE not in _existing_tables():
        return
    if _COLUMN not in _columns(_TABLE):
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.String(), nullable=True))


def downgrade() -> None:
    if _TABLE not in _existing_tables():
        return
    if _COLUMN in _columns(_TABLE):
        # SQLite < 3.35 needs batch mode for drop_column.
        with op.batch_alter_table(_TABLE) as batch:
            batch.drop_column(_COLUMN)
