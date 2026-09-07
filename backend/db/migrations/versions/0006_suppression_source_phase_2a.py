"""suppression source column (phase 2a)

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-06

Phase 2A — promote the 1D ``suppression`` shell into an enforced store. Adds a
``source`` column recording the provenance of each objection (manual add,
import, …). The scope/match-key model reuses the existing columns
(``subject_type`` = scope, ``subject`` = the minimum-retention match key: a
SHA-256 hash for email/domain, the normalized name for company), so only the
new ``source`` column is required.

Additive only, guarded/idempotent (add the column only if absent), consistent
with the Phase 1A stamp-and-reconcile model.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "suppression"
_COLUMN = "source"


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
        op.drop_column(_TABLE, _COLUMN)
