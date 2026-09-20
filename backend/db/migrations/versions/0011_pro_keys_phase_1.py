"""pro keys entitlement store (0.17.0 phase 1)

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-17

0.17.0 Phase 1 — the hosted paid lead-enrichment tier needs somewhere to
validate a caller's Pro key against. This migration adds the ``pro_keys`` table:
one row per issued entitlement, storing only the SHA-256 ``key_hash`` (never the
raw key), an ``active`` flag, an operator ``notes`` memo and ``created_at``.

``validate_pro_key`` = "an active row exists whose hash matches". Population is
manual for now (``scripts/pro_keys_admin.py``); Phase 5 replaces the population
path with Stripe webhooks behind the same interface.

Additive + guarded/idempotent (create the table only if absent), consistent with
the 0004 create-table pattern; a fresh DB and a create_all-built pre-Alembic DB
both converge on the same schema.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "pro_keys"
_INDEX = "ix_pro_keys_key_hash"


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if _TABLE in _existing_tables():
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("key_hash", sa.String(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("notes", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash", name="uq_pro_keys_key_hash"),
    )
    op.create_index(_INDEX, _TABLE, ["key_hash"], unique=True)


def downgrade() -> None:
    if _TABLE not in _existing_tables():
        return
    op.drop_index(_INDEX, table_name=_TABLE)
    op.drop_table(_TABLE)
