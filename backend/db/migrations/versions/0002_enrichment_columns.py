"""enrichment columns: version the former hand-rolled startup ALTERs

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-05

This is the versioned replacement for the ``_migrate_add_*`` helpers that used
to run on every startup in ``backend/db/database.py``. It adds the eleven
``investigations`` enrichment columns (graph_data, credential_risk_score,
canonical_email, timeline_json, defenders_brief_json, the name-consensus fields,
and the started_at/error recovery fields) plus the ``canonical_email`` index.

Every operation is **guarded** by live introspection, for one reason: the
pre-Alembic install base is heterogeneous. A database freshly created by
v0.14.4's ``create_all`` already has all of these columns *and* the index; a
database that was upgraded across versions via the old ``ADD COLUMN`` path has
the columns but is *missing* ``ix_investigations_canonical_email`` (the old
ALTER never created it); an older one may have none. ``init_db`` stamps all such
databases at ``0001`` and lets this revision reconcile each of them to the same
head schema — exactly the idempotent behaviour the old startup code had, now
with version history and a real downgrade.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CANONICAL_EMAIL_INDEX = "ix_investigations_canonical_email"


def _enrichment_columns() -> list[tuple[str, sa.types.TypeEngine]]:
    """Fresh column-type instances each call (types aren't reused across ops)."""
    return [
        ("canonical_email", sa.String()),
        ("started_at", sa.DateTime(timezone=True)),
        ("error", sa.String()),
        ("credential_risk_score", sa.Integer()),
        ("confirmed_name", sa.String()),
        ("name_confidence", sa.String()),
        ("name_reasoning", sa.String()),
        ("name_sources", sa.JSON()),
        ("graph_data", sa.JSON()),
        ("timeline_json", sa.JSON()),
        ("defenders_brief_json", sa.JSON()),
    ]


def _existing(table: str, kind: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if kind == "columns":
        return {c["name"] for c in inspector.get_columns(table)}
    return {ix["name"] for ix in inspector.get_indexes(table)}


def upgrade() -> None:
    have = _existing("investigations", "columns")
    for name, coltype in _enrichment_columns():
        if name not in have:
            op.add_column("investigations", sa.Column(name, coltype, nullable=True))
    if _CANONICAL_EMAIL_INDEX not in _existing("investigations", "indexes"):
        op.create_index(_CANONICAL_EMAIL_INDEX, "investigations", ["canonical_email"])


def downgrade() -> None:
    if _CANONICAL_EMAIL_INDEX in _existing("investigations", "indexes"):
        op.drop_index(_CANONICAL_EMAIL_INDEX, table_name="investigations")

    have = _existing("investigations", "columns")
    to_drop = [name for name, _ in _enrichment_columns() if name in have]
    if to_drop:
        # Batch (table-recreate) so the drops work on SQLite < 3.35 too.
        with op.batch_alter_table("investigations") as batch_op:
            for name in to_drop:
                batch_op.drop_column(name)
