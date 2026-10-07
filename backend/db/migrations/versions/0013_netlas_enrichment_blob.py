"""netlas enrichment-blob markers on crawl_snapshots (F8)

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-01

F8's enrichment store reuses ``crawl_snapshots`` as its per-domain dated blobs.
Two additive markers let it tell which snapshots came from a keyed Netlas fetch
(so the 30-day refresh clock counts only those) without touching native caching:

* ``netlas_enriched``  — True when a keyed Netlas fetch (F1-F5) ran for this
  snapshot;
* ``netlas_fetched_at`` — when that fetch happened (the refresh clock).

Additive + guarded/idempotent (add each column only if absent), mirroring 0012.
Existing native snapshots backfill to ``netlas_enriched=0`` / NULL — i.e. "not a
Netlas blob", which is correct.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "crawl_snapshots"


def _columns() -> set[str]:
    insp = sa.inspect(op.get_bind())
    if _TABLE not in insp.get_table_names():
        return set()
    return {c["name"] for c in insp.get_columns(_TABLE)}


def upgrade() -> None:
    cols = _columns()
    if not cols:  # table absent — nothing to alter
        return
    if "netlas_enriched" not in cols:
        op.add_column(
            _TABLE,
            sa.Column("netlas_enriched", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
    if "netlas_fetched_at" not in cols:
        op.add_column(
            _TABLE, sa.Column("netlas_fetched_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    cols = _columns()
    if "netlas_fetched_at" in cols:
        op.drop_column(_TABLE, "netlas_fetched_at")
    if "netlas_enriched" in cols:
        op.drop_column(_TABLE, "netlas_enriched")
