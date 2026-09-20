"""pro keys lifecycle status + expiry (0.17.0 admin console)

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-19

The admin console issues test keys (hard-capped at 30 days) and can suspend /
revoke keys. For those to take effect at ``/v1/enrich`` the entitlement store must
carry an expiry and a lifecycle status, and ``validate_pro_key`` must honor both.

Additive + guarded/idempotent (add each column only if absent), consistent with
the 0011 create-if-absent pattern; a fresh create_all-built DB (model already has
the columns) and an existing 0011 DB both converge on the same schema. Existing
rows backfill to ``status='active'`` (or ``'revoked'`` where already inactive).
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "pro_keys"


def _columns() -> set[str]:
    insp = sa.inspect(op.get_bind())
    if _TABLE not in insp.get_table_names():
        return set()
    return {c["name"] for c in insp.get_columns(_TABLE)}


def upgrade() -> None:
    cols = _columns()
    if not cols:  # table absent (pre-0011 / non-Pro DB) — nothing to alter
        return
    if "status" not in cols:
        op.add_column(
            _TABLE,
            sa.Column("status", sa.String(), nullable=False, server_default="active"),
        )
        # Any pre-existing inactive row becomes 'revoked'; active rows stay 'active'.
        op.execute("UPDATE pro_keys SET status='revoked' WHERE active = 0")
    if "expires_at" not in cols:
        op.add_column(
            _TABLE, sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    cols = _columns()
    if "expires_at" in cols:
        op.drop_column(_TABLE, "expires_at")
    if "status" in cols:
        op.drop_column(_TABLE, "status")
