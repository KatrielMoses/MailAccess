"""Shared IP intelligence cache.

Revision ID: 0014
Revises: 0013
"""

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade():
    if "ip_intel_cache" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "ip_intel_cache",
            sa.Column("ip", sa.String(), primary_key=True),
            sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tier", sa.String(), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("empty", sa.Boolean(), nullable=False, server_default=sa.false()),
        )


def downgrade():
    if "ip_intel_cache" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("ip_intel_cache")
