"""WhoisFreaks answer cache.

Revision ID: 0015
Revises: 0014

Rollback: ``update alembic_version set version_num='0014';`` (the table is
additive and unused by 0.18.7, so it may stay or be dropped).
"""

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade():
    if "whoisfreaks_cache" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "whoisfreaks_cache",
            sa.Column("kind", sa.String(), primary_key=True),
            sa.Column("query", sa.String(), primary_key=True),
            sa.Column("page", sa.Integer(), primary_key=True),
            sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("empty", sa.Boolean(), nullable=False, server_default=sa.false()),
        )


def downgrade():
    if "whoisfreaks_cache" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("whoisfreaks_cache")
