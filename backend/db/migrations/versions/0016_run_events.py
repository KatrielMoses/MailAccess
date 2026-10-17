"""Saved live-run event log (``run_events``).

Revision ID: 0016
Revises: 0015

Rollback (to run 0.18.7 or earlier): ``drop table run_events;`` then
``update alembic_version set version_num='0014';`` (0015's table is additive and
unused by 0.18.7, so it may stay). ``alembic downgrade 0015`` does the same from a
0.18.8 install. The table is additive, so nothing else changes.
"""

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade():
    if "run_events" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "run_events",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("investigation_id", sa.String(), nullable=False),
            sa.Column("seq", sa.Integer(), nullable=False),
            sa.Column("ts", sa.String(), nullable=False),
            sa.Column("type", sa.String(), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.UniqueConstraint("investigation_id", "seq", name="uq_run_events_seq"),
        )
        op.create_index(
            "ix_run_events_investigation_seq", "run_events", ["investigation_id", "seq"]
        )


def downgrade():
    if "run_events" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_index("ix_run_events_investigation_seq", table_name="run_events")
        op.drop_table("run_events")
