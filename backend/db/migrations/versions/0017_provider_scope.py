"""Provider scope for evidence: observations.provider and run_manifests.providers.

Revision ID: 0017
Revises: 0016

Backfill rule for existing observations (provider is NULL for everything else):
``extraction_method`` ``ip_intel`` -> ipgeolocation; ``whoisfreaks_*`` -> whoisfreaks;
or a ``source_type`` of ipgeolocation.io / whoisfreaks.

Rollback: ``alembic downgrade 0016`` drops both columns (additive; 0.18.7 ignores them).
"""

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def _cols(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    if "provider" not in _cols("observations"):
        with op.batch_alter_table("observations") as batch:
            batch.add_column(sa.Column("provider", sa.String(), nullable=True))
        op.create_index("ix_observations_provider", "observations", ["provider"])
    if "providers" not in _cols("run_manifests"):
        with op.batch_alter_table("run_manifests") as batch:
            batch.add_column(sa.Column("providers", sa.JSON(), nullable=True))
    bind = op.get_bind()
    bind.execute(sa.text(
        "UPDATE observations SET provider='ipgeolocation' WHERE provider IS NULL AND "
        "(extraction_method='ip_intel' OR lower(coalesce(source_type,'')) LIKE 'ipgeolocation%')"
    ))
    bind.execute(sa.text(
        "UPDATE observations SET provider='whoisfreaks' WHERE provider IS NULL AND "
        "(extraction_method LIKE 'whoisfreaks%' OR lower(coalesce(source_type,'')) LIKE 'whoisfreaks%')"
    ))


def downgrade():
    if "provider" in _cols("observations"):
        op.drop_index("ix_observations_provider", table_name="observations")
        with op.batch_alter_table("observations") as batch:
            batch.drop_column("provider")
    if "providers" in _cols("run_manifests"):
        with op.batch_alter_table("run_manifests") as batch:
            batch.drop_column("providers")
