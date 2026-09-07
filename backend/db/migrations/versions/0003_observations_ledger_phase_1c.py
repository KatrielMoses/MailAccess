"""observations ledger (phase 1c)

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-05

Phase 1C — the canonical, append-only evidence ledger. Adds two tables:

* ``observations`` — one immutable row per public observation from either
  pipeline (investigate or harvest), carrying full provenance (subject, claim,
  source, capture time, content hash, extraction method + version, policy
  status, expiry). Modelled PROV-compatibly (entity = row, activity =
  ``activity_id`` + ``extraction_method`` + ``module_version``, agent =
  ``source_type`` + ``source_url``) for the Phase 2 PROV export.
* ``observation_raw_payloads`` — optional, expiry-bound raw evidence bytes,
  written only when ``settings.ledger_store_raw_payloads`` is enabled.

Additive only: nothing in the existing schema is touched, and the ``findings``
table is left exactly as-is (1D, not 1C, makes readers use this ledger).
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OBSERVATION_INDEXES = (
    ("ix_observations_activity_id", "activity_id", False),
    ("ix_observations_claim_key", "claim_key", False),
    ("ix_observations_content_hash", "content_hash", False),
    ("ix_observations_extraction_method", "extraction_method", False),
    ("ix_observations_pipeline", "pipeline", False),
    ("ix_observations_source_type", "source_type", False),
    ("ix_observations_subject", "subject", False),
)
_RAW_PAYLOAD_INDEXES = (
    ("ix_observation_raw_payloads_content_hash", "content_hash", False),
    ("ix_observation_raw_payloads_observation_id", "observation_id", True),
)


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    # Guarded/idempotent create, consistent with the Phase 1A stamp-and-reconcile
    # model: a pre-Alembic database stamped at 0001 may already carry these
    # tables (e.g. one built by create_all); only create what is missing.
    existing = _existing_tables()

    if "observations" not in existing:
        _create_observations()
    if "observation_raw_payloads" not in existing:
        _create_raw_payloads()


def _create_observations() -> None:
    op.create_table(
        "observations",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("pipeline", sa.String(), nullable=False),
        sa.Column("activity_id", sa.String(), nullable=False),
        sa.Column("extraction_method", sa.String(), nullable=False),
        sa.Column("module_version", sa.String(), nullable=False),
        sa.Column("subject_type", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("claim", sa.JSON(), nullable=False),
        sa.Column("claim_key", sa.String(), nullable=True),
        sa.Column("source_type", sa.String(), nullable=True),
        sa.Column("source_url", sa.String(), nullable=True),
        sa.Column("capture_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("source_policy_status", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, column, unique in _OBSERVATION_INDEXES:
        op.create_index(name, "observations", [column], unique=unique)


def _create_raw_payloads() -> None:
    op.create_table(
        "observation_raw_payloads",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("observation_id", sa.String(), nullable=False),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("media_type", sa.String(), nullable=True),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("stored_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["observation_id"], ["observations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, column, unique in _RAW_PAYLOAD_INDEXES:
        op.create_index(name, "observation_raw_payloads", [column], unique=unique)


def downgrade() -> None:
    existing = _existing_tables()
    if "observation_raw_payloads" in existing:
        for name, _column, _unique in _RAW_PAYLOAD_INDEXES:
            op.drop_index(name, table_name="observation_raw_payloads")
        op.drop_table("observation_raw_payloads")
    if "observations" in existing:
        for name, _column, _unique in _OBSERVATION_INDEXES:
            op.drop_index(name, table_name="observations")
        op.drop_table("observations")
