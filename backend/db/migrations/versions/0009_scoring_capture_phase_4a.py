"""scoring capture — feature snapshots + outcome labels (phase 4a)

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-06

Phase 4A — self-calibrating scoring ground-truth capture. Adds two append-only
tables that turn every deliverability score into a future training example:

* ``score_feature_snapshots`` — one immutable row per scored email per run: the
  exact feature vector fed to the hand-tuned scorer, the ``hand_score`` it
  produced, a deterministic ``content_hash`` of the features, and the governance
  fields mirrored from the 1C ledger (``mode``, ``source_policy_status``,
  ``expires_at``). Linked to the ledger/corpus by ``subject`` + ``activity_id``.
* ``score_outcome_labels`` — a NEW linked row when an objective outcome later
  becomes known (SMTP/provider verdict, corpus re-verification, human label). The
  snapshot is never mutated; the outcome is joined by FK (and, denormalized, by
  ``subject`` + ``content_hash`` so a later run can attach without the id).

Additive only. Guarded/idempotent create-if-not-exists, consistent with the
Phase 1A stamp-and-reconcile model (a create_all-built pre-Alembic DB stamped at
0001 may already carry these tables; only create what is missing).
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SNAPSHOT_INDEXES = (
    ("ix_score_feature_snapshots_pipeline", "pipeline", False),
    ("ix_score_feature_snapshots_activity_id", "activity_id", False),
    ("ix_score_feature_snapshots_subject", "subject", False),
    ("ix_score_feature_snapshots_subject_domain", "subject_domain", False),
    ("ix_score_feature_snapshots_model_version", "model_version", False),
    ("ix_score_feature_snapshots_content_hash", "content_hash", False),
    ("ix_score_feature_snapshots_mode", "mode", False),
    ("ix_score_feature_snapshots_created_at", "created_at", False),
)
_LABEL_INDEXES = (
    ("ix_score_outcome_labels_snapshot_id", "snapshot_id", False),
    ("ix_score_outcome_labels_subject", "subject", False),
    ("ix_score_outcome_labels_content_hash", "content_hash", False),
    ("ix_score_outcome_labels_label_source", "label_source", False),
)


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    existing = _existing_tables()
    if "score_feature_snapshots" not in existing:
        _create_snapshots()
    if "score_outcome_labels" not in existing:
        _create_labels()


def _create_snapshots() -> None:
    op.create_table(
        "score_feature_snapshots",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("pipeline", sa.String(), nullable=False),
        sa.Column("activity_id", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("subject_domain", sa.String(), nullable=True),
        sa.Column("model_version", sa.String(), nullable=False),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("hand_score", sa.Float(), nullable=False),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("source_policy_status", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, column, unique in _SNAPSHOT_INDEXES:
        op.create_index(name, "score_feature_snapshots", [column], unique=unique)


def _create_labels() -> None:
    op.create_table(
        "score_outcome_labels",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("snapshot_id", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("content_hash", sa.String(), nullable=True),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("label", sa.Float(), nullable=True),
        sa.Column("label_source", sa.String(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["snapshot_id"], ["score_feature_snapshots.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, column, unique in _LABEL_INDEXES:
        op.create_index(name, "score_outcome_labels", [column], unique=unique)


def downgrade() -> None:
    existing = _existing_tables()
    if "score_outcome_labels" in existing:
        for name, _column, _unique in _LABEL_INDEXES:
            op.drop_index(name, table_name="score_outcome_labels")
        op.drop_table("score_outcome_labels")
    if "score_feature_snapshots" in existing:
        for name, _column, _unique in _SNAPSHOT_INDEXES:
            op.drop_index(name, table_name="score_feature_snapshots")
        op.drop_table("score_feature_snapshots")
