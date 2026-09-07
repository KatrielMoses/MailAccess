"""corpus store (phase 1d)

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-05

Phase 1D — the unified corpus store. Adds the read-model tables that replace the
per-domain JSON harvest cache as the source of truth:

* ``crawl_snapshots`` — one row per harvest crawl, holding the full serialized
  result for parity-identical, offline read-first reconstruction;
* ``domains`` / ``contacts`` / ``verification_outcomes`` — compounding aggregate
  projections (contacts are email-centric for now; person fields are Phase 3);
* ``suppression`` — a shell table, created for schema completeness; enforcement
  is Phase 2 (create the table, don't wire the gate).

``policy_status`` / ``eligibility_status`` columns and ``contacts.last_verified``
(decay readiness) are modelled now so Phase 2/6 need no re-migration. Additive
only — nothing existing is touched. Guarded/idempotent creates, consistent with
the Phase 1A stamp-and-reconcile model.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (table, [(index_name, column, unique), ...]) — created after each table.
_INDEXES: dict[str, tuple[tuple[str, str, bool], ...]] = {
    "crawl_snapshots": (("ix_crawl_snapshots_domain", "domain", False),),
    "contacts": (
        ("ix_contacts_domain", "domain", False),
        ("ix_contacts_email", "email", False),
    ),
    "domains": (("ix_domains_domain", "domain", True),),
    "verification_outcomes": (
        ("ix_verification_outcomes_contact_id", "contact_id", False),
        ("ix_verification_outcomes_domain", "domain", False),
        ("ix_verification_outcomes_email", "email", False),
    ),
    "suppression": (("ix_suppression_subject", "subject", False),),
}
# FK-safe creation order (parents before children); drop in reverse.
_CREATE_ORDER = ("crawl_snapshots", "contacts", "domains", "verification_outcomes", "suppression")


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _indexes(table: str) -> None:
    for name, column, unique in _INDEXES[table]:
        op.create_index(name, table, [column], unique=unique)


_CREATORS = {}


def upgrade() -> None:
    existing = _existing_tables()
    for table in _CREATE_ORDER:
        if table not in existing:
            _CREATORS[table]()
            _indexes(table)


def downgrade() -> None:
    existing = _existing_tables()
    for table in reversed(_CREATE_ORDER):
        if table in existing:
            for name, _column, _unique in _INDEXES[table]:
                op.drop_index(name, table_name=table)
            op.drop_table(table)


def _create_crawl_snapshots() -> None:
    op.create_table(
        "crawl_snapshots",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("harvested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("mailaccess_version", sa.String(), nullable=False),
        sa.Column("ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("total_unique_emails", sa.Integer(), nullable=False),
        sa.Column("high_confidence_count", sa.Integer(), nullable=False),
        sa.Column("likely_confidence_count", sa.Integer(), nullable=False),
        sa.Column("medium_confidence_count", sa.Integer(), nullable=False),
        sa.Column("low_confidence_count", sa.Integer(), nullable=False),
        sa.Column("catchall_detected", sa.Boolean(), nullable=True),
        sa.Column("confirmed_pattern", sa.String(), nullable=True),
        sa.Column("result_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_contacts() -> None:
    op.create_table(
        "contacts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("on_domain", sa.Boolean(), nullable=False),
        sa.Column("is_role", sa.Boolean(), nullable=False),
        sa.Column("confidence_label", sa.String(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("source_count", sa.Integer(), nullable=False),
        sa.Column("found_by_modules", sa.JSON(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_verified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("policy_status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain", "email", name="uq_contacts_domain_email"),
    )


def _create_domains() -> None:
    op.create_table(
        "domains",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("first_harvested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_harvested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_crawl_snapshot_id", sa.String(), nullable=True),
        sa.Column("total_emails", sa.Integer(), nullable=False),
        sa.Column("high_confidence_count", sa.Integer(), nullable=False),
        sa.Column("catchall_detected", sa.Boolean(), nullable=True),
        sa.Column("policy_status", sa.String(), nullable=False),
        sa.Column("eligibility_status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["last_crawl_snapshot_id"], ["crawl_snapshots.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_verification_outcomes() -> None:
    op.create_table(
        "verification_outcomes",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("contact_id", sa.String(), nullable=True),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("method", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observation_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["contact_id"], ["contacts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_suppression() -> None:
    op.create_table(
        "suppression",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("subject_type", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


_CREATORS.update(
    {
        "crawl_snapshots": _create_crawl_snapshots,
        "contacts": _create_contacts,
        "domains": _create_domains,
        "verification_outcomes": _create_verification_outcomes,
        "suppression": _create_suppression,
    }
)
