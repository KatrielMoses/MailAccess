from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class InvestigationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, index=True, nullable=False)
    canonical_email: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    status: Mapped[InvestigationStatus] = mapped_column(
        SAEnum(InvestigationStatus),
        default=InvestigationStatus.PENDING,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    # Phase 2B — the product mode this investigation was run under (run manifest).
    mode: Mapped[str] = mapped_column(
        String, nullable=False, default="security-investigation"
    )
    exposure_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    credential_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confirmed_name: Mapped[str | None] = mapped_column(String, nullable=True)
    name_confidence: Mapped[str | None] = mapped_column(String, nullable=True)
    name_reasoning: Mapped[str | None] = mapped_column(String, nullable=True)
    name_sources: Mapped[list | None] = mapped_column(JSON, nullable=True)
    graph_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    timeline_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    defenders_brief_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    module_runs: Mapped[list[ModuleRun]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )


class ModuleRun(Base):
    """Records the execution of a single OSINT module within an investigation."""

    __tablename__ = "module_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id"), nullable=False, index=True
    )
    module_name: Mapped[str] = mapped_column(String, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String, nullable=False)
    # Stores ModuleResult.metadata dict
    run_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    errors: Mapped[list | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    investigation: Mapped[Investigation] = relationship(back_populates="module_runs")


class Finding(Base):
    """A single data point emitted by a module — flexible JSON payload."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id"), nullable=False, index=True
    )
    module_name: Mapped[str] = mapped_column(String, nullable=False, index=True)
    data: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    investigation: Mapped[Investigation] = relationship(back_populates="findings")


class Observation(Base):
    """Phase 1C — the canonical, append-only evidence ledger.

    One immutable row per public observation the tool makes, from either
    pipeline (investigate or harvest). This is the atomic unit of provenance:
    every displayed field will (in Phase 1D) trace back to one of these rows.

    Append-only: a correction or a re-observation is a NEW row, never a mutation
    of an existing one. Modelled to serialize to a W3C PROV-DM view later
    (Phase 2): the row is the PROV *entity*; ``activity_id`` + ``pipeline`` +
    ``extraction_method`` + ``module_version`` identify the PROV *activity* (the
    module run); ``source_type`` + ``source_url`` identify the PROV *agent* (the
    source). The heavy raw evidence bytes live in the optional, expiry-bound
    :class:`ObservationRawPayload` side table (off by default); the
    ``content_hash`` of that evidence is stored here always.
    """

    __tablename__ = "observations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)

    # PROV activity — which run/pipeline/module produced this observation.
    pipeline: Mapped[str] = mapped_column(String, nullable=False, index=True)
    activity_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    extraction_method: Mapped[str] = mapped_column(String, nullable=False, index=True)
    module_version: Mapped[str] = mapped_column(String, nullable=False)

    # Subject — the normalized entity the observation is about.
    subject_type: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str] = mapped_column(String, nullable=False, index=True)

    # Claim — the asserted value/payload, plus a normalized key for lookup/dedup.
    claim: Mapped[dict] = mapped_column(JSON, nullable=False)
    claim_key: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    # PROV agent — the source the claim came from (existing SOURCE_WEIGHTS
    # vocabulary; never a parallel taxonomy).
    source_type: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    source_url: Mapped[str | None] = mapped_column(String, nullable=True)

    # Provenance discipline.
    capture_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    content_hash: Mapped[str] = mapped_column(String, nullable=False, index=True)
    # Phase 2B — the product mode this observation was collected under, so a
    # fact's collection mode is always known (excluded from content_hash).
    mode: Mapped[str] = mapped_column(
        String, nullable=False, default="security-investigation", index=True
    )
    # Source-policy status — populated now, enforced in Phase 2.
    source_policy_status: Mapped[str] = mapped_column(
        String, nullable=False, default="unreviewed"
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Ledger write time (distinct from capture_time).
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    raw_payload: Mapped[ObservationRawPayload | None] = relationship(
        back_populates="observation",
        cascade="all, delete-orphan",
        uselist=False,
    )


class ObservationRawPayload(Base):
    """Optional, expiry-bound raw evidence bytes for an observation (Doc-1 #2).

    Off by default (``settings.ledger_store_raw_payloads``). The observation
    always carries the ``content_hash``; the bytes themselves are stored here
    only when explicitly enabled, and are expiry-bound so they can be reaped.
    """

    __tablename__ = "observation_raw_payloads"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    observation_id: Mapped[str] = mapped_column(
        ForeignKey("observations.id"), nullable=False, unique=True, index=True
    )
    content_hash: Mapped[str] = mapped_column(String, nullable=False, index=True)
    media_type: Mapped[str | None] = mapped_column(String, nullable=True)
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    stored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    observation: Mapped[Observation] = relationship(back_populates="raw_payload")


# ---------------------------------------------------------------------------
# Phase 1D — unified corpus store (read models over the 1C ledger)
#
# The per-domain JSON harvest cache is replaced by these DB-backed corpus
# tables: `crawl_snapshots` is the read-first source of truth (holds the full
# serialized harvest result for offline, parity-identical reconstruction), and
# `domains` / `contacts` / `verification_outcomes` are the compounding aggregate
# projections. `suppression` and the `policy_status` / `eligibility_status`
# columns are shells created now for schema completeness; their enforcement is
# Phase 2 (create the table, don't wire the gate). `last_verified` on contacts
# is modelled now so Phase 6's confidence decay layers on with no re-migration.
# ---------------------------------------------------------------------------


class CrawlSnapshot(Base):
    """One harvest crawl of a domain — the read-first source of truth.

    Holds the full serialized :class:`DomainHarvestResult` (``result_json``) so a
    fresh snapshot can reconstruct a byte-identical result offline, guaranteeing
    parity with the old JSON-cache path. Summary counts are denormalized for fast
    corpus reads.
    """

    __tablename__ = "crawl_snapshots"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    domain: Mapped[str] = mapped_column(String, nullable=False, index=True)
    harvested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    mailaccess_version: Mapped[str] = mapped_column(String, nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_unique_emails: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_confidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    likely_confidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_confidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low_confidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    catchall_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    confirmed_pattern: Mapped[str | None] = mapped_column(String, nullable=True)
    # Phase 2B — the product mode this crawl was collected under (run manifest).
    mode: Mapped[str] = mapped_column(
        String, nullable=False, default="security-investigation"
    )
    result_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Domain(Base):
    """Aggregate projection: one row per known domain."""

    __tablename__ = "domains"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    domain: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    first_harvested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_harvested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_crawl_snapshot_id: Mapped[str | None] = mapped_column(
        ForeignKey("crawl_snapshots.id"), nullable=True
    )
    total_emails: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_confidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    catchall_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Phase 2 shells — recorded now, enforced later.
    policy_status: Mapped[str] = mapped_column(String, nullable=False, default="unreviewed")
    eligibility_status: Mapped[str] = mapped_column(String, nullable=False, default="eligible")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Contact(Base):
    """Aggregate projection: one row per (domain, email) — the servable Lead.

    Phase 3A adds the person fields (name/title/seniority/…), each populated only
    from resolved, evidenced observations; ``person_field_provenance`` carries the
    per-field evidence link. Phase 3C/3D add the deliverability score + grade."""

    __tablename__ = "contacts"
    __table_args__ = (UniqueConstraint("domain", "email", name="uq_contacts_domain_email"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String, nullable=False, index=True)
    on_domain: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_role: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confidence_label: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    found_by_modules: Mapped[list | None] = mapped_column(JSON, nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # --- Phase 3A person fields (evidence-or-null) ---
    full_name: Mapped[str | None] = mapped_column(String, nullable=True)
    first_name: Mapped[str | None] = mapped_column(String, nullable=True)
    last_name: Mapped[str | None] = mapped_column(String, nullable=True)
    job_title: Mapped[str | None] = mapped_column(String, nullable=True)
    seniority: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    department: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    linkedin_url: Mapped[str | None] = mapped_column(String, nullable=True)
    phone: Mapped[str | None] = mapped_column(String, nullable=True)
    location: Mapped[str | None] = mapped_column(String, nullable=True)
    person_field_provenance: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # --- Phase 3C/3D deliverability ---
    deliverability_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    deliverability_grade: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    # Decay readiness (Doc-2 A4) — when we last confirmed/observed this contact.
    # Phase 6 layers a decay curve on this with no schema change.
    last_verified: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    policy_status: Mapped[str] = mapped_column(String, nullable=False, default="unreviewed")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class VerificationOutcome(Base):
    """Per-contact verification result (SMTP / provider / …)."""

    __tablename__ = "verification_outcomes"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    contact_id: Mapped[str | None] = mapped_column(
        ForeignKey("contacts.id"), nullable=True, index=True
    )
    email: Mapped[str] = mapped_column(String, nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String, nullable=False, index=True)
    method: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    provider: Mapped[str | None] = mapped_column(String, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Provenance link back to the ledger observation, when known (nullable in 1D).
    observation_id: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Suppression(Base):
    """Phase 2A — enforced suppression store. A subject that must never appear in
    any export/lead output, in any mode. Minimum-retention (Doc-1 #7 / ICO):
    ``subject_type`` is the scope (email|domain|company); ``subject`` is the
    stored match key — a SHA-256 hash for email/domain (no clear-text PII) and
    the normalized public name for company. ``source`` records where the
    objection came from (manual add, import, …)."""

    __tablename__ = "suppression"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    subject_type: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str] = mapped_column(String, nullable=False, index=True)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    # Phase 2A — provenance of the objection (manual/import/objection/takedown).
    source: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


# ---------------------------------------------------------------------------
# Phase 2E — retention, deletion & reproducibility governance.
# ---------------------------------------------------------------------------


class AuditLogEntry(Base):
    """Tamper-evident audit log of governance actions (suppression, deletion,
    takedown, mode-of-collection, exports). Integrity is a hash chain: each
    row's ``entry_hash`` = sha256(prev_hash + canonical(payload)), so any
    mutation or deletion breaks the chain from that point on."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    # Monotonic sequence — the chain order (0-based).
    seq: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    action: Mapped[str] = mapped_column(String, nullable=False, index=True)
    subject: Mapped[str | None] = mapped_column(String, nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    prev_hash: Mapped[str] = mapped_column(String, nullable=False)
    entry_hash: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Takedown(Base):
    """Per-record deletion/takedown. Recording the takedown (not just deleting)
    is what lets a future re-collection be suppressed — a companion suppression
    row is written so the subject cannot silently re-enter. Minimum-retention:
    ``subject`` is a hash, like :class:`Suppression`."""

    __tablename__ = "takedowns"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    subject_type: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str] = mapped_column(String, nullable=False, index=True)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    # What was removed (e.g. an investigation id) — provenance of the action.
    removed_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class RunManifest(Base):
    """Reproducible run manifest — persisted with every result so a run can be
    reproduced and its evidence chain audited: config version, module versions,
    source policy (mode), corpus version, run seed. The 2E PROV-DM export is a
    machine-readable view over the 1C ledger built with this as the activity."""

    __tablename__ = "run_manifests"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    pipeline: Mapped[str] = mapped_column(String, nullable=False)
    mode: Mapped[str] = mapped_column(String, nullable=False)
    app_version: Mapped[str] = mapped_column(String, nullable=False)
    config_fingerprint: Mapped[str | None] = mapped_column(String, nullable=True)
    module_versions: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    source_policy: Mapped[str | None] = mapped_column(String, nullable=True)
    corpus_version: Mapped[str | None] = mapped_column(String, nullable=True)
    seed: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


# ---------------------------------------------------------------------------
# Phase 4A — self-calibrating scoring: ground-truth & feature capture.
#
# Every deliverability score becomes a future training example. The feature
# vector that produced a score is snapshotted immutably (``score_feature_snapshots``)
# the moment the score is computed; when an objective outcome later becomes known
# (an SMTP/provider verdict, a corpus re-verification, or a human truth label) it
# is attached as a NEW linked row (``score_outcome_labels``) — the snapshot is
# never mutated. Together they are the substrate the Phase-4B trainer learns from.
# Governance-aligned with the 1C ledger: every snapshot carries its collection
# ``mode``, ``source_policy_status`` and ``expires_at`` (retention), and links back
# to the ledger/corpus by ``subject`` + ``activity_id``.
# ---------------------------------------------------------------------------


class ScoreFeatureSnapshot(Base):
    """Immutable snapshot of the features that produced one deliverability score.

    Append-only. One row per scored email per run. ``features`` is the exact
    feature vector fed to the hand-tuned scorer; ``hand_score`` is the probability
    it produced. ``content_hash`` is a deterministic fingerprint of the feature
    vector (volatile keys stripped) so a snapshot is reproducible and an outcome
    arriving in a later run can be matched to the evidence that produced it. The
    ``subject``/``subject_domain``/``activity_id`` triple links a snapshot to the
    1C observation ledger and 1D corpus for full provenance.
    """

    __tablename__ = "score_feature_snapshots"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    # Provenance link — mirrors the ledger's PROV activity/subject fields.
    pipeline: Mapped[str] = mapped_column(String, nullable=False, index=True)
    activity_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String, nullable=False, index=True)
    subject_domain: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    # The model that produced the score, and the score itself.
    model_version: Mapped[str] = mapped_column(String, nullable=False, index=True)
    features: Mapped[dict] = mapped_column(JSON, nullable=False)
    hand_score: Mapped[float] = mapped_column(Float, nullable=False)
    content_hash: Mapped[str] = mapped_column(String, nullable=False, index=True)

    # Governance (mirrors the 1C ledger) — collection mode, lawful basis, expiry.
    mode: Mapped[str] = mapped_column(
        String, nullable=False, default="security-investigation", index=True
    )
    source_policy_status: Mapped[str] = mapped_column(
        String, nullable=False, default="unreviewed"
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )

    outcomes: Mapped[list[ScoreOutcomeLabel]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )


class ScoreOutcomeLabel(Base):
    """An objective deliverability outcome attached to a feature snapshot.

    Written as a NEW row when an outcome becomes known — never a mutation of the
    snapshot. ``label`` is the 0/1 training target (deliverable / not); ``outcome``
    is the raw status (``verified``/``bounced``/``not_found``/…); ``label_source``
    records where the truth came from (``smtp``/``provider``/``corpus``/``human``)
    so the trainer can weight or filter by label provenance.
    """

    __tablename__ = "score_outcome_labels"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("score_feature_snapshots.id"), nullable=False, index=True
    )
    # Denormalized natural key — lets an outcome be matched to a snapshot even
    # when the snapshot id is not at hand (a later run joins by subject+hash).
    subject: Mapped[str] = mapped_column(String, nullable=False, index=True)
    content_hash: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    outcome: Mapped[str] = mapped_column(String, nullable=False)
    label: Mapped[float | None] = mapped_column(Float, nullable=True)
    label_source: Mapped[str] = mapped_column(String, nullable=False, index=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    snapshot: Mapped[ScoreFeatureSnapshot] = relationship(back_populates="outcomes")
