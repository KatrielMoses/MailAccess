from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import DateTime, Integer
from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, JSON, String
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
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
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
