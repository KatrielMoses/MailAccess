from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..config import settings
from ..db.models import Finding, Investigation, InvestigationStatus, ModuleRun
from .breach_normalizer import collapse_breach_findings
from .credential_risk import assess_credential_risk_from_report, credential_risk_band
from .defenders_brief import defenders_brief_to_dict, generate_defenders_brief_from_report
from .email_credibility import normalize_email_address
from .engine import InvestigationEngine
from .timeline import build_timeline


def _risk_level(score: int | None) -> str:
    if score is None:
        return "unknown"
    if score <= 20:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"


def _build_summary(data: dict) -> str:
    runs = data.get("module_runs", [])
    findings = data.get("findings", [])
    total = len(runs)
    success = sum(1 for r in runs if r["status"] == "success")
    partial = sum(1 for r in runs if r["status"] == "partial")
    failed = sum(1 for r in runs if r["status"] == "failed")
    skipped = sum(1 for r in runs if r["status"] == "skipped")
    return f"Ran {total} modules ({success} success, {partial} partial, {failed} failed, {skipped} skipped). Found {len(findings)} data points."


def _email_credibility_from_report(data: dict) -> dict | None:
    findings_by_module = data.get("findings_by_module", {})
    if not isinstance(findings_by_module, dict):
        return None
    findings = findings_by_module.get("email_credibility")
    if not isinstance(findings, list) or not findings:
        return None
    first = findings[0]
    if not isinstance(first, dict):
        return None
    metadata = first.get("metadata")
    return metadata if isinstance(metadata, dict) else first


def enrich_report(data: dict) -> dict:
    score = data.get("exposure_score")
    data["risk_level"] = _risk_level(score)
    data.pop("credential_risk", None)
    data["original_email"] = data.get("email")
    name_sources = data.get("name_sources") if isinstance(data.get("name_sources"), list) else []
    data["name_confidence"] = data.get("name_confidence") or "unknown"
    data["name_reasoning"] = data.get("name_reasoning") or ""
    data["name_sources"] = name_sources
    data["name_consensus"] = {
        "confirmed_name": data.get("confirmed_name"),
        "name_confidence": data["name_confidence"],
        "confidence": data["name_confidence"],
        "name_reasoning": data["name_reasoning"],
        "name_sources": name_sources,
    }

    findings = collapse_breach_findings(data.get("findings", []))
    data["findings"] = findings
    data["summary"] = _build_summary(data)
    timeline = data.get("timeline_json") or data.get("timeline")
    if not isinstance(timeline, dict):
        timeline = asdict(build_timeline(findings))
    data["timeline"] = timeline
    data.pop("timeline_json", None)

    data["metadata_table"] = {
        r["module_name"]: r.get("run_metadata") or {}
        for r in data.get("module_runs", [])
    }

    findings_by_module: dict[str, list] = {}
    for f in findings:
        findings_by_module.setdefault(f["module_name"], []).append(f["data"])
    data["findings_by_module"] = findings_by_module

    credibility = _email_credibility_from_report(data)
    if isinstance(credibility, dict):
        data["email_credibility"] = credibility
        canonical_email = credibility.get("canonical_email") or data.get("canonical_email")
        if isinstance(canonical_email, str) and canonical_email.strip():
            data["canonical_email"] = canonical_email.strip()
        elif data.get("canonical_email") is None:
            data["canonical_email"] = data.get("email")
    else:
        data["email_credibility"] = {}
        if data.get("canonical_email") is None:
            data["canonical_email"] = data.get("email")

    credential_assessment = assess_credential_risk_from_report(data)
    stored_credential_score = data.get("credential_risk_score")
    credential_score = (
        stored_credential_score
        if isinstance(stored_credential_score, int)
        else credential_assessment.score
    )
    data["credential_risk_score"] = credential_score
    data["credential_risk_band"] = credential_risk_band(credential_score)
    data["score_drivers"] = credential_assessment.score_drivers
    data["recommended_actions"] = credential_assessment.recommended_actions
    stored_brief = data.get("defenders_brief_json")
    if isinstance(stored_brief, dict) and stored_brief.get("risk_level"):
        data["defenders_brief"] = stored_brief
    else:
        data["defenders_brief"] = defenders_brief_to_dict(
            generate_defenders_brief_from_report(data)
        )
    data.pop("defenders_brief_json", None)

    return data

class InvestigationService:
    """
    Application-layer facade over the DB and InvestigationEngine.

    Intended to be instantiated per-request with an injected AsyncSession::

        service = InvestigationService(session)
        investigation_id, created_at, queue, cached = await service.create_investigation("user@example.com")
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _find_recent_complete(
        self,
        email: str,
        canonical_email: str | None = None,
    ) -> Investigation | None:
        """Return the most recent COMPLETE investigation for `email` within the
        configured cache window, or None if none qualifies."""
        window = timedelta(minutes=settings.investigation_cache_window_minutes)
        cutoff = datetime.now(timezone.utc) - window
        candidates = [email]
        if canonical_email and canonical_email not in candidates:
            candidates.append(canonical_email)
        result = await self._session.execute(
            select(Investigation)
            .where(
                Investigation.email.in_(candidates),
                Investigation.status == InvestigationStatus.COMPLETE,
                Investigation.created_at >= cutoff,
            )
            .order_by(Investigation.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def create_investigation(
        self,
        email: str,
        module_names: list[str] | None = None,
        force: bool = False,
        enable_modules: list[str] | None = None,
    ) -> tuple[str, datetime, asyncio.Queue | None, bool]:
        """
        Persist a new Investigation (PENDING), launch the engine in the
        background, and return (id, created_at, queue, cached).

        When `enable_investigation_cache` is set and a COMPLETE investigation
        for the same email exists within the cache window, returns that
        investigation's id with `cached=True` and `queue=None` — no new
        engine run is started. Pass `force=True` to bypass the cache.

        The caller is responsible for storing the queue in the registry so
        WebSocket handlers can consume it (skip when cached=True).
        """
        canonical_email = normalize_email_address(email).canonical_email
        if (
            not force
            and settings.enable_investigation_cache
            and module_names is None
            and not enable_modules
        ):
            recent = await self._find_recent_complete(email, canonical_email)
            if recent is not None:
                return recent.id, recent.created_at, None, True

        inv = Investigation(
            email=email,
            canonical_email=canonical_email,
            status=InvestigationStatus.PENDING,
        )
        self._session.add(inv)
        await self._session.flush()
        investigation_id = inv.id
        created_at = inv.created_at
        await self._session.commit()

        engine = InvestigationEngine(
            timeout=settings.module_timeout_seconds,
            max_concurrency=settings.max_concurrent_modules,
        )
        queue = await engine.investigate(email, investigation_id, module_names, enable_modules)
        return investigation_id, created_at, queue, False

    async def get_investigation(self, investigation_id: str) -> dict | None:
        """Return the full investigation with all findings and module runs."""
        result = await self._session.execute(
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .options(
                selectinload(Investigation.findings),
                selectinload(Investigation.module_runs),
            )
        )
        inv = result.scalar_one_or_none()
        if inv is None:
            return None

        return {
            "id": inv.id,
            "email": inv.email,
            "canonical_email": inv.canonical_email,
            "status": inv.status.value,
            "error": inv.error,
            "exposure_score": inv.exposure_score,
            "credential_risk_score": inv.credential_risk_score,
            "confirmed_name": inv.confirmed_name,
            "name_confidence": inv.name_confidence or "unknown",
            "name_reasoning": inv.name_reasoning or "",
            "name_sources": inv.name_sources or [],
            "graph_data": inv.graph_data,
            "timeline_json": inv.timeline_json,
            "defenders_brief_json": inv.defenders_brief_json,
            "created_at": inv.created_at.isoformat(),
            "started_at": inv.started_at.isoformat() if inv.started_at else None,
            "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
            "findings": [
                {
                    "id": f.id,
                    "module_name": f.module_name,
                    "data": f.data,
                    "created_at": f.created_at.isoformat(),
                }
                for f in inv.findings
            ],
            "module_runs": [
                {
                    "id": r.id,
                    "module_name": r.module_name,
                    "status": r.status,
                    "run_metadata": r.run_metadata,
                    "errors": r.errors,
                    "started_at": r.started_at.isoformat(),
                    "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                }
                for r in inv.module_runs
            ],
        }

    async def list_investigations(
        self,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """Return a paginated list of investigations, newest first."""
        total: int = (
            await self._session.execute(
                select(func.count()).select_from(Investigation)
            )
        ).scalar_one()

        rows = (
            await self._session.execute(
                select(Investigation)
                .order_by(Investigation.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, (total + page_size - 1) // page_size),
            "items": [
                {
                    "id": inv.id,
                    "email": inv.email,
                    "canonical_email": inv.canonical_email,
                    "status": inv.status.value,
                    "exposure_score": inv.exposure_score,
                    "credential_risk_score": inv.credential_risk_score,
                    "confirmed_name": inv.confirmed_name,
                    "name_confidence": inv.name_confidence or "unknown",
                    "created_at": inv.created_at.isoformat(),
                    "completed_at": (
                        inv.completed_at.isoformat() if inv.completed_at else None
                    ),
                }
                for inv in rows
            ],
        }

    async def delete_investigation(self, investigation_id: str) -> bool:
        """Hard-delete an investigation and all its related records. Returns False if not found."""
        exists = (
            await self._session.execute(
                select(Investigation.id).where(Investigation.id == investigation_id)
            )
        ).scalar_one_or_none()
        if exists is None:
            return False

        await self._session.execute(
            delete(Finding).where(Finding.investigation_id == investigation_id)
        )
        await self._session.execute(
            delete(ModuleRun).where(ModuleRun.investigation_id == investigation_id)
        )
        await self._session.execute(
            delete(Investigation).where(Investigation.id == investigation_id)
        )
        await self._session.commit()
        return True
