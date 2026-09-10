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
from .policy import module_weight
from .suppression import SuppressionUnavailable
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
    base = (
        f"Ran {total} modules ({success} success, {partial} partial, "
        f"{failed} failed, {skipped} skipped). Found {len(findings)} data points."
    )
    truncated = _budget_truncated_modules(runs)
    if truncated:
        base += (
            f" Time budget reached: {len(truncated)} module(s) truncated "
            f"({', '.join(truncated)})."
        )
    return base


def _budget_truncated_modules(module_runs: list[dict]) -> list[str]:
    """Modules cut short or skipped by the Phase 1B investigation time budget."""
    names = [
        str(run.get("module_name") or "")
        for run in module_runs
        if isinstance(run, dict)
        and isinstance(run.get("run_metadata"), dict)
        and run["run_metadata"].get("budget_truncated")
    ]
    return sorted(n for n in names if n)


def _build_budget_report(data: dict) -> dict:
    """Explicit completed-vs-truncated record for the run's time budget."""
    runs = [r for r in data.get("module_runs", []) if isinstance(r, dict)]
    truncated = _budget_truncated_modules(runs)
    truncated_set = set(truncated)
    completed = sorted(
        str(r.get("module_name") or "")
        for r in runs
        if str(r.get("status") or "").lower() in ("success", "partial")
        and str(r.get("module_name") or "") not in truncated_set
        and str(r.get("module_name") or "")
    )
    return {
        "truncated": bool(truncated),
        "truncated_modules": truncated,
        "truncated_count": len(truncated),
        "completed_modules": completed,
        "completed_count": len(completed),
    }


def _exposure_score_pct(score: int | None, module_runs: list[dict]) -> int | None:
    if score is None:
        return None
    executed_statuses = {"success", "partial"}
    denominator = sum(
        module_weight(str(run.get("module_name") or ""))
        for run in module_runs
        if str(run.get("status") or "").lower() in executed_statuses
    )
    if denominator <= 0:
        return 0
    return max(0, min(round((score / denominator) * 100), 100))


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


def _report_reference_date(data: dict) -> datetime | None:
    """The investigation's original assessment date, for stable historical recompute.

    Prefers ``completed_at`` (when scoring ran), falls back to ``created_at``. Returns
    ``None`` (→ assessor defaults to today) only when neither is a parseable ISO string,
    e.g. a brand-new in-flight report.
    """
    for key in ("completed_at", "created_at"):
        raw = data.get(key)
        if isinstance(raw, datetime):
            return raw
        if isinstance(raw, str) and raw.strip():
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


def enrich_report(data: dict) -> dict:
    score = data.get("exposure_score")
    data["risk_level"] = _risk_level(score)
    # RC4 (Output-Trust): the exposure_score is ALREADY a 0-100 severity, so it IS
    # the percentage — presenting it as "100" alongside a separately
    # coverage-normalized "59%" was self-contradicting. The headline percentage is
    # the score itself; the coverage-of-achievable-signal diagnostic is kept under
    # its own explicit name.
    data["exposure_score_pct"] = score if isinstance(score, int) else None
    data["exposure_signal_coverage_pct"] = _exposure_score_pct(
        score if isinstance(score, int) else None,
        [
            run
            for run in data.get("module_runs", [])
            if isinstance(run, dict)
        ],
    )
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
    data["budget"] = _build_budget_report(data)
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

    # L6 — recompute the drivers against the investigation's ORIGINAL reference date
    # (its completion time), not wall-clock "now". The numeric score is stored and
    # fixed; recomputing recency-dependent drivers with today's date made an old
    # report's explanation drift away from its own stored score ("within the last
    # year" quietly becoming "about 2 years ago"). Pinning the reference date keeps
    # the recomputed drivers/actions consistent with the persisted score.
    reference_dt = _report_reference_date(data)
    credential_assessment = assess_credential_risk_from_report(data, as_of=reference_dt)
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
    data["credential_risk_insufficient_evidence"] = credential_assessment.insufficient_evidence
    stored_brief = data.get("defenders_brief_json")
    if isinstance(stored_brief, dict) and stored_brief.get("risk_level"):
        data["defenders_brief"] = stored_brief
    else:
        data["defenders_brief"] = defenders_brief_to_dict(
            generate_defenders_brief_from_report(data)
        )
    data.pop("defenders_brief_json", None)

    # RC4 (Output-Trust): reconcile the two risk systems into ONE authoritative
    # level. The exposure-derived level (breadth of what was found) and the
    # Defender's-Brief level (actionable credential/threat assessment) routinely
    # disagreed (critical/HIGH, HIGH/LOW). The Brief is the authoritative security
    # assessment, so the headline ``risk_level`` follows it; the exposure-derived
    # level is preserved, clearly labelled, as ``exposure_level`` (breadth).
    brief_risk = str((data.get("defenders_brief") or {}).get("risk_level") or "").upper()
    if brief_risk:
        data["exposure_level"] = data.get("risk_level")
        data["risk_level"] = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "MINIMAL": "low",
            "UNKNOWN": "unknown",
        }.get(brief_risk, data.get("risk_level"))

    # Phase 2A — irreversible suppression at the report boundary. enrich_report
    # feeds both the raw report API (get_report) and all six exporters, so one
    # read-time filter here excludes a suppressed subject from every output.
    try:
        from .suppression import redact_report

        data = redact_report(data)
    except SuppressionUnavailable:
        # R2 (S1): FAIL CLOSED. The store is unreadable, so we cannot prove the
        # report is suppression-clean — propagate so the boundary returns an
        # unavailable response rather than an unfiltered report. (Previously a
        # blanket ``except Exception`` swallowed this into a fail-open skip.)
        raise
    except Exception:  # any OTHER assembly hiccup must not crash the report
        import logging

        logging.getLogger(__name__).exception("suppression redaction skipped")

    # Phase 2D — attach the eligibility verdict (orthogonal to the exposure /
    # confidence scores, which are left untouched). An investigate run has no
    # per-address deliverability score, so under the default security mode this
    # is "research-only"; a suppressed subject is "suppressed".
    try:
        from .eligibility import Eligibility, evaluate
        from .product_mode import policy_status_for_mode

        mode = data.get("mode") or "security-investigation"
        if data.get("suppressed"):
            data["eligibility"] = Eligibility.SUPPRESSED.value
            data["eligibility_reason"] = "subject is suppressed"
        else:
            verdict = evaluate(
                mode=mode,
                policy_status=policy_status_for_mode(mode),
                suppressed=False,
                confidence=None,
            )
            data["eligibility"] = verdict.verdict.value
            data["eligibility_reason"] = verdict.reason
    except Exception:
        import logging

        logging.getLogger(__name__).exception("eligibility verdict skipped")

    # Phase 2E / R12 — export watermark: which run/mode/policy produced this
    # report. Prefer the RECORDED manifest (attached by get_investigation) so an
    # old report shows its own run's time/version, not the current process/time;
    # fall back to a freshly generated manifest only when none was recorded.
    try:
        recorded = data.get("run_manifest")
        if isinstance(recorded, dict) and recorded:
            data["watermark"] = recorded
        else:
            from .run_manifest import manifest_dict

            data["watermark"] = manifest_dict(
                run_id=str(data.get("id") or "unknown"),
                pipeline="investigate",
                mode=str(data.get("mode") or "security-investigation"),
            )
    except Exception:
        import logging

        logging.getLogger(__name__).exception("watermark skipped")

    return data

class InvestigationService:
    """
    Application-layer facade over the DB and InvestigationEngine.

    Intended to be instantiated per-request with an injected AsyncSession::

        service = InvestigationService(session)
        investigation_id, created_at, queue, cached = await service.create_investigation(
            "user@example.com"
        )
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _find_recent_complete(
        self,
        email: str,
        canonical_email: str | None = None,
        mode: str | None = None,
    ) -> Investigation | None:
        """Return the most recent COMPLETE investigation for `email` within the
        configured cache window, or None if none qualifies.

        L2 governance fix: reuse is scoped to the *same product mode*. A result
        produced under one mode (e.g. ``security-investigation``) must never be
        served to a request in another mode (e.g. ``public-business-contact``),
        which would leak security-scope data past the governance gate.
        """
        window = timedelta(minutes=settings.investigation_cache_window_minutes)
        cutoff = datetime.now(timezone.utc) - window
        candidates = [email]
        if canonical_email and canonical_email not in candidates:
            candidates.append(canonical_email)
        conditions = [
            Investigation.email.in_(candidates),
            Investigation.status == InvestigationStatus.COMPLETE,
            Investigation.created_at >= cutoff,
        ]
        if mode is not None:
            conditions.append(Investigation.mode == mode)
        result = await self._session.execute(
            select(Investigation)
            .where(*conditions)
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
        budget_seconds: float | None = None,
        mode: str | None = None,
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
        from .product_mode import normalize_mode

        canonical_email = normalize_email_address(email).canonical_email
        # Resolve the effective mode exactly as the engine does (per-run override
        # else the server default) so the cache key matches the mode actually
        # persisted on a completed investigation.
        resolved_mode = normalize_mode(
            mode if mode is not None else settings.product_mode
        ).value
        if (
            not force
            and settings.enable_investigation_cache
            and module_names is None
            and not enable_modules
        ):
            recent = await self._find_recent_complete(
                email, canonical_email, mode=resolved_mode
            )
            if recent is not None:
                return recent.id, recent.created_at, None, True

        inv = Investigation(
            email=email,
            canonical_email=canonical_email,
            status=InvestigationStatus.PENDING,
            mode=resolved_mode,
        )
        self._session.add(inv)
        await self._session.flush()
        investigation_id = inv.id
        created_at = inv.created_at
        await self._session.commit()

        engine = InvestigationEngine(
            timeout=settings.module_timeout_seconds,
            max_concurrency=settings.max_concurrent_modules,
            budget_seconds=budget_seconds,
            min_module_seconds=settings.investigation_budget_min_module_seconds,
            mode=mode,
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

        # R12 (S1) — attach the RECORDED run manifest (this run's own time /
        # version / config), so enrich_report's watermark reflects the run rather
        # than the current process. Guarded → None when nothing was recorded.
        from .run_manifest import read_run_manifest

        recorded_manifest = await read_run_manifest(inv.id, session=self._session)

        return {
            "id": inv.id,
            "email": inv.email,
            "canonical_email": inv.canonical_email,
            "status": inv.status.value,
            "error": inv.error,
            "run_manifest": recorded_manifest,
            # R12 (S1) — carry the run's product mode into the serialized report
            # so eligibility, watermark and provenance are scoped to the mode the
            # run was collected under (not the default).
            "mode": inv.mode,
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
