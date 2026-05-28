from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.service import InvestigationService, enrich_report
from ...db.database import get_db
from ...exporters import EXPORTERS
from .. import queue_registry

router = APIRouter()

async def _cleanup_queue(investigation_id: str, delay: float = 300.0) -> None:
    await asyncio.sleep(delay)
    queue_registry.pop(investigation_id)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    email: str
    modules: list[str] | None = None
    force: bool = False
    enable_modules: list[str] = []


class InvestigateResponse(BaseModel):
    id: str
    status: str
    created_at: str
    cached: bool = False


class InvestigationSummary(BaseModel):
    id: str
    email: str
    canonical_email: str | None = None
    status: str
    exposure_score: int | None
    credential_risk_score: int | None
    created_at: str
    completed_at: str | None


class PaginatedInvestigations(BaseModel):
    total: int
    page: int
    page_size: int
    pages: int
    items: list[InvestigationSummary]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/investigate", response_model=InvestigateResponse, status_code=202)
async def start_investigation(
    body: InvestigateRequest,
    session: AsyncSession = Depends(get_db),
) -> InvestigateResponse:
    """Create a new investigation and kick off the engine in the background.

    Returns `cached=true` when a recent COMPLETE investigation for the same
    email is reused; in that case no engine run is started.
    """
    service = InvestigationService(session)
    investigation_id, created_at, queue, cached = await service.create_investigation(
        body.email, body.modules, force=body.force, enable_modules=body.enable_modules
    )
    if not cached and queue is not None:
        queue_registry.put(investigation_id, queue)
        # Release the queue from memory after 5 minutes if no WS consumer arrives.
        asyncio.create_task(_cleanup_queue(investigation_id, delay=300.0))
    return InvestigateResponse(
        id=investigation_id,
        status="complete" if cached else "pending",
        created_at=created_at.isoformat(),
        cached=cached,
    )


@router.get("/report/{investigation_id}")
async def get_report(
    investigation_id: str,
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Return the full enriched investigation report."""
    service = InvestigationService(session)
    data = await service.get_investigation(investigation_id)

    if data is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return enrich_report(data)


@router.get("/report/{investigation_id}/export")
async def export_report(
    investigation_id: str,
    format: str = Query("json", pattern="^(json|csv|markdown|pdf|stix|maltego)$"),
    session: AsyncSession = Depends(get_db),
) -> Response:
    """Export the investigation report in the requested format."""

    service = InvestigationService(session)
    data = await service.get_investigation(investigation_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    data = enrich_report(data)
    email = data.get("email", "unknown")

    exporter = EXPORTERS[format]()
    if format == "pdf":
        from ...exporters.pdf_exporter import PdfExporter
        assert isinstance(exporter, PdfExporter)
        content = await exporter.generate(investigation_id, data)
    else:
        content = exporter.export(investigation_id, data)
    return Response(
        content=content,
        media_type=exporter.content_type,
        headers={
            "Content-Disposition": (
                f'attachment; filename="mailaccess_{email}_{investigation_id}'
                f'.{"stix.json" if format == "stix" else "maltego.csv" if format == "maltego" else format}"'
            )
        },
    )


@router.get("/investigations", response_model=PaginatedInvestigations)
async def list_investigations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_db),
) -> PaginatedInvestigations:
    """Paginated list of past investigations, newest first."""
    service = InvestigationService(session)
    result = await service.list_investigations(page=page, page_size=page_size)
    return PaginatedInvestigations(
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
        pages=result["pages"],
        items=[
            InvestigationSummary(
                id=item["id"],
                email=item["email"],
                canonical_email=item.get("canonical_email"),
                status=item["status"],
                exposure_score=item.get("exposure_score"),
                credential_risk_score=item.get("credential_risk_score"),
                created_at=item["created_at"],
                completed_at=item.get("completed_at"),
            )
            for item in result["items"]
        ],
    )


@router.delete("/investigation/{investigation_id}", status_code=204, response_class=Response)
async def delete_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_db),
) -> Response:
    """Hard-delete an investigation and all associated findings."""
    service = InvestigationService(session)
    deleted = await service.delete_investigation(investigation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return Response(status_code=204)
