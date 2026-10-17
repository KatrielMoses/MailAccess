from __future__ import annotations

import asyncio
import json
import time
import traceback

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.service import InvestigationService, enrich_report
from ...core.suppression import SuppressionUnavailable
from ...db.database import get_db
from ...exporters import EXPORTERS
from ...core import run_events
from .. import queue_registry

router = APIRouter()

# R2 (S1) — a suppression-store read failure must fail closed at the boundary.
_SUPPRESSION_UNAVAILABLE = HTTPException(
    status_code=503, detail="suppression store unavailable"
)


def _parse_iso(value: object) -> object | None:
    """Parse an ISO-8601 timestamp string to a datetime (R12 provenance
    ``as_of`` bound). Returns None for missing/invalid values."""
    if not isinstance(value, str) or not value:
        return None
    from datetime import datetime

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

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
    # Phase 1B — overall wall-clock completion budget (seconds). None = server
    # default (settings.investigation_budget_seconds); <= 0 = unlimited.
    budget_seconds: float | None = None
    # Phase 2B — product mode for this run. None = server default
    # (settings.product_mode). One of: security-investigation,
    # public-business-contact, org-authorized-verification.
    mode: str | None = None
    # BYOK Netlas per-run opt-out (``--no-netlas``). Accepted now so the CLI
    # contract is stable; investigate-path Netlas sources (F2+) gate on it via
    # ``netlas_client.netlas_active(no_netlas=...)``.
    no_netlas: bool = False
    no_ipgeo: bool = False
    no_whoisfreaks: bool = False
    # F7 deep mode (``--org-surface-deep``): full subdomain enumeration.
    org_surface_deep: bool = False
    # F8 (``--refresh``): force a Netlas fetch past the 30-day store gate.
    refresh: bool = False


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
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> InvestigateResponse:
    """Create a new investigation and kick off the engine in the background.

    Returns `cached=true` when a recent COMPLETE investigation for the same
    email is reused; in that case no engine run is started.
    """
    # Phase 2F — per-principal quota on this investigation-triggering endpoint.
    from ..security import enforce_quota

    enforce_quota(request)
    service = InvestigationService(session)
    investigation_id, created_at, queue, cached = await service.create_investigation(
        body.email,
        body.modules,
        force=body.force,
        enable_modules=body.enable_modules,
        budget_seconds=body.budget_seconds,
        mode=body.mode,
        no_netlas=body.no_netlas,
        no_ipgeo=body.no_ipgeo,
        no_whoisfreaks=body.no_whoisfreaks,
        org_surface_deep=body.org_surface_deep,
        refresh=body.refresh,
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


SSE_HEARTBEAT_SECONDS = 15.0
_DB_POLL_SECONDS = 0.5
# Events that carry finding content; withheld for a suppressed subject.
_FINDING_EVENTS = frozenset({"finding", "finding_updated", "edge_added"})


def wire_event(event: dict) -> dict:
    """The contract's wire shape: the event's own fields at the top level plus ``seq``
    and ``ts``. No ``payload`` wrapper; the type is on the ``event:`` line."""
    return {"seq": event["seq"], "ts": event["ts"], **event["payload"]}


def _sse_message(event: dict) -> str:
    body = json.dumps(wire_event(event), separators=(",", ":"))
    return f"id: {event['seq']}\nevent: {event['type']}\ndata: {body}\n\n"


async def _saved_events(investigation_id: str, since: int) -> list[dict]:
    from sqlalchemy import select

    from ...db.database import AsyncSessionLocal
    from ...db.models import RunEvent

    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(RunEvent)
                .where(RunEvent.investigation_id == investigation_id, RunEvent.seq > since)
                .order_by(RunEvent.seq)
            )
        ).scalars().all()
    return [{"seq": r.seq, "ts": r.ts, "type": r.type, "payload": r.payload} for r in rows]


async def _events_from_log(investigation_id: str, since: int):
    """Replay saved events, then follow them: from the live emitter when this process
    owns the run, else by polling the saved log. Yields ``None`` as a heartbeat tick."""
    emitter = run_events.get(investigation_id)
    if emitter is not None:
        async for event in emitter.follow(since, heartbeat=SSE_HEARTBEAT_SECONDS):
            yield event
        return
    from ...db.database import AsyncSessionLocal
    from ...db.models import Investigation, InvestigationStatus

    last_beat = time.monotonic()
    cursor = since
    while True:
        batch = await _saved_events(investigation_id, cursor)
        for event in batch:
            cursor = event["seq"]
            yield event
            if event["type"] == "run_done":
                return
        if not batch:
            async with AsyncSessionLocal() as db:
                inv = await db.get(Investigation, investigation_id)
            if inv is None or inv.status in (
                InvestigationStatus.COMPLETE,
                InvestigationStatus.FAILED,
            ):
                # Finished with nothing (more) to replay, e.g. a run saved before
                # the event log existed: close rather than hang.
                tail = await _saved_events(investigation_id, cursor)
                if not tail:
                    return
                continue
            # The run may now live in this process (registered after the first check).
            emitter = run_events.get(investigation_id)
            if emitter is not None:
                async for event in emitter.follow(cursor, heartbeat=SSE_HEARTBEAT_SECONDS):
                    yield event
                return
            await asyncio.sleep(_DB_POLL_SECONDS)
        if time.monotonic() - last_beat >= SSE_HEARTBEAT_SECONDS:
            last_beat = time.monotonic()
            yield None


@router.get("/investigations/{investigation_id}/events")
async def stream_investigation_events(
    investigation_id: str,
    request: Request,
    since: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Server-sent events for one run: replay every saved event with ``seq > since``,
    then follow live until ``run_done``. Each message carries ``id: <seq>`` so a
    client resumes with ``Last-Event-ID``. Works after the run finished (full
    replay) and for any number of viewers. A heartbeat comment goes out every 15 s."""
    from ...core.suppression import load_index, subject_suppressed
    from ...db.models import Investigation

    inv = await session.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    header = request.headers.get("last-event-id")
    if header and header.strip().isdigit():
        since = max(since, int(header.strip()))
    # R2 (S1) — a suppressed subject's findings never stream; fail closed.
    # The store can be momentarily busy while a run is writing (SQLite): retry a few
    # times before failing closed, so a viewer is not refused by a transient lock.
    index = None
    for attempt in range(4):
        try:
            index = await load_index()
            break
        except SuppressionUnavailable as exc:
            if attempt == 3:
                raise _SUPPRESSION_UNAVAILABLE from exc
            await asyncio.sleep(0.25 * (attempt + 1))
    subject = inv.canonical_email or inv.email
    withhold = bool(subject) and subject_suppressed(index, email=subject)

    async def generate():
        yield ": stream open\n\n"
        async for event in _events_from_log(investigation_id, since):
            if event is None:
                yield ": hb\n\n"
                continue
            if withhold and event["type"] in _FINDING_EVENTS:
                continue
            yield _sse_message(event)
            if event["type"] == "run_done":
                return

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
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

    # R2 (S1) — enrich_report runs the suppression redactor; fail closed (503)
    # if the store is unreadable rather than return an unfiltered report.
    try:
        enriched = enrich_report(data)
    except SuppressionUnavailable as exc:
        raise _SUPPRESSION_UNAVAILABLE from exc
    # Phase 1E — attach ledger-derived field provenance (conflict resolution).
    # Additive and fully guarded: never alters existing keys or fails the report.
    try:
        from ...core.claim_resolver import resolve_report_fields

        subject = enriched.get("canonical_email") or enriched.get("email")
        if subject:
            # R12 (S1) — scope provenance to THIS run's mode and run time so a
            # later or different-mode run can't leak a name/title into it.
            as_of = _parse_iso(enriched.get("completed_at"))
            # Provider facts count only when that provider was ON for THIS run.
            from ...core.capabilities import allowed_providers_for_run

            allowed = await allowed_providers_for_run(investigation_id, session=session)
            provenance = await resolve_report_fields(
                str(subject),
                session=session,
                mode=enriched.get("mode"),
                as_of=as_of,
                allowed_providers=allowed,
            )
            if provenance:
                # R2 — provenance is attached AFTER redaction, so redact it too.
                from ...core.suppression import redact_field_provenance

                provenance = redact_field_provenance(provenance)
                if provenance:
                    enriched["field_provenance"] = provenance
    except SuppressionUnavailable as exc:
        raise _SUPPRESSION_UNAVAILABLE from exc
    except Exception:
        pass
    return enriched


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

    try:
        data = enrich_report(data)
    except SuppressionUnavailable as exc:
        raise _SUPPRESSION_UNAVAILABLE from exc
    email = data.get("email", "unknown")

    exporter = EXPORTERS[format]()
    if format == "pdf":
        from ...exporters.pdf_exporter import PdfExporter

        assert isinstance(exporter, PdfExporter)
        try:
            content = await exporter.generate(investigation_id, data)
        except (ImportError, OSError):
            print(traceback.format_exc())
            return JSONResponse(
                status_code=422,
                content={
                    "error": "PDF export requires weasyprint.",
                    "install": "pip install mailaccess[pdf]",
                },
            )
        except Exception:
            print(traceback.format_exc())
            raise
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
    # R2 (S1) — a suppressed subject must not appear even in the summary list.
    # Fail closed if the store is unreadable. Empty index → zero-overhead pass.
    from ...core.suppression import load_index, subject_suppressed

    try:
        index = await load_index()
    except SuppressionUnavailable as exc:
        raise _SUPPRESSION_UNAVAILABLE from exc
    items = []
    for item in result["items"]:
        subject = item.get("canonical_email") or item.get("email")
        if isinstance(subject, str) and subject_suppressed(index, email=subject):
            continue
        items.append(
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
        )
    return PaginatedInvestigations(
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
        pages=result["pages"],
        items=items,
    )


@router.delete("/investigation/{investigation_id}", status_code=204, response_class=Response)
async def delete_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_db),
) -> Response:
    """Take down an investigation: delete it and all associated findings, then
    record the takedown (Phase 2E) so the subject cannot silently re-enter — a
    companion suppression row blocks re-collection and the action is written to
    the tamper-evident audit log."""
    service = InvestigationService(session)
    # Capture the subject before deletion so the takedown can suppress it.
    existing = await service.get_investigation(investigation_id)
    subject_email = None
    if existing:
        subject_email = existing.get("canonical_email") or existing.get("email")

    deleted = await service.delete_investigation(investigation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if subject_email:
        from backend.core.takedown import record_takedown

        await record_takedown(
            email=subject_email,
            removed_ref=investigation_id,
            reason="investigation deleted via API",
        )
    return Response(status_code=204)
