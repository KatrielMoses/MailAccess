"""Maltego local transform server endpoint.

Implements the TRX protocol (XML over HTTP POST) so Maltego Desktop can run
email investigations directly without any API key.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.service import InvestigationService, enrich_report
from ...db.database import get_db
from ...integrations.maltego_transform import build_error_response, build_response, parse_request
from .. import queue_registry

logger = logging.getLogger("mailaccess.maltego")

router = APIRouter()

_TRANSFORM_TIMEOUT = 55.0
_XML = "application/xml"


@router.post("/email_investigate")
async def email_investigate(
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> Response:
    """TRX transform: run a full email investigation and return Maltego entities."""
    # Phase 2F — the Maltego full-investigation path is expensive; cap it per
    # principal (auth itself is enforced by the API-key middleware, which no
    # longer bypasses /maltego/).
    from ..security import enforce_quota

    enforce_quota(request)

    body = await request.body()

    try:
        email = parse_request(body)
    except Exception as exc:
        return Response(
            content=build_error_response(f"Invalid TRX request: {exc}"),
            media_type=_XML,
        )

    service = InvestigationService(session)
    try:
        investigation_id, _created_at, queue, cached = await service.create_investigation(email)
        if not cached and queue is not None:
            queue_registry.put(investigation_id, queue)
    except Exception as exc:
        logger.exception("Failed to start investigation for %s", email)
        return Response(
            content=build_error_response(f"Failed to start investigation: {exc}"),
            media_type=_XML,
        )

    # Drain the event queue until the engine pushes the None sentinel or we hit 55s.
    # When `cached` is true we reused a finished investigation — no queue to drain.
    partial = False
    if not cached and queue is not None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _TRANSFORM_TIMEOUT

        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                partial = True
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=remaining)
                if event is None:  # completion sentinel from the engine
                    break
            except asyncio.TimeoutError:
                partial = True
                break

    data = await service.get_investigation(investigation_id)
    if data is None:
        return Response(
            content=build_error_response("Investigation record not found"),
            media_type=_XML,
        )

    return Response(
        content=build_response(enrich_report(data), partial=partial),
        media_type=_XML,
    )
