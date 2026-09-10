from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..core.credential_risk import credential_risk_band
from ..core.engine import QueueEvent
from ..core.suppression import (
    SuppressionUnavailable,
    filter_findings,
    load_index_sync,
)
from ..db.database import AsyncSessionLocal
from ..db.models import Investigation, InvestigationStatus
from . import queue_registry

router = APIRouter()

_MAX_WS_PAYLOAD_BYTES = 900 * 1024


def _safe_payload(size_hint: int, extra: dict | None = None) -> dict:
    extra = extra or {}
    return {"_truncated": True, "findings_count": size_hint, **extra}


def _terminal_frame(inv: Investigation | None) -> dict:
    """Build the WS terminal frame from the PERSISTED investigation status (L4).

    The engine's ``queue.put(None)`` sentinel fires on both success and failure, so
    outcome must be read from the row: a missing row or ``FAILED`` status yields an
    ``investigation_failed`` frame rather than a success frame with null scores.
    """
    if inv is None or inv.status == InvestigationStatus.FAILED:
        return {
            "type": "investigation_failed",
            "error": (
                (inv.error if inv and inv.error else "investigation failed")
                if inv is not None
                else "investigation not found"
            ),
        }
    score = inv.exposure_score
    credential_score = inv.credential_risk_score
    frame = {
        "type": "investigation_complete",
        "canonical_email": inv.canonical_email,
        "exposure_score": score,
        "risk_level": "unknown" if score is None else (
            "low" if score <= 20 else "medium" if score <= 50 else "high" if score <= 80 else "critical"
        ),
        "credential_risk_score": credential_score,
        "credential_risk_band": credential_risk_band(credential_score),
        "timeline": inv.timeline_json or {},
    }
    # R2 (S1) — the terminal frame emits the subject's canonical email + timeline;
    # withhold both if the subject is suppressed, and fail closed (withhold) if
    # the suppression store cannot be read.
    try:
        index = load_index_sync()
    except SuppressionUnavailable:
        frame["canonical_email"] = None
        frame["timeline"] = {}
        frame["_suppression_unavailable"] = True
        return frame
    if inv.canonical_email and index.hit(email=inv.canonical_email):
        frame["canonical_email"] = None
        frame["timeline"] = {}
        frame["suppressed"] = True
    return frame


def _prepare_module_result_payload(item: QueueEvent) -> dict:
    assert item.result is not None
    base = {
        "type": "module_result",
        "module": item.module_name,
        "status": item.result.status.value,
    }
    # R2 (S1) — live module findings are streamed raw; redact suppressed subjects
    # before they reach the socket. Fail closed: if the store is unreadable,
    # withhold findings for this frame rather than stream them unfiltered.
    try:
        findings = filter_findings(item.result.findings)
    except SuppressionUnavailable:
        base["_suppression_unavailable"] = True
        return base
    raw = json.dumps({"findings": findings})
    if len(raw.encode("utf-8")) <= _MAX_WS_PAYLOAD_BYTES:
        base["findings"] = findings
    else:
        base.update(_safe_payload(len(findings)))
    return base

@router.websocket("/ws/investigate/{investigation_id}")
async def ws_investigate(investigation_id: str, websocket: WebSocket) -> None:
    """
    Stream investigation events in real time.

    Connect immediately after POST /api/investigate. The server pushes one
    event per module as it starts and completes, then a final
    "investigation_complete" frame when all modules are done and the DB is
    persisted.

    Event frames::

        { "type": "module_start",  "module": "hibp", "timestamp": "..." }
        { "type": "module_result", "module": "hibp", "findings": [...], "status": "success" }
        # oversized frame (R9): no `findings`, carries the truncation marker
        { "type": "module_result", "module": "hibp", "status": "success",
          "_truncated": true, "findings_count": 5000 }
        { "type": "module_error",  "module": "social", "error": "...", "status": "failed" }
        {
          "type": "investigation_complete",
          "exposure_score": 72,
          "risk_level": "high",
          "credential_risk_score": 81,
          "credential_risk_band": "CRITICAL",
          "timeline": { ... }
        }
        # terminal FAILURE frame (R9 / L4) — read from the persisted row, so the
        # client leaves the "running" state instead of hanging:
        { "type": "investigation_failed", "error": "..." }

    The terminal frame (complete/failed) is authoritative for lifecycle, but the
    client should fetch the persisted report to converge its view (R9): live
    frames may have been partial or truncated.
    """
    # Phase 2F — the WebSocket is authenticated here (BaseHTTPMiddleware does not
    # run for WS). With a key configured it is required (via ?api_key=… or the
    # X-API-Key header); with no key, only local callers are allowed.
    from ..config import settings
    from .security import is_local, key_ok

    if settings.mailaccess_api_key:
        if not key_ok(websocket):
            await websocket.close(code=1008)
            return
    elif not is_local(websocket):
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # The queue is registered before the HTTP 202 response is sent, but poll
    # briefly in case of any scheduling delay (e.g. server under load).
    queue = None
    for _ in range(20):  # up to 10 s (20 × 0.5 s)
        queue = queue_registry.pop(investigation_id)
        if queue is not None:
            break
        await asyncio.sleep(0.5)

    if queue is None:
        await websocket.send_json(
            {"type": "error", "error": "investigation not found or already streaming"}
        )
        await websocket.close(code=1008)
        return

    try:
        while True:
            item: QueueEvent | None = await queue.get()

            if item is None:
                # Sentinel: the engine finished — but it fires on BOTH the success and
                # failure paths, so it carries no outcome. Read the PERSISTED status
                # (L4) instead of assuming success.
                async with AsyncSessionLocal() as db:
                    inv = await db.get(Investigation, investigation_id)
                await websocket.send_json(_terminal_frame(inv))
                # Give the client 5 s to drain the frame before we close.
                await asyncio.sleep(5)
                break

            if item.type == "module_start":
                await websocket.send_json(
                    {
                        "type": "module_start",
                        "module": item.module_name,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            elif item.type == "module_result":
                assert item.result is not None
                await websocket.send_json(_prepare_module_result_payload(item))
            elif item.type == "module_error":
                assert item.result is not None
                await websocket.send_json(
                    {
                        "type": "module_error",
                        "module": item.module_name,
                        "error": ", ".join(item.result.errors or ["unknown error"]),
                        "status": "failed",
                    }
                )

    except WebSocketDisconnect:
        # Drain the queue so the engine's background task isn't blocked.
        asyncio.create_task(_drain_silently(queue))


async def _drain_silently(queue: asyncio.Queue) -> None:
    while True:
        item = await queue.get()
        if item is None:
            break
