from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..core.credential_risk import credential_risk_band
from ..core.engine import QueueEvent
from ..db.database import AsyncSessionLocal
from ..db.models import Investigation
from . import queue_registry

router = APIRouter()

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
        { "type": "module_error",  "module": "social", "error": "...", "status": "failed" }
        {
          "type": "investigation_complete",
          "exposure_score": 72,
          "risk_level": "high",
          "credential_risk_score": 81,
          "credential_risk_band": "CRITICAL",
          "timeline": { ... }
        }
    """
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
                # Sentinel: engine finished and persisted — fetch final score from DB.
                async with AsyncSessionLocal() as db:
                    inv = await db.get(Investigation, investigation_id)
                score = inv.exposure_score if inv else None
                credential_score = inv.credential_risk_score if inv else None
                timeline = inv.timeline_json if inv else None
                await websocket.send_json(
                    {
                        "type": "investigation_complete",
                        "canonical_email": inv.canonical_email if inv else None,
                        "exposure_score": score,
                        "risk_level": "unknown" if score is None else (
                            "low" if score <= 20 else "medium" if score <= 50 else "high" if score <= 80 else "critical"
                        ),
                        "credential_risk_score": credential_score,
                        "credential_risk_band": credential_risk_band(credential_score),
                        "timeline": timeline or {},
                    }
                )
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
                await websocket.send_json(
                    {
                        "type": "module_result",
                        "module": item.module_name,
                        "findings": item.result.findings,
                        "status": item.result.status.value,
                    }
                )
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
