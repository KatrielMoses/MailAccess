from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...core.breach_normalizer import collapse_breach_findings
from ...core.identity_graph import IdentityGraph
from ...core.suppression import (
    SuppressionUnavailable,
    filter_findings,
    load_index,
    redact_graph,
    subject_suppressed,
)
from ...db.database import get_db
from ...db.models import Investigation

router = APIRouter()


async def _suppression_index() -> object:
    """Load the suppression index, translating unavailability into a fail-closed
    503 so no route can serve an unfiltered graph/cluster view."""
    try:
        return await load_index()
    except SuppressionUnavailable as exc:
        raise HTTPException(
            status_code=503, detail="suppression store unavailable"
        ) from exc


@router.get("/report/{investigation_id}/graph")
async def get_investigation_graph(
    investigation_id: str,
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Return the identity graph in D3.js force-directed format."""
    result = await session.execute(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .options(
            selectinload(Investigation.findings),
        )
    )
    inv = result.scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # R2 (S1) — this route bypasses enrich_report/redact_report, so suppression
    # must be enforced here directly. Fail-closed if the store is unavailable.
    index = await _suppression_index()
    if subject_suppressed(index, email=inv.email):
        return {"nodes": [], "links": [], "suppressed": True}

    if inv.graph_data and inv.graph_data.get("nodes"):
        return redact_graph(
            {
                "nodes": inv.graph_data.get("nodes", []),
                "links": inv.graph_data.get("links", []),
            },
            index,
        )

    if inv.status.value != "complete":
        raise HTTPException(
            status_code=409,
            detail="Investigation not complete — graph not yet available",
        )

    graph_input = {
        "email": inv.email,
        # Redact suppressed findings at the source so the built graph is clean.
        "findings": filter_findings(
            collapse_breach_findings([
                {"module_name": f.module_name, "data": f.data}
                for f in inv.findings
            ]),
            index,
        ),
    }
    graph = IdentityGraph.build(graph_input)
    d3 = graph.to_d3()
    return d3

@router.get("/report/{investigation_id}/clusters")
async def get_investigation_clusters(
    investigation_id: str,
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Return identity clusters scored by confidence."""
    result = await session.execute(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .options(
            selectinload(Investigation.findings),
        )
    )
    inv = result.scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if inv.status.value != "complete":
        raise HTTPException(
            status_code=409,
            detail="Investigation not complete — clusters not yet available",
        )

    # R2 (S1) — enforce suppression here (this route bypasses redact_report).
    index = await _suppression_index()
    if subject_suppressed(index, email=inv.email):
        return {
            "clusters": [],
            "total_findings": 0,
            "collapsed_findings": 0,
            "shadow_findings": [],
            "suppressed": True,
        }

    raw_findings = filter_findings(
        collapse_breach_findings([
            {"module_name": f.module_name, "data": f.data}
            for f in inv.findings
        ]),
        index,
    )
    # Phase 6B.2 — supply the persisted name consensus to the V2
    # shadow-profile detector so the CLI can render the SHADOW PROFILES
    # section without re-running the engine.
    name_consensus_dict: dict | None = None
    if inv.confirmed_name:
        name_consensus_dict = {
            "confirmed_name": inv.confirmed_name,
            "name_confidence": inv.name_confidence,
        }
    graph_input = {
        "email": inv.email,
        "findings": raw_findings,
    }
    graph = IdentityGraph.build(
        graph_input, name_consensus=name_consensus_dict
    )
    clusters = graph.to_cli(raw_findings)

    total_findings = len(raw_findings)
    collapsed_findings = sum(c["finding_count"] for c in clusters if c["is_collision"])

    return {
        "clusters": clusters,
        "total_findings": total_findings,
        "collapsed_findings": collapsed_findings,
        "shadow_findings": graph.shadow_findings,
    }
