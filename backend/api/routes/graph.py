from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...core.breach_normalizer import collapse_breach_findings
from ...core.identity_graph import IdentityGraph
from ...db.database import get_db
from ...db.models import Investigation

router = APIRouter()


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

    if inv.graph_data and inv.graph_data.get("nodes"):
        return {
            "nodes": inv.graph_data.get("nodes", []),
            "links": inv.graph_data.get("links", []),
        }

    if inv.status.value != "complete":
        raise HTTPException(
            status_code=409,
            detail="Investigation not complete — graph not yet available",
        )

    graph_input = {
        "email": inv.email,
        "findings": collapse_breach_findings([
            {"module_name": f.module_name, "data": f.data}
            for f in inv.findings
        ]),
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

    raw_findings = collapse_breach_findings([
        {"module_name": f.module_name, "data": f.data}
        for f in inv.findings
    ])
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
