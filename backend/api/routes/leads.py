"""Phase 3A — read-only Lead API over the corpus ``contacts`` projection.

The harvest pipeline is CLI-driven; the corpus ``contacts`` table is its servable
Lead projection but nothing exposed it over HTTP until now. These routes surface
the enriched Lead (person fields + deliverability grade) with the lead-gen
filters marketers expect (seniority band, deliverability grade), backward-
compatibly: they are additive and read-only, and every row still carries the
email-only fields existing consumers rely on.

Auth: mounted under ``/api``, so the Phase-2F ``APIKeyMiddleware`` protects it
(localhost-open in dev, key-enforced off-localhost) with no per-route wiring.
Per-principal quota is applied explicitly, matching the investigate routes.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

from ...core import corpus_store
from ..security import enforce_quota

router = APIRouter()


@router.get("/leads/{domain}")
async def get_leads(
    request: Request,
    domain: str,
    seniority: str | None = Query(
        default=None,
        description="Filter by seniority band (c-level/vp/director/manager/ic).",
    ),
    grade: str | None = Query(
        default=None,
        description="Filter by deliverability grade (Valid/Risky/Catch-all/Invalid/Unknown).",
    ),
    has_person: bool | None = Query(
        default=None, description="Only leads with (true) / without (false) a resolved name."
    ),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """Return the servable Leads harvested for ``domain`` (read-only).

    Data comes from prior harvest runs' corpus projection; this endpoint never
    triggers collection. Suppressed subjects are already excluded at write time.
    """
    enforce_quota(request)
    return await corpus_store.read_leads(
        domain,
        seniority=seniority,
        grade=grade,
        has_person=has_person,
        limit=limit,
        offset=offset,
    )


@router.get("/leads/{domain}/changes")
async def get_change_intelligence(request: Request, domain: str) -> dict:
    """Phase 6F — change signals for a domain from its two most recent crawls.

    Surfaces likely new-hire / departure, title-change, verification-drift and
    likely-stale signals derived from corpus diffs. Read-only; never triggers
    collection.
    """
    enforce_quota(request)
    from ...core.change_intelligence import domain_change_report

    report = await domain_change_report(domain)
    return report.to_dict()


@router.get("/leads/{domain}/verification-history")
async def get_verification_history(
    request: Request,
    domain: str,
    email: str | None = Query(default=None, description="Restrict to one address."),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict:
    """Verification-outcome history for a domain (or a single email within it)."""
    enforce_quota(request)
    history = await corpus_store.read_verification_history(
        email=email, domain=domain, limit=limit
    )
    return {"domain": domain, "email": email, "count": len(history), "history": history}
