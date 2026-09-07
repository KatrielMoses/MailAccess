"""Phase 7C — org-chart reconstruction from harvested contacts.

ZoomInfo sells org charts as a premium feature; we derive a usable one for free
from data we already hold — the Phase-3A person fields + Phase-3B seniority band
+ department. This module is pure: it clusters a list of already-normalized
contact rows (department x seniority) and renders a self-contained HTML/SVG
artifact. It performs no collection and no inference-to-fill — a contact with no
resolved title lands in the ``unknown`` band (evidence-or-null still holds).

Eligibility is respected: :func:`build_org_chart` takes ``outreach`` (default
True) and, when set, keeps only rows whose eligibility verdict is sendable
(:func:`eligibility.is_outreach_verdict`) — so suppressed / research-only
contacts never leak into an outreach org chart. The caller supplies rows already
carrying an ``eligibility`` verdict (see
``domain_harvest_report.format_harvest_orgchart_export``), so the chart inherits
the exact mode/eligibility of its inputs.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from .eligibility import is_outreach_verdict
from .seniority_classifier import _BAND_ORDER, BAND_UNKNOWN

# Vertical ordering, most senior first, with the catch-all band last.
SENIORITY_ORDER: tuple[str, ...] = (*_BAND_ORDER, BAND_UNKNOWN)
_BAND_RANK = {band: i for i, band in enumerate(SENIORITY_ORDER)}

# Human labels for the bands (rendering only).
_BAND_LABEL = {
    "c-level": "C-Level",
    "vp": "VP",
    "director": "Director",
    "manager": "Manager",
    "ic": "Individual Contributor",
    "unknown": "Unclassified",
}
_UNASSIGNED = "unassigned"


def _band_of(person: dict[str, Any]) -> str:
    band = (person.get("seniority") or "").strip().lower()
    return band if band in _BAND_RANK else BAND_UNKNOWN


def _department_of(person: dict[str, Any]) -> str:
    dept = (person.get("department") or "").strip()
    return dept.lower() if dept else _UNASSIGNED


def _contact_node(row: dict[str, Any]) -> dict[str, Any]:
    person = row.get("person") or {}
    return {
        "email": row.get("email"),
        "full_name": person.get("full_name"),
        "job_title": person.get("job_title"),
        "seniority": _band_of(person),
        "department": _department_of(person),
        "linkedin_url": person.get("linkedin_url"),
        "confidence_score": row.get("confidence_score"),
        "eligibility": row.get("eligibility"),
    }


def build_org_chart(
    rows: list[dict[str, Any]],
    *,
    domain: str | None = None,
    outreach: bool = True,
    include_review: bool = False,
) -> dict[str, Any]:
    """Cluster ``rows`` into a department x seniority org chart.

    Each row is a dict with an ``email``, a nested ``person`` block (from
    ``_person_export``: full_name/job_title/seniority/department/linkedin_url),
    an ``eligibility`` verdict, and a ``confidence_score``.

    When ``outreach`` is True (the default) only sendable rows are placed; the
    number of rows dropped for eligibility is reported as ``excluded_count``.
    """
    kept: list[dict[str, Any]] = []
    excluded = 0
    for row in rows:
        if outreach and not is_outreach_verdict(
            str(row.get("eligibility", "")), include_review=include_review
        ):
            excluded += 1
            continue
        kept.append(_contact_node(row))

    # Group department -> band -> contacts.
    by_dept: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for node in kept:
        by_dept.setdefault(node["department"], {}).setdefault(node["seniority"], []).append(node)

    departments: list[dict[str, Any]] = []
    for dept_name, bands in by_dept.items():
        band_blocks: list[dict[str, Any]] = []
        for band in sorted(bands, key=lambda b: _BAND_RANK.get(b, len(SENIORITY_ORDER))):
            contacts = sorted(
                bands[band],
                key=lambda c: (
                    -(c["confidence_score"] or 0.0),
                    (c["full_name"] or c["email"] or "").lower(),
                ),
            )
            band_blocks.append({"band": band, "label": _BAND_LABEL.get(band, band),
                                 "count": len(contacts), "contacts": contacts})
        dept_count = sum(b["count"] for b in band_blocks)
        departments.append(
            {"department": dept_name, "count": dept_count, "bands": band_blocks}
        )

    # Order departments: largest first, unassigned last, then alphabetical.
    departments.sort(
        key=lambda d: (d["department"] == _UNASSIGNED, -d["count"], d["department"])
    )

    placed = len(kept)
    unplaced = sum(
        1 for n in kept if n["seniority"] == BAND_UNKNOWN and n["department"] == _UNASSIGNED
    )
    return {
        "kind": "org_chart",
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "outreach_only": outreach,
        "total_contacts": placed,
        "unplaced_contacts": unplaced,
        "excluded_for_eligibility": excluded,
        "seniority_order": list(SENIORITY_ORDER),
        "departments": departments,
    }


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def render_org_chart_html(chart: dict[str, Any]) -> str:
    """Render *chart* as a single self-contained HTML document (no external assets)."""
    domain = _esc(chart.get("domain") or "")
    rows_html: list[str] = []
    for dept in chart.get("departments", []):
        band_html: list[str] = []
        for band in dept.get("bands", []):
            cards = "".join(
                f'<div class="card">'
                f'<div class="name">{_esc(c["full_name"] or c["email"])}</div>'
                f'<div class="title">{_esc(c["job_title"] or "")}</div>'
                f'<div class="email">{_esc(c["email"])}</div>'
                f"</div>"
                for c in band.get("contacts", [])
            )
            band_html.append(
                f'<div class="band"><div class="band-label">{_esc(band["label"])} '
                f'<span class="count">{band["count"]}</span></div>'
                f'<div class="cards">{cards}</div></div>'
            )
        rows_html.append(
            f'<section class="dept"><h2>{_esc(dept["department"])} '
            f'<span class="count">{dept["count"]}</span></h2>{"".join(band_html)}</section>'
        )
    body = "".join(rows_html) or '<p class="empty">No eligible contacts to chart.</p>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Org chart — {domain}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 14px/1.4 system-ui, sans-serif; margin: 24px; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .meta {{ color: #666; font-size: 12px; margin-bottom: 20px; }}
  .dept {{ margin: 0 0 28px; }}
  .dept h2 {{ font-size: 15px; text-transform: capitalize; border-bottom: 2px solid #ccc;
              padding-bottom: 4px; }}
  .band {{ margin: 10px 0; }}
  .band-label {{ font-weight: 600; font-size: 12px; color: #555; margin-bottom: 6px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .card {{ border: 1px solid #d0d0d0; border-radius: 8px; padding: 8px 12px; min-width: 180px;
           background: rgba(127,127,127,.06); }}
  .card .name {{ font-weight: 600; }}
  .card .title {{ font-size: 12px; color: #555; }}
  .card .email {{ font-size: 11px; color: #888; }}
  .count {{ display: inline-block; background: #8884; border-radius: 10px; padding: 0 8px;
            font-size: 11px; font-weight: 600; }}
  .empty {{ color: #888; }}
</style></head>
<body>
<h1>Org chart — {domain}</h1>
<div class="meta">{chart.get("total_contacts", 0)} contacts ·
  {chart.get("excluded_for_eligibility", 0)} excluded for eligibility ·
  generated {_esc(chart.get("generated_at"))}
  {"· outreach-only" if chart.get("outreach_only") else ""}</div>
{body}
</body></html>"""
