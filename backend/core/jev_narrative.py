"""Phase JEV-6 — narrative output call sites (the only user-facing free text).

Hallucination control is load-bearing: every model output is re-validated at the
boundary and DROPPED / DEFERRED if it introduces an email, domain, or entity absent
from the input. JEV supplies only wording and grounded, hypothesis-framed leads — it
never changes the risk level, any score, the severity order, or the SET of
findings/actions. No JEV key → templated brief and no leads section (byte-identical).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from . import jev
from .jev.tasks.narrative import BRIEF_WORDING, FINDING_CORRELATION, MAX_LEADS

_LOG = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.IGNORECASE)
# Any dotted host token (a.b, a.b.c) — used to ground OUTPUT domains against INPUT.
_ANY_DOMAIN_RE = re.compile(r"\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)+\b", re.IGNORECASE)


def _emails(text: str) -> set[str]:
    return {m.group(0).lower() for m in _EMAIL_RE.finditer(text or "")}


def _domains(text: str) -> set[str]:
    return {m.group(0).lower() for m in _ANY_DOMAIN_RE.finditer(text or "")}


def _allowed(*texts: str) -> tuple[set[str], set[str]]:
    """Allowed emails + domains from the input (domains include each email's host)."""
    blob = "\n".join(t for t in texts if t)
    emails = _emails(blob)
    domains = _domains(blob) | {e.split("@", 1)[1] for e in emails}
    return emails, domains


def _introduces_new_entity(text: str, emails: set[str], domains: set[str]) -> bool:
    """True if the output text names an email/domain not present in the input."""
    if any(e not in emails for e in _emails(text)):
        return True
    # Check domains, ignoring hosts of already-allowed emails.
    for d in _domains(text):
        if d in domains:
            continue
        # A domain that is a subdomain/suffix match of an allowed domain is fine.
        if any(d == a or d.endswith("." + a) or a.endswith("." + d) for a in domains):
            continue
        return True
    return False


# ---------------------------------------------------------------------------
# Task 1 — narrative.brief_wording
# ---------------------------------------------------------------------------
async def reword_brief(brief: dict[str, Any], *, email: str, name: str | None) -> dict[str, Any]:
    """Return the brief with reworded wording fields, or the brief unchanged.

    Only the summary / next-action / finding-line text is swapped; risk level,
    severity order, the finding set, and remediation are preserved. Any grounding or
    shape violation (new entity, changed finding count, missing action) → the
    original brief (DEFER to today's template). No-op without a JEV key.
    """
    if not jev.is_active() or not isinstance(brief, dict):
        return brief
    findings = brief.get("top_findings")
    if not isinstance(findings, list):
        return brief
    try:
        finding_texts = [str((f or {}).get("detail") or (f or {}).get("title") or "")
                         for f in findings]
        payload = {
            "risk_level": str(brief.get("risk_level") or "")[:20],
            "subject_email": str(email or "")[:254],
            "subject_name": (name or None) and str(name)[:120],
            "next_action": str(brief.get("next_action") or "")[:400],
            "findings": [
                {"severity": str((f or {}).get("severity") or "")[:20], "text": t[:400]}
                for f, t in zip(findings, finding_texts)
            ],
        }
        verdict = await jev.judge(BRIEF_WORDING, payload)
        if verdict is jev.DEFER:
            return brief
        out = verdict.output
        # Shape: same finding-line count, non-empty summary + action.
        if len(out.finding_lines) != len(findings) or not out.summary.strip() or not (
            out.next_action.strip()
        ):
            return brief
        emails, domains = _allowed(
            payload["subject_email"], payload["subject_name"] or "",
            payload["next_action"], *finding_texts, str(brief.get("risk_summary") or ""),
        )
        candidates = [out.summary, out.next_action, *out.finding_lines]
        if any(_introduces_new_entity(text, emails, domains) for text in candidates):
            return brief  # grounding violation → template
        reworded = dict(brief)
        reworded["risk_summary"] = out.summary.strip()
        reworded["next_action"] = out.next_action.strip()
        reworded["top_findings"] = [
            {**dict(f or {}), "detail": line.strip()}
            for f, line in zip(findings, out.finding_lines)
        ]
        reworded["jev_assisted"] = True
        reworded["jev_task"] = BRIEF_WORDING
        return reworded
    except Exception:
        _LOG.exception("JEV brief rewording skipped")
        return brief


# ---------------------------------------------------------------------------
# Task 2 — narrative.finding_correlation
# ---------------------------------------------------------------------------
async def generate_leads(
    *,
    email: str,
    name: str | None,
    findings: list[dict[str, Any]],
    breaches: list[str],
    roles: list[str],
) -> list[dict[str, Any]] | None:
    """Return grounded analyst leads (each citing existing finding ids), or None.

    A lead is dropped if any cited id is unknown or its text names an entity not in
    the input; the section is capped. None/empty → no leads section (today). No-op
    without a JEV key.
    """
    if not jev.is_active() or not findings:
        return None
    try:
        ids = {str(f.get("id")) for f in findings if f.get("id")}
        summaries = [str(f.get("summary") or "") for f in findings]
        emails, domains = _allowed(
            str(email or ""), str(name or ""), *summaries, *breaches, *roles
        )
        verdict = await jev.judge(FINDING_CORRELATION, {
            "subject_email": str(email or "")[:254],
            "subject_name": (name or None) and str(name)[:120],
            "findings": [
                {"id": str(f["id"])[:80], "type": str(f.get("type") or "")[:60],
                 "summary": str(f.get("summary") or "")[:400]}
                for f in findings if f.get("id")
            ][:60],
            "breaches": [str(b)[:120] for b in breaches][:40],
            "roles": [str(r)[:80] for r in roles][:20],
            "max_leads": MAX_LEADS,
        })
        if verdict is jev.DEFER:
            return None
        leads: list[dict[str, Any]] = []
        for lead in verdict.output.leads:
            based_on = [b for b in lead.based_on if b in ids]
            if not based_on:
                continue  # a lead must cite at least one real finding id
            if _introduces_new_entity(lead.text, emails, domains):
                continue  # grounding violation → drop this lead
            leads.append({
                "text": lead.text.strip(),
                "based_on": based_on,
                "severity_hint": lead.severity_hint,
                "jev_assisted": True,
                "jev_task": FINDING_CORRELATION,
            })
            if len(leads) >= MAX_LEADS:
                break
        return leads or None
    except Exception:
        _LOG.exception("JEV lead generation skipped")
        return None


def finding_summaries(collected: dict[str, Any]) -> list[dict[str, Any]]:
    """Build stable {id, type, summary} rows for correlation from collected results."""
    rows: list[dict[str, Any]] = []
    for module_name in sorted(collected):
        result = collected[module_name]
        for idx, finding in enumerate(getattr(result, "findings", None) or []):
            if not isinstance(finding, dict):
                continue
            meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
            summary = str(
                finding.get("signal_type") or finding.get("platform")
                or meta.get("breach_name") or meta.get("summary") or module_name
            )
            rows.append({
                "id": f"{module_name}:{idx}", "type": module_name, "summary": summary[:400],
            })
    return rows
