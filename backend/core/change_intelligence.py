"""Phase 6F — change intelligence over corpus diffs.

The corpus keeps an append-only history of crawls per domain (``crawl_snapshots``).
Diffing consecutive crawls turns that history into recurring-value signals that a
premium vendor (ZoomInfo/UserGems) sells as "job-change alerts" (Doc-1 #18,
Doc-2 G1/G2):

* **first-seen** — a new on-domain address; if it matches the org's confirmed
  email pattern it is a *likely new hire*;
* **disappeared** — an address present before and now gone; if it had verified,
  that is a *likely departure*;
* **title-change** — the same address with a different resolved job title;
* **verification-drift** — the same address whose deliverability regressed
  (verified → bounced/invalid) — a *likely departure* signal;
* **likely-stale** — a row aged past the 6A decay threshold, surfaced for
  re-verification rather than silently retained.

Pure diff logic (:func:`diff_email_views`) is separated from the corpus read
(:func:`domain_change_report`) so it is unit-testable without a DB. The read is
fully guarded — a corpus failure yields an empty report, never an exception.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# Change signal types.
NEW_CONTACT = "new_contact"
LIKELY_NEW_HIRE = "likely_new_hire"
DISAPPEARED = "disappeared"
LIKELY_DEPARTURE = "likely_departure"
TITLE_CHANGE = "title_change"
VERIFICATION_DRIFT = "verification_drift"
LIKELY_STALE = "likely_stale"


def _enabled() -> bool:
    from ..config import settings

    return bool(getattr(settings, "enable_change_intelligence", True))


@dataclass(frozen=True)
class ChangeSignal:
    """One detected change between two corpus states."""

    type: str
    email: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ChangeReport:
    domain: str
    previous_at: str | None
    current_at: str | None
    signals: list[ChangeSignal] = field(default_factory=list)

    def by_type(self, signal_type: str) -> list[ChangeSignal]:
        return [s for s in self.signals if s.type == signal_type]

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for s in self.signals:
            out[s.type] = out.get(s.type, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "previous_at": self.previous_at,
            "current_at": self.current_at,
            "counts": self.counts,
            "signals": [
                {"type": s.type, "email": s.email, "detail": s.detail, "evidence": s.evidence}
                for s in self.signals
            ],
        }


# ---------------------------------------------------------------------------
# Pure diff logic.
# ---------------------------------------------------------------------------

_VERIFIED_STATES = {"verified", "valid"}
_BOUNCED_STATES = {"bounced", "invalid", "not_found", "undeliverable"}


def email_view(row: dict[str, Any]) -> dict[str, Any]:
    """Reduce a serialized HarvestedEmail row to the fields the diff needs."""
    email = str(row.get("email") or "").strip().lower()
    return {
        "email": email,
        "on_domain": bool(row.get("on_domain", True)),
        "is_role": bool(row.get("is_role", False)),
        "job_title": (str(row.get("job_title")).strip() if row.get("job_title") else None),
        "seniority": row.get("seniority"),
        "verification": _verification_state(row),
    }


def _verification_state(row: dict[str, Any]) -> str:
    grade = str(row.get("deliverability_grade") or "").strip().lower()
    if grade == "valid":
        return "verified"
    if grade in {"invalid"}:
        return "bounced"
    if row.get("is_smtp_verified") or row.get("is_provider_verified"):
        status = str(row.get("provider_verification_status") or "").strip().lower()
        if status in _BOUNCED_STATES:
            return "bounced"
        return "verified"
    status = str(row.get("provider_verification_status") or "").strip().lower()
    if status in _VERIFIED_STATES:
        return "verified"
    if status in _BOUNCED_STATES:
        return "bounced"
    return "unknown"


def _views_by_email(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        view = email_view(row)
        if view["email"]:
            out[view["email"]] = view
    return out


def _template_to_regex(template: str) -> re.Pattern[str] | None:
    """Compile a confirmed pattern's local part into a structural matcher.

    ``{first}.{last}`` → ``[a-z0-9]+\\.[a-z0-9]+``. Token placeholders become
    one-or-more (or single, for initials) alphanumerics; literal separators are
    preserved. Returns ``None`` for an unusable template.
    """
    local = str(template or "").split("@", 1)[0].strip().lower()
    if not local:
        return None
    parts = re.split(r"(\{[a-z]+\})", local)
    pieces: list[str] = []
    saw_token = False
    for part in parts:
        if not part:
            continue
        if part in ("{first}", "{last}"):
            pieces.append(r"[a-z0-9]+")
            saw_token = True
        elif part in ("{f}", "{l}"):
            pieces.append(r"[a-z0-9]")
            saw_token = True
        elif part.startswith("{") and part.endswith("}"):
            pieces.append(r"[a-z0-9]+")
            saw_token = True
        else:
            pieces.append(re.escape(part))
    if not saw_token:
        return None
    try:
        return re.compile("^" + "".join(pieces) + "$")
    except re.error:
        return None


def matches_pattern(email: str, confirmed_pattern: str | None) -> bool:
    """Whether ``email``'s local part matches the org's confirmed pattern shape."""
    if not confirmed_pattern:
        return False
    regex = _template_to_regex(confirmed_pattern)
    if regex is None:
        return False
    local = str(email or "").split("@", 1)[0].strip().lower()
    return bool(local) and bool(regex.fullmatch(local))


def diff_email_views(
    previous: list[dict[str, Any]],
    current: list[dict[str, Any]],
    *,
    confirmed_pattern: str | None = None,
) -> list[ChangeSignal]:
    """Diff two serialized email lists into change signals. Pure, no I/O."""
    prev = _views_by_email(previous)
    curr = _views_by_email(current)
    signals: list[ChangeSignal] = []

    # New addresses.
    for email in sorted(curr.keys() - prev.keys()):
        view = curr[email]
        if view["on_domain"] and not view["is_role"] and matches_pattern(email, confirmed_pattern):
            signals.append(
                ChangeSignal(
                    LIKELY_NEW_HIRE,
                    email,
                    "new on-domain address matching the org email pattern",
                    {"pattern": confirmed_pattern, "job_title": view["job_title"],
                     "raw": NEW_CONTACT},
                )
            )
        else:
            signals.append(
                ChangeSignal(
                    NEW_CONTACT, email, "address first seen this crawl",
                    {"on_domain": view["on_domain"], "is_role": view["is_role"]},
                )
            )

    # Disappeared addresses.
    for email in sorted(prev.keys() - curr.keys()):
        was = prev[email]
        if was["verification"] == "verified":
            signals.append(
                ChangeSignal(
                    LIKELY_DEPARTURE,
                    email,
                    "previously-verified address no longer present",
                    {"prior_job_title": was["job_title"], "raw": DISAPPEARED},
                )
            )
        else:
            signals.append(
                ChangeSignal(DISAPPEARED, email, "address no longer present", {})
            )

    # Persisting addresses — title change and verification drift.
    for email in sorted(curr.keys() & prev.keys()):
        was, now = prev[email], curr[email]
        if was["job_title"] and now["job_title"] and was["job_title"] != now["job_title"]:
            signals.append(
                ChangeSignal(
                    TITLE_CHANGE,
                    email,
                    f"title changed: {was['job_title']!r} → {now['job_title']!r}",
                    {"from": was["job_title"], "to": now["job_title"]},
                )
            )
        if was["verification"] == "verified" and now["verification"] == "bounced":
            signals.append(
                ChangeSignal(
                    VERIFICATION_DRIFT,
                    email,
                    "deliverability regressed: verified → bounced (likely departure)",
                    {"from": "verified", "to": "bounced", "likely_departure": True},
                )
            )
    return signals


# ---------------------------------------------------------------------------
# Corpus-backed report.
# ---------------------------------------------------------------------------


async def _recent_snapshots(domain: str, limit: int = 2) -> list[dict[str, Any]]:
    """The most recent ``limit`` crawl snapshots for a domain (newest first)."""
    from sqlalchemy import desc, select

    from ..db.database import AsyncSessionLocal
    from ..db.models import CrawlSnapshot
    from .corpus_store import normalize_domain

    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(CrawlSnapshot)
                .where(CrawlSnapshot.domain == normalize_domain(domain))
                .order_by(desc(CrawlSnapshot.harvested_at))
                .limit(max(1, int(limit)))
            )
        ).scalars().all()
    return [
        {
            "harvested_at": r.harvested_at.isoformat() if r.harvested_at else None,
            "confirmed_pattern": r.confirmed_pattern,
            "result_json": dict(r.result_json or {}),
        }
        for r in rows
    ]


async def domain_change_report(domain: str, *, include_stale: bool = True) -> ChangeReport:
    """Change intelligence for a domain from its two most recent crawls.

    Guarded → an empty report on any failure. With fewer than two crawls there
    is nothing to diff, but stale flags (6A) are still surfaced so a single-crawl
    domain is not silently retained.
    """
    from .corpus_store import normalize_domain
    from .suppression import SuppressionUnavailable

    normalized = normalize_domain(domain)
    empty = ChangeReport(domain=normalized, previous_at=None, current_at=None, signals=[])
    if not _enabled():
        return empty
    try:
        from .corpus_store import _corpus_enabled

        if not _corpus_enabled():
            return empty
        snapshots = await _recent_snapshots(normalized, limit=2)
        signals: list[ChangeSignal] = []
        current_at = snapshots[0]["harvested_at"] if snapshots else None
        previous_at = snapshots[1]["harvested_at"] if len(snapshots) > 1 else None
        if len(snapshots) >= 2:
            current, previous = snapshots[0], snapshots[1]
            signals = diff_email_views(
                previous["result_json"].get("unique_emails") or [],
                current["result_json"].get("unique_emails") or [],
                confirmed_pattern=current.get("confirmed_pattern"),
            )
        if include_stale:
            from .corpus_store import read_stale_contacts

            for lead in await read_stale_contacts(domain=normalized):
                signals.append(
                    ChangeSignal(
                        LIKELY_STALE,
                        str(lead.get("email") or ""),
                        "aged past re-verification threshold — surfaced, not served blind",
                        {"age_days": lead.get("decay", {}).get("age_days"),
                         "reason": lead.get("decay", {}).get("reason")},
                    )
                )
        # R2 (S1) — read-time suppression over the emitted signals. The email
        # diff reads raw snapshot ``unique_emails``, so a subject objected-to
        # after collection is only removed here. ``index.hit(email=...)``
        # escalates email → its domain, so a domain-scope objection is honoured
        # too. Fail-closed: SuppressionUnavailable propagates to the boundary.
        from .suppression import load_index_sync, subject_suppressed

        index = load_index_sync()
        if subject_suppressed(index, domain=normalized):
            return empty
        signals = [s for s in signals if not index.hit(email=s.email)]
        return ChangeReport(
            domain=normalized,
            previous_at=previous_at,
            current_at=current_at,
            signals=signals,
        )
    except SuppressionUnavailable:
        raise
    except Exception:
        logger.exception("domain_change_report failed for %s", domain)
        return empty
