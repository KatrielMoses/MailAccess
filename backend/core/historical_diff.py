"""Timeline annotations for archive-backed email evidence."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..modules.base import ModuleResult


def _parse(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if len(raw) >= 14 and raw[:14].isdigit():
            return datetime.strptime(raw[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def annotate_historical_diff(module_results: dict[str, ModuleResult]) -> dict[str, Any]:
    """Annotate archive findings and return aggregate timeline metrics.

    The function is deliberately post-processing: it never creates or removes
    email findings, so historical classification cannot change harvest counts.
    """
    by_email: dict[str, list[datetime]] = {}
    archive_modules = {"commoncrawl_email", "wayback_domain_harvest"}
    for module_name in archive_modules:
        result = module_results.get(module_name)
        if not result:
            continue
        for finding in result.findings or []:
            metadata = finding.get("metadata") if isinstance(finding, dict) else None
            if not isinstance(metadata, dict):
                continue
            email = str(metadata.get("email") or "").strip().lower()
            if "@" not in email:
                continue
            values = [metadata.get("oldest_timestamp"), metadata.get("newest_timestamp"), metadata.get("snapshot_timestamp")]
            dates = [parsed for parsed in (_parse(value) for value in values) if parsed]
            if dates:
                by_email.setdefault(email, []).extend(dates)

    now = datetime.now(timezone.utc)
    annotated = 0
    persistent = 0
    historical_only = 0
    recent = 0
    for email, dates in by_email.items():
        first, last = min(dates), max(dates)
        span_days = max(0, (last - first).days)
        age_days = max(0, (now - last).days)
        if age_days > 730:
            status = "historical_only"
            historical_only += 1
        elif len(dates) >= 2 and span_days >= 30:
            status = "persistent"
            persistent += 1
        else:
            status = "recent" if age_days <= 365 else "single_sighting"
            if status == "recent":
                recent += 1
        for module_name in archive_modules:
            result = module_results.get(module_name)
            if not result:
                continue
            for finding in result.findings or []:
                metadata = finding.get("metadata") if isinstance(finding, dict) else None
                if isinstance(metadata, dict) and str(metadata.get("email") or "").strip().lower() == email:
                    metadata.update({"historical_status": status, "historical_first_seen": first.isoformat(), "historical_last_seen": last.isoformat(), "historical_span_days": span_days})
                    annotated += 1
    return {"emails_with_archive_timeline": len(by_email), "findings_annotated": annotated, "persistent": persistent, "recent": recent, "historical_only": historical_only}
