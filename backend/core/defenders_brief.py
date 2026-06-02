from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from typing import Any

from .breach_normalizer import collapse_breach_findings, is_breach_finding
from .credential_risk import CredentialRiskAssessment
from .email_credibility import EmailCredibilityResult
from .name_consensus import NameConsensusResult
from .timeline import Timeline


@dataclass(frozen=True)
class DefenderFinding:
    title: str
    detail: str
    severity: str
    remediation: str


@dataclass(frozen=True)
class DefendersBrief:
    risk_level: str
    risk_summary: str
    top_findings: list[DefenderFinding]
    next_action: str
    generated_at: str


_RISK_ORDER = ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_BREACH_MODULES = {"hibp", "haveibeenpwned", "breachdirectory", "breach_deep", "xposedornot", "leakcheck"}
_ACCOUNT_MODULES = {
    "account_discovery",
    "user_scanner",
    "whatsmyname",
    "social",
    "github_commits",
    "twitter_profile",
    "linkedin_serp",
    "keybase",
    "gravatar",
}


def generate_defenders_brief(
    investigation: Any,
    findings: list[Any],
    credential_risk: CredentialRiskAssessment,
    name_consensus: NameConsensusResult,
    timeline: Timeline,
    email_credibility: EmailCredibilityResult | dict[str, Any],
) -> DefendersBrief:
    rows = collapse_breach_findings([_row_from_finding(finding) for finding in findings])
    email = str(_get(investigation, "email", "") or "")
    credibility = _asdict(email_credibility)

    risk_level = _determine_risk_level(
        credential_risk,
        rows,
        name_consensus,
        credibility,
    )
    candidates = _finding_candidates(rows, name_consensus, timeline)
    top_findings = [
        candidate["finding"]
        for candidate in sorted(
            candidates,
            key=lambda item: (
                -_SEVERITY_ORDER.get(item["finding"].severity, 0),
                -int(item.get("year") or 0),
                int(item.get("priority") or 999),
            ),
        )[:3]
    ]
    next_action = _next_action(email, risk_level, top_findings, rows, name_consensus)
    risk_summary = _risk_summary(
        risk_level, top_findings, rows, name_consensus, timeline, credibility
    )
    return DefendersBrief(
        risk_level=risk_level,
        risk_summary=risk_summary,
        top_findings=top_findings,
        next_action=next_action,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def generate_defenders_brief_from_report(report: dict[str, Any]) -> DefendersBrief:
    from .credential_risk import assess_credential_risk_from_report
    from .name_consensus import NameConsensusEngine, extract_name_candidates
    from .timeline import build_timeline

    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    credential_risk = assess_credential_risk_from_report(report)
    email = str(report.get("original_email") or report.get("email") or "")
    name_consensus = NameConsensusEngine(email).resolve(
        extract_name_candidates(report.get("findings_by_module", {}), email)
    )
    if report.get("confirmed_name") or report.get("name_confidence"):
        name_consensus.confirmed_name = report.get("confirmed_name")
        name_consensus.name_confidence = str(report.get("name_confidence") or "unknown")
        name_consensus.name_sources = list(report.get("name_sources") or [])
        name_consensus.name_reasoning = str(report.get("name_reasoning") or "")

    timeline_raw = report.get("timeline")
    timeline = build_timeline(findings)
    if isinstance(timeline_raw, dict):
        timeline.events = []
        timeline.first_seen_date = timeline_raw.get("first_seen_date")
        timeline.first_seen_source = timeline_raw.get("first_seen_source")
        timeline.most_recent_date = timeline_raw.get("most_recent_date")
        timeline.most_recent_event = timeline_raw.get("most_recent_event")
        timeline.most_recent_is_active_risk = bool(timeline_raw.get("most_recent_is_active_risk"))
        timeline.established_identity = bool(timeline_raw.get("established_identity"))
        timeline.identity_age_years = timeline_raw.get("identity_age_years")
        timeline.active_risk_count = int(timeline_raw.get("active_risk_count") or 0)
        timeline.timeline_span_years = timeline_raw.get("timeline_span_years")
        timeline.metadata = timeline_raw.get("metadata") if isinstance(timeline_raw.get("metadata"), dict) else {}

    credibility = report.get("email_credibility") if isinstance(report.get("email_credibility"), dict) else {}
    return generate_defenders_brief(
        report,
        findings,
        credential_risk,
        name_consensus,
        timeline,
        credibility,
    )


def defenders_brief_to_dict(brief: DefendersBrief | dict[str, Any]) -> dict[str, Any]:
    if isinstance(brief, DefendersBrief):
        return asdict(brief)
    return brief


def _row_from_finding(finding: Any) -> dict[str, Any]:
    if hasattr(finding, "module_name") and hasattr(finding, "data"):
        return {
            "module_name": str(getattr(finding, "module_name", "") or ""),
            "data": getattr(finding, "data") if isinstance(getattr(finding, "data", None), dict) else {},
        }
    if isinstance(finding, dict):
        if isinstance(finding.get("data"), dict):
            return finding
        return {
            "module_name": str(finding.get("module_name") or finding.get("source") or ""),
            "data": finding,
        }
    return {"module_name": "", "data": {}}


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _asdict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return {}


def _payload(row: dict[str, Any]) -> dict[str, Any]:
    data = row.get("data")
    if isinstance(data, dict):
        return data
    return row


def _meta(payload: dict[str, Any]) -> dict[str, Any]:
    metadata = payload.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _parse_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    if len(text) == 4 and text.isdigit():
        return date(int(text), 1, 1)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")[:10]).date()
    except ValueError:
        pass
    if len(text) >= 4 and text[:4].isdigit():
        return date(int(text[:4]), 1, 1)
    return None


def _year(value: Any) -> int:
    parsed = _parse_date(value)
    return parsed.year if parsed else 0


def _breach_date(payload: dict[str, Any]) -> date | None:
    meta = _meta(payload)
    for value in (
        payload.get("breach_date"),
        payload.get("breached_date"),
        payload.get("xposed_date"),
        payload.get("year"),
        meta.get("breach_date"),
        meta.get("breached_date"),
        meta.get("xposed_date"),
        meta.get("year"),
        meta.get("added_date"),
    ):
        parsed = _parse_date(value)
        if parsed:
            return parsed
    return None


def _breach_name(payload: dict[str, Any]) -> str:
    meta = _meta(payload)
    for key in ("canonical_breach_name", "breach_name", "name", "title", "breach_id"):
        value = meta.get(key) or payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return str(payload.get("platform") or "Unknown breach")


def _has_plaintext_password(payload: dict[str, Any]) -> bool:
    meta = _meta(payload)
    values = []
    for key in ("password_risk", "data_classes", "exposed_data"):
        raw = payload.get(key) or meta.get(key)
        values.extend(raw if isinstance(raw, list) else [raw])
    haystack = " ".join(str(value).lower() for value in values if value)
    return bool(meta.get("has_plaintext_hashes")) or "plaintext" in haystack


def _has_password_data(payload: dict[str, Any]) -> bool:
    meta = _meta(payload)
    values = []
    for key in ("password_risk", "data_classes", "exposed_data"):
        raw = payload.get(key) or meta.get(key)
        values.extend(raw if isinstance(raw, list) else [raw])
    haystack = " ".join(str(value).lower() for value in values if value)
    return _has_plaintext_password(payload) or "password" in haystack or bool(meta.get("has_password_hash"))


def _stealer_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if str(row.get("module_name") or "").lower() == "hudson_rock"
        or str(_payload(row).get("signal_type") or "").lower() == "stealer_signal"
    ]


def _phone_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches = []
    for row in rows:
        payload = _payload(row)
        meta = _meta(payload)
        signal = str(payload.get("signal_type") or "").lower()
        if signal in {"phone_in_bio", "phone_number"} or meta.get("phone") or meta.get("phone_number"):
            matches.append(row)
    return matches


def _breach_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if is_breach_finding(row)
        or str(row.get("module_name") or "").lower() in _BREACH_MODULES
    ]


def _determine_risk_level(
    credential_risk: CredentialRiskAssessment,
    rows: list[dict[str, Any]],
    name_consensus: NameConsensusResult,
    credibility: dict[str, Any],
) -> str:
    band = str(getattr(credential_risk, "band", "LOW") or "LOW").upper()
    level = {"UNKNOWN": "MINIMAL", "LOW": "LOW", "MODERATE": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}.get(band, "LOW")
    if not rows and getattr(credential_risk, "score", 0) <= 0:
        level = "MINIMAL"

    if _stealer_rows(rows):
        level = _max_risk(level, "HIGH")
    confirmed_name = bool(name_consensus.confirmed_name and name_consensus.name_confidence in {"confirmed", "probable"})
    if confirmed_name and _phone_rows(rows):
        level = _max_risk(level, "HIGH")
    elif confirmed_name:
        level = _bump_risk(level)

    now = datetime.now(timezone.utc).date()
    recent_password_breach = any(
        _has_password_data(_payload(row))
        and (date_value := _breach_date(_payload(row))) is not None
        and (now - date_value).days <= 731
        for row in _breach_rows(rows)
    )
    if recent_password_breach or len(_breach_rows(rows)) > 10:
        level = _max_risk(level, "HIGH")
    if bool(credibility.get("is_disposable")):
        level = _min_risk(level, "MEDIUM")
    return level


def _max_risk(left: str, right: str) -> str:
    return _RISK_ORDER[max(_RISK_ORDER.index(left), _RISK_ORDER.index(right))]


def _min_risk(left: str, right: str) -> str:
    return _RISK_ORDER[min(_RISK_ORDER.index(left), _RISK_ORDER.index(right))]


def _bump_risk(level: str) -> str:
    return _RISK_ORDER[min(_RISK_ORDER.index(level) + 1, len(_RISK_ORDER) - 1)]


def _finding_candidates(
    rows: list[dict[str, Any]],
    name_consensus: NameConsensusResult,
    timeline: Timeline,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    if _stealer_rows(rows):
        candidates.append(_candidate(
            1,
            DefenderFinding(
                "Active credential theft detected",
                "An infostealer malware infection was detected, indicating credentials were captured live from an infected device.",
                "critical",
                "Treat all passwords as compromised. Rotate credentials and revoke sessions immediately.",
            ),
            _latest_year(_stealer_rows(rows)),
        ))

    recent_plaintext = _recent_plaintext_breach(rows)
    if recent_plaintext:
        payload = _payload(recent_plaintext)
        year = _year(_breach_date(payload))
        candidates.append(_candidate(
            2,
            DefenderFinding(
                "Plaintext passwords in recent breach",
                f"Email appeared in {_breach_name(payload)} ({year or 'recent'}) with plaintext passwords exposed.",
                "critical",
                "Force password reset on all linked accounts. Audit for password reuse.",
            ),
            year,
        ))

    if name_consensus.confirmed_name and name_consensus.name_confidence in {"confirmed", "probable"}:
        source_count = len(name_consensus.name_sources or [])
        candidates.append(_candidate(
            3,
            DefenderFinding(
                "Real identity confirmed and public",
                f"Name '{name_consensus.confirmed_name}' confirmed across {source_count or 1} independent sources and directly linked to this email address.",
                "high",
                "Advise employee to review public profile exposure. Separate work and personal email where possible.",
            ),
            0,
        ))

    phones = _phone_rows(rows)
    if phones:
        source = str(phones[0].get("module_name") or _payload(phones[0]).get("source") or "public source")
        candidates.append(_candidate(
            4,
            DefenderFinding(
                "Phone number publicly linked to email",
                f"Phone number found via {source}. Enables targeted vishing and SIM-swap attacks.",
                "high",
                "Remove phone from MFA where possible. Switch to hardware key or authenticator app.",
            ),
            _latest_year(phones),
        ))

    breaches = _breach_rows(rows)
    if len(breaches) > 2:
        years = sorted({_year(_breach_date(_payload(row))) for row in breaches if _year(_breach_date(_payload(row)))})
        span = f"{years[0]}-{years[-1]}" if len(years) > 1 else str(years[0]) if years else "unknown years"
        severity = "high" if len(breaches) > 5 else "medium"
        candidates.append(_candidate(
            5,
            DefenderFinding(
                f"Email in {len(breaches)} data breaches",
                f"Found in {len(breaches)} breaches spanning {span}. Indicates long-term credential exposure risk.",
                severity,
                "Audit password reuse across all confirmed platform accounts.",
            ),
            years[-1] if years else 0,
        ))

    platforms = _confirmed_platforms(rows)
    if platforms:
        shown = ", ".join(platforms[:5])
        candidates.append(_candidate(
            6,
            DefenderFinding(
                "Active accounts on sensitive platforms",
                f"Confirmed accounts on: {shown}",
                "medium",
                "Verify MFA is active on each. Ensure recovery email/phone are not exposed.",
            ),
            0,
        ))

    if name_consensus.confirmed_name and name_consensus.name_confidence == "possible":
        candidates.append(_candidate(
            7,
            DefenderFinding(
                "Partial identity linkage detected",
                f"Name '{name_consensus.confirmed_name}' is probable but not confirmed across independent sources.",
                "low",
                "No immediate action required. Monitor for additional identity linkage.",
            ),
            0,
        ))

    if breaches and not any(_SEVERITY_ORDER.get(c["finding"].severity, 0) > 1 for c in candidates):
        most_recent = max((_breach_date(_payload(row)) for row in breaches), default=None)
        if most_recent and (datetime.now(timezone.utc).date() - most_recent).days > 1826:
            candidates.append(_candidate(
                8,
                DefenderFinding(
                    "Historical breach exposure only",
                    f"Email appears in older breaches (most recent: {most_recent.year}). Lower active risk.",
                    "low",
                    "Advise password audit as general hygiene. No urgent action required.",
                ),
                most_recent.year,
            ))

    return candidates


def _candidate(priority: int, finding: DefenderFinding, year: int) -> dict[str, Any]:
    return {"priority": priority, "finding": finding, "year": year}


def _latest_year(rows: list[dict[str, Any]]) -> int:
    return max((_year(_breach_date(_payload(row))) for row in rows), default=0)


def _recent_plaintext_breach(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc).date()
    matches = []
    for row in _breach_rows(rows):
        payload = _payload(row)
        date_value = _breach_date(payload)
        if date_value and (now - date_value).days <= 731 and _has_plaintext_password(payload):
            matches.append(row)
    return max(matches, key=lambda row: _breach_date(_payload(row)) or date.min, default=None)


def _confirmed_platforms(rows: list[dict[str, Any]]) -> list[str]:
    platforms: list[str] = []
    for row in rows:
        module = str(row.get("module_name") or "").lower()
        if module not in _ACCOUNT_MODULES:
            continue
        payload = _payload(row)
        if str(payload.get("confidence") or "high").lower() == "low":
            continue
        platform = str(payload.get("platform") or payload.get("service") or module).strip()
        if platform and platform not in platforms:
            platforms.append(platform.replace("_", " ").title())
    return sorted(platforms)


def _next_action(
    email: str,
    risk_level: str,
    top_findings: list[DefenderFinding],
    rows: list[dict[str, Any]],
    name_consensus: NameConsensusResult,
) -> str:
    highest = top_findings[0] if top_findings else None
    platforms = _confirmed_platforms(rows)
    if highest and highest.severity == "critical":
        return f"Immediately rotate credentials and enforce hardware MFA for {email}."
    if risk_level == "HIGH" and name_consensus.confirmed_name and _phone_rows(rows):
        return f"Issue advisory to {name_consensus.confirmed_name} about phishing and vishing risk from public identity exposure."
    if risk_level == "HIGH" and _breach_rows(rows):
        return f"Audit password reuse and enforce MFA across all {len(platforms)} confirmed platform accounts."
    if risk_level == "MEDIUM":
        return "Review public profile exposure and verify MFA is active on confirmed accounts."
    return "No immediate action required - log for periodic review."


def _risk_summary(
    risk_level: str,
    top_findings: list[DefenderFinding],
    rows: list[dict[str, Any]],
    name_consensus: NameConsensusResult,
    timeline: Timeline,
    credibility: dict[str, Any],
) -> str:
    if bool(credibility.get("is_disposable")) and not top_findings:
        return f"{risk_level} - DISPOSABLE email provider detected; no significant threats detected."
    if bool(credibility.get("is_disposable")):
        return f"{risk_level} - DISPOSABLE email provider detected; risk is capped for lower identity persistence."
    if top_findings and top_findings[0].title == "Active credential theft detected":
        return f"{risk_level} - Active infostealer infection detected; all credentials should be treated as compromised."
    if name_consensus.confirmed_name and name_consensus.name_confidence in {"confirmed", "probable"}:
        return f"{risk_level} - Confirmed identity ({name_consensus.confirmed_name}) is publicly linked to this email across {len(name_consensus.name_sources or []) or 1} sources."
    breaches = _breach_rows(rows)
    if breaches:
        recent = timeline.most_recent_date or str(max((_breach_date(_payload(row)) for row in breaches), default=""))
        return f"{risk_level} - Breach exposure detected; most recent evidence dates to {recent or 'an unknown date'}."
    if top_findings:
        return f"{risk_level} - {top_findings[0].detail}"
    return f"{risk_level} - No significant threats detected."
