from __future__ import annotations

import math
import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from ..modules.base import ModuleResult
from .breach_normalizer import collapse_breach_findings, is_breach_finding

_INFOSTEALER_FLOOR = 76
_CONFIRMED_ACCOUNT_MODULES = frozenset(
    {"whatsmyname", "user_scanner", "social", "account_discovery"}
)
_HISTORICAL_MODULES = frozenset({"wayback", "github_commits"})
_ROW_OMIT_KEYS = frozenset({"id", "module_name", "created_at", "data"})
_SERVICE_CATEGORY_CAP = 5
_PASTE_COUNT_CAP = 10
# Headroom-critical signals (infostealer evidence, recent breaches, exposed
# credentials, and phone exposure) carry enough weight to determine the risk
# band on their own. Volume and live-account signals add meaningful context,
# while pastes, service diversity, and verification are deliberately lighter
# tail signals. The total exceeds 100 so strong combinations saturate at the
# existing clipping boundary without changing the underlying scaling model.
_WEIGHTS = {
    "infostealer": 30,
    "breach_recency": 20,
    "credential_class": 15,
    "breach_count": 10,
    "live_accounts": 10,
    "pastes": 8,
    "service_diversity": 5,
    "verified_fraction": 2,
    "personal_phone": 15,
    "business_phone": 8,
}
_LOW_SCORE_REASONS = (
    "No infostealer evidence was detected.",
    "No confirmed breach records were detected.",
    "No live account confirmations were returned by account-enumeration modules.",
)
_SERVICE_CATEGORIES_PATH = Path(__file__).resolve().parents[2] / "data" / "service_categories.yaml"
_SERVICE_CATEGORIES_CACHE: dict[str, list[str]] | None = None
_WEAK_HASH_TOKENS = ("md5", "sha1", "unsalted", "easytocrack", "weakhash")
_STRONG_HASH_TOKENS = ("bcrypt", "scrypt", "argon2", "pbkdf2", "hardtocrack", "stronghash")


@dataclass(frozen=True)
class CredentialRiskAssessment:
    score: int
    band: str
    score_drivers: list[str]
    recommended_actions: list[str]


def load_service_categories() -> dict[str, list[str]]:
    global _SERVICE_CATEGORIES_CACHE

    if _SERVICE_CATEGORIES_CACHE is None:
        raw = yaml.safe_load(_SERVICE_CATEGORIES_PATH.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Service category catalog must be a mapping")
        _SERVICE_CATEGORIES_CACHE = {
            str(category).strip().lower(): [str(token).strip().lower() for token in tokens]
            for category, tokens in raw.items()
            if isinstance(tokens, list)
        }
    return _SERVICE_CATEGORIES_CACHE


def assess_credential_risk_from_results(
    results: dict[str, ModuleResult],
    *,
    as_of: datetime | date | None = None,
) -> CredentialRiskAssessment:
    rows = [
        {"module_name": module_name, "data": finding}
        for module_name, result in results.items()
        for finding in result.findings
    ]
    metadata_table = {
        module_name: deepcopy(result.metadata) if result.metadata else {}
        for module_name, result in results.items()
    }
    return _assess(collapse_breach_findings(rows), metadata_table, as_of=as_of)


def assess_credential_risk_from_report(
    report: dict[str, Any],
    *,
    as_of: datetime | date | None = None,
) -> CredentialRiskAssessment:
    rows = collapse_breach_findings(report.get("findings", []))
    metadata_table = {
        str(run.get("module_name")): deepcopy(run.get("run_metadata") or {})
        for run in report.get("module_runs", [])
        if isinstance(run, dict) and run.get("module_name")
    }
    return _assess(rows, metadata_table, as_of=as_of)


def credential_risk_band(score: int | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score <= 25:
        return "LOW"
    if score <= 50:
        return "MODERATE"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"


def _assess(
    rows: list[dict[str, Any]],
    metadata_table: dict[str, dict[str, Any]],
    *,
    as_of: datetime | date | None = None,
) -> CredentialRiskAssessment:
    reference_date = _as_of_date(as_of)
    breach_rows = [row for row in rows if is_breach_finding(row)]
    breach_payloads = [_finding_payload(row) for row in breach_rows]
    breach_count = len(breach_payloads)

    infostealer_payloads = [
        _finding_payload(row)
        for row in rows
        if str(row.get("module_name") or "").strip().lower() == "hudson_rock"
    ]
    hudson_meta = metadata_table.get("hudson_rock") or {}
    infostealer_present = bool(hudson_meta.get("is_infostealer_victim") or infostealer_payloads)

    most_recent_breach = _most_recent_breach_date(breach_payloads)
    recency_value = _breach_recency_value(most_recent_breach, reference_date)

    credential_class_score, credential_class_label, credential_class_count = (
        _credential_class_details(breach_payloads, metadata_table)
    )
    breach_count_value = _log_scaled_value(breach_count, 15)

    confirmed_accounts = _confirmed_account_payloads(rows)
    live_account_count = len(confirmed_accounts)
    live_account_value = min(live_account_count, 10) / 10 if live_account_count else 0.0

    service_categories = _service_categories(confirmed_accounts)
    service_diversity_value = (
        min(len(service_categories), _SERVICE_CATEGORY_CAP) / _SERVICE_CATEGORY_CAP
        if service_categories
        else 0.0
    )

    paste_count = _extract_paste_count(metadata_table.get("xposedornot"))
    paste_value = min(paste_count, _PASTE_COUNT_CAP) / _PASTE_COUNT_CAP if paste_count else 0.0

    verified_true, verified_available = _verified_counts(breach_payloads)
    verified_fraction = verified_true / verified_available if verified_available else 0.0
    personal_phone_count, business_phone_count = _phone_exposure_counts(rows)

    contributions = {
        "infostealer": _WEIGHTS["infostealer"] if infostealer_present else 0.0,
        "breach_recency": _WEIGHTS["breach_recency"] * recency_value,
        "credential_class": _WEIGHTS["credential_class"] * credential_class_score,
        "breach_count": _WEIGHTS["breach_count"] * breach_count_value,
        "live_accounts": _WEIGHTS["live_accounts"] * live_account_value,
        "pastes": _WEIGHTS["pastes"] * paste_value,
        "service_diversity": _WEIGHTS["service_diversity"] * service_diversity_value,
        "verified_fraction": _WEIGHTS["verified_fraction"] * verified_fraction,
        "personal_phone": _WEIGHTS["personal_phone"] if personal_phone_count else 0.0,
        "business_phone": _WEIGHTS["business_phone"] if business_phone_count else 0.0,
    }
    raw_score = round(sum(contributions.values()))
    score = max(0, min(raw_score, 100))
    if infostealer_present and score < _INFOSTEALER_FLOOR:
        score = _INFOSTEALER_FLOOR

    band = credential_risk_band(score)
    score_drivers = _score_drivers(
        contributions=contributions,
        reference_date=reference_date,
        infostealer_present=infostealer_present,
        infostealer_payloads=infostealer_payloads,
        infostealer_forced=infostealer_present and raw_score < _INFOSTEALER_FLOOR,
        most_recent_breach=most_recent_breach,
        credential_class_label=credential_class_label,
        credential_class_count=credential_class_count,
        breach_count=breach_count,
        live_account_count=live_account_count,
        service_categories=service_categories,
        paste_count=paste_count,
        verified_true=verified_true,
        verified_available=verified_available,
        personal_phone_count=personal_phone_count,
        business_phone_count=business_phone_count,
    )
    recommended_actions = _recommended_actions(
        infostealer_present=infostealer_present,
        breach_count=breach_count,
        credential_class_score=credential_class_score,
        live_account_count=live_account_count,
        service_categories=service_categories,
        paste_count=paste_count,
        historical_hit_count=_historical_hit_count(rows),
        recent_breach=most_recent_breach is not None
        and _years_since(most_recent_breach, reference_date) <= 5,
    )
    return CredentialRiskAssessment(
        score=score,
        band=band,
        score_drivers=score_drivers,
        recommended_actions=recommended_actions,
    )


def _as_of_date(value: datetime | date | None) -> date:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).date()
    if isinstance(value, date):
        return value
    return datetime.now(timezone.utc).date()


def _finding_payload(row: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    raw = row.get("data")
    if isinstance(raw, dict):
        payload.update(deepcopy(raw))
    for key, value in row.items():
        if key in _ROW_OMIT_KEYS or value is None:
            continue
        payload[key] = deepcopy(value)
    return payload


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) == 4 and text.isdigit():
        return datetime(int(text), 1, 1, tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    if len(text) >= 4 and text[:4].isdigit():
        return datetime(int(text[:4]), 1, 1, tzinfo=timezone.utc)
    return None


def _most_recent_breach_date(breach_payloads: list[dict[str, Any]]) -> datetime | None:
    candidates: list[datetime] = []
    for payload in breach_payloads:
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        for value in (
            payload.get("breach_date"),
            payload.get("breached_date"),
            payload.get("xposed_date"),
            payload.get("year"),
            metadata.get("breach_date"),
            metadata.get("breached_date"),
            metadata.get("xposed_date"),
            metadata.get("year"),
            metadata.get("added_date"),
        ):
            parsed = _parse_datetime(value)
            if parsed is not None:
                candidates.append(parsed)
    return max(candidates) if candidates else None


def _years_since(value: datetime, reference_date: date) -> float:
    delta_days = max((reference_date - value.date()).days, 0)
    return delta_days / 365.25


def _breach_recency_value(value: datetime | None, reference_date: date) -> float:
    if value is None:
        return 0.0
    years = _years_since(value, reference_date)
    if years <= 2:
        return 1.0
    if years <= 5:
        return 0.6
    if years <= 10:
        return 0.3
    return 0.1


def _password_material(payload: dict[str, Any]) -> tuple[float, str] | None:
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    data_classes = [
        str(item).lower()
        for item in (
            payload.get("data_classes")
            or payload.get("exposed_data")
            or metadata.get("data_classes")
            or metadata.get("exposed_data")
            or []
        )
        if str(item).strip()
    ]
    password_risk_values = [
        str(value).lower()
        for value in (
            payload.get("password_risk"),
            metadata.get("password_risk"),
        )
        if value is not None and str(value).strip()
    ]
    raw_text = " ".join(data_classes + password_risk_values)

    if _truthy(metadata.get("has_plaintext_hashes")):
        return (1.0, "plaintext")
    if "plaintext" in raw_text:
        return (1.0, "plaintext")
    if any(token in raw_text for token in _WEAK_HASH_TOKENS):
        return (0.8, "weak_hash")
    if any(token in raw_text for token in _STRONG_HASH_TOKENS):
        return (0.3, "strong_hash")
    if _truthy(metadata.get("has_password_hash")) or any(
        "password" in item for item in data_classes
    ):
        return (0.8, "password")
    return None


def _credential_class_details(
    breach_payloads: list[dict[str, Any]],
    metadata_table: dict[str, dict[str, Any]],
) -> tuple[float, str, int]:
    best_score = 0.0
    best_label = "none"
    matching_count = 0

    for payload in breach_payloads:
        details = _password_material(payload)
        if details is None:
            continue
        score, label = details
        if score > best_score:
            best_score = score
            best_label = label
            matching_count = 1
        elif score == best_score:
            matching_count += 1

    breach_directory_meta = metadata_table.get("breachdirectory") or {}
    if _truthy(breach_directory_meta.get("has_plaintext_hashes")) and best_score < 1.0:
        best_score = 1.0
        best_label = "plaintext"
        matching_count = max(matching_count, 1)

    if best_score > 0:
        return best_score, best_label, matching_count
    if breach_payloads:
        return 0.1, "no_password", len(breach_payloads)
    return 0.0, "none", 0


def _log_scaled_value(count: int, cap: int) -> float:
    if count <= 0:
        return 0.0
    capped = min(count, cap)
    return math.log1p(capped) / math.log1p(cap)


def _confirmed_account_payloads(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    confirmed: list[dict[str, Any]] = []
    for row in rows:
        module_name = str(row.get("module_name") or "").strip().lower()
        if module_name not in _CONFIRMED_ACCOUNT_MODULES:
            continue
        payload = _finding_payload(row)
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        confidence = str(payload.get("confidence") or "").strip().lower()
        if module_name == "whatsmyname" and _truthy(metadata.get("search_result")):
            continue
        if confidence == "low":
            continue
        confirmed.append(payload)
    return confirmed


def _service_categories(payloads: list[dict[str, Any]]) -> set[str]:
    categories: set[str] = set()
    for payload in payloads:
        category = _categorize_service(payload)
        if category:
            categories.add(category)
    return categories


def _categorize_service(payload: dict[str, Any]) -> str | None:
    catalog = load_service_categories()
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    raw_category = metadata.get("category")
    if isinstance(raw_category, str) and raw_category.strip():
        category = raw_category.strip().lower()
        if category in catalog:
            return category
        if category in {"code", "developer", "development"}:
            return "dev"
        if category in {"crypto", "banking", "payments"}:
            return "finance"
        return category

    platform = str(payload.get("platform") or "").strip().lower()
    profile_url = str(payload.get("profile_url") or payload.get("url") or "").strip().lower()
    host = ""
    if profile_url:
        parsed = urlparse(profile_url if "://" in profile_url else f"https://{profile_url}")
        host = (parsed.netloc or parsed.path).lower()
    service_tokens = {platform} if platform else set()
    service_tokens.update(token for token in re.split(r"[.-]+", host) if token)

    for category, catalog_tokens in catalog.items():
        if service_tokens.intersection(catalog_tokens):
            return category
    return None


def _extract_paste_count(xon_metadata: Any) -> int:
    counts = _paste_count_candidates(xon_metadata)
    return max(counts) if counts else 0


def _paste_count_candidates(value: Any, *, paste_branch: bool = False) -> list[int]:
    counts: list[int] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            key_hint = paste_branch or ("paste" in str(key).lower())
            if key_hint and isinstance(nested, list):
                counts.append(len(nested))
            if key_hint and isinstance(nested, (int, float)):
                counts.append(max(int(nested), 0))
            counts.extend(_paste_count_candidates(nested, paste_branch=key_hint))
    elif isinstance(value, list):
        if paste_branch:
            counts.append(len(value))
        for item in value:
            counts.extend(_paste_count_candidates(item, paste_branch=paste_branch))
    elif paste_branch and isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            counts.append(max(int(text), 0))
    return counts


def _verified_counts(breach_payloads: list[dict[str, Any]]) -> tuple[int, int]:
    true_count = 0
    available_count = 0
    for payload in breach_payloads:
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        raw = _first_present(
            payload,
            metadata,
            keys=("is_verified", "verified", "isVerified"),
        )
        parsed = _truthy(raw, allow_false=True)
        if parsed is None:
            continue
        available_count += 1
        if parsed:
            true_count += 1
    return true_count, available_count


def _first_present(
    payload: dict[str, Any],
    metadata: dict[str, Any],
    *,
    keys: tuple[str, ...],
) -> Any:
    for key in keys:
        if key in payload:
            return payload.get(key)
        if key in metadata:
            return metadata.get(key)
    return None


def _truthy(value: Any, *, allow_false: bool = False) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1"}:
            return True
        if normalized in {"false", "no", "n", "0"}:
            return False if allow_false else None
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0 and allow_false:
            return False
    return None


def _historical_hit_count(rows: list[dict[str, Any]]) -> int:
    return sum(
        1
        for row in rows
        if str(row.get("module_name") or "").strip().lower() in _HISTORICAL_MODULES
    )


def _phone_exposure_counts(rows: list[dict[str, Any]]) -> tuple[int, int]:
    personal = 0
    business = 0
    for row in rows:
        module_name = str(row.get("module_name") or "").strip().lower()
        payload = _finding_payload(row)
        signal_type = str(payload.get("signal_type") or "").strip().lower()
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        has_phone = bool(
            metadata.get("phone")
            or metadata.get("phone_number")
            or payload.get("phone")
            or payload.get("phone_number")
        )
        if not has_phone:
            continue
        if signal_type == "phone_in_bio":
            personal += 1
        elif (
            module_name in {"whois_lookup", "press_intel", "sec_edgar"}
            or signal_type == "phone_number"
        ):
            business += 1
    return personal, business


def _score_drivers(
    *,
    contributions: dict[str, float],
    reference_date: date,
    infostealer_present: bool,
    infostealer_payloads: list[dict[str, Any]],
    infostealer_forced: bool,
    most_recent_breach: datetime | None,
    credential_class_label: str,
    credential_class_count: int,
    breach_count: int,
    live_account_count: int,
    service_categories: set[str],
    paste_count: int,
    verified_true: int,
    verified_available: int,
    personal_phone_count: int,
    business_phone_count: int,
) -> list[str]:
    candidates: list[tuple[float, str]] = []

    if infostealer_present:
        families: list[str] = []
        seen: set[str] = set()
        last_seen: datetime | None = None
        for payload in infostealer_payloads:
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            for family in (
                metadata.get("stealer_families", [])
                if isinstance(metadata.get("stealer_families"), list)
                else []
            ):
                family_text = str(family).strip()
                if family_text and family_text not in seen:
                    seen.add(family_text)
                    families.append(family_text)
            family_text = str(metadata.get("stealer_family") or "").strip()
            if family_text and family_text not in seen:
                seen.add(family_text)
                families.append(family_text)
            for value in (metadata.get("last_seen"), metadata.get("date_compromised")):
                parsed = _parse_datetime(value)
                if parsed is not None and (last_seen is None or parsed > last_seen):
                    last_seen = parsed
        family_label = families[0] if families else "infostealer"
        date_label = last_seen.strftime("%Y") if last_seen is not None else None
        reason = f"Infostealer infection detected ({family_label}"
        if date_label:
            reason += f", {date_label}"
        reason += ")"
        if infostealer_forced:
            reason += ", forcing CRITICAL credential risk"
        candidates.append((contributions["infostealer"], reason))

    if most_recent_breach is not None and contributions["breach_recency"] > 0:
        age_year = max(int(_years_since(most_recent_breach, reference_date)), 0)
        if age_year < 1:
            age_label = "within the last year"
        elif age_year == 1:
            age_label = "about 1 year ago"
        else:
            age_label = f"about {age_year} years ago"
        candidates.append(
            (
                contributions["breach_recency"],
                "Most recent breach exposure dates to "
                f"{most_recent_breach.date().isoformat()} ({age_label})",
            )
        )

    if contributions["credential_class"] > 0 and credential_class_count > 0:
        if credential_class_label == "plaintext":
            message = f"Passwords exposed in plaintext in {credential_class_count} breach match"
        elif credential_class_label == "weak_hash":
            message = (
                "Weak password hashes (MD5/SHA1-class) exposed in "
                f"{credential_class_count} breach match"
            )
        elif credential_class_label == "strong_hash":
            message = f"Password hashes exposed in {credential_class_count} breach match"
        elif credential_class_label == "password":
            message = f"Passwords present in {credential_class_count} breach match"
        elif credential_class_label == "no_password":
            message = "Breach matches did not include password data classes"
        else:
            message = "Credential exposure indicators were present in breach data"
        if credential_class_label == "no_password":
            driver = message
        else:
            suffix = "" if credential_class_count == 1 else "es"
            driver = f"{message}{suffix}"
        candidates.append((contributions["credential_class"], driver))

    if breach_count > 0 and contributions["breach_count"] > 0:
        candidates.append(
            (
                contributions["breach_count"],
                (
                    "1 confirmed breach match was identified"
                    if breach_count == 1
                    else f"{breach_count} confirmed breach matches were identified"
                ),
            )
        )

    if live_account_count > 0 and contributions["live_accounts"] > 0:
        category_suffix = "ies" if len(service_categories) != 1 else "y"
        detail = (
            f" across {len(service_categories)} service categor{category_suffix}"
            if service_categories
            else ""
        )
        platform_suffix = "s" if live_account_count != 1 else ""
        candidates.append(
            (
                contributions["live_accounts"],
                f"Email actively used across {live_account_count} confirmed "
                f"platform{platform_suffix}{detail}",
            )
        )

    if paste_count > 0 and contributions["pastes"] > 0:
        candidates.append(
            (
                contributions["pastes"],
                f"Email appeared in {paste_count} paste record{'s' if paste_count != 1 else ''}",
            )
        )

    if service_categories and contributions["service_diversity"] > 0:
        categories = ", ".join(sorted(service_categories))
        candidates.append(
            (
                contributions["service_diversity"],
                f"Confirmed accounts span {len(service_categories)} service "
                f"categories ({categories})",
            )
        )

    if verified_available > 0 and contributions["verified_fraction"] > 0:
        match_suffix = "es" if verified_available != 1 else ""
        candidates.append(
            (
                contributions["verified_fraction"],
                f"{verified_true}/{verified_available} breach match{match_suffix} "
                "are source-verified",
            )
        )

    if personal_phone_count > 0 and contributions["personal_phone"] > 0:
        candidates.append(
            (
                contributions["personal_phone"],
                (
                    "Personal phone exposure was identified"
                    if personal_phone_count == 1
                    else f"{personal_phone_count} personal phone exposures were identified"
                ),
            )
        )

    if business_phone_count > 0 and contributions["business_phone"] > 0:
        candidates.append(
            (
                contributions["business_phone"],
                (
                    "Business phone exposure was identified"
                    if business_phone_count == 1
                    else f"{business_phone_count} business phone exposures were identified"
                ),
            )
        )

    candidates.sort(key=lambda item: item[0], reverse=True)
    reasons = [reason for points, reason in candidates if points > 0][:3]
    for fallback in _LOW_SCORE_REASONS:
        if len(reasons) >= 3:
            break
        if fallback not in reasons:
            reasons.append(fallback)
    return reasons[:3]


def _recommended_actions(
    *,
    infostealer_present: bool,
    breach_count: int,
    credential_class_score: float,
    live_account_count: int,
    service_categories: set[str],
    paste_count: int,
    historical_hit_count: int,
    recent_breach: bool,
) -> list[str]:
    actions: list[str] = []

    if infostealer_present:
        actions.append(
            "Prioritize endpoint triage and session invalidation for services "
            "exposed in Hudson Rock infostealer logs."
        )
    if breach_count > 0 and credential_class_score >= 0.8:
        actions.append(
            "Reset credentials for breach-linked services first and check for "
            "password reuse on any confirmed live accounts."
        )
    elif breach_count > 0 and recent_breach:
        actions.append(
            "Prioritize recently breached services for password-reset and MFA "
            "verification follow-up."
        )

    if live_account_count > 0:
        if service_categories & {"finance", "communication"}:
            actions.append(
                "Pivot into confirmed finance and communication accounts first "
                "to map takeover paths and recovery-channel exposure."
            )
        else:
            actions.append(
                "Pivot into the confirmed live accounts to map recovery paths, "
                "MFA posture, and takeover opportunities."
            )

    if paste_count > 0:
        actions.append(
            "Review XposedOrNot paste exposure details for leaked secrets, "
            "usernames, or recovery clues tied to the email."
        )

    if historical_hit_count > 0:
        actions.append(
            "Review Wayback and GitHub history for legacy usernames, alternate "
            "emails, or leaked authentication clues tied to active accounts."
        )

    if not actions:
        actions.extend(
            [
                "No immediate credential-containment pivot is indicated from the "
                "current evidence set.",
                "Keep this address as a low-priority lead unless new breach or "
                "live-account evidence appears.",
            ]
        )

    deduped: list[str] = []
    for action in actions:
        if action not in deduped:
            deduped.append(action)
    return deduped[:3]
