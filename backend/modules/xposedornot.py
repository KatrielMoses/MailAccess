from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from ..core.http_client import build_client
from ..core.rate_limiter import rate_limiter
from .base import BaseModule, ModuleResult, ModuleStatus

_API_BASE = "https://api.xposedornot.com"
_API_HOST = "api.xposedornot.com"
# XposedOrNot's own docs warn about 1 request/sec across all endpoints.
_MIN_DELAY_SECONDS = 1.0


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        ordered.append(cleaned)
    return ordered


def _normalize(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum())


def _flatten_strings(value: Any) -> list[str]:
    items: list[str] = []
    if isinstance(value, str):
        parts = value.replace("|", ";").replace(",", ";").split(";")
        for part in parts:
            piece = part.strip()
            if piece:
                items.append(piece)
        return items
    if isinstance(value, (list, tuple, set)):
        for item in value:
            items.extend(_flatten_strings(item))
        return items
    if value is None:
        return items
    text = str(value).strip()
    if text:
        items.append(text)
    return items


def _parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1"}:
            return True
        if normalized in {"false", "no", "n", "0"}:
            return False
    return None


def _parse_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_data_classes(detail: dict[str, Any]) -> list[str]:
    raw = detail.get("xposed_data")
    if raw is None:
        raw = detail.get("exposedData")
    if raw is None:
        raw = detail.get("data_classes")
    return _dedupe(_flatten_strings(raw))


def _severity_from_data_classes(data_classes: list[str]) -> str:
    normalized = [item.lower() for item in data_classes]

    critical_tokens = (
        "password",
        "credential",
        "hash",
        "financial",
        "credit card",
        "bank",
        "token",
        "secret",
        "ssn",
        "social security",
        "passport",
        "private key",
        "api key",
    )
    high_tokens = (
        "phone",
        "address",
        "location",
        "geo",
        "birth",
        "dob",
        "ip address",
        "ip addresses",
    )

    if any(any(token in item for token in critical_tokens) for item in normalized):
        return "critical"
    if any(any(token in item for token in high_tokens) for item in normalized):
        return "high"
    return "medium"


def _extract_year(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if len(text) >= 4 and text[:4].isdigit():
        return int(text[:4])
    return None


def _first_mapping(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                return item
            if isinstance(item, list):
                for nested in item:
                    if isinstance(nested, dict):
                        return nested
    return None


def _get_json_error(data: dict[str, Any]) -> str | None:
    status = str(data.get("status") or "").lower()
    if status == "error":
        message = data.get("message") or data.get("error") or "XposedOrNot returned an error"
        return str(message)
    error = str(data.get("Error") or data.get("error") or "").strip()
    if error:
        return error
    return None


def _extract_direct_breaches(data: dict[str, Any] | None) -> list[str]:
    if not isinstance(data, dict):
        return []
    raw = data.get("breaches")
    names: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, (list, tuple, set)):
                names.extend(_flatten_strings(list(item)))
            elif isinstance(item, dict):
                for key in ("breach", "breachID", "name", "site"):
                    value = item.get(key)
                    if value:
                        names.extend(_flatten_strings(value))
            else:
                names.extend(_flatten_strings(item))
    return _dedupe(names)


def _extract_analytics_details(data: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []

    exposed = data.get("ExposedBreaches") or data.get("exposedBreaches")
    if isinstance(exposed, dict):
        raw_details = (
            exposed.get("breaches_details")
            or exposed.get("Breaches_Details")
            or exposed.get("details")
            or []
        )
    elif isinstance(exposed, list):
        raw_details = exposed
    else:
        raw_details = []

    details: list[dict[str, Any]] = []
    for item in raw_details:
        if isinstance(item, dict):
            details.append(item)
    return details


def _analytics_summary(data: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}

    metrics = data.get("BreachMetrics")
    breaches_summary = data.get("BreachesSummary")
    summary: dict[str, Any] = {}

    if isinstance(breaches_summary, dict):
        summary["breaches_summary"] = breaches_summary
        if breaches_summary.get("site"):
            summary["breaches_summary_site"] = breaches_summary.get("site")

    if isinstance(metrics, dict):
        risk = _first_mapping(metrics.get("risk"))
        passwords_strength = _first_mapping(metrics.get("passwords_strength"))
        yearwise_details = _first_mapping(metrics.get("yearwise_details"))
        xposed_data = _first_mapping(metrics.get("xposed_data"))

        if risk:
            summary["risk_label"] = risk.get("risk_label")
            summary["risk_score"] = risk.get("risk_score")
            summary["risk"] = risk
        if passwords_strength:
            summary["passwords_strength"] = passwords_strength
        if yearwise_details:
            summary["yearwise_details"] = yearwise_details
        if xposed_data:
            summary["xposed_data_summary"] = xposed_data
        summary["breach_metrics"] = metrics

    return summary


def _build_finding(
    detail: dict[str, Any] | None,
    breach_name: str,
    analytics: dict[str, Any],
    *,
    direct_only: bool = False,
) -> dict[str, Any]:
    detail = detail or {}
    data_classes = _extract_data_classes(detail)
    severity = _severity_from_data_classes(data_classes)
    breach_domain = str(detail.get("domain") or "").strip()
    breached_date = (
        detail.get("breachedDate")
        or detail.get("breached_date")
        or detail.get("xposed_date")
        or detail.get("breach_date")
    )
    added_date = detail.get("addedDate")
    logo = detail.get("logo")
    password_risk = detail.get("password_risk") or detail.get("passwordRisk")
    searchable = _parse_bool(detail.get("searchable"))
    verified = _parse_bool(detail.get("verified"))
    sensitive = _parse_bool(detail.get("sensitive"))
    exposed_records = _parse_int(detail.get("xposed_records") or detail.get("exposedRecords"))
    exposure_description = detail.get("exposureDescription") or detail.get("details")
    reference_url = detail.get("referenceURL") or detail.get("references")
    breach_id = detail.get("breachID") or detail.get("breach") or breach_name

    metadata: dict[str, Any] = {
        "breach_name": breach_name,
        "breach_id": breach_id,
        "domain": breach_domain or None,
        "breached_date": breached_date,
        "added_date": added_date,
        "industry": detail.get("industry"),
        "logo": logo,
        "password_risk": password_risk,
        "searchable": searchable,
        "verified": verified,
        "sensitive": sensitive,
        "exposed_records": exposed_records,
        "exposed_data": data_classes,
        "data_classes": data_classes,
        "exposure_description": exposure_description,
        "reference_url": reference_url,
        "year": _extract_year(breached_date),
        "risk": severity,
        "risk_indicators": {
            "password_risk": password_risk,
            "searchable": searchable,
            "verified": verified,
            "sensitive": sensitive,
        },
        "source_module": "xposedornot",
        "direct_match": True,
        "direct_only": direct_only,
        "corpus_match": True,
        "analytics": analytics,
        "raw_detail": detail if detail else {"breach_name": breach_name, "direct_only": True},
    }
    metadata = {k: v for k, v in metadata.items() if v is not None}

    url = f"https://{breach_domain}" if breach_domain else "https://xposedornot.com"
    if reference_url and not breach_domain:
        url = str(reference_url)

    return {
        "platform": "XposedOrNot",
        "url": url,
        "source": "xposedornot",
        "confidence": "high",
        "severity": severity,
        "breach_name": breach_name,
        "breach_id": breach_id,
        "breach_date": breached_date,
        "domain": breach_domain or None,
        "data_classes": data_classes,
        "exposed_data": data_classes,
        "password_risk": password_risk,
        "exposed_records": exposed_records,
        "metadata": metadata,
    }


class XposedOrNotModule(BaseModule):
    name = "xposedornot"
    description = (
        "Check XposedOrNot's public breach corpus for direct breach hits and detailed analytics."
    )
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        rate_limiter.set_delay(
            _API_HOST, max(rate_limiter.get_delay(_API_HOST), _MIN_DELAY_SECONDS)
        )

        direct_data: dict[str, Any] | None = None
        analytics_data: dict[str, Any] | None = None
        direct_status: int | None = None
        analytics_status: int | None = None
        errors: list[str] = []
        partial = False

        async with build_client(base_url=_API_BASE, timeout=15.0, follow_redirects=True) as client:
            direct_status, direct_data, direct_error = await self._fetch_direct(client, email)
            analytics_status, analytics_data, analytics_error = await self._fetch_analytics(
                client, email
            )

        if direct_error:
            errors.append(direct_error)
        if analytics_error:
            errors.append(analytics_error)

        if direct_status == 429 or analytics_status == 429:
            partial = True
        if direct_status and direct_status not in (200, 404, 429) and direct_error:
            partial = partial or bool(analytics_data)
        if analytics_status and analytics_status not in (200, 404, 429) and analytics_error:
            partial = partial or bool(direct_data)

        direct_names = _extract_direct_breaches(direct_data)
        analytics_details = _extract_analytics_details(analytics_data)
        analytics_summary = _analytics_summary(analytics_data)

        details_by_name: dict[str, dict[str, Any]] = {}
        for detail in analytics_details:
            name = str(detail.get("breach") or detail.get("breachID") or "").strip()
            if not name:
                continue
            details_by_name.setdefault(_normalize(name), detail)

        findings: list[dict[str, Any]] = []
        matched: set[str] = set()
        all_data_classes: set[str] = set()

        for breach_name in direct_names:
            detail = details_by_name.get(_normalize(breach_name))
            if detail is not None:
                matched.add(_normalize(breach_name))
                data_classes = _extract_data_classes(detail)
                all_data_classes.update(data_classes)
                findings.append(_build_finding(detail, breach_name, analytics_summary))
                continue

            partial = True
            errors.append(
                "XposedOrNot analytics did not return detailed metadata for at least one "
                "direct breach match; using the direct breach name only."
            )
            findings.append(
                _build_finding({}, breach_name, analytics_summary, direct_only=True)
            )

        for normalized_name, detail in details_by_name.items():
            if normalized_name in matched:
                continue
            breach_name = str(detail.get("breach") or detail.get("breachID") or "").strip()
            if not breach_name:
                continue
            data_classes = _extract_data_classes(detail)
            all_data_classes.update(data_classes)
            findings.append(_build_finding(detail, breach_name, analytics_summary))

        severity_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        findings.sort(
            key=lambda item: (
                severity_rank.get(str(item.get("severity", "")).lower(), 0),
                item.get("breach_name", ""),
            ),
            reverse=True,
        )

        paste_count = 0
        if isinstance(analytics_data, dict):
            exposed_pastes = analytics_data.get("ExposedPastes")
            if isinstance(exposed_pastes, list):
                paste_count = len(exposed_pastes)
                for paste in exposed_pastes:
                    if not isinstance(paste, dict):
                        continue
                    paste_source = str(paste.get("source") or paste.get("pasteID") or "Paste").strip()
                    findings.append({
                        "platform": paste_source,
                        "url": "https://xposedornot.com",
                        "source": "xposedornot_pastes",
                        "confidence": "high",
                        "severity": "low",
                        "signal_type": "paste_exposure",
                        "metadata": {
                            "paste_source": paste_source,
                            "date": paste.get("date"),
                            "email_count": paste.get("emailCount"),
                            **paste
                        }
                    })

        if findings:
            status = ModuleStatus.PARTIAL if partial or errors else ModuleStatus.SUCCESS
        else:
            if direct_status == 429 or analytics_status == 429:
                status = ModuleStatus.PARTIAL
            elif errors:
                status = ModuleStatus.FAILED
            else:
                status = ModuleStatus.SUCCESS

        metadata: dict[str, Any] = {
            "email": email,
            "breaches_found": sum(1 for f in findings if f.get("signal_type") != "paste_exposure"),
            "paste_count": paste_count,
            "direct_breaches": direct_names,
            "analytics_breaches": [
                str(detail.get("breach") or detail.get("breachID") or "").strip()
                for detail in analytics_details
                if str(detail.get("breach") or detail.get("breachID") or "").strip()
            ],
            "all_data_classes": sorted(all_data_classes),
            **analytics_summary,
        }

        if direct_data is not None:
            metadata["direct_response"] = direct_data
        if analytics_data is not None:
            metadata["analytics_response"] = analytics_data

        errors = _dedupe(errors)
        return ModuleResult(status=status, findings=findings, metadata=metadata, errors=errors)

    async def _fetch_direct(
        self, client: httpx.AsyncClient, email: str
    ) -> tuple[int | None, dict[str, Any] | None, str | None]:
        path = f"/v1/check-email/{quote(email, safe='')}"
        try:
            response = await client.get(path)
        except httpx.TimeoutException:
            return None, None, "XposedOrNot direct breach check timed out"
        except Exception as exc:
            return None, None, f"XposedOrNot direct breach check failed: {exc}"

        return self._parse_response(response, "XposedOrNot direct breach check")

    async def _fetch_analytics(
        self, client: httpx.AsyncClient, email: str
    ) -> tuple[int | None, dict[str, Any] | None, str | None]:
        try:
            response = await client.get("/v1/breach-analytics", params={"email": email})
        except httpx.TimeoutException:
            return None, None, "XposedOrNot breach analytics timed out"
        except Exception as exc:
            return None, None, f"XposedOrNot breach analytics failed: {exc}"

        return self._parse_response(response, "XposedOrNot breach analytics")

    def _parse_response(
        self, response: httpx.Response, label: str
    ) -> tuple[int | None, dict[str, Any] | None, str | None]:
        status_code = response.status_code
        if status_code == 429:
            return status_code, None, f"{label} rate limit exceeded; retry after a short pause."
        if status_code == 404:
            return status_code, None, None
        if status_code != 200:
            return status_code, None, f"{label} API error: {status_code}"

        try:
            data = response.json()
        except Exception:
            return status_code, None, f"{label} response was not valid JSON"
        if not isinstance(data, dict):
            return status_code, None, f"{label} response had an unexpected shape"

        json_error = _get_json_error(data)
        if json_error:
            if "not found" in json_error.lower():
                return 404, data, None
            return status_code, data, f"{label}: {json_error}"
        return status_code, data, None
