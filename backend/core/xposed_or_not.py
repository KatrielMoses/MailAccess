"""Keyless XposedOrNot breach lookups for passive email corroboration."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from .http_client import build_client

_EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)
_BASE_URL = "https://api.xposedornot.com/v1"


@dataclass(frozen=True)
class BreachCheck:
    email: str
    source_type: str | None = None
    breach_dates: tuple[str, ...] = ()
    breaches: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _date_values(value: Any) -> list[date]:
    dates: list[date] = []
    for match in re.findall(r"\b20\d{2}(?:[-/]\d{1,2}(?:[-/]\d{1,2})?)?\b", str(value)):
        parts = re.split(r"[-/]", match)
        try:
            if len(parts) == 3:
                dates.append(date(int(parts[0]), int(parts[1]), int(parts[2])))
            elif len(parts) == 2:
                dates.append(date(int(parts[0]), int(parts[1]), 1))
            else:
                dates.append(date(int(parts[0]), 1, 1))
        except ValueError:
            continue
    return dates


def _classify_dates(dates: list[date]) -> str:
    if any(item >= date.today() - timedelta(days=365 * 2) for item in dates):
        return "breach_recent"
    return "breach_historical"


def _extract_breach_dates(payload: dict[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    for item in _walk(payload):
        for key, value in item.items():
            if "date" in str(key).lower() and value:
                values.extend(str(value) for _ in [0])
    return tuple(dict.fromkeys(values))


def _extract_breach_names(payload: dict[str, Any]) -> tuple[str, ...]:
    """Extract names from both nested-list and object response shapes."""
    names: list[str] = []
    breach_keys = {"breach", "breaches", "exposedbreaches", "breachessummary"}
    for key, value in payload.items():
        if str(key).lower() not in breach_keys:
            continue
        for item in _walk(value):
            for item_key, item_value in item.items():
                if str(item_key).lower() in {"name", "breach", "breach_name", "title"}:
                    if isinstance(item_value, str) and item_value.strip():
                        names.append(item_value.strip())
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    names.append(item.strip())
                elif isinstance(item, list):
                    names.extend(str(part).strip() for part in item if isinstance(part, str) and part.strip())
    return tuple(dict.fromkeys(names))


async def check_email(email: str, *, timeout: float = 10.0) -> BreachCheck | None:
    """Return breach evidence, or ``None`` for errors and no-hit responses."""
    cleaned = str(email or "").strip().lower()
    if not cleaned or "@" not in cleaned:
        return None
    url = f"{_BASE_URL}/check-email/{cleaned}"
    try:
        async with build_client(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url, headers={"user-agent": "MailAccess"})
        if response.status_code != 200:
            return None
        payload = response.json()
        if not isinstance(payload, dict):
            return None
    except Exception:  # noqa: BLE001 - breach lookup is best-effort
        return None

    breach_containers = [
        value
        for key, value in payload.items()
        if str(key).lower() in {"breach", "breaches", "exposedbreaches", "breachessummary"}
    ]
    breach_names = _extract_breach_names(payload)
    if not breach_containers or not breach_names:
        return None
    dates_text = _extract_breach_dates(payload)
    parsed_dates = [parsed for value in dates_text for parsed in _date_values(value)]
    return BreachCheck(
        email=cleaned,
        source_type=_classify_dates(parsed_dates),
        breach_dates=dates_text,
        breaches=breach_names,
        raw=payload,
    )


def _format_for_local(local: str) -> str | None:
    if re.fullmatch(r"[a-z]+\.[a-z]+", local):
        return "{first}.{last}@{domain}"
    if re.fullmatch(r"[a-z]+_[a-z]+", local):
        return "{first}_{last}@{domain}"
    return None


def _infer_format_from_payload(payload: Any) -> dict[str, Any]:
    """Infer a dominant format from an already-obtained payload."""
    emails = sorted({match.group(0).lower() for match in _EMAIL_RE.finditer(str(payload))})
    counts: dict[str, int] = {}
    for email in emails:
        template = _format_for_local(email.rsplit("@", 1)[0])
        if template:
            counts[template] = counts.get(template, 0) + 1
    result: dict[str, Any] = {"emails_seen": len(emails), "format_counts": counts}
    if counts:
        template, count = max(counts.items(), key=lambda item: (item[1], item[0]))
        if count >= 10 and count / max(len(emails), 1) >= 0.8:
            result.update(format_template=template, format_count=count)
    return result


async def infer_domain_format(domain: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Fail closed because the current domain endpoint requires an API key."""
    cleaned = str(domain or "").strip().lower()
    if not cleaned:
        return {}
    del timeout
    return {"status": "unavailable", "reason": "domain_endpoint_requires_api_key", "domain": cleaned}


async def check_emails(
    emails: list[str],
    *,
    max_checks: int = 25,
    delay_seconds: float = 1.0,
) -> list[BreachCheck]:
    """Check a capped list at the public endpoint's documented pace."""
    results: list[BreachCheck] = []
    for index, email in enumerate(emails[: max(0, int(max_checks))]):
        if index:
            await asyncio.sleep(max(0.0, float(delay_seconds)))
        result = await check_email(email)
        if result is not None:
            results.append(result)
    return results
