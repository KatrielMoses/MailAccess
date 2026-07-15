"""Low-cost Microsoft tenant/realm metadata discovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from .http_client import build_client


@dataclass
class M365RealmResult:
    domain: str
    namespace_type: str = "Unknown"
    auth_url: str | None = None
    federation_brand_name: str | None = None
    cloud_instance_name: str | None = None
    status: str = "inconclusive"
    http_status: int | None = None
    error: str | None = None


async def get_user_realm(
    domain: str,
    *,
    timeout_seconds: float = 10.0,
) -> M365RealmResult:
    cleaned = (domain or "").strip().lower()
    result = M365RealmResult(domain=cleaned)
    if not cleaned or "." not in cleaned:
        result.error = "invalid_domain"
        return result
    url = (
        "https://login.microsoftonline.com/common/userrealm/"
        f"?user={quote('probe@' + cleaned)}&api-version=2.1"
    )
    try:
        async with build_client(timeout=max(float(timeout_seconds), 1.0)) as client:
            response = await client.get(url, headers={"Accept": "application/json"})
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    result.http_status = response.status_code
    if response.status_code != 200:
        result.error = f"http_{response.status_code}"
        return result
    try:
        payload: dict[str, Any] = response.json()
    except Exception as exc:  # noqa: BLE001
        result.error = f"invalid_json:{exc}"
        return result
    result.namespace_type = str(payload.get("NameSpaceType") or "Unknown")
    result.auth_url = _string_or_none(payload.get("AuthURL"))
    result.federation_brand_name = _string_or_none(payload.get("FederationBrandName"))
    result.cloud_instance_name = _string_or_none(payload.get("CloudInstanceName"))
    normalized = result.namespace_type.lower()
    if normalized == "managed":
        result.status = "managed"
    elif normalized == "federated":
        result.status = "federated"
    elif normalized in {"unknown", "none"}:
        result.status = "inconclusive"
    else:
        result.status = "inconclusive"
    return result


def _string_or_none(value: Any) -> str | None:
    return str(value) if isinstance(value, str) and value.strip() else None
