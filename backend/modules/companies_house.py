from __future__ import annotations

import base64
from typing import Any

import httpx

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus
from .domain_intel import _FREE_PROVIDERS

_BASE_URL = "https://api.company-information.service.gov.uk"
_UK_SUFFIXES = (".co.uk", ".uk", ".org.uk")


class CompaniesHouseModule(BaseModule):
    name = "companies_house"
    description = "Look up UK company registration data from Companies House."
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@", 1)[1].lower() if "@" in email else ""
        key = settings.companies_house_api_key
        if not domain or domain in _FREE_PROVIDERS:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"domain": domain},
                errors=["free provider"],
            )
        if not key:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"domain": domain},
                errors=["COMPANIES_HOUSE_API_KEY not set"],
            )
        if not _is_uk_domain(domain) and not key:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"domain": domain},
                errors=["not a UK-related domain"],
            )

        auth = base64.b64encode(f"{key}:".encode("utf-8")).decode("ascii")
        headers = {"Authorization": f"Basic {auth}"}
        domain_keyword = _domain_keyword(domain)
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        async with build_client(timeout=12.0, follow_redirects=True, headers=headers) as client:
            companies, search_error = await _search_companies(client, domain_keyword)
            if search_error:
                errors.append(search_error)
            for company in companies[:5]:
                number = str(company.get("company_number") or "")
                officers, officer_error = await _fetch_officers(client, number)
                if officer_error:
                    errors.append(officer_error)
                address, address_error = await _fetch_registered_address(client, number)
                if address_error:
                    errors.append(address_error)

                company_name = str(company.get("title") or company.get("company_name") or "")
                if not company_name:
                    continue
                findings.append(
                    {
                        "platform": "companies_house",
                        "signal_type": "company_registration",
                        "confidence": "medium",
                        "metadata": {
                            "company_name": company_name,
                            "company_number": number,
                            "registered_address": address,
                            "officers": officers,
                            "company_status": company.get("company_status"),
                            "domain_keyword": domain_keyword,
                        },
                    }
                )

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL
        return ModuleResult(
            status=status,
            findings=findings,
            metadata={"domain": domain, "companies_found": len(findings)},
            errors=errors,
        )


def _is_uk_domain(domain: str) -> bool:
    return domain.endswith(_UK_SUFFIXES)


def _domain_keyword(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in {"co.uk", "org.uk"}:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


async def _search_companies(
    client: httpx.AsyncClient, query: str
) -> tuple[list[dict[str, Any]], str | None]:
    try:
        resp = await client.get(f"{_BASE_URL}/search/companies", params={"q": query})
    except httpx.TimeoutException:
        return [], "Companies House search timed out"
    except Exception as exc:
        return [], f"Companies House search error: {exc}"
    if resp.status_code in (401, 403):
        return [], "Companies House API key rejected"
    if resp.status_code != 200:
        return [], f"Companies House search HTTP {resp.status_code}"
    try:
        data = resp.json()
    except Exception:
        return [], "Companies House search returned unparseable JSON"
    items = data.get("items")
    return (items if isinstance(items, list) else [])[:5], None


async def _fetch_officers(
    client: httpx.AsyncClient, company_number: str
) -> tuple[list[dict[str, str]], str | None]:
    if not company_number:
        return [], None
    try:
        resp = await client.get(f"{_BASE_URL}/company/{company_number}/officers")
    except httpx.TimeoutException:
        return [], "Companies House officers fetch timed out"
    except Exception as exc:
        return [], f"Companies House officers fetch error: {exc}"
    if resp.status_code != 200:
        return [], None
    try:
        items = resp.json().get("items")
    except Exception:
        return [], None
    officers: list[dict[str, str]] = []
    if isinstance(items, list):
        for item in items[:10]:
            if not isinstance(item, dict):
                continue
            officers.append(
                {
                    "name": str(item.get("name") or ""),
                    "role": str(item.get("officer_role") or ""),
                }
            )
    return officers, None


async def _fetch_registered_address(
    client: httpx.AsyncClient, company_number: str
) -> tuple[str | None, str | None]:
    if not company_number:
        return None, None
    try:
        resp = await client.get(f"{_BASE_URL}/company/{company_number}/registered-office-address")
    except httpx.TimeoutException:
        return None, "Companies House registered address fetch timed out"
    except Exception as exc:
        return None, f"Companies House registered address fetch error: {exc}"
    if resp.status_code != 200:
        return None, None
    try:
        data = resp.json()
    except Exception:
        return None, None
    return _format_address(data), None


def _format_address(address: dict[str, Any]) -> str | None:
    parts = [
        address.get("premises"),
        address.get("address_line_1"),
        address.get("address_line_2"),
        address.get("locality"),
        address.get("region"),
        address.get("postal_code"),
        address.get("country"),
    ]
    text = ", ".join(str(part).strip() for part in parts if str(part or "").strip())
    return text or None
