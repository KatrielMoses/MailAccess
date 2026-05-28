from __future__ import annotations

from typing import Any

import httpx

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_OC_SEARCH = "https://api.opencorporates.com/v0.4/companies/search"
_OC_COMPANY = "https://api.opencorporates.com/v0.4/companies/{jurisdiction}/{number}"

_FREE_PROVIDERS = frozenset(
    {
        "gmail.com",
        "yahoo.com",
        "yahoo.co.uk",
        "hotmail.com",
        "hotmail.co.uk",
        "outlook.com",
        "live.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "aol.com",
        "protonmail.com",
        "proton.me",
        "pm.me",
        "tutanota.com",
        "tuta.io",
        "gmx.com",
        "gmx.net",
        "yandex.com",
        "yandex.ru",
        "mail.com",
        "fastmail.com",
        "fastmail.fm",
        "zoho.com",
        "mailinator.com",
        "guerrillamail.com",
        "throwam.com",
        "sharklasers.com",
        "msn.com",
        "inbox.com",
        "rediffmail.com",
    }
)


def _domain_name(domain: str) -> str:
    """Return the registrable part without TLD. e.g. rootaccess.tech → rootaccess"""
    parts = domain.rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _name_matches_domain(company_name: str, domain_keyword: str) -> bool:
    name_lower = company_name.lower()
    keyword_lower = domain_keyword.lower()
    return keyword_lower in name_lower or name_lower in keyword_lower


class OpenCorporatesModule(BaseModule):
    name = "opencorporates"
    description = "Look up company registration data for business email domains."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@", 1)[1].lower() if "@" in email else ""

        if not domain or domain in _FREE_PROVIDERS:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["OpenCorporates: free email provider, skipping"],
            )

        domain_keyword = _domain_name(domain)
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        async with build_client(timeout=12.0, follow_redirects=True) as client:
            companies, search_err = await self._search_companies(client, domain_keyword)
            if search_err:
                errors.append(search_err)

            for company in companies[:5]:
                if not _name_matches_domain(str(company.get("name") or ""), domain_keyword):
                    continue

                detail, detail_err = await self._fetch_company(
                    client,
                    str(company.get("jurisdiction_code") or ""),
                    str(company.get("company_number") or ""),
                )
                if detail_err:
                    errors.append(detail_err)

                c = detail if detail else company
                name = str(c.get("name") or "")
                registered_address = _extract_address(c)
                jurisdiction = str(c.get("jurisdiction_code") or "")
                company_number = str(c.get("company_number") or "")
                company_type = str(c.get("company_type") or "")
                status_str = str(c.get("current_status") or "")
                officers = _extract_officers(c)
                oc_url = str(c.get("opencorporates_url") or "")

                if not name:
                    continue

                findings.append(
                    {
                        "platform": "opencorporates",
                        "url": oc_url,
                        "confidence": "medium",
                        "source": "opencorporates",
                        "signal_type": "company_registration",
                        "trust_weight": 0.7,
                        "metadata": {
                            "company_name": name,
                            "registered_address": registered_address,
                            "company_number": company_number,
                            "jurisdiction": jurisdiction,
                            "company_type": company_type,
                            "status": status_str,
                            "officers": officers,
                            "domain_keyword": domain_keyword,
                        },
                    }
                )

        status = ModuleStatus.SUCCESS
        if not findings and not errors:
            status = ModuleStatus.SUCCESS  # no results but clean run
        elif errors:
            status = ModuleStatus.PARTIAL if findings else ModuleStatus.FAILED

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={"companies_found": len(findings), "domain": domain},
            errors=errors,
        )

    async def _search_companies(
        self, client: httpx.AsyncClient, query: str
    ) -> tuple[list[dict[str, Any]], str | None]:
        try:
            resp = await client.get(
                _OC_SEARCH,
                params={"q": query, "format": "json"},
            )
        except httpx.TimeoutException:
            return [], "OpenCorporates search timed out"
        except Exception as exc:
            return [], f"OpenCorporates search error: {exc}"

        if resp.status_code == 403:
            return [], "OpenCorporates API rate limit or auth required"
        if resp.status_code == 404:
            return [], None
        if resp.status_code != 200:
            return [], f"OpenCorporates search HTTP {resp.status_code}"

        try:
            data = resp.json()
        except Exception:
            return [], "OpenCorporates returned unparseable JSON"

        results = (
            data.get("results", {}).get("companies")
            if isinstance(data.get("results"), dict)
            else None
        )
        if not isinstance(results, list):
            return [], None

        companies: list[dict[str, Any]] = []
        for item in results:
            if isinstance(item, dict) and isinstance(item.get("company"), dict):
                companies.append(item["company"])
        return companies, None

    async def _fetch_company(
        self, client: httpx.AsyncClient, jurisdiction: str, number: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        if not jurisdiction or not number:
            return None, None
        try:
            resp = await client.get(
                _OC_COMPANY.format(jurisdiction, number),
                params={"format": "json"},
            )
        except httpx.TimeoutException:
            return None, "OpenCorporates company fetch timed out"
        except Exception as exc:
            return None, f"OpenCorporates company fetch error: {exc}"

        if resp.status_code != 200:
            return None, None

        try:
            data = resp.json()
            company = data.get("results", {}).get("company")
            return company if isinstance(company, dict) else None, None
        except Exception:
            return None, None


def _extract_address(company: dict[str, Any]) -> str | None:
    addr = company.get("registered_address")
    if isinstance(addr, dict):
        parts = [
            str(addr.get("street_address") or ""),
            str(addr.get("locality") or ""),
            str(addr.get("region") or ""),
            str(addr.get("postal_code") or ""),
            str(addr.get("country") or ""),
        ]
        address_str = ", ".join(p for p in parts if p.strip())
        return address_str or None
    if isinstance(addr, str):
        return addr.strip() or None
    return None


def _extract_officers(company: dict[str, Any]) -> list[dict[str, Any]]:
    officers_raw = company.get("officers")
    if not isinstance(officers_raw, list):
        return []
    officers: list[dict[str, Any]] = []
    for item in officers_raw:
        if isinstance(item, dict) and isinstance(item.get("officer"), dict):
            o = item["officer"]
            officers.append(
                {
                    "name": str(o.get("name") or ""),
                    "position": str(o.get("position") or ""),
                    "address": _extract_address(o) or "",
                }
            )
    return officers
