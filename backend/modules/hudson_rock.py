from __future__ import annotations

from urllib.parse import urlparse

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_HEADERS = {"User-Agent": "MailAccess OSINT Tool"}


class HudsonRockModule(BaseModule):
    name = "hudson_rock"
    description = (
        "Check if the email appears in infostealer credential logs via Hudson Rock Cavalier."
    )
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        # scrapingant: dropped in S5 audit (Hudson Rock OSINT endpoint returns JSON)
        async with build_client(timeout=15.0, follow_redirects=True) as client:
            try:
                res = await client.get(
                    f"{_BASE_URL}/search-by-email",
                    headers=_HEADERS,
                    params={"email": email},
                )
            except Exception as e:
                return ModuleResult(
                    status=ModuleStatus.FAILED,
                    errors=[f"Hudson Rock network error: {e}"],
                )

        if res.status_code == 404:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=[],
                metadata={
                    "is_infostealer_victim": False,
                    "total_infections": 0,
                    "total_exposed_services": 0,
                    "all_compromised_domains": [],
                },
            )
        if res.status_code == 429:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["Hudson Rock rate limit exceeded"],
            )
        if res.status_code != 200:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Hudson Rock API error: {res.status_code}"],
            )

        return self._parse(res.json())

    def _parse(self, data: dict) -> ModuleResult:
        total = data.get("total", 0)
        stealers = data.get("stealers", [])

        if not total or not stealers:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=[],
                metadata={
                    "is_infostealer_victim": False,
                    "total_infections": 0,
                    "total_exposed_services": 0,
                    "all_compromised_domains": [],
                },
            )

        stealer_families: set[str] = set()
        dates: list[str] = []
        # domain -> first metadata record for that domain
        seen_domains: dict[str, dict] = {}

        for infection in stealers:
            family = infection.get("stealer_family") or "Unknown"
            date_compromised = infection.get("date_compromised")
            stealer_families.add(family)
            if date_compromised:
                dates.append(date_compromised)

            for cred in infection.get("credentials", []):
                raw_url = cred.get("url", "")
                if not raw_url:
                    continue
                try:
                    parsed = urlparse(raw_url)
                    domain = parsed.netloc or raw_url
                except Exception:
                    domain = raw_url

                if domain not in seen_domains:
                    seen_domains[domain] = {
                        "source": "infostealer_log",
                        "stealer_family": family,
                        "date_compromised": date_compromised,
                        "credential_type": cred.get("type", ""),
                        "high_value": True,
                    }

        dates.sort()
        first_seen = dates[0] if dates else None
        last_seen = dates[-1] if dates else None
        corporate = data.get("total_corporate_services", 0)
        user_svc = data.get("total_user_services", 0)

        findings: list[dict] = [
            {
                "platform": "hudson_rock",
                "metadata": {
                    "total_infections": total,
                    "stealer_families": sorted(stealer_families),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "exposed_corporate_services": corporate,
                    "exposed_user_services": user_svc,
                },
                "confidence": "high",
                "severity": "critical",
            }
        ]

        for domain, meta in seen_domains.items():
            findings.append(
                {
                    "platform": domain,
                    "url": f"https://{domain}" if "://" not in domain else domain,
                    "metadata": meta,
                    "confidence": "high",
                }
            )

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "is_infostealer_victim": True,
                "total_infections": total,
                "total_exposed_services": corporate + user_svc,
                "all_compromised_domains": list(seen_domains.keys()),
            },
        )

    # ------------------------------------------------------------------
    # Helpers for cross-module correlation
    # ------------------------------------------------------------------

    async def search_by_domain(self, domain: str) -> dict:
        # scrapingant: dropped in S5 audit (Hudson Rock domain endpoint returns JSON)
        async with build_client(timeout=15.0, follow_redirects=True) as client:
            try:
                res = await client.get(
                    f"{_BASE_URL}/search-by-domain",
                    headers=_HEADERS,
                    params={"domain": domain},
                )
                if res.status_code == 200:
                    return res.json()
            except Exception:
                pass
        return {}

    async def search_by_username(self, username: str) -> dict:
        # scrapingant: dropped in S5 audit (Hudson Rock username endpoint returns JSON)
        async with build_client(timeout=15.0, follow_redirects=True) as client:
            try:
                res = await client.get(
                    f"{_BASE_URL}/search-by-username",
                    headers=_HEADERS,
                    params={"username": username},
                )
                if res.status_code == 200:
                    return res.json()
            except Exception:
                pass
        return {}
