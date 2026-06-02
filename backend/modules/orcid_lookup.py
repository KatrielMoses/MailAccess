from __future__ import annotations

from typing import Any

import httpx

from ..core.bio_analyzer import analyze_bio
from ..core.http_client import build_client
from ..core.rate_limiter import rate_limiter
from .base import BaseModule, ModuleResult, ModuleStatus

_ORCID_API = "https://pub.orcid.org/v3.0"


class ORCIDLookupModule(BaseModule):
    name = "orcid_lookup"
    description = "Search public ORCID records for researcher names and contact links."
    requires_key = False
    default_enabled = True

    async def run(self, email: str) -> ModuleResult:
        rate_limiter.set_delay("pub.orcid.org", 0.5)
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            async with build_client(base_url=_ORCID_API, timeout=10.0) as client:
                headers = {"Accept": "application/json"}
                search = await client.get("/search/", params={"q": f"email:{email}"}, headers=headers)
                if search.status_code != 200:
                    return ModuleResult(
                        status=ModuleStatus.PARTIAL,
                        errors=[f"ORCID search returned HTTP {search.status_code}"],
                    )
                payload = search.json()
                results = payload.get("result") if isinstance(payload, dict) else []
                for result in results or []:
                    identifier = result.get("orcid-identifier") if isinstance(result, dict) else {}
                    orcid_id = str(identifier.get("path") or "").strip()
                    if not orcid_id:
                        continue
                    profile_findings, profile_errors = await self._fetch_person(client, headers, orcid_id)
                    findings.extend(profile_findings)
                    errors.extend(profile_errors)
        except httpx.TimeoutException:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=["ORCID lookup timed out"])
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=[f"ORCID network error: {exc}"])
        except Exception as exc:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=[f"ORCID lookup error: {exc}"])

        return ModuleResult(
            status=ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS,
            findings=findings,
            metadata={"profiles_found": len([f for f in findings if f.get("platform") == "orcid_profile"])},
            errors=errors,
        )

    async def _fetch_person(
        self, client: httpx.AsyncClient, headers: dict[str, str], orcid_id: str
    ) -> tuple[list[dict[str, Any]], list[str]]:
        try:
            response = await client.get(f"/{orcid_id}/person", headers=headers)
        except httpx.TimeoutException:
            return [], [f"ORCID person lookup timed out for {orcid_id}"]
        except Exception as exc:
            return [], [f"ORCID person lookup failed for {orcid_id}: {exc}"]

        if response.status_code != 200:
            return [], [f"ORCID person lookup returned HTTP {response.status_code} for {orcid_id}"]
        person = response.json()
        name = person.get("name") if isinstance(person.get("name"), dict) else {}
        given = _value(name.get("given-names"))
        family = _value(name.get("family-name"))
        credit = _value(name.get("credit-name"))
        full_name = " ".join(part for part in (given, family) if part).strip()

        biography_obj = person.get("biography") if isinstance(person.get("biography"), dict) else {}
        biography = str(biography_obj.get("content") or "").strip() or None
        email_objs = (person.get("emails") or {}).get("email") if isinstance(person.get("emails"), dict) else []
        additional_emails = [_value(item) for item in email_objs or [] if _value(item)]
        researcher_url_objs = (
            (person.get("researcher-urls") or {}).get("researcher-url")
            if isinstance(person.get("researcher-urls"), dict)
            else []
        )
        researcher_urls = [_researcher_url(item) for item in researcher_url_objs or []]
        researcher_urls = [url for url in researcher_urls if url]

        findings: list[dict[str, Any]] = [
            {
                "platform": "orcid_profile",
                "profile_url": f"https://orcid.org/{orcid_id}",
                "confidence": "high",
                "metadata": {
                    "orcid_id": orcid_id,
                    "given_name": given,
                    "family_name": family,
                    "full_name": full_name,
                    "credit_name": credit or None,
                    "biography": biography[:300] if biography else None,
                    "researcher_urls": researcher_urls,
                    "additional_emails": additional_emails,
                },
            }
        ]

        if biography:
            bio = analyze_bio(biography)
            for phone in bio.phones:
                findings.append(
                    {
                        "platform": "orcid_bio",
                        "confidence": "medium",
                        "signal_type": "phone_in_bio",
                        "metadata": {"phone": phone, "orcid_id": orcid_id, "source_field": "biography"},
                    }
                )
            for found_email in bio.emails:
                if found_email not in additional_emails:
                    additional_emails.append(found_email)
        for found_email in additional_emails:
            findings.append(
                {
                    "platform": "alternate_email",
                    "profile_url": f"https://orcid.org/{orcid_id}",
                    "confidence": "high",
                    "metadata": {
                        "discovered_email": found_email,
                        "source": "orcid_lookup",
                        "source_detail": f"ORCID profile {orcid_id}",
                        "discovery_method": "orcid_public_profile",
                        "reason": "Additional public email listed in ORCID profile",
                    },
                }
            )
        return findings, []


def _value(obj: Any) -> str:
    if isinstance(obj, dict):
        return str(obj.get("value") or "").strip()
    return str(obj or "").strip()


def _researcher_url(obj: Any) -> str:
    if not isinstance(obj, dict):
        return ""
    url_obj = obj.get("url")
    if isinstance(url_obj, dict):
        return str(url_obj.get("value") or "").strip()
    return str(url_obj or "").strip()
