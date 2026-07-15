"""Name-aware public email discovery.

This module is deliberately separate from pattern generation: a generated
address is only a hypothesis, while this module requires public evidence from
GitHub or a search-result snippet before emitting an email finding.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote_plus

from ..config import settings
from ..core.bing_dorker import BingDorker
from ..core.concurrent_fetch_cache import CachedFetch
from ..core.duckduckgo_dorker import DuckDuckGoDorker
from ..core.email_extraction import extract_emails
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)
_MAX_NAMES = 40
_MAX_SEARCH_RESULTS = 8
_ROLE_LOCALS = frozenset({
    "abuse", "admin", "contact", "hello", "help", "info", "office",
    "press", "privacy", "sales", "security", "support", "team",
})


def derive_name_from_email(email: str) -> str | None:
    """Derive a cautious name candidate from a name-shaped local part."""
    local = str(email).split("@", 1)[0].strip().casefold()
    role_key = local.replace("_", "-").replace(".", "-")
    if not local or local in _ROLE_LOCALS or role_key in _ROLE_LOCALS or role_key.startswith("security-") or len(local) < 3:
        return None
    parts = [part for part in local.replace("_", ".").replace("-", ".").split(".") if part]
    if len(parts) >= 2 and parts[0].isalpha() and len(parts[0]) > 1 and parts[1].isalpha():
        return " ".join(part.capitalize() for part in parts[:3])
    if local.isalpha():
        return local.capitalize()
    return None


def _tokens(name: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in str(name).split() if len(part) > 1)


def _local_matches_name(name: str, local: str) -> bool:
    parts = _tokens(name)
    compact = "".join(parts)
    value = "".join(ch for ch in local.casefold() if ch.isalnum())
    if len(parts) < 2 or not value:
        return False
    first, last = parts[0], parts[-1]
    return (
        value in {first + last, first[:1] + last, first + last[:1], last + first}
        or value == first
        or value == last
        or (value.startswith(first[:1]) and value.endswith(last))
        or compact == value
    )


class PersonEmailPivotModule(BaseModule):
    name = "person_email_pivot"
    description = "Find public email evidence for discovered employee names"
    requires_key = False

    async def run(self, domain: str) -> ModuleResult:
        return ModuleResult(status=ModuleStatus.SKIPPED, findings=[])

    async def run_with_payload(
        self,
        payload: dict[str, Any],
        *,
        fetch: CachedFetch | None = None,
    ) -> ModuleResult:
        domain = str(payload.get("domain") or "").strip().lower()
        names = [
            str(item.get("name") if isinstance(item, dict) else item).strip()
            for item in payload.get("names", [])
        ]
        names = list(dict.fromkeys(name for name in names if len(_tokens(name)) >= 1))[:_MAX_NAMES]
        if not domain or not names:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"names_attempted": 0, "reason": "no_qualified_names"},
            )
        if fetch is None:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["person_email_pivot has no HTTP transport"],
                metadata={"names_attempted": len(names)},
            )

        findings: list[dict[str, Any]] = []
        telemetry: list[dict[str, Any]] = []
        github_count = 0
        search_count = 0

        for name in names:
            row = {"name": name, "github_queries": 0, "search_queries": 0, "emails_found": 0}
            github_findings = await self._github(name, domain, fetch, row)
            findings.extend(github_findings)
            github_count += len(github_findings)

            # Search engines are opt-in at the existing dork master switch.
            # They are bounded to one exact-name query per engine and stop on
            # the first block, preserving the harvest's fast-fail behavior.
            if getattr(settings, "enable_email_search_dork", True):
                search_findings = await self._search(name, domain, fetch, row)
                findings.extend(search_findings)
                search_count += len(search_findings)
            row["emails_found"] = len([f for f in findings if (f.get("metadata") or {}).get("source_name") == name])
            telemetry.append(row)

        return ModuleResult(
            status=ModuleStatus.SUCCESS if findings else ModuleStatus.PARTIAL,
            findings=findings,
            metadata={
                "names_attempted": len(names),
                "names_with_email_evidence": sum(1 for row in telemetry if row["emails_found"]),
                "github_emails_found": github_count,
                "search_emails_found": search_count,
                "per_person": telemetry,
            },
        )

    async def _github(
        self, name: str, domain: str, fetch: CachedFetch, row: dict[str, Any]
    ) -> list[dict[str, Any]]:
        query = quote_plus(name)
        org = domain.split(".", 1)[0]
        urls = [
            f"https://api.github.com/search/users?q={query}+org:{quote_plus(org)}&per_page=5",
            f"https://api.github.com/search/users?q={query}&per_page=5",
        ]
        seen_logins: set[str] = set()
        findings: list[dict[str, Any]] = []
        for url in urls:
            row["github_queries"] += 1
            try:
                response = await fetch.get(url)
                if response.status_code != 200:
                    continue
                data = self._json(response)
                for user in (data.get("items") or [])[:5]:
                    login = str(user.get("login") or "")
                    if not login or login in seen_logins:
                        continue
                    seen_logins.add(login)
                    profile_response = await fetch.get(f"https://api.github.com/users/{quote_plus(login)}")
                    if profile_response.status_code != 200:
                        continue
                    profile = self._json(profile_response)
                    email = str(profile.get("email") or "").strip()
                    if "@" not in email or email.casefold().endswith("@users.noreply.github.com"):
                        continue
                    # Harvest output is target-domain scoped.  A matching
                    # local part on Gmail/another domain is identity context,
                    # not an address at the organization being harvested.
                    if email.casefold().endswith("@" + domain):
                        findings.append(self._finding(email, name, profile.get("html_url") or url, "github_profile_email", 0.85, login))
                if findings:
                    break
            except Exception as exc:  # noqa: BLE001
                _LOG.debug("person_email_pivot GitHub query failed: %s", exc)
        return findings

    async def _search(
        self, name: str, domain: str, fetch: CachedFetch, row: dict[str, Any]
    ) -> list[dict[str, Any]]:
        query = f'"{name}" "@{domain}"'
        ddg = DuckDuckGoDorker(fetch=fetch, min_interval=0.0)
        bing = BingDorker(fetch=fetch, min_interval=0.0)
        findings: list[dict[str, Any]] = []
        for engine, dorker in (("ddg", ddg), ("bing", bing)):
            row["search_queries"] += 1
            try:
                results, blocked = await dorker.search(query, max_results=_MAX_SEARCH_RESULTS)
            except Exception:  # noqa: BLE001
                continue
            if blocked:
                break
            for result in results:
                text = f"{result.title} {result.snippet}"
                for extracted in extract_emails(text, domain):
                    local = extracted.email.split("@", 1)[0]
                    if not _local_matches_name(name, local):
                        continue
                    findings.append(self._finding(extracted.email, name, result.url, "name_search_snippet", 0.65, engine))
        return findings

    @staticmethod
    def _json(response: Any) -> dict[str, Any]:
        value = response.json() if callable(getattr(response, "json", None)) else json.loads(response.text or "{}")
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _finding(email: str, name: str, url: str, source_type: str, score: float, source: str) -> dict[str, Any]:
        return {
            "platform": "person_email_pivot",
            "profile_url": url,
            "username": email.split("@", 1)[0],
            "confidence": "high" if score >= 0.8 else "medium",
            "metadata": {
                "email": email,
                "name": name,
                "source_name": name,
                "source_url": url,
                "source_type": source_type,
                "pivot_source": source,
                "confidence_score": score,
            },
        }
