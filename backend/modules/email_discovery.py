from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import httpx

from ..config import settings
from ..core.http_client import build_client
from ..core.name_extractor import PersonName, extract_names
from .base import BaseModule, ModuleResult, ModuleStatus
from .domain_intel import _FREE_PROVIDERS

_SERPAPI_URL = "https://serpapi.com/search"
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_INVALID_LOCAL_PARTS = frozenset({
    "admin",
    "administrator",
    "info",
    "noreply",
    "no-reply",
    "no_reply",
    "donotreply",
    "do-not-reply",
})


def _email_domain(email: str) -> str | None:
    if "@" not in email:
        return None
    return email.rsplit("@", 1)[-1].lower()


def _is_corporate_domain(domain: str | None) -> bool:
    return bool(domain and domain not in _FREE_PROVIDERS)


def _build_dorks(name: PersonName, original_email: str) -> list[tuple[str, str]]:
    full_name = name.full_name
    dorks = [
        (
            "consumer_email",
            f'"{full_name}" "@gmail.com" OR "@outlook.com" '
            'OR "@yahoo.com" OR "@protonmail.com"',
        ),
        (
            "contact_terms",
            f'"{full_name}" "email" OR "contact" -site:linkedin.com -site:facebook.com',
        ),
        ("document_mentions", f'"{full_name}" "@" filetype:pdf OR filetype:csv'),
    ]

    domain = _email_domain(original_email)
    if _is_corporate_domain(domain):
        dorks.append(("linkedin_domain", f'site:linkedin.com "{full_name}" "{domain}"'))

    return dorks


def _is_valid_discovered_email(candidate: str, original_email: str) -> bool:
    email = candidate.strip().lower()
    if email == original_email.lower():
        return False
    if ".." in email:
        return False
    local, _, domain = email.partition("@")
    if not local or not domain or "." not in domain:
        return False
    local_compact = local.replace(".", "").replace("_", "").replace("-", "")
    if local in _INVALID_LOCAL_PARTS or local_compact in _INVALID_LOCAL_PARTS:
        return False
    if any(
        local_compact.startswith(invalid.replace("-", ""))
        for invalid in _INVALID_LOCAL_PARTS
    ):
        return False
    return True


def _context_for_email(text: str, email: str, radius: int = 50) -> str:
    idx = text.lower().find(email.lower())
    if idx < 0:
        return text[: radius * 2].strip()
    start = max(0, idx - radius)
    end = min(len(text), idx + len(email) + radius)
    return text[start:end].strip()


class EmailDiscoveryModule(BaseModule):
    name = "email_discovery"
    description = (
        "Search public web results for other email addresses linked to a recovered real name."
    )
    requires_key = True

    async def run(
        self, email: str, collected: dict[str, ModuleResult] | None = None
    ) -> ModuleResult:
        from ..config import opt_in_active

        if not opt_in_active("enable_email_discovery", settings.enable_email_discovery):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_EMAIL_DISCOVERY=true to run this module"],
            )

        if not settings.serpapi_key:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["SERPAPI_KEY not set"],
            )

        names = extract_names(collected or {})
        if not names:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["No names recovered from primary modules"],
            )

        dorks: list[tuple[PersonName, str, str]] = []
        for name in names[:3]:
            for dork_name, query in _build_dorks(name, email):
                dorks.append((name, dork_name, query))

        findings: list[dict] = []
        errors: list[str] = []
        seen_emails: set[str] = set()
        finding_by_email: dict[str, dict] = {}

        async with build_client(timeout=15.0, follow_redirects=True) as client:
            tasks = [
                self._run_dork(client, name, dork_name, query, email)
                for name, dork_name, query in dorks
            ]
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        for dork, result in zip(dorks, raw_results):
            if isinstance(result, Exception):
                errors.append(f"Dork failed [{dork[2]!r}]: {result}")
                continue
            dork_findings, dork_error = result
            if dork_error:
                errors.append(dork_error)
            for finding in dork_findings:
                discovered = str(
                    (finding.get("metadata") or {}).get("discovered_email", "")
                ).lower()
                existing = finding_by_email.get(discovered)
                if existing is None or (
                    existing.get("confidence") != "high"
                    and finding.get("confidence") == "high"
                ):
                    finding_by_email[discovered] = finding

        seen_emails = set(finding_by_email)
        findings = list(finding_by_email.values())

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL if findings else ModuleStatus.FAILED

        discovered_emails = sorted(seen_emails)
        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "names_searched": len(names[:3]),
                "dorks_run": len(dorks),
                "emails_discovered": len(discovered_emails),
                "discovered_emails": discovered_emails,
            },
            errors=errors,
        )

    async def _run_dork(
        self,
        client: httpx.AsyncClient,
        name: PersonName,
        dork_name: str,
        query: str,
        original_email: str,
    ) -> tuple[list[dict], str | None]:
        params = {"engine": "google", "api_key": settings.serpapi_key, "q": query}
        try:
            res = await client.get(_SERPAPI_URL, params=params)
            if res.status_code != 200:
                return [], f"SerpAPI error {res.status_code} for query {query!r}"
            data = res.json()
        except Exception as exc:
            return [], f"Request error for query {query!r}: {exc}"

        findings: list[dict] = []
        seen_in_dork: set[str] = set()
        for item in data.get("organic_results", [])[:10]:
            title = str(item.get("title") or "")
            snippet = str(item.get("snippet") or "")
            url = str(item.get("link") or "")
            text = f"{title} {snippet}"
            for match in _EMAIL_RE.findall(text):
                discovered_email = match.lower()
                if discovered_email in seen_in_dork:
                    continue
                if not _is_valid_discovered_email(discovered_email, original_email):
                    continue
                seen_in_dork.add(discovered_email)
                snippet_has_email = discovered_email in snippet.lower()
                findings.append(
                    {
                        "platform": "email_discovery",
                        "profile_url": url,
                        "confidence": "high" if snippet_has_email else "medium",
                        "metadata": {
                            "discovered_email": discovered_email,
                            "source_name": name.full_name,
                            "source_url": url,
                            "snippet": _context_for_email(text, discovered_email),
                            "dork_used": dork_name,
                            "dork_query": query,
                            "source_domain": urlparse(url).hostname or "",
                        },
                    }
                )

        return findings, None
