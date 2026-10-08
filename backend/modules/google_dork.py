from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_DORK_TEMPLATES = [
    'site:linkedin.com "{email}"',
    'site:github.com "{email}"',
    '"{email}" site:pastebin.com',
    '"{email}" filetype:pdf OR filetype:csv OR filetype:xlsx',
    'intext:"{email}" -site:linkedin.com -site:github.com',
]

_SERPAPI_URL = "https://serpapi.com/search"


def _infer_platform(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return "other"
    if "linkedin.com" in host:
        return "linkedin"
    if "github.com" in host:
        return "github"
    if "pastebin.com" in host:
        return "pastebin"
    return "other"


class GoogleDorkModule(BaseModule):
    name = "google_dork"
    email_linked = True
    description = "Run Google dork queries via SerpAPI to surface email mentions across LinkedIn, GitHub, Pastebin, and the open web."
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        if not settings.serpapi_key:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["SERPAPI_KEY not set"],
            )

        queries = [t.replace("{email}", email) for t in _DORK_TEMPLATES]

        async with build_client(timeout=15.0, follow_redirects=True) as client:
            tasks = [self._run_dork(client, q, settings.serpapi_key) for q in queries]
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[dict] = []
        errors: list[str] = []
        dorks_with_hits = 0

        for query, result in zip(queries, raw_results):
            if isinstance(result, Exception):
                errors.append(f"Dork failed [{query!r}]: {result}")
                continue
            dork_findings, dork_error = result
            if dork_error:
                errors.append(dork_error)
            if dork_findings:
                dorks_with_hits += 1
                findings.extend(dork_findings)

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL if findings else ModuleStatus.FAILED

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "total_results_found": len(findings),
                "dorks_run": len(queries),
                "dorks_with_hits": dorks_with_hits,
            },
            errors=errors,
        )

    async def _run_dork(
        self, client: httpx.AsyncClient, query: str, api_key: str
    ) -> tuple[list[dict], str | None]:
        params = {"engine": "google", "api_key": api_key, "q": query}
        try:
            res = await client.get(_SERPAPI_URL, params=params)
            if res.status_code != 200:
                return [], f"SerpAPI error {res.status_code} for query {query!r}"
            data = res.json()
        except Exception as exc:
            return [], f"Request error for query {query!r}: {exc}"

        findings = []
        for item in data.get("organic_results", [])[:5]:
            url = item.get("link", "")
            platform = _infer_platform(url)
            findings.append({
                "platform": platform,
                "url": url,
                "metadata": {
                    "title": item.get("title", ""),
                    "snippet": item.get("snippet", ""),
                    "dork_query": query,
                },
                "confidence": "medium" if platform in ("linkedin", "github") else "low",
            })
        return findings, None
