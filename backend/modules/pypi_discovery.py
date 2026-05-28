from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_PYPI_JSON = "https://pypi.org/pypi/{}/json"
_PYPI_SEARCH = "https://pypi.org/search/"
_PACKAGE_NAME_RE = re.compile(
    r'<span\s+class="package-snippet__name"[^>]*>\s*([^<]+)\s*</span>'
)
_MAX_SEARCH_PACKAGES = 5


def _canonical(email: str) -> str:
    return email.strip().lower()


def _emails_match(a: str, b: str) -> bool:
    return _canonical(a) == _canonical(b)


class PyPIDiscoveryModule(BaseModule):
    name = "pypi_discovery"
    description = "Find PyPI packages authored or maintained by the target email address."
    requires_key = False

    async def run(self, email: str, original_email: str | None = None) -> ModuleResult:
        target_emails: frozenset[str] = frozenset(
            e.strip().lower()
            for e in ([original_email, email] if original_email and original_email.lower() != email.lower() else [email])
            if e
        )
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        seen_packages: set[str] = set()

        async with build_client(timeout=10.0, follow_redirects=True) as client:
            # 1. Direct lookup: package named after each email's local part
            local_parts = list(dict.fromkeys(e.split("@")[0] if "@" in e else e for e in target_emails))
            for local_part in local_parts:
                direct_finding, direct_err = await self._fetch_package(
                    client, local_part, target_emails
                )
                if direct_err:
                    errors.append(direct_err)
                if direct_finding and direct_finding["metadata"]["package_name"] not in seen_packages:
                    seen_packages.add(direct_finding["metadata"]["package_name"])
                    findings.append(direct_finding)

            # 2. Search PyPI for each target email
            all_search_names: list[str] = []
            for search_email in target_emails:
                search_names, search_err = await self._search_packages(client, search_email)
                if search_err:
                    errors.append(search_err)
                for name in search_names:
                    if name not in all_search_names:
                        all_search_names.append(name)

            fetch_tasks = [
                self._fetch_package(client, name, target_emails)
                for name in all_search_names[:_MAX_SEARCH_PACKAGES * len(target_emails)]
                if name not in seen_packages
            ]
            results = await asyncio.gather(*fetch_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    continue
                pkg_finding, pkg_err = result
                if pkg_err:
                    errors.append(pkg_err)
                if pkg_finding:
                    pkg_name = pkg_finding["metadata"]["package_name"]
                    if pkg_name not in seen_packages:
                        seen_packages.add(pkg_name)
                        findings.append(pkg_finding)

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL if findings else ModuleStatus.FAILED

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={"packages_found": len(findings)},
            errors=errors,
        )

    async def _search_packages(
        self, client: httpx.AsyncClient, email: str
    ) -> tuple[list[str], str | None]:
        try:
            resp = await client.get(
                _PYPI_SEARCH,
                params={"q": email, "o": "", "c": ""},
                headers={"Accept": "text/html"},
            )
        except httpx.TimeoutException:
            return [], "PyPI search timed out"
        except Exception as exc:
            return [], f"PyPI search error: {exc}"

        if resp.status_code != 200:
            return [], f"PyPI search HTTP {resp.status_code}"

        names = _PACKAGE_NAME_RE.findall(resp.text)
        return [n.strip() for n in names if n.strip()], None

    async def _fetch_package(
        self, client: httpx.AsyncClient, package_name: str, target_emails: frozenset[str]
    ) -> tuple[dict[str, Any] | None, str | None]:
        try:
            resp = await client.get(_PYPI_JSON.format(package_name))
        except httpx.TimeoutException:
            return None, f"PyPI package fetch timed out: {package_name}"
        except Exception as exc:
            return None, f"PyPI package fetch error ({package_name}): {exc}"

        if resp.status_code == 404:
            return None, None
        if resp.status_code != 200:
            return None, f"PyPI package HTTP {resp.status_code}: {package_name}"

        try:
            data = resp.json()
        except Exception:
            return None, f"PyPI unparseable JSON: {package_name}"

        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        author = str(info.get("author") or "")
        author_email = str(info.get("author_email") or "")
        maintainer = str(info.get("maintainer") or "")
        maintainer_email = str(info.get("maintainer_email") or "")
        home_page = str(info.get("home_page") or "")
        project_urls = info.get("project_urls")
        if not isinstance(project_urls, dict):
            project_urls = {}
        version = str(info.get("version") or "")
        description = str(info.get("summary") or "")[:200]
        name = str(info.get("name") or package_name)

        # Determine role and confidence — check against all target emails
        def _matches_any(addr: str) -> bool:
            return any(_emails_match(addr, t) for t in target_emails)

        role = None
        if _matches_any(author_email):
            role = "author"
            confidence = "high"
        elif _matches_any(maintainer_email):
            role = "maintainer"
            confidence = "high"
        else:
            # Check if any email in comma-separated fields matches
            all_emails = [
                e.strip()
                for field in (author_email, maintainer_email)
                for e in field.split(",")
                if e.strip()
            ]
            matched = any(_matches_any(e) for e in all_emails)
            if not matched:
                return None, None
            role = "contributor"
            confidence = "medium"

        return (
            {
                "platform": "pypi",
                "url": f"https://pypi.org/project/{name}/",
                "confidence": confidence,
                "source": "pypi",
                "signal_type": "package_authorship",
                "metadata": {
                    "package_name": name,
                    "version": version,
                    "author": author,
                    "author_email": author_email,
                    "maintainer": maintainer or None,
                    "maintainer_email": maintainer_email or None,
                    "home_page": home_page or None,
                    "project_urls": project_urls or None,
                    "description": description or None,
                    "role": role,
                },
            },
            None,
        )
