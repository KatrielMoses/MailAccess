from __future__ import annotations

import asyncio
from typing import Any

import httpx

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
_NPM_PACKAGE = "https://registry.npmjs.org/{}"


def _canonical(email: str) -> str:
    return email.strip().lower()


def _emails_match(a: str, b: str) -> bool:
    return _canonical(a) == _canonical(b)


def _extract_email(obj: Any) -> str:
    if isinstance(obj, dict):
        return str(obj.get("email") or "")
    return ""


class NpmDiscoveryModule(BaseModule):
    name = "npm_discovery"
    description = "Find npm packages authored or maintained by the target email address."
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
                if direct_finding:
                    pkg_name = direct_finding["metadata"]["package_name"]
                    if pkg_name not in seen_packages:
                        seen_packages.add(pkg_name)
                        findings.append(direct_finding)

            # 2. Search registry for each target email
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
                for name in all_search_names
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
                _NPM_SEARCH,
                params={"text": email, "size": "10"},
            )
        except httpx.TimeoutException:
            return [], "npm search timed out"
        except Exception as exc:
            return [], f"npm search error: {exc}"

        if resp.status_code != 200:
            return [], f"npm search HTTP {resp.status_code}"

        try:
            data = resp.json()
        except Exception:
            return [], "npm search returned unparseable JSON"

        objects = data.get("objects") if isinstance(data.get("objects"), list) else []
        names: list[str] = []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            pkg = obj.get("package") if isinstance(obj.get("package"), dict) else {}
            name = str(pkg.get("name") or "")
            if name:
                names.append(name)
        return names, None

    async def _fetch_package(
        self, client: httpx.AsyncClient, package_name: str, target_emails: frozenset[str]
    ) -> tuple[dict[str, Any] | None, str | None]:
        try:
            resp = await client.get(_NPM_PACKAGE.format(package_name))
        except httpx.TimeoutException:
            return None, f"npm package fetch timed out: {package_name}"
        except Exception as exc:
            return None, f"npm package fetch error ({package_name}): {exc}"

        if resp.status_code == 404:
            return None, None
        if resp.status_code != 200:
            return None, f"npm package HTTP {resp.status_code}: {package_name}"

        try:
            data = resp.json()
        except Exception:
            return None, f"npm unparseable JSON: {package_name}"

        name = str(data.get("name") or package_name)
        description = str(data.get("description") or "")[:200]
        homepage = str(data.get("homepage") or "")

        repo_obj = data.get("repository")
        repo_url = ""
        if isinstance(repo_obj, dict):
            repo_url = str(repo_obj.get("url") or "")
        elif isinstance(repo_obj, str):
            repo_url = repo_obj

        # Look in latest version's dist-tags → latest
        dist_tags = data.get("dist-tags") if isinstance(data.get("dist-tags"), dict) else {}
        latest_version = str(dist_tags.get("latest") or "")
        versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
        latest_data = versions.get(latest_version) if isinstance(versions.get(latest_version), dict) else {}

        author_obj = latest_data.get("author") or data.get("author")
        author_name = ""
        author_email = ""
        if isinstance(author_obj, dict):
            author_name = str(author_obj.get("name") or "")
            author_email = str(author_obj.get("email") or "")
        elif isinstance(author_obj, str):
            author_name = author_obj

        maintainers = data.get("maintainers") if isinstance(data.get("maintainers"), list) else []

        # Check authorship against all target emails
        def _matches_any(addr: str) -> bool:
            return any(_emails_match(addr, t) for t in target_emails)

        role = None
        confidence = "medium"
        if author_email and _matches_any(author_email):
            role = "author"
            confidence = "high"
        else:
            for m in maintainers:
                m_email = _extract_email(m)
                if m_email and _matches_any(m_email):
                    role = "maintainer"
                    confidence = "high"
                    break

        if role is None:
            return None, None

        maintainer_emails = [
            _extract_email(m)
            for m in maintainers
            if _extract_email(m)
        ]

        return (
            {
                "platform": "npm",
                "url": f"https://www.npmjs.com/package/{name}",
                "confidence": confidence,
                "source": "npm",
                "signal_type": "package_authorship",
                "metadata": {
                    "package_name": name,
                    "author_name": author_name or None,
                    "author_email": author_email or None,
                    "maintainer_emails": maintainer_emails or None,
                    "homepage": homepage or None,
                    "repository_url": repo_url or None,
                    "description": description or None,
                    "role": role,
                },
            },
            None,
        )
