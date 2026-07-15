"""Keyless RubyGems and Packagist package metadata discovery."""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

from ..config import settings
from ..core.concurrent_fetch_cache import CachedFetch
from ..core.email_extraction import extract_emails
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus


def _keyword(domain: str) -> str:
    parts = [p for p in domain.lower().split(".") if p]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def _json(response: Any) -> Any:
    method = getattr(response, "json", None)
    if callable(method):
        return method()
    return json.loads(getattr(response, "text", "") or "{}")


class PackageEcosystemsModule(BaseModule):
    name = "package_ecosystems"
    description = "RubyGems and Packagist maintainer metadata discovery with exact-domain filtering."
    requires_key = False
    default_enabled = True

    async def run(self, domain: str, *, fetch: CachedFetch | None = None) -> ModuleResult:
        domain = (domain or "").strip().lower()
        if not settings.enable_package_ecosystems:
            return ModuleResult(status=ModuleStatus.SKIPPED, metadata={"domain": domain})
        keyword = _keyword(domain)
        if len(keyword) < 3:
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["no package keyword"])

        async def get(url: str) -> Any:
            if fetch is not None:
                return await fetch.get(url)
            async with build_client(timeout=8.0) as client:
                return await client.get(url)

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        checked = 0

        async def add_metadata(source: str, url: str, payload: Any, package: str = "") -> None:
            nonlocal checked
            checked += 1
            if not isinstance(payload, dict):
                return
            candidates: list[str] = []
            for key in ("email", "authors", "author", "maintainers", "maintainer"):
                value = payload.get(key)
                if isinstance(value, str):
                    candidates.append(value)
                elif isinstance(value, list):
                    candidates.extend(str(v.get("email", "")) if isinstance(v, dict) else str(v) for v in value)
                elif isinstance(value, dict):
                    candidates.append(str(value.get("email", "")))
            for raw in candidates:
                for item in extract_emails(raw, target_domain=domain):
                    if item.on_domain:
                        findings.append({"platform": self.name, "profile_url": url, "username": item.email.split("@", 1)[0], "confidence": "high", "metadata": {"email": item.email, "on_domain": True, "ecosystem": source, "package": package, "source_type": f"{source}_maintainer"}})

        try:
            ruby = await get(f"https://rubygems.org/api/v1/search.json?query={quote(keyword)}")
            if int(getattr(ruby, "status_code", 0) or 0) < 400:
                rows = _json(ruby)
                for row in (rows if isinstance(rows, list) else [])[: settings.package_ecosystems_max_packages]:
                    name = row.get("name") if isinstance(row, dict) else None
                    if name:
                        detail = await get(f"https://rubygems.org/api/v2/rubygems/{quote(name, safe='')}.json")
                        if int(getattr(detail, "status_code", 0) or 0) < 400:
                            await add_metadata("rubygems", f"https://rubygems.org/gems/{name}", _json(detail), name)
            else:
                errors.append(f"rubygems: HTTP {ruby.status_code}")
        except Exception as exc:
            errors.append(f"rubygems: {exc}")
        try:
            pack = await get(f"https://packagist.org/search.json?q={quote(keyword)}")
            if int(getattr(pack, "status_code", 0) or 0) < 400:
                rows = (_json(pack) or {}).get("results", [])
                for row in rows[: settings.package_ecosystems_max_packages]:
                    name = row.get("name") if isinstance(row, dict) else None
                    if not name or "/" not in name:
                        continue
                    detail = await get(f"https://repo.packagist.org/p2/{quote(name, safe='/')}.json")
                    if int(getattr(detail, "status_code", 0) or 0) < 400:
                        payload = _json(detail)
                        packages = payload.get("packages", {}) if isinstance(payload, dict) else {}
                        versions = next(iter(packages.values()), []) if isinstance(packages, dict) else []
                        if versions:
                            await add_metadata("packagist", f"https://packagist.org/packages/{name}", versions[0], name)
            else:
                errors.append(f"packagist: HTTP {pack.status_code}")
        except Exception as exc:
            errors.append(f"packagist: {exc}")
        status = ModuleStatus.SUCCESS if checked else ModuleStatus.FAILED
        if errors and checked:
            status = ModuleStatus.PARTIAL
        return ModuleResult(status=status, findings=findings, metadata={"domain": domain, "packages_checked": checked, "email_hits": len(findings), "ecosystems": ["rubygems", "packagist"]}, errors=errors[:10])
