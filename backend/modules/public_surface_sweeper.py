"""Bounded, keyless sweep of public website contact surfaces."""
from __future__ import annotations

import logging
import asyncio
from typing import Any
from urllib.parse import urljoin

from ..config import settings
from ..core.concurrent_fetch_cache import CachedFetch
from ..core.email_extraction import extract_emails
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)
_SURFACES = (
    ("security_txt", "/.well-known/security.txt"),
    ("security_txt_root", "/security.txt"),
    ("humans_txt", "/humans.txt"),
    ("llms_txt", "/llms.txt"),
    ("contact", "/contact"),
    ("about", "/about"),
    ("team", "/team"),
    ("leadership", "/leadership"),
    ("support", "/support"),
    ("press", "/press"),
    ("robots_txt", "/robots.txt"),
    ("sitemap_xml", "/sitemap.xml"),
)
_MAX_BODY = 512_000


def _target_domain(value: str) -> str:
    return (value or "").strip().lower().lstrip(".")


class PublicSurfaceSweeper(BaseModule):
    name = "public_surface_sweeper"
    description = "Bounded sweep of well-known, contact, support, and machine-readable public pages."
    requires_key = False
    default_enabled = True

    async def run(self, domain: str, *, fetch: CachedFetch | None = None) -> ModuleResult:
        domain = _target_domain(domain)
        if not settings.enable_public_surface_sweeper:
            return ModuleResult(status=ModuleStatus.SKIPPED, metadata={"domain": domain})
        if not domain or "." not in domain:
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["invalid domain"])

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        checked = 0
        hits = 0

        async def get(url: str) -> Any:
            if fetch is not None:
                return await fetch.get(url)
            async with build_client(timeout=6.0, follow_redirects=True, max_redirects=2) as client:
                return await client.get(url)

        async def sweep_one(surface: str, path: str) -> tuple[int, list[dict[str, Any]], str | None]:
            url = urljoin(f"https://{domain}/", path.lstrip("/"))
            try:
                response = await get(url)
                if int(getattr(response, "status_code", 0) or 0) >= 400:
                    return 1, [], None
                text = getattr(response, "text", "") or ""
                emails = extract_emails(text[:_MAX_BODY], target_domain=domain)
                local_findings: list[dict[str, Any]] = []
                for item in emails:
                    if not item.on_domain:
                        continue
                    local_findings.append({
                        "platform": self.name,
                        "profile_url": url,
                        "username": item.email.split("@", 1)[0],
                        "confidence": "high" if surface.startswith("security") else "medium",
                        "metadata": {
                            "email": item.email,
                            "on_domain": True,
                            "surface": surface,
                            "url": url,
                            "source_type": "public_surface",
                            "snippet": item.source_text_snippet[:300],
                        },
                    })
                return 1, local_findings, None
            except Exception as exc:  # source failures must not abort harvest
                _LOG.debug("public surface %s failed", url, exc_info=True)
                return 0, [], f"{surface}: {exc}"

        sem = asyncio.Semaphore(4)
        async def bounded(surface: str, path: str):
            async with sem:
                return await sweep_one(surface, path)

        outcomes = await asyncio.gather(*[
            bounded(surface, path)
            for surface, path in _SURFACES[: settings.public_surface_max_urls]
        ])
        for count, local_findings, error in outcomes:
            checked += count
            findings.extend(local_findings)
            hits += len(local_findings)
            if error:
                errors.append(error)

        status = ModuleStatus.SUCCESS if checked else ModuleStatus.FAILED
        if errors and checked:
            status = ModuleStatus.PARTIAL
        return ModuleResult(
            status=status,
            findings=findings,
            metadata={"domain": domain, "urls_checked": checked, "email_hits": hits, "surfaces": len(_SURFACES)},
            errors=errors[:10],
        )
