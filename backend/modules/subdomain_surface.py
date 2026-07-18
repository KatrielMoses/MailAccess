"""Bounded certificate/DNS subdomain discovery followed by page extraction."""
from __future__ import annotations

import asyncio
from typing import Any

from ..config import settings
from ..core.concurrent_fetch_cache import CachedFetch
from ..core.email_extraction import extract_emails
from ..core.harvester_collectors import collect_certspotter, collect_crtsh
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus


class SubdomainSurfaceModule(BaseModule):
    name = "subdomain_surface"
    description = "Certificate-backed subdomain discovery and bounded page email extraction."
    requires_key = False
    default_enabled = True

    async def run(self, domain: str, *, fetch: CachedFetch | None = None) -> ModuleResult:
        domain = (domain or "").strip().lower().rstrip(".")
        if not settings.enable_subdomain_surface:
            return ModuleResult(status=ModuleStatus.SKIPPED, metadata={"domain": domain})
        if not domain or "." not in domain:
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["invalid domain"])

        discovered: dict[str, set[str]] = {}
        errors: list[str] = []
        try:
            async with build_client(timeout=8.0) as client:
                sem = asyncio.Semaphore(3)
                results = await asyncio.gather(
                    collect_crtsh(client, domain, sem),
                    collect_certspotter(client, domain, sem),
                    return_exceptions=True,
                )
            for source, result in zip(("crtsh", "certspotter"), results):
                if isinstance(result, BaseException):
                    errors.append(f"{source}: {result}")
                    continue
                for host in result or set():
                    host = str(host).lower().strip().rstrip(".")
                    if host == domain or host.endswith(f".{domain}"):
                        discovered.setdefault(host, set()).add(source)
        except Exception as exc:
            errors.append(f"discovery: {exc}")

        hosts = sorted(discovered, key=lambda h: (h.count("."), h))[: settings.subdomain_surface_max_hosts]
        findings: list[dict[str, Any]] = []
        checked = 0

        async def get(url: str) -> Any:
            if fetch is not None:
                return await fetch.get(url)
            async with build_client(timeout=6.0, follow_redirects=True, max_redirects=2) as client:
                return await client.get(url)

        sem = asyncio.Semaphore(3)
        async def inspect(host: str) -> tuple[int, list[dict[str, Any]], str | None]:
            async with sem:
                last = f"{host}: no successful response"
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}/"
                    try:
                        response = await get(url)
                        if int(getattr(response, "status_code", 0) or 0) >= 400:
                            continue
                        text = (getattr(response, "text", "") or "")[:300_000]
                        local = []
                        for item in extract_emails(text, target_domain=domain):
                            if item.on_domain:
                                local.append({
                                    "platform": self.name,
                                    "profile_url": url,
                                    "username": item.email.split("@", 1)[0],
                                    "confidence": "high" if len(discovered[host]) > 1 else "medium",
                                    "metadata": {"email": item.email, "on_domain": True, "subdomain": host, "url": url, "sources": sorted(discovered[host]), "source_type": "subdomain_surface", "source_text_snippet": item.source_text_snippet[:300]},
                                })
                        return 1, local, None
                    except Exception as exc:
                        last = f"{host}: {exc}"
                return 0, [], last

        outcomes = await asyncio.gather(*(inspect(host) for host in hosts))
        for count, local, error in outcomes:
            checked += count
            findings.extend(local)
            if error:
                errors.append(error)

        status = ModuleStatus.SUCCESS if hosts and checked else ModuleStatus.PARTIAL if discovered else ModuleStatus.FAILED
        return ModuleResult(
            status=status,
            findings=findings,
            metadata={"domain": domain, "discovered": len(discovered), "hosts_checked": checked, "email_hits": len(findings), "source_counts": {k: len(v) for k, v in discovered.items()}},
            errors=errors[:10],
        )
