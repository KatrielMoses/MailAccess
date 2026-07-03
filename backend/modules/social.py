from __future__ import annotations

import asyncio
from typing import Any

from ..core.http_client import build_client
from ..core.platform_executor import PlatformExecutor
from ..core.platform_loader import PlatformLoader
from .base import BaseModule, ModuleResult, ModuleStatus


class SocialModule(BaseModule):
    name = "social"
    description = "Check social platform account existence via YAML-defined probes."
    requires_key = False

    async def run(self, email: str, **kwargs) -> ModuleResult:
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        gravatar_data = kwargs.get("gravatar_data")
        loader = PlatformLoader()
        platforms = loader.load_category("social") + loader.load_category("communication")
        executor = PlatformExecutor()

        # scrapingant: keep for social profile HTML where rendered/anti-bot access matters
        async with build_client(
            scrapingant_zone="platforms", timeout=10.0, follow_redirects=True
        ) as client:
            tasks = [
                executor.check(
                    platform,
                    email,
                    client,
                    gravatar_data=gravatar_data,
                )
                for platform in platforms
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception):
                errors.append(f"Social check exception: {str(res)}")
            elif isinstance(res, dict):
                if res.get("rate_limited"):
                    continue
                if "findings" in res:
                    findings.extend(res["findings"])
                elif "error" in res:
                    errors.append(res["error"])
                elif res.get("platform"):
                    findings.append(
                        {
                            "platform": res["platform"],
                            "profile_url": res.get("profile_url"),
                            "metadata": res.get("metadata", {}),
                            "confidence": res.get("confidence", "medium"),
                        }
                    )

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL if findings else ModuleStatus.FAILED

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={},
            errors=errors,
        )
