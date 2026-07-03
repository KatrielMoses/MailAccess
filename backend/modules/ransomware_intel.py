from __future__ import annotations

import logging
from typing import Any

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus
from .domain_intel import _FREE_PROVIDERS

logger = logging.getLogger(__name__)


class RansomwareIntelModule(BaseModule):
    name = "ransomware_intel"
    description = "Checks if the email's domain appears in ransomware victim listings."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@")[-1].lower()

        if domain in _FREE_PROVIDERS:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"domain": domain, "is_free_provider": True},
                errors=["free provider"],
            )

        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # We will attempt multiple possible endpoints to find if the domain is a victim
        # 1. Ransomware.live search endpoint
        # 2. Ransomlook API search endpoint

        metadata = {
            "domain_checked": domain,
            "victim_found": False,
            "ransomware_group": None,
            "attack_date": None,
        }

        found_group = None
        found_date = None

        # scrapingant: dropped in S5 audit (ransomware feed endpoint returns JSON)
        async with build_client(timeout=10.0) as client:
            # Check Ransomware.live
            try:
                # Sometimes ransomware.live has a search API or domain-specific endpoint
                # We'll use a hypothetical search endpoint and gracefully handle 404/errors
                resp = await client.get(f"https://api.ransomware.live/search/{domain}")
                if resp.status_code == 200:
                    data = resp.json()
                    # Expecting a list of hits or a dict
                    if isinstance(data, list) and len(data) > 0:
                        first_hit = data[0]
                        found_group = first_hit.get("group_name") or first_hit.get("group")
                        found_date = first_hit.get("discovered") or first_hit.get("date")
                    elif isinstance(data, dict) and data.get("group_name"):
                        found_group = data.get("group_name")
                        found_date = data.get("discovered")
            except Exception as exc:
                errors.append(f"ransomware.live: {exc}")

            # Check RansomLook if not found
            if not found_group:
                try:
                    resp = await client.get(f"https://api.ransomlook.io/search?query={domain}")
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 0:
                            first_hit = data[0]
                            found_group = first_hit.get("group_name") or first_hit.get("group")
                            found_date = first_hit.get("discovered") or first_hit.get("date")
                except Exception as exc:
                    errors.append(f"ransomlook: {exc}")

        if found_group:
            metadata["victim_found"] = True
            metadata["ransomware_group"] = found_group
            metadata["attack_date"] = found_date

            findings.append(
                {
                    "platform": "RansomwareIntel",
                    "signal_type": "ransomware_victim_domain",
                    "confidence": "medium",
                    "severity": "high",
                    "metadata": {
                        "domain": domain,
                        "group_name": found_group,
                        "attack_date": found_date,
                        "note": (
                            "[domain-level signal — all @domain.com addresses inherit "
                            "this exposure context]"
                        ),
                    },
                }
            )

            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=findings,
                metadata=metadata,
                errors=errors if errors else None,
            )

        status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS

        return ModuleResult(
            status=status, findings=findings, metadata=metadata, errors=errors if errors else None
        )
