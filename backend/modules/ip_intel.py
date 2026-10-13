"""Enrich IPs already collected by breach and DNS modules; discover nothing."""

from __future__ import annotations

from ..config import settings
from ..core.enrichment_store import enrich_ips, netlas_refresh
from ..core.ipgeo_client import public_ips
from .base import BaseModule, ModuleResult, ModuleStatus
from .domain_intel import _FREE_PROVIDERS


def collect_investigate_ips(email: str, collected: dict) -> dict[str, str | None]:
    sources: dict[str, str | None] = {}
    for name, result in collected.items():
        if name not in {
            "breach_aggregator",
            "breach_deep",
            "hibp",
            "breachdirectory",
            "xposedornot",
            "intelx_lookup",
        }:
            continue
        for finding in result.findings:
            meta = finding.get("metadata") or {}
            for record in [meta, *(meta.get("breach_data") or [])]:
                if not isinstance(record, dict):
                    continue
                for ip in public_ips([record.get("ip_address") or record.get("ip")]):
                    sources.setdefault(
                        ip,
                        record.get("breach_source")
                        or meta.get("breach_source")
                        or meta.get("breach_name"),
                    )
    domain = email.rsplit("@", 1)[-1].lower()
    if domain not in _FREE_PROVIDERS:
        dns = collected.get("dns_lookup")
        for finding in getattr(dns, "findings", []):
            if finding.get("platform") == "dns_a":
                for ip in public_ips([(finding.get("metadata") or {}).get("ip_address")]):
                    sources.setdefault(ip, None)
    return dict(list(sources.items())[: max(0, settings.ipgeo_investigate_ip_cap)])


class IpIntelModule(BaseModule):
    name = "ip_intel"
    description = "Location, owner, risk and abuse contact for existing IPs via ipgeolocation.io."
    email_linked = False

    async def run(self, email: str, collected: dict | None = None) -> ModuleResult:
        sources = collect_investigate_ips(email, collected or {})
        records = await enrich_ips(list(sources), refresh=netlas_refresh())
        findings = [
            {
                "platform": "ip_intel",
                "confidence": "none",
                "email_linked": sources[ip] is not None or _is_breach_ip(ip, collected or {}),
                "metadata": {**data, "source_breach": sources[ip]},
            }
            for ip, data in records.items()
        ]
        return ModuleResult(
            ModuleStatus.SUCCESS if findings else ModuleStatus.SKIPPED,
            findings=findings,
            metadata={"ips_found": len(sources)},
        )


def _is_breach_ip(ip: str, collected: dict) -> bool:
    breach_only = {name: result for name, result in collected.items() if name != "dns_lookup"}
    return ip in collect_investigate_ips("target@gmail.com", breach_only)
