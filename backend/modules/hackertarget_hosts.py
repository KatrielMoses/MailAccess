"""Free HackerTarget host-search source for domain harvests."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any
from urllib.parse import quote

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)
_ENDPOINT = "https://api.hackertarget.com/hostsearch/"


def parse_hackertarget_response(text: str, domain: str) -> list[dict[str, Any]]:
    target = domain.strip().lower().rstrip(".")
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or "").splitlines():
        if "," not in line:
            continue
        hostname, raw_ip = (part.strip().lower().rstrip(".") for part in line.split(",", 1))
        if hostname != target and not hostname.endswith(f".{target}"):
            continue
        try:
            ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            continue
        if (hostname, ip) in seen:
            continue
        seen.add((hostname, ip))
        findings.append(
            {
                "subdomain": hostname,
                "addresses": [ip],
                "resolved_ips": [ip],
                "discovery_method": ["hackertarget"],
                "score": 0.0,
                "tier": "LOW",
                "scraped": [],
            }
        )
    return findings


class HackerTargetHostsModule(BaseModule):
    name = "hackertarget_hosts"
    description = "Free HackerTarget subdomain and IP discovery"
    requires_key = False
    default_enabled = True

    async def run(self, domain: str, *, fetch: Any | None = None) -> ModuleResult:
        target = domain.strip().lower().rstrip(".")
        if not target or "." not in target:
            return ModuleResult(ModuleStatus.SKIPPED, errors=["invalid domain"])
        try:
            if fetch is not None:
                response = await fetch.get(f"{_ENDPOINT}?q={quote(target)}", timeout=10.0)
            else:
                async with build_client(timeout=10.0) as client:
                    response = await client.get(_ENDPOINT, params={"q": target})
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("hackertarget host search failed: %s", exc)
            return ModuleResult(
                ModuleStatus.PARTIAL,
                errors=[f"hackertarget: {exc}"],
                metadata={"domain": target, "infrastructure": {"ips": [], "asns": []}},
            )
        body = str(getattr(response, "text", "") or "")
        if response.status_code == 429 or "api count exceeded" in body.lower():
            _LOG.warning("hackertarget API count exceeded or rate limited")
            return ModuleResult(
                ModuleStatus.PARTIAL,
                errors=["hackertarget rate limited"],
                metadata={"domain": target, "infrastructure": {"ips": [], "asns": []}},
            )
        if response.status_code != 200:
            return ModuleResult(
                ModuleStatus.PARTIAL,
                errors=[f"hackertarget HTTP {response.status_code}"],
            )
        findings = parse_hackertarget_response(body, target)
        ip_rows: dict[str, set[str]] = {}
        for finding in findings:
            for ip in finding["resolved_ips"]:
                ip_rows.setdefault(ip, set()).add(finding["subdomain"])
        return ModuleResult(
            ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "domain": target,
                "subdomains_found": len(findings),
                "infrastructure": {
                    "ips": [
                        {"ip": ip, "subdomains": sorted(hosts), "sources": ["hackertarget"]}
                        for ip, hosts in sorted(ip_rows.items())
                    ],
                    "asns": [],
                },
            },
        )


__all__ = ["HackerTargetHostsModule", "parse_hackertarget_response"]
