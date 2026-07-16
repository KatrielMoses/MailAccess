"""No-key Shodan InternetDB enrichment for resolved IP addresses."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus


@dataclass
class InternetDBRecord:
    ip: str
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def parse_internetdb(ip: str, payload: dict[str, Any]) -> InternetDBRecord:
    return InternetDBRecord(
        ip=ip,
        ports=sorted({int(port) for port in payload.get("ports", []) if str(port).isdigit()}),
        hostnames=sorted({str(value) for value in payload.get("hostnames", []) if value}),
        vulns=sorted({str(value) for value in payload.get("vulns", []) if value}),
        cpes=sorted({str(value) for value in payload.get("cpes", []) if value}),
        tags=sorted({str(value) for value in payload.get("tags", []) if value}),
    )


class ShodanInternetDBModule(BaseModule):
    name = "shodan_internetdb"
    description = "Enrich resolved IPs with open ports and CVEs from InternetDB"
    requires_key = False
    default_enabled = False

    async def run(self, domain: str) -> ModuleResult:
        return ModuleResult(ModuleStatus.SKIPPED)

    async def enrich(
        self, ips: list[str], *, client: Any | None = None
    ) -> dict[str, dict[str, Any]]:
        unique: list[str] = []
        for value in ips:
            try:
                cleaned = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            if cleaned not in unique:
                unique.append(cleaned)
        unique = unique[:50]
        own_client = client is None
        http = client or build_client(timeout=5.0)
        records: dict[str, dict[str, Any]] = {}
        try:
            for index, ip in enumerate(unique):
                if index:
                    await asyncio.sleep(1.0)
                try:
                    response = await asyncio.wait_for(
                        http.get(f"https://internetdb.shodan.io/{ip}"), timeout=5.0
                    )
                    if response.status_code != 200:
                        continue
                    payload = response.json()
                    if isinstance(payload, dict):
                        records[ip] = asdict(parse_internetdb(ip, payload))
                except Exception:  # noqa: BLE001
                    continue
        finally:
            if own_client:
                await http.aclose()
        return records


__all__ = ["InternetDBRecord", "ShodanInternetDBModule", "parse_internetdb"]
