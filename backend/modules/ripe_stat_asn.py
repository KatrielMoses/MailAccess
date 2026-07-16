"""RIPE Stat announced-prefix enrichment for discovered ASNs."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus


@dataclass
class RIPEStatRecord:
    asn: int
    org_name: str = "Unknown"
    prefixes: list[str] = field(default_factory=list)


def parse_ripe_stat(asn: int, org_name: str, payload: dict[str, Any]) -> RIPEStatRecord:
    data = payload.get("data") if isinstance(payload, dict) else {}
    rows = data.get("prefixes", []) if isinstance(data, dict) else []
    prefixes: set[str] = set()
    for row in rows:
        value = row.get("prefix") if isinstance(row, dict) else None
        try:
            if value:
                prefixes.add(str(ipaddress.ip_network(str(value), strict=False)))
        except ValueError:
            continue
    return RIPEStatRecord(asn=int(asn), org_name=org_name or "Unknown", prefixes=sorted(prefixes))


class RIPEStatASNModule(BaseModule):
    name = "ripe_stat_asn"
    description = "Fetch announced CIDR prefixes for discovered ASNs"
    requires_key = False
    default_enabled = False

    async def run(
        self,
        domain: str,
        *,
        resolved_ips: list[str] | None = None,
        client: Any | None = None,
    ) -> ModuleResult:
        ips: list[str] = []
        for value in resolved_ips or []:
            try:
                normalized = str(ipaddress.ip_address(str(value)))
            except ValueError:
                continue
            if normalized not in ips:
                ips.append(normalized)
        if not ips:
            return ModuleResult(
                ModuleStatus.SKIPPED,
                metadata={
                    "domain": domain,
                    "skip_reason": "no_resolved_ips",
                    "infrastructure": {"ips": [], "asns": []},
                },
            )

        records = (
            await self.enrich(ips, client=client)
            if client is not None
            else await self.enrich(ips)
        )
        asn_rows = [records[asn] for asn in sorted(records)]
        ip_to_asn = {
            str(ip): int(row["asn"])
            for row in asn_rows
            for ip in row.get("ips", [])
        }
        return ModuleResult(
            ModuleStatus.SUCCESS if asn_rows else ModuleStatus.PARTIAL,
            metadata={
                "domain": domain,
                "resolved_ips": len(ips),
                "asns_found": len(asn_rows),
                "infrastructure": {
                    "ips": [
                        {
                            "ip": ip,
                            "asn": ip_to_asn.get(ip),
                            "sources": ["hackertarget", "ripe_stat"],
                        }
                        for ip in ips
                    ],
                    "asns": asn_rows,
                },
            },
            errors=[] if asn_rows else ["No ASNs resolved for discovered IPs"],
        )

    async def enrich(
        self,
        asns: list[dict[str, Any]] | list[str],
        *,
        client: Any | None = None,
    ) -> dict[int, dict[str, Any]]:
        asn_rows: list[dict[str, Any]]
        if asns and isinstance(asns[0], str):
            from .subdomain_intel import aggregate_infrastructure

            infrastructure = await aggregate_infrastructure(
                [
                    {
                        "subdomain": "",
                        "resolved_ips": [ip],
                        "discovery_method": ["hackertarget"],
                    }
                    for ip in asns
                ]
            )
            asn_rows = [dict(row) for row in infrastructure["asns"]]
        else:
            asn_rows = [dict(row) for row in asns if isinstance(row, dict)]

        unique: dict[int, str] = {}
        rows_by_asn: dict[int, dict[str, Any]] = {}
        for row in asn_rows:
            try:
                number = int(row.get("asn"))
            except (TypeError, ValueError):
                continue
            unique.setdefault(number, str(row.get("name") or row.get("org_name") or "Unknown"))
            rows_by_asn.setdefault(number, row)
        selected = list(unique.items())[:20]
        own_client = client is None
        http = client or build_client(timeout=10.0)
        records: dict[int, dict[str, Any]] = {}
        try:
            for index, (asn, org_name) in enumerate(selected):
                if index:
                    await asyncio.sleep(1.0)
                try:
                    response = await asyncio.wait_for(
                        http.get(
                            "https://stat.ripe.net/data/announced-prefixes/data.json",
                            params={"resource": f"AS{asn}"},
                        ),
                        timeout=10.0,
                    )
                    if response.status_code != 200:
                        continue
                    payload = response.json()
                    if isinstance(payload, dict):
                        record = asdict(parse_ripe_stat(asn, org_name, payload))
                        seed = rows_by_asn.get(asn, {})
                        prefixes = sorted(
                            {
                                *(str(value) for value in seed.get("cidrs", []) if value),
                                *(str(value) for value in record["prefixes"] if value),
                            }
                        )
                        record.update(
                            {
                                "name": org_name,
                                "ips": sorted(str(value) for value in seed.get("ips", [])),
                                "subdomains": sorted(
                                    str(value)
                                    for value in seed.get("subdomains", [])
                                    if value
                                ),
                                "sources": sorted(
                                    {
                                        *(str(value) for value in seed.get("sources", [])),
                                        "ripe_stat",
                                    }
                                ),
                                "prefixes": prefixes,
                                "cidrs": prefixes,
                            }
                        )
                        records[asn] = record
                except Exception:  # noqa: BLE001
                    continue
        finally:
            if own_client:
                await http.aclose()
        return records


__all__ = ["RIPEStatASNModule", "RIPEStatRecord", "parse_ripe_stat"]
