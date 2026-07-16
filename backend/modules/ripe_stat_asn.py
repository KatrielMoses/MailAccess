"""RIPE Stat IP-to-ASN and announced-prefix enrichment."""

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


def parse_ripe_network_info(ip: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize RIPE network-info data into seed ASN rows for one IP."""
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return []
    prefix = data.get("prefix")
    try:
        normalized_prefix = (
            str(ipaddress.ip_network(str(prefix), strict=False)) if prefix else None
        )
    except ValueError:
        normalized_prefix = None
    rows: list[dict[str, Any]] = []
    for value in data.get("asns") or []:
        try:
            asn = int(value)
        except (TypeError, ValueError):
            continue
        rows.append(
            {
                "asn": asn,
                "name": "Unknown",
                "ips": [ip],
                "cidrs": [normalized_prefix] if normalized_prefix else [],
                "prefixes": [normalized_prefix] if normalized_prefix else [],
                "subdomains": [],
                "sources": ["ripe_stat"],
            }
        )
    return rows


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
        own_client = client is None
        http = client or build_client(timeout=10.0)
        semaphore = asyncio.Semaphore(6)

        async def get_payload(endpoint: str, resource: str) -> dict[str, Any] | None:
            try:
                async with semaphore:
                    response = await asyncio.wait_for(
                        http.get(
                            f"https://stat.ripe.net/data/{endpoint}/data.json",
                            params={"resource": resource, "sourceapp": "mailaccess"},
                        ),
                        timeout=10.0,
                    )
                if response.status_code != 200:
                    return None
                payload = response.json()
                if not isinstance(payload, dict) or payload.get("status") == "error":
                    return None
                return payload
            except Exception:  # noqa: BLE001
                return None

        ip_input = bool(asns and isinstance(asns[0], str))
        asn_rows: list[dict[str, Any]] = []
        try:
            if ip_input:
                ip_values = [str(value) for value in asns if isinstance(value, str)]
                payloads = await asyncio.gather(
                    *(get_payload("network-info", ip) for ip in ip_values)
                )
                for ip, payload in zip(ip_values, payloads):
                    if payload is not None:
                        asn_rows.extend(parse_ripe_network_info(ip, payload))
            else:
                asn_rows = [dict(row) for row in asns if isinstance(row, dict)]

            rows_by_asn: dict[int, dict[str, Any]] = {}
            for row in asn_rows:
                try:
                    number = int(row.get("asn"))
                except (TypeError, ValueError):
                    continue
                existing = rows_by_asn.setdefault(
                    number,
                    {
                        "asn": number,
                        "name": str(
                            row.get("name") or row.get("org_name") or "Unknown"
                        ),
                        "ips": [],
                        "cidrs": [],
                        "prefixes": [],
                        "subdomains": [],
                        "sources": [],
                    },
                )
                for field in ("ips", "cidrs", "prefixes", "subdomains", "sources"):
                    existing[field] = sorted(
                        {
                            *(str(value) for value in existing.get(field, []) if value),
                            *(str(value) for value in row.get(field, []) if value),
                        }
                    )
                if existing["name"] == "Unknown":
                    existing["name"] = str(
                        row.get("name") or row.get("org_name") or "Unknown"
                    )

            selected = list(sorted(rows_by_asn))[:20]

            async def enrich_one(asn: int) -> tuple[int, dict[str, Any]]:
                seed = rows_by_asn[asn]
                announced, overview = await asyncio.gather(
                    get_payload("announced-prefixes", f"AS{asn}"),
                    get_payload("as-overview", f"AS{asn}"),
                )
                org_name = str(seed.get("name") or "Unknown")
                overview_data = overview.get("data") if overview else None
                if isinstance(overview_data, dict) and overview_data.get("holder"):
                    org_name = str(overview_data["holder"])
                ripe_record = parse_ripe_stat(asn, org_name, announced or {})
                prefixes = sorted(
                    {
                        *(str(value) for value in seed.get("cidrs", []) if value),
                        *(str(value) for value in seed.get("prefixes", []) if value),
                        *(str(value) for value in ripe_record.prefixes if value),
                    }
                )
                record = asdict(ripe_record)
                record.update(
                    {
                        "name": org_name,
                        "ips": list(seed.get("ips", [])),
                        "subdomains": list(seed.get("subdomains", [])),
                        "sources": sorted(
                            {*seed.get("sources", []), "ripe_stat"}
                        ),
                        "prefixes": prefixes,
                        "cidrs": prefixes,
                    }
                )
                return asn, record

            enriched = await asyncio.gather(*(enrich_one(asn) for asn in selected))
            return dict(enriched)
        finally:
            if own_client:
                await http.aclose()


__all__ = [
    "RIPEStatASNModule",
    "RIPEStatRecord",
    "parse_ripe_network_info",
    "parse_ripe_stat",
]
