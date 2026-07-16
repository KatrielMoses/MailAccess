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

    async def run(self, domain: str) -> ModuleResult:
        return ModuleResult(ModuleStatus.SKIPPED)

    async def enrich(
        self, asns: list[dict[str, Any]], *, client: Any | None = None
    ) -> dict[int, dict[str, Any]]:
        unique: dict[int, str] = {}
        for row in asns:
            try:
                number = int(row.get("asn"))
            except (TypeError, ValueError):
                continue
            unique.setdefault(number, str(row.get("name") or row.get("org_name") or "Unknown"))
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
                        records[asn] = asdict(parse_ripe_stat(asn, org_name, payload))
                except Exception:  # noqa: BLE001
                    continue
        finally:
            if own_client:
                await http.aclose()
        return records


__all__ = ["RIPEStatASNModule", "RIPEStatRecord", "parse_ripe_stat"]
