from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from typing import Any

from ..config import settings
from ..core.disposable_domains import is_disposable_email
from ..core.harvester_collectors import (
    collect_bufferoverun,
    collect_certspotter,
    collect_crtsh,
    collect_rapiddns,
    collect_threatminer,
    dns_brute_force,
    resolve_ips,
)
from ..core.harvester_loader import load_sources, load_wordlist
from ..core.http_client import build_client
from ..core.platform_health import get_health_db
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_WAVE1_CONCURRENCY = 5
_WAVE2_CONCURRENCY = 3
_BRUTE_PREFIX_CAP = 200

_WAVE1_SOURCES = frozenset({"crtsh", "certspotter", "bufferoverun"})
_WAVE2_SOURCES = frozenset({"rapiddns", "threatminer"})

_COLLECTOR_MAP = {
    "crtsh": collect_crtsh,
    "rapiddns": collect_rapiddns,
    "certspotter": collect_certspotter,
    "bufferoverun": collect_bufferoverun,
    "threatminer": collect_threatminer,
}


def _normalise_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


async def _resolve_ip_asn_footprint(
    client: Any,
    domain: str,
    ip_map: dict[str, list[str]],
    sem: asyncio.Semaphore,
) -> dict[str, list[dict[str, Any]]]:
    """Resolve unique subdomain/root IPs to BGPView ASN and CIDR data."""
    try:
        root_map = await resolve_ips(client, {domain}, sem)
    except Exception as exc:
        _LOG.debug("domain_harvester: root IP resolution failed for %s: %s", domain, exc)
        root_map = {}

    host_ips: dict[str, set[str]] = {}
    for host, values in {**ip_map, **root_map}.items():
        for value in values or []:
            ip = _normalise_ip(value)
            if ip:
                host_ips.setdefault(ip, set()).add(host)

    async def lookup(ip: str) -> tuple[str, dict[str, Any] | None]:
        async with sem:
            try:
                response = await client.get(f"https://api.bgpview.io/ip/{ip}")
                if int(getattr(response, "status_code", 0) or 0) >= 400:
                    return ip, None
                body = response.json()
            except Exception as exc:
                _LOG.debug("domain_harvester: ASN lookup failed for %s: %s", ip, exc)
                return ip, None

        prefixes = ((body.get("data") or {}).get("prefixes") or []) if isinstance(body, dict) else []
        asns: dict[int, dict[str, Any]] = {}
        for item in prefixes:
            if not isinstance(item, dict):
                continue
            asn_data = item.get("asn")
            if not isinstance(asn_data, dict):
                continue
            try:
                number = int(asn_data.get("asn"))
            except (TypeError, ValueError):
                continue
            record = asns.setdefault(
                number,
                {
                    "asn": number,
                    "name": str(asn_data.get("name") or asn_data.get("description") or "Unknown"),
                    "cidrs": set(),
                },
            )
            prefix = item.get("prefix")
            if prefix:
                record["cidrs"].add(str(prefix))

        records = [
            {
                "asn": record["asn"],
                "name": record["name"],
                "cidrs": sorted(record["cidrs"]),
            }
            for record in asns.values()
        ]
        return ip, {"asns": records}

    lookups = await asyncio.gather(*(lookup(ip) for ip in sorted(host_ips)))
    ip_records: list[dict[str, Any]] = []
    asn_groups: dict[int, dict[str, Any]] = {}
    for ip, result in lookups:
        records = (result or {}).get("asns", [])
        cidrs: set[str] = set()
        asn_values: list[int] = []
        for record in records:
            asn = int(record["asn"])
            asn_values.append(asn)
            cidrs.update(record.get("cidrs") or [])
            group = asn_groups.setdefault(
                asn,
                {"asn": asn, "name": record["name"], "ips": set(), "cidrs": set()},
            )
            group["ips"].add(ip)
            group["cidrs"].update(record.get("cidrs") or [])
        ip_records.append(
            {
                "ip": ip,
                "hosts": sorted(host_ips[ip]),
                "asn": asn_values[0] if len(asn_values) == 1 else None,
                "asn_name": records[0]["name"] if len(records) == 1 else None,
                "asns": sorted(asn_values),
                "cidrs": sorted(cidrs),
            }
        )

    return {
        "ips": ip_records,
        "asns": [
            {
                "asn": group["asn"],
                "name": group["name"],
                "ips": sorted(group["ips"]),
                "cidrs": sorted(group["cidrs"]),
            }
            for group in sorted(asn_groups.values(), key=lambda item: item["asn"])
        ],
    }


def _enabled_source_names() -> set[str]:
    sources = load_sources()
    return {s["name"] for s in sources if s.get("name")}


def _subdomain_finding(
    subdomain: str,
    parent_domain: str,
    sources_found: list[str],
    ips: list[str],
    wave: int,
) -> dict[str, Any]:
    return {
        "platform": f"host:{subdomain}",
        "profile_url": f"https://{subdomain}",
        "username": None,
        "confidence": "medium",
        "metadata": {
            "source": "domain_harvester",
            "subdomain": subdomain,
            "parent_domain": parent_domain,
            "sources_found": sources_found,
            "ips": ips,
            "wave": wave,
        },
    }


def _ip_finding(subdomain: str, ip: str) -> dict[str, Any]:
    return {
        "platform": f"host_ip:{subdomain}",
        "profile_url": f"https://{subdomain}",
        "username": None,
        "confidence": "low",
        "metadata": {
            "source": "domain_harvester",
            "subdomain": subdomain,
            "ip": ip,
            "type": "ip_resolution",
        },
    }


class DomainHarvesterModule(BaseModule):
    name = "domain_harvester"
    description = (
        "Subdomain enumeration + DNS brute force + hostname resolution for the target "
        "email's domain. Native port of curated theHarvester collectors."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_domain_harvester or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["domain_harvester disabled — set ENABLE_DOMAIN_HARVESTER=true to enable"],
            )

        if not isinstance(email, str) or "@" not in email:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["invalid email — no @ sign"],
            )

        domain = email.split("@", 1)[1].lower().strip()

        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        personal_providers = set(settings.personal_email_providers)
        if domain in personal_providers:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"skip_reason": "personal_email_provider", "domain": domain},
            )

        if is_disposable_email(email):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"skip_reason": "disposable_email", "domain": domain},
            )

        enabled_names = _enabled_source_names()
        health = get_health_db()

        wave1_sources = [n for n in _WAVE1_SOURCES if n in enabled_names]
        wave2_sources = [n for n in _WAVE2_SOURCES if n in enabled_names]

        per_source: dict[str, set[str]] = {}
        errors: list[str] = []
        sources_succeeded: list[str] = []
        sources_failed: list[str] = []
        all_subdomains: set[str] = set()
        brute_hits: set[str] = set()
        ip_map: dict[str, list[str]] = {}

        # scrapingant: dropped in S5 audit (subdomain collectors use structured APIs)
        async with build_client(timeout=18.0) as client:
            # Wave 1: fast JSON APIs
            w1_sem = asyncio.Semaphore(_WAVE1_CONCURRENCY)
            w1_results = await asyncio.gather(
                *[self._run_source(client, domain, name, w1_sem, health) for name in wave1_sources],
                return_exceptions=True,
            )
            for name, outcome in zip(wave1_sources, w1_results):
                if isinstance(outcome, BaseException):
                    errors.append(f"{name}: {outcome}")
                    sources_failed.append(name)
                    per_source[name] = set()
                else:
                    found, failed = outcome
                    per_source[name] = found
                    all_subdomains.update(found)
                    if failed:
                        sources_failed.append(name)
                        errors.append(failed)
                    else:
                        sources_succeeded.append(name)

            # Wave 2: HTML scraping + slower APIs
            w2_sem = asyncio.Semaphore(_WAVE2_CONCURRENCY)
            w2_results = await asyncio.gather(
                *[self._run_source(client, domain, name, w2_sem, health) for name in wave2_sources],
                return_exceptions=True,
            )
            for name, outcome in zip(wave2_sources, w2_results):
                if isinstance(outcome, BaseException):
                    errors.append(f"{name}: {outcome}")
                    sources_failed.append(name)
                    per_source[name] = set()
                else:
                    found, failed = outcome
                    per_source[name] = found
                    all_subdomains.update(found)
                    if failed:
                        sources_failed.append(name)
                        errors.append(failed)
                    else:
                        sources_succeeded.append(name)

            # DNS brute force
            wordlist = load_wordlist()
            brute_sem = asyncio.Semaphore(20)
            try:
                brute_hits = await dns_brute_force(client, domain, list(wordlist), brute_sem)
                all_subdomains.update(brute_hits)
            except Exception as exc:
                _LOG.debug("domain_harvester: dns_brute error for %s: %s", domain, exc)
                errors.append(f"dns_brute: {exc}")

            # IP resolution
            ip_sem = asyncio.Semaphore(20)
            try:
                ip_map = await resolve_ips(client, all_subdomains, ip_sem)
            except Exception as exc:
                _LOG.debug("domain_harvester: resolve_ips error for %s: %s", domain, exc)
                errors.append(f"resolve_ips: {exc}")

            infrastructure = await _resolve_ip_asn_footprint(
                client, domain, ip_map, ip_sem
            )

        # Build per-subdomain source attribution
        subdomain_sources: dict[str, list[str]] = {}
        for source_name, found in per_source.items():
            for sub in found:
                subdomain_sources.setdefault(sub, []).append(source_name)
        for sub in brute_hits:
            subdomain_sources.setdefault(sub, []).append("dns_brute")

        # Determine wave per subdomain. MUST-FIX S9: wave 1 (highest
        # confidence) is reserved for subdomains found by a structured
        # API source (``_WAVE1_SOURCES`` — crt.sh / certspotter /
        # bufferoverun). The pre-fix code OR'd ``s == "dns_brute"``
        # into the wave-1 check, which incorrectly promoted
        # brute-force-only subdomains (the LOWEST confidence source)
        # to wave 1.
        def _subdomain_wave(sub: str) -> int:
            srcs = subdomain_sources.get(sub, [])
            for s in srcs:
                if s in _WAVE1_SOURCES:
                    return 1
            return 2

        # Build findings
        findings: list[dict[str, Any]] = []
        seen_subdomains: set[str] = set()

        for sub in sorted(all_subdomains):
            if sub in seen_subdomains:
                continue
            seen_subdomains.add(sub)
            ips = ip_map.get(sub, [])
            srcs = subdomain_sources.get(sub, [])
            wave = _subdomain_wave(sub)
            findings.append(_subdomain_finding(sub, domain, srcs, ips, wave))
            for ip in ips:
                findings.append(_ip_finding(sub, ip))

        # MUST-FIX S7: removed the dead ``_extract_associate_emails`` call.
        # The function always returned ``[]`` because subdomain hostname
        # strings do not contain ``@`` characters — subdomains are
        # hostnames, not email addresses. We keep the metadata key
        # ``associate_emails`` so the public schema doesn't change, but
        # the value is always an empty list. The correct way to find
        # emails associated with discovered subdomains is to fetch
        # the page content at those subdomains and run email extraction
        # on it — tracked separately as future work.
        associate_emails: list[str] = []

        subdomains_per_source = {name: len(found) for name, found in per_source.items()}

        all_sources_probed = wave1_sources + wave2_sources
        all_errored = len(sources_failed) == len(all_sources_probed) and len(all_sources_probed) > 0

        if all_errored and not brute_hits:
            status = ModuleStatus.PARTIAL
            errors = [f"all sources errored ({', '.join(sources_failed)})"] + errors
        else:
            status = ModuleStatus.SUCCESS

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "domain": domain,
                "sources_probed": all_sources_probed,
                "sources_succeeded": sources_succeeded,
                "sources_failed": sources_failed,
                "subdomains_found": len(seen_subdomains),
                "subdomains_per_source": subdomains_per_source,
                "ips_resolved": len(ip_map),
                "infrastructure": infrastructure,
                "dns_brute_hits": len(brute_hits),
                "associate_emails": associate_emails,
                "errors": errors,
            },
            errors=errors[:50],
        )

    async def _run_source(
        self,
        client: Any,
        domain: str,
        source_name: str,
        sem: asyncio.Semaphore,
        health: Any,
    ) -> tuple[set[str], str]:
        fn = _COLLECTOR_MAP.get(source_name)
        if fn is None:
            return set(), f"{source_name}: no collector"

        if not await health.should_probe_async(f"harvester:{source_name}"):
            _LOG.debug("domain_harvester: skipping %s (health DB)", source_name)
            return set(), ""

        t0 = time.perf_counter()
        try:
            found = await fn(client, domain, sem)
            latency_ms = int((time.perf_counter() - t0) * 1000)
            try:
                await health.record_probe_async(
                    platform=f"harvester:{source_name}",
                    domain=domain,
                    outcome="hit" if found else "miss",
                    latency_ms=latency_ms,
                    content_length=len(found),
                )
            except Exception:
                pass
            return found, ""
        except Exception as exc:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            try:
                await health.record_probe_async(
                    platform=f"harvester:{source_name}",
                    domain=domain,
                    outcome="inconclusive",
                    latency_ms=latency_ms,
                    content_length=0,
                )
            except Exception:
                pass
            return set(), f"{source_name}: {exc}"
