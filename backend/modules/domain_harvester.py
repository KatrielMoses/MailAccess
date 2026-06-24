from __future__ import annotations

import asyncio
import logging
import re
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

_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


def _enabled_source_names() -> set[str]:
    sources = load_sources()
    return {s["name"] for s in sources if s.get("name")}


def _extract_associate_emails(subdomains: set[str], domain: str) -> list[str]:
    emails: set[str] = set()
    for sub in subdomains:
        for match in _EMAIL_RE.findall(sub):
            candidate = match.lower()
            if candidate.endswith(f"@{domain}") or f"@{domain}" in candidate:
                emails.add(candidate)
    return sorted(emails)


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
                brute_hits = await dns_brute_force(
                    client, domain, list(wordlist), brute_sem
                )
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

        # Build per-subdomain source attribution
        subdomain_sources: dict[str, list[str]] = {}
        for source_name, found in per_source.items():
            for sub in found:
                subdomain_sources.setdefault(sub, []).append(source_name)
        for sub in brute_hits:
            subdomain_sources.setdefault(sub, []).append("dns_brute")

        # Determine wave per subdomain (wave 1 if any wave-1 source found it)
        def _subdomain_wave(sub: str) -> int:
            srcs = subdomain_sources.get(sub, [])
            for s in srcs:
                if s in _WAVE1_SOURCES or s == "dns_brute":
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

        associate_emails = _extract_associate_emails(all_subdomains, domain)

        subdomains_per_source = {
            name: len(found) for name, found in per_source.items()
        }

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
