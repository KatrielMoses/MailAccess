"""Domain infrastructure clustering — post-primary module.

Walks the platform findings already collected by primary modules, extracts
the platform domain from each ``profile_url``, runs a short WHOIS + DNS-A
lookup per unique domain, and feeds the (platform, domain, registrar, ip)
tuples into :class:`backend.core.enrichment.domain_cluster.InfrastructureClusterer`.

Clusters of three or more platforms sharing the same registrar AND /24 IP
subnet are emitted as ``infra_cluster`` findings with ``signal_type =
infrastructure_correlation``.  Known free providers (Gmail, GitHub, Twitter,
etc.) are skipped at the domain level so the cluster signal stays useful —
three random free providers all on Cloudflare would otherwise produce a
nonsensical "shared infrastructure" cluster.

Configuration:
    ENABLE_DOMAIN_CLUSTER  – master switch (default true).  Set false to
                             skip the entire phase without code changes.
    DOMAIN_CLUSTER_CAP     – maximum number of unique domains to look up
                             per investigation (default 20).  Keeps the
                             WHOIS fan-out bounded when the target has
                             accounts on dozens of platforms.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

from ..config import settings
from ..core.enrichment.domain_cluster import (
    InfrastructureClusterer,
    ip_to_subnet,
    normalize_registrar,
)
from ..modules.base import BaseModule, ModuleResult, ModuleStatus
from ..modules.domain_intel import _FREE_PROVIDERS

logger = logging.getLogger(__name__)


def _extract_platform_domain(finding: dict[str, Any]) -> str | None:
    """Return the registered domain for a platform finding.

    Falls back to the ``domain`` / ``breach_domain`` metadata keys when
    the ``profile_url`` is missing or unparsable.  Returns None for free
    providers and any domain that fails the basic shape check.
    """
    candidates: list[str] = []
    profile_url = finding.get("profile_url") or finding.get("url")
    if isinstance(profile_url, str) and profile_url.strip():
        try:
            parsed = urlparse(profile_url.strip())
            if parsed.netloc:
                candidates.append(parsed.netloc.lower().lstrip("www."))
        except (ValueError, TypeError):
            pass
    meta = finding.get("metadata")
    if isinstance(meta, dict):
        for key in ("domain", "breach_domain", "platform_domain"):
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append(value.strip().lower().lstrip("www."))
    for raw in candidates:
        # Strip path, keep only host[:port] → host
        host = raw.split("/")[0].split(":")[0]
        if not host or "." not in host:
            continue
        if host in _FREE_PROVIDERS:
            continue
        return host
    return None


def _sync_whois(domain: str) -> str | None:
    """Run a WHOIS lookup and return the registrar string (or None).

    Wraps the optional ``whois`` package — the call site is already gated
    on availability by the import in ``whois_lookup`` / ``domain_intel``.
    """
    try:
        import whois  # type: ignore[import]

        result = whois.whois(domain)
        registrar = result.get("registrar") if isinstance(result, dict) else None
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None
        if isinstance(registrar, str) and registrar.strip():
            return registrar.strip()
    except Exception as exc:
        logger.debug("domain_cluster whois %s failed: %s", domain, exc)
    return None


def _sync_dns_a(domain: str) -> str | None:
    """Return the first A record for a domain, or None on failure."""
    try:
        import dns.resolver  # type: ignore[import]

        answers = dns.resolver.resolve(domain, "A", lifetime=4.0)
        if answers:
            return str(answers[0])
    except Exception as exc:
        logger.debug("domain_cluster dns %s failed: %s", domain, exc)
    return None


class DomainClusterModule(BaseModule):
    name = "domain_cluster"
    description = (
        "Group platform domains by shared registrar + /24 IP subnet. "
        "Emits infrastructure_correlation findings when 3+ platforms share "
        "infrastructure."
    )
    requires_key = False

    async def run(
        self, email: str, collected: dict[str, ModuleResult]
    ) -> ModuleResult:
        # Cheap master switch — modules that depend on opt-in env vars
        # normally guard via settings, but the phase runner already calls
        # every post-primary module unconditionally, so we do the gate
        # here as well to keep behaviour consistent with the spec.
        if not getattr(settings, "enable_domain_cluster", True):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"skip_reason": "ENABLE_DOMAIN_CLUSTER disabled"},
            )

        cap = int(getattr(settings, "domain_cluster_cap", 20) or 20)
        platform_to_domain: dict[str, str] = {}
        for module_name, result in collected.items():
            if not isinstance(result, ModuleResult):
                continue
            for finding in result.findings:
                if not isinstance(finding, dict):
                    continue
                platform = str(
                    finding.get("platform") or module_name or "unknown"
                ).strip().lower()
                if not platform:
                    continue
                domain = _extract_platform_domain(finding)
                if not domain:
                    continue
                platform_to_domain[platform] = domain

        if not platform_to_domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                findings=[],
                metadata={"skip_reason": "no_platforms_with_domain"},
            )

        # Cap the WHOIS fan-out.  If the target has more platforms than
        # the cap, prefer the most-recent findings (the tail of the dict
        # iteration order matches insertion order which is the order
        # primary modules were recorded).
        ordered = list(platform_to_domain.items())
        if len(ordered) > cap:
            ordered = ordered[:cap]
            truncated = True
        else:
            truncated = False

        unique_domains: dict[str, list[str]] = {}
        for platform, domain in ordered:
            unique_domains.setdefault(domain, []).append(platform)

        async def lookup(domain: str) -> tuple[str, str | None, str | None]:
            try:
                registrar, ip = await asyncio.gather(
                    asyncio.to_thread(_sync_whois, domain),
                    asyncio.to_thread(_sync_dns_a, domain),
                )
            except Exception as exc:
                logger.debug("domain_cluster gather %s failed: %s", domain, exc)
                return domain, None, None
            return domain, registrar, ip

        domain_results = await asyncio.gather(
            *(lookup(d) for d in unique_domains.keys()),
            return_exceptions=True,
        )

        observations: list[tuple[str, str, str | None, str | None]] = []
        domains_with_registrar = 0
        domains_with_ip = 0
        for outcome in domain_results:
            if isinstance(outcome, BaseException):
                continue
            domain, registrar, ip = outcome
            if normalize_registrar(registrar) is not None:
                domains_with_registrar += 1
            if ip_to_subnet(ip or "", 24) is not None:
                domains_with_ip += 1
            for platform in unique_domains[domain]:
                observations.append((platform, domain, registrar, ip))

        clusters = InfrastructureClusterer(min_cluster_size=3).cluster(observations)

        findings: list[dict[str, Any]] = []
        for cluster in clusters:
            findings.append({
                "platform": "infra_cluster",
                "signal_type": "infrastructure_correlation",
                "confidence": "medium",
                "metadata": {
                    "cluster_id": cluster.cluster_id,
                    "platforms": cluster.platforms,
                    "domains": cluster.domains,
                    "shared_registrar": cluster.shared_registrar,
                    "shared_subnet": cluster.shared_ip_subnet,
                    "shared_ip_subnet": cluster.shared_ip_subnet,
                    "platform_count": cluster.platform_count,
                    "cluster_confidence": cluster.confidence,
                    "signal": cluster.signal,
                },
            })

        status = ModuleStatus.SUCCESS if findings else ModuleStatus.SUCCESS
        # Empty result is still a success — we just had nothing to cluster
        # (most common case for free-provider investigations).

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "domains_looked_up": len(unique_domains),
                "platforms_seen": len(platform_to_domain),
                "domains_with_registrar": domains_with_registrar,
                "domains_with_ip": domains_with_ip,
                "clusters_emitted": len(clusters),
                "cap": cap,
                "truncated": truncated,
            },
        )
