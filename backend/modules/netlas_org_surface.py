"""Org attack-surface context via Netlas (investigate path) — F7.

The organizational-context half of the Netlas integration. From the email's
*domain* (not the person) it attaches a public posture block: subdomains,
exposed login/admin panels, open ports/services, and known CVEs on the org's
hosts. Context *around* the person's employer, kept distinct from the person's
own findings.

Guardrails: free-provider domains SKIP (0 calls — webmail-provider surface is
meaningless and enormous); light mode is ~2 Netlas calls and runs on every
keyed corporate-domain investigate; ``--org-surface-deep`` adds F1 subdomain
enumeration (≤500). Never raises — any failure returns PARTIAL and the
investigate exits 0 with native + F6 findings intact.
"""

from __future__ import annotations

from ..config import settings
from ..core.enrichment_store import (
    fetch_answered,
    load_investigate_findings,
    merge_investigate,
    netlas_refresh,
    serve_from_store,
    should_fetch_investigate,
)
from ..core.netlas_client import (
    FAILURE_STATUSES,
    fetch_org_surface,
    netlas_active,
    org_surface_deep,
)
from .base import BaseModule, ModuleResult, ModuleStatus
from .domain_intel import _FREE_PROVIDERS


class NetlasOrgSurfaceModule(BaseModule):
    name = "netlas_org_surface"
    description = "Org attack-surface context (subdomains, panels, ports, CVEs) via Netlas."
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        domain = str(email or "").split("@")[-1].strip().lower()

        # Free-provider domains: the org surface of a webmail provider is
        # meaningless and enormous. SKIP before any store read or Netlas call.
        if not domain or "." not in domain or domain in _FREE_PROVIDERS:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["free provider or invalid domain"],
                metadata={"domain": domain, "is_free_provider": domain in _FREE_PROVIDERS,
                          "skip_reason": "free_provider"},
            )
        # F8: unconditional store read; key + 30-day-TTL gated fetch.
        stored = await load_investigate_findings(email, self.name)
        do_fetch = netlas_active() and await should_fetch_investigate(
            email, self.name, refresh=netlas_refresh()
        )
        if not do_fetch:
            if stored:
                served = serve_from_store(stored)
                return ModuleResult(
                    status=ModuleStatus.SUCCESS, findings=served,
                    metadata={"source": "netlas", "grade": "public source",
                              "context": "org_surface", "org_domain": domain,
                              "served_from_store": True, "calls": 0,
                              "summary": f"{len(served)} org-surface finding(s) from the "
                                         "enrichment store (no fresh Netlas fetch)."},
                )
            if netlas_active():
                # Active, but a fresh marker says we already checked: honest copy,
                # same SKIPPED state (no logic change).
                days = int(getattr(settings, "netlas_refresh_ttl_days", 30))
                return ModuleResult(
                    status=ModuleStatus.SKIPPED,
                    errors=[f"Checked within the last {days} days — nothing found"],
                    metadata={"domain": domain, "skip_reason": "recently_checked_empty"},
                )
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Netlas not active and nothing stored"],
                metadata={"domain": domain, "skip_reason": "netlas_inactive"},
            )

        deep = org_surface_deep()
        surface = await fetch_org_surface(domain, settings.netlas_api_key, deep=deep)

        if surface.overall_status() in FAILURE_STATUSES:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"Netlas org surface unavailable ({surface.overall_status()})"],
                metadata={
                    "source": "netlas", "domain": domain,
                    "netlas_status": surface.overall_status(),
                    "statuses": surface.statuses, "calls": surface.calls,
                    "summary": "Netlas org surface unavailable — used native findings only.",
                },
            )

        findings: list[dict] = []

        def _finding(signal: str, confidence: str, severity: str, summary: str,
                     extra: dict, source_url: str = "") -> dict:
            f = {
                "platform": "netlas",
                "source": "netlas",
                "confidence": confidence,
                "severity": severity,
                "grade": "public source",
                "metadata": {
                    "source": "netlas", "netlas_signal": signal, "grade": "public source",
                    "context": "org_surface", "org_domain": domain,
                    "summary": summary, **extra,
                },
            }
            if source_url:
                f["source_url"] = source_url
                f["profile_url"] = source_url
                f["metadata"]["source_url"] = source_url
            return f

        # CVEs — the only org-surface signal that contributes (lightly) to the
        # person's exposure; everything else is pure context (confidence "none").
        for cve in surface.cves:
            sev = (cve.severity or "").upper()
            findings.append(_finding(
                "org_cve", "low", "medium" if sev in {"HIGH", "CRITICAL"} else "low",
                f"{cve.name} ({cve.severity or 'unknown'}) on {cve.host or domain}",
                {"cve": cve.name, "cve_severity": cve.severity,
                 "cve_base_score": cve.base_score, "host": cve.host},
            ))

        # Exposed login / admin panels (contextual).
        for panel in surface.panels:
            findings.append(_finding(
                "org_exposed_panel", "none", "info",
                f"Exposed {panel.matched} panel: {panel.title or panel.source_url}",
                {"matched": panel.matched, "title": panel.title, "port": panel.port},
                source_url=panel.source_url,
            ))

        # Posture summary (ports / services / software / subdomain count).
        findings.append(_finding(
            "org_posture", "none", "info",
            f"{surface.subdomain_count or 0} subdomain(s), {len(surface.services)} service(s), "
            f"{len(surface.cves)} CVE(s), {len(surface.panels)} exposed panel(s)",
            {
                "subdomain_count": surface.subdomain_count,
                "open_ports": surface.ports,
                "software": surface.software,
                "related_domains_count": surface.related_domains_count,
                "service_count": len(surface.services),
                "deep": surface.deep,
                "subdomains": surface.subdomains if surface.deep else [],
            },
        ))

        summary = (
            f"Org surface for {domain}: {surface.subdomain_count or 0} subdomains, "
            f"{len(surface.panels)} exposed panel(s), {len(surface.services)} service(s), "
            f"{len(surface.cves)} CVE(s)"
        )
        metadata = {
            "source": "netlas", "grade": "public source", "context": "org_surface",
            "org_domain": domain, "deep": surface.deep,
            "netlas_status": surface.overall_status(), "statuses": surface.statuses,
            "calls": surface.calls, "capped": surface.capped,
            "subdomain_count": surface.subdomain_count,
            "exposed_panel_count": len(surface.panels),
            "service_count": len(surface.services),
            "cve_count": len(surface.cves),
            "cves": [c.name for c in surface.cves],
            "open_ports": surface.ports,
            "software": surface.software,
            "summary": summary,
        }
        # Empty-result marker: a clean keyed fetch (even with 0 findings) starts
        # the 30-day clock; a failed one does not, so it is retried next run.
        metadata["netlas_fetched"] = fetch_answered(surface.statuses)
        findings = merge_investigate(findings, stored)
        return ModuleResult(
            status=ModuleStatus.SUCCESS if findings else ModuleStatus.PARTIAL,
            findings=findings,
            metadata=metadata,
        )
