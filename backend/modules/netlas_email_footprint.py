"""Reverse email footprint via Netlas (investigate path) — F6.

The per-email half of the Netlas integration (mirrors
:mod:`backend.modules.hunter_io`): for one exact address, three bounded Netlas
lookups show *where it appears online* —

* **responses / FTP banners** — public pages/banners that publish the address;
* **certificates** — TLS certs whose subject / SAN carries the address;
* **reverse-WHOIS** — domains where the address is a registration contact
  (registrant / admin / tech) — a strong ownership signal.

Each becomes an investigate finding with ``source="netlas"`` and
``grade="public source"``, and feeds the existing exposure score (more public
appearances = more exposure; reverse-WHOIS ranks highest). Reverse-WHOIS
domains are *reported only* — never auto-harvested (that is the user's next
action). Exactly 3 Netlas calls per investigate; never raises (any failure
leaves native findings intact and the run exits 0).
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
    fetch_email_footprint,
    netlas_active,
)
from .base import BaseModule, ModuleResult, ModuleStatus


class NetlasEmailFootprintModule(BaseModule):
    name = "netlas_email_footprint"
    description = "Where an email appears online via Netlas (responses, certs, reverse-WHOIS)."
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        # F8: the store READ is unconditional (key-independent). The FETCH is key
        # + 30-day-TTL gated. A no-key run with stored findings still serves them.
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
                              "served_from_store": True, "calls": 0,
                              "summary": f"{len(served)} footprint finding(s) from the "
                                         "enrichment store (no fresh Netlas fetch)."},
                )
            if netlas_active():
                # Active, but a fresh marker says we already checked: honest copy,
                # same SKIPPED state (no logic change).
                days = int(getattr(settings, "netlas_refresh_ttl_days", 30))
                return ModuleResult(
                    status=ModuleStatus.SKIPPED,
                    errors=[f"Checked within the last {days} days — nothing found"],
                    metadata={"skip_reason": "recently_checked_empty"},
                )
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Netlas not active and nothing stored"],
                metadata={"skip_reason": "netlas_inactive"},
            )

        outcome = await fetch_email_footprint(email, settings.netlas_api_key)

        if outcome.overall_status() in FAILURE_STATUSES:
            # Logged inside the client; surface a dim note, keep the run green.
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"Netlas footprint unavailable ({outcome.overall_status()})"],
                metadata={
                    "source": "netlas",
                    "netlas_status": outcome.overall_status(),
                    "statuses": outcome.statuses,
                    "calls": outcome.calls,
                    "summary": "Netlas footprint unavailable — used native findings only.",
                },
            )

        findings: list[dict] = []

        # Reverse-WHOIS — ownership. Highest confidence; one finding per domain.
        for wd in outcome.whois_domains:
            findings.append({
                "platform": "netlas",
                "source": "netlas",
                "confidence": "high",
                "severity": "medium",
                "grade": "public source",
                "metadata": {
                    "source": "netlas",
                    "netlas_signal": "reverse_whois",
                    "grade": "public source",
                    "registered_domain": wd.domain,
                    "whois_roles": list(wd.roles),
                    "summary": f"Registration contact on {wd.domain} ({', '.join(wd.roles) or 'contact'})",
                },
            })

        # Certificates — where the address is used in TLS.
        for cert in outcome.certs:
            findings.append({
                "platform": "netlas",
                "source": "netlas",
                "confidence": "medium",
                "severity": "low",
                "grade": "public source",
                "metadata": {
                    "source": "netlas",
                    "netlas_signal": "certificate",
                    "grade": "public source",
                    "certificate_names": list(cert.names),
                    "last_seen": cert.last_seen,
                    "summary": f"On a TLS certificate for {', '.join(cert.names[:3]) or 'a host'}",
                },
            })

        # Responses / FTP banners — public mentions, each with its source URL.
        for resp in outcome.responses:
            findings.append({
                "platform": "netlas",
                "source": "netlas",
                "confidence": "medium" if resp.protocol == "ftp" else "low",
                "severity": "low",
                "grade": "public source",
                "source_url": resp.source_url,
                # ``profile_url`` is the field the CSV/report columns read.
                "profile_url": resp.source_url,
                "metadata": {
                    "source": "netlas",
                    "netlas_signal": "ftp_banner" if resp.protocol == "ftp" else "response",
                    "grade": "public source",
                    "source_url": resp.source_url,
                    "protocol": resp.protocol,
                    "summary": f"Published at {resp.source_url}",
                },
            })

        n_resp = len(outcome.responses)
        n_cert = len(outcome.certs)
        n_whois = len(outcome.whois_domains)
        summary = (
            f"Netlas footprint: {n_whois} registered domain(s), "
            f"{n_cert} certificate(s), {n_resp} public response(s)"
        )
        metadata = {
            "source": "netlas",
            "grade": "public source",
            "netlas_status": outcome.overall_status(),
            "statuses": outcome.statuses,
            "calls": outcome.calls,
            "capped": outcome.capped,
            "reverse_whois_domains": [wd.domain for wd in outcome.whois_domains],
            "response_count": n_resp,
            "certificate_count": n_cert,
            "reverse_whois_count": n_whois,
            "total_appearances": outcome.total_appearances,
            "summary": summary,
        }
        # Marker: a clean keyed fetch starts the 30-day clock; a failed one does
        # not (retried next run). A deadline-truncated run still counts as long as
        # no source failed and at least one answered (results or a clean empty) —
        # otherwise a normal no-hit address with a slow certs lookup would re-spend
        # its calls on every repeat. Nothing answered at all → retry.
        truncated = list(getattr(outcome, "truncated", []) or [])
        metadata["netlas_fetched"] = fetch_answered(outcome.statuses)
        if truncated:
            metadata["netlas_partial"] = True
            metadata["netlas_truncated"] = truncated
            metadata["summary"] += f" (partial — deadline hit on: {', '.join(truncated)})"
        findings = merge_investigate(findings, stored)
        return ModuleResult(
            status=ModuleStatus.SUCCESS if findings else ModuleStatus.PARTIAL,
            findings=findings,
            metadata=metadata,
        )
