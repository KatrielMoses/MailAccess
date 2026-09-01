from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Any

from ..config import settings
from ..core.breach_corpus import BreachCorpus, BreachSite
from ..core.http_client import build_client
from ..core.platform_executor import PlatformExecutor
from ..core.platform_loader import PlatformLoader
from ..core.reset_prober import probe as reset_probe
from ..platforms.schema import PlatformCheck
from .base import BaseModule, ModuleResult, ModuleStatus

_CONCURRENCY = 30
_CHECK_TIMEOUT_SECONDS = 8.0

_YAML_DOMAIN_TO_SLUG = {
    "adobe.com": "adobe",
    "spotify.com": "spotify",
    "dropbox.com": "dropbox",
    "github.com": "github",
    "discord.com": "discord",
    "discordapp.com": "discord",
    "linkedin.com": "linkedin",
    "zoom.us": "zoom",
    "skype.com": "skype_microsoft",
    "apple.com": "apple",
    "patreon.com": "patreon",
}


def _format_site_metadata(site: BreachSite, method: str) -> dict[str, Any]:
    return {
        "breach_name": site.breach_name,
        "breach_date": site.breach_date,
        "pwn_count": site.pwn_count,
        "data_classes": site.data_classes,
        "severity_score": site.severity_score,
        "severity_label": site.severity_label,
        "probe_method": method,
        "implication": (
            "Credentials from this account may be in publicly available breach datasets"
        ),
    }


def _finding(site: BreachSite, method: str) -> dict[str, Any]:
    return {
        "platform": site.domain,
        "url": f"https://{site.domain}",
        "confidence": "high" if method == "yaml" else "medium",
        "severity": site.severity_label,
        "metadata": _format_site_metadata(site, method),
        "source": "breach_deep",
    }


class BreachDeepModule(BaseModule):
    name = "breach_deep"
    description = "Probe account existence on the highest-severity breached websites from HIBP."
    requires_key = False

    async def run(self, email: str, *, force: bool = False) -> ModuleResult:
        if not force and not settings.enable_breach_deep:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_BREACH_DEEP=true or run with --modules breach_deep"],
            )

        corpus = BreachCorpus()
        try:
            if settings.breach_deep_full:
                sites = await asyncio.to_thread(corpus.get_all)
            else:
                sites = await asyncio.to_thread(corpus.get_top, max(settings.breach_deep_limit, 0))
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"breach corpus load failed: {exc}"],
            )

        sites = [site for site in sites if site.domain]
        if not settings.breach_deep_full:
            sites = sites[: max(settings.breach_deep_limit, 0)]

        platforms_by_slug = {platform.slug: platform for platform in PlatformLoader().load_all()}
        executor = PlatformExecutor()
        semaphore = asyncio.Semaphore(_CONCURRENCY)

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        checked = 0
        inconclusive = 0
        not_found = 0

        # scrapingant: keep for mixed profile/account-existence probes with anti-bot variance
        async with build_client(
            scrapingant_zone="platforms", timeout=10.0, follow_redirects=False
        ) as client:

            async def check_site(site: BreachSite) -> tuple[str, dict[str, Any] | None, str | None]:
                nonlocal checked
                async with semaphore:
                    checked += 1
                    slug = _YAML_DOMAIN_TO_SLUG.get(site.domain)
                    platform: PlatformCheck | None = platforms_by_slug.get(slug) if slug else None
                    try:
                        if platform is not None:
                            result = await asyncio.wait_for(
                                executor.check(platform, email, client),
                                timeout=_CHECK_TIMEOUT_SECONDS,
                            )
                            if isinstance(result, dict):
                                if result.get("rate_limited"):
                                    return ("inconclusive", None, None)
                                if result.get("error"):
                                    return ("error", None, str(result["error"]))
                                if result.get("platform") or result.get("findings"):
                                    return ("found", _finding(site, "yaml"), None)
                            return ("not_found", None, None)

                        exists = await asyncio.wait_for(
                            reset_probe(site.domain, email, client),
                            timeout=_CHECK_TIMEOUT_SECONDS,
                        )
                        if exists is True:
                            return ("found", _finding(site, "generic_reset"), None)
                        if exists is False:
                            return ("not_found", None, None)
                        return ("inconclusive", None, None)
                    except asyncio.TimeoutError:
                        return ("inconclusive", None, None)
                    except Exception as exc:
                        return ("error", None, f"{site.domain}: {exc}")

            results = await asyncio.gather(
                *(check_site(site) for site in sites),
                return_exceptions=True,
            )

        for result in results:
            if isinstance(result, Exception):
                errors.append(str(result))
                continue
            status, finding, error = result
            if status == "found" and finding is not None:
                findings.append(finding)
            elif status == "not_found":
                not_found += 1
            elif status == "inconclusive":
                inconclusive += 1
            elif error:
                errors.append(error)

        findings.sort(
            key=lambda f: (
                f.get("metadata", {}).get("severity_score", 0),
                f.get("metadata", {}).get("pwn_count", 0),
                f.get("platform", ""),
            ),
            reverse=True,
        )

        critical_hits = sum(1 for f in findings if f.get("severity") == "critical")
        high_hits = sum(1 for f in findings if f.get("severity") == "high")
        total_records = sum(int(f.get("metadata", {}).get("pwn_count") or 0) for f in findings)
        top_breach = findings[0].get("metadata", {}).get("breach_name") if findings else None

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL if findings or checked > 0 else ModuleStatus.FAILED

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "sites_checked": checked,
                "sites_confirmed": len(findings),
                "sites_inconclusive": inconclusive,
                "sites_not_found": not_found,
                "critical_hits": critical_hits,
                "high_hits": high_hits,
                "total_records_potentially_exposed": total_records,
                "top_breach": top_breach,
                "corpus_size": len(corpus.get_all()),
                "sites": [asdict(site) for site in sites],
            },
            errors=errors,
        )
