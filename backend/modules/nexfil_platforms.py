from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from ..config import settings
from ..core.http_client import build_client
from ..core.nexfil_loader import load_nexfil_sites
from ..core.platform_health import PlatformHealthDB, get_health_db
from ..core.sherlock_detector import probe_sherlock_site
from .base import BaseModule, ModuleResult, ModuleStatus

_WAVE1_CONCURRENCY = 80
_WAVE2_CONCURRENCY = 20
_FRAGILE_DEMOTE_THRESHOLD = 0.7


def _username_variants(email: str, defn: dict[str, Any] | None = None) -> list[str]:
    """Generate username variants and apply any per-site character stripping."""
    local = email.split("@", 1)[0]
    base_variants = [
        local,
        re.sub(r"[._-]+", "", local),
        re.sub(r"[.-]+", "_", local),
    ]
    variants = list(dict.fromkeys(value for value in base_variants if value))
    if defn and defn.get("strip_bad_char"):
        strip = str(defn["strip_bad_char"])
        stripped = [value.translate(str.maketrans("", "", strip)) for value in variants]
        variants = list(dict.fromkeys([*variants, *stripped]))
    return variants


def _wave(defn: dict[str, Any]) -> int:
    """Wave 1 is regular HTTP; wave 2 is slower JSON API probing."""
    return 2 if defn.get("error_type") == "api" else 1


def _confidence(defn: dict[str, Any]) -> str:
    """Nexfil single-marker status probes are weaker than content/API probes."""
    return "high" if defn.get("error_type") in ("message", "response_url", "api") else "medium"


def _finding(
    site_name: str,
    defn: dict[str, Any],
    username: str,
    profile_url: str,
    wave: int,
    email: str | None = None,
) -> dict[str, Any]:
    from ..core.common_names import is_common_username
    from ..core.disposable_domains import is_disposable_email

    category = defn.get("category", "")
    finding: dict[str, Any] = {
        "platform": f"nexfil:{site_name}",
        "profile_url": profile_url,
        "username": username,
        "confidence": _confidence(defn),
        "metadata": {
            "category": category,
            "tags": [category] if category else [],
            "error_type": str(defn.get("error_type") or "status_code"),
            "source": "nexfil",
            "wave": wave,
            "waf_protected": False,
        },
    }
    strip = defn.get("strip_bad_char")
    if strip:
        finding["metadata"]["strip_bad_char_applied"] = strip
    if is_common_username(username):
        finding["confidence"] = "low"
        finding["metadata"].setdefault("fp_warnings", []).append(
            "common_username_no_corroboration"
        )
    if is_disposable_email(email or username):
        finding["confidence"] = "low"
        finding["metadata"].setdefault("fp_warnings", []).append(
            "disposable_email_domain"
        )
    return finding


class NexfilPlatformsModule(BaseModule):
    name = "nexfil_platforms"
    description = (
        "Username enumeration across ~300 regional and forum-heavy platforms "
        "via a native Nexfil dataset port. Disable via ENABLE_NEXFIL_PLATFORMS=false."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_nexfil_platforms or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "nexfil_platforms disabled — set ENABLE_NEXFIL_PLATFORMS=true "
                    "to scan ~300 platforms (default behavior)"
                ],
            )

        include_wave2 = settings.enable_nexfil_wave2
        try:
            sites, load_meta = await load_nexfil_sites()
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Failed to load Nexfil platform database: {exc}"],
            )
        if not sites:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=["Nexfil site database is empty or failed to load"],
            )

        catch_all = await self._detect_catch_all(sites)
        health = get_health_db()
        wave1_queue: list[tuple[str, dict[str, Any], str]] = []
        wave2_queue: list[tuple[str, dict[str, Any], str]] = []
        queued: set[tuple[str, str]] = set()
        health_skipped = 0

        for site_name, defn in sites.items():
            if site_name in catch_all:
                continue
            platform_key = f"nexfil:{site_name}"
            if not await health.should_probe_async(platform_key):
                health_skipped += 1
                continue
            wave = _wave(defn)
            if health.get_fragility_score(platform_key) >= _FRAGILE_DEMOTE_THRESHOLD:
                wave = 2
            if wave == 2 and not include_wave2:
                continue
            for variant in _username_variants(email, defn):
                key = (site_name, variant)
                if key in queued:
                    continue
                queued.add(key)
                (wave1_queue if wave == 1 else wave2_queue).append((site_name, defn, variant))

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        misses = 0
        inconclusive = 0

        async with build_client(timeout=12.0) as client:
            wave1_results = await self._run_wave(client, wave1_queue, wave=1, health=health)
            wave2_results = (
                await self._run_wave(client, wave2_queue, wave=2, health=health)
                if include_wave2
                else []
            )

        seen_hits: set[tuple[str, str]] = set()
        for site_name, defn, variant, outcome, detail, wave in [
            *wave1_results,
            *wave2_results,
        ]:
            if outcome == "hit" and detail:
                key = (site_name, variant)
                if key not in seen_hits:
                    seen_hits.add(key)
                    findings.append(_finding(site_name, defn, variant, detail, wave, email=email))
            elif outcome == "miss":
                misses += 1
            elif outcome != "illegal":
                inconclusive += 1
                if detail and detail not in {"timeout", "waf_blocked"} and len(errors) < 50:
                    errors.append(f"{site_name}: {detail}")

        status = (
            ModuleStatus.PARTIAL
            if load_meta.get("partial") or inconclusive
            else ModuleStatus.SUCCESS
        )
        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                **load_meta,
                "total_platforms_checked": len(wave1_queue) + len(wave2_queue),
                "platforms_confirmed": len(findings),
                "platforms_not_found": misses,
                "platforms_inconclusive": inconclusive,
                "catch_all_skipped": len(catch_all),
                "health_skipped": health_skipped,
                "username_variants": _username_variants(email),
                "wave1_probes": len(wave1_queue),
                "wave2_probes": len(wave2_queue),
            },
            errors=errors,
        )

    async def _run_wave(
        self,
        client: Any,
        queue: list[tuple[str, dict[str, Any], str]],
        wave: int,
        health: PlatformHealthDB,
    ) -> list[tuple[str, dict[str, Any], str, str, str | None, int]]:
        sem = asyncio.Semaphore(_WAVE1_CONCURRENCY if wave == 1 else _WAVE2_CONCURRENCY)
        timeout = 6.0 if wave == 1 else 10.0

        async def _timed_probe(
            site_name: str, defn: dict[str, Any], username: str
        ) -> tuple[str, str | None]:
            started = time.perf_counter()
            outcome, detail = await probe_sherlock_site(
                client, sem, site_name, defn, username, timeout=timeout
            )
            latency_ms = int((time.perf_counter() - started) * 1000)
            try:
                await health.record_probe_async(
                    platform=f"nexfil:{site_name}",
                    domain=None,
                    outcome=outcome if outcome != "illegal" else "miss",
                    latency_ms=latency_ms,
                    content_length=len(detail) if isinstance(detail, str) else 0,
                )
            except Exception:
                pass
            return outcome, detail

        tasks = [_timed_probe(name, defn, username) for name, defn, username in queue]
        results = await asyncio.gather(*tasks)
        return [
            (name, defn, username, outcome, detail, wave)
            for (name, defn, username), (outcome, detail) in zip(queue, results)
        ]

    async def _detect_catch_all(self, sites: dict[str, dict[str, Any]]) -> set[str]:
        """Identify a bounded sample of status-only sites that accept any username."""
        probe_username = f"__nexfil_ca_{int(time.time())}_noclash__"
        candidates = [
            (name, defn)
            for name, defn in sites.items()
            if str(defn.get("error_type") or "status_code") == "status_code"
        ][:40]
        sem = asyncio.Semaphore(20)
        async with build_client(timeout=6.0) as client:
            tasks = [
                probe_sherlock_site(client, sem, name, defn, probe_username, timeout=6.0)
                for name, defn in candidates
            ]
            results = await asyncio.gather(*tasks)
        return {
            name
            for (name, _defn), (outcome, _detail) in zip(candidates, results)
            if outcome == "hit"
        }
