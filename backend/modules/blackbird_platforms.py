from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from ..config import settings
from ..core.blackbird_detector import probe_blackbird_site
from ..core.blackbird_loader import load_blackbird_sites
from ..core.http_client import build_client
from ..core.platform_health import PlatformHealthDB, get_health_db
from .base import BaseModule, ModuleResult, ModuleStatus

_WAVE1_CONCURRENCY = 60
_WAVE2_CONCURRENCY = 20
_FRAGILE_DEMOTE_THRESHOLD = 0.7


def _username_variants(email: str) -> list[str]:
    local = email.split("@", 1)[0]
    variants = [
        local,
        re.sub(r"[._-]+", "", local),
        re.sub(r"[.-]+", "_", local),
    ]
    return list(dict.fromkeys(variant for variant in variants if variant))


def _wave(defn: dict[str, Any]) -> int:
    """Wave 1 = GET requests (fast), Wave 2 = POST requests (slower APIs)."""
    return 2 if defn.get("post_body") else 1


def _is_waf_protected(defn: dict[str, Any]) -> bool:
    protection = defn.get("protection") or []
    if isinstance(protection, str):
        protection = [protection]
    return any(str(item).lower() == "cloudflare" for item in protection)


def _finding(
    site_name: str,
    defn: dict[str, Any],
    username: str,
    profile_url: str,
    wave: int,
    email: str,
) -> dict[str, Any]:
    from ..core.common_names import is_common_username
    from ..core.disposable_domains import is_disposable_email

    category = str(defn.get("cat") or "")
    finding: dict[str, Any] = {
        "platform": f"blackbird:{site_name}",
        "profile_url": profile_url,
        "username": username,
        "confidence": "high",
        "metadata": {
            "source": "blackbird",
            "category": category,
            "tags": [category] if category else [],
            "wave": wave,
            "method": "POST" if defn.get("post_body") else "GET",
            "waf_protected": _is_waf_protected(defn),
            "e_code": defn.get("e_code"),
            "m_code": defn.get("m_code"),
            "strip_bad_char_applied": defn.get("strip_bad_char") or None,
        },
    }
    if is_common_username(username):
        finding["confidence"] = "low"
        finding["metadata"].setdefault("fp_warnings", []).append(
            "common_username_no_corroboration"
        )
    if is_disposable_email(email):
        finding["confidence"] = "low"
        finding["metadata"].setdefault("fp_warnings", []).append(
            "disposable_email_domain"
        )
    return finding


class BlackbirdPlatformsModule(BaseModule):
    name = "blackbird_platforms"
    description = (
        "Username enumeration across ~700 platforms using the WhatsMyName dataset "
        "and native two-marker detection (no Blackbird dependency)."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_blackbird_platforms or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "blackbird_platforms disabled — set ENABLE_BLACKBIRD_PLATFORMS=true "
                    "to scan WhatsMyName platforms"
                ],
            )

        include_wave2 = settings.enable_blackbird_wave2
        include_nsfw = settings.enable_blackbird_nsfw
        try:
            sites, load_meta = await load_blackbird_sites()
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Failed to load WhatsMyName platform database: {exc}"],
            )

        if not sites:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=["WhatsMyName site database is empty or failed to load"],
            )

        variants = _username_variants(email)
        health = get_health_db()
        wave1_queue: list[tuple[str, dict[str, Any], str]] = []
        wave2_queue: list[tuple[str, dict[str, Any], str]] = []
        queued: set[tuple[str, str]] = set()
        health_skipped = 0
        nsfw_skipped = 0
        fragile_demoted = 0

        for site_name, defn in sites.items():
            if defn.get("cat") == "xx NSFW xx" and not include_nsfw:
                nsfw_skipped += 1
                continue
            health_key = f"blackbird:{site_name}"
            if not await health.should_probe_async(health_key):
                health_skipped += 1
                continue
            wave = _wave(defn)
            if (
                wave == 1
                and health.get_fragility_score(health_key) >= _FRAGILE_DEMOTE_THRESHOLD
            ):
                wave = 2
                fragile_demoted += 1
            if wave == 2 and not include_wave2:
                continue
            for variant in variants:
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
            wave1 = await self._run_wave(client, wave1_queue, wave=1, health=health)
            wave2 = (
                await self._run_wave(client, wave2_queue, wave=2, health=health)
                if include_wave2
                else []
            )

        seen_hits: set[tuple[str, str]] = set()
        for site_name, defn, variant, outcome, detail, wave in [*wave1, *wave2]:
            if outcome == "hit" and detail:
                key = (site_name, variant)
                if key in seen_hits:
                    continue
                seen_hits.add(key)
                findings.append(_finding(site_name, defn, variant, detail, wave, email))
            elif outcome == "miss":
                misses += 1
            elif outcome != "illegal":
                inconclusive += 1
                if detail and detail not in {"timeout", "waf_blocked"} and len(errors) < 50:
                    errors.append(f"{site_name}: {detail}")

        all_inconclusive = not findings and inconclusive > 0 and misses == 0
        if all_inconclusive:
            errors.insert(0, "all sources errored")
        if load_meta.get("partial"):
            status = ModuleStatus.PARTIAL
        elif findings:
            status = ModuleStatus.SUCCESS
        elif inconclusive:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                **load_meta,
                "total_platforms_checked": len(wave1_queue) + len(wave2_queue),
                "platforms_confirmed": len(findings),
                "platforms_not_found": misses,
                "platforms_inconclusive": inconclusive,
                "health_skipped": health_skipped,
                "nsfw_skipped": nsfw_skipped,
                "fragile_demoted": fragile_demoted,
                "username_variants": variants,
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
        configured = getattr(settings, "blackbird_concurrency", _WAVE1_CONCURRENCY)
        wave1_concurrency = (
            configured
            if isinstance(configured, int) and configured > 0
            else _WAVE1_CONCURRENCY
        )
        sem = asyncio.Semaphore(wave1_concurrency if wave == 1 else _WAVE2_CONCURRENCY)
        timeout = 6.0 if wave == 1 else 10.0

        async def _timed_probe(
            site_name: str, defn: dict[str, Any], username: str
        ) -> tuple[str, str | None]:
            started = time.perf_counter()
            outcome, detail = await probe_blackbird_site(
                client, sem, site_name, defn, username, timeout=timeout
            )
            latency_ms = int((time.perf_counter() - started) * 1000)
            try:
                await health.record_probe_async(
                    platform=f"blackbird:{site_name}",
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
