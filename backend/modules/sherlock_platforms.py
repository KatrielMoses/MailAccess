from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from ..config import settings
from ..core.http_client import build_client
from ..core.platform_health import PlatformHealthDB, get_health_db
from ..core.sherlock_detector import probe_sherlock_site
from ..core.sherlock_loader import load_sherlock_sites
from .base import BaseModule, ModuleResult, ModuleStatus

_FALLBACK_FRAGILITY_DEMOTION_THRESHOLD = 0.7

_WAVE1_CONCURRENCY = 80
_WAVE2_CONCURRENCY = 30


def _tags(defn: dict[str, Any]) -> list[str]:
    cat = defn.get("category", "")
    return [cat] if cat else []


def _username_variants(email: str) -> list[str]:
    local = email.split("@", 1)[0]
    variants = [
        local,
        re.sub(r"[._-]+", "", local),
        re.sub(r"[.-]+", "_", local),
    ]
    return list(dict.fromkeys(v for v in variants if v))


def _wave(defn: dict[str, Any]) -> int:
    error_type = str(defn.get("error_type") or "status_code")
    return 1 if error_type == "status_code" else 2


def _confidence(defn: dict[str, Any]) -> str:
    error_type = str(defn.get("error_type") or "status_code")
    return "medium" if error_type == "status_code" else "high"


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

    tags = _tags(defn)
    finding: dict[str, Any] = {
        "platform": f"sherlock:{site_name}",
        "profile_url": profile_url,
        "username": username,
        "confidence": _confidence(defn),
        "metadata": {
            "category": tags[0] if tags else "",
            "tags": tags,
            "error_type": str(defn.get("error_type") or "status_code"),
            "source": "sherlock",
            "wave": wave,
            "waf_protected": False,
            "dual_confirmed": False,
        },
    }
    if is_common_username(username):
        if finding["confidence"] != "low":
            finding["confidence"] = "low"
        finding["metadata"].setdefault("fp_warnings", []).append("common_username_no_corroboration")
    if is_disposable_email(email or username):
        if finding["confidence"] != "low":
            finding["confidence"] = "low"
        finding["metadata"].setdefault("fp_warnings", []).append("disposable_email_domain")
    return finding


class SherlockPlatformsModule(BaseModule):
    name = "sherlock_platforms"
    description = (
        "Username enumeration across ~400 platforms via the Sherlock dataset "
        "(natively ported, no upstream dependency). "
        "Disable via ENABLE_SHERLOCK_PLATFORMS=false."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_sherlock_platforms or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "sherlock_platforms disabled — set ENABLE_SHERLOCK_PLATFORMS=true "
                    "to scan ~400 platforms (default behavior)"
                ],
            )

        include_wave2 = settings.enable_sherlock_wave2
        try:
            sites, load_meta = await load_sherlock_sites()
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Failed to load Sherlock platform database: {exc}"],
            )

        if not sites:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=["Sherlock site database is empty or failed to load"],
            )

        variants = _username_variants(email)
        catch_all = await self._detect_catch_all(sites)

        health = get_health_db()
        wave1_queue: list[tuple[str, dict[str, Any], str]] = []
        wave2_queue: list[tuple[str, dict[str, Any], str]] = []
        queued: set[tuple[str, str]] = set()
        health_skipped = 0

        for site_name, defn in sites.items():
            if site_name in catch_all:
                continue
            if not await health.should_probe_async(f"sherlock:{site_name}"):
                health_skipped += 1
                continue
            wave = _wave(defn)
            fragile = (
                health.get_fragility_score(f"sherlock:{site_name}")
                >= _FALLBACK_FRAGILITY_DEMOTION_THRESHOLD
            )
            if wave == 1 and fragile:
                wave = 2
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
                findings.append(_finding(site_name, defn, variant, detail, wave, email=email))
            elif outcome == "miss":
                misses += 1
            elif outcome == "illegal":
                pass
            else:
                inconclusive += 1
                if detail and detail not in {"timeout", "waf_blocked"} and len(errors) < 50:
                    errors.append(f"{site_name}: {detail}")

        status = ModuleStatus.SUCCESS
        if load_meta.get("partial") or inconclusive:
            status = ModuleStatus.PARTIAL
        if not findings and inconclusive and not misses:
            status = ModuleStatus.FAILED

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
        sem = asyncio.Semaphore(_WAVE1_CONCURRENCY if wave == 1 else _WAVE2_CONCURRENCY)
        timeout = 6.0 if wave == 1 else 10.0

        async def _timed_probe(
            site_name: str, defn: dict[str, Any], username: str
        ) -> tuple[str, str | None]:
            t0 = time.perf_counter()
            outcome, detail = await probe_sherlock_site(
                client, sem, site_name, defn, username, timeout=timeout
            )
            latency_ms = int((time.perf_counter() - t0) * 1000)
            try:
                await health.record_probe_async(
                    platform=f"sherlock:{site_name}",
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
        """Identify sites that return 200 for any username (catch-all detection)."""
        probe_username = f"__sherlock_ca_{int(time.time())}_noclash__"
        candidates = [
            (name, defn)
            for name, defn in sites.items()
            if str(defn.get("error_type") or "status_code") == "status_code"
        ]
        candidates = candidates[:40]
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
