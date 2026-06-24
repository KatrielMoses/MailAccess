from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from typing import Any

from ..config import settings
from ..core.demotion_log import env_var_key_for
from ..core.demotion_log import log_event as log_demotion_event
from ..core.http_client import build_client
from ..core.maigret_detector import probe_platform, username_matches_regex
from ..core.maigret_loader import load_maigret_sites
from ..core.platform_health import PlatformHealthDB, get_health_db
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_FALLBACK_FRAGILITY_DEMOTION_THRESHOLD = 0.7

_WAVE1_CONCURRENCY = 100
_WAVE2_CONCURRENCY = 40


def _is_forced(platform: str) -> bool:
    """Return True if the user explicitly forces this platform via env var.

    Mapping rule: ``"NoisySite.com"`` → ``MAIGRET_FORCE_NOISYSITECOM=true``.
    Any truthy value counts; the test suite pins to ``"true"``.
    """
    key = env_var_key_for(platform)
    value = os.environ.get(key, "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _alexa_rank(defn: dict[str, Any]) -> int | None:
    value = defn.get("alexaRank", defn.get("alexa_rank"))
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tags(defn: dict[str, Any]) -> list[str]:
    raw = defn.get("tags")
    if isinstance(raw, list):
        return [str(tag) for tag in raw if str(tag)]
    return []


def _username_variants(email: str) -> list[str]:
    local = email.split("@", 1)[0]
    variants = [
        local,
        re.sub(r"[._-]+", "", local),
        re.sub(r"[.-]+", "_", local),
    ]
    return list(dict.fromkeys(v for v in variants if v))


def _is_regional_fragile(defn: dict[str, Any]) -> bool:
    tags = {tag.lower() for tag in _tags(defn)}
    return bool(tags & {"cn", "ru", "china", "russia"})


def _wave(defn: dict[str, Any]) -> int:
    check_type = str(defn.get("checkType") or "status_code")
    rank = _alexa_rank(defn)
    if (
        check_type == "status_code"
        and not defn.get("protection")
        and not _is_regional_fragile(defn)
        and (rank is None or rank < 50_000)
    ):
        return 1
    return 2


def _confidence(defn: dict[str, Any]) -> str:
    if defn.get("similarSearch") or defn.get("protection"):
        return "low"
    if (
        str(defn.get("checkType") or "status_code") == "status_code"
        and not defn.get("presenseStrs")
    ):
        return "medium"
    return "high"


def _finding(
    name: str,
    defn: dict[str, Any],
    username: str,
    profile_url: str,
    wave: int,
    email: str | None = None,
) -> dict[str, Any]:
    from ..core.common_names import is_common_username
    from ..core.disposable_domains import is_disposable_email

    tags = _tags(defn)
    finding = {
        "platform": name,
        "profile_url": profile_url,
        "username": username,
        "confidence": _confidence(defn),
        "metadata": {
            "category": tags[0] if tags else "",
            "tags": tags,
            "check_type": str(defn.get("checkType") or "status_code"),
            "source": "maigret",
            "wave": wave,
            "alexa_rank": _alexa_rank(defn),
            "dual_confirmed": False,
        },
    }
    if is_common_username(username):
        if finding["confidence"] != "low":
            finding["confidence"] = "low"
        finding["metadata"].setdefault("fp_warnings", []).append(
            "common_username_no_corroboration"
        )
    if is_disposable_email(email or username):
        if finding["confidence"] != "low":
            finding["confidence"] = "low"
        finding["metadata"].setdefault("fp_warnings", []).append(
            "disposable_email_domain"
        )
    return finding


class MaigretPlatformsModule(BaseModule):
    name = "maigret_platforms"
    description = (
        "Username enumeration across 2500+ platforms via the Maigret platform database. "
        "Disable via ENABLE_MAIGRET_PLATFORMS=false."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_maigret_platforms or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "maigret_platforms disabled \u2014 set ENABLE_MAIGRET_PLATFORMS=true "
                    "to scan 2500+ platforms (default behavior)"
                ],
            )

        include_wave2 = settings.enable_maigret_wave2
        try:
            sites, load_meta = await load_maigret_sites(include_wave2=include_wave2)
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Failed to load Maigret platform database: {exc}"],
            )

        variants = _username_variants(email)
        catch_all = await self._detect_catch_all(sites)

        health = get_health_db()

        # ── Phase 6D auto-demotion / auto-upgrade ─────────────────────────────
        # Wave classification has to happen before skip/demote/upgrade so that
        # `get_demote_set` and `get_upgrade_set` know which wave each platform
        # is currently in.  We compute the wave for every loaded site here and
        # pass the wave-1/wave-2 name sets into the health DB queries.
        wave_for_site: dict[str, int] = {name: _wave(defn) for name, defn in sites.items()}
        wave1_names = {name for name, wave in wave_for_site.items() if wave == 1}
        wave2_names = {name for name, wave in wave_for_site.items() if wave == 2}

        raw_skip_set = health.get_skip_set()
        raw_demote_set = health.get_demote_set(wave1_names=wave1_names)
        raw_upgrade_set = health.get_upgrade_set(wave2_names=wave2_names)

        # Env-var overrides win. If the user sets MAIGRET_FORCE_<KEY>=true,
        # the platform runs in its native wave regardless of health stats.
        skip_set: set[str] = {n for n in raw_skip_set if not _is_forced(n)}
        demote_set: set[str] = {n for n in raw_demote_set if not _is_forced(n)}
        upgrade_set: set[str] = {n for n in raw_upgrade_set if not _is_forced(n)}

        # Track actions we actually applied (after the override filter) so we
        # can surface counts in metadata and write a single audit-log entry per
        # platform affected by this investigation.
        applied_skip: set[str] = set()
        applied_demote: set[str] = set()
        applied_upgrade: set[str] = set()

        wave1_queue: list[tuple[str, dict[str, Any], str]] = []
        wave2_queue: list[tuple[str, dict[str, Any], str]] = []
        queued: set[tuple[str, str]] = set()
        regex_skipped = 0
        health_skipped = 0

        for name, defn in sites.items():
            if name in catch_all:
                continue
            if not await health.should_probe_async(name):
                health_skipped += 1
                continue
            if name in skip_set:
                applied_skip.add(name)
                continue
            wave = wave_for_site.get(name, _wave(defn))
            # 6D.2 — auto-upgrade: Wave-2 platform with strong stats → Wave 1
            if name in upgrade_set and wave == 2:
                wave = 1
                applied_upgrade.add(name)
            # 6D.1 — auto-demote: Wave-1 platform with high noise → Wave 2
            elif name in demote_set and wave == 1:
                wave = 2
                applied_demote.add(name)
            # Demote fragile wave-1 platforms to wave-2 rather than skipping them entirely
            fragile = health.get_fragility_score(name) >= _FALLBACK_FRAGILITY_DEMOTION_THRESHOLD
            if wave == 1 and fragile:
                wave = 2
            if wave == 2 and not include_wave2:
                continue
            for variant in variants:
                key = (name, variant)
                if key in queued:
                    continue
                queued.add(key)
                if not username_matches_regex(defn, variant):
                    regex_skipped += 1
                    continue
                (wave1_queue if wave == 1 else wave2_queue).append((name, defn, variant))

        # ── Write one audit-log entry per applied action ──────────────────────
        # Stats are computed from the rolling window. We log AFTER queueing so
        # the log captures the same numbers the skip/demote decision used.
        def _record(name: str, action: str) -> None:
            stats = health.get_stats(name)
            total = int(stats.get("total_probes") or 0)
            inconclusive = int(stats.get("inconclusive") or 0)
            inconclusive_rate = (inconclusive / total) if total else 0.0
            hit_rate = float(stats.get("hit_rate") or 0.0)
            log_demotion_event(
                platform=name,
                action=action,
                stats={
                    "inconclusive_rate": round(inconclusive_rate, 3),
                    "hit_rate": round(hit_rate, 3),
                    "total_probes": total,
                },
                reason=f"inconclusive_rate={inconclusive_rate:.2f}, probes={total}",
                reversible_via=env_var_key_for(name),
            )

        for name in applied_skip:
            _record(name, "skip")
        for name in applied_demote:
            _record(name, "demote")
        for name in applied_upgrade:
            _record(name, "upgrade")

        health_tracked = len({name for name, _, _ in [*wave1_queue, *wave2_queue]})
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
        for name, defn, variant, outcome, detail, wave in [*wave1, *wave2]:
            if outcome == "hit" and detail:
                key = (name, variant)
                if key in seen_hits:
                    continue
                seen_hits.add(key)
                findings.append(_finding(name, defn, variant, detail, wave, email=email))
            elif outcome == "miss":
                misses += 1
            else:
                inconclusive += 1
                if detail and detail not in {"timeout", "regex_rejected"} and len(errors) < 50:
                    errors.append(f"{name}: {detail}")

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
                "regex_skipped": regex_skipped,
                "health_skipped": health_skipped,
                "health_tracked": health_tracked,
                "username_variants": variants,
                "wave1_probes": len(wave1_queue),
                "wave2_probes": len(wave2_queue),
                "auto_demoted_skipped": len(applied_skip),
                "auto_demoted_to_wave2": len(applied_demote),
                "auto_upgraded_to_wave1": len(applied_upgrade),
                "auto_demotion_overrides": {
                    name: env_var_key_for(name)
                    for name in (applied_skip | applied_demote | applied_upgrade)
                },
            },
            errors=errors,
        )

    async def _run_wave(
        self,
        client,
        queue: list[tuple[str, dict[str, Any], str]],
        wave: int,
        health: PlatformHealthDB,
    ) -> list[tuple[str, dict[str, Any], str, str, str | None, int]]:
        sem = asyncio.Semaphore(_WAVE1_CONCURRENCY if wave == 1 else _WAVE2_CONCURRENCY)
        timeout = 6.0 if wave == 1 else 10.0

        async def _timed_probe(
            name: str, defn: dict[str, Any], username: str
        ) -> tuple[str, str | None]:
            t0 = time.perf_counter()
            outcome, detail = await probe_platform(
                client, sem, name, defn, username, timeout=timeout
            )
            latency_ms = int((time.perf_counter() - t0) * 1000)
            try:
                await health.record_probe_async(
                    platform=name,
                    domain=None,
                    outcome=outcome,
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
        candidates = [
            (name, defn)
            for name, defn in sites.items()
            if str(defn.get("checkType") or "status_code") == "status_code"
            and defn.get("usernameUnclaimed")
        ]
        candidates.sort(key=lambda item: _alexa_rank(item[1]) or 10**9)
        candidates = candidates[:50]
        sem = asyncio.Semaphore(20)
        async with build_client(timeout=6.0) as client:
            tasks = [
                probe_platform(
                    client,
                    sem,
                    name,
                    defn,
                    str(defn.get("usernameUnclaimed")),
                    timeout=6.0,
                )
                for name, defn in candidates
            ]
            results = await asyncio.gather(*tasks)
        return {
            name
            for (name, _defn), (outcome, _detail) in zip(candidates, results)
            if outcome == "hit"
        }
