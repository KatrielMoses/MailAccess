from __future__ import annotations

import asyncio
import re
from typing import Any

from ..config import settings
from ..core.http_client import build_client
from ..core.maigret_detector import probe_platform, username_matches_regex
from ..core.maigret_loader import load_maigret_sites
from .base import BaseModule, ModuleResult, ModuleStatus

_WAVE1_CONCURRENCY = 100
_WAVE2_CONCURRENCY = 40


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
    if str(defn.get("checkType") or "status_code") == "status_code" and not defn.get("presenseStrs"):
        return "medium"
    return "high"


def _finding(name: str, defn: dict[str, Any], username: str, profile_url: str, wave: int) -> dict[str, Any]:
    tags = _tags(defn)
    return {
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


class MaigretPlatformsModule(BaseModule):
    name = "maigret_platforms"
    description = (
        "Username enumeration across 2500+ platforms via the Maigret platform database. "
        "Enable via ENABLE_MAIGRET_PLATFORMS=true."
    )
    requires_key = False
    default_enabled = False

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_maigret_platforms or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "Set ENABLE_MAIGRET_PLATFORMS=true or run with --modules "
                    "maigret_platforms to enable. Checks 2500+ additional platforms."
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

        wave1_queue: list[tuple[str, dict[str, Any], str]] = []
        wave2_queue: list[tuple[str, dict[str, Any], str]] = []
        queued: set[tuple[str, str]] = set()
        regex_skipped = 0

        for name, defn in sites.items():
            if name in catch_all:
                continue
            wave = _wave(defn)
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

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        misses = 0
        inconclusive = 0

        async with build_client(timeout=12.0) as client:
            wave1 = await self._run_wave(client, wave1_queue, wave=1)
            wave2 = await self._run_wave(client, wave2_queue, wave=2) if include_wave2 else []

        seen_hits: set[tuple[str, str]] = set()
        for name, defn, variant, outcome, detail, wave in [*wave1, *wave2]:
            if outcome == "hit" and detail:
                key = (name, variant)
                if key in seen_hits:
                    continue
                seen_hits.add(key)
                findings.append(_finding(name, defn, variant, detail, wave))
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
                "username_variants": variants,
                "wave1_probes": len(wave1_queue),
                "wave2_probes": len(wave2_queue),
            },
            errors=errors,
        )

    async def _run_wave(
        self,
        client,
        queue: list[tuple[str, dict[str, Any], str]],
        wave: int,
    ) -> list[tuple[str, dict[str, Any], str, str, str | None, int]]:
        sem = asyncio.Semaphore(_WAVE1_CONCURRENCY if wave == 1 else _WAVE2_CONCURRENCY)
        timeout = 6.0 if wave == 1 else 10.0
        tasks = [
            probe_platform(client, sem, name, defn, username, timeout=timeout)
            for name, defn, username in queue
        ]
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
