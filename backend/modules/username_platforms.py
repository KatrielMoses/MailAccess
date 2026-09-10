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
from ..core.platform_health import PlatformHealthDB, get_health_db
from ..core.probe_detector import probe_platform, username_matches_regex
from ..core.username_sites import load_username_sites
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_FALLBACK_FRAGILITY_DEMOTION_THRESHOLD = 0.7

_WAVE1_CONCURRENCY = 100
_WAVE2_CONCURRENCY = 40


def _is_forced(platform: str) -> bool:
    """Return True if the user explicitly forces this platform via env var.

    Mapping rule: ``"NoisySite.com"`` → ``USERNAME_FORCE_NOISYSITECOM=true``. Any
    truthy value counts; the test suite pins to ``"true"``.
    """
    value = os.environ.get(env_var_key_for(platform), "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _alexa_rank(defn: dict[str, Any]) -> int | None:
    value = defn.get("alexaRank", defn.get("alexa_rank"))
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_high_precision(defn: dict[str, Any]) -> bool:
    """Is a localpart probe against this platform HIGH-PRECISION?

    T1 (Output-Trust final): the username sweep is seeded from a speculative
    localpart guess, so we only probe platforms whose result is meaningful — either
    the site is popularity-ranked (a real major) OR its probe contract genuinely
    discriminates on the username: two-marker presence+absence strings, a regex
    check, or distinct existence-vs-miss HTTP codes. The excluded remainder is the
    unranked, bare ``status_code`` long tail whose soft-200 for any string is the
    false-positive source RC1 documented. ``alexaRank`` alone can't select this set
    (it is too sparse — GitHub/YouTube are unranked yet clearly majors), which is why
    the discriminating-contract signals are OR-ed in.
    """
    if _alexa_rank(defn) is not None:
        return True
    has_two_marker = bool(
        defn.get("presenseStrs") or defn.get("presence_strs")
    ) and bool(defn.get("absenceStrs") or defn.get("absence_strs"))
    has_regex = bool(defn.get("regexCheck") or defn.get("regex_check"))
    has_distinct_codes = bool(defn.get("e_code")) and bool(defn.get("m_code"))
    return has_two_marker or has_regex or has_distinct_codes


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
    """Assign a probe wave by popularity + reliability, not by detection method.

    Wave 1 is the default, high-signal cut; Wave 2 is opt-in long tail. The gate used to
    require ``checkType == "status_code"``, which stranded every higher-signal ``message`` /
    ``response_url`` platform (tiktok / youtube / telegram / …) in the opt-in Wave 2 even when
    it was a top-ranked major — only the ``status_code`` sites survived by default. Wave
    membership now keys on rank/reliability so popular platforms probe by default regardless of
    how their existence marker is read:

    * protected / regionally-fragile sites are always held for Wave 2 (fast high-concurrency
      probing is unreliable there);
    * a well-ranked site (``alexaRank < 50k``) is Wave 1 for *any* detection method — this is
      what pulls the message/response_url majors back into the default run;
    * cheap ``status_code`` existence checks stay Wave 1 (the safe corpus backbone), while the
      unranked ``message`` / ``response_url`` long tail stays Wave 2.
    """
    if defn.get("protection") or _is_regional_fragile(defn):
        return 2
    rank = _alexa_rank(defn)
    if rank is not None and rank < 50_000:
        return 1
    check_type = str(defn.get("checkType") or "status_code")
    if check_type == "status_code":
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
    profile: dict[str, str] | None = None,
) -> dict[str, Any]:
    from ..core.common_names import is_common_username
    from ..core.disposable_domains import is_disposable_email

    tags = _tags(defn)
    # RC1 (Output-Trust): every username_platforms hit probes a SPECULATIVE variant
    # of the email localpart (not a confirmed handle), so on its own it is UNVERIFIED
    # — an account with a similar handle may belong to someone else entirely. The
    # site's detection method (``_confidence``) says how reliably we detected the
    # handle EXISTS, not that it is the subject's account; keep it as
    # ``detection_confidence`` but cap the finding's account-is-subject
    # ``confidence`` to LOW until an independent signal corroborates it (platform_dedup
    # upgrades a dual-confirmed hit to high/confirmed). This is what stops a
    # localpart guess (roll-number, noreply@, user@nonexistent) from producing a
    # large HIGH-confidence account list.
    detection_confidence = _confidence(defn)
    finding = {
        "platform": name,
        "profile_url": profile_url,
        "username": username,
        "confidence": "low",
        "metadata": {
            "category": tags[0] if tags else "",
            "tags": tags,
            "check_type": str(defn.get("checkType") or "status_code"),
            "source": "username_platforms",
            "wave": wave,
            "alexa_rank": _alexa_rank(defn),
            "dual_confirmed": False,
            "verification": "unverified",
            "speculative": True,
            "detection_confidence": detection_confidence,
        },
    }
    # Logic upgrade (Phase 3): fold extracted profile data into the finding using the
    # metadata-key convention the identity graph + name-consensus already consume.
    if profile:
        for key in ("display_name", "bio", "avatar_url", "location"):
            value = profile.get(key)
            if value:
                finding["metadata"][key] = value
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


def _drop_low_precision(
    queue: list[tuple[str, dict[str, Any], str]],
) -> list[tuple[str, dict[str, Any], str]]:
    """Drop the low-precision tail from a SPECULATIVE (localpart-seeded) probe queue.

    T1 (Output-Trust final): keep only :func:`_is_high_precision` platforms (ranked
    majors or discriminating probe contracts) and drop the unranked bare
    ``status_code`` long tail whose soft-200 for any string is RC1's false-positive
    source. This is the substantive shrink of the default localpart sweep — the
    corpus's ``alexaRank`` is too sparse to select the subset by rank alone (real
    majors like GitHub/YouTube are unranked), so precision, not rank, chooses. Applied
    to Wave 1 only; the Wave-2 opt-in deliberately widens the net and keeps its tail.
    """
    return [item for item in queue if _is_high_precision(item[1])]


def _cap_queue_by_rank(
    queue: list[tuple[str, dict[str, Any], str]], cap: int
) -> list[tuple[str, dict[str, Any], str]]:
    """Restrict a probe queue to the top-``cap`` platforms by popularity rank.

    Selection is per *platform* (best alexaRank first, unranked last); all queued
    username variants for a kept platform are retained. ``cap <= 0`` disables the
    cap and returns the queue unchanged.
    """
    if cap <= 0:
        return queue
    best_rank: dict[str, int] = {}
    for name, defn, _variant in queue:
        rank = _alexa_rank(defn)
        rank = 10**9 if rank is None else rank
        if name not in best_rank or rank < best_rank[name]:
            best_rank[name] = rank
    if len(best_rank) <= cap:
        return queue
    keep = set(sorted(best_rank, key=lambda n: (best_rank[n], n))[:cap])
    return [item for item in queue if item[0] in keep]


class UsernamePlatformsModule(BaseModule):
    name = "username_platforms"
    description = (
        "Username enumeration across 4000+ platforms via the native MailAccess site corpus. "
        "Disable via ENABLE_USERNAME_PLATFORMS=false."
    )
    requires_key = False
    default_enabled = True

    async def run(
        self,
        email: str,
        force: bool = False,
        sink: list[dict[str, Any]] | None = None,
    ) -> ModuleResult:
        from ..config import opt_in_active

        enabled = opt_in_active("enable_username_platforms", settings.enable_username_platforms)
        if not (enabled or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "username_platforms disabled \u2014 set ENABLE_USERNAME_PLATFORMS=true "
                    "to scan 4000+ platforms (default behavior)"
                ],
            )

        include_wave2 = settings.enable_username_wave2
        try:
            sites, load_meta = await load_username_sites(include_wave2=include_wave2)
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Failed to load the username platform corpus: {exc}"],
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

        # Env-var overrides win. If the user sets USERNAME_FORCE_<KEY>=true,
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
            # `force` bypasses the health gate consistently with the skip/demote sets
            # below (which already honor `_is_forced`), so USERNAME_FORCE_<KEY>=true
            # re-enables a platform at *every* health gate, not just the Phase-6D sets.
            if not await health.should_probe_async(name, force=_is_forced(name)):
                health_skipped += 1
                continue
            if name in skip_set:
                # R10 (S4): a Phase-6D skip is not permanent — let a recovered
                # platform through for a bounded-time recovery probe (or when
                # forced) instead of stranding it until its stats age out.
                if not _is_forced(name) and not await health.recovery_due_async(name):
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
            # Demote fragile wave-1 platforms to wave-2 rather than skipping them
            # entirely. R10: a forced platform bypasses EVERY health demotion,
            # including fragility, so USERNAME_FORCE_<KEY>=true keeps it in wave 1.
            fragile = health.get_fragility_score(name) >= _FALLBACK_FRAGILITY_DEMOTION_THRESHOLD
            if wave == 1 and fragile and not _is_forced(name):
                wave = 2
            if wave == 2 and not include_wave2:
                continue
            probe_variants = [email] if defn.get("is_email_only") else variants
            for variant in probe_variants:
                key = (name, variant)
                if key in queued:
                    continue
                queued.add(key)
                if not username_matches_regex(defn, variant):
                    regex_skipped += 1
                    continue
                (wave1_queue if wave == 1 else wave2_queue).append((name, defn, variant))

        # ── Rank-prioritized per-run cap ──────────────────────────────────────
        # Bound each wave to a high-signal subset by popularity rank (best first)
        # so a default run probes the most-likely platforms instead of sweeping the
        # full corpus — which would be slow and risk mass-blocking. The health DB
        # further prunes noisy platforms over time; wave-2 opt-in widens the net.
        # T1 — Wave 1 is the DEFAULT speculative localpart sweep: drop its
        # low-precision tail (keep ranked majors + discriminating contracts) before
        # the rank ceiling. Wave 2 is the opt-in wide net and keeps its tail.
        wave1_queue = _cap_queue_by_rank(
            _drop_low_precision(wave1_queue), settings.username_wave1_cap
        )
        wave2_queue = _cap_queue_by_rank(wave2_queue, settings.username_wave2_cap)

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

        # Q4 — stream each confirmed hit into the run-owned ``sink`` (if provided) the
        # moment it lands, so an outer budget timeout that cancels this module mid-run
        # keeps the hits found so far instead of erasing the whole wave.
        seen_hits: set[tuple[str, str]] = set()

        def _emit_hit(
            name: str,
            defn: dict[str, Any],
            variant: str,
            detail: str,
            profile: dict[str, str] | None,
            wave: int,
        ) -> None:
            key = (name, variant)
            if key in seen_hits:
                return
            seen_hits.add(key)
            finding = _finding(name, defn, variant, detail, wave, email=email, profile=profile)
            findings.append(finding)
            if sink is not None:
                sink.append(finding)

        async with build_client(timeout=12.0) as client:
            wave1 = await self._run_wave(
                client, wave1_queue, wave=1, health=health, on_hit=_emit_hit
            )
            wave2 = (
                await self._run_wave(
                    client, wave2_queue, wave=2, health=health, on_hit=_emit_hit
                )
                if include_wave2
                else []
            )

        for name, defn, variant, outcome, detail, profile, wave in [*wave1, *wave2]:
            if outcome == "hit" and detail:
                continue  # already streamed via _emit_hit
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

        # Coverage accounting (Part 0.3): count DISTINCT platforms, not queued probe
        # rows. Each platform is probed with up to len(variants) usernames, so the old
        # `len(wave1_queue)+len(wave2_queue)` inflated "platforms checked" by the variant
        # fan-out. Keep the raw probe count separately as `total_probes_attempted`.
        distinct_platforms_probed = health_tracked
        total_probes_attempted = len(wave1_queue) + len(wave2_queue)
        probe_funnel = {
            "corpus_sites": load_meta.get("sites_loaded") or load_meta.get("username_sites"),
            "distinct_platforms_probed": distinct_platforms_probed,
            "probes_attempted": total_probes_attempted,
            "confirmed": len(findings),
            "not_found": misses,
            "inconclusive": inconclusive,
            "excluded_by_reason": {
                "catch_all": len(catch_all),
                "health_skipped": health_skipped,
                "regex_skipped": regex_skipped,
                "auto_demoted_skipped": len(applied_skip),
            },
        }
        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                **load_meta,
                "total_platforms_checked": distinct_platforms_probed,
                "total_probes_attempted": total_probes_attempted,
                "probe_funnel": probe_funnel,
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
                "wave1_platform_cap": settings.username_wave1_cap,
                "wave2_platform_cap": settings.username_wave2_cap,
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
        on_hit: Any = None,
    ) -> list[tuple[str, dict[str, Any], str, str, str | None, dict[str, str] | None, int]]:
        sem = asyncio.Semaphore(_WAVE1_CONCURRENCY if wave == 1 else _WAVE2_CONCURRENCY)
        # R10 (S4): measure latency POST-semaphore. probe_platform acquires its
        # own semaphore internally, so timing around it would include queue-wait
        # under high concurrency and inflate the health latency stats. We hold the
        # concurrency limit here and hand probe_platform an unbounded semaphore, so
        # ``latency_ms`` reflects the actual probe, not the wait to start it.
        no_limit = asyncio.Semaphore(2**31)
        timeout = 6.0 if wave == 1 else 10.0

        async def _timed_probe(
            name: str, defn: dict[str, Any], username: str
        ) -> tuple[str, dict[str, Any], str, str, str | None, dict[str, str] | None]:
            async with sem:
                t0 = time.perf_counter()
                outcome, detail, profile = await probe_platform(
                    client, no_limit, name, defn, username, timeout=timeout
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
            return name, defn, username, outcome, detail, profile

        # Explicit tasks + as_completed so each hit is surfaced to ``on_hit`` the
        # instant it lands (Q4 streaming). A ``finally`` cancels still-pending probes
        # if this wave is cancelled by an outer timeout, so nothing is orphaned.
        tasks = [
            asyncio.ensure_future(_timed_probe(name, defn, username))
            for name, defn, username in queue
        ]
        results: list[
            tuple[str, dict[str, Any], str, str, str | None, dict[str, str] | None, int]
        ] = []
        try:
            for future in asyncio.as_completed(tasks):
                try:
                    name, defn, username, outcome, detail, profile = await future
                except Exception:
                    # probe_platform never raises, but stay defensive: one bad probe
                    # must not wipe the wave's other hits.
                    continue
                results.append((name, defn, username, outcome, detail, profile, wave))
                if outcome == "hit" and detail and on_hit is not None:
                    on_hit(name, defn, username, detail, profile, wave)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
        return results

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
            for (name, _defn), (outcome, _detail, _profile) in zip(candidates, results)
            if outcome == "hit"
        }
