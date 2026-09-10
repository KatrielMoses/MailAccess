from __future__ import annotations

import asyncio
import re
from typing import Any

from ..config import settings
from ..core.http_client import build_client
from ..core.probe_detector import probe_platform, username_matches_regex
from ..core.username_sites import load_username_sites
from .base import BaseModule, ModuleResult, ModuleStatus

_MAX_USERNAMES = 5
_USERNAME_KEYS = frozenset({"username", "login", "user", "handle"})
_DISPLAY_NAME_KEYS = frozenset({"display_name", "name", "full_name", "real_name"})
# Bound the pivot to a high-signal subset ranked by popularity: probing the full
# corpus for every recovered username would be slow and mass-blocked. The cap keeps
# the pivot a fast confirmation pass over the most-likely platforms.
_PIVOT_SITE_CAP = 750


def _rank(defn: dict[str, Any]) -> int:
    value = defn.get("alexaRank", defn.get("alexa_rank"))
    try:
        return int(value)
    except (TypeError, ValueError):
        return 10**9


def _slug_variants(display_name: str) -> list[str]:
    s = display_name.strip().lower()
    if not s or "@" in s:
        return []
    variants = [
        re.sub(r"\s+", "_", s),
        re.sub(r"\s+", "", s),
        re.sub(r"\s+", ".", s),
    ]
    out: list[str] = []
    seen: set[str] = set()
    for v in variants:
        v = re.sub(r"[^a-z0-9._-]", "", v)
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _collect_usernames(email: str, collected: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        u = value.strip().lower()
        if not u or "@" in u or len(u) < 2:
            return
        if u not in seen:
            seen.add(u)
            candidates.append(u)

    if "@" in email:
        _add(email.split("@", 1)[0])

    for result in collected.values():
        if not hasattr(result, "findings"):
            continue
        for finding in result.findings:
            if not isinstance(finding, dict):
                continue
            payloads: list[dict[str, Any]] = [finding]
            meta = finding.get("metadata")
            if isinstance(meta, dict):
                payloads.append(meta)
            for payload in payloads:
                for key in _USERNAME_KEYS:
                    val = payload.get(key)
                    if isinstance(val, str):
                        _add(val)
                for key in _DISPLAY_NAME_KEYS:
                    val = payload.get(key)
                    if isinstance(val, str):
                        for variant in _slug_variants(val):
                            _add(variant)

    return candidates[:_MAX_USERNAMES]


def _confirmed_accounts(collected: dict[str, Any]) -> set[tuple[str, str]]:
    """Accounts already confirmed by primary enumeration, keyed by
    ``(platform, username)``.

    R7 (S3): keying by platform ALONE excluded a genuinely distinct account on a
    platform already seen (Alice@github would suppress Bob@github). Keying by the
    account identity lets distinct usernames on the same platform survive; only
    the exact same account is skipped (and platform_dedup is the real dedup by
    profile handle downstream anyway).
    """
    accounts: set[tuple[str, str]] = set()
    enum_result = collected.get("username_platforms")
    if enum_result and hasattr(enum_result, "findings"):
        for f in enum_result.findings:
            if isinstance(f, dict) and f.get("platform"):
                meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
                username = str(
                    f.get("username")
                    or meta.get("username")
                    or meta.get("matched_username")
                    or ""
                ).lower()
                accounts.add((str(f["platform"]).lower(), username))
    return accounts


class UsernamePivotModule(BaseModule):
    name = "username_pivot"
    description = (
        "Pivot recovered usernames across the username platform corpus after primary modules. "
        "Enable via ENABLE_USERNAME_PIVOT=true."
    )
    requires_key = False

    async def run(
        self, email: str, collected: dict[str, Any] | None = None
    ) -> ModuleResult:
        if collected is None:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Runs in post-primary phase only"],
            )

        if not settings.enable_username_pivot:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_USERNAME_PIVOT=true to run this module"],
            )

        usernames = _collect_usernames(email, collected)
        if not usernames:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["No usernames recovered from primary findings"],
            )

        try:
            sites, load_meta = await load_username_sites(include_wave2=False)
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Failed to load the username platform corpus: {exc}"],
            )

        # High-signal subset: the most popular probeable platforms, ranked.
        selected = sorted(sites.items(), key=lambda kv: _rank(kv[1]))[:_PIVOT_SITE_CAP]
        already_found = _confirmed_accounts(collected)
        sem = asyncio.Semaphore(50)
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        checked = 0
        confirmed = 0
        # R11 (S2) — track outcome classes so a blocked/all-unknown sweep can
        # never be reported as a successful all-negative.
        hits = 0
        misses = 0
        inconclusive = 0

        async with build_client(timeout=6.0, follow_redirects=True) as client:
            for username in usernames:
                queue = [
                    (name, defn)
                    for name, defn in selected
                    if username_matches_regex(defn, username)
                ]
                tasks = [
                    probe_platform(client, sem, name, defn, username, timeout=6.0)
                    for name, defn in queue
                ]
                results = await asyncio.gather(*tasks)
                checked += len(queue)

                for (name, defn), (outcome, detail, profile) in zip(queue, results):
                    if outcome == "hit":
                        hits += 1
                    elif outcome == "miss":
                        misses += 1
                    else:
                        inconclusive += 1
                    if outcome != "hit" or not name:
                        continue
                    # R7 (S3): dedupe by the ACCOUNT identity (platform, username),
                    # not the platform alone — two distinct usernames on the same
                    # platform are two accounts and must both survive.
                    account = (name.lower(), username.lower())
                    if account in already_found:
                        continue
                    already_found.add(account)
                    confirmed += 1
                    tags = defn.get("tags") if isinstance(defn.get("tags"), list) else []
                    finding = {
                        "platform": name,
                        "profile_url": detail,
                        "username": username,
                        "metadata": {
                            "matched_username": username,
                            "category": tags[0] if tags else "",
                            "source": "username_pivot",
                            # RC1 (Output-Trust): the pivot probes usernames DERIVED
                            # from the localpart / display names — a derivative,
                            # speculative signal. On its own it is UNVERIFIED and
                            # capped to LOW; independent corroboration (platform_dedup
                            # dual-confirm) is what promotes it.
                            "verification": "unverified",
                            "speculative": True,
                        },
                        "confidence": "low",
                    }
                    if profile:
                        for key in ("display_name", "bio", "avatar_url", "location"):
                            value = profile.get(key)
                            if value:
                                finding["metadata"][key] = value
                    findings.append(finding)

        # R11 (S2) — honest coverage. A blocked / all-inconclusive sweep produced
        # no definitive answer, so it is never a successful all-negative.
        coverage_complete = inconclusive == 0 and not errors
        if checked == 0:
            # Nothing applicable to probe (no username matched any platform).
            status = ModuleStatus.SUCCESS_EMPTY
        elif hits == 0 and misses == 0:
            # Every probe was inconclusive/blocked → no coverage at all.
            status = ModuleStatus.FAILED if errors else ModuleStatus.PARTIAL
        elif not coverage_complete:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS if findings else ModuleStatus.SUCCESS_EMPTY

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "usernames_pivoted": usernames,
                "platforms_checked": checked,
                "platforms_confirmed": confirmed,
                "platforms_hits": hits,
                "platforms_misses": misses,
                "platforms_inconclusive": inconclusive,
                "coverage_complete": coverage_complete,
                "sites_pool": len(selected),
                **load_meta,
            },
            errors=errors,
        )
