from __future__ import annotations

import asyncio
import re
from typing import Any

from ..config import settings
from ..core import run_events
from ..core.evidence import evidence_label
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


def _collect_usernames(
    email: str,
    collected: dict[str, Any],
    origins: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """Candidate usernames to pivot. ``origins`` (optional) is filled with where each
    came from: the module, the finding, and whether that finding was itself only a
    username match, so every pivot hit can say what it was derived from."""
    candidates: list[str] = []
    seen: set[str] = set()
    current: dict[str, Any] = {"module": "email", "finding_id": None, "username_match": False}

    def _add(value: str) -> None:
        u = value.strip().lower()
        if not u or "@" in u or len(u) < 2:
            return
        if u not in seen:
            seen.add(u)
            candidates.append(u)
            if origins is not None:
                origins[u] = dict(current)

    if "@" in email:
        _add(email.split("@", 1)[0])

    for module_name, result in collected.items():
        if not hasattr(result, "findings"):
            continue
        for finding in result.findings:
            if not isinstance(finding, dict):
                continue
            current = {
                "module": module_name,
                "finding_id": finding.get("finding_id"),
                "username_match": evidence_label(finding, module_name) == "username_match",
            }
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


# Modules whose findings carry OTHER people's identifiers (search results, org members,
# harvested addresses): never a source of usernames for this person.
_THIRD_PARTY_MODULES = frozenset({
    "email_search_dork", "employee_name_discovery", "github_org_members", "commoncrawl_email",
    "code_and_cert_email", "domain_harvester", "permutation_discovery", "google_dork",
    "linkedin_serp",
})
_HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,38}$")


def ranked_usernames(email: str, collected: dict[str, Any]) -> list[tuple[str, int, dict[str, Any]]]:
    """``(username, tier, origin)`` best first, at most ``_MAX_USERNAMES``.

    Tier 1: a handle a profile itself states (``profile_username``, a linked handle
    in ``other_handles``) on a core-site hit whose parsed name matches a name found for
    this person, or a GitHub commit author login (tied to the email).
    Tier 2: usernames from other findings (profile URLs, username fields).
    Tier 3: slugs of names found for this person.
    """
    from ..core.evidence import subject_is_freemail
    from ..core.identity_match import known_names, names_match

    names = known_names(collected)
    out: dict[str, tuple[int, dict[str, Any]]] = {}

    def add(value: Any, tier: int, origin: dict[str, Any]) -> None:
        u = str(value or "").strip().lower().lstrip("@")
        if not _HANDLE_RE.fullmatch(u) or "@" in u:
            return
        if u not in out or tier < out[u][0]:
            out[u] = (tier, origin)

    # UC7.2: the raw email local part seeds a pivot only when it is actually the
    # person's handle — a freemail subject, or a --username subject (no "@"). For a
    # domain subject the local part is a role, and seeding it launched full @localpart
    # sweeps across strangers that share the local part.
    local = email.split("@", 1)[0] if "@" in email else email
    if local and (subject_is_freemail(email) or "@" not in email):
        add(local, 2, {"module": "email", "finding_id": None, "username_match": False})
    for module, result in collected.items():
        if module in _THIRD_PARTY_MODULES or not hasattr(result, "findings"):
            continue
        for f in result.findings:
            if not isinstance(f, dict):
                continue
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            is_username_match = evidence_label(f, module) == "username_match"
            verified = module == "github_commits" or (
                module == "username_platforms" and meta.get("core")
                and any(names_match(meta.get("display_name"), n) for n in names)
            )
            # UC7.2: a bare, name-unverified Class-2 match is not a trusted seed — it is
            # someone who merely shares the handle. Only spine-tied handles (Class-1, or a
            # core sweep hit whose name matches a known name) pivot.
            if is_username_match and not verified:
                continue
            origin = {"module": module, "finding_id": f.get("finding_id"),
                      "username_match": is_username_match}
            for handle in [meta.get("profile_username"), meta.get("login")] + [
                h.split(":", 1)[1] for h in meta.get("other_handles") or []
                if isinstance(h, str) and ":" in h and not h.startswith("linkedin:")
            ]:
                add(handle, 1 if verified else 2, origin)
            for key in _USERNAME_KEYS:
                for payload in (f, meta):
                    add(payload.get(key), 2, origin)
    for n in names:
        for variant in _slug_variants(n):
            add(variant, 3, {"module": "name", "finding_id": None, "username_match": False})
    ranked = sorted(out.items(), key=lambda kv: kv[1][0])
    return [(u, tier, origin) for u, (tier, origin) in ranked][:_MAX_USERNAMES]


def _swept_pairs(collected: dict[str, Any], sites: dict[str, dict[str, Any]]) -> set[tuple[str, str]]:
    """(site, handle) pairs the primary sweep already probed: every core site for each
    handle variant it used (``username_variants``, including the name-split pivot)."""
    from .username_platforms import _variant_allowed

    result = collected.get("username_platforms")
    meta = getattr(result, "metadata", None) or {}
    variants = [str(v).lower() for v in meta.get("username_variants") or []]
    pairs = set()
    for name, defn in sites.items():
        if defn.get("core"):
            for v in variants:
                if _variant_allowed(defn, v):
                    pairs.add((name, v))
    return pairs


class UsernamePivotModule(BaseModule):
    name = "username_pivot"
    description = (
        "Pivot recovered usernames across the username platform corpus after primary modules. "
        "Enable via ENABLE_USERNAME_PIVOT=true."
    )
    requires_key = False

    async def run(
        self,
        email: str,
        collected: dict[str, Any] | None = None,
        sink: list[dict[str, Any]] | None = None,
    ) -> ModuleResult:
        """UC4: a time budget instead of a wall timeout, priority ordering, and no
        re-probing of what the primary sweep already checked.

        Order: for each username (best tier first) the sites where the sweep already
        found this person, then the rest of the validated core list; after every
        username's priority sites, the remaining Wave-1 sites by rank. No new probe
        starts once fewer than one probe timeout is left in the budget, so the pivot
        ends inside ``username_pivot_budget_seconds`` with everything found so far.
        """
        import time

        from .username_platforms import _variant_allowed

        if collected is None:
            return ModuleResult(status=ModuleStatus.SKIPPED,
                                errors=["Runs in post-primary phase only"])
        if not settings.enable_username_pivot:
            return ModuleResult(status=ModuleStatus.SKIPPED,
                                errors=["Set ENABLE_USERNAME_PIVOT=true to run this module"])
        ranked = ranked_usernames(email, collected)
        if not ranked:
            return ModuleResult(status=ModuleStatus.SKIPPED,
                                errors=["No usernames recovered from primary findings"])
        try:
            sites, load_meta = await load_username_sites(include_wave2=False)
        except Exception as exc:
            return ModuleResult(status=ModuleStatus.FAILED,
                                errors=[f"Failed to load the username platform corpus: {exc}"])

        budget = float(getattr(settings, "username_pivot_budget_seconds", 45.0) or 45.0)
        timeout = 6.0
        started = time.monotonic()
        seen = _swept_pairs(collected, sites)
        already_found = _confirmed_accounts(collected)
        found_on = [str(f.get("platform")) for f in getattr(collected.get("username_platforms"),
                                                              "findings", []) or []
                    if isinstance(f, dict) and f.get("platform")]
        usable = {n: d for n, d in sites.items() if not d.get("alwaysHit")}
        by_rank = sorted(usable, key=lambda n: _rank(usable[n]))
        core = [n for n in by_rank if usable[n].get("core")]
        # UC4: only validated (UC2) non-core sites, so the pivot never revives the
        # flappy false-positive long tail the core list was built to exclude.
        rest = [n for n in by_rank if usable[n].get("validated") and not usable[n].get("core")]
        first = [n for n in dict.fromkeys(found_on) if n in usable]

        queue: list[tuple[str, str]] = []
        queued: set[tuple[str, str]] = set()

        def enqueue(handle: str, names: list[str]) -> None:
            for name in names:
                key = (name, handle)
                if key in queued or key in seen or (name.lower(), handle) in already_found:
                    continue
                if not _variant_allowed(usable[name], handle):
                    continue
                queued.add(key)
                queue.append(key)

        for handle, _tier, _origin in ranked:
            enqueue(handle, first + core)
        priority_len = len(queue)
        for handle, _tier, _origin in ranked:
            enqueue(handle, rest)

        origins = {u: origin for u, _t, origin in ranked}
        tiers = {u: tier for u, tier, _o in ranked}
        findings: list[dict[str, Any]] = []
        stats = {"checked": 0, "hits": 0, "misses": 0, "inconclusive": 0, "cache_served": 0}
        stopped_by_budget = False
        sem = asyncio.Semaphore(50)
        no_limit = asyncio.Semaphore(2**31)

        async def probe(client: Any, name: str, handle: str) -> None:
            from ..core import probe_cache
            from ..core.profiles import enrich

            defn = usable[name]
            # UC4: a fresh 7-day cache row answers without an HTTP request.
            cached = probe_cache.get(defn, name, handle)
            if cached is not None:
                stats["cache_served"] += 1
                outcome = cached["outcome"]
                if outcome == "hit":
                    profile = dict(cached.get("fields") or {})
                    detail = profile.pop("_url", None)
                    profile["cached"] = True
                    profile["cached_age_days"] = cached["age_days"]
                else:
                    detail, profile = None, None
            else:
                outcome, detail, profile = await probe_platform(
                    client, no_limit, name, defn, handle, timeout=timeout)
                if outcome == "hit":
                    await enrich(client, defn, handle, profile)
                elif isinstance(profile, dict):
                    profile.pop("_body", None)
                cache_fields = None
                if outcome == "hit":
                    cache_fields = {k: v for k, v in (profile or {}).items() if k != "_probe_response"}
                    cache_fields["_url"] = detail
                probe_cache.put(defn, name, handle, outcome, fields=cache_fields)
            stats["checked"] += 1
            stats["hits" if outcome == "hit" else "misses" if outcome == "miss" else "inconclusive"] += 1
            run_events.module_progress(
                "username_pivot", stats["checked"], len(queue), found=len(findings))
            if outcome != "hit" or not detail or (name.lower(), handle) in already_found:
                return
            already_found.add((name.lower(), handle))
            tags = defn.get("tags") if isinstance(defn.get("tags"), list) else []
            origin = origins.get(handle, {})
            finding = {
                "platform": name,
                "profile_url": detail,
                "username": handle,
                "metadata": {
                    "matched_username": handle,
                    "category": tags[0] if tags else "",
                    "source": "username_pivot",
                    # RC1: a derived username is a speculative signal; LOW until
                    # independently corroborated (platform_dedup).
                    "verification": "unverified",
                    "speculative": True,
                    "pivot_tier": tiers.get(handle),
                    "core": bool(defn.get("core")),
                    "derived_from_module": origin.get("module"),
                    "derived_from_finding": origin.get("finding_id"),
                    "derived_from_username_match": bool(origin.get("username_match")),
                },
                "confidence": "low",
            }
            from ..core.profiles import FIELD_KEYS

            for key in (*FIELD_KEYS.values(), "location_normalized", "linkedin_url", "field_sources"):
                value = (profile or {}).get(key)
                if value not in (None, "", [], {}):
                    finding["metadata"][key] = value
            if (profile or {}).get("cached"):
                finding["metadata"]["cached"] = True
                finding["metadata"]["cached_age_days"] = profile.get("cached_age_days")
            findings.append(finding)
            if sink is not None:
                sink.append(finding)

        async with build_client(timeout=timeout, follow_redirects=True) as client:
            pending: set[asyncio.Task] = set()
            for name, handle in queue:
                if time.monotonic() - started > budget - timeout:
                    stopped_by_budget = True
                    break
                await sem.acquire()
                task = asyncio.ensure_future(probe(client, name, handle))
                task.add_done_callback(lambda _t: sem.release())
                pending.add(task)
                pending = {t for t in pending if not t.done()}
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        checked = stats["checked"]
        if stopped_by_budget and not findings:
            status = ModuleStatus.PARTIAL  # out of time is never "nothing there"
        elif checked == 0:
            status = ModuleStatus.SUCCESS_EMPTY
        elif stats["hits"] == 0 and stats["misses"] == 0:
            status = ModuleStatus.PARTIAL
        elif stats["inconclusive"] or stopped_by_budget:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS if findings else ModuleStatus.SUCCESS_EMPTY
        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "usernames_pivoted": [u for u, _t, _o in ranked],
                "username_tiers": tiers,
                "platforms_checked": checked,
                "platforms_confirmed": len(findings),
                "platforms_hits": stats["hits"],
                "platforms_misses": stats["misses"],
                "platforms_inconclusive": stats["inconclusive"],
                "cache_served": stats["cache_served"],
                "coverage_complete": not stopped_by_budget and not stats["inconclusive"],
                "queued": len(queue),
                "priority_queued": priority_len,
                "skipped_already_swept": sum(1 for u, _t, _o in ranked for n in first + core
                                             if (n, u) in seen),
                "budget_seconds": budget,
                "stopped_by_budget": stopped_by_budget,
                "elapsed_seconds": round(time.monotonic() - started, 1),
                **load_meta,
            },
        )
