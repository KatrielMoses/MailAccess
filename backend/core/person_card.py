"""UC5 person card: one summary across an investigation's accounts, names, locations,
photos, timeline and links.

A pure function of findings the engine already collected. The only network activity in the
whole card is the capped avatar fetch in :func:`attach_avatar_hashes`, which runs during
the async investigation (host-politeness path) and writes a perceptual hash into each
account's metadata; :func:`build_card` then dedups photos from those hashes with no I/O.

Hard rules (UC5 guardrails): city / region / country only — never a phone number or a
street address (``fields.py`` already strips them, and the card never reintroduces them);
and an account joins the name/photo/location aggregates only when it ties back to the
subject (the "name + one more detail" rule, gate 4).
"""

from __future__ import annotations

import logging
from typing import Any

from .profiles.fields import FIELD_KEYS

_LOG = logging.getLogger(__name__)

# Modules whose findings describe an account/profile of the subject.
_ACCOUNT_MODULES = (
    "username_platforms", "username_pivot", "account_discovery", "linkedin_brightdata",
    "github_commits", "github_domain_commits", "linkedin_serp", "google_account_intel",
    "hackernews", "gravatar", "keybase",
    # UC7.3: a verified provider mailbox (Google/Microsoft) is a first-class Class-1
    # account, not just metadata.
    "outlook_autodiscover", "m365_active_intel", "m365_passive_intel", "imap_existence",
)
# Modules keyed on the email/commit identity itself (tie to the subject on their own).
_EMAIL_LINKED_MODULES = frozenset(
    {"account_discovery", "github_commits", "github_domain_commits", "linkedin_brightdata",
     "linkedin_serp", "google_account_intel", "gravatar",
     "outlook_autodiscover", "m365_active_intel", "m365_passive_intel", "imap_existence"}
)
_PHOTO_DISTANCE = 6  # perceptual-hash Hamming distance for "same photo"
_AVATAR_FETCH_CAP = 8
_AVATAR_TIMEOUT_S = 5.0

# UC7.2: the identity spine. Class 1 = email-anchored signals (the email itself proves
# the account); a Class-2 username/local-part guess only joins the identity when UC7.1
# corroborated it up to the spine. See dev/UC-IDENTITY-ARCHITECTURE.md.
from .evidence import (  # noqa: E402 - small, stable constant set; avoids a cycle at call time
    SIG_BREACH, SIG_GRAVATAR, SIG_LOCALPART, SIG_PROVIDER, SIG_PUBLIC_RECORD,
    SIG_REGISTRATION, SIG_SIGNIN_PROBE, SIG_USERNAME, signal_type_for, subject_is_freemail,
)

_CLASS1_SIGNALS = frozenset({
    SIG_REGISTRATION, SIG_SIGNIN_PROBE, SIG_PUBLIC_RECORD, SIG_PROVIDER, SIG_GRAVATAR, SIG_BREACH,
})
_CLASS2_SIGNALS = frozenset({SIG_USERNAME, SIG_LOCALPART})


def _finding_signal(module: str, f: dict[str, Any]) -> str:
    trace = f.get("trace") if isinstance(f.get("trace"), dict) else {}
    return str(trace.get("signal_type") or "") or signal_type_for(module, f)


def _finding_corroborated(f: dict[str, Any]) -> bool:
    """UC7.1 lifted this Class-2 match up to the spine (freemail-aware)."""
    meta = _meta(f) if isinstance(f, dict) else {}
    if meta.get("localpart_group") == "corroborated":
        return True
    trace = f.get("trace") if isinstance(f.get("trace"), dict) else {}
    return (trace.get("username_corroboration") or {}).get("tier") in ("possible", "confirmed")


# ── small helpers ───────────────────────────────────────────────────────────

def _name_words(name: Any) -> list[str]:
    import re

    return [w for w in re.split(r"[^a-z]+", str(name or "").lower()) if w]


def names_match(a: Any, b: Any) -> bool:
    """First and last name agree (case-insensitive); middle names ignored; an initial
    matches a full first name. Reused from the LinkedIn module's rule."""
    wa, wb = _name_words(a), _name_words(b)
    if len(wa) < 2 or len(wb) < 2 or wa[-1] != wb[-1]:
        return False
    fa, fb = wa[0], wb[0]
    return fa == fb or (len(fa) == 1 and fb.startswith(fa)) or (len(fb) == 1 and fa.startswith(fb))


def _name_compatible(name: Any, primary: Any) -> bool:
    """True when ``name`` does not contradict the confirmed ``primary`` — they share a
    surname (last word), so "Jane Alex Doe" is compatible with "Jane Doe" but
    "Jane Smith" is not. No name or no primary ⇒ compatible (nothing to contradict)."""
    wa, wp = set(_name_words(name)), set(_name_words(primary))
    if len(_name_words(name)) < 2 or not wp:
        return True
    pa, pp = _name_words(name), _name_words(primary)
    return pa[-1] in wp or pp[-1] in wa


def _subject(data: dict[str, Any]) -> dict[str, str]:
    handle = data.get("subject_username")
    if handle:
        return {"type": "username", "value": str(handle)}
    target = data.get("original_email") or data.get("email") or data.get("canonical_email") or ""
    # UC5 --username: a target with no "@" is a handle, not an email.
    if target and "@" not in str(target):
        return {"type": "username", "value": str(target)}
    return {"type": "email", "value": str(target)}


def _subject_handles(data: dict[str, Any]) -> set[str]:
    """Every handle variant the search probed, lowercased."""
    from ..modules.username_platforms import _username_variants

    subj = _subject(data)
    if subj["type"] == "username":
        import re

        local = subj["value"]
        variants = [local, re.sub(r"[._-]+", "", local), re.sub(r"[._]+", "-", local),
                    re.sub(r"[.-]+", "_", local)]
        return {v.lower() for v in dict.fromkeys(variants) if v}
    email = data.get("original_email") or data.get("email") or ""
    out: set[str] = set()
    for e in {email, data.get("canonical_email") or ""}:
        if e:
            out |= {v.lower() for v in _username_variants(e)}
    return out


def _account_findings(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """``[(module, finding_data)]`` for every account/profile finding on the report."""
    fbm = data.get("findings_by_module") or {}
    out: list[tuple[str, dict[str, Any]]] = []
    for module in _ACCOUNT_MODULES:
        for f in fbm.get(module) or []:
            if isinstance(f, dict) and f.get("platform"):
                out.append((module, f))
    return out


def _meta(f: dict[str, Any]) -> dict[str, Any]:
    m = f.get("metadata")
    return m if isinstance(m, dict) else {}


def _tier(meta: dict[str, Any]) -> str | None:
    if meta.get("core"):
        return "core"
    if meta.get("validated"):
        return "validated"
    if meta.get("source") in ("username_pivot",) or meta.get("pivot_tier"):
        return "pivot"
    return None


def _other_handles(meta: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for h in meta.get("other_handles") or []:
        if isinstance(h, str) and ":" in h:
            out.add(h.split(":", 1)[1].lower())
    return out


# ── 1a accounts (dedup across modules) ──────────────────────────────────────

_CONF_RANK = {"high": 3, "medium": 2, "low": 1, None: 0, "": 0}


def _collect_accounts(data: dict[str, Any]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for module, f in _account_findings(data):
        meta = _meta(f)
        handle = str(f.get("username") or meta.get("profile_username")
                     or meta.get("matched_username") or "").strip()
        key = (str(f.get("platform")).lower(), handle.lower())
        entry = by_key.get(key)
        if entry is None:
            entry = {
                "platform": f.get("platform"), "handle": handle or None,
                "url": f.get("profile_url"), "modules": [], "confidence": "low",
                "tier": _tier(meta), "email_linked": False, "_metas": [],
                "class1": False, "class2": False, "corroborated": False,
            }
            by_key[key] = entry
        if module not in entry["modules"]:
            entry["modules"].append(module)
        entry["_metas"].append((module, meta, f))
        entry["email_linked"] = entry["email_linked"] or bool(f.get("email_linked")) \
            or module in _EMAIL_LINKED_MODULES
        # UC7.2: identity class per account, by SIGNAL CLASS (not a UC7.1 tag, which
        # misses core-tier username hits). Class-1 = email-anchored; Class-2 = a
        # username / local-part guess. An account with ANY Class-1 signal is on the
        # spine; one with only Class-2 signals is not (see _mark_direct).
        signal = _finding_signal(module, f)
        if signal in _CLASS1_SIGNALS:
            entry["class1"] = True
        if signal in _CLASS2_SIGNALS:
            entry["class2"] = True
        if _finding_corroborated(f):
            entry["corroborated"] = True
        if _CONF_RANK.get(str(f.get("confidence") or "").lower(), 0) > _CONF_RANK.get(entry["confidence"], 0):
            entry["confidence"] = str(f.get("confidence") or "low").lower()
        # a core-site hit outranks a tail hit
        for cand in (_tier(meta),):
            if cand == "core" or (cand and entry["tier"] not in ("core",)):
                entry["tier"] = cand if entry["tier"] != "core" else "core"
        if not entry["url"] and f.get("profile_url"):
            entry["url"] = f.get("profile_url")
    return list(by_key.values())


# ── 1f collision guard ──────────────────────────────────────────────────────

def _mark_direct(accounts: list[dict[str, Any]], data: dict[str, Any]) -> None:
    """Pass 1 (UC7.2 r2): the identity is the email-anchored spine. A direct tie is
    ``email_linked`` or a Class-1 signal. Class membership is decided by SIGNAL CLASS,
    not a tag (which missed core-tier username hits and merged strangers who share a
    common local part into one person).

    - **Domain email subject:** Class-1 ONLY. A Class-2 username / local-part match is
      never a tie, whatever its tier or UC7.1 corroboration — the local part is a role.
    - **Freemail subject:** the local part is the person's own handle, so a Class-2 match
      UC7.1 corroborated up to the spine (consistent handle + name) may tie in too.
    - **``--username`` subject:** the handle IS the identity, so a handle match ties.
    """
    subj = _subject(data)
    username_subject = subj["type"] == "username"
    email = str(data.get("original_email") or data.get("email") or data.get("canonical_email") or "")
    # UC7.3 r3: a freemail subject keeps corroborated Class-2 ONLY when its handle is
    # specific. A bare common first name (``john@gmail.com``) collides with strangers
    # exactly like a domain role, so a low-specificity freemail handle is treated as
    # Class-1 only — the freemail/domain split alone does not catch this.
    from .common_names import is_specific_handle

    local_part = email.split("@", 1)[0] if "@" in email else ""
    freemail_specific = (
        (not username_subject) and subject_is_freemail(email) and is_specific_handle(local_part)
    )
    subj_handles = _subject_handles(data)
    for a in accounts:
        handle_match = bool(a["handle"] and a["handle"].lower() in subj_handles)
        if username_subject:
            a["_direct"] = bool(a["email_linked"] or a["class1"] or handle_match)
        elif freemail_specific:
            a["_direct"] = bool(a["email_linked"] or a["class1"] or a["corroborated"])
        else:
            a["_direct"] = bool(a["email_linked"] or a["class1"])
        a["in_aggregates"] = a["_direct"]


def _resolve_primary(data: dict[str, Any], accounts: list[dict[str, Any]]) -> str | None:
    """The subject's name: name_consensus if it confirmed one, else the most frequent
    two-word name among the directly-tied accounts (longest as the tie-break)."""
    from collections import Counter

    primary = (data.get("name_consensus") or {}).get("confirmed_name") or data.get("confirmed_name")
    if primary:
        return primary
    freq: Counter = Counter()
    longest: dict[str, str] = {}
    for a in accounts:
        if not a["_direct"]:
            continue
        for _m, meta, _f in a["_metas"]:
            name = meta.get("display_name")
            if name and len(_name_words(name)) >= 2:
                freq[name.lower()] += 1
                longest[name.lower()] = max(longest.get(name.lower(), ""), name, key=len)
    if not freq:
        return None
    best = max(freq, key=lambda k: (freq[k], len(longest[k])))
    return longest[best]


def _mark_tied(accounts: list[dict[str, Any]], data: dict[str, Any], primary_name: str | None) -> None:
    """Set ``in_aggregates`` per account (gate 4). Call after ``_mark_direct`` and after
    the primary name is resolved. Name-matches the confirmed name AND a second detail
    (location / cross-linked handle) tie a non-direct account in; a parsed name that
    contradicts the confirmed surname drops an account out (a handle collision)."""
    username_subject = _subject(data)["type"] == "username"
    tied_handles: set[str] = set()
    for a in accounts:
        if a["_direct"]:
            if a["handle"]:
                tied_handles.add(a["handle"].lower())
            for _m, meta, _f in a["_metas"]:
                tied_handles |= _other_handles(meta)
    # Pass 2: name + one more detail (a cross-linked handle, or an agreeing location)
    # ties a non-direct account in. UC7.2 r2: this runs in ``--username`` mode ONLY —
    # for an EMAIL subject the identity is Class-1 only, so a Class-2 account must never
    # be pulled in by a name match (that re-introduced the strangers the spine excludes).
    tied_locations = {
        _loc_tuple(meta.get("location_normalized"))
        for a in accounts if a["in_aggregates"]
        for _m, meta, _f in a["_metas"] if meta.get("location_normalized")
    }
    tied_locations.discard(None)
    for a in accounts:
        if a["in_aggregates"] or not username_subject:
            continue
        name = _account_name(a)
        if not (primary_name and name and names_match(name, primary_name)):
            continue
        cross = (a["handle"] and a["handle"].lower() in tied_handles) or any(
            h in tied_handles for _m, meta, _f in a["_metas"] for h in _other_handles(meta))
        loc_ok = any(_loc_tuple(meta.get("location_normalized")) in tied_locations
                     for _m, meta, _f in a["_metas"] if meta.get("location_normalized"))
        if cross or loc_ok:
            a["in_aggregates"] = True
    # Gate 4: a handle collision (chess.com/<handle> owned by a different person) is a
    # direct tie but carries a contradicting name. Drop any aggregated account whose
    # parsed name contradicts the confirmed surname — never a wrong person's name,
    # photo or location in the aggregates. Email-linked accounts are exempt (the email
    # itself is the tie, stronger than a handle).
    if primary_name:
        for a in accounts:
            if not a["in_aggregates"] or a["email_linked"]:
                continue
            # any parsed name on this account that contradicts the confirmed surname
            # marks a handle collision (a different person who owns the same handle).
            names = [meta.get("display_name") for _m, meta, _f in a["_metas"] if meta.get("display_name")]
            if any(not _name_compatible(n, primary_name) for n in names):
                a["in_aggregates"] = False


def _loc_tuple(loc: Any):
    if not isinstance(loc, dict):
        return None
    return (loc.get("city"), loc.get("region"), loc.get("country_code")) if loc else None


def _account_name(a: dict[str, Any]) -> str | None:
    for _m, meta, _f in a["_metas"]:
        if meta.get("display_name"):
            return str(meta["display_name"])
    return None


# ── 1b names / 1c locations / 1d photos / 1e timeline / 1g links ─────────────

def _build_names(accounts: list[dict[str, Any]], primary: str | None) -> dict[str, Any]:
    from collections import Counter

    tied = [a for a in accounts if a["in_aggregates"]]
    # Fallback when name_consensus didn't confirm one (common in --username mode): the
    # most frequent name across the subject's own accounts, longest as the tie-break.
    if not primary:
        freq: Counter = Counter()
        longest: dict[str, str] = {}
        for a in tied:
            name = _account_name(a)
            if name and len(_name_words(name)) >= 2:
                freq[name.lower()] += 1
                longest[name.lower()] = max(longest.get(name.lower(), ""), name, key=len)
        if freq:
            best = max(freq, key=lambda k: (freq[k], len(longest[k])))
            primary = longest[best]
    variants: list[dict[str, str]] = []
    seen: set[str] = {(primary or "").lower()}
    for a in tied:
        name = _account_name(a)
        if name and name.lower() not in seen:
            seen.add(name.lower())
            variants.append({"name": name, "source": str(a["platform"])})
    return {"primary": primary, "variants": variants}


def _build_locations(accounts: list[dict[str, Any]]) -> dict[str, Any]:
    from collections import Counter

    counts: Counter = Counter()
    repr_loc: dict[tuple, dict[str, str]] = {}
    for a in accounts:
        if not a["in_aggregates"]:
            continue
        seen_here: set[tuple] = set()
        for _m, meta, _f in a["_metas"]:
            loc = meta.get("location_normalized")
            t = _loc_tuple(loc)
            if not t or any(t) is False or not any(t) or t in seen_here:
                continue
            seen_here.add(t)
            counts[t] += 1
            repr_loc.setdefault(t, {k: v for k, v in loc.items() if k in ("city", "region", "country_code") and v})
    if not counts:
        return {"primary": None, "also_seen": [], "countries": []}
    ordered = [t for t, _n in counts.most_common()]
    primary_t = ordered[0]
    countries = sorted({t[2] for t in counts if t[2]})
    return {
        "primary": {**repr_loc[primary_t], "sources": counts[primary_t]},
        "also_seen": [{**repr_loc[t], "sources": counts[t]} for t in ordered[1:]],
        "countries": countries,  # >1 country ⇒ disagreement shown, not resolved
    }


def _phash_groups(photos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop near-duplicate avatars by perceptual hash (distance <= 6); keep URL+source.
    Photos without a hash are deduped by URL only."""
    try:
        import imagehash
    except Exception:  # pragma: no cover
        imagehash = None
    kept: list[dict[str, Any]] = []
    kept_hashes: list[Any] = []
    seen_urls: set[str] = set()
    for p in photos:
        if p["url"] in seen_urls:
            continue
        h = None
        if imagehash is not None and p.get("phash"):
            try:
                h = imagehash.hex_to_hash(p["phash"])
            except Exception:
                h = None
        if h is not None and any((h - kh) <= _PHOTO_DISTANCE for kh in kept_hashes):
            continue
        seen_urls.add(p["url"])
        kept.append({"url": p["url"], "source": p["source"], "kind": p.get("kind", "avatar")})
        if h is not None:
            kept_hashes.append(h)
    return kept


def _build_photos(accounts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    photos: list[dict[str, Any]] = []
    for a in accounts:
        if not a["in_aggregates"]:
            continue
        for _m, meta, _f in a["_metas"]:
            for kind, key in (("avatar", "avatar_url"), ("banner", "banner_url")):
                url = meta.get(key)
                if url:
                    photos.append({"url": str(url), "source": str(a["platform"]), "kind": kind,
                                   "phash": meta.get("avatar_phash") if kind == "avatar" else None})
    return _phash_groups(photos)


def _build_timeline(accounts: list[dict[str, Any]]) -> dict[str, Any]:
    joined: list[str] = []
    active: list[str] = []
    for a in accounts:
        if not a["in_aggregates"]:
            continue
        for _m, meta, _f in a["_metas"]:
            if meta.get("joined_at"):
                joined.append(str(meta["joined_at"]))
            if meta.get("last_active_at"):
                active.append(str(meta["last_active_at"]))
    out: dict[str, Any] = {}
    if joined:
        out["first_seen"] = min(joined)
    if active or joined:
        out["last_seen"] = max(active + joined)
    return out


def _build_links_handles(accounts: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    links: list[str] = []
    handles: list[str] = []
    for a in accounts:
        if not a["in_aggregates"]:
            continue
        for _m, meta, _f in a["_metas"]:
            for u in meta.get("links") or []:
                if isinstance(u, str) and u not in links:
                    links.append(u)
            for h in meta.get("other_handles") or []:
                if isinstance(h, str) and h not in handles:
                    handles.append(h)
    return links, handles


def build_card(data: dict[str, Any]) -> dict[str, Any]:
    """The person card for a finished report. Pure: no network, no mutation of ``data``."""
    accounts = _collect_accounts(data)
    _mark_direct(accounts, data)
    primary_name = _resolve_primary(data, accounts)
    _mark_tied(accounts, data, primary_name)
    locations = _build_locations(accounts)
    links, handles = _build_links_handles(accounts)
    photos = _build_photos(accounts)
    public_accounts = [
        {k: a[k] for k in ("platform", "handle", "url", "modules", "confidence", "tier")}
        | {"in_aggregates": a["in_aggregates"]}
        for a in sorted(accounts, key=lambda a: (not a["in_aggregates"], str(a["platform"]).lower()))
    ]
    names = _build_names(accounts, primary_name)
    primary_name = names["primary"]
    return {
        "schema_version": 1,
        "subject": _subject(data),
        "names": names,
        "locations": locations,
        "photos": photos,
        "timeline": _build_timeline(accounts),
        "accounts": public_accounts,
        "links": links,
        "handles": handles,
        "counts": {
            "accounts": len(public_accounts),
            "linked_to_subject": sum(1 for a in accounts if a["in_aggregates"]),
            "photos": len(photos),
            "names": len(names["variants"]) + (1 if primary_name else 0),
            "locations": (1 if locations["primary"] else 0) + len(locations["also_seen"]),
        },
    }


# ── 1d avatar hashing (the one network step; async, host-politeness) ─────────

async def attach_avatar_hashes(collected: dict[str, Any]) -> None:
    """Fetch each distinct avatar once (cap 8, 5 s each, host-politeness) and write a
    perceptual hash into its finding's metadata. Best-effort: any failure is skipped and
    never fatal. Run inside the async investigation, before the report is built."""
    try:
        import imagehash
        from io import BytesIO

        from PIL import Image

        from . import host_politeness
        from .http_client import build_client
    except Exception:  # pragma: no cover
        return

    url_to_metas: dict[str, list[dict[str, Any]]] = {}
    for module in _ACCOUNT_MODULES:
        result = collected.get(module)
        for f in getattr(result, "findings", None) or []:
            meta = f.get("metadata") if isinstance(f, dict) else None
            if isinstance(meta, dict) and meta.get("avatar_url") and not meta.get("avatar_phash"):
                url_to_metas.setdefault(str(meta["avatar_url"]), []).append(meta)
    urls = list(url_to_metas)[:_AVATAR_FETCH_CAP]
    if not urls:
        return
    import asyncio

    host_politeness.activate()

    async def _hash_one(client, url: str) -> None:
        # build_client already enforces one request per host (host-politeness) inside
        # send(); wrapping it again here would deadlock on the same non-reentrant slot.
        try:
            resp = await client.get(url, timeout=_AVATAR_TIMEOUT_S)
            if resp.status_code != 200 or not resp.content:
                return
            phash = str(imagehash.dhash(Image.open(BytesIO(resp.content)).convert("RGB")))
        except Exception:
            return
        for meta in url_to_metas[url]:
            meta["avatar_phash"] = phash

    async with build_client(timeout=_AVATAR_TIMEOUT_S, follow_redirects=True) as client:
        # Concurrent + an overall ceiling so the card never adds more than ~6 s.
        try:
            await asyncio.wait_for(
                asyncio.gather(*(_hash_one(client, u) for u in urls)),
                timeout=_AVATAR_TIMEOUT_S + 1.0,
            )
        except asyncio.TimeoutError:
            pass


def _host(url: str) -> str:
    from urllib.parse import urlparse

    try:
        return urlparse(url).netloc
    except ValueError:
        return ""
