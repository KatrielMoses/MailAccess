"""LinkedIn profile card via Bright Data (Pro, BYOK): one lookup per investigation.

Runs in the profile phase right after ``linkedin_serp`` (the username sweep has
finished by then). Steps:

1. Find a LinkedIn profile URL, first match wins: a LinkedIn link on one of the
   person's own profiles → a handle the sweep found (a dotted handle as a hyphen slug
   first, LinkedIn's usual ``first-last``) → the slug ``linkedin_serp`` found.
2. Require a name already found for this person; none means no call (SKIPPED).
3. One Bright Data call (or a 7-day cache hit), then the match rule: the LinkedIn name
   must match a known name AND one more detail must agree (city/country, company,
   school, or a link back to a known profile). With fewer than 3 other confirmed
   profiles a name match alone is accepted; otherwise the card is discarded.
4. Keep only the card fields below. Similar profiles, "people also viewed",
   experience, and any phone / email / street address are never stored or logged.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from ..config import settings
from ..core.brightdata_client import brightdata_active, fetch_profile
from ..core.profiles.fields import scrub, to_count
from ..core.profiles.geo import country_code, normalize_location
from .base import BaseModule, ModuleResult, ModuleStatus

_LINKEDIN_IN = re.compile(r"linkedin\.com/(?:in|pub)/([A-Za-z0-9%_-]{3,100})", re.I)
_SLUG = re.compile(r"[a-z0-9-]{3,100}")
_CACHE_DIR = Path.home() / ".mailaccess" / "cache" / "linkedin_brightdata"
_MIN_PROFILES_FOR_STRICT = 3


def _findings(collected: dict[str, Any]):
    for module, result in (collected or {}).items():
        for f in getattr(result, "findings", None) or []:
            if isinstance(f, dict):
                yield module, f


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)


def profile_url(slug: str) -> str:
    return f"https://www.linkedin.com/in/{slug.strip('/').lower()}/"


def find_profile_url(collected: dict[str, Any]) -> tuple[str, str] | None:
    """``(url, source)`` with source ``own_link`` | ``handle`` | ``serp``, or None."""
    for module, f in _findings(collected):
        if module in ("linkedin_serp", "linkedin_brightdata"):
            continue
        meta = f.get("metadata") or {}
        for text in _strings([meta.get("linkedin_url"), meta.get("links"), meta.get("bio"),
                              meta.get("other_handles")]):
            m = _LINKEDIN_IN.search(text)
            if m:
                return profile_url(m.group(1)), "own_link"
            if text.startswith("linkedin:") and _SLUG.fullmatch(text[9:].lower()):
                return profile_url(text[9:]), "own_link"
    handles: list[str] = []
    for module, f in _findings(collected):
        if module == "username_platforms" and (f.get("metadata") or {}).get("core"):
            handle = str(f.get("username") or "").lower()
            if handle and handle not in handles:
                handles.append(handle)
    for handle in [h.replace(".", "-") for h in handles if "." in h] + handles:
        if _SLUG.fullmatch(handle) and not handle.startswith("-") and not handle.endswith("-"):
            return profile_url(handle), "handle"
    for _module, f in _findings({"linkedin_serp": (collected or {}).get("linkedin_serp")}):
        m = _LINKEDIN_IN.search(str(f.get("profile_url") or (f.get("metadata") or {}).get("linkedin_url") or ""))
        if m:
            return profile_url(m.group(1)), "serp"
    return None


def _words(name: Any) -> list[str]:
    return [w for w in re.split(r"[^a-z]+", str(name or "").lower()) if w]


def known_names(collected: dict[str, Any]) -> list[str]:
    """Names already found for this person: commit authors, parsed profile names."""
    from .linkedin_serp import _find_confirmed_name

    names: list[str] = []
    try:
        name, _src = _find_confirmed_name(collected)
        if name:
            names.append(name)
    except Exception:  # noqa: BLE001
        pass
    for module, f in _findings(collected):
        meta = f.get("metadata") or {}
        if module == "github_commits" and meta.get("name"):
            names.append(str(meta["name"]))
        if module == "username_platforms" and meta.get("core") and meta.get("display_name"):
            names.append(str(meta["display_name"]))
    out = []
    for n in names:
        words = _words(n)
        if len(words) >= 2 and max(map(len, words)) > 1 and n not in out:
            out.append(n)
    return out


def names_match(a: Any, b: Any) -> bool:
    """First and last name agree (case-insensitive); middle names ignored; an initial
    matches a full first name."""
    wa, wb = _words(a), _words(b)
    if len(wa) < 2 or len(wb) < 2 or wa[-1] != wb[-1]:
        return False
    fa, fb = wa[0], wb[0]
    return fa == fb or (len(fa) == 1 and fb.startswith(fa)) or (len(fb) == 1 and fa.startswith(fb))


def _norm_url(url: str) -> str:
    return re.sub(r"^https?://(www\.)?", "", str(url).lower()).rstrip("/")


def known_context(collected: dict[str, Any]) -> dict[str, set[str]]:
    ctx: dict[str, set[str]] = {"countries": set(), "cities": set(), "employers": set(),
                                "schools": set(), "urls": set(), "handles": set()}
    for module, f in _findings(collected):
        if module == "linkedin_brightdata":
            continue
        meta = f.get("metadata") or {}
        loc = meta.get("location_normalized") or normalize_location(meta.get("location")) or {}
        if loc.get("country_code"):
            ctx["countries"].add(loc["country_code"])
        if loc.get("city"):
            ctx["cities"].add(str(loc["city"]).lower())
        for key in ("employer", "company", "current_company", "organization"):
            if meta.get(key):
                ctx["employers"].add(str(meta[key]).lower().strip())
        for key in ("school", "education"):
            for s in _strings(meta.get(key)):
                ctx["schools"].add(s.lower().strip())
        for url in _strings([f.get("profile_url"), meta.get("links")]):
            if url.startswith("http"):
                ctx["urls"].add(_norm_url(url))
        for h in _strings(meta.get("other_handles")):
            ctx["handles"].add(h.lower())
        if module == "username_platforms" and f.get("username"):
            ctx["handles"].add(str(f["username"]).lower())
    return ctx


def confirmed_profile_count(collected: dict[str, Any]) -> int:
    seen = set()
    for module, f in _findings(collected):
        if module in ("username_platforms", "github_commits") and str(
            f.get("confidence") or ""
        ).lower() in ("medium", "high"):
            seen.add((module, str(f.get("platform") or "").lower()))
    return len(seen)


def second_detail(card: dict[str, Any], ctx: dict[str, set[str]]) -> str | None:
    loc = card.get("location_normalized") or {}
    if loc.get("city") and str(loc["city"]).lower() in ctx["cities"]:
        return "city"
    if loc.get("country_code") and loc["country_code"] in ctx["countries"]:
        return "country"
    company = str(card.get("current_company") or "").lower().strip()
    if company and any(company in e or e in company for e in ctx["employers"] if len(e) > 2):
        return "company"
    for edu in card.get("education") or []:
        title = str(edu.get("title") or "").lower()
        if title and any(title in s or s in title for s in ctx["schools"] if len(s) > 3):
            return "school"
    for url in card.get("links") or []:
        if _norm_url(url) in ctx["urls"]:
            return "link_back"
        m = re.search(r"(?:github\.com|x\.com|twitter\.com|instagram\.com)/([^/?#]+)", url, re.I)
        if m and m.group(1).lower() in {h.split(":")[-1] for h in ctx["handles"]}:
            return "link_back"
    return None


def _text(value: Any, limit: int | None = None) -> str | None:
    text = scrub(value)
    if text and limit:
        text = text[:limit]
    return text


def extract_card(record: dict[str, Any], url: str) -> dict[str, Any]:
    """Only the card fields; everything else in the record is dropped here."""
    card: dict[str, Any] = {}
    name = record.get("name") or " ".join(
        x for x in (record.get("first_name"), record.get("last_name")) if x)
    if name and "@" not in str(name):
        card["display_name"] = _text(name)
    if record.get("headline"):
        card["headline"] = _text(record["headline"], 220)
    city = str(record.get("city") or "").strip()
    parts = [city] + [str(record.get(k) or "").strip() for k in ("state", "country")
                      if record.get(k) and str(record.get(k)) not in city]
    loc_raw = ", ".join(p for p in parts if p)
    loc = normalize_location(loc_raw) if loc_raw else None
    if loc_raw and loc is not None:
        card["location"] = loc_raw
        code = country_code(str(record.get("country_code") or ""))
        if code and "country_code" not in loc:
            loc["country_code"] = code
        card["location_normalized"] = loc
    elif record.get("country_code") and country_code(str(record["country_code"])):
        card["location_normalized"] = {"country_code": country_code(str(record["country_code"]))}
    for key, src in (("avatar_url", ("profile_photo", "avatar")), ("banner_url", ("cover_photo", "banner_image"))):
        val = next((record.get(s) for s in src if record.get(s)), None)
        if isinstance(val, str) and val.startswith("http"):
            card[key] = val
    if record.get("about"):
        card["bio"] = _text(record["about"], 2000)
    company = record.get("current_company")
    company_name = company.get("name") if isinstance(company, dict) else record.get("current_company_name")
    if company_name:
        card["current_company"] = _text(company_name)
    edu = []
    for e in record.get("education") or []:
        if isinstance(e, dict) and e.get("title"):
            edu.append({k: e.get(k) for k in ("title", "start_year", "end_year") if e.get(k)})
    if edu:
        card["education"] = edu
    certs = [c.get("name") or c.get("title") for c in record.get("certifications") or []
             if isinstance(c, dict) and (c.get("name") or c.get("title"))]
    if certs:
        card["certifications"] = certs
    for key, src in (("followers", ("followers_count", "followers")),
                     ("connections", ("connections_count", "connections"))):
        val = next((record.get(s) for s in src if record.get(s) is not None), None)
        if to_count(val) is not None:
            card[key] = to_count(val)
    links = []
    for w in record.get("websites") or []:
        u = w.get("url") if isinstance(w, dict) else w
        if isinstance(u, str) and u.strip():
            links.append(u.strip() if u.startswith("http") else "https://" + u.strip())
    if links:
        card["links"] = links
    orgs = [o.get("title") or o.get("name") for o in record.get("organizations") or []
            if isinstance(o, dict) and (o.get("title") or o.get("name"))]
    if orgs:
        card["organizations"] = orgs
    posts = []
    for p in (record.get("posts") or [])[:3]:
        text = p.get("text") or p.get("title") if isinstance(p, dict) else None
        if text and _text(text, 200):
            posts.append(_text(text, 200))
    if posts:
        card["recent_posts"] = posts
    card["linkedin_url"] = url
    card["field_sources"] = {k: url for k in card if k not in ("linkedin_url", "location_normalized")}
    return card


def _cache_path(url: str) -> Path:
    return _CACHE_DIR / f"{hashlib.sha256(url.encode()).hexdigest()}.json"


def _cache_read(url: str) -> dict[str, Any] | None:
    path = _cache_path(url)
    try:
        if time.time() - path.stat().st_mtime > settings.brightdata_cache_days * 86400:
            return None
        return json.loads(path.read_text(encoding="utf-8")).get("card")
    except (OSError, ValueError):
        return None


def _cache_write(url: str, card: dict[str, Any]) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(url).write_text(json.dumps({"url": url, "card": card}), encoding="utf-8")
    except OSError:
        pass


class LinkedInBrightDataModule(BaseModule):
    name = "linkedin_brightdata"
    description = "LinkedIn profile card via Bright Data (Pro; needs BRIGHTDATA_API_KEY)."
    requires_key = True

    async def run(self, email: str, collected: dict[str, Any] | None = None) -> ModuleResult:
        if collected is None:
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["Runs in the profile phase only"])
        if not brightdata_active():
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["Bright Data is not configured"])
        found = find_profile_url(collected)
        if not found:
            return ModuleResult(status=ModuleStatus.SKIPPED, errors=["No LinkedIn profile URL found"])
        url, url_source = found
        names = known_names(collected)
        if not names:
            return ModuleResult(status=ModuleStatus.SKIPPED,
                                errors=["No confirmed name to match a LinkedIn profile against"])
        card = _cache_read(url)
        from_cache = card is not None
        if card is None:
            record = await fetch_profile(url)  # the one Bright Data call of this run
            if not record:
                return ModuleResult(status=ModuleStatus.SUCCESS_EMPTY,
                                    metadata={"url_source": url_source, "calls": 1})
            card = extract_card(record, url)
            _cache_write(url, card)
        meta_out = {"url_source": url_source, "from_cache": from_cache, "calls": 0 if from_cache else 1}
        matched = next((n for n in names if names_match(card.get("display_name"), n)), None)
        if not matched:
            return ModuleResult(status=ModuleStatus.SUCCESS_EMPTY,
                                metadata={**meta_out, "discarded": "name_mismatch"})
        detail = second_detail(card, known_context(collected))
        profiles = confirmed_profile_count(collected)
        if detail is None and profiles >= _MIN_PROFILES_FOR_STRICT:
            return ModuleResult(status=ModuleStatus.SUCCESS_EMPTY,
                                metadata={**meta_out, "discarded": "no_second_detail"})
        slug = url.rstrip("/").rsplit("/", 1)[-1]
        finding = {
            "platform": "LinkedIn",
            "profile_url": url,
            "username": slug,
            "confidence": "high" if detail else "medium",
            "source": "linkedin_brightdata",
            "metadata": {
                **card,
                "match": {"name": matched, "second_detail": detail,
                          "other_confirmed_profiles": profiles},
                "verification": "corroborated" if detail else "unverified",
                "url_source": url_source,
                "provider": "brightdata",
                "from_cache": from_cache,
            },
        }
        return ModuleResult(status=ModuleStatus.SUCCESS, findings=[finding], metadata=meta_out)
