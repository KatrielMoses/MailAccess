"""Generic profile extraction from a public HTML page: og:/twitter: meta tags, JSON-LD
(Person / ProfilePage, with interactionStatistic follower counts and sameAs links) and
schema.org microdata (itemprop name / homeLocation / url). Used for every site without
its own parser, and as the base most site parsers build on."""

from __future__ import annotations

import html as html_lib
import json
import re
from typing import Any

from .fields import Profile

_META = re.compile(r"<meta\s+([^>]+?)/?>", re.I | re.S)
_ATTR = re.compile(r'([a-zA-Z:_-]+)\s*=\s*("([^"]*)"|\'([^\']*)\')', re.S)
_LD = re.compile(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.I | re.S)
_ITEMPROP = re.compile(r'itemprop="(name|homeLocation|addressLocality|url|description)"[^>]*>(.*?)</', re.I | re.S)
_TAG = re.compile(r"<[^>]+>")


def meta_tags(body: str) -> dict[str, str]:
    """``og:title`` / ``twitter:image`` / ``description`` … → content (first wins)."""
    out: dict[str, str] = {}
    for m in _META.finditer(body[:400_000]):
        attrs = {a.group(1).lower(): (a.group(3) if a.group(3) is not None else a.group(4))
                 for a in _ATTR.finditer(m.group(1))}
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key and "content" in attrs and key not in out:
            out[key] = html_lib.unescape(attrs["content"]).strip()
    return out


def json_ld(body: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for m in _LD.finditer(body):
        try:
            data = json.loads(m.group(1).strip())
        except ValueError:
            continue
        stack = data if isinstance(data, list) else [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                items.append(node)
                for key in ("@graph", "mainEntity", "author"):
                    child = node.get(key)
                    if isinstance(child, (dict, list)):
                        stack.extend(child if isinstance(child, list) else [child])
            elif isinstance(node, list):
                stack.extend(node)
    return items


def _person(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    for item in items:
        kind = item.get("@type")
        kinds = kind if isinstance(kind, list) else [kind]
        if any(k in ("Person", "ProfilePage") for k in kinds):
            return item.get("mainEntity") if isinstance(item.get("mainEntity"), dict) else item
    return None


def parse_html(body: str, url: str, profile: Profile | None = None) -> Profile:
    """Name/bio/avatar/location through the existing tuned extractor (site-suffix and
    junk-title filtering, person-name plausibility), plus JSON-LD counts and sameAs
    links and microdata location, which it doesn't read."""
    from ..profile_extractor import extract_profile

    p = profile or Profile()
    if not body:
        return p
    base = extract_profile(body, url) or {}
    p.set("name", base.get("display_name"), url)
    p.set("avatar", base.get("avatar_url"), url)
    p.set("bio", base.get("bio"), url)
    p.set("location", base.get("location"), url)
    person = _person(json_ld(body))
    if person:
        address = person.get("address") or person.get("homeLocation")
        if isinstance(address, dict):
            locality = address.get("addressLocality") or address.get("name")
            country = address.get("addressCountry")
            country = country.get("name") if isinstance(country, dict) else country
            p.set("location", ", ".join(str(x) for x in (locality, country) if x), url)
        stats = person.get("interactionStatistic") or []
        for stat in stats if isinstance(stats, list) else [stats]:
            if not isinstance(stat, dict):
                continue
            kind = stat.get("interactionType") or ""
            kind = kind.get("@type", "") if isinstance(kind, dict) else str(kind)
            if "Follow" in kind:
                p.set("followers", stat.get("userInteractionCount"), url)
            elif "Write" in kind or "Create" in kind:
                p.set("posts", stat.get("userInteractionCount"), url)
        same_as = person.get("sameAs")
        p.add_links(same_as if isinstance(same_as, list) else [same_as] if same_as else [], url)
    for prop, raw in _ITEMPROP.findall(body[:600_000]):
        if prop.lower() in ("homelocation", "addresslocality"):
            p.set("location", html_lib.unescape(_TAG.sub(" ", raw)).strip(), url)
    return p
