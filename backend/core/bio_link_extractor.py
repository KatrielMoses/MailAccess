from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import httpx

_AGGREGATOR_PATTERNS: dict[str, str] = {
    "linktr.ee": "linktree",
    "about.me": "about_me",
    "beacons.ai": "beacons",
    "bio.link": "bio_link",
    "linkin.bio": "linkin_bio",
    "campsite.bio": "campsite",
    "allmylinks.com": "allmylinks",
}

_SOCIAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:twitter|x)\.com/(?!intent|share|home)([A-Za-z0-9_]{1,50})"), "twitter"),
    (re.compile(r"instagram\.com/([A-Za-z0-9_.]{1,50})/?$"), "instagram"),
    (re.compile(r"github\.com/([A-Za-z0-9\-]{1,100})/?$"), "github"),
    (re.compile(r"linkedin\.com/in/([A-Za-z0-9\-_%]{1,100})"), "linkedin"),
    (re.compile(r"facebook\.com/([A-Za-z0-9.\-]{1,100})/?$"), "facebook"),
    (re.compile(r"youtube\.com/@([A-Za-z0-9_.\-]{1,100})"), "youtube"),
    (re.compile(r"tiktok\.com/@([A-Za-z0-9_.]{1,50})"), "tiktok"),
    (re.compile(r"twitch\.tv/([A-Za-z0-9_]{1,50})/?$"), "twitch"),
]


@dataclass
class ExtractedLink:
    url: str
    platform: str
    handle: str
    link_type: str  # social / phone / email / whatsapp / website


def aggregator_name(url: str) -> str | None:
    """Return the aggregator slug if the URL matches a known bio-link page, else None."""
    for domain, name in _AGGREGATOR_PATTERNS.items():
        if domain in url:
            return name
    return None


async def extract_from_aggregator(
    url: str, client: httpx.AsyncClient
) -> list[ExtractedLink]:
    """Fetch an aggregator page and return all outbound links found."""
    try:
        resp = await client.get(url, follow_redirects=True, timeout=8.0)
        if resp.status_code != 200:
            return []
        html = resp.text
    except Exception:
        return []

    raw_urls: list[str] = []

    # Try parsing __NEXT_DATA__ JSON blob (Linktree, Campsite etc.)
    m = re.search(r'<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL)
    if m:
        try:
            data = json.loads(m.group(1))
            raw_urls.extend(_urls_from_json(data))
        except Exception:
            pass

    # Try JSON-LD
    for ld_match in re.finditer(
        r'<script[^>]*type="application/ld\+json"[^>]*>(.*?)</script>', html, re.DOTALL
    ):
        try:
            data = json.loads(ld_match.group(1))
            raw_urls.extend(_urls_from_json(data))
        except Exception:
            pass

    # Fallback: scan raw HTML for tel:, mailto:, https: href values
    raw_urls += re.findall(r'href=["\']([^"\']+)["\']', html)

    return _classify_links(raw_urls)


def _classify_links(raw_urls: list[str]) -> list[ExtractedLink]:
    links: list[ExtractedLink] = []
    seen: set[str] = set()

    for raw in raw_urls:
        raw = raw.strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)

        if raw.startswith("tel:"):
            phone = raw[4:].strip()
            if phone:
                links.append(ExtractedLink(url=raw, platform="phone", handle=phone, link_type="phone"))
        elif raw.startswith("mailto:"):
            email = raw[7:].strip().split("?")[0]
            if email:
                links.append(ExtractedLink(url=raw, platform="email", handle=email, link_type="email"))
        elif "wa.me/" in raw:
            m = re.search(r"wa\.me/(\d+)", raw)
            phone = m.group(1) if m else ""
            links.append(ExtractedLink(url=raw, platform="whatsapp", handle=phone, link_type="whatsapp"))
        elif raw.startswith("http"):
            matched = False
            for pattern, platform in _SOCIAL_PATTERNS:
                m2 = pattern.search(raw)
                if m2:
                    handle = m2.group(1).rstrip("/")
                    links.append(ExtractedLink(url=raw, platform=platform, handle=handle, link_type="social"))
                    matched = True
                    break
            if not matched:
                links.append(ExtractedLink(url=raw, platform="website", handle="", link_type="website"))

    return links


def _urls_from_json(data: Any, depth: int = 0) -> list[str]:
    """Walk a JSON structure and collect URL-like strings."""
    if depth > 12:
        return []
    out: list[str] = []
    if isinstance(data, dict):
        for v in data.values():
            out.extend(_urls_from_json(v, depth + 1))
    elif isinstance(data, list):
        for item in data:
            out.extend(_urls_from_json(item, depth + 1))
    elif isinstance(data, str):
        s = data.strip()
        if s.startswith(("http://", "https://", "tel:", "mailto:")):
            out.append(s)
    return out
