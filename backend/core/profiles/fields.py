"""The profile field set (UC3) and the rules every parser's output goes through.

Fields: name, username, avatar, banner, bio, location, joined, last_active, followers,
following, posts, links, other_handles, verified. Each one keeps the URL it came from
(``field_sources``). Values are typed and cleaned here, once, for every parser:

* dates become ISO-8601 (from epoch seconds/ms or ISO strings);
* counts become ints (``"1.2k"`` → 1200);
* default / placeholder avatars and banners are dropped;
* a name that is an email address is dropped;
* phone numbers and street addresses are never stored: bios have them cut out, a
  location that looks like one is refused, and only city/region/country are normalised;
* links and LinkedIn URLs found in bios are kept; other handles are derived from links.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .geo import looks_private, normalize_location

# Metadata key per field (the keys findings already use for name/bio/avatar/location).
FIELD_KEYS: dict[str, str] = {
    "name": "display_name",
    "username": "profile_username",
    "avatar": "avatar_url",
    "banner": "banner_url",
    "bio": "bio",
    "location": "location",
    "joined": "joined_at",
    "last_active": "last_active_at",
    "followers": "followers",
    "following": "following",
    "posts": "posts",
    "links": "links",
    "other_handles": "other_handles",
    "verified": "verified",
}

_DEFAULT_IMAGE = re.compile(
    r"default|no-avatar|no_avatar|no-title|placeholder|blank|anonymous|silhouette|"
    r"twitter-share|social-share|pplogo|og-images|og_image|logo|personalProfileImage|"
    r"opengraph-image|/web/deeplink/snapcode",
    re.I,
)
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_LINKEDIN = re.compile(r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:in|pub)/[^\s/?#<>\"']+", re.I)
_HANDLE_HOSTS = {
    "twitter.com": "x", "x.com": "x", "github.com": "github", "gitlab.com": "gitlab",
    "instagram.com": "instagram", "linkedin.com": "linkedin", "facebook.com": "facebook",
    "youtube.com": "youtube", "medium.com": "medium", "t.me": "telegram",
    "tiktok.com": "tiktok", "reddit.com": "reddit", "twitch.tv": "twitch",
}


def to_iso(value: Any) -> str | None:
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        ts = float(value)
        if ts > 1e12:  # milliseconds
            ts /= 1000
        if not 0 < ts < 4e9:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    text = str(value).strip()
    for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%d", "%b %d, %Y", "%d %b %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def to_count(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value) if value >= 0 else None
    m = re.fullmatch(r"\s*([\d.,]+)\s*([kKmMbB]?)\s*", str(value))
    if not m:
        return None
    num = m.group(1).replace(",", "")
    try:
        n = float(num)
    except ValueError:
        return None
    n *= {"k": 1e3, "m": 1e6, "b": 1e9}.get(m.group(2).lower(), 1)
    return int(n)


def scrub(text: Any) -> str | None:
    """Plain text without phone numbers; None when nothing is left."""
    s = re.sub(r"\s+", " ", str(text or "")).strip()
    # A phone number has at least 9 digits; "2019-2020" or "5 years" are left alone.
    s = _PHONE.sub(lambda m: "" if sum(c.isdigit() for c in m.group()) >= 9 else m.group(), s)
    return s.strip(" ,;·-") or None


def handle_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = parsed.netloc.lower().removeprefix("www.").removeprefix("m.")
    site = _HANDLE_HOSTS.get(host)
    if not site:
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if site == "linkedin" and len(parts) >= 2 and parts[0] in ("in", "pub"):
        return f"linkedin:{parts[1]}"
    if parts and not parts[0].startswith(("?", "#")) and parts[0].lower() not in (
        "in", "pub", "channel", "user", "c", "share", "sharer", "intent", "home", "watch",
    ):
        return f"{site}:{parts[0].lstrip('@')}"
    return None


class Profile:
    """Collects fields with their source URLs; ``merge_into`` writes finding metadata."""

    def __init__(self) -> None:
        self.values: dict[str, Any] = {}
        self.sources: dict[str, str] = {}
        self.location_normalized: dict[str, str] | None = None

    def set(self, field: str, value: Any, source: str | None) -> None:
        if field not in FIELD_KEYS or field in self.values:
            return  # first parser to supply a field wins
        clean = self._clean(field, value)
        if clean is None:
            return
        self.values[field] = clean
        if source:
            self.sources[field] = source
        if field == "bio":
            self._links_from_text(clean, source)

    def add_links(self, urls: list[Any], source: str | None) -> None:
        for url in urls or []:
            url = str(url or "").strip()
            if not url:
                continue
            if not url.startswith("http"):
                url = "https://" + url.lstrip("/")
            links = self.values.setdefault("links", [])
            if url not in links:
                links.append(url)
                self.sources.setdefault("links", source or url)
            handle = handle_from_url(url)
            if handle:
                handles = self.values.setdefault("other_handles", [])
                if handle not in handles:
                    handles.append(handle)
                    self.sources.setdefault("other_handles", source or url)

    def _links_from_text(self, text: str, source: str | None) -> None:
        self.add_links(_URL.findall(text) + _LINKEDIN.findall(text), source)

    def _clean(self, field: str, value: Any) -> Any:
        if field in ("followers", "following", "posts"):
            return to_count(value)
        if field in ("joined", "last_active"):
            return to_iso(value)
        if field == "verified":
            return value if isinstance(value, bool) else None
        if field in ("avatar", "banner"):
            url = str(value or "").strip()
            if url.startswith("//"):
                url = "https:" + url
            if not url.startswith("http") or _DEFAULT_IMAGE.search(url):
                return None
            return url
        if field == "location":
            text = scrub(value)
            if not text or looks_private(text):
                return None
            self.location_normalized = normalize_location(text)
            return text
        if field == "name":
            text = scrub(value)
            return text if text and "@" not in text and len(text) <= 120 else None
        if field in ("bio", "username"):
            return scrub(value)
        return None

    def merge_into(self, meta: dict[str, Any]) -> None:
        for field, value in self.values.items():
            key = FIELD_KEYS[field]
            if value in (None, "", [], {}):
                continue
            meta[key] = value
        if self.location_normalized:
            meta["location_normalized"] = self.location_normalized
        linkedin = [u for u in self.values.get("links", []) if "linkedin.com/" in u]
        if linkedin:
            meta["linkedin_url"] = linkedin[0]
        if self.sources:
            meta["field_sources"] = {
                FIELD_KEYS[f]: s for f, s in self.sources.items() if f in self.values
            }
