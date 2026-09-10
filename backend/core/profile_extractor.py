"""Native profile-data extractor for username-URL probe hits.

A small, dependency-free extractor over the common open-graph / Twitter-card /
JSON-LD / ``<title>`` conventions that the large majority of profile pages
expose. It turns a probe hit's HTML into candidate person-data
(``display_name`` / ``bio`` / ``avatar_url`` / ``location``) using the metadata-key
convention already consumed by the identity graph and (for names) name-consensus.

Everything here is best-effort and must never raise — extraction failure degrades to an
empty dict, leaving the finding's existence signal untouched.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any
from urllib.parse import urlparse

from .name_quality import is_plausible_person_name

# ── meta tag scraping ────────────────────────────────────────────────────────
# Matches <meta ... property="og:title" ... content="..."> in either attribute order.
_META_RE = re.compile(
    r"<meta\b[^>]*?"
    r"(?:(?:property|name)\s*=\s*[\"']([^\"']+)[\"'][^>]*?content\s*=\s*[\"']([^\"']*)[\"']"
    r"|content\s*=\s*[\"']([^\"']*)[\"'][^>]*?(?:property|name)\s*=\s*[\"']([^\"']+)[\"'])",
    re.IGNORECASE | re.DOTALL,
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_JSONLD_RE = re.compile(
    r"<script[^>]*type\s*=\s*[\"']application/ld\+json[\"'][^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")

# Generic values that are never a person's real name/bio.
_JUNK = {
    "", "home", "login", "sign in", "sign up", "profile", "error", "not found",
    "404", "page not found", "access denied", "forbidden",
}
_MAX_NAME = 80
_MAX_BIO = 400


def _clean(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = html.unescape(_TAG_RE.sub(" ", value))
    return re.sub(r"\s+", " ", text).strip()


def _metas(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _META_RE.finditer(body):
        key = (m.group(1) or m.group(4) or "").strip().lower()
        val = m.group(2) if m.group(1) else m.group(3)
        if key and key not in out:
            cleaned = _clean(val)
            if cleaned:
                out[key] = cleaned
    return out


def _strip_name_artifacts(value: str, host: str) -> str:
    """Strip site suffixes and ``(@handle)`` artifacts off a raw display string.

    Applied to *every* display-name branch (``og:title`` / ``twitter:title`` /
    ``<title>`` / json-ld), not just ``<title>`` — otherwise a raw
    ``"Jane Doe (@jane) · GitHub"`` from ``og:title`` leaks straight into the
    finding and (because name-consensus used to label a cluster with its longest
    member) overwrites the real "Jane Doe".
    """
    title = _clean(value)
    # "Jane Doe (@jane) · GitHub" / "Jane Doe - Twitter" → strip the site suffix.
    for sep in ("·", "|", "—", "–", " - ", ":"):
        if sep in title:
            head = title.split(sep, 1)[0].strip()
            if head:
                title = head
                break
    return re.sub(r"\s*[(@][^)]*\)?\s*$", "", title).strip()


def _title_name(body: str, host: str) -> str:
    m = _TITLE_RE.search(body)
    if not m:
        return ""
    title = _strip_name_artifacts(m.group(1), host)
    return "" if title.lower() in _JUNK or host.split(".")[0] in title.lower() else title


def _jsonld_fields(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for block in _JSONLD_RE.findall(body):
        try:
            data = json.loads(block.strip())
        except (ValueError, TypeError):
            continue
        for node in data if isinstance(data, list) else [data]:
            if not isinstance(node, dict):
                continue
            name = node.get("name") or node.get("alternateName")
            if isinstance(name, str) and "display_name" not in out:
                cleaned = _clean(name)
                if cleaned and cleaned.lower() not in _JUNK:
                    out["display_name"] = cleaned
            desc = node.get("description")
            if isinstance(desc, str) and "bio" not in out:
                out["bio"] = _clean(desc)
            addr = node.get("address") or node.get("homeLocation")
            if isinstance(addr, dict):
                loc = addr.get("addressLocality") or addr.get("name")
                if isinstance(loc, str) and "location" not in out:
                    out["location"] = _clean(loc)
            image = node.get("image")
            if "avatar_url" not in out:
                if isinstance(image, str):
                    out["avatar_url"] = image.strip()
                elif isinstance(image, dict) and isinstance(image.get("url"), str):
                    out["avatar_url"] = image["url"].strip()
    return out


def extract_profile(body: str, final_url: str = "") -> dict[str, str]:
    """Best-effort person-data from a profile page. Never raises; may return ``{}``.

    Keys use the graph/name-consensus convention: ``display_name``, ``bio``,
    ``avatar_url``, ``location``.
    """
    if not body or not isinstance(body, str):
        return {}
    try:
        host = (urlparse(final_url).hostname or "").lower().removeprefix("www.")
        metas = _metas(body)
        jsonld = _jsonld_fields(body)
        result: dict[str, str] = {}

        # ``profile:username`` is a handle, not a person name, so it is no longer a
        # display-name source. Every remaining branch is artifact-stripped and then gated
        # through ``is_plausible_person_name`` — a probe-hit display name feeds
        # name-consensus as a person-name candidate, so a title/handle artifact that slips
        # through corrupts ``confirmed_name``.
        name = ""
        for candidate in (
            metas.get("og:title"),
            metas.get("twitter:title"),
            jsonld.get("display_name"),
            _title_name(body, host),
        ):
            stripped = _strip_name_artifacts(candidate or "", host)
            if (
                stripped
                and stripped.lower() not in _JUNK
                and len(stripped) <= _MAX_NAME
                and is_plausible_person_name(stripped)
            ):
                name = stripped
                break
        if name:
            result["display_name"] = name

        bio = (
            metas.get("og:description")
            or metas.get("description")
            or metas.get("twitter:description")
            or jsonld.get("bio")
        )
        bio = _clean(bio)
        if bio and bio.lower() not in _JUNK:
            result["bio"] = bio[:_MAX_BIO]

        avatar = metas.get("og:image") or metas.get("twitter:image") or jsonld.get("avatar_url")
        if avatar and str(avatar).startswith("http"):
            result["avatar_url"] = str(avatar).strip()

        location = metas.get("profile:location") or jsonld.get("location")
        location = _clean(location)
        if location and location.lower() not in _JUNK:
            result["location"] = location[:_MAX_NAME]

        return result
    except Exception:
        return {}
