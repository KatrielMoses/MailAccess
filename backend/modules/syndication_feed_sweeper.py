from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree as ET

import httpx

from ..config import settings
from ..core.concurrent_fetch_cache import CachedFetch
from ..core.signal_normalize import normalize_slug_or_email
from ..core.signal_pool import AsyncSignalPool, Signal
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_ATOM_NS = "http://www.w3.org/2005/Atom"
_DC_NS = "http://purl.org/dc/elements/1.1/"
_EMAIL_RE = re.compile(
    r"([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})",
    flags=re.IGNORECASE,
)
_MAX_FEEDS = 6


def _normalize_target(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return ""
    if "@" in raw and "://" not in raw:
        raw = raw.rsplit("@", 1)[-1].strip()
    if "://" in raw:
        parsed = urlsplit(raw)
        host = parsed.netloc.strip()
        if not host:
            return ""
        scheme = parsed.scheme or "https"
        return urlunsplit((scheme, host, "", "", "")).rstrip("/")
    return f"https://{raw.rstrip('/')}"


def _clean_text(value: Any) -> str:
    text = unescape(str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower() if "}" in tag else tag.lower()


def _namespace_uri(tag: str) -> str:
    if tag.startswith("{") and "}" in tag:
        return tag[1 : tag.index("}")]
    return ""


def _split_author_text(text: Any) -> tuple[str | None, str | None]:
    cleaned = _clean_text(text)
    if not cleaned:
        return None, None
    match = _EMAIL_RE.search(cleaned)
    if not match:
        return cleaned or None, None

    email = match.group(1).lower().strip()
    remainder = f"{cleaned[: match.start()]} {cleaned[match.end() :]}"
    remainder = remainder.replace("<", " ").replace(">", " ")
    remainder = remainder.replace("(", " ").replace(")", " ")
    remainder = remainder.replace("[", " ").replace("]", " ")
    remainder = re.sub(r"(?i)\bmailto:\b", " ", remainder)
    name = _clean_text(remainder)
    return (name or None), email


def _feed_links_from_html(html: str, base_url: str) -> list[str]:
    class _Parser(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.links: list[str] = []

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag.lower() != "link":
                return
            attr_map = {key.lower(): (value or "") for key, value in attrs}
            rel = attr_map.get("rel", "").lower().split()
            mime = attr_map.get("type", "").lower()
            href = attr_map.get("href", "").strip()
            if "alternate" not in rel or not href:
                return
            if not (
                mime.startswith("application/rss+xml")
                or mime.startswith("application/atom+xml")
            ):
                return
            self.links.append(urljoin(base_url, href))

    parser = _Parser()
    parser.feed(html or "")
    return list(dict.fromkeys(parser.links))


def _fallback_feed_urls(origin: str) -> list[str]:
    root = origin.rstrip("/") + "/"
    return [urljoin(root, "feed/"), urljoin(root, "rss/")]


def _item_elements(root: ET.Element) -> list[ET.Element]:
    return [
        elem
        for elem in root.iter()
        if _local_name(elem.tag) in {"item", "entry"}
    ]


def _element_text(elem: ET.Element) -> str:
    return _clean_text("".join(elem.itertext()))


def _extract_item_link(item: ET.Element) -> str:
    for elem in item.iter():
        if _local_name(elem.tag) != "link":
            continue
        href = (
            elem.attrib.get("href")
            or elem.attrib.get("{http://www.w3.org/1999/xlink}href")
            or ""
        ).strip()
        if href:
            return href
        text = _element_text(elem)
        if text:
            return text
    return ""


def _extract_item_title(item: ET.Element) -> str:
    for elem in item.iter():
        if _local_name(elem.tag) == "title":
            text = _element_text(elem)
            if text:
                return text
    return ""


@dataclass(slots=True)
class _IdentityCandidate:
    name: str | None = None
    email: str | None = None
    source_fields: set[str] = field(default_factory=set)


def _merge_candidate(
    candidates: dict[tuple[str | None, str | None], _IdentityCandidate],
    *,
    name: str | None,
    email: str | None,
    source_field: str,
) -> None:
    key = (name or None, email or None)
    candidate = candidates.get(key)
    if candidate is None:
        candidate = _IdentityCandidate(name=name, email=email)
        candidates[key] = candidate
    if name and not candidate.name:
        candidate.name = name
    if email and not candidate.email:
        candidate.email = email
    candidate.source_fields.add(source_field)


def _extract_candidates(item: ET.Element) -> list[_IdentityCandidate]:
    candidates: dict[tuple[str | None, str | None], _IdentityCandidate] = {}
    for elem in item.iter():
        local = _local_name(elem.tag)
        ns = _namespace_uri(elem.tag)
        if local == "author":
            name, email = _split_author_text(_element_text(elem))
            if name or email:
                _merge_candidate(candidates, name=name, email=email, source_field="author")
        elif local == "creator" and ns == _DC_NS:
            name, email = _split_author_text(_element_text(elem))
            if name or email:
                _merge_candidate(
                    candidates,
                    name=name,
                    email=email,
                    source_field="dc:creator",
                )
        elif local == "email" and ns == _ATOM_NS:
            email = _split_author_text(_element_text(elem))[1]
            if email:
                _merge_candidate(
                    candidates,
                    name=None,
                    email=email,
                    source_field="atom:email",
                )

    return list(candidates.values())


async def _fetch_text(fetch: Any, url: str) -> tuple[int, str, dict[str, str]]:
    response = await fetch.get(url)
    status = int(getattr(response, "status_code", 0) or 0)
    text = str(getattr(response, "text", "") or "")
    headers_raw = getattr(response, "headers", {}) or {}
    headers = {str(k): str(v) for k, v in dict(headers_raw).items()}
    return status, text, headers


class SyndicationFeedSweeper(BaseModule):
    name = "syndication_feed_sweeper"
    description = "Discover feed authors from RSS and Atom syndication feeds."
    requires_key = False
    default_enabled = False

    async def run(
        self,
        target: str,
        *,
        fetch: CachedFetch | None = None,
        pool: AsyncSignalPool | None = None,
        **_unused: Any,
    ) -> ModuleResult:  # type: ignore[override]
        if not getattr(settings, "enable_syndication_feed_sweeper", False):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={
                    "skip_reason": "disabled_by_configuration",
                    "failure_categories": ["configuration"],
                    "health_category": "configuration",
                },
                errors=[
                    "syndication_feed_sweeper disabled â€” set "
                    "ENABLE_SYNDICATION_FEED_SWEEPER=true to enable"
                ],
            )

        origin = _normalize_target(target)
        if not origin:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["syndication_feed_sweeper: invalid target"],
                metadata={"skip_reason": "invalid_target", "target": target},
            )

        owns_client = False
        client: Any = fetch
        if client is None:
            client = httpx.AsyncClient(follow_redirects=True, timeout=10.0)
            owns_client = True

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        feed_urls_attempted: list[str] = []
        discovered_feed_urls: list[str] = []
        homepage_url = f"{origin.rstrip('/')}/"
        homepage_html = ""
        feeds_fetched = 0
        items_scanned = 0
        names_found = 0
        emails_found = 0
        signals_published = 0
        fallback_used = False

        try:
            try:
                status, text, _headers = await _fetch_text(client, homepage_url)
                if status == 200:
                    homepage_html = text
                elif status and status not in {404}:
                    errors.append(
                        f"syndication_feed_sweeper: homepage returned HTTP {status}"
                    )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"syndication_feed_sweeper: homepage fetch failed: {exc}")

            discovered_feed_urls = _feed_links_from_html(homepage_html, homepage_url)
            feed_urls = list(discovered_feed_urls)
            if not feed_urls:
                feed_urls = _fallback_feed_urls(origin)
                fallback_used = True

            async def process_feed_urls(urls: list[str]) -> None:
                nonlocal feeds_fetched, items_scanned, names_found, emails_found
                nonlocal signals_published
                for feed_url in urls[:_MAX_FEEDS]:
                    if feed_url in feed_urls_attempted:
                        continue
                    feed_urls_attempted.append(feed_url)
                    try:
                        status, xml_text, _headers = await _fetch_text(client, feed_url)
                    except Exception as exc:  # noqa: BLE001
                        errors.append(
                            f"syndication_feed_sweeper: fetch failed for {feed_url}: {exc}"
                        )
                        continue
                    if status == 404:
                        continue
                    if status != 200:
                        errors.append(
                            f"syndication_feed_sweeper: feed returned HTTP {status} for {feed_url}"
                        )
                        continue
                    try:
                        root = ET.fromstring(xml_text)
                    except Exception as exc:  # noqa: BLE001
                        errors.append(
                            f"syndication_feed_sweeper: invalid XML at {feed_url}: {exc}"
                        )
                        continue

                    feeds_fetched += 1
                    item_urls = _item_elements(root)
                    for item in item_urls:
                        items_scanned += 1
                        item_title = _extract_item_title(item)
                        item_link = _extract_item_link(item) or feed_url
                        candidates = _extract_candidates(item)
                        item_email = next(
                            (candidate.email for candidate in candidates if candidate.email),
                            None,
                        )
                        shared_slug_or_email = (
                            normalize_slug_or_email(item_email) if item_email else None
                        )
                        for candidate in candidates:
                            name = candidate.name
                            email = candidate.email
                            if not name and not email:
                                continue
                            slug_or_email = (
                                shared_slug_or_email
                                or email
                                or normalize_slug_or_email(name)
                            )
                            metadata: dict[str, Any] = {
                                "source": self.name,
                                "feed_url": feed_url,
                                "item_url": item_link,
                                "item_title": item_title or None,
                                "name": name,
                                "email": email,
                                "slug_or_email": slug_or_email,
                                "source_fields": sorted(candidate.source_fields),
                                "source_type": "+".join(sorted(candidate.source_fields)),
                            }
                            if email:
                                metadata["on_domain"] = email.lower().endswith(
                                    f"@{origin.split('://', 1)[-1]}"
                                )
                            finding: dict[str, Any] = {
                                "platform": self.name,
                                "profile_url": item_link,
                                "username": (
                                    email.split("@", 1)[0]
                                    if email and "@" in email
                                    else (normalize_slug_or_email(name) or "")
                                ),
                                "confidence": "high" if email else "medium",
                                "metadata": metadata,
                            }
                            findings.append(finding)
                            page_signals: list[Signal] = []
                            if name:
                                page_signals.append(
                                    Signal(
                                        source=self.name,
                                        kind="name",
                                        value=name,
                                        metadata=metadata,
                                    )
                                )
                                names_found += 1
                            if email:
                                page_signals.append(
                                    Signal(
                                        source=self.name,
                                        kind="email",
                                        value=email,
                                        metadata=metadata,
                                    )
                                )
                                emails_found += 1
                            if pool is not None and page_signals:
                                await pool.publish_many(page_signals)
                                signals_published += len(page_signals)

            await process_feed_urls(feed_urls)

            if not findings and discovered_feed_urls:
                fallback_urls = _fallback_feed_urls(origin)
                extra_fallback = [
                    url for url in fallback_urls if url not in feed_urls_attempted
                ]
                if extra_fallback:
                    fallback_used = True
                    await process_feed_urls(extra_fallback)
        finally:
            if owns_client:
                close = getattr(client, "aclose", None)
                if callable(close):
                    result = close()
                    if hasattr(result, "__await__"):
                        await result

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL if findings else ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            errors=errors,
            metadata={
                "target": origin,
                "homepage_url": homepage_url,
                "feeds_discovered": len(discovered_feed_urls),
                "feeds_fetched": feeds_fetched,
                "items_scanned": items_scanned,
                "names_found": names_found,
                "emails_found": emails_found,
                "signals_published": signals_published,
                "feed_urls": feed_urls_attempted,
                "fallback_used": fallback_used,
            },
        )
