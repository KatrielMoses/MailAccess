from __future__ import annotations

import asyncio
import re
from html import unescape
from typing import Any
from urllib.parse import urlparse

import httpx

from ..core.http_client import build_client
from ..core.phone_extractor import normalize_phone
from .base import BaseModule, ModuleResult, ModuleStatus
from .domain_intel import _FREE_PROVIDERS

_DDG_HTML = "https://html.duckduckgo.com/html/"
_PRESS_QUERIES = (
    'site:prnewswire.com "{domain}"',
    'site:businesswire.com "{domain}"',
    'site:globenewswire.com "{domain}"',
)
_PHONE_RE = re.compile(r"\+?[\d\s\-\(\)\.]{10,20}")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
_CONTACT_MARKER_RE = re.compile(
    r"(contact:|media contact:|for more information:)", re.I
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_LINK_RE = re.compile(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")


class PressIntelModule(BaseModule):
    name = "press_intel"
    description = "Search public press release archives for contact phones tied to a domain."
    requires_key = False
    default_enabled = False

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@", 1)[1].lower() if "@" in email else ""
        if not domain or domain in _FREE_PROVIDERS:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"domain": domain},
                errors=["free provider"],
            )

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        seen_urls: set[str] = set()

        async with build_client(timeout=10.0, follow_redirects=True) as client:
            for query_template in _PRESS_QUERIES:
                if len(seen_urls) >= 3:
                    break
                query = query_template.format(domain=domain)
                urls, error = await _duckduckgo_urls(client, query)
                if error:
                    errors.append(error)
                    if "captcha" in error.lower():
                        return ModuleResult(
                            status=ModuleStatus.PARTIAL,
                            findings=findings,
                            metadata={"domain": domain, "press_releases_fetched": len(seen_urls)},
                            errors=errors,
                        )
                for url in urls:
                    if len(seen_urls) >= 3:
                        break
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    await asyncio.sleep(2.0)
                    release_findings, release_error = await _fetch_release(client, url)
                    if release_error:
                        errors.append(release_error)
                    findings.extend(release_findings)

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL
        return ModuleResult(
            status=status,
            findings=_dedupe_findings(findings),
            metadata={"domain": domain, "press_releases_fetched": len(seen_urls)},
            errors=errors,
        )


async def _duckduckgo_urls(
    client: httpx.AsyncClient, query: str
) -> tuple[list[str], str | None]:
    try:
        resp = await client.get(_DDG_HTML, params={"q": query})
    except httpx.TimeoutException:
        return [], "DuckDuckGo press search timed out"
    except Exception as exc:
        return [], f"DuckDuckGo press search error: {exc}"
    if resp.status_code in (403, 429):
        return [], "DuckDuckGo CAPTCHA or rate limit"
    if resp.status_code != 200:
        return [], f"DuckDuckGo press search HTTP {resp.status_code}"

    urls: list[str] = []
    for href, _label in _LINK_RE.findall(resp.text):
        href = unescape(href)
        if "duckduckgo.com/l/?" in href:
            continue
        host = urlparse(href).netloc.lower()
        if any(host.endswith(site) for site in ("prnewswire.com", "businesswire.com", "globenewswire.com")):
            urls.append(href)
        if len(urls) >= 3:
            break
    return urls, None


async def _fetch_release(
    client: httpx.AsyncClient, url: str
) -> tuple[list[dict[str, Any]], str | None]:
    try:
        resp = await client.get(url)
    except httpx.TimeoutException:
        return [], f"Press release timed out: {url}"
    except Exception as exc:
        return [], f"Press release fetch error: {exc}"
    if resp.status_code != 200:
        return [], f"Press release HTTP {resp.status_code}: {url}"

    title = _extract_title(resp.text)
    text = _html_text(resp.text)
    contact_block = _contact_block(text)
    if not contact_block:
        return [], None

    contact_name = _extract_contact_name(contact_block)
    findings: list[dict[str, Any]] = []
    for match in _PHONE_RE.finditer(contact_block):
        phone = normalize_phone(match.group(0))
        if not phone:
            continue
        findings.append(
            {
                "platform": "press_release",
                "signal_type": "phone_number",
                "confidence": "medium",
                "metadata": {
                    "phone": phone,
                    "contact_name": contact_name,
                    "contact_email": _extract_email(contact_block),
                    "source_url": url,
                    "press_release_title": title,
                },
            }
        )
    return findings, None


def _html_text(html: str) -> str:
    text = _TAG_RE.sub(" ", html)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def _extract_title(html: str) -> str:
    match = _TITLE_RE.search(html)
    if not match:
        return ""
    return re.sub(r"\s+", " ", unescape(_TAG_RE.sub(" ", match.group(1)))).strip()


def _contact_block(text: str) -> str:
    match = _CONTACT_MARKER_RE.search(text)
    if not match:
        return ""
    start = match.start()
    return text[start : start + 900]


def _extract_contact_name(block: str) -> str | None:
    after_marker = _CONTACT_MARKER_RE.sub("", block, count=1).strip()
    first_sentence = re.split(r"\s{2,}|[|]", after_marker, maxsplit=1)[0]
    first_sentence = _EMAIL_RE.sub("", first_sentence)
    first_sentence = _PHONE_RE.sub("", first_sentence).strip(" -:,;")
    return first_sentence[:80] or None


def _extract_email(block: str) -> str | None:
    match = _EMAIL_RE.search(block)
    return match.group(0) if match else None


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for finding in findings:
        meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        key = (str(meta.get("phone") or ""), str(meta.get("source_url") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
