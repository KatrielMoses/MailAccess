from __future__ import annotations

import re
from html import unescape
from typing import Any
from urllib.parse import urljoin

import httpx

from ..core.http_client import build_client
from ..core.phone_extractor import normalize_phone
from .base import BaseModule, ModuleResult, ModuleStatus
from .domain_intel import _FREE_PROVIDERS

_SEC_SEARCH = "https://efts.sec.gov/LATEST/search-index"
_PHONE_RE = re.compile(r"\+?[\d\s\-\(\)\.]{10,20}")
_TAG_RE = re.compile(r"<[^>]+>")
_DOC_LINK_RE = re.compile(r'href="([^"]+\.(?:htm|html|txt))"', re.I)


class SecEdgarModule(BaseModule):
    name = "sec_edgar"
    description = "Search SEC EDGAR filings for contact phones near the email domain."
    requires_key = False

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
        headers = {"User-Agent": "MailAccess/0.7.0 contact@example.com"}

        async with build_client(timeout=10.0, follow_redirects=True, headers=headers) as client:
            filing_urls, search_error = await _search_filings(client, f'"{domain}"')
            if search_error:
                errors.append(search_error)

            keyword = domain.rsplit(".", 1)[0]
            company_urls, company_error = await _search_filings(client, f'"{keyword}"', forms="10-K")
            if company_error:
                errors.append(company_error)

            seen_urls: set[str] = set()
            filings_fetched = 0
            for filing_url in [*filing_urls, *company_urls]:
                if len(seen_urls) >= 3:
                    break
                if filing_url in seen_urls:
                    continue
                seen_urls.add(filing_url)
                doc_url, index_error = await _primary_document_url(client, filing_url)
                if index_error:
                    errors.append(index_error)
                target_url = doc_url or filing_url
                release_findings, fetch_error = await _fetch_filing(client, target_url, domain)
                if fetch_error:
                    errors.append(fetch_error)
                findings.extend(release_findings)
                filings_fetched += 1

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL
        return ModuleResult(
            status=status,
            findings=_dedupe_findings(findings),
            metadata={"domain": domain, "filings_fetched": filings_fetched},
            errors=errors,
        )


async def _search_filings(
    client: httpx.AsyncClient,
    query: str,
    *,
    forms: str = "DEF+14A,10-K,8-K,SC+13G",
) -> tuple[list[str], str | None]:
    try:
        resp = await client.get(
            _SEC_SEARCH,
            params={
                "q": query,
                "dateRange": "custom",
                "startdt": "2018-01-01",
                "forms": forms,
            },
        )
    except httpx.TimeoutException:
        return [], "SEC EDGAR search timed out"
    except Exception as exc:
        return [], f"SEC EDGAR search error: {exc}"
    if resp.status_code != 200:
        return [], f"SEC EDGAR search HTTP {resp.status_code}"
    try:
        data = resp.json()
    except Exception:
        return [], "SEC EDGAR search returned unparseable JSON"
    hits = data.get("hits", {}).get("hits") if isinstance(data.get("hits"), dict) else []
    urls: list[str] = []
    if isinstance(hits, list):
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            source = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
            root = source.get("root_form") or source.get("form")
            url = source.get("url") or source.get("filename")
            if url:
                url_text = str(url)
                if url_text.startswith("/"):
                    url_text = urljoin("https://www.sec.gov", url_text)
                urls.append(url_text)
            elif source.get("adsh"):
                urls.append(f"https://www.sec.gov/Archives/edgar/data/{source.get('ciks', [''])[0]}/{source.get('adsh')}")
    return urls[:3], None


async def _primary_document_url(
    client: httpx.AsyncClient, filing_url: str
) -> tuple[str | None, str | None]:
    try:
        resp = await client.get(filing_url)
    except httpx.TimeoutException:
        return None, f"SEC filing index timed out: {filing_url}"
    except Exception as exc:
        return None, f"SEC filing index error: {exc}"
    if resp.status_code != 200:
        return None, None
    for href in _DOC_LINK_RE.findall(resp.text):
        if "ixviewer" in href.lower():
            continue
        return urljoin(str(resp.url), href)
    return None, None


async def _fetch_filing(
    client: httpx.AsyncClient, url: str, domain: str
) -> tuple[list[dict[str, Any]], str | None]:
    try:
        resp = await client.get(url)
    except httpx.TimeoutException:
        return [], f"SEC filing timed out: {url}"
    except Exception as exc:
        return [], f"SEC filing fetch error: {exc}"
    if resp.status_code != 200:
        return [], f"SEC filing HTTP {resp.status_code}: {url}"

    text = _html_text(resp.text)
    paragraphs = re.split(r"(?<=[.!?])\s+|\n+", text)
    findings: list[dict[str, Any]] = []
    for paragraph in paragraphs:
        if domain not in paragraph.lower():
            continue
        for match in _PHONE_RE.finditer(paragraph):
            phone = normalize_phone(match.group(0))
            if not phone:
                continue
            start = max(match.start() - 50, 0)
            end = min(match.end() + 50, len(paragraph))
            findings.append(
                {
                    "platform": "sec_edgar",
                    "signal_type": "phone_number",
                    "confidence": "medium",
                    "metadata": {
                        "phone": phone,
                        "company_name": _company_name(text),
                        "filing_type": _filing_type(text),
                        "filing_url": url,
                        "context": paragraph[start:end].strip(),
                    },
                }
            )
    return findings, None


def _html_text(html: str) -> str:
    text = _TAG_RE.sub(" ", html)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def _company_name(text: str) -> str:
    match = re.search(r"COMPANY CONFORMED NAME:\s*([^\n\r]+)", text, re.I)
    return match.group(1).strip() if match else ""


def _filing_type(text: str) -> str:
    match = re.search(r"CONFORMED SUBMISSION TYPE:\s*([A-Z0-9\- ]+)", text, re.I)
    return match.group(1).strip() if match else ""


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for finding in findings:
        meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        key = (str(meta.get("phone") or ""), str(meta.get("filing_url") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
