from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_CDX_URL = "https://web.archive.org/cdx/search/cdx"
_CDX_LIMIT = 20
_PAGE_FETCH_LIMIT = 5


def _parse_cdx_rows(data: object) -> list[dict[str, str]]:
    if not isinstance(data, list) or not data:
        return []
    headers = data[0]
    if not isinstance(headers, list):
        return []

    rows: list[dict[str, str]] = []
    for raw_row in data[1:]:
        if not isinstance(raw_row, list):
            continue
        row = {
            str(key): str(value)
            for key, value in zip(headers, raw_row, strict=False)
            if value is not None
        }
        if row.get("original") and row.get("timestamp"):
            rows.append(row)
    return rows


def _archive_date(timestamp: str) -> str:
    try:
        parsed = datetime.strptime(timestamp[:14], "%Y%m%d%H%M%S")
        return parsed.replace(tzinfo=timezone.utc).date().isoformat()
    except ValueError:
        return timestamp


def _years_ago(archive_date: str) -> int:
    try:
        year = datetime.fromisoformat(archive_date).year
    except ValueError:
        return 0
    return max(datetime.now(timezone.utc).year - year, 0)


def _page_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return html.unescape(title)


def _snippet(text: str, email: str, radius: int = 100) -> str:
    plain = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    plain = re.sub(r"<[^>]+>", " ", plain)
    plain = html.unescape(re.sub(r"\s+", " ", plain)).strip()
    index = plain.lower().find(email.lower())
    if index < 0:
        return ""
    start = max(index - radius, 0)
    end = min(index + len(email) + radius, len(plain))
    prefix = "..." if start else ""
    suffix = "..." if end < len(plain) else ""
    return f"{prefix}{plain[start:end].strip()}{suffix}"


class WaybackModule(BaseModule):
    name = "wayback"
    description = (
        "Search the Internet Archive Wayback Machine for historical public mentions "
        "of an email address."
    )
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        errors: list[str] = []
        partial = False

        try:
            # scrapingant: dropped in S5 audit (Wayback CDX endpoint returns JSON)
            async with build_client(follow_redirects=True) as client:
                rows, cdx_errors, cdx_partial = await self._search_cdx(client, email)
                errors.extend(cdx_errors)
                partial = partial or cdx_partial

                findings: list[dict] = []
                seen: set[tuple[str, str]] = set()
                for row in rows[:_CDX_LIMIT]:
                    original_url = row.get("original", "")
                    timestamp = row.get("timestamp", "")
                    key = (original_url, timestamp)
                    if not original_url or not timestamp or key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._base_finding(email, original_url, timestamp))

                for finding in findings[:_PAGE_FETCH_LIMIT]:
                    meta = finding["metadata"]
                    archived_url = str(finding["profile_url"])
                    page_error, was_rate_limited = await self._enrich_page(
                        client, email, archived_url, meta
                    )
                    if page_error:
                        errors.append(page_error)
                    partial = partial or was_rate_limited
                    original_lower = str(meta["original_url"]).lower()
                    if meta.get("context_snippet") and email.lower() not in original_lower:
                        finding["confidence"] = "medium"

        except httpx.TimeoutException:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=["Wayback Machine request timed out"],
            )
        except Exception as exc:
            return ModuleResult(status=ModuleStatus.FAILED, errors=[str(exc)])

        archive_dates = [
            str(f["metadata"].get("archive_date"))
            for f in findings
            if isinstance(f.get("metadata"), dict) and f["metadata"].get("archive_date")
        ]
        domains = [
            str(f["metadata"].get("original_domain"))
            for f in findings
            if isinstance(f.get("metadata"), dict) and f["metadata"].get("original_domain")
        ]
        oldest_domain = ""
        if findings:
            oldest = min(findings, key=lambda f: str(f.get("metadata", {}).get("archive_date", "")))
            oldest_domain = str(oldest.get("metadata", {}).get("original_domain") or "")

        status = ModuleStatus.SUCCESS
        if partial:
            status = ModuleStatus.PARTIAL
        elif errors and findings:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "pages_found": len(findings),
                "earliest_mention": min(archive_dates) if archive_dates else "",
                "latest_mention": max(archive_dates) if archive_dates else "",
                "unique_domains": sorted(set(domains)),
                "oldest_domain": oldest_domain,
            },
            errors=errors,
        )

    async def _search_cdx(
        self, client: httpx.AsyncClient, email: str
    ) -> tuple[list[dict[str, str]], list[str], bool]:
        searches = [
            {
                "url": f"*{email}*",
                "output": "json",
                "limit": str(_CDX_LIMIT),
                "fl": "original,timestamp,statuscode,mimetype",
                "filter": ["statuscode:200"],
                "collapse": "urlkey",
            },
            {
                "url": "*",
                "output": "json",
                "limit": "10",
                "fl": "original,timestamp",
                "filter": [f"original:.*{re.escape(email)}.*"],
            },
        ]
        rows: list[dict[str, str]] = []
        errors: list[str] = []
        partial = False

        for params in searches:
            try:
                response = await client.get(_CDX_URL, params=params, timeout=10.0)
            except httpx.TimeoutException:
                errors.append("Wayback CDX query timed out")
                partial = True
                continue
            except Exception as exc:
                errors.append(f"Wayback CDX query failed: {exc}")
                partial = True
                continue

            if response.status_code == 429:
                errors.append("Wayback Machine rate-limited CDX search")
                partial = True
                continue
            if response.status_code != 200:
                errors.append(f"Wayback CDX returned {response.status_code}")
                partial = True
                continue
            try:
                rows.extend(_parse_cdx_rows(response.json()))
            except Exception:
                errors.append("Wayback CDX returned unparseable JSON")
                partial = True

        deduped: dict[tuple[str, str], dict[str, str]] = {}
        for row in rows:
            deduped.setdefault((row.get("original", ""), row.get("timestamp", "")), row)
        return list(deduped.values())[:_CDX_LIMIT], errors, partial

    def _base_finding(self, email: str, original_url: str, timestamp: str) -> dict:
        archive_date = _archive_date(timestamp)
        parsed = urlparse(original_url)
        domain = parsed.hostname or parsed.netloc or ""
        archive_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
        email_in_url = email.lower() in original_url.lower()
        return {
            "platform": "wayback_machine",
            "profile_url": archive_url,
            "confidence": "high" if email_in_url else "medium",
            "metadata": {
                "original_url": original_url,
                "archive_date": archive_date,
                "page_title": "",
                "context_snippet": "",
                "original_domain": domain,
                "years_ago": _years_ago(archive_date),
            },
        }

    async def _enrich_page(
        self,
        client: httpx.AsyncClient,
        email: str,
        archived_url: str,
        metadata: dict,
    ) -> tuple[str | None, bool]:
        try:
            response = await client.get(archived_url, timeout=8.0)
        except httpx.TimeoutException:
            return f"Archived page fetch timed out: {archived_url}", False
        except Exception as exc:
            return f"Archived page fetch failed: {exc}", False

        if response.status_code == 429:
            return "Wayback Machine rate-limited archived page fetch", True
        if response.status_code >= 400:
            return f"Archived page returned {response.status_code}: {archived_url}", False

        text = response.text
        metadata["page_title"] = _page_title(text)
        metadata["context_snippet"] = _snippet(text, email)
        return None, False
