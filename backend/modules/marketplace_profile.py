from __future__ import annotations

import re
from typing import Any

import httpx

from ..core.bio_analyzer import analyze_bio
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_ETSY_PLATFORM_NAMES = frozenset({"etsy", "etsy shop"})
_EBAY_PLATFORM_NAMES = frozenset({"ebay", "ebay profile"})

_SCRAPER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _find_marketplace_usernames(
    collected: dict[str, Any],
) -> tuple[str | None, str | None]:
    """Return (etsy_username, ebay_username) from whatsmyname/username_pivot findings."""
    etsy_user: str | None = None
    ebay_user: str | None = None

    for module_name in ("whatsmyname", "username_pivot"):
        result = collected.get(module_name)
        if not result or not hasattr(result, "findings"):
            continue
        for finding in result.findings:
            if not isinstance(finding, dict):
                continue
            platform = str(finding.get("platform") or "").lower().strip()
            meta = finding.get("metadata") or {}
            username = str(
                finding.get("username")
                or meta.get("matched_username")
                or ""
            ).strip()
            if not username:
                continue
            if platform in _ETSY_PLATFORM_NAMES and etsy_user is None:
                etsy_user = username
            elif platform in _EBAY_PLATFORM_NAMES and ebay_user is None:
                ebay_user = username

        if etsy_user and ebay_user:
            break

    return etsy_user, ebay_user


class MarketplaceProfileModule(BaseModule):
    name = "marketplace_profile"
    description = "Extract Etsy shop and eBay profile data for confirmed usernames."
    requires_key = False

    async def run(
        self, email: str, collected: dict[str, Any] | None = None
    ) -> ModuleResult:
        if collected is None:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Runs in post-primary phase only"],
            )

        etsy_user, ebay_user = _find_marketplace_usernames(collected)
        if not etsy_user and not ebay_user:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["No confirmed Etsy or eBay account found"],
            )

        domain = email.split("@", 1)[1] if "@" in email else None
        headers = {
            "User-Agent": _SCRAPER_UA,
            "Accept-Language": "en-US,en;q=0.9",
        }
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        async with build_client(timeout=12.0, follow_redirects=True) as client:
            if etsy_user:
                e_findings, e_errs = await _fetch_etsy(
                    client, etsy_user, headers, domain
                )
                findings.extend(e_findings)
                errors.extend(e_errs)
            if ebay_user:
                b_findings, b_errs = await _fetch_ebay(
                    client, ebay_user, headers
                )
                findings.extend(b_findings)
                errors.extend(b_errs)

        if not findings and errors:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=errors)

        status = ModuleStatus.PARTIAL if errors else ModuleStatus.SUCCESS
        return ModuleResult(status=status, findings=findings, errors=errors)


async def _fetch_etsy(
    client: httpx.AsyncClient,
    username: str,
    headers: dict[str, str],
    email_domain: str | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    url = f"https://www.etsy.com/shop/{username}"
    try:
        resp = await client.get(url, headers=headers)
    except httpx.TimeoutException:
        return [], ["Etsy request timed out"]
    except Exception as exc:
        return [], [f"Etsy request error: {exc}"]

    if resp.status_code == 404:
        return [], []
    if resp.status_code in (403, 429):
        return [], [f"Etsy blocked the request (HTTP {resp.status_code})"]
    if resp.status_code != 200:
        return [], [f"Etsy HTTP {resp.status_code}"]

    profile = _parse_etsy_html(resp.text, username)
    finding: dict[str, Any] = {
        "platform": "etsy_shop",
        "profile_url": url,
        "username": username,
        "confidence": "high",
        "source": "marketplace_profile",
        "metadata": {
            "shop_name": username,
            "extraction_method": "html_scrape",
            **profile,
        },
    }
    extra: list[dict[str, Any]] = []

    bio_text = str(profile.get("bio") or "")
    if bio_text:
        analysis = analyze_bio(bio_text, exclude_domain=email_domain)
        for phone in analysis.phones:
            extra.append({
                "platform": "etsy_shop",
                "signal_type": "phone_in_bio",
                "confidence": "medium",
                "source": "marketplace_profile",
                "metadata": {
                    "phone": phone,
                    "source_field": "bio",
                    "source_platform": "etsy_shop",
                },
            })
        for addr in analysis.emails:
            extra.append({
                "platform": "etsy_shop",
                "signal_type": "email_in_bio",
                "confidence": "medium",
                "source": "marketplace_profile",
                "metadata": {
                    "email": addr,
                    "source_field": "bio",
                    "source_platform": "etsy_shop",
                },
            })

    return [finding] + extra, []


async def _fetch_ebay(
    client: httpx.AsyncClient,
    username: str,
    headers: dict[str, str],
) -> tuple[list[dict[str, Any]], list[str]]:
    url = f"https://www.ebay.com/usr/{username}"
    try:
        resp = await client.get(url, headers=headers)
    except httpx.TimeoutException:
        return [], ["eBay request timed out"]
    except Exception as exc:
        return [], [f"eBay request error: {exc}"]

    if resp.status_code == 404:
        return [], []
    if resp.status_code in (403, 429):
        return [], [f"eBay blocked the request (HTTP {resp.status_code})"]
    if resp.status_code != 200:
        return [], [f"eBay HTTP {resp.status_code}"]

    profile = _parse_ebay_html(resp.text, username)
    finding: dict[str, Any] = {
        "platform": "ebay_profile",
        "profile_url": url,
        "username": username,
        "confidence": "high",
        "source": "marketplace_profile",
        "metadata": {
            "username": username,
            "extraction_method": "html_scrape",
            **profile,
        },
    }
    return [finding], []


def _parse_etsy_html(html: str, username: str) -> dict[str, Any]:
    data: dict[str, Any] = {}

    # Shop name
    m = re.search(
        r'"shopName"\s*:\s*"([^"]{2,80})"', html
    )
    if not m:
        m = re.search(
            r'<h1[^>]*class="[^"]*shop-name[^"]*"[^>]*>(.*?)</h1>',
            html,
            re.IGNORECASE | re.DOTALL,
        )
    if m:
        raw = re.sub(r"<[^>]+>", "", m.group(1)).strip()
        if raw:
            data["shop_name"] = raw
    else:
        # Fall back to <title>
        tm = re.search(
            r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL
        )
        if tm:
            t = re.sub(r"<[^>]+>", "", tm.group(1)).strip()
            part = re.split(r"\s*[-|]\s*(?:Etsy|etsy)", t)[0].strip()
            if part:
                data["shop_name"] = part

    # Owner name
    om = re.search(
        r'"ownerName"\s*:\s*"([^"]{2,60})"', html
    )
    if not om:
        om = re.search(
            r'(?:shop\s+owner|seller)[^<]*<[^>]+>([A-Z][a-zA-Z ]{1,30})</[^>]+>',
            html,
            re.IGNORECASE,
        )
    if om:
        data["owner_name"] = re.sub(r"<[^>]+>", "", om.group(1)).strip()

    # Location
    lm = re.search(r'"sellerLocation"\s*:\s*"([^"]{2,80})"', html)
    if not lm:
        lm = re.search(
            r'class="[^"]*location[^"]*"[^>]*>\s*([^<]{3,60})\s*<',
            html,
            re.IGNORECASE,
        )
    if lm:
        data["location"] = lm.group(1).strip()

    # Sales count
    sm = re.search(r'"salesCount"\s*:\s*(\d+)', html)
    if not sm:
        sm = re.search(r'([\d,]+)\s+sales', html, re.IGNORECASE)
    if sm:
        try:
            data["sales_count"] = int(re.sub(r"[,\s]", "", sm.group(1)))
        except ValueError:
            pass

    # Member since
    mm = re.search(
        r'(?:member|joined)\s+(?:since\s+)?([A-Z][a-z]+\s+\d{4}|\d{4})',
        html,
        re.IGNORECASE,
    )
    if mm:
        data["member_since"] = mm.group(1).strip()

    # Bio / about text
    bm = re.search(r'"shopAbout"\s*:\s*"([^"]{10,})"', html)
    if not bm:
        bm = re.search(
            r'class="[^"]*shop-about[^"]*"[^>]*>(.*?)</(?:div|p|section)>',
            html,
            re.IGNORECASE | re.DOTALL,
        )
    if bm:
        bio = re.sub(r"<[^>]+>", " ", bm.group(1)).strip()
        bio = re.sub(r"\s{2,}", " ", bio)
        if len(bio) >= 10:
            data["bio"] = bio[:500]

    # Profile photo
    pm = re.search(r'"profileImageUrl"\s*:\s*"([^"]+)"', html)
    if pm:
        data["profile_photo_url"] = pm.group(1)

    return data


def _parse_ebay_html(html: str, username: str) -> dict[str, Any]:
    data: dict[str, Any] = {}

    # Feedback score
    fm = re.search(r'"feedbackScore"\s*:\s*(\d+)', html)
    if not fm:
        fm = re.search(r'Feedback\s+Score[^:]*:\s*(\d+)', html, re.IGNORECASE)
    if not fm:
        fm = re.search(
            r'<span[^>]*class="[^"]*feedback[^"]*"[^>]*>(\d+)</span>',
            html,
            re.IGNORECASE,
        )
    if fm:
        try:
            data["feedback_score"] = int(fm.group(1))
        except ValueError:
            pass

    # Member since
    mm = re.search(
        r'Member\s+since[^:]*:\s*([A-Za-z]+[\s\-]\d{2,4}(?:[,\s]+\d{4})?)',
        html,
        re.IGNORECASE,
    )
    if mm:
        data["member_since"] = mm.group(1).strip()

    # Location
    lm = re.search(r'"location"\s*:\s*"([^"]{2,80})"', html)
    if not lm:
        lm = re.search(
            r'<span[^>]*class="[^"]*location[^"]*"[^>]*>([^<]{3,60})</span>',
            html,
            re.IGNORECASE,
        )
    if lm:
        data["location"] = lm.group(1).strip()

    data["top_rated_seller"] = bool(
        re.search(r"top.rated.seller", html, re.IGNORECASE)
    )

    return data
