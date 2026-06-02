from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Any

from ..core.bio_analyzer import analyze_bio, is_aggregator_url
from ..core.bio_link_extractor import extract_from_aggregator
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_PLATFORM_URL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"twitter\.com|x\.com"), "twitter"),
    (re.compile(r"github\.com"), "github"),
    (re.compile(r"linkedin\.com"), "linkedin"),
    (re.compile(r"facebook\.com"), "facebook"),
    (re.compile(r"instagram\.com"), "instagram"),
    (re.compile(r"youtube\.com"), "youtube"),
    (re.compile(r"reddit\.com"), "reddit"),
    (re.compile(r"mastodon\.social|hachyderm\.io"), "mastodon"),
]


def _identify_platform(url: str) -> str:
    for pattern, name in _PLATFORM_URL_PATTERNS:
        if pattern.search(url):
            return name
    return "website"


class GravatarModule(BaseModule):
    name = "gravatar"
    description = "Deep Gravatar profile extraction: name, location, bio, verified accounts, linked URLs."
    requires_key = False

    async def run(self, email: str, original_email: str | None = None) -> ModuleResult:
        # Try original email first (it may differ from canonical and be the registered one)
        emails_to_try: list[str] = []
        if original_email and original_email.strip().lower() != email.strip().lower():
            emails_to_try.append(original_email.strip().lower())
        emails_to_try.append(email.strip().lower())

        last_result: ModuleResult | None = None
        for try_email in emails_to_try:
            result = await self._run_for_email(try_email)
            last_result = result
            if any(f.get("platform") == "gravatar_profile" for f in result.findings):
                return result
        return last_result  # type: ignore[return-value]

    async def _run_for_email(self, email_clean: str) -> ModuleResult:
        md5_hash = hashlib.md5(email_clean.encode("utf-8")).hexdigest()
        sha256_hash = hashlib.sha256(email_clean.encode("utf-8")).hexdigest()
        domain = email_clean.split("@", 1)[1] if "@" in email_clean else None

        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        async with build_client(timeout=10.0, follow_redirects=True) as client:
            gravatar_url = f"https://www.gravatar.com/{md5_hash}.json"
            libravatar_url = f"https://www.libravatar.org/avatar/{md5_hash}?d=404"

            grav_res, librav_res = await asyncio.gather(
                client.get(gravatar_url),
                client.get(libravatar_url),
                return_exceptions=True,
            )

            # --- Gravatar profile ---
            if isinstance(grav_res, Exception):
                errors.append(f"Gravatar error: {grav_res}")
            else:
                try:
                    if grav_res.status_code == 200:
                        data = grav_res.json()
                        if data.get("entry"):
                            entry = data["entry"][0]
                            grav_findings, grav_errors = await self._process_entry(
                                entry, md5_hash, domain, client
                            )
                            findings.extend(grav_findings)
                            errors.extend(grav_errors)
                    elif grav_res.status_code != 404:
                        errors.append(f"Gravatar HTTP {grav_res.status_code}")
                except Exception as exc:
                    errors.append(f"Gravatar parsing error: {exc}")

            # --- Libravatar ---
            if isinstance(librav_res, Exception):
                errors.append(f"Libravatar error: {librav_res}")
            elif librav_res.status_code == 200:
                findings.append(
                    {
                        "platform": "Libravatar",
                        "url": f"https://www.libravatar.org/avatar/{md5_hash}",
                        "metadata": {},
                        "confidence": "low",
                    }
                )
            elif librav_res.status_code not in (404,):
                errors.append(f"Libravatar HTTP {librav_res.status_code}")

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL if findings else ModuleStatus.FAILED

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={"md5_hash": md5_hash, "sha256_hash": sha256_hash},
            errors=errors,
        )

    async def _process_entry(
        self,
        entry: dict[str, Any],
        md5_hash: str,
        domain: str | None,
        client: Any,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # Extract structured name
        name_obj = entry.get("name") if isinstance(entry.get("name"), dict) else {}
        full_name = (
            name_obj.get("formatted")
            or entry.get("displayName")
            or entry.get("preferredUsername")
        )
        location = entry.get("currentLocation")
        about_me = entry.get("aboutMe")
        thumbnail = entry.get("thumbnailUrl")
        profile_url = entry.get("profileUrl") or f"https://www.gravatar.com/{md5_hash}"
        username = entry.get("hash") or entry.get("id") or ""

        # Build profile summary finding
        profile_meta: dict[str, Any] = {}
        if full_name:
            profile_meta["name"] = full_name
            profile_meta["display_name"] = full_name
        if location:
            profile_meta["location"] = location
        if about_me:
            profile_meta["bio"] = about_me
        if thumbnail:
            profile_meta["thumbnail_url"] = thumbnail
        if username:
            profile_meta["username"] = entry.get("preferredUsername") or ""

        findings.append(
            {
                "platform": "gravatar_profile",
                "url": profile_url,
                "confidence": "high",
                "source": "gravatar",
                "signal_type": "profile",
                "metadata": profile_meta,
            }
        )

        # Process urls[] array — platform links
        urls_list = entry.get("urls") if isinstance(entry.get("urls"), list) else []
        aggregator_urls: list[str] = []
        for url_entry in urls_list:
            if not isinstance(url_entry, dict):
                continue
            url_val = str(url_entry.get("value") or url_entry.get("url") or "")
            title = str(url_entry.get("title") or "")
            if not url_val:
                continue
            platform = _identify_platform(url_val)
            findings.append(
                {
                    "platform": f"gravatar_url_{platform}",
                    "url": url_val,
                    "confidence": "high",
                    "source": "gravatar",
                    "signal_type": "profile_link",
                    "metadata": {"link_title": title, "link_platform": platform},
                }
            )
            if is_aggregator_url(url_val):
                aggregator_urls.append(url_val)

        # Process accounts[] — verified external accounts
        accounts_list = entry.get("accounts") if isinstance(entry.get("accounts"), list) else []
        verified_platforms: list[str] = []
        for acct in accounts_list:
            if not isinstance(acct, dict):
                continue
            acct_domain = str(acct.get("domain") or "")
            display = str(acct.get("display") or acct.get("username") or "")
            acct_url = str(acct.get("url") or acct.get("profileUrl") or "")
            shortname = str(acct.get("shortname") or acct.get("name") or acct_domain)
            verified = bool(acct.get("verified"))
            platform_label = shortname or acct_domain or "unknown"
            verified_platforms.append(platform_label)
            findings.append(
                {
                    "platform": f"gravatar_account",
                    "url": acct_url or profile_url,
                    "confidence": "high",
                    "source": "gravatar",
                    "signal_type": "verified_account",
                    "metadata": {
                        "account_platform": platform_label,
                        "domain": acct_domain,
                        "display": display,
                        "verified": verified,
                    },
                }
            )
            if acct_url and is_aggregator_url(acct_url):
                aggregator_urls.append(acct_url)

        # Store verified platform list in profile finding for CLI rendering
        if verified_platforms:
            findings[0]["metadata"]["verified_accounts"] = verified_platforms

        # Bio analysis — phone/email/url extraction
        if about_me:
            bio = analyze_bio(about_me, exclude_domain=domain)
            for phone in bio.phones:
                findings.append(
                    {
                        "platform": "gravatar_bio",
                        "confidence": "medium",
                        "source": "gravatar",
                        "signal_type": "phone_in_bio",
                        "metadata": {
                            "phone": phone,
                            "source_field": "aboutMe",
                            "source_platform": "gravatar",
                        },
                    }
                )
            for extra_email in bio.emails:
                findings.append(
                    {
                        "platform": "gravatar_bio",
                        "confidence": "high",
                        "source": "gravatar",
                        "signal_type": "email_in_bio",
                        "metadata": {
                            "email": extra_email,
                            "source_field": "aboutMe",
                            "source_platform": "gravatar",
                        },
                    }
                )
            aggregator_urls.extend(bio.aggregator_urls)

        # Sub-extract aggregator pages
        for agg_url in dict.fromkeys(aggregator_urls):  # dedup preserving order
            agg_links = await extract_from_aggregator(agg_url, client)
            for link in agg_links:
                if link.link_type == "phone":
                    findings.append(
                        {
                            "platform": "gravatar_bio",
                            "confidence": "medium",
                            "source": "gravatar",
                            "signal_type": "phone_in_bio",
                            "metadata": {
                                "phone": link.handle,
                                "source_field": "aggregator",
                                "source_url": agg_url,
                                "source_platform": "gravatar",
                            },
                        }
                    )
                elif link.link_type == "whatsapp":
                    findings.append(
                        {
                            "platform": "gravatar_bio",
                            "confidence": "medium",
                            "source": "gravatar",
                            "signal_type": "phone_in_bio",
                            "metadata": {
                                "phone": f"WhatsApp: {link.handle}",
                                "source_field": "aggregator",
                                "source_url": agg_url,
                                "source_platform": "gravatar",
                            },
                        }
                    )
                elif link.link_type == "email":
                    findings.append(
                        {
                            "platform": "gravatar_bio",
                            "confidence": "high",
                            "source": "gravatar",
                            "signal_type": "email_in_bio",
                            "metadata": {
                                "email": link.handle,
                                "source_field": "aggregator",
                                "source_url": agg_url,
                                "source_platform": "gravatar",
                            },
                        }
                    )
                elif link.link_type == "social":
                    findings.append(
                        {
                            "platform": f"gravatar_aggregator_{link.platform}",
                            "url": link.url,
                            "confidence": "high",
                            "source": "gravatar",
                            "signal_type": "aggregator_link",
                            "metadata": {
                                "link_platform": link.platform,
                                "handle": link.handle,
                                "aggregator_url": agg_url,
                            },
                        }
                    )

        return findings, errors
