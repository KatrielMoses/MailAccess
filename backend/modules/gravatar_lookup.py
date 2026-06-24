from __future__ import annotations

import hashlib
import logging
from typing import Any

import httpx

from ..config import settings
from .base import BaseModule, ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)

_ASSOCIATE_USERNAME_CAP = 20
_ABOUT_ME_MAX_LEN = 500


class GravatarLookupModule(BaseModule):
    name = "gravatar_lookup"
    description = (
        "Look up the target email's Gravatar profile for display name, bio, avatar, "
        "and linked social accounts."
    )
    requires_key = False
    default_enabled = True

    async def run(self, email: str, force: bool = False) -> ModuleResult:
        if not (settings.enable_gravatar_lookup or force):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "gravatar_lookup disabled — set ENABLE_GRAVATAR_LOOKUP=true to enable"
                ],
            )

        email_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://www.gravatar.com/{email_hash}.json",
                    headers={"Accept": "application/json"},
                )
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"Gravatar request failed: {exc}"],
                metadata={
                    "gravatar_found": False,
                    "linked_accounts": 0,
                    "display_name": None,
                    "email_hash": email_hash,
                    "associate_usernames": [],
                },
            )

        if resp.status_code == 404:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                metadata={
                    "gravatar_found": False,
                    "linked_accounts": 0,
                    "display_name": None,
                    "email_hash": email_hash,
                    "associate_usernames": [],
                },
            )

        if resp.status_code in (403, 429):
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"Gravatar: rate limited or forbidden (HTTP {resp.status_code})"],
                metadata={
                    "gravatar_found": False,
                    "linked_accounts": 0,
                    "display_name": None,
                    "email_hash": email_hash,
                    "associate_usernames": [],
                },
            )

        if resp.status_code >= 500:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"Gravatar: server error HTTP {resp.status_code}"],
                metadata={
                    "gravatar_found": False,
                    "linked_accounts": 0,
                    "display_name": None,
                    "email_hash": email_hash,
                    "associate_usernames": [],
                },
            )

        if resp.status_code != 200:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"Gravatar: unexpected HTTP {resp.status_code}"],
                metadata={
                    "gravatar_found": False,
                    "linked_accounts": 0,
                    "display_name": None,
                    "email_hash": email_hash,
                    "associate_usernames": [],
                },
            )

        try:
            data = resp.json()
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                errors=[f"Gravatar: invalid JSON: {exc}"],
                metadata={
                    "gravatar_found": False,
                    "linked_accounts": 0,
                    "display_name": None,
                    "email_hash": email_hash,
                    "associate_usernames": [],
                },
            )

        entries = data.get("entry") or []
        if not entries:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                metadata={
                    "gravatar_found": False,
                    "linked_accounts": 0,
                    "display_name": None,
                    "email_hash": email_hash,
                    "associate_usernames": [],
                },
            )

        entry = entries[0]
        accounts = entry.get("accounts") or []
        display_name = entry.get("displayName")
        about_me_raw = entry.get("aboutMe")
        about_me: str | None = about_me_raw[:_ABOUT_ME_MAX_LEN] if about_me_raw else None

        associate_usernames: list[str] = []
        for acct in accounts:
            uname = acct.get("username")
            if (
                uname
                and uname not in associate_usernames
                and len(associate_usernames) < _ASSOCIATE_USERNAME_CAP
            ):
                associate_usernames.append(uname)

        findings: list[dict[str, Any]] = []

        findings.append({
            "platform": "gravatar",
            "profile_url": entry.get("profileUrl"),
            "username": entry.get("preferredUsername") or display_name,
            "confidence": "high",
            "metadata": {
                "source": "gravatar",
                "type": "primary_profile",
                "display_name": display_name,
                "about_me": about_me,
                "location": entry.get("currentLocation"),
                "avatar_url": entry.get("thumbnailUrl"),
                "email_hash": email_hash,
                "linked_accounts": [
                    {
                        "shortname": acct.get("shortname"),
                        "url": acct.get("url"),
                        "username": acct.get("username"),
                    }
                    for acct in accounts
                ],
            },
        })

        for acct in accounts:
            shortname = acct.get("shortname") or ""
            findings.append({
                "platform": f"gravatar:{shortname}",
                "profile_url": acct.get("url"),
                "username": acct.get("username"),
                "confidence": "medium",
                "metadata": {
                    "source": "gravatar",
                    "type": "linked_account",
                    "shortname": shortname,
                    "verified": acct.get("verified") == "true",
                },
            })

        logger.debug("gravatar_lookup: found profile with %d linked accounts", len(accounts))

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "gravatar_found": True,
                "linked_accounts": len(accounts),
                "display_name": display_name,
                "email_hash": email_hash,
                "associate_usernames": associate_usernames,
            },
        )
