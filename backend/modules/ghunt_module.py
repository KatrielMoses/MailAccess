"""GHunt module: deep Google account intelligence via GAIA lookup."""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from ..config import settings
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_GOOGLE_MAIL_DOMAINS = frozenset({"gmail.com", "googlemail.com"})
_GOOGLE_MX_SUFFIX = "google.com"


async def _is_google_domain(domain: str) -> bool:
    """True if domain is gmail.com/googlemail.com or routes through Google MX servers."""
    if domain in _GOOGLE_MAIL_DOMAINS:
        return True
    try:
        import dns.asyncresolver
        answers = await dns.asyncresolver.resolve(domain, "MX")
        return any(_GOOGLE_MX_SUFFIX in str(r.exchange).lower() for r in answers)
    except Exception:
        return False


def _load_creds(creds_path: str) -> Any:
    """Load GHunt credentials from disk (sync — called via asyncio.to_thread)."""
    # ghunt >=2.x: credentials load via the GHuntCreds object (base64 .m file)
    try:
        from ghunt.objects.base import GHuntCreds
        creds = GHuntCreds(creds_path=creds_path)
        creds.load_creds(silent=True)
        return creds
    except (ImportError, AttributeError, TypeError):
        pass

    # Legacy fallback: older ghunt helpers.auth.load_creds(creds, file=...)
    from ghunt.objects.base import SmartObj

    creds = SmartObj()
    try:
        from ghunt.helpers.auth import load_creds as _ghunt_load
        _ghunt_load(creds, file=creds_path)
        return creds
    except (ImportError, TypeError, AttributeError):
        pass

    # Last resort for builds that wrote plain-JSON creds
    raw = json.loads(Path(creds_path).read_text(encoding="utf-8"))
    for k, v in raw.items():
        setattr(creds, k, v)
    return creds


class GHuntModule(BaseModule):
    name = "ghunt"
    description = (
        "Extract GAIA ID, YouTube channel, Maps reviews, and profile data "
        "from Google accounts via GHunt. Gmail and Google Workspace only."
    )
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        if not settings.enable_ghunt:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_GHUNT=true to run this module"],
            )

        domain = email.split("@", 1)[-1].lower()
        if not await _is_google_domain(domain):
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[f"Skipped: {domain} is not a Gmail or Google Workspace domain"],
            )

        if not settings.ghunt_creds_path:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["GHUNT_CREDS_PATH not set — run `ghunt login`, see docs/ghunt-setup.md"],
            )

        creds_file = Path(settings.ghunt_creds_path)
        if not creds_file.exists():
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    f"GHunt credentials file not found at {settings.ghunt_creds_path} — "
                    "run `ghunt login`, see docs/ghunt-setup.md"
                ],
            )

        try:
            from ghunt.apis.peoplepa import PeoplePaHttp  # noqa: F401 — verifies install
            from ghunt.modules.email import hunt as ghunt_email_hunt
        except ImportError as exc:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[f"ghunt not installed: {exc} — run `pip install ghunt>=2.3`"],
            )

        try:
            creds = await asyncio.to_thread(_load_creds, settings.ghunt_creds_path)
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Failed to load GHunt credentials: {exc}"],
            )

        json_all: dict[str, Any] = {}
        try:
            await asyncio.to_thread(ghunt_email_hunt, creds, email, json_all)
        except Exception as exc:
            _LOG.debug("GHunt hunt error", exc_info=True)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"GHunt hunt failed: {exc}"],
            )

        return self._parse(json_all)

    # ------------------------------------------------------------------

    def _parse(self, data: dict[str, Any]) -> ModuleResult:
        if not data:
            return ModuleResult(
                status=ModuleStatus.SUCCESS,
                findings=[],
                metadata={"found": False},
            )

        gaia_id = data.get("gaia_id") or data.get("personId")

        # Profile
        profile = data.get("profile") or {}
        names = profile.get("names") or data.get("names") or []
        display_name: str | None = None
        if names:
            first = names[0]
            if isinstance(first, dict):
                display_name = first.get("displayName") or first.get("formattedName")
            else:
                display_name = str(first)

        photos = profile.get("profilePhotos") or data.get("profilePhotos") or []
        profile_photo_url: str | None = None
        custom_profile_photo = False
        if photos:
            p = photos[0] if isinstance(photos[0], dict) else {}
            profile_photo_url = p.get("url")
            custom_profile_photo = not p.get("isDefault", True)

        # Account metadata
        account_creation = data.get("account_creation_date") or data.get("creationTime")
        last_edit = (
            data.get("last_edit_timestamp")
            or data.get("lastEditedUnixTimestamp")
            or data.get("lastUpdated")
        )

        # YouTube
        yt = data.get("youtube_channel") or data.get("youtubeChannel") or {}
        youtube_channel_url = yt.get("channel_url") or yt.get("url")
        youtube_channel_name = yt.get("channel_name") or yt.get("name")

        # Drive
        drive_files = data.get("drive_files") or data.get("driveFiles") or []
        public_drive_files = len(drive_files) if isinstance(drive_files, list) else 0

        # Maps
        maps_reviews = data.get("maps_reviews") or data.get("mapsReviews") or []
        if not isinstance(maps_reviews, list):
            maps_reviews = []
        maps_reviews_count = len(maps_reviews)

        # Services
        google_services_active = (
            data.get("activated_services")
            or data.get("activatedServices")
            or data.get("google_services_active")
            or []
        )

        # Location hint: top 3 unique place names from Maps reviews
        location_places = []
        for r in maps_reviews:
            if isinstance(r, dict):
                place = r.get("place_name") or r.get("placeName") or r.get("name")
                if place and place not in location_places:
                    location_places.append(place)
        possible_location_hint = ", ".join(location_places[:3]) if location_places else None

        findings: list[dict[str, Any]] = []

        if gaia_id:
            findings.append({
                "platform": "google_account",
                "profile_url": f"https://plus.google.com/{gaia_id}",
                "metadata": {
                    "gaia_id": gaia_id,
                    "account_creation_date": account_creation,
                    "display_name": display_name,
                    "profile_photo_url": profile_photo_url,
                    "custom_profile_photo": custom_profile_photo,
                    "youtube_channel_url": youtube_channel_url,
                    "youtube_channel_name": youtube_channel_name,
                    "public_drive_files": public_drive_files,
                    "maps_reviews_count": maps_reviews_count,
                    "last_edit_timestamp": last_edit,
                    "google_services_active": google_services_active,
                    "possible_location_hint": possible_location_hint,
                },
                "confidence": "high",
            })

        for review in maps_reviews:
            if not isinstance(review, dict):
                continue
            place = review.get("place_name") or review.get("placeName") or review.get("name")
            date = review.get("review_date") or review.get("date") or review.get("publishTime")
            rating = review.get("rating") or review.get("starRating")
            loc_hint = review.get("location_hint") or review.get("address") or place
            findings.append({
                "platform": "google_maps_review",
                "metadata": {
                    "place_name": place,
                    "review_date": date,
                    "rating": rating,
                    "location_hint": loc_hint,
                },
                "confidence": "high",
            })

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            metadata={
                "found": bool(gaia_id),
                "gaia_id": gaia_id,
                "display_name": display_name,
                "maps_reviews_count": maps_reviews_count,
                "public_drive_files": public_drive_files,
                "google_services_active": google_services_active,
            },
        )
