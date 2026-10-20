"""Profile details for username hits (UC3).

``enrich`` runs once per hit, at probe time, on the response the existence check
already received: a site parser from ``sites.PARSERS`` when there is one, the generic
HTML parser otherwise. It writes the field set (see ``fields.FIELD_KEYS``) plus
``field_sources`` and ``location_normalized`` into the probe's profile dict, and drops
the full body so only the compact ``_probe_response`` snapshot is ever stored.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .fields import FIELD_KEYS, Profile
from .generic import parse_html
from .sites import PARSERS, Ctx

_LOG = logging.getLogger(__name__)
ENRICH_TIMEOUT_S = 8.0

__all__ = ["FIELD_KEYS", "Profile", "enrich"]


async def enrich(
    client: Any, defn: dict[str, Any], username: str, profile: dict[str, Any] | None
) -> None:
    """Parse profile fields into ``profile`` (mutated). Never raises."""
    if not isinstance(profile, dict):
        return
    body = profile.pop("_body", "") or ""
    snapshot = profile.get("_probe_response") or {}
    site_id = str(defn.get("id") or "")
    url = str(defn.get("url") or defn.get("uri_check") or "").replace("{username}", username)
    probe_url = str(snapshot.get("url") or url)
    p = Profile()
    try:
        fn = PARSERS.get(site_id)
        if fn is not None:
            ctx = Ctx(site_id=site_id, username=username, url=url, probe_url=probe_url,
                      body=body, client=client, profile=p)
            await asyncio.wait_for(fn(ctx), timeout=ENRICH_TIMEOUT_S)
        elif "html" in str(snapshot.get("content_type") or "") or body.lstrip()[:1] == "<":
            parse_html(body, url, p)
    except Exception as exc:  # noqa: BLE001 - fields are best-effort, existence stands
        _LOG.debug("profile parse failed for %s: %s", site_id, exc)
    meta: dict[str, Any] = {}
    p.merge_into(meta)
    if meta:
        # Parsed fields replace the old 4-field generic extraction for this hit.
        for key in ("display_name", "bio", "avatar_url", "location"):
            profile.pop(key, None)
        profile.update(meta)
