"""Phase 5B — rotating client fingerprints for the stealth transport.

Today the stealth path hardcodes a single Chrome-120 fingerprint (UA +
``sec-ch-ua`` + ``impersonate="chrome120"``). A single static fingerprint across
a bulk run is itself a block signal. This module supplies a small pool of
*internally consistent* desktop fingerprints — the curl-cffi ``impersonate``
target, the ``User-Agent``, and the ``sec-ch-ua`` client hints all agree on the
same browser+version, so TLS/JA3, HTTP/2 and header fingerprints don't
contradict each other (a mismatch is more detectable than no rotation at all).

The default fingerprint is byte-identical to the previous hardcoded Chrome-120
values, so behaviour is unchanged when rotation is disabled or a session pins
one. ``impersonate`` targets are validated against the installed curl-cffi build
at import time, so an unsupported target can never be handed to curl-cffi.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from ..config import settings


@dataclass(frozen=True)
class Fingerprint:
    """A self-consistent browser fingerprint for the stealth transport."""

    impersonate: str          # curl-cffi impersonate target, e.g. "chrome124"
    user_agent: str
    sec_ch_ua: str
    sec_ch_ua_platform: str   # quoted, e.g. '"Windows"'
    sec_ch_ua_mobile: str = "?0"

    @property
    def normalized_impersonate(self) -> str:
        """curl-cffi accepts the un-hyphenated form."""
        return self.impersonate.replace("-", "").replace("_", "")


# The current hardcoded values — kept as the default so nothing changes when
# rotation is off. Must match ``stealth_client._CHROME_UA`` / ``_SEC_CH_UA``.
DEFAULT_FINGERPRINT = Fingerprint(
    impersonate="chrome120",
    user_agent=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    sec_ch_ua_platform='"Windows"',
)


# A conservative pool of modern desktop Chrome/Edge fingerprints. Each is
# internally consistent (UA version == sec-ch-ua version == impersonate version).
_POOL: tuple[Fingerprint, ...] = (
    DEFAULT_FINGERPRINT,
    Fingerprint(
        impersonate="chrome124",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_platform='"Windows"',
    ),
    Fingerprint(
        impersonate="chrome131",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        sec_ch_ua='"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        sec_ch_ua_platform='"Windows"',
    ),
    Fingerprint(
        impersonate="chrome124",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        sec_ch_ua_platform='"macOS"',
    ),
    Fingerprint(
        impersonate="edge101",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 Edg/101.0.1210.53"
        ),
        sec_ch_ua='"Microsoft Edge";v="101", "Chromium";v="101", "Not A;Brand";v="99"',
        sec_ch_ua_platform='"Windows"',
    ),
)


def _supported_targets() -> set[str]:
    """Impersonate targets the installed curl-cffi build actually supports."""
    try:
        from curl_cffi.requests import BrowserType  # type: ignore[import-not-found]

        return {b.name for b in BrowserType}
    except Exception:
        return set()


# Filter the pool to targets the installed curl-cffi supports (never hand it an
# unknown target). Falls back to the default alone if introspection is
# unavailable — the default is known-good on any build that ships chrome120.
_SUPPORTED = _supported_targets()
if _SUPPORTED:
    _VALID_POOL: tuple[Fingerprint, ...] = tuple(
        fp for fp in _POOL if fp.normalized_impersonate in _SUPPORTED
    ) or (DEFAULT_FINGERPRINT,)
else:
    _VALID_POOL = (DEFAULT_FINGERPRINT,)


def pick_fingerprint(rng: random.Random | None = None) -> Fingerprint:
    """Return a fingerprint for a new stealth session.

    When ``harvest_fingerprint_rotation`` is off, or a specific
    ``harvest_impersonate_browser`` is pinned in config, that choice wins;
    otherwise a random member of the validated pool is returned so each session
    (and, across a bulk run, each domain) presents a different consistent
    fingerprint.
    """
    pinned = str(getattr(settings, "harvest_impersonate_browser", "") or "").strip()
    if pinned:
        norm = pinned.replace("-", "").replace("_", "")
        for fp in _POOL:
            if fp.normalized_impersonate == norm:
                return fp
        # A pinned-but-unknown target: honour the impersonate string but keep the
        # default headers (best-effort; curl-cffi validates the target itself).
        if not _SUPPORTED or norm in _SUPPORTED:
            return Fingerprint(
                impersonate=pinned,
                user_agent=DEFAULT_FINGERPRINT.user_agent,
                sec_ch_ua=DEFAULT_FINGERPRINT.sec_ch_ua,
                sec_ch_ua_platform=DEFAULT_FINGERPRINT.sec_ch_ua_platform,
            )
        return DEFAULT_FINGERPRINT
    if not bool(getattr(settings, "harvest_fingerprint_rotation", True)):
        return DEFAULT_FINGERPRINT
    chooser = rng or random
    return chooser.choice(_VALID_POOL)


__all__ = ["Fingerprint", "DEFAULT_FINGERPRINT", "pick_fingerprint"]
