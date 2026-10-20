"""Shared WAF / bot-wall response fingerprints.

0.15.0 Phase 4 — the shared WAF fingerprint set. After the Phase-6 detector collapse there is a
single probe engine (``probe_detector``); this module remains the one source of truth for the
fingerprints it consults. When one of these fingerprints appears in a response body, the page is a
challenge/interstitial, not a real profile — so a would-be hit is downgraded to *inconclusive*
rather than counted.
"""

from __future__ import annotations

# Verbatim challenge/error-page markers observed on live WAF challenge responses.
_WAF_FINGERPRINTS: tuple[str, ...] = (
    # 2024-05-13 Cloudflare JS challenge
    ".loading-spinner{visibility:hidden}body.no-js .challenge-running{display:none}"
    "body.dark{background-color:#222;color:#d9d9d9}body.dark a{color:#fff}"
    "body.dark a:hover{color:#ee730a;text-decoration:underline}"
    "body.dark .lds-ring div{border-color:#999 transparent transparent}"
    "body.dark .font-red{color:#b20f03}body.dark",
    # 2024-11-11 Cloudflare error page
    '<span id="challenge-error-text">',
    # 2024-11-11 AWS WAF / CloudFront
    "AwsWafIntegration.forceRefreshToken",
    # 2024-04-09 PerimeterX / Human Security
    '{return l.onPageView}}),Object.defineProperty(r,"perimeterxIdentifiers",{enumerable:',
)


class WAFDetector:
    def is_waf_blocked(self, body: str) -> bool:
        return any(fp in body for fp in _WAF_FINGERPRINTS)


_WAF = WAFDetector()


# UC2 — bot-challenge interstitials (live-observed 2026-10-20). A challenge says
# nothing about the account: it is always *inconclusive*, never "not found", and we
# never try to pass it.
_CHALLENGE_HEADERS: tuple[tuple[str, str], ...] = (
    ("x-vercel-mitigated", "challenge"),  # Vercel Security Checkpoint (TryHackMe)
    ("cf-mitigated", "challenge"),  # Cloudflare managed challenge
)
_CHALLENGE_BODY_MARKERS: tuple[str, ...] = (
    "<title>Just a moment...</title>",  # Cloudflare
    "<title>Client Challenge</title>",  # PyPI / Fastly
    "<title>Vercel Security Checkpoint</title>",
)


def is_challenge_response(headers: object, body: str) -> bool:
    """True when a response is a bot-challenge page rather than the site's answer."""
    try:
        for name, value in _CHALLENGE_HEADERS:
            if value in str(headers.get(name) or "").lower():  # type: ignore[attr-defined]
                return True
    except Exception:
        pass
    head = body[:20_000] if body else ""
    return any(marker in head for marker in _CHALLENGE_BODY_MARKERS)
