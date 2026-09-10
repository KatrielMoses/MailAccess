from __future__ import annotations

import asyncio
import html
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import APP_VERSION
from .pre_check import apply_pre_check_values, cookie_header, run_pre_check
from .profile_extractor import extract_profile
from .waf_fingerprints import _WAF

# Single identified User-Agent for every username-url / email-existence probe. Centralised
# here so all probes identify consistently through the one unified detector. Kept dynamic so
# it never goes stale (guarded by S6 test).
_USER_AGENT = f"mailaccess/{APP_VERSION}"


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _domains_match(left: str, right: str) -> bool:
    left_host = urlparse(left).netloc.lower().removeprefix("www.")
    right_host = urlparse(right).netloc.lower().removeprefix("www.")
    return bool(left_host and right_host and left_host == right_host)


def _detect_message(defn: dict[str, Any], body: str) -> str:
    body = html.unescape(body)

    # R3 (S4): body-based detection needs a body. An empty/whitespace response
    # cannot prove existence OR absence, so it is UNKNOWN — never a default "hit"
    # from an absence-only rule that simply failed to find its marker.
    if not body.strip():
        return "inconclusive"

    for marker in _as_list(defn.get("absenceStrs")):
        if marker in body:
            return "miss"

    presense = _as_list(defn.get("presenseStrs"))
    if presense:
        return "hit" if all(marker in body for marker in presense) else "miss"

    if _as_list(defn.get("absenceStrs")):
        return "hit"
    return "miss"


def detect_hit(defn: dict[str, Any], body: str, status: int, final_url: str) -> str:
    """Classify a username-URL / email-existence probe result as hit, miss, or inconclusive."""
    body = html.unescape(body)

    if "e_code" in defn and "m_code" in defn:
        # Two-marker detection (schema contract, mailaccess-sites-schema.md:66-68):
        # EXISTS and NOT-EXISTS are *independent* conditions read from one response, so it
        # costs no extra request. The existence rule decides a hit on its own — status ==
        # ``e_code`` AND (empty or present) ``e_string``; the absence marker is never
        # AND-ed in (doing so suppressed real hits whenever ``m_string`` happened to appear
        # anywhere in a live profile page). Empty markers are vacuous (an empty ``e_string``
        # imposes no presence requirement; an empty ``m_string`` no absence requirement), so
        # status-only rows behave exactly as before.
        e_string = str(defn.get("e_string") or "")
        m_string = str(defn.get("m_string") or "")
        e_present = status == defn.get("e_code") and (not e_string or e_string in body)
        m_present = status == defn.get("m_code") and (not m_string or m_string in body)
        # Absence marker strictly MORE specific than the presence marker: a non-empty
        # ``e_string`` that is a substring of a *present* ``m_string``. The not-found
        # response then necessarily also contains ``e_string``, so exists-first would
        # misread every miss as a hit — e.g. Femometer's not-found body ``{"userId":0}``
        # contains the exists marker ``"userId":`` (the not-found marker is ``"userId":0``).
        # Let the more specific absence signal win in that collision ONLY; status-only
        # rows (empty ``e_string``) and non-overlapping markers are unaffected, and a real
        # account whose body lacks ``m_string`` still hits below.
        if e_present and m_present and e_string and e_string in m_string and e_string != m_string:
            return "miss"
        if e_present:
            return "hit"
        if m_present:
            return "miss"
        return "inconclusive"

    # R3 (S4): classify VALIDITY before existence. A rate-limit / server error
    # (429, 5xx) or an anti-bot challenge body is a PROVIDER-AVAILABILITY failure,
    # so the result is UNKNOWN — never a target hit or miss — for EVERY detector
    # family below (status_code / message / tags / response_url alike). The
    # two-marker contract above is a site-specific positive proof and decides
    # first; everything else must clear this gate. Centralised here so both the
    # username path and the declarative account path share one guard.
    if status == 429 or 500 <= status <= 599:
        return "inconclusive"
    if body and _WAF.is_waf_blocked(body):
        return "inconclusive"

    for marker in defn.get("errors") or {}:
        if str(marker) in body:
            return "inconclusive"

    check_type = str(defn.get("checkType") or "status_code")

    if check_type == "status_code":
        if status == 200:
            for marker in _as_list(defn.get("absenceStrs")):
                if marker in body:
                    return "miss"
            min_response_bytes = defn.get("min_response_bytes", 500)
            try:
                min_response_bytes = int(min_response_bytes)
            except (TypeError, ValueError):
                min_response_bytes = 500
            if len(body) < min_response_bytes:
                return "inconclusive"
            return "hit"
        if status == 404:
            return "miss"
        if status == 403 and defn.get("ignore403"):
            return "inconclusive"
        if status in (429, 503, 599):
            return "inconclusive"
        return "miss"

    if check_type in ("message", "tags"):
        return _detect_message(defn, body)

    if check_type == "response_url":
        error_url = str(defn.get("errorUrl") or "")
        if error_url and error_url in final_url:
            return "miss"
        main_url = str(defn.get("urlMain") or "")
        parsed = urlparse(final_url)
        if main_url and _domains_match(main_url, final_url) and parsed.path in ("", "/", "/404"):
            return "miss"
        if status in (404, 410):
            return "miss"
        if status in (429, 503):
            return "inconclusive"
        return "hit"

    return "miss"


def is_non_discriminating_url(url: str, token: str | None = None) -> bool:
    """RC1 (Output-Trust): True when a 'hit' URL cannot be a user-specific profile.

    A bare domain (``discord.com/``) or a search-results page
    (``fanslist.com/search?q=…``) returns 200 for ANY input, so such a hit is not
    an existence signal. If the probed handle appears in the URL *path* the page
    is user-specific and is kept; otherwise a bare-domain or search URL is
    rejected. Conservative: a non-empty, non-search path with no handle match is
    NOT rejected (many real profiles use numeric ids).
    """
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return False
    path = (parsed.path or "").strip("/").lower()
    query = (parsed.query or "").lower()
    tok = (token or "").strip().lower()
    if tok and tok in path:
        return False  # user-specific profile path → discriminating
    if not path:
        return True  # bare-domain 200
    if any(marker in path for marker in ("search", "find", "lookup", "results")):
        return True  # search-results page
    if any(key in query for key in ("q=", "query=", "search=", "keyword=", "term=", "s=")):
        return True  # search query — succeeds for any input
    return False


def is_confirmed_account_hit(finding: dict[str, Any]) -> bool:
    """The single predicate for "this hit is a confirmed/corroborated account, not a
    speculative localpart-sweep FP."

    Every surface that treats an account hit as FACT — the identity graph, the
    Defender's Brief "confirmed accounts" list, the name-candidate path — must gate on
    this so the same false positive cannot leak into one surface after being kept out
    of another (Output-Trust M1/M2). A hit qualifies only when:

    * it was corroborated (``metadata.verification == "confirmed"`` — platform_dedup
      promotes a dual-confirmed hit), OR
    * it is not speculative/unverified (RC1 caps a raw ``username_platforms`` localpart
      guess to ``verification: unverified`` / ``confidence: low``) AND its URL is
      user-discriminating — NOT a bare domain / search page. ``account_discovery`` emits
      a bare ``https://<domain>`` profile_url for every hit, so an uncorroborated one
      (Femometer/Mastodon-style FP) is correctly rejected here.
    """
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    verification = str((meta or {}).get("verification") or "").lower()
    if verification == "confirmed":
        return True
    if verification == "unverified" or bool((meta or {}).get("speculative")):
        return False
    if str(finding.get("confidence") or "").lower() == "low":
        return False
    url = str(
        finding.get("profile_url")
        or finding.get("url")
        or finding.get("response_url")
        or ""
    )
    token = str(finding.get("username") or (meta or {}).get("username") or "")
    if url and is_non_discriminating_url(url, token or None):
        return False
    return True


def prepare_platform_defn(defn: dict[str, Any], username: str) -> dict[str, Any]:
    """Normalise a site definition for probing.

    Engine templates are pre-expanded at corpus build time, so every row already
    carries its own ``uri_check`` / ``url`` / ``checkType`` / detection markers — no
    engine lookup or Discourse special-casing is needed here. This is a light copy hook kept for
    forward-compatibility and to preserve the ``prepare → probe`` seam.
    """
    return dict(defn)


def username_matches_regex(defn: dict[str, Any], username: str) -> bool:
    regex = defn.get("regexCheck")
    if not regex:
        return True
    try:
        return re.fullmatch(str(regex), username) is not None
    except re.error:
        return False


def substitute_username(value: Any, username: str) -> Any:
    if isinstance(value, str):
        return value.replace("{username}", username)
    if isinstance(value, dict):
        return {key: substitute_username(item, username) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute_username(item, username) for item in value]
    return value


async def probe_platform(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    name: str,
    defn: dict[str, Any],
    username: str,
    timeout: float = 8.0,
) -> tuple[str, str | None, dict[str, str] | None]:
    """Probe one platform. Never raises.

    Returns ``(outcome, detail, profile)`` where ``outcome`` is
    ``hit`` / ``miss`` / ``inconclusive``, ``detail`` is the profile URL on a hit (else a
    short diagnostic), and ``profile`` is best-effort extracted person-data
    (``display_name`` / ``bio`` / ``avatar_url`` / ``location``) on a hit, else ``None``.
    """
    prepared = prepare_platform_defn(defn, username)
    if not username_matches_regex(prepared, username):
        return ("inconclusive", "regex_rejected", None)

    probe_template = prepared.get("uri_check") or prepared.get("urlProbe") or prepared.get("url")
    display_template = prepared.get("url") or prepared.get("uri_check")
    if not probe_template or not display_template:
        return ("inconclusive", "missing_url", None)

    # ``strip_bad_char``: some sites reject usernames containing certain characters
    # (e.g. "."), so the probe strips them before substitution.
    strip_bad_char = prepared.get("strip_bad_char")
    if isinstance(strip_bad_char, str) and strip_bad_char:
        username = re.sub(f"[{re.escape(strip_bad_char)}]", "", username)

    probe_url = str(probe_template).replace("{username}", username)
    display_url = str(display_template).replace("{username}", username)
    # A templated ``errorUrl`` (a redirect target such as
    # ``https://site/search?q={username}``) must have the username baked in before ``detect_hit``
    # does its substring match against the final URL, or it can never match (silent false hits).
    if prepared.get("errorUrl"):
        prepared["errorUrl"] = str(prepared["errorUrl"]).replace("{username}", username)
    method = str(prepared.get("requestMethod") or "GET").upper()
    headers = dict(prepared.get("headers") or {})
    headers.setdefault("User-Agent", _USER_AGENT)
    payload = prepared.get("requestPayload")
    if payload:
        payload = substitute_username(payload, username)
    if prepared.get("protection"):
        timeout = max(timeout, 12.0)

    async with sem:
        try:
            precheck = await run_pre_check(client, prepared, timeout)
            cookies = precheck["cookies"]
            headers = apply_pre_check_values(headers, cookies, precheck["csrf_token"])
            payload = apply_pre_check_values(payload, cookies, precheck["csrf_token"])
            if cookies and "Cookie" not in headers:
                headers["Cookie"] = cookie_header(cookies) or ""
            response = await client.request(
                method,
                probe_url,
                headers=headers,
                json=payload if isinstance(payload, dict | list) else None,
                data=payload if payload and not isinstance(payload, dict | list) else None,
                cookies=cookies or None,
                timeout=timeout,
                follow_redirects=True,
            )
            body = response.text
            # Bot-wall / WAF challenge pages return 200 with real-looking HTML; treat them as
            # inconclusive rather than a false hit (shared fingerprint set — Phase 4 fold).
            if body and _WAF.is_waf_blocked(body):
                return ("inconclusive", "waf_blocked", None)
            verdict = detect_hit(prepared, body, response.status_code, str(response.url))
            if verdict == "hit" and is_non_discriminating_url(str(response.url), username):
                # RC1: a bare-domain / search-URL 200 is not an existence signal.
                return ("inconclusive", "non_discriminating_url", None)
            if verdict == "hit":
                profile = extract_profile(response.text, str(response.url)) or None
                return ("hit", display_url, profile)
            if verdict == "miss":
                return ("miss", None, None)
            return ("inconclusive", f"{name}: {response.status_code}", None)
        except httpx.TimeoutException:
            return ("inconclusive", "timeout", None)
        except Exception as exc:
            return ("inconclusive", str(exc)[:80], None)
