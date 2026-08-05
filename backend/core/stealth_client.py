"""Stealth HTTP client for harvest-mode requests.

MailAccess 0.11.1 Phase 1 — replaces plain ``httpx`` for the
free-source harvest modules so search engines (DuckDuckGo, Bing)
stop answering with HTTP 202 / block pages on the back of
``httpx``'s identifiable TLS / HTTP2 fingerprint.

What lives here
---------------

1. :func:`build_chrome_headers` — Chrome 120+ header set, in the
   exact order Chrome sends them.  Includes Sec-Fetch-Site / -Mode /
   -Dest / -User computed from the URL + a referrer, so requests
   pass the server-side fetch-metadata checks that Bing and DDG
   added in 2024–2025.

2. :class:`TimingProfile` — six predefined pacing profiles (T0–T5).
   ``T0 Ghost`` is for the most fingerprint-sensitive flows (DDG /
   Bing), ``T2 Balanced`` is the default, ``T5 Insane`` is the
   disable-delay profile for unit tests and benchmark runs.

3. :class:`StealthSession` — thin wrapper around
   :mod:`curl_cffi.requests.Session` (the synchronous session
   that exposes ``impersonate="chrome120"``).  Exposes both
   ``async get()`` and sync ``get_sync()`` so callers can pick
   the right shape without reaching into curl-cffi internals.

The module is intentionally stateful: ``StealthSession`` keeps
the cookie jar, the last URL (for the next request's
``Referer``), the request count, and the active timing profile.
No global state is mutated at import time.

A soft ``ImportError`` guard means the rest of the codebase can
``import StealthSession`` unconditionally; the actual
``curl_cffi`` import is only attempted when the symbol is
accessed.  This keeps investigation-mode modules (which never
touch this file) immune to the optional dependency.
"""

from __future__ import annotations

import logging
import random
import time as _time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Import guard
# ---------------------------------------------------------------------------
# curl-cffi is an *optional* dep — investigation mode does not need it,
# harvest mode does.  The wrapper exposes ``StealthSession`` / the timing
# helpers even when curl-cffi is not installed, so import-time failure is
# contained to actually using the network layer.
try:
    from curl_cffi import requests as cffi_requests  # type: ignore[import-not-found]
    from curl_cffi.curl import CurlError, CurlHttpVersion  # type: ignore[import-not-found]

    _CFFI_AVAILABLE = True
    _CFFI_IMPORT_ERROR: ImportError | None = None
except ImportError as _exc:  # pragma: no cover — exercised on import
    cffi_requests = None  # type: ignore[assignment]
    CurlError = None  # type: ignore[assignment,misc]
    CurlHttpVersion = None  # type: ignore[assignment,misc]
    _CFFI_AVAILABLE = False
    _CFFI_IMPORT_ERROR = _exc


# ---------------------------------------------------------------------------
# HTTP/2 / HTTP/3 retry
# ---------------------------------------------------------------------------
# curl-cffi raises ``CurlError`` with these codes against servers that
# handle HTTP/2 / HTTP/3 poorly.  Most common offender: INE.com, which
# closes the HTTP/2 stream mid-response and surfaces as code 16
# ("HTTP/2 framing layer error").  Without an automatic downgrade
# retry, the exception propagates to ``site_discovery._get`` which
# catches ALL exceptions and silently returns ``(-1, "")`` — every
# URL on the target site is then dropped on the floor.
#
# Code legend (curl/libcurl):
#   16 = HTTP/2 framing layer error
#   92 = HTTP/2 stream error
#   95 = HTTP/3 error
#
# Retry once on HTTP/1.1 with the same session (per the project
# "no new connections" rule — we still want cookie jar / connection
# pool continuity).
HTTP_VERSION_RETRY_CODES: frozenset[int] = frozenset({16, 92, 95})


def _require_cffi() -> None:
    """Raise a friendly ``ImportError`` when curl-cffi is missing.

    The message tells the user exactly which extra to install — this is
    the only failure mode a non-investigation caller should ever see
    from this module.
    """
    if _CFFI_AVAILABLE:
        return
    raise ImportError(
        "curl-cffi is required for stealth harvest mode but is not installed. "
        "Install the base package: pip install mailaccess"
    ) from _CFFI_IMPORT_ERROR


# ---------------------------------------------------------------------------
# Chrome fingerprint constants
# ---------------------------------------------------------------------------
# These match Chrome 120 on Windows in mid-2024.  Sites verify these
# values for consistency (e.g. sec-ch-ua must match the User-Agent's
# "Chrome/<major>" token, Accept-Encoding must include zstd since
# Chrome 123+).
_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
_SEC_CH_UA = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
_SEC_CH_UA_MOBILE = "?0"
_SEC_CH_UA_PLATFORM = '"Windows"'

_ACCEPT_HTML = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8,"
    "application/signed-exchange;v=b3;q=0.7"
)
_ACCEPT_ENCODING = "gzip, deflate, br, zstd"
_ACCEPT_LANGUAGE = "en-US,en;q=0.9"


# ---------------------------------------------------------------------------
# Header builder
# ---------------------------------------------------------------------------
def _registrable_domain(host: str) -> str:
    """Best-effort registrable domain extraction.

    We use the public-suffix list's effective-TLD+1 heuristic only at the
    "last two labels" granularity (e.g. ``www.bbc.co.uk`` ->
    ``bbc.co.uk``).  That is good enough for the fetch-metadata
    ``Sec-Fetch-Site`` check, which only cares whether two hosts share
    an eTLD+1.
    """
    if not host:
        return ""
    host = host.strip().lower().rstrip(".")
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Two-label TLD heuristic for the well-known multi-label cases —
    # not a full PSL, but matches what fetch-metadata sites do.
    last_two = parts[-2:]
    if len(last_two[0]) <= 3 and len(last_two) == 2:
        return ".".join(parts[-3:]) if len(parts) >= 3 else host
    return ".".join(parts[-2:])


def _classify_sec_fetch_site(url: str, referrer: str | None) -> str:
    """Compute the ``Sec-Fetch-Site`` value Chrome would send.

    Returns one of: ``"none"``, ``"same-origin"``, ``"same-site"``,
    ``"cross-site"``.  See MDN's Sec-Fetch-Site page for the
    algorithm.
    """
    if not referrer:
        return "none"
    try:
        target = urlparse(url)
        ref = urlparse(referrer)
    except ValueError:
        return "cross-site"
    target_host = (target.hostname or "").lower()
    ref_host = (ref.hostname or "").lower()
    if not target_host or not ref_host:
        return "cross-site"
    if target_host == ref_host:
        return "same-origin"
    target_reg = _registrable_domain(target_host)
    ref_reg = _registrable_domain(ref_host)
    if target_reg and target_reg == ref_reg:
        return "same-site"
    return "cross-site"


def build_chrome_headers(
    url: str,
    referrer: str | None = None,
    navigation_type: str = "navigate",
) -> dict[str, str]:
    """Return the full Chrome 120+ header set in Chrome's document order.

    Parameters
    ----------
    url:
        The URL being requested.  Used to compute the relative
        ``Sec-Fetch-Site`` value.
    referrer:
        The page that issued the request.  When ``None`` the function
        assumes the request is a top-level navigation with no
        document referrer (``Sec-Fetch-Site: none``).  When set the
        function computes ``none`` / ``same-origin`` / ``same-site`` /
        ``cross-site`` from the URL and referrer hosts.
    navigation_type:
        ``"navigate"`` (default) — emit the navigation header set
        (Upgrade-Insecure-Requests, Sec-Fetch-User, Sec-Fetch-Mode =
        navigate).  Any other value (e.g. ``"subresource"``) emits
        a subresource-style set without those headers.

    Returns
    -------
    ``dict`` of headers.  Insertion order matches the order Chrome
    itself emits headers (the request lib is expected to preserve it).
    """
    is_navigate = navigation_type == "navigate"
    sec_fetch_site = _classify_sec_fetch_site(url, referrer)

    headers: dict[str, str] = {
        "sec-ch-ua": _SEC_CH_UA,
        "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
    }
    if is_navigate:
        headers["Upgrade-Insecure-Requests"] = "1"
    headers["User-Agent"] = _CHROME_UA
    headers["Accept"] = _ACCEPT_HTML
    headers["Sec-Fetch-Site"] = sec_fetch_site
    headers["Sec-Fetch-Mode"] = "navigate" if is_navigate else "no-cors"
    if is_navigate:
        headers["Sec-Fetch-User"] = "?1"
    headers["Sec-Fetch-Dest"] = "document"
    headers["Accept-Encoding"] = _ACCEPT_ENCODING
    headers["Accept-Language"] = _ACCEPT_LANGUAGE
    if referrer:
        headers["Referer"] = referrer
    return headers


# ---------------------------------------------------------------------------
# Timing profiles
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TimingProfile:
    """Per-request delay distribution.

    ``get_delay()`` samples a Gaussian with ``mean_delay`` and
    ``std_dev`` and clamps the result to ``[min_delay, max_delay]``.
    The ``T5 Insane`` profile is a deterministic zero (used by tests
    and CI runs that do not want real wall-clock pacing).
    """

    name: str
    mean_delay: float
    std_dev: float
    min_delay: float
    max_delay: float
    description: str = ""

    def get_delay(self) -> float:
        """Return one pacing sample, in seconds.

        The ``T5 Insane`` profile short-circuits to ``0.0`` so unit
        tests never spend real wall-clock time on stealth pacing.
        Every other profile returns ``max(min_delay, min(sample,
        max_delay))`` where ``sample`` is drawn from a Gaussian with
        the configured mean / std.
        """
        if self.mean_delay <= 0.0 and self.std_dev <= 0.0:
            return 0.0
        sample = random.gauss(self.mean_delay, self.std_dev)
        if sample < self.min_delay:
            return self.min_delay
        if sample > self.max_delay:
            return self.max_delay
        return sample


# Predefined profiles.  T0 is the most-cautious (T0 Ghost is meant for
# running against DDG / Bing directly with full fingerprint evasion),
# T5 disables pacing entirely.
T0_GHOST = TimingProfile(
    name="T0 Ghost",
    mean_delay=8.0,
    std_dev=3.0,
    min_delay=4.0,
    max_delay=20.0,
    description="Maximum stealth — slow, jittered, ideal for high-fingerprint sites",
)
T1_STEALTH = TimingProfile(
    name="T1 Stealth",
    mean_delay=4.0,
    std_dev=1.5,
    min_delay=2.0,
    max_delay=10.0,
    description="High stealth with faster turnaround than T0",
)
T2_BALANCED = TimingProfile(
    name="T2 Balanced",
    mean_delay=2.0,
    std_dev=0.8,
    min_delay=0.8,
    max_delay=6.0,
    description="Default — slow enough to dodge heuristics, fast enough to finish in time",
)
T3_NORMAL = TimingProfile(
    name="T3 Normal",
    mean_delay=1.0,
    std_dev=0.3,
    min_delay=0.4,
    max_delay=3.0,
    description="Normal human-paced browsing",
)
T4_FAST = TimingProfile(
    name="T4 Fast",
    mean_delay=0.3,
    std_dev=0.1,
    min_delay=0.1,
    max_delay=1.0,
    description="Fast — minimal stealth, use only when the target is permissive",
)
T5_INSANE = TimingProfile(
    name="T5 Insane",
    mean_delay=0.0,
    std_dev=0.0,
    min_delay=0.0,
    max_delay=0.0,
    description="No pacing — for tests and benchmark runs only",
)


# Canonical lookup table, indexed by the lowercase "t0".."t5" codes the
# CLI / env var use.
TIMING_PROFILES: dict[str, TimingProfile] = {
    "t0": T0_GHOST,
    "t1": T1_STEALTH,
    "t2": T2_BALANCED,
    "t3": T3_NORMAL,
    "t4": T4_FAST,
    "t5": T5_INSANE,
}


def resolve_timing_profile(name: str | None) -> TimingProfile:
    """Map a profile name (``"t2"``, ``"T3"``, ``"ghost"``, ...) to a :class:`TimingProfile`.

    Returns ``T2_BALANCED`` when the input is empty or unknown — the
    default the rest of the codebase assumes.
    """
    if not name:
        return T2_BALANCED
    key = str(name).strip().lower()
    if key in TIMING_PROFILES:
        return TIMING_PROFILES[key]
    # Aliases that humans may pass.
    aliases = {
        "ghost": T0_GHOST,
        "stealth": T1_STEALTH,
        "balanced": T2_BALANCED,
        "normal": T3_NORMAL,
        "fast": T4_FAST,
        "insane": T5_INSANE,
    }
    return aliases.get(key, T2_BALANCED)


# ---------------------------------------------------------------------------
# StealthSession
# ---------------------------------------------------------------------------
@dataclass
class StealthSession:
    """Stateful Chrome-impersonating HTTP session.

    Wraps a :class:`curl_cffi.requests.Session` so harvest modules
    can swap their existing ``httpx.AsyncClient`` for this class
    with minimal API churn.  The session is *not* a context manager
    on its own — modules typically construct one inside
    ``__init__`` / ``run()`` and call :meth:`close` when done.  The
    ``async get()`` / ``get_sync()`` methods both block on
    :meth:`get_delay` for inter-request pacing (except the first
    request, which is allowed to fire immediately so a fresh
    session does not waste 8 seconds on the very first packet).

    Attributes
    ----------
    cookie_jar:
        The session's cookie jar (exposed mostly for tests and
        debugging; curl-cffi manages it internally).
    last_url:
        The URL of the last successful request.  Becomes the
        ``Referer`` of the next request.  ``None`` until the first
        request returns.
    timing_profile:
        Active pacing profile.  Swap to :data:`T0_GHOST` for
        maximum stealth.
    request_count:
        Number of requests issued so far.  Monotonic, never
        decremented.
    impersonate:
        Browser fingerprint to impersonate (passed to curl-cffi
        as the ``impersonate`` argument).  Default ``"chrome120"``
        matches the headers in :func:`build_chrome_headers`.
    """

    timing_profile: TimingProfile = T2_BALANCED
    impersonate: str = "chrome120"
    # Per-request timeout (seconds) applied to all curl-cffi get() calls.
    # Default 10s prevents a single unreachable/blocked host from hanging
    # the entire harvest for libcurl's 21s default connection timeout.
    timeout: float = field(default=10.0)

    # Internal state — populated by the lifecycle methods.  Declared as
    # ``field(default=...)`` so the dataclass decorator leaves them
    # alone.
    cookie_jar: Any = field(default=None, init=False, repr=False)
    last_url: str | None = field(default=None, init=False)
    request_count: int = field(default=0, init=False)
    _session: Any = field(default=None, init=False, repr=False)
    _nav_graph_enabled: bool = field(default=False, init=False)
    # Wayback fix: when True the navigation-graph simulation is
    # suppressed even if the timing profile would otherwise enable it.
    # Wayback / archive.org fetches have no fingerprinting check, so
    # the intermediate homepage / parent-path GETs (which include a
    # blocking ``time.sleep`` of 4–20s on T0) are pure overhead — and
    # worse, they have no hard timeout, so a slow archive.org response
    # can deadlock the entire harvest. The inter-request pacing delay
    # (``self.timing_profile.get_delay()``) is kept; only the nav-graph
    # fire-and-discord intermediate pages are skipped.
    _skip_nav_sim: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        """Lazily build the underlying curl-cffi session.

        Defers the actual curl-cffi import to session creation time
        so that the module can be imported even when curl-cffi is
        absent (the :func:`_require_cffi` check is the only thing
        that fails later, with a clear install hint).
        """
        _require_cffi()
        if cffi_requests is None:  # defensive — already checked, but mypy-friendly
            raise ImportError("curl-cffi unavailable")
        self._session = cffi_requests.Session()
        # Coerce the impersonate string to the right shape for
        # curl-cffi.  Accepts "chrome120" / "chrome-120" / "chrome_120"
        # — the library is happy with the un-hyphenated form.
        self._impersonate_value = self.impersonate.replace("-", "").replace("_", "")
        self.cookie_jar = getattr(self._session, "cookies", None)
        # T0 Ghost and T1 Stealth get the navigation graph simulation.
        self._nav_graph_enabled = self.timing_profile in (T0_GHOST, T1_STEALTH)
        # Track how many nav-graph hops have been fired this session.
        self._nav_hop_count: int = 0

    # -- navigation graph simulation --------------------------------------
    def _nav_path_depth(self, path: str) -> int:
        """Return the depth of *path* (segments excluding empty root)."""
        return len([s for s in path.strip("/").split("/") if s])

    def _nav_parent_url(self, url: str) -> str | None:
        """Return the parent-path URL for *url*, or None if already at root."""
        try:
            parsed = urlparse(url)
        except ValueError:
            return None
        path = parsed.path or "/"
        depth = self._nav_path_depth(path)
        if depth <= 1:
            return None
        segments = [s for s in path.strip("/").split("/") if s]
        parent_segments = segments[:-1]
        parent_path = "/" + "/".join(parent_segments)
        return f"{parsed.scheme}://{parsed.netloc}{parent_path}"

    def _simulate_navigation(self, target_url: str) -> None:
        """Fire intermediate page fetches to build a realistic referrer chain.

        Called at the start of every ``_get_sync_inner`` call when
        ``_nav_graph_enabled`` is True (T0 / T1 profiles).

        Rules:
        1. First request (no ``last_url``): fetch the domain homepage.
        2. Same-registrable-domain target with path depth > 1: fetch parent path first.
        3. Never fire more than 2 intermediate hops before the real target.
        4. T0 sessions add dwell time (reading delay) after each intermediate page.
        """
        if self._nav_hop_count >= 2:
            return

        try:
            parsed = urlparse(target_url)
        except ValueError:
            return
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Rule 1: first request — warm up with the homepage.
        if self.last_url is None:
            self._fire_nav_page(base_url)
            self._nav_hop_count += 1
            if self._nav_hop_count >= 2:
                return

        # Rule 2: same-domain deep URL — fetch parent path first.
        if self.last_url is not None:
            try:
                last_parsed = urlparse(self.last_url)
            except ValueError:
                pass
            else:
                target_reg = _registrable_domain(parsed.netloc)
                last_reg = _registrable_domain(last_parsed.netloc)
                if target_reg and target_reg == last_reg:
                    parent = self._nav_parent_url(target_url)
                    if parent and self._nav_hop_count < 2:
                        self._fire_nav_page(parent)
                        self._nav_hop_count += 1

    def _fire_nav_page(self, url: str) -> None:
        """Fetch one navigation page via the underlying curl-cffi session.

        Applies timing delay and updates ``last_url`` and ``request_count``.
        For T0 profiles, dwell time is applied AFTER the fetch.
        Navigation responses are discarded — callers never see them.
        """
        delay = self.timing_profile.get_delay()
        if delay > 0:
            _time.sleep(delay)
        headers = build_chrome_headers(url, referrer=self.last_url)
        try:
            self._session.get(
                url,
                headers=headers,
                impersonate=self._impersonate_value,
            )
        finally:
            self.request_count += 1
        self.last_url = url
        # T0 dwell time: simulates reading / scanning the intermediate page.
        if self.timing_profile is T0_GHOST:
            dwell = max(0.0, random.gauss(2.0, 0.8))
            if dwell > 0:
                _time.sleep(dwell)

    # -- sync helper -----------------------------------------------------
    def _get_sync_inner(self, url: str, **kwargs: Any) -> Any:
        """Run one request through the underlying curl-cffi session.

        Centralises header building, delay application, and the
        ``last_url`` update so :meth:`get` and :meth:`get_sync` cannot
        drift apart.

        HTTP/2 / HTTP/3 errors (curl codes 16, 92, 95) are caught
        and the request is retried exactly once on HTTP/1.1 with the
        same session.  See :data:`HTTP_VERSION_RETRY_CODES` for the
        rationale and code legend.  Any other ``CurlError`` is
        re-raised so the caller (typically
        ``site_discovery._get``) can decide what to do with it.
        """
        # Wayback fix: callers can flip ``_skip_nav_sim = True`` to
        # suppress the navigation-graph simulation against targets that
        # do no fingerprinting (archive.org Wayback snapshots, etc.).
        # The delay below (``timing_profile.get_delay()``) still paces
        # the request normally — only the intermediate homepage /
        # parent-path hops are skipped.
        if self._nav_graph_enabled and not self._skip_nav_sim:
            self._simulate_navigation(url)
        delay = self._resolve_delay()
        if delay > 0:
            _time.sleep(delay)
        headers = build_chrome_headers(url, referrer=self.last_url)
        # Caller-supplied headers win, but we still apply our
        # Chrome-shaped defaults underneath so e.g. a custom UA
        # override still gets a Chrome Sec-Fetch-Site etc.
        merged = dict(headers)
        merged.update(kwargs.pop("headers", {}) or {})
        # The outer ``try``/``finally`` guarantees
        # ``self.request_count += 1`` runs exactly once per call,
        # regardless of which branch (normal / retry / re-raise) the
        # inner block took.  The inner ``try``/``except`` isolates
        # the CurlError retry so the outer bookkeeping still fires
        # even when the except clause re-raises.
        try:
            try:
                response = self._session.get(
                    url,
                    headers=merged,
                    impersonate=self._impersonate_value,
                    timeout=self.timeout,
                    **kwargs,
                )
            except CurlError as exc:
                # Server closed the HTTP/2 / HTTP/3 stream mid-response
                # (most common: INE.com → code 16).  Downgrade to
                # HTTP/1.1 on the same session and try once more.
                # Anything else propagates — the caller decides.
                if int(exc.code) in HTTP_VERSION_RETRY_CODES:
                    _LOG.info(
                        "HTTP/2/3 error (code=%s) on %s, retrying with HTTP/1.1",
                        int(exc.code),
                        url,
                    )
                    response = self._session.get(
                        url,
                        headers=merged,
                        impersonate=self._impersonate_value,
                        http_version=CurlHttpVersion.V1_1,
                        timeout=self.timeout,
                        **kwargs,
                    )
                else:
                    raise
        finally:
            self.request_count += 1
        self.last_url = url
        return response

    def _resolve_delay(self) -> float:
        """First request fires immediately; everything else paces.

        Skipping the delay on the first request keeps startup snappy
        — there is no risk of being clocked as a bot for the first
        packet alone, and modules that fail fast on the first URL
        (e.g. CAPTCHA detection) save the full pacing budget.
        """
        if self.request_count == 0:
            return 0.0
        return float(self.timing_profile.get_delay())

    # -- public surface --------------------------------------------------
    async def get(self, url: str, **kwargs: Any) -> Any:
        """Async-shaped get — schedules the sync call on the default loop.

        curl-cffi ships only a sync ``requests.Session`` (its async
        API requires a different ``AsyncSession`` class which is not
        used here).  We still expose an ``async`` method so callers
        that previously used ``httpx.AsyncClient.get`` keep the
        same shape.
        """
        import asyncio

        return await asyncio.to_thread(self._get_sync_inner, url, **kwargs)

    def get_sync(self, url: str, **kwargs: Any) -> Any:
        """Synchronous get.  Same semantics as :meth:`get` minus the await."""
        return self._get_sync_inner(url, **kwargs)

    def close(self) -> None:
        """Release the underlying curl-cffi session and its connection pool."""
        if self._session is not None:
            with _suppress(Exception):
                self._session.close()
            self._session = None


class _suppress:
    """Tiny context manager that swallows exceptions.

    Vendored here to avoid pulling in ``contextlib.suppress`` noise
    on hot paths.  Used only in :meth:`StealthSession.close`.
    """

    def __init__(self, *exceptions: type[BaseException]) -> None:
        self._exceptions = exceptions or (Exception,)

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return exc_type is not None and issubclass(exc_type, self._exceptions)


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------
__all__ = [
    "TIMING_PROFILES",
    "StealthSession",
    "T0_GHOST",
    "T1_STEALTH",
    "T2_BALANCED",
    "T3_NORMAL",
    "T4_FAST",
    "T5_INSANE",
    "TimingProfile",
    "build_chrome_headers",
    "resolve_timing_profile",
]
