from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from typing import TypeVar

import httpx

from ..config import APP_VERSION

_LOG = logging.getLogger(__name__)

# MUST-FIX S6: User-Agent version string is derived from APP_VERSION
# at import time so it stays in sync with the package metadata. Pre-fix
# code had a hardcoded ``mailaccess/0.8.3`` which lagged the actual
# package version and made the tool look stale to target servers.
_USER_AGENT = f"mailaccess/{APP_VERSION}"
_HEADERS = {"User-Agent": _USER_AGENT}


# MUST-FIX S10: shared retry-with-backoff helper for the five HTTP
# collectors. HTTP 429 is a soft-cap from the upstream — they want us
# to slow down, not stop entirely. Exponential backoff (2s/4s/8s)
# usually clears the rate limit window without burning the harvest.
#
# ONLY 429 is retried (per the audit spec): 5xx, timeouts, network
# errors, etc. continue to surface as before (graceful return empty set).
# Retrying other error classes is out of scope — and risks amplifying a
# real outage into a stalled harvest.
_T = TypeVar("_T")


async def _retry_with_backoff(
    fn: Callable[[], Awaitable[_T]],
    *,
    max_retries: int = 3,
    base_delay: float = 2.0,
    label: str = "collector",
) -> _T | None:
    """Call ``fn()`` and retry ONLY on HTTP 429 with exponential backoff.

    MUST-FIX S10: returns ``None`` on any non-429 error or when retries
    are exhausted — the callers expect "empty result" semantics and
    should never raise out of a retry loop. ``label`` is just for log
    messages so we can see which collector gave up.

    ``base_delay=2.0`` is the production default (2s, 4s, 8s); tests
    can pass ``base_delay=0`` to skip the sleep entirely.
    """
    attempt = 0
    while True:
        try:
            result = await fn()
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("%s: request error (no retry): %s", label, exc)
            return None

        # Non-429 errors: return whatever the caller produced (which
        # the collector functions treat as "no result"). We can't read
        # ``.status_code`` here without coupling to httpx.Response, so
        # the collectors wrap the retry themselves below.
        if not isinstance(result, httpx.Response):
            return result
        if result.status_code != 429:
            return result

        # 429: back off.
        attempt += 1
        if attempt > max_retries:
            _LOG.warning(
                "%s: 429 still present after %d retries — giving up",
                label,
                max_retries,
            )
            return None
        delay = base_delay * (2 ** (attempt - 1))
        if delay > 0:
            _LOG.info(
                "%s: 429 rate-limited (attempt %d/%d) — sleeping %.1fs",
                label,
                attempt,
                max_retries,
                delay,
            )
            await asyncio.sleep(delay)


def _strip_wildcard(name: str) -> str:
    return name.lstrip("*.").lower().strip()


def _is_subdomain(name: str, domain: str) -> bool:
    n = name.lower().strip()
    return bool(n) and n.endswith(f".{domain}") or n == domain


def _clean_subdomains(raw: list[str], domain: str) -> set[str]:
    result: set[str] = set()
    for entry in raw:
        for line in entry.splitlines():
            cleaned = _strip_wildcard(line.strip())
            if cleaned and _is_subdomain(cleaned, domain):
                result.add(cleaned)
    return result


# MUST-FIX S10: shared GET primitive that the five collectors call.
# Performs ONE HTTP request through _retry_with_backoff so each
# collector gets the 429-aware retry behaviour without duplicating the
# exponential-backoff loop five times. Returns the httpx.Response on
# success (any 2xx status), or None on a non-429 error / retry exhaustion.
async def _get_with_429_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    sem: asyncio.Semaphore,
    timeout: float,
    label: str,
    max_retries: int = 3,
    base_delay: float = 2.0,
) -> httpx.Response | None:
    async def _do_get() -> httpx.Response | None:
        async with sem:
            try:
                resp = await client.get(url, headers=_HEADERS, timeout=timeout)
            except httpx.TimeoutException:
                _LOG.debug("%s: timeout", label)
                return None
            except Exception as exc:  # noqa: BLE001
                _LOG.debug("%s: request error: %s", label, exc)
                return None
            return resp

    outcome = await _retry_with_backoff(
        _do_get, label=label, max_retries=max_retries, base_delay=base_delay
    )
    if outcome is None or not isinstance(outcome, httpx.Response):
        return None
    if outcome.status_code == 429:
        # retry helper already logged the giving-up message.
        return None
    if outcome.status_code != 200:
        _LOG.debug("%s: HTTP %s", label, outcome.status_code)
        return None
    return outcome


async def collect_crtsh(
    client: httpx.AsyncClient,
    domain: str,
    sem: asyncio.Semaphore,
    timeout: float = 15.0,
) -> set[str]:
    """Fetch subdomain list from crt.sh.

    MUST-FIX S10: ``_get_with_429_retry`` handles 429 retries with
    exponential backoff (2s/4s/8s) before giving up. Non-429 errors
    still surface as empty set (graceful degradation).
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = await _get_with_429_retry(
        client, url, sem=sem, timeout=timeout, label="crtsh"
    )
    if resp is None:
        return set()

    try:
        data = resp.json()
    except Exception:
        _LOG.debug("crtsh: malformed JSON for %s", domain)
        return set()

    if not isinstance(data, list):
        return set()

    raw: list[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value") or ""
        common_name = entry.get("common_name") or ""
        if name_value:
            raw.append(str(name_value))
        if common_name:
            raw.append(str(common_name))

    return _clean_subdomains(raw, domain)


async def collect_rapiddns(
    client: httpx.AsyncClient,
    domain: str,
    sem: asyncio.Semaphore,
    timeout: float = 15.0,
) -> set[str]:
    """Fetch subdomain list from rapiddns.io.

    MUST-FIX S10: 429 → retry via _get_with_429_retry.
    """
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    resp = await _get_with_429_retry(
        client, url, sem=sem, timeout=timeout, label="rapiddns"
    )
    if resp is None:
        return set()

    try:
        html = resp.text
    except Exception:
        return set()

    pattern = re.compile(
        r"<td>([a-z0-9_*.-]+" + re.escape(domain) + r")</td>",
        re.IGNORECASE,
    )
    matches = pattern.findall(html)
    if not matches:
        _LOG.debug("rapiddns: no table matches for %s (structure may have changed)", domain)

    return _clean_subdomains(matches, domain)


async def collect_certspotter(
    client: httpx.AsyncClient,
    domain: str,
    sem: asyncio.Semaphore,
    timeout: float = 15.0,
) -> set[str]:
    """Fetch subdomain list from certspotter.

    MUST-FIX S10: 429 → retry via _get_with_429_retry.
    """
    url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )
    resp = await _get_with_429_retry(
        client, url, sem=sem, timeout=timeout, label="certspotter"
    )
    if resp is None:
        return set()

    try:
        data = resp.json()
    except Exception:
        _LOG.debug("certspotter: malformed JSON for %s", domain)
        return set()

    if not isinstance(data, list):
        return set()

    raw: list[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        dns_names = entry.get("dns_names") or []
        if isinstance(dns_names, list):
            for name in dns_names:
                if name:
                    raw.append(str(name))

    return _clean_subdomains(raw, domain)


async def collect_bufferoverun(
    client: httpx.AsyncClient,
    domain: str,
    sem: asyncio.Semaphore,
    timeout: float = 15.0,
) -> set[str]:
    """Fetch subdomain list from bufferover.run.

    MUST-FIX S10: 429 → retry via _get_with_429_retry.
    """
    url = f"https://tls.bufferover.run/dns?q={domain}"
    resp = await _get_with_429_retry(
        client, url, sem=sem, timeout=timeout, label="bufferoverun"
    )
    if resp is None:
        return set()

    try:
        data = resp.json()
    except Exception:
        _LOG.debug("bufferoverun: malformed JSON for %s", domain)
        return set()

    if not isinstance(data, dict):
        return set()

    raw: list[str] = []
    for key in ("FDNS_A", "RDNS"):
        entries = data.get(key) or []
        if not isinstance(entries, list):
            continue
        for line in entries:
            if not isinstance(line, str):
                continue
            parts = line.split("\t", 1)
            if len(parts) == 2:
                raw.append(parts[1].strip())
            elif len(parts) == 1:
                raw.append(parts[0].strip())

    return _clean_subdomains(raw, domain)


async def collect_threatminer(
    client: httpx.AsyncClient,
    domain: str,
    sem: asyncio.Semaphore,
    timeout: float = 15.0,
) -> set[str]:
    """Fetch subdomain list from threatminer.

    MUST-FIX S10: 429 → retry via _get_with_429_retry.
    """
    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    resp = await _get_with_429_retry(
        client, url, sem=sem, timeout=timeout, label="threatminer"
    )
    if resp is None:
        return set()

    try:
        data = resp.json()
    except Exception:
        _LOG.debug("threatminer: malformed JSON for %s", domain)
        return set()

    if not isinstance(data, dict):
        return set()

    results = data.get("results") or []
    if not isinstance(results, list):
        return set()

    raw = [str(r) for r in results if r]
    return _clean_subdomains(raw, domain)


async def _resolve_a_record(hostname: str, timeout: float) -> list[str]:
    """Resolve *hostname* to its A-record IPs via dnspython's async resolver.

    MUST-FIX M7: the previous implementation used
    ``socket.getaddrinfo(host, None, AF_INET, SOCK_STREAM)``, which
    triggers a TCP SYN to port 0 of the target host on every call.
    For a 200-prefix brute that meant 200 TCP SYNs to ports on
    arbitrary hosts — a textbook IDS-alert pattern on the operator's
    own network AND on the target nameserver.

    dnspython's ``dns.asyncresolver.resolve`` issues proper UDP/53
    DNS queries (falling back to TCP/53 only when the response is
    truncated, which is rare for A records). No TCP SYN packets.
    No port 0 noise.

    Returns the list of IPv4 addresses as strings, or ``[]`` on any
    failure (NXDOMAIN, timeout, no dnspython installed).
    """
    try:
        import dns.asyncresolver  # type: ignore[import]
        import dns.exception  # type: ignore[import]
    except ImportError:
        _LOG.debug("dns_brute: dnspython async resolver unavailable")
        return []

    try:
        answers = await asyncio.wait_for(
            dns.asyncresolver.resolve(hostname, "A"),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return []
    except dns.exception.DNSException:
        return []
    except Exception as exc:  # noqa: BLE001
        # Any other resolver error (network unreachable, etc.) is
        # treated as "host doesn't resolve" — same semantics as
        # gaierror in the old code path.
        _LOG.debug("dns_brute: resolver error for %s: %s", hostname, exc)
        return []

    out: list[str] = []
    for rdata in answers:
        try:
            out.append(str(rdata.address))
        except Exception:
            continue
    return out


async def dns_brute_force(
    client: httpx.AsyncClient,  # noqa: ARG001 — kept for API consistency
    domain: str,
    prefixes: list[str],
    sem: asyncio.Semaphore,
    timeout: float = 5.0,
) -> set[str]:
    """Brute-force candidate subdomains by querying their A records.

    MUST-FIX M7: now uses dnspython's async resolver (proper DNS
    query, no TCP SYN packets). The previous implementation called
    ``socket.getaddrinfo(SOCK_STREAM)`` which attempted a TCP
    connection per hostname — flagging as an attack pattern.
    """
    capped = prefixes[:200]
    found: set[str] = set()

    async def _resolve_one(prefix: str) -> str | None:
        hostname = f"{prefix}.{domain}"
        async with sem:
            ips = await _resolve_a_record(hostname, timeout=timeout)
            return hostname if ips else None

    tasks = [_resolve_one(p) for p in capped]
    results = await asyncio.gather(*tasks)
    for r in results:
        if r is not None:
            found.add(r)
    return found


async def resolve_ips(
    client: httpx.AsyncClient,  # noqa: ARG001 — kept for API consistency
    hosts: set[str],
    sem: asyncio.Semaphore,
    timeout: float = 5.0,
) -> dict[str, list[str]]:
    """Resolve *hosts* to their A-record IPs via dnspython.

    MUST-FIX M7: replaced ``socket.getaddrinfo(SOCK_STREAM)`` (which
    triggered a TCP SYN per host) with proper DNS resolution via
    dnspython. Same semantics, no port-0 noise.
    """
    result: dict[str, list[str]] = {}

    async def _resolve_host(host: str) -> tuple[str, list[str]]:
        async with sem:
            ips = await _resolve_a_record(host, timeout=timeout)
            # MUST-FIX M7: dnspython can return duplicate A records for
            # the same host (round-robin DNS). Dedup by preserving order.
            unique = list(dict.fromkeys(ips))
            return host, unique

    tasks = [_resolve_host(h) for h in hosts]
    pairs = await asyncio.gather(*tasks)
    for host, ips in pairs:
        if ips:
            result[host] = ips
    return result
