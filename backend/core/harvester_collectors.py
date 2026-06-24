from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Any

import httpx

_LOG = logging.getLogger(__name__)

_USER_AGENT = "mailaccess/0.8.3"
_HEADERS = {"User-Agent": _USER_AGENT}


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


async def collect_crtsh(
    client: httpx.AsyncClient,
    domain: str,
    sem: asyncio.Semaphore,
    timeout: float = 15.0,
) -> set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    async with sem:
        try:
            resp = await client.get(url, headers=_HEADERS, timeout=timeout)
        except httpx.TimeoutException:
            _LOG.debug("crtsh: timeout for %s", domain)
            return set()
        except Exception as exc:
            _LOG.debug("crtsh: request error for %s: %s", domain, exc)
            return set()

    if resp.status_code == 429:
        _LOG.warning("crtsh: rate limited (429) for %s — consider spacing requests", domain)
        return set()
    if resp.status_code != 200:
        _LOG.debug("crtsh: HTTP %s for %s", resp.status_code, domain)
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
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    async with sem:
        try:
            resp = await client.get(url, headers=_HEADERS, timeout=timeout)
        except httpx.TimeoutException:
            _LOG.debug("rapiddns: timeout for %s", domain)
            return set()
        except Exception as exc:
            _LOG.debug("rapiddns: request error for %s: %s", domain, exc)
            return set()

    if resp.status_code == 429:
        _LOG.warning("rapiddns: rate limited (429) for %s", domain)
        return set()
    if resp.status_code != 200:
        _LOG.debug("rapiddns: HTTP %s for %s", resp.status_code, domain)
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
    url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )
    async with sem:
        try:
            resp = await client.get(url, headers=_HEADERS, timeout=timeout)
        except httpx.TimeoutException:
            _LOG.debug("certspotter: timeout for %s", domain)
            return set()
        except Exception as exc:
            _LOG.debug("certspotter: request error for %s: %s", domain, exc)
            return set()

    if resp.status_code == 429:
        _LOG.warning("certspotter: rate limited (429) for %s", domain)
        return set()
    if resp.status_code != 200:
        _LOG.debug("certspotter: HTTP %s for %s", resp.status_code, domain)
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
    url = f"https://tls.bufferover.run/dns?q={domain}"
    async with sem:
        try:
            resp = await client.get(url, headers=_HEADERS, timeout=timeout)
        except httpx.TimeoutException:
            _LOG.debug("bufferoverun: timeout for %s", domain)
            return set()
        except Exception as exc:
            _LOG.debug("bufferoverun: request error for %s: %s", domain, exc)
            return set()

    if resp.status_code == 429:
        _LOG.warning("bufferoverun: rate limited (429) for %s", domain)
        return set()
    if resp.status_code != 200:
        _LOG.debug("bufferoverun: HTTP %s for %s", resp.status_code, domain)
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
    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    async with sem:
        try:
            resp = await client.get(url, headers=_HEADERS, timeout=timeout)
        except httpx.TimeoutException:
            _LOG.debug("threatminer: timeout for %s", domain)
            return set()
        except Exception as exc:
            _LOG.debug("threatminer: request error for %s: %s", domain, exc)
            return set()

    if resp.status_code == 429:
        _LOG.warning("threatminer: rate limited (429) for %s", domain)
        return set()
    if resp.status_code != 200:
        _LOG.debug("threatminer: HTTP %s for %s", resp.status_code, domain)
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


async def dns_brute_force(
    client: httpx.AsyncClient,  # noqa: ARG001 — kept for API consistency
    domain: str,
    prefixes: list[str],
    sem: asyncio.Semaphore,
    timeout: float = 5.0,  # noqa: ARG001 — socket timeout applied via asyncio.wait_for
) -> set[str]:
    capped = prefixes[:200]
    found: set[str] = set()

    async def _resolve_one(prefix: str) -> str | None:
        hostname = f"{prefix}.{domain}"
        async with sem:
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(
                        socket.getaddrinfo, hostname, None, socket.AF_INET, socket.SOCK_STREAM
                    ),
                    timeout=5.0,
                )
                return hostname
            except asyncio.TimeoutError:
                return None
            except socket.gaierror:
                return None
            except Exception as exc:
                _LOG.debug("dns_brute: error resolving %s: %s", hostname, exc)
                return None

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
    timeout: float = 5.0,  # noqa: ARG001 — socket timeout applied via asyncio.wait_for
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}

    async def _resolve_host(host: str) -> tuple[str, list[str]]:
        async with sem:
            try:
                infos: list[Any] = await asyncio.wait_for(
                    asyncio.to_thread(
                        socket.getaddrinfo, host, None, socket.AF_INET, socket.SOCK_STREAM
                    ),
                    timeout=5.0,
                )
                ips = list(dict.fromkeys(info[4][0] for info in infos if info and info[4]))
                return host, ips
            except asyncio.TimeoutError:
                return host, []
            except socket.gaierror:
                return host, []
            except Exception as exc:
                _LOG.debug("resolve_ips: error for %s: %s", host, exc)
                return host, []

    tasks = [_resolve_host(h) for h in hosts]
    pairs = await asyncio.gather(*tasks)
    for host, ips in pairs:
        if ips:
            result[host] = ips
    return result
