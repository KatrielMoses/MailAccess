"""Subdomain discovery and candidate filtering for Subdomain Intelligence."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlsplit

import dns.asyncresolver
import dns.exception
import dns.query
import dns.resolver
import dns.zone
import httpx

from ..config import settings
from ..core.company_page_names import discover_and_extract
from ..core.http_client import build_client
from ..core.signal_pool import Signal
from ..core.stealth_client import StealthSession
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)
_HOST_RE = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_DEFAULT_WORDLIST = Path(__file__).resolve().parents[2] / "data" / "subdomain_wordlist.json"
_DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)
_STAGING_PREFIXES = frozenset(
    {"stg", "staging", "dev", "development", "test", "qa", "uat", "preview", "sandbox", "demo", "beta", "alpha", "next", "canary"}
)
_TITLE_SIGNAL = re.compile(r"\b(team|people|leadership|staff|board|founders?|executives?)\b", re.I)
_NAME_TITLE_SIGNAL = re.compile(r"\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\s*,\s*[A-Za-z][A-Za-z -]{2,}\b")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.I)
_INFRA_SIGNATURES = (
    "ssh-2.0-", "220 ", "smtp", "ftp server", "cpanel", "plesk", "apache2 ubuntu default",
    "welcome to nginx", "iis windows server", "test page", "default web site",
)
_PARKED_SIGNATURES = (
    "domain is parked", "this domain may be for sale", "buy this domain", "parked free",
    "coming soon", "under construction", "domain parking",
)
_VERTICAL_ALIASES = {
    "medical": "healthcare",
    "university": "education",
    "lms": "education",
    "saas": "tech",
    "agency": "tech",
    "ecommerce": "finance",
}


@dataclass
class DiscoveryResult:
    domain: str
    candidates: dict[str, set[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    axfr_succeeded: bool = False
    wildcard_detected: bool = False
    addresses: dict[str, set[str]] = field(default_factory=dict)
    root_content_hash: str | None = None

    def add(self, hosts: set[str] | list[str], source: str) -> None:
        for host in hosts:
            normalized = normalize_hostname(host, self.domain)
            if normalized:
                self.candidates.setdefault(normalized, set()).add(source)

    @property
    def hosts(self) -> set[str]:
        return set(self.candidates)


@dataclass
class SubdomainBudget:
    """Component-local view of the parent harvest budget."""

    total_seconds: float
    soft_fraction: float = 0.30
    hard_fraction: float = 0.50
    parent: object | None = None
    started: float = field(default_factory=time.monotonic)

    @property
    def soft_seconds(self) -> float:
        return max(0.0, self.total_seconds * self.soft_fraction)

    @property
    def hard_seconds(self) -> float:
        return max(0.0, self.total_seconds * self.hard_fraction)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    @property
    def hard_remaining(self) -> float:
        own = max(0.0, self.hard_seconds - self.elapsed)
        parent_remaining = getattr(self.parent, "remaining", lambda: own)()
        return min(own, max(0.0, float(parent_remaining)))

    @property
    def soft_exceeded(self) -> bool:
        return self.elapsed >= self.soft_seconds

    @property
    def hard_exceeded(self) -> bool:
        return self.hard_remaining <= 0.0

    def can_start(self) -> bool:
        return not self.hard_exceeded


def normalize_hostname(value: str, domain: str) -> str | None:
    """Return a normalized in-scope hostname, excluding the bare domain."""
    host = str(value or "").strip().lower().rstrip(".")
    host = host.removeprefix("*.")
    domain = domain.strip().lower().rstrip(".")
    if not host or host == domain or not host.endswith(f".{domain}"):
        return None
    if any(ch.isspace() for ch in host) or ".." in host:
        return None
    return host


def tier3_excluded(hostname: str, blocklist: list[str] | set[str]) -> bool:
    """Return whether the hostname's leftmost label is explicitly excluded."""
    leftmost = hostname.split(".", 1)[0].lower()
    return leftmost in {str(item).strip().lower() for item in blocklist}


def filter_tier3(candidates: dict[str, set[str]], blocklist: list[str] | set[str]) -> None:
    """Remove Tier 3 hosts in-place immediately after discovery."""
    for hostname in list(candidates):
        if tier3_excluded(hostname, blocklist):
            del candidates[hostname]


def is_staging_hostname(hostname: str) -> bool:
    return hostname.split(".", 1)[0].lower() in _STAGING_PREFIXES


def _first_label(hostname: str) -> str:
    return hostname.split(".", 1)[0].lower()


def _extract_title(html: str) -> str:
    match = re.search(r"<title\b[^>]*>(.*?)</title\s*>", html, re.I | re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", match.group(1))).strip() if match else ""


def _extract_h1(html: str) -> str:
    match = re.search(r"<h1\b[^>]*>(.*?)</h1\s*>", html, re.I | re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", match.group(1))).strip() if match else ""


def _score_label(score: float) -> str:
    if score >= 0.50:
        return "HIGH"
    if score >= 0.25:
        return "MEDIUM"
    if score >= 0.10:
        return "LOW"
    return "SKIP"


def score_subdomain(
    hostname: str,
    domain: str,
    html: str,
    *,
    final_url: str | None = None,
    root_content_hash: str | None = None,
    content_hash: str | None = None,
) -> dict[str, object]:
    """Score one probe response using the requirements signal matrix."""
    body = html or ""
    title = _extract_title(body)
    h1 = _extract_h1(body)
    lower = body.lower()
    url = final_url or f"https://{hostname}/"
    path = (urlsplit(url).path or "/").lower()
    evidence: list[str] = []

    infra = any(signature in lower for signature in _INFRA_SIGNATURES)
    if infra:
        return {"score": None, "tier": "INFRA", "is_staging": is_staging_hostname(hostname), "evidence": ["infrastructure_signature"]}

    score = 0.0
    if _TITLE_SIGNAL.search(title) or _TITLE_SIGNAL.search(h1):
        score += 0.35
        evidence.append("people_title_or_h1")
    if re.search(r'"@type"\s*:\s*"Person"', body, re.I) or re.search(r"'@type'\s*:\s*['\"]Person", body, re.I):
        score += 0.30
        evidence.append("jsonld_person")
    if re.search(r'class\s*=\s*["\'][^"\']*\bvcard\b', body, re.I) or re.search(r'itemprop\s*=\s*["\']name', body, re.I):
        score += 0.25
        evidence.append("hcard_or_vcard")

    domain_emails = {
        match.group(0).lower()
        for match in _EMAIL_RE.finditer(body[:16384])
        if match.group(1).lower().rstrip(".") == domain.lower().rstrip(".")
        or match.group(1).lower().endswith(f".{domain.lower().rstrip('.')}")
    }
    if domain_emails:
        score += min(0.40, 0.20 * len(domain_emails))
        evidence.append(f"on_domain_email:{len(domain_emails)}")
    title_matches = len(_TITLE_SIGNAL.findall(title)) + len(_TITLE_SIGNAL.findall(h1))
    if title_matches:
        score += min(0.30, 0.15 * title_matches)
        evidence.append(f"name_title_pattern:{title_matches}")
    name_title_matches = len(_NAME_TITLE_SIGNAL.findall(body[:16384]))
    if name_title_matches:
        score += min(0.30, 0.15 * name_title_matches)
        evidence.append(f"name_role_pattern:{name_title_matches}")
    if any(token in path for token in ("/team", "/people", "/about", "/staff", "/leadership")):
        score += 0.15
        evidence.append("people_path")
    if _first_label(hostname) in {"blog", "news"} and ("author" in lower or "/by/" in lower):
        score += 0.20
        evidence.append("author_archive")
    if any(token in path for token in ("/careers", "/jobs", "/apply")):
        score += 0.25
        evidence.append("careers_path")
    if re.search(r"\b(sign\s*in|log\s*in|login)\b", title, re.I):
        score -= 0.50
        evidence.append("login_page")
    if any(signature in lower for signature in _PARKED_SIGNATURES):
        score -= 1.00
        evidence.append("parked_page")
    if len(body.encode("utf-8", errors="ignore")) < 500:
        score -= 0.30
        evidence.append("short_content")
    if root_content_hash and content_hash and root_content_hash == content_hash:
        score -= 0.40
        evidence.append("root_content_clone")
    final_domain = (urlsplit(url).hostname or "").lower().rstrip(".")
    if final_domain and final_domain != domain.lower().rstrip(".") and not final_domain.endswith(f".{domain.lower().rstrip('.')}"):
        score -= 0.20
        evidence.append("cross_domain_redirect")

    score = max(0.0, min(1.0, score))
    staging = is_staging_hostname(hostname)
    tier = "HIGH" if staging and score >= 0.10 else _score_label(score)
    if staging and score >= 0.10:
        evidence.append("staging_override")
    return {"score": round(score, 4), "tier": tier, "is_staging": staging, "evidence": evidence}


def load_wordlist(path: Path | None = None) -> dict[str, list[str]]:
    source = path or _DEFAULT_WORDLIST
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.warning("subdomain_intel: wordlist unavailable: %s", exc)
        return {"tier1": [], "tier2": [], "tier3_exclude": [], "vertical_extras": {}}
    return payload if isinstance(payload, dict) else {}


def _hosts_from_text(text: str, domain: str) -> set[str]:
    return {
        host
        for match in _HOST_RE.findall(text or "")
        if (host := normalize_hostname(match, domain))
    }


async def discover_axfr(domain: str, *, resolver: object | None = None) -> set[str]:
    """Attempt AXFR against every authoritative nameserver."""
    resolver = resolver or dns.asyncresolver.Resolver()
    try:
        answers = await resolver.resolve(domain, "NS")  # type: ignore[attr-defined]
    except Exception:
        return set()

    nameservers = [str(answer.target).rstrip(".") for answer in answers]

    async def transfer(ns: str) -> set[str]:
        try:
            ns_answers = await resolver.resolve(ns, "A")  # type: ignore[attr-defined]
            ips = [str(answer) for answer in ns_answers]
        except Exception:
            ips = [ns]
        for ip in ips:
            try:
                zone = await asyncio.to_thread(dns.query.xfr, ip, domain, timeout=5)
                zone_obj = dns.zone.from_xfr(zone)
                return {
                    str(name).rstrip(".")
                    for name in zone_obj.nodes
                    if str(name).strip(".")
                }
            except Exception:
                continue
        return set()

    results = await asyncio.gather(*(transfer(ns) for ns in nameservers))
    return {
        host if host.endswith(f".{domain}") else f"{host}.{domain}"
        for result in results
        for host in result
        if host not in {"@", ""}
    }


async def discover_crtsh(client: httpx.AsyncClient, domain: str) -> set[str]:
    response = await client.get(f"https://crt.sh/?q=%25.{quote(domain)}&output=json")
    if response.status_code != 200:
        return set()
    try:
        records = response.json()
    except ValueError:
        return set()
    values = [str(row.get("name_value", "")) for row in records if isinstance(row, dict)]
    return {host for value in values for host in (_hosts_from_text(value, domain))}


async def discover_subdomain_center(client: httpx.AsyncClient, domain: str) -> set[str]:
    response = await client.get(f"https://subdomain.center/?domain={quote(domain)}")
    if response.status_code != 200:
        return set()
    return _hosts_from_text(response.text, domain)


async def discover_wayback(client: httpx.AsyncClient, domain: str) -> set[str]:
    url = (
        "https://web.archive.org/cdx/search/cdx?"
        f"url=*.{quote(domain)}/*&output=json&fl=original&collapse=urlkey&"
        "filter=statuscode:200&limit=10000"
    )
    response = await client.get(url)
    if response.status_code != 200:
        return set()
    try:
        rows = response.json()
    except ValueError:
        return set()
    values: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        original = row[0] if isinstance(row, list) and row else row
        if not isinstance(original, str):
            continue
        values.add(urlsplit(original).hostname or "")
    return {host for value in values for host in (_hosts_from_text(value, domain))}


async def discover_certspotter(client: httpx.AsyncClient, domain: str) -> set[str]:
    headers = {}
    token = getattr(settings, "certspotter_api_key", None) or os.getenv("CERTSPOTTER_API_KEY")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = await client.get(
        f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}",
        headers=headers,
    )
    if response.status_code != 200:
        return set()
    try:
        records = response.json()
    except ValueError:
        return set()
    values: list[str] = []
    for row in records if isinstance(records, list) else []:
        if not isinstance(row, dict):
            continue
        for key in ("dns_names", "san", "sans", "name_value"):
            raw = row.get(key, [])
            values.extend(str(item) for item in (raw if isinstance(raw, list) else [raw]))
    return {host for value in values for host in (_hosts_from_text(value, domain))}


async def resolve_doh(client: httpx.AsyncClient, hostname: str) -> set[str]:
    """Resolve A/AAAA through Cloudflare, falling back to Google DoH."""
    addresses: set[str] = set()
    for endpoint in _DOH_ENDPOINTS:
        for record_type in ("A", "AAAA"):
            try:
                if "google" in endpoint:
                    response = await client.get(endpoint, params={"name": hostname, "type": record_type})
                else:
                    response = await client.get(
                        endpoint,
                        params={"name": hostname, "type": record_type},
                        headers={"accept": "application/dns-json"},
                    )
                if response.status_code != 200:
                    continue
                payload = response.json()
                for answer in payload.get("Answer", []) if isinstance(payload, dict) else []:
                    if not isinstance(answer, dict) or not answer.get("data"):
                        continue
                    value = str(answer["data"]).strip()
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    addresses.add(value)
            except Exception:
                continue
        if addresses:
            break
    return addresses


async def discover_ptr(
    client: httpx.AsyncClient,
    addresses: dict[str, set[str]],
    domain: str,
) -> set[str]:
    """Mine PTR names for discovered IPs and retain only target-domain hosts."""
    hosts: set[str] = set()
    seen_ips: set[str] = set()
    for values in addresses.values():
        seen_ips.update(values)
    for raw_ip in seen_ips:
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        query = ip.reverse_pointer
        for endpoint in _DOH_ENDPOINTS:
            try:
                response = await client.get(
                    endpoint,
                    params={"name": query, "type": "PTR"},
                    headers={"accept": "application/dns-json"},
                )
                if response.status_code != 200:
                    continue
                payload = response.json()
                for answer in payload.get("Answer", []) if isinstance(payload, dict) else []:
                    if isinstance(answer, dict):
                        hosts.update(_hosts_from_text(str(answer.get("data", "")), domain))
                if hosts:
                    break
            except Exception:
                continue
    return hosts


async def resolve_candidates(
    client: httpx.AsyncClient,
    candidates: dict[str, set[str]],
    *,
    concurrency: int = 30,
) -> dict[str, set[str]]:
    """Resolve all candidates and retain A-only, AAAA-only, and dual-stack hosts."""
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def resolve_one(hostname: str) -> tuple[str, set[str]]:
        async with semaphore:
            return hostname, await resolve_doh(client, hostname)

    resolved = await asyncio.gather(*(resolve_one(host) for host in candidates))
    return {hostname: addresses for hostname, addresses in resolved if addresses}


def _txt_value(record: object) -> str:
    """Normalize dnspython TXT rdata to a plain string."""
    value = getattr(record, "to_text", lambda: str(record))()
    return str(value).strip().strip('"')


async def lookup_asn_team_cymru(ip: str, *, resolver: object | None = None) -> dict[str, object] | None:
    """Resolve an IPv4 address to its origin ASN via Team Cymru DNS."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if parsed.version != 4 or parsed.is_private or parsed.is_loopback or parsed.is_reserved:
        return None
    dns_resolver = resolver or dns.asyncresolver
    try:
        reversed_octets = ".".join(reversed(str(parsed).split(".")))
        answers = await dns_resolver.resolve(
            f"{reversed_octets}.origin.asn.cymru.com", "TXT"
        )
    except Exception:
        return None
    for answer in answers:
        fields = [part.strip() for part in _txt_value(answer).split("|")]
        if len(fields) < 5 or not fields[0].isdigit():
            continue
        return {
            "asn": int(fields[0]),
            "prefix": fields[1],
            "country": fields[2],
            "rir": fields[3],
            "date": fields[4],
        }
    return None


async def lookup_asn_org(asn: int, *, resolver: object | None = None) -> dict[str, object] | None:
    """Resolve a Team Cymru ASN number to its organization name."""
    dns_resolver = resolver or dns.asyncresolver
    try:
        answers = await dns_resolver.resolve(f"AS{int(asn)}.asn.cymru.com", "TXT")
    except Exception:
        return None
    for answer in answers:
        fields = [part.strip() for part in _txt_value(answer).split("|")]
        if len(fields) < 5 or not fields[0].isdigit():
            continue
        return {
            "asn": int(fields[0]),
            "country": fields[1],
            "rir": fields[2],
            "date": fields[3],
            "name": " | ".join(fields[4:]).strip(),
        }
    return None


async def aggregate_infrastructure(
    findings: list[dict[str, object]], *, resolver: object | None = None
) -> dict[str, list[dict[str, object]]]:
    """Aggregate resolved subdomain IPs by origin ASN."""
    ip_hosts: dict[str, set[str]] = {}
    ip_sources: dict[str, set[str]] = {}
    for finding in findings:
        host = str(finding.get("subdomain") or "")
        addresses = finding.get("resolved_ips") or finding.get("addresses") or []
        for raw_ip in addresses if isinstance(addresses, (list, tuple, set)) else []:
            ip = str(raw_ip)
            ip_hosts.setdefault(ip, set()).add(host)
            for source in finding.get("discovery_method") or []:
                ip_sources.setdefault(ip, set()).add(str(source))

    lookups = await asyncio.gather(
        *(lookup_asn_team_cymru(ip, resolver=resolver) for ip in sorted(ip_hosts)),
        return_exceptions=True,
    )
    asn_ips: dict[int, list[str]] = {}
    asn_records: dict[int, dict[str, object]] = {}
    ip_asns: dict[str, int] = {}
    for ip, record in zip(sorted(ip_hosts), lookups):
        if isinstance(record, BaseException) or not isinstance(record, dict):
            continue
        asn = int(record["asn"])
        ip_asns[ip] = asn
        asn_ips.setdefault(asn, []).append(ip)
        asn_records.setdefault(asn, record)

    orgs = await asyncio.gather(
        *(lookup_asn_org(asn, resolver=resolver) for asn in sorted(asn_ips)),
        return_exceptions=True,
    )
    asn_rows: list[dict[str, object]] = []
    for asn, org in zip(sorted(asn_ips), orgs):
        row = dict(asn_records[asn])
        if isinstance(org, dict):
            row.update({key: value for key, value in org.items() if key != "asn"})
        row["asn"] = asn
        row["name"] = row.get("name") or "Unknown"
        row["ips"] = sorted(asn_ips[asn])
        row["cidrs"] = sorted(
            {str(asn_records[asn].get("prefix") or "")} - {""}
        )
        row["subdomains"] = sorted({host for ip in asn_ips[asn] for host in ip_hosts[ip]})
        row["sources"] = sorted({source for ip in asn_ips[asn] for source in ip_sources.get(ip, set())})
        asn_rows.append(row)

    return {
        "ips": [
            {
                "ip": ip,
                "asn": ip_asns.get(ip),
                "subdomains": sorted(ip_hosts[ip]),
                "sources": sorted(ip_sources.get(ip, set())),
            }
            for ip in sorted(ip_hosts)
        ],
        "asns": asn_rows,
    }


async def _content_hash(client: httpx.AsyncClient, hostname: str) -> str | None:
    for scheme in ("https", "http"):
        try:
            response = await client.get(f"{scheme}://{hostname}/")
            if int(getattr(response, "status_code", 0) or 0) >= 400:
                continue
            body = (getattr(response, "content", None) or getattr(response, "text", ""))[:16384]
            if isinstance(body, str):
                body = body.encode("utf-8", errors="ignore")
            return hashlib.sha256(body).hexdigest()
        except Exception:
            continue
    return None


async def probe_subdomain(client: httpx.AsyncClient, hostname: str) -> dict[str, object] | None:
    """Perform the required HEAD plus bounded GET probe."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            try:
                await client.head(url, follow_redirects=True)
            except Exception:
                # Some injected clients and minimal HTTP transports expose GET only.
                pass
            try:
                response = await client.get(url, headers={"Range": "bytes=0-16383"})
            except TypeError:
                response = await client.get(url)
            if int(getattr(response, "status_code", 0) or 0) >= 400:
                continue
            content = getattr(response, "content", None)
            if content is None:
                content = getattr(response, "text", "")
            if isinstance(content, bytes):
                content = content[:16384].decode("utf-8", errors="ignore")
            else:
                content = str(content or "")[:16384]
            final_url = str(getattr(response, "url", None) or url)
            return {"html": content, "url": final_url, "content_hash": hashlib.sha256(content.encode()).hexdigest()}
        except Exception:
            continue
    return None


async def score_live_candidates(
    client: httpx.AsyncClient,
    domain: str,
    candidates: dict[str, set[str]],
    *,
    concurrency: int = 8,
    budget: SubdomainBudget | None = None,
) -> dict[str, dict[str, object]]:
    """Probe and score all live candidates concurrently."""
    root_hash = await _content_hash(client, domain)
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def score_one(hostname: str) -> tuple[str, dict[str, object] | None]:
        async with semaphore:
            if budget is not None and not budget.can_start():
                return hostname, None
            probe = await probe_subdomain(client, hostname)
            if not probe:
                return hostname, None
            scored = score_subdomain(
                hostname,
                domain,
                str(probe["html"]),
                final_url=str(probe["url"]),
                root_content_hash=root_hash,
                content_hash=str(probe["content_hash"]),
            )
            scored["url"] = probe["url"]
            return hostname, scored

    outcomes = await asyncio.gather(*(score_one(host) for host in candidates))
    return {hostname: scored for hostname, scored in outcomes if scored is not None}


def _scrape_profile(tier: str, is_staging: bool) -> dict[str, object] | None:
    if tier in {"SKIP", "INFRA"}:
        return None
    if tier == "HIGH" and is_staging:
        return {
            "timeout": 10.0,
            "max_candidates": 2,
            "candidate_paths": ["/team", "/people", "/staff", "/leadership", "/about", "/board", "/founders"],
        }
    if tier == "HIGH":
        return {"timeout": 8.0, "max_candidates": 1, "candidate_paths": []}
    if tier == "MEDIUM":
        return {"timeout": 3.0, "max_candidates": 1, "candidate_paths": []}
    return None


def profile_behavior(profile: str, *, with_subdomains: bool = False, subdomain_deep: bool = False) -> dict[str, object]:
    """Return the Component 7 profile contract without mutating global settings."""
    normalized = (profile or "t2").lower()
    if normalized not in {"t0", "t1", "t2", "t3", "t4", "t5"}:
        normalized = "t2"
    active = with_subdomains or normalized in {"t0", "t1"}
    deep = subdomain_deep or normalized == "t0"
    scrape_tiers = {
        "t0": {"HIGH", "MEDIUM"},
        "t1": {"HIGH", "MEDIUM"},
        "t2": {"HIGH"},
        "t3": {"HIGH"},
        "t4": {"HIGH"},
        "t5": set(),
    }[normalized]
    return {
        "profile": normalized,
        "passive": True,
        "active": active,
        "tier1": active,
        "tier2": deep,
        "github": deep,
        "scrape_tiers": scrape_tiers,
    }


async def scrape_scored_subdomain(
    session: object,
    hostname: str,
    score_data: dict[str, object],
    *,
    domain: str,
) -> list[dict[str, object]]:
    """Run the existing company-page extractor using the tier profile."""
    tier = str(score_data.get("tier", "SKIP"))
    profile = _scrape_profile(tier, bool(score_data.get("is_staging")))
    if profile is None:
        if tier == "LOW":
            for scheme in ("https", "http"):
                try:
                    response = await session.get(f"{scheme}://{hostname}/", timeout=0.5)
                    html = getattr(response, "text", "") or ""
                    head = html[:1024]
                    return [{
                        "name": None,
                        "email": None,
                        "title": _extract_title(head),
                        "h1": _extract_h1(head),
                        "meta_description": (
                            (match.group(1) if (match := re.search(
                                r'<meta\b[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)',
                                head, re.I,
                            )) else None)
                        ),
                        "url": f"{scheme}://{hostname}/",
                        "subdomain": hostname,
                        "score": score_data.get("score"),
                        "tier": tier,
                    }]
                except Exception:
                    continue
        return []
    try:
        records = await discover_and_extract(
            hostname,
            session,
            aggressive=False,
            max_candidates=int(profile["max_candidates"]),
            timeout=float(profile["timeout"]),
            include_homepage=True,
            candidate_paths=list(profile["candidate_paths"]),
        )
    except Exception as exc:
        _LOG.debug("subdomain_intel: scrape failed for %s: %s", hostname, exc)
        return []
    findings: list[dict[str, object]] = []
    for record in records:
        findings.append(
            {
                "name": getattr(record, "name", None),
                "email": getattr(record, "email", None),
                "title": getattr(record, "title", None),
                "source_type": getattr(record, "source_type", None),
                "confidence": getattr(record, "confidence", None),
                "url": getattr(record, "page_url", None),
                "subdomain": hostname,
                "score": score_data.get("score"),
                "tier": tier,
            }
        )
    return findings


async def scrape_scored_candidates(
    domain: str,
    scored: dict[str, dict[str, object]],
    *,
    session: object | None = None,
    budget: SubdomainBudget | None = None,
) -> dict[str, list[dict[str, object]]]:
    """Scrape eligible candidates with one shared StealthSession."""
    own_session = session is None
    active_session = session or StealthSession(timeout=10.0)
    try:
        pairs = [(host, data) for host, data in scored.items() if budget is None or budget.can_start()]
        tasks = [asyncio.create_task(scrape_scored_subdomain(active_session, host, data, domain=domain)) for host, data in pairs]
        if budget is None:
            outcomes = await asyncio.gather(*tasks)
        else:
            done, pending = await asyncio.wait(tasks, timeout=budget.hard_remaining)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            outcomes = [task.result() for task in done if not task.cancelled() and task.exception() is None]
        return {host: records for (host, _), records in zip(pairs, outcomes) if records}
    finally:
        if own_session and hasattr(active_session, "close"):
            active_session.close()


async def publish_subdomain_signals(
    signal_pool: object,
    domain: str,
    findings: list[dict[str, object]],
) -> int:
    """Publish extracted names and emails through the shared signal pool."""
    published = 0
    publish = getattr(signal_pool, "publish", None)
    if not callable(publish):
        raise TypeError("signal_pool must expose async publish(signal)")
    for finding in findings:
        subdomain = str(finding.get("subdomain") or "")
        discovery_methods = finding.get("discovery_method") or []
        if isinstance(discovery_methods, str):
            discovery_methods = [discovery_methods]
        records = finding.get("scraped") or []
        for record in records:
            if not isinstance(record, dict):
                continue
            metadata = {
                "subdomain": subdomain,
                "url": record.get("url") or finding.get("url"),
                "score": finding.get("score"),
                "tier": finding.get("tier"),
                "is_staging": bool(finding.get("is_staging")),
                "discovery_method": discovery_methods[0] if discovery_methods else "unknown",
                "discovery_methods": list(discovery_methods),
            }
            for kind, value in (("name", record.get("name")), ("email", record.get("email"))):
                cleaned = " ".join(str(value or "").split()) if kind == "name" else str(value or "").strip().lower()
                if not cleaned or (kind == "email" and "@" not in cleaned):
                    continue
                await publish(
                    Signal(
                        kind=kind,
                        value=cleaned,
                        source="subdomain_intel",
                        metadata=metadata.copy(),
                        flags=frozenset({"target_domain_match"}),
                    )
                )
                published += 1
    return published


async def filter_wildcard_by_content_hash(
    client: httpx.AsyncClient,
    domain: str,
    candidates: dict[str, set[str]],
) -> set[str]:
    """Drop brute-force hosts whose first-page content clones the root domain."""
    root_hash = await _content_hash(client, domain)
    if not root_hash:
        return set(candidates)
    keep: set[str] = set()
    for hostname, sources in candidates.items():
        if not any(source.startswith("brute_") for source in sources):
            keep.add(hostname)
            continue
        if await _content_hash(client, hostname) != root_hash:
            keep.add(hostname)
    return keep


async def detect_wildcard(
    domain: str,
    *,
    resolver: object | None = None,
    nonce_count: int = 3,
) -> bool:
    """Treat a domain as wildcarded when all nonce probes resolve identically."""
    resolver = resolver or dns.asyncresolver.Resolver()
    answers: list[frozenset[str]] = []
    for _ in range(nonce_count):
        nonce = secrets.token_hex(8)
        try:
            values: set[str] = set()
            for record_type in ("A", "AAAA"):
                result = await resolver.resolve(f"{nonce}.{domain}", record_type)  # type: ignore[attr-defined]
                values.update(str(answer) for answer in result)
            answers.append(frozenset(values))
        except Exception:
            return False
    return bool(answers and answers[0] and len(set(answers)) == 1)


async def discover_bruteforce(
    client: httpx.AsyncClient,
    domain: str,
    prefixes: list[str],
    *,
    concurrency: int = 20,
    jitter: tuple[float, float] = (0.05, 0.2),
    budget: SubdomainBudget | None = None,
) -> set[str]:
    random_prefixes = list(dict.fromkeys(prefixes))
    random.shuffle(random_prefixes)
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def probe(prefix: str) -> str | None:
        async with semaphore:
            if budget is not None and not budget.can_start():
                return None
            await asyncio.sleep(random.uniform(*jitter))
            host = f"{prefix}.{domain}"
            return host if await resolve_doh(client, host) else None

    results = await asyncio.gather(*(probe(prefix) for prefix in random_prefixes))
    return {host for host in results if host}


async def discover_github(client: httpx.AsyncClient, domain: str) -> set[str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = getattr(settings, "github_token", None) or os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    hosts: set[str] = set()
    for query in (f"*.{domain}", f'"{domain}"'):
        try:
            response = await client.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 100},
                headers=headers,
            )
            if response.status_code not in {200, 401, 403, 422}:
                continue
            payload = response.json()
            for item in payload.get("items", []) if isinstance(payload, dict) else []:
                if isinstance(item, dict):
                    hosts.update(_hosts_from_text(json.dumps(item), domain))
        except Exception:
            continue
    return hosts


class SubdomainIntelModule(BaseModule):
    name = "subdomain_intel"
    description = "Passive and opt-in active subdomain discovery."
    requires_key = False
    priority = 15

    async def run(
        self,
        domain: str,
        *,
        with_subdomains: bool = False,
        subdomain_deep: bool = False,
        profile: str | None = None,
        context_vertical: str | tuple[str, ...] | list[str] | None = None,
        client: httpx.AsyncClient | None = None,
        resolver: object | None = None,
        scrape_session: object | None = None,
        enable_scraping: bool = True,
        signal_pool: object | None = None,
        budget: object | None = None,
        budget_seconds: float | None = None,
        progress_callback: object | None = None,
    ) -> ModuleResult:
        domain = domain.strip().lower().rstrip(".")
        if not domain or "." not in domain:
            return ModuleResult(ModuleStatus.SKIPPED, errors=["invalid domain"])
        if (
            not getattr(settings, "enable_subdomain_intel", True)
            or not getattr(settings, "enable_subdomain_surface", True)
        ):
            return ModuleResult(
                ModuleStatus.SKIPPED,
                metadata={"domain": domain, "skip_reason": "disabled_by_config"},
            )
        behavior = profile_behavior(
            profile or getattr(settings, "harvest_timing_profile", "t2"),
            with_subdomains=with_subdomains,
            subdomain_deep=subdomain_deep,
        )
        profile = str(behavior["profile"])
        active = bool(behavior["active"])
        deep = bool(behavior["tier2"])
        profile_budgets = {"t0": 2700.0, "t1": 1200.0, "t2": 600.0, "t3": 300.0, "t4": 120.0, "t5": 60.0}
        slice_budget = SubdomainBudget(
            budget_seconds or profile_budgets.get(profile, 600.0),
            parent=budget,
        )
        result = DiscoveryResult(domain)
        own_client = client is None
        http = client or build_client(timeout=15.0, follow_redirects=True, max_redirects=2)
        wordlist = load_wordlist()

        try:
            if callable(progress_callback):
                progress_callback(f"Resolving {domain} passive sources...")
            axfr = await discover_axfr(domain, resolver=resolver)
            if axfr:
                result.axfr_succeeded = True
                result.add(axfr, "axfr")
            else:
                certificate_results = await asyncio.gather(
                    discover_crtsh(http, domain),
                    discover_certspotter(http, domain),
                    return_exceptions=True,
                )
                for source, value in zip(
                    ("crt.sh", "certspotter"), certificate_results
                ):
                    if isinstance(value, BaseException):
                        result.errors.append(f"{source}: {value}")
                    else:
                        result.add(value, source)
                sources = [
                    ("subdomain.center", discover_subdomain_center),
                    ("wayback", discover_wayback),
                ]
                for source, discoverer in sources:
                    try:
                        result.add(await discoverer(http, domain), source)
                    except Exception as exc:
                        detail = str(exc).strip() or type(exc).__name__
                        result.errors.append(f"{source}: {detail}")

                if active and slice_budget.can_start():
                    prefixes = list(wordlist.get("tier1", []))
                    raw_verticals = (
                        [context_vertical]
                        if isinstance(context_vertical, str)
                        else list(context_vertical or [])
                    )
                    vertical_extras = wordlist.get("vertical_extras") or {}
                    extras: list[str] = []
                    for vertical in raw_verticals:
                        key = _VERTICAL_ALIASES.get(str(vertical).lower(), str(vertical).lower())
                        extras.extend(vertical_extras.get(key, []))
                    prefixes.extend(list(dict.fromkeys(extras))[:25])
                    result.wildcard_detected = await detect_wildcard(domain, resolver=resolver)
                    concurrency = {"t0": 10, "t1": 20}.get(profile, 30)
                    brute = await discover_bruteforce(http, domain, prefixes, concurrency=concurrency, budget=slice_budget)
                    result.add(brute, "brute_t1")
                    if deep and slice_budget.can_start():
                        result.add(
                            await discover_bruteforce(http, domain, list(wordlist.get("tier2", [])), concurrency=concurrency, budget=slice_budget),
                            "brute_t2",
                        )
                        result.add(await discover_github(http, domain), "github")
        except Exception as exc:
            result.errors.append(f"discovery: {exc}")
        # Component 2: remove Tier 3 noise before any DNS work.
        filter_tier3(result.candidates, wordlist.get("tier3_exclude", []))
        try:
            if callable(progress_callback):
                for hostname in list(result.candidates)[:10]:
                    progress_callback(f"Resolving {hostname}...")
            result.addresses = await resolve_candidates(http, result.candidates)
        except Exception as exc:
            result.errors.append(f"dns: {exc}")
            result.addresses = {}
        result.candidates = {
            hostname: result.candidates[hostname]
            for hostname in result.addresses
            if hostname in result.candidates
        }
        if result.wildcard_detected and result.candidates:
            kept = await filter_wildcard_by_content_hash(http, domain, result.candidates)
            result.candidates = {
                hostname: sources
                for hostname, sources in result.candidates.items()
                if hostname in kept
            }

        if deep and result.addresses and slice_budget.can_start():
            ptr_hosts = await discover_ptr(http, result.addresses, domain)
            if ptr_hosts:
                result.add(ptr_hosts, "ptr")
                filter_tier3(result.candidates, wordlist.get("tier3_exclude", []))
                resolved_ptr = await resolve_candidates(
                    http,
                    {host: sources for host, sources in result.candidates.items() if host not in result.addresses},
                )
                result.addresses.update(resolved_ptr)
                result.candidates = {
                    hostname: sources
                    for hostname, sources in result.candidates.items()
                    if hostname in result.addresses
                }

        scores: dict[str, dict[str, object]] = {}
        if result.candidates:
            try:
                scores = await score_live_candidates(http, domain, result.candidates, budget=slice_budget)
            except Exception as exc:
                result.errors.append(f"scoring: {exc}")

        scraped: dict[str, list[dict[str, object]]] = {}
        scrape_scores = {
            host: data for host, data in scores.items()
            if str(data.get("tier")) in behavior["scrape_tiers"]
        }
        if enable_scraping and scrape_scores and slice_budget.can_start():
            scraped = await scrape_scored_candidates(domain, scrape_scores, session=scrape_session, budget=slice_budget)

        subdomain_findings = [
            {
                "subdomain": host,
                "discovery_method": sorted(result.candidates[host]),
                "addresses": sorted(result.addresses.get(host, set())),
                "resolved_ips": sorted(result.addresses.get(host, set())),
                **scores.get(host, {"score": 0.0, "tier": "SKIP", "is_staging": is_staging_hostname(host), "evidence": ["probe_failed"]}),
                "scraped": scraped.get(host, []),
            }
            for host in sorted(result.hosts)
        ]
        # Keep the email findings emitted by the legacy subdomain surface
        # collector.  The 0.12.3 replacement retained only the host records,
        # which silently removed published role and personal addresses from
        # the harvest aggregate.
        email_findings: list[dict[str, object]] = []
        for host_finding in subdomain_findings:
            for record in host_finding.get("scraped", []) or []:
                if not isinstance(record, dict) or not isinstance(record.get("email"), str):
                    continue
                email = str(record["email"]).strip().lower()
                if "@" not in email:
                    continue
                email_findings.append({
                    "platform": self.name,
                    "profile_url": record.get("url"),
                    "username": email.split("@", 1)[0],
                    "metadata": {
                        "email": email,
                        "on_domain": email.rsplit("@", 1)[-1] == domain,
                        "subdomain": host_finding["subdomain"],
                        "url": record.get("url"),
                        "source_type": "subdomain_surface",
                        "source_types": ["structured_page"],
                        "is_role": bool(record.get("is_role")),
                    },
                })
        findings = subdomain_findings + email_findings
        infrastructure = await aggregate_infrastructure(subdomain_findings, resolver=resolver)
        from .ripe_stat_asn import RIPEStatASNModule
        from .shodan_internetdb import ShodanInternetDBModule

        shodan_records = await ShodanInternetDBModule().enrich(
            [str(row.get("ip")) for row in infrastructure["ips"]],
            client=http,
        )
        for row in infrastructure["ips"]:
            ip = str(row.get("ip") or "")
            if ip in shodan_records:
                row["shodan_data"] = shodan_records[ip]
        ripe_records = await RIPEStatASNModule().enrich(
            infrastructure["asns"], client=http
        )
        for row in infrastructure["asns"]:
            try:
                asn = int(row.get("asn"))
            except (TypeError, ValueError):
                continue
            record = ripe_records.get(asn)
            if not record:
                continue
            prefixes = sorted(
                {
                    *(str(value) for value in row.get("cidrs", []) if value),
                    *(str(value) for value in record.get("prefixes", []) if value),
                }
            )
            row["prefixes"] = prefixes
            row["cidrs"] = prefixes
        if signal_pool is not None and findings:
            try:
                published = await publish_subdomain_signals(signal_pool, domain, findings)
            except Exception as exc:
                result.errors.append(f"signal_pool: {exc}")
                published = 0
        else:
            published = 0
        metadata = {
            "domain": domain,
            "subdomains_found": len(findings),
            "source_counts": {
                source: sum(source in sources for sources in result.candidates.values())
                for source in sorted({source for sources in result.candidates.values() for source in sources})
            },
            "axfr_succeeded": result.axfr_succeeded,
            "wildcard_detected": result.wildcard_detected,
            "active_enabled": active,
            "deep_enabled": deep,
            "profile_behavior": {
                "profile": profile,
                "passive": behavior["passive"],
                "active": active,
                "tier1": behavior["tier1"],
                "tier2": behavior["tier2"],
                "github": behavior["github"],
                "scrape_tiers": sorted(behavior["scrape_tiers"]),
            },
            "signals_published": published,
            "infrastructure": infrastructure,
            "shodan_ips_enriched": len(shodan_records),
            "ripe_asns_enriched": len(ripe_records),
            "budget": {
                "total_seconds": slice_budget.total_seconds,
                "soft_seconds": slice_budget.soft_seconds,
                "hard_seconds": slice_budget.hard_seconds,
                "elapsed_seconds": round(slice_budget.elapsed, 3),
                "soft_exceeded": slice_budget.soft_exceeded,
                "hard_exceeded": slice_budget.hard_exceeded,
            },
        }
        status = ModuleStatus.SUCCESS if findings else ModuleStatus.PARTIAL
        if own_client:
            await http.aclose()
        return ModuleResult(status=status, findings=findings, metadata=metadata, errors=result.errors[:20])


__all__ = [
    "DiscoveryResult", "SubdomainIntelModule", "detect_wildcard", "discover_axfr",
    "discover_bruteforce", "discover_certspotter", "discover_crtsh", "discover_github", "discover_ptr",
    "discover_subdomain_center", "discover_wayback", "load_wordlist", "normalize_hostname",
    "resolve_doh",
]
