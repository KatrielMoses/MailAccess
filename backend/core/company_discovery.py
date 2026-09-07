"""Phase 5C — company discovery pipeline (segment -> ranked company domains).

A new top-of-funnel entry point: turn a market *segment* (industry / geo / size)
into a ranked list of candidate company domains, BEFORE any harvesting. This is
the actual paid-tool workflow ("give me SaaS companies in Berlin, 50-200 staff"),
built entirely on $0 lawful-public sources.

Design (the exploration-latitude decisions of the 5C brief):

* **Discovery confidence is its own claim.** A company being a plausible segment
  match is a *different* assertion from an email being deliverable — so the
  candidate carries ``discovery_confidence`` / ``discovery_confidence_label`` and
  is NEVER expressed in the contact/email confidence vocabulary. The two are kept
  in separate fields and never fused (Doc-1 #17).

* **Stages are independent and reviewable.** Each source is a stage that returns
  its own findings + any error; the result retains every stage so a reviewer can
  audit which source contributed what. Stages are guarded — one failing (or
  block) never sinks discovery.

* **Fusion by corroboration (noisy-OR).** A domain surfaced by more independent
  stages, higher in results, and matching a registered company name in the target
  jurisdiction scores higher. Noisy-OR over per-signal weights rewards
  corroboration without letting any single weak source dominate.

* **Lawful-public only.** Every stage (search dorking, OpenCorporates free tier,
  Common Crawl host index) is a public source; the pipeline records the run's
  product mode + policy status and the lawful gate classifies ``company_discovery``
  as allowed in every mode (it is in no blocked bucket).

* **Hands off to 5A.** The ranked domain list is written as a CSV whose first
  column is the domain, which ``harvest-emails --file`` consumes directly. No
  harvesting happens here (non-scope).
"""
from __future__ import annotations

import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ..config import APP_VERSION

logger = logging.getLogger(__name__)

# Aggregators / social / directories whose domains are NOT the company's own site
# (they surface in results but are not candidate leads). Their *listings* could be
# mined for company links, but that needs fetching — out of scope for v1, which
# takes company domains straight from organic results.
_NON_COMPANY_HOSTS = frozenset(
    {
        "linkedin.com", "facebook.com", "twitter.com", "x.com", "instagram.com",
        "youtube.com", "crunchbase.com", "wikipedia.org", "yelp.com", "indeed.com",
        "glassdoor.com", "bloomberg.com", "reuters.com", "medium.com", "github.com",
        "amazon.com", "apple.com", "play.google.com", "g2.com", "capterra.com",
        "trustpilot.com", "clutch.co", "pinterest.com", "reddit.com", "quora.com",
        "opencorporates.com", "google.com", "bing.com", "duckduckgo.com",
        "wordpress.com", "wixsite.com", "blogspot.com", "tumblr.com",
    }
)

# Confidence label thresholds (discovery-specific vocabulary — NOT contact labels).
_STRONG = 0.70
_MODERATE = 0.45

# Per-signal base weights for the noisy-OR fusion.
_W_SEARCH_TOP3 = 0.50
_W_SEARCH_TOP10 = 0.40
_W_SEARCH_TAIL = 0.30
_W_OC_NAME_MATCH = 0.50
_W_CC_PRESENT = 0.30

# Rough geo -> ISO country code map for the OpenCorporates jurisdiction filter.
_GEO_COUNTRY = {
    "usa": "us", "united states": "us", "us": "us", "america": "us",
    "uk": "gb", "united kingdom": "gb", "england": "gb", "britain": "gb",
    "germany": "de", "berlin": "de", "munich": "de",
    "france": "fr", "paris": "fr", "canada": "ca", "australia": "au",
    "india": "in", "netherlands": "nl", "spain": "es", "italy": "it",
    "ireland": "ie", "singapore": "sg",
}


@dataclass(frozen=True)
class DiscoveryQuery:
    industry: str
    geo: str = ""
    size: str = ""
    limit: int = 25

    def country_code(self) -> str | None:
        g = (self.geo or "").strip().lower()
        if not g:
            return None
        if g in _GEO_COUNTRY:
            return _GEO_COUNTRY[g]
        # try the last token (e.g. "Berlin, Germany")
        for token in reversed(re.split(r"[\s,]+", g)):
            if token in _GEO_COUNTRY:
                return _GEO_COUNTRY[token]
        return None


@dataclass
class DiscoveryStageResult:
    stage: str
    domains_found: int = 0
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class CandidateDomain:
    domain: str
    company_name: str | None
    discovery_confidence: float
    discovery_confidence_label: str
    discovery_sources: list[str]
    discovery_reasoning: str
    signals: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "company_name": self.company_name,
            # NOTE: discovery_* — deliberately distinct from contact confidence.
            "discovery_confidence": round(self.discovery_confidence, 4),
            "discovery_confidence_label": self.discovery_confidence_label,
            "discovery_sources": self.discovery_sources,
            "discovery_reasoning": self.discovery_reasoning,
            "signals": self.signals,
        }


@dataclass
class DiscoveryResult:
    query: DiscoveryQuery
    mode: str
    policy_status: str
    candidates: list[CandidateDomain]
    stages: list[DiscoveryStageResult]
    generated_at: str
    mailaccess_version: str = APP_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "company_discovery",
            "schema_version": 1,
            "generated_at": self.generated_at,
            "mailaccess_version": self.mailaccess_version,
            "mode": self.mode,
            "policy_status": self.policy_status,
            "query": {
                "industry": self.query.industry,
                "geo": self.query.geo,
                "size": self.query.size,
                "limit": self.query.limit,
            },
            "candidate_count": len(self.candidates),
            "stages": [
                {"stage": s.stage, "domains_found": s.domains_found,
                 "error": s.error, "detail": s.detail}
                for s in self.stages
            ],
            "candidates": [c.as_dict() for c in self.candidates],
        }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _registrable_domain(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    # two-label TLD heuristic (co.uk, com.au, …)
    if len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_company_domain(domain: str) -> bool:
    if not domain or "." not in domain:
        return False
    from .email_extraction import validate_domain

    if domain in _NON_COMPANY_HOSTS:
        return False
    # exclude subdomains of known non-company hosts
    if any(domain == h or domain.endswith("." + h) for h in _NON_COMPANY_HOSTS):
        return False
    return validate_domain(domain, reject_free_provider=True)


def _name_token(domain: str) -> str:
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _noisy_or(weights: list[float]) -> float:
    product = 1.0
    for w in weights:
        product *= (1.0 - max(0.0, min(1.0, w)))
    return 1.0 - product


def _label(score: float) -> str:
    if score >= _STRONG:
        return "STRONG"
    if score >= _MODERATE:
        return "MODERATE"
    return "WEAK"


def build_segment_queries(query: DiscoveryQuery) -> list[str]:
    """Segment dork queries (industry + geo + size). Intentionally short — every
    extra query is one closer to a search block (5B territory)."""
    industry = query.industry.strip()
    geo = query.geo.strip()
    size = query.size.strip()
    queries: list[str] = []
    base = f'"{industry}" company' if industry else "company"
    if geo:
        queries.append(f'{base} {geo}')
        queries.append(f'{industry} companies in {geo}')
    else:
        queries.append(base)
        queries.append(f'{industry} companies')
    if size:
        queries.append(f'{industry} company {geo} {size} employees'.strip())
    # de-dup, drop empties
    seen: set[str] = set()
    out: list[str] = []
    for q in queries:
        q = re.sub(r"\s+", " ", q).strip()
        if q and q not in seen:
            seen.add(q)
            out.append(q)
    return out


# ---------------------------------------------------------------------------
# stages
# ---------------------------------------------------------------------------
SearchFn = Callable[[str], Awaitable[list[Any]]]
OcSearchFn = Callable[[str, str | None], Awaitable[list[dict[str, Any]]]]
CcCheckFn = Callable[[str], Awaitable[bool]]


async def _stage_search(
    query: DiscoveryQuery, search_fn: SearchFn, acc: dict[str, dict[str, Any]]
) -> DiscoveryStageResult:
    """Search dorking — the primary segment->domain resolver."""
    queries = build_segment_queries(query)
    found = 0
    errors: list[str] = []
    for q in queries:
        try:
            rows = await search_fn(q)
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
            continue
        for rank, row in enumerate(rows or []):
            url = getattr(row, "url", None) or (row.get("url") if isinstance(row, dict) else None)
            if not url:
                continue
            try:
                host = urlparse(url if "://" in str(url) else f"https://{url}").hostname or ""
            except ValueError:
                continue
            domain = _registrable_domain(host)
            if not _is_company_domain(domain):
                continue
            weight = (
                _W_SEARCH_TOP3 if rank < 3
                else _W_SEARCH_TOP10 if rank < 10
                else _W_SEARCH_TAIL
            )
            slot = acc.setdefault(domain, {"weights": [], "sources": set(), "signals": {}})
            slot["weights"].append(weight)
            slot["sources"].add("search")
            sig = slot["signals"].setdefault("search", {"queries": [], "best_rank": rank})
            sig["queries"].append(q)
            sig["best_rank"] = min(sig["best_rank"], rank)
            found += 1
    return DiscoveryStageResult(
        stage="search", domains_found=len({d for d in acc if "search" in acc[d]["sources"]}),
        error="; ".join(errors) or None, detail={"queries": queries},
    )


async def _stage_opencorporates(
    query: DiscoveryQuery, oc_fn: OcSearchFn, acc: dict[str, dict[str, Any]]
) -> DiscoveryStageResult:
    """OpenCorporates corroboration: a discovered domain whose name-token matches a
    registered company in the target jurisdiction gets a name-match signal."""
    try:
        companies = await oc_fn(query.industry, query.country_code())
    except Exception as exc:  # noqa: BLE001
        return DiscoveryStageResult(stage="opencorporates", error=str(exc))
    names = [str(c.get("name") or "").lower() for c in companies if isinstance(c, dict)]
    names = [n for n in names if n]
    matched = 0
    for domain, slot in acc.items():
        token = _name_token(domain)
        if not token:
            continue
        hit = next((n for n in names if token in n.replace(" ", "")), None) or \
            next((n for n in names if token in n), None)
        if hit:
            slot["weights"].append(_W_OC_NAME_MATCH)
            slot["sources"].add("opencorporates")
            slot["signals"]["opencorporates"] = {"matched_name": hit}
            if not slot.get("company_name"):
                slot["company_name"] = hit.title()
            matched += 1
    return DiscoveryStageResult(
        stage="opencorporates", domains_found=matched,
        detail={"companies_seen": len(names), "country_code": query.country_code()},
    )


async def _stage_common_crawl(
    cc_fn: CcCheckFn, acc: dict[str, dict[str, Any]], *, limit: int
) -> DiscoveryStageResult:
    """Common Crawl host-index presence — a cheap liveness corroboration for the
    top candidates (bounded so it never becomes the slow path)."""
    # only validate the current top-N by provisional search weight
    ranked = sorted(
        acc.items(), key=lambda kv: _noisy_or(kv[1]["weights"]), reverse=True
    )[: max(0, limit)]
    present = 0
    for domain, slot in ranked:
        try:
            ok = await cc_fn(domain)
        except Exception:  # noqa: BLE001
            ok = False
        if ok:
            slot["weights"].append(_W_CC_PRESENT)
            slot["sources"].add("common_crawl")
            slot["signals"]["common_crawl"] = {"present": True}
            present += 1
    return DiscoveryStageResult(stage="common_crawl", domains_found=present)


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
async def discover_companies(
    query: DiscoveryQuery,
    *,
    mode: str | None = None,
    search_fn: SearchFn | None = None,
    oc_fn: OcSearchFn | None = None,
    cc_fn: CcCheckFn | None = None,
) -> DiscoveryResult:
    """Run the discovery pipeline and return a ranked candidate-domain list.

    Sources are injectable for testing; the defaults use the live lawful-public
    sources. ``mode`` defaults to public-business-contact (lead-gen); the lawful
    gate governs ``company_discovery`` as an allowed-in-all-modes public source.
    """
    from .product_mode import (
        DEFAULT_MODE,
        ProductMode,
        is_module_allowed,
        normalize_mode,
        policy_status_for_mode,
    )

    # Lead-gen default; a bad mode is a hard error (never a silent fallback).
    resolved = normalize_mode(mode) if mode else ProductMode.PUBLIC_BUSINESS_CONTACT
    # Defensive: the gate must permit discovery in this mode (it always should —
    # company_discovery is lawful-public, in no blocked bucket).
    if not is_module_allowed("company_discovery", resolved):
        resolved = DEFAULT_MODE
    policy_status = policy_status_for_mode(resolved)

    search_fn = search_fn or _default_search_fn()
    oc_fn = oc_fn or _default_oc_fn()

    acc: dict[str, dict[str, Any]] = {}
    stages: list[DiscoveryStageResult] = []

    stages.append(await _stage_search(query, search_fn, acc))
    stages.append(await _stage_opencorporates(query, oc_fn, acc))
    if cc_fn is not None:
        stages.append(await _stage_common_crawl(cc_fn, acc, limit=query.limit))

    candidates: list[CandidateDomain] = []
    for domain, slot in acc.items():
        score = _noisy_or(slot["weights"])
        sources = sorted(slot["sources"])
        reasoning = f"corroborated by {len(sources)} source(s): {', '.join(sources)}"
        candidates.append(
            CandidateDomain(
                domain=domain,
                company_name=slot.get("company_name"),
                discovery_confidence=score,
                discovery_confidence_label=_label(score),
                discovery_sources=sources,
                discovery_reasoning=reasoning,
                signals=slot["signals"],
            )
        )
    candidates.sort(key=lambda c: (c.discovery_confidence, c.domain), reverse=True)
    candidates = candidates[: max(1, query.limit)]

    return DiscoveryResult(
        query=query,
        mode=resolved.value,
        policy_status=policy_status,
        candidates=candidates,
        stages=stages,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# default live sources (guarded, lawful-public)
# ---------------------------------------------------------------------------
def _default_search_fn() -> SearchFn:
    async def _search(query: str) -> list[Any]:
        from .search_provider_router import SearchProviderRouter

        try:
            return await SearchProviderRouter().search(query, max_results=15)
        except Exception:
            logger.debug("discovery search failed for %r", query, exc_info=True)
            return []

    return _search


def _default_oc_fn() -> OcSearchFn:
    async def _oc(industry: str, country_code: str | None) -> list[dict[str, Any]]:
        from .http_client import build_client

        params: dict[str, str] = {"q": industry, "format": "json"}
        if country_code:
            params["country_code"] = country_code
        try:
            async with build_client(timeout=12.0, follow_redirects=True) as client:
                resp = await client.get(
                    "https://api.opencorporates.com/v0.4/companies/search", params=params
                )
                data = resp.json()
        except Exception:
            logger.debug("discovery OpenCorporates lookup failed", exc_info=True)
            return []
        results = data.get("results", {}) if isinstance(data, dict) else {}
        companies = (results or {}).get("companies", [])
        out: list[dict[str, Any]] = []
        for entry in companies:
            company = (entry or {}).get("company") if isinstance(entry, dict) else None
            if isinstance(company, dict) and company.get("name"):
                out.append({
                    "name": company["name"],
                    "jurisdiction": company.get("jurisdiction_code"),
                })
        return out

    return _oc


def discovery_to_csv(result: DiscoveryResult) -> str:
    """Render the ranked candidates as a CSV whose FIRST column is the domain, so
    ``harvest-emails --file`` consumes it directly (5A hand-off)."""
    lines = ["domain,company_name,discovery_confidence,discovery_confidence_label,sources"]
    for c in result.candidates:
        name = (c.company_name or "").replace(",", " ")
        lines.append(
            f"{c.domain},{name},{c.discovery_confidence:.4f},"
            f"{c.discovery_confidence_label},{'|'.join(c.discovery_sources)}"
        )
    return "\n".join(lines) + "\n"


__all__ = [
    "DiscoveryQuery",
    "CandidateDomain",
    "DiscoveryResult",
    "discover_companies",
    "discovery_to_csv",
    "build_segment_queries",
]
