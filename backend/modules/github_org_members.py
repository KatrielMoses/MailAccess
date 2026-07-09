"""GitHub organization public member discovery module.

0.11.1 Phase 4 — discovers employee emails via GitHub's public
organization member list.  Anonymous API (no auth required) for
public members; uses ``GITHUB_TOKEN`` when available for higher
rate limits (5000 vs 60 req/hr).

Domain → org name derivation:
  1. Fetch the domain homepage, look for ``github.com/{org}`` links.
  2. Fallback candidates: stripped TLD, stripped TLD with hyphens removed,
     title-cased variant, plus common suffixes (-inc, -corp, -hq).
  3. Probe each candidate with GET /orgs/{candidate}.  200 = found.

For confirmed orgs: enumerate public members, fetch each profile,
filter by company field containing the target domain, and emit
FindingItem records.

Module status conventions:
  SUCCESS  — org found and members fetched
  PARTIAL  — org found but rate-limited mid-fetch
  SKIPPED  — no org candidate resolves (NOT FAILED)
  FAILED   — network error
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from ..config import settings
from ..core.email_confidence import compute_confidence_breakdown, label_for_score
from ..core.email_extraction import extract_emails
from ..core.role_classifier import classify_email
from ..core.stealth_client import StealthSession, resolve_timing_profile
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"
# Known GitHub hostname patterns in page source.
_GITHUB_HOST_RE = re.compile(
    r"github\.com/([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)",
    re.IGNORECASE,
)
_TAG_RE = re.compile(r"<[^>]+>")


def _strip_tld(domain: str) -> str:
    """Strip the TLD from a domain, returning the organisational name.

    ``lavellene.net`` → ``lavellene``
    ``acmecorp.co.uk`` → ``co``  (two-label TLD: co is the domain, .uk is TLD)
    ``www.example.com`` → ``example``
    ``foo.bar.acmecorp.net`` → ``acmecorp``
    """
    parts = domain.rstrip("/").split(".")
    if len(parts) == 2:
        return parts[0]
    if len(parts) >= 3:
        return parts[-2]
    return parts[-1] if parts else domain


def _derive_org_candidates(domain: str) -> list[str]:
    """Generate ordered candidate org slugs to probe.

    Order matters — homepage link lookup is tried first (step 1),
    then these candidates in order.
    """
    base = _strip_tld(domain).lower()
    candidates = [base]
    # No-hyphen variant.
    no_hyphen = base.replace("-", "")
    if no_hyphen != base:
        candidates.append(no_hyphen)
    # Title-case variant.
    title_cased = base.title().replace("-", "")
    if title_cased.lower() != base:
        candidates.append(title_cased.lower())
    # Common suffixes.
    for suffix in ("-inc", "-corp", "-hq", "-io"):
        candidate = base + suffix
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _company_matches_domain(company: str | None, domain: str, org_slug: str) -> bool:
    """Return True when *company* field plausibly matches *domain* or *org_slug*."""
    if not company:
        return False
    company_lower = company.lower().strip()
    domain_lower = domain.lower()
    org_lower = org_slug.lower()
    return (
        domain_lower in company_lower
        or org_lower in company_lower
        or company_lower.rstrip(".,;/") == org_lower
    )


async def _probe_org(
    org_slug: str,
    session: httpx.AsyncClient,
    token: str | None,
) -> bool:
    """Return True if the org slug exists on GitHub."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = await session.get(
            f"{_GITHUB_API}/orgs/{org_slug}",
            headers=headers,
            timeout=10.0,
        )
        return resp.status_code == 200
    except Exception:
        return False


async def _fetch_homepage_org(domain: str, stealth: StealthSession) -> str | None:
    """Fetch the domain's homepage and look for a github.com/{org} link.

    Returns the first org slug found, or None.
    """
    url = f"https://{domain}"
    try:
        response = await stealth.get(url, timeout=10.0)
        if response.status_code != 200:
            return None
        body = response.text or ""
        match = _GITHUB_HOST_RE.search(body)
        if match:
            return match.group(1).lower()
    except Exception as exc:
        _LOG.debug("Could not fetch homepage for %s: %s", domain, exc)
    return None


async def _fetch_members(
    org_slug: str,
    session: httpx.AsyncClient,
    token: str | None,
    target_domain: str,
) -> tuple[list[dict[str, Any]], bool]:
    """Fetch public members of *org_slug*, filtered by company field.

    Returns (member_records, rate_limited).
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    members: list[dict[str, Any]] = []
    rate_limited = False

    try:
        resp = await session.get(
            f"{_GITHUB_API}/orgs/{org_slug}/public_members",
            headers=headers,
            timeout=15.0,
        )
        if resp.status_code == 403:
            rate_limited = True
            _LOG.warning("GitHub org members: rate-limited for org=%r", org_slug)
            return [], True
        if resp.status_code != 200:
            return [], False
        member_logins: list[str] = [m.get("login", "") for m in resp.json() or []]
    except Exception as exc:
        _LOG.warning("GitHub org members: failed to fetch member list: %s", exc)
        return [], False

    for login in member_logins:
        try:
            user_resp = await session.get(
                f"{_GITHUB_API}/users/{login}",
                headers=headers,
                timeout=10.0,
            )
            if user_resp.status_code == 403:
                rate_limited = True
                break
            if user_resp.status_code != 200:
                continue
            user = user_resp.json() or {}
        except Exception:
            continue

        name = user.get("name") or user.get("login") or ""
        email = user.get("email") or ""
        company = user.get("company") or ""
        blog = user.get("blog") or ""

        # Filter: company field must contain domain or org slug.
        if not _company_matches_domain(company, target_domain, org_slug):
            continue

        has_email = bool(email and "@" in email)

        members.append(
            {
                "github_login": login,
                "name": name,
                "email": email if has_email else "",
                "company": company,
                "blog": blog,
                "has_email": has_email,
                "confidence": 0.85 if has_email else 0.60,
                "source_type": "github_org_member",
            }
        )

    return members, rate_limited


class GitHubOrgMembersModule(BaseModule):
    """Discover employee emails via GitHub organization public member list.

    Requires no API key by default (60 req/hr anonymous limit).
    When ``GITHUB_TOKEN`` is set: 5000 req/hr.
    """

    name = "github_org_members"
    description = "Employee discovery via GitHub organization public member list"
    requires_key = False
    default_enabled = False  # Domain harvest mode only

    async def run(
        self,
        target: str,
        *,
        lite_mode: bool | None = None,
        use_proxies: bool = False,
    ) -> ModuleResult:  # type: ignore[override]
        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["github_org_members: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        token = settings.github_token

        # Build a shared httpx session for the API calls.
        async with httpx.AsyncClient(follow_redirects=True) as http_session:
            # Step 1: try to derive org from homepage link.
            try:
                stealth_profile = resolve_timing_profile("t2")
                stealth = StealthSession(timing_profile=stealth_profile)
            except ImportError:
                stealth = None

            org_slug: str | None = None
            if stealth is not None:
                org_slug = await _fetch_homepage_org(domain, stealth)

            # Step 2: if no org found on homepage, probe candidates.
            if org_slug is None:
                candidates = _derive_org_candidates(domain)
                for candidate in candidates:
                    if await _probe_org(candidate, http_session, token):
                        org_slug = candidate
                        break

            if org_slug is None:
                return ModuleResult(
                    status=ModuleStatus.SKIPPED,
                    findings=[],
                    errors=[],
                    metadata={
                        "domain": domain,
                        "skip_reason": "no_org_resolved",
                        "candidates_tried": _derive_org_candidates(domain),
                    },
                )

            # Step 3: fetch and filter members.
            members, rate_limited = await _fetch_members(
                org_slug, http_session, token, domain
            )

        if not members and rate_limited:
            return ModuleResult(
                status=ModuleStatus.PARTIAL,
                findings=[],
                metadata={
                    "domain": domain,
                    "org": org_slug,
                    "skip_reason": "rate_limited",
                },
            )

        # ------------------------------------------------------------------
        # Build findings
        # ------------------------------------------------------------------
        findings: list[dict[str, Any]] = []

        for member in members:
            has_email = member["has_email"]
            source_types = ["github_org_member"]
            confidence_info = compute_confidence_breakdown(
                source_types=source_types,
                is_smtp_verified=False,
                is_ca_attested=False,
            )
            classification = (
                classify_email(member["email"]) if has_email else None
            )

            findings.append(
                {
                    "platform": "github_org_member",
                    "profile_url": f"https://github.com/{member['github_login']}",
                    "username": member["github_login"],
                    "confidence": label_for_score(confidence_info.score).lower(),
                    "metadata": {
                        "github_login": member["github_login"],
                        "name": member["name"],
                        "email": member["email"],
                        "company": member["company"],
                        "blog": member["blog"],
                        "has_email": has_email,
                        "source_type": "github_org_member",
                        "confidence_score": round(confidence_info.score, 4),
                        "confidence_breakdown": confidence_info.breakdown,
                        "is_role": classification.is_role if classification else False,
                    },
                }
            )

            # Also emit email-only findings for name consensus engine.
            if has_email and member["email"]:
                extracted = extract_emails(member["email"], target_domain=domain)
                for ext in extracted:
                    source_types_email = ["github_org_member"]
                    ci = compute_confidence_breakdown(
                        source_types=source_types_email,
                        is_smtp_verified=False,
                        is_ca_attested=False,
                    )
                    findings.append(
                        {
                            "platform": "github_org_member",
                            "profile_url": f"https://github.com/{member['github_login']}",
                            "username": ext.local_part if "@" in ext.email else "",
                            "confidence": label_for_score(ci.score).lower(),
                            "metadata": {
                                "email": ext.email,
                                "on_domain": ext.on_domain,
                                "source_type": "github_org_member",
                                "github_login": member["github_login"],
                                "name": member["name"],
                                "confidence_score": round(ci.score, 4),
                                "confidence_breakdown": ci.breakdown,
                            },
                        }
                    )

        status = ModuleStatus.SUCCESS if members else ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            errors=[],
            metadata={
                "domain": domain,
                "org": org_slug,
                "members_found": len(members),
                "members_with_email": sum(1 for m in members if m["has_email"]),
                "rate_limited": rate_limited,
            },
        )
