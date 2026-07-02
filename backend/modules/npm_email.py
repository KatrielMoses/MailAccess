"""npm Registry email discovery (domain harvest mode) — W5 of 0.10.0.

This module queries the public npm registry
(``registry.npmjs.org``) for package metadata whose author or
maintainer email addresses match the target domain.  It slots into
Phase 1 of the domain harvest orchestrator (the parallel fast /
cheap-sources phase) and runs concurrently with ``commoncrawl_email``
and ``code_and_cert_email`` via ``asyncio.gather``.

Why a separate module from the existing ``npm_discovery``:
    The existing ``npm_discovery`` module is a SINGLE-EMAIL-mode
    investigator — given a known email, find packages authored /
    maintained by that person.  This new ``npm_email`` module is
    DOMAIN-mode — given a target domain, find ALL packages whose
    author / maintainer email matches that domain.

    The existing ``npm_discovery`` is NOT modified; consolidation
    between the two execution paths is left as a future cleanup
    (the audit calls out to note overlap in code comments).

Why strict domain filtering matters here:
    The npm registry contains EVERY email of EVERY maintainer of
    EVERY package.  If we naively returned all author/maintainer
    emails in a search result, we would harvest emails from random
    contributors who happened to work on a package related to the
    domain keyword (e.g. ``support@example-fork.com`` ends up
    matching ``example.com`` only because of substring overlap).
    The strict "email's domain must equal the target domain" filter
    is what makes this module useful rather than noise.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings
from ..core.email_confidence import compute_confidence_breakdown, label_for_score
from ..core.http_client import build_client
from ..core.role_classifier import classify_email
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

# Public npm registry endpoints — no authentication required for read-only
# metadata queries.  The npm registry is generally tolerant but we still
# apply a polite 1 req / 2s cadence (configured via ``_RATE_LIMIT_SECONDS``).
_NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
_NPM_PACKAGE_URL = "https://registry.npmjs.org/{}"

_REQUEST_TIMEOUT = 8.0
_RATE_LIMIT_SECONDS = 2.0
_MAX_SEARCH_RESULTS = 20  # npm search endpoint size cap

# Source-weight identifier (mirrors SOURCE_WEIGHTS key in email_confidence).
_TYPE = "npm_package_author"


@dataclass
class _SubSourceOutcome:
    source_id: str  # "search" | "direct_keyword"
    ok: bool = False
    error: str | None = None
    count: int = 0
    packages_checked: int = 0
    emails: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def _domain_keyword(domain: str) -> str | None:
    """Derive a package-name guess from a domain.

    For ``example.com`` → ``example``; for ``www.stripe.com`` →
    ``stripe``.  Returns None when the keyword would be too short,
    all-numeric, or otherwise unsuitable as a package name.
    """
    if not domain or "." not in domain:
        return None
    parts = [p for p in domain.lower().split(".") if p]
    if not parts:
        return None
    # Prefer the second-to-last segment — handles ``stripe.com`` →
    # ``stripe`` and ``co.uk`` ccTLDs cleanly (``bbc.co.uk`` → ``bbc``).
    if len(parts) >= 2:
        keyword = parts[-2]
    else:
        keyword = parts[0]
    if len(keyword) < 4:
        return None
    if not any(c.isalpha() for c in keyword):
        return None
    if keyword.replace("-", "").isdigit():
        return None
    return keyword


def _email_domain_matches(email: str, target_domain: str) -> bool:
    """Strict domain-equality check used by the filter.

    An email passes when the LHS of the ``@`` matches *target_domain*
    EXACTLY (case-insensitive).  Substring / suffix / contains checks
    are intentionally NOT used — a contributor with
    ``alice@example-fork.com`` should NOT match a target of
    ``example.com``.
    """
    if not email or "@" not in email:
        return False
    _, _, dom = email.strip().lower().rpartition("@")
    return bool(dom) and dom == target_domain.lower()


def _extract_email_from_maintainer(obj: Any) -> str | None:
    """Maintainer entries in npm metadata can be ``str`` or ``dict``."""
    if isinstance(obj, dict):
        value = obj.get("email")
        return str(value).strip().lower() if value else None
    if isinstance(obj, str) and "@" in obj:
        return obj.strip().lower()
    return None


class NpmEmailModule(BaseModule):
    """DOMAIN-mode: discover maintainer emails on the npm registry."""

    name = "npm_email"
    description = (
        "Email discovery via npm registry package metadata — "
        "extracts author and maintainer emails that match the target domain."
    )
    requires_key = False
    default_enabled = False  # domain harvest mode only

    async def run(self, target: str) -> ModuleResult:  # type: ignore[override]
        if not settings.enable_npm_email:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "npm_email disabled — set ENABLE_NPM_EMAIL=true to enable"
                ],
            )

        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["npm_email: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        outcomes: dict[str, _SubSourceOutcome] = {
            "search": _SubSourceOutcome(source_id="search"),
            "direct_keyword": _SubSourceOutcome(source_id="direct_keyword"),
        }

        # email -> {
        #   "types": set[str] (currently a single source type — reserved),
        #   "evidence": list[dict] (per-finding package metadata),
        # }
        aggregated: dict[str, dict[str, Any]] = {}

        try:
            async with build_client(timeout=_REQUEST_TIMEOUT) as client:
                # --- Step 1: search the registry for packages whose
                # text mentions the target domain. -------------------
                search_outcome = await self._search_registry(
                    client, domain
                )
                outcomes["search"] = search_outcome
                for email, evidence in search_outcome.emails.items():
                    bucket = aggregated.setdefault(
                        email, {"types": set(), "evidence": []}
                    )
                    bucket["types"].add(_TYPE)
                    bucket["evidence"].extend(evidence)

                # --- Step 2: direct package lookup by domain keyword. ---
                keyword = _domain_keyword(domain)
                if keyword:
                    direct_outcome = await self._direct_package_lookup(
                        client, keyword, domain
                    )
                    outcomes["direct_keyword"] = direct_outcome
                    for email, evidence in direct_outcome.emails.items():
                        bucket = aggregated.setdefault(
                            email, {"types": set(), "evidence": []}
                        )
                        bucket["types"].add(_TYPE)
                        bucket["evidence"].extend(evidence)
                else:
                    outcomes["direct_keyword"].error = (
                        "no_keyword_from_domain"
                    )
        except Exception as exc:
            _LOG.error("npm_email: catastrophic error: %s", exc)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"npm_email: {exc}"],
                metadata={"domain": domain},
            )

        # ------------------------------------------------------------------
        # Build findings
        # ------------------------------------------------------------------
        findings: list[dict[str, Any]] = []
        role_count = 0
        personal_count = 0
        on_domain_count = 0

        for email in sorted(aggregated):
            data = aggregated[email]
            confidence_info = compute_confidence_breakdown(
                source_types=[_TYPE],
                is_smtp_verified=False,
                is_ca_attested=False,
                oldest_timestamp=None,
            )
            classification = classify_email(email)
            local_part = email.split("@", 1)[0]
            _, _, dom = email.partition("@")
            on_domain = bool(dom and dom == domain)
            if on_domain:
                on_domain_count += 1

            findings.append(
                {
                    "platform": "npm_email",
                    "profile_url": f"https://www.npmjs.com/~{local_part}"
                    if on_domain
                    else "",
                    "username": local_part,
                    "confidence": label_for_score(confidence_info.score).lower(),
                    "metadata": {
                        "email": email,
                        "on_domain": on_domain,
                        "source_type": _TYPE,
                        "all_sources": sorted(data["types"]),
                        "evidence": data["evidence"][:8],
                        "is_role": classification.is_role,
                        "role_match_type": classification.match_type,
                        "role_confidence": classification.confidence,
                        "role_matched_prefix": classification.matched_prefix,
                        "confidence_score": round(confidence_info.score, 4),
                        "confidence_breakdown": confidence_info.breakdown,
                    },
                }
            )
            if classification.is_role:
                role_count += 1
            else:
                personal_count += 1

        # ------------------------------------------------------------------
        # Module status
        # ------------------------------------------------------------------
        ok_count = sum(
            1
            for o in outcomes.values()
            if o.ok or o.packages_checked or o.emails
        )
        if ok_count == 0:
            status = ModuleStatus.FAILED
        elif ok_count == 1:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "domain": domain,
                "packages_checked_search": outcomes["search"].packages_checked,
                "packages_checked_direct": outcomes["direct_keyword"].packages_checked,
                "total_unique_emails": len(aggregated),
                "on_domain_emails": on_domain_count,
                "role_accounts": role_count,
                "personal_emails": personal_count,
                "sub_source_outcomes": {
                    sid: {"ok": o.ok, "error": o.error, "count": o.count}
                    for sid, o in outcomes.items()
                },
            },
        )

    # ----------------------------------------------------------------------
    # Sub-source fetchers
    # ----------------------------------------------------------------------
    async def _throttle(self) -> None:
        """Polite 1 req / 2s pacing for the npm registry."""
        await asyncio.sleep(_RATE_LIMIT_SECONDS)

    async def _search_registry(
        self, client: httpx.AsyncClient, domain: str
    ) -> _SubSourceOutcome:
        outcome = _SubSourceOutcome(source_id="search")
        try:
            await self._throttle()
            response = await client.get(
                _NPM_SEARCH_URL,
                params={"text": domain, "size": str(_MAX_SEARCH_RESULTS)},
                timeout=_REQUEST_TIMEOUT,
            )
        except httpx.TimeoutException:
            outcome.error = "search_timeout"
            return outcome
        except Exception as exc:
            outcome.error = f"search_request:{exc}"
            return outcome

        if response.status_code == 429:
            outcome.error = "search_rate_limited"
            return outcome
        if response.status_code != 200:
            outcome.error = f"search_http_{response.status_code}"
            return outcome

        try:
            data = response.json()
        except Exception as exc:
            outcome.error = f"search_invalid_json:{exc}"
            return outcome

        objects = (
            data.get("objects") if isinstance(data.get("objects"), list) else []
        )
        outcome.packages_checked = len(objects)
        outcome.ok = True

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            pkg = (
                obj.get("package") if isinstance(obj.get("package"), dict) else {}
            )
            pkg_name = str(pkg.get("name") or "")
            # Top-level publisher / maintainer from search index entry.
            publisher = pkg.get("publisher") if isinstance(pkg.get("publisher"), dict) else {}
            publisher_email = _extract_email_from_maintainer(publisher)
            self._record_email(
                outcome, publisher_email, domain, pkg_name, "search_publisher"
            )
            # Author from package.latest fields (search entries don't carry
            # author but some packages surface it via ``maintainers``).
            for maintainer in pkg.get("maintainers") or []:
                if isinstance(maintainer, dict):
                    m_email = _extract_email_from_maintainer(maintainer)
                    self._record_email(
                        outcome, m_email, domain, pkg_name, "search_maintainer"
                    )

        return outcome

    async def _direct_package_lookup(
        self,
        client: httpx.AsyncClient,
        keyword: str,
        domain: str,
    ) -> _SubSourceOutcome:
        """Hit ``registry.npmjs.org/{keyword}`` for the canonical package."""
        outcome = _SubSourceOutcome(source_id="direct_keyword")
        try:
            await self._throttle()
            response = await client.get(
                _NPM_PACKAGE_URL.format(keyword),
                timeout=_REQUEST_TIMEOUT,
            )
        except httpx.TimeoutException:
            outcome.error = "direct_timeout"
            return outcome
        except Exception as exc:
            outcome.error = f"direct_request:{exc}"
            return outcome

        if response.status_code == 404:
            outcome.error = "direct_not_found"
            return outcome
        if response.status_code == 429:
            outcome.error = "direct_rate_limited"
            return outcome
        if response.status_code != 200:
            outcome.error = f"direct_http_{response.status_code}"
            return outcome

        try:
            data = response.json()
        except Exception as exc:
            outcome.error = f"direct_invalid_json:{exc}"
            return outcome

        pkg_name = str(data.get("name") or keyword)
        outcome.packages_checked = 1
        outcome.ok = True

        # Maintainers (top-level).
        for maintainer in data.get("maintainers") or []:
            m_email = _extract_email_from_maintainer(maintainer)
            self._record_email(
                outcome, m_email, domain, pkg_name, "maintainer"
            )

        # Author — pick the latest version's author for the freshest signal.
        dist_tags = (
            data.get("dist-tags") if isinstance(data.get("dist-tags"), dict) else {}
        )
        latest_version = str(dist_tags.get("latest") or "")
        versions = (
            data.get("versions") if isinstance(data.get("versions"), dict) else {}
        )
        latest_data = versions.get(latest_version) or {}
        author = latest_data.get("author") or data.get("author")
        author_email = _extract_email_from_maintainer(author)
        self._record_email(outcome, author_email, domain, pkg_name, "author")

        return outcome

    def _record_email(
        self,
        outcome: _SubSourceOutcome,
        email: str | None,
        domain: str,
        package_name: str,
        source_label: str,
    ) -> None:
        """Apply the strict domain filter and append evidence."""
        if not email or "@" not in email:
            return
        if not _email_domain_matches(email, domain):
            # Strict filter: only the target domain's emails make it
            # through.  Random contributors with unrelated emails are
            # silently dropped — no log spam.
            return
        outcome.emails.setdefault(email, []).append(
            {
                "source": source_label,
                "package": package_name,
            }
        )
        outcome.count += 1