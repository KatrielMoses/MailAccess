"""PyPI Registry email discovery (domain harvest mode) — W5 of 0.10.0.

This module queries the public PyPI JSON / XML-RPC APIs for package
metadata whose author or maintainer email addresses match the target
domain.  It slots into Phase 1 of the domain harvest orchestrator
(the parallel fast / cheap-sources phase) and runs concurrently with
``commoncrawl_email`` and ``code_and_cert_email`` via
``asyncio.gather``.

Why a separate module from the existing ``pypi_discovery``:
    The existing ``pypi_discovery`` module is a SINGLE-EMAIL-mode
    investigator — given a known email, find packages authored /
    maintained by that person.  This new ``pypi_email`` module is
    DOMAIN-mode — given a target domain, find ALL packages whose
    author / maintainer email matches that domain.

    The existing ``pypi_discovery`` is NOT modified; consolidation
    between the two execution paths is left as a future cleanup
    (the audit calls out to note overlap in code comments).

Why strict domain filtering matters here:
    Same rationale as :mod:`backend.modules.npm_email` — PyPI's
    author_email / maintainer_email fields are free-form, often
    filled with personal addresses, and the registry contains
    unrelated contributors in any package search result.  Without
    a strict "email's domain must equal the target domain" filter
    the module would harvest emails from random contributors.

API choice:
    PyPI's XML-RPC search endpoint is deprecated but still
    functional.  We use it as the primary search path (returns
    matches with metadata summaries) and the JSON API
    (``https://pypi.org/pypi/<name>/json``) for the direct
    package-name lookup fallback.  No API key required for
    either endpoint.
"""

from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings
from ..core.email_confidence import compute_confidence_breakdown, label_for_score
from ..core.http_client import build_client
from ..core.role_classifier import classify_email
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

# Public PyPI endpoints — no authentication required.
_PYPI_XMLRPC_SEARCH_URL = "https://pypi.org/pypi"
_PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"

_REQUEST_TIMEOUT = 8.0
_RATE_LIMIT_SECONDS = 2.0
_MAX_SEARCH_RESULTS = 20

# Source-weight identifier (mirrors SOURCE_WEIGHTS key in email_confidence).
_TYPE = "pypi_package_author"


@dataclass
class _SubSourceOutcome:
    source_id: str  # "xmlrpc_search" | "direct_keyword"
    ok: bool = False
    error: str | None = None
    count: int = 0
    packages_checked: int = 0
    emails: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def _domain_keyword(domain: str) -> str | None:
    """Derive a package-name guess from a domain (same shape as npm)."""
    if not domain or "." not in domain:
        return None
    parts = [p for p in domain.lower().split(".") if p]
    if not parts:
        return None
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
    """Strict equality filter — substring matches are explicitly rejected."""
    if not email or "@" not in email:
        return False
    _, _, dom = email.strip().lower().rpartition("@")
    return bool(dom) and dom == target_domain.lower()


def _extract_emails_from_csv(value: str | None) -> list[str]:
    """Split a comma-separated author_email / maintainer_email field."""
    if not value or not isinstance(value, str):
        return []
    out: list[str] = []
    for chunk in value.split(","):
        cleaned = chunk.strip().lower()
        if cleaned and "@" in cleaned:
            out.append(cleaned)
    return out


def _parse_xmlrpc_search(xml_text: str) -> list[str]:
    """Pull package names from a PyPI XML-RPC search response.

    The response shape is::

        <methodResponse>
          <params>
            <param>
              <value>
                <array>
                  <data>
                    <string>foo</string>
                    ...
                  </data>
                </array>
              </value>
            </param>
          </params>
        </methodResponse>

    Some error responses come back as ``<methodResponse><fault>...</fault></methodResponse>``
    — we let those fall through and return an empty list.
    """
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    names: list[str] = []
    for string_el in root.iter("string"):
        if string_el.text and string_el.text.strip():
            names.append(string_el.text.strip())
    return names


class PyPIEmailModule(BaseModule):
    """DOMAIN-mode: discover maintainer emails on the PyPI registry."""

    name = "pypi_email"
    description = (
        "Email discovery via PyPI registry package metadata — "
        "extracts author and maintainer emails that match the target domain."
    )
    requires_key = False
    default_enabled = False  # domain harvest mode only

    async def run(self, target: str) -> ModuleResult:  # type: ignore[override]
        if not settings.enable_pypi_email:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "pypi_email disabled — set ENABLE_PYPI_EMAIL=true to enable"
                ],
            )

        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["pypi_email: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        outcomes: dict[str, _SubSourceOutcome] = {
            "xmlrpc_search": _SubSourceOutcome(source_id="xmlrpc_search"),
            "direct_keyword": _SubSourceOutcome(source_id="direct_keyword"),
        }

        aggregated: dict[str, dict[str, Any]] = {}

        try:
            async with build_client(timeout=_REQUEST_TIMEOUT) as client:
                # --- Step 1: XML-RPC search for packages mentioning
                # the target domain. -----------------------------
                xmlrpc_outcome = await self._xmlrpc_search(client, domain)
                outcomes["xmlrpc_search"] = xmlrpc_outcome
                for email, evidence in xmlrpc_outcome.emails.items():
                    bucket = aggregated.setdefault(
                        email, {"types": set(), "evidence": []}
                    )
                    bucket["types"].add(_TYPE)
                    bucket["evidence"].extend(evidence)

                # --- Step 2: JSON API direct package lookup by domain
                # keyword. ----------------------------------------
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
                    outcomes["direct_keyword"].error = "no_keyword_from_domain"
        except Exception as exc:
            _LOG.error("pypi_email: catastrophic error: %s", exc)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"pypi_email: {exc}"],
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
                    "platform": "pypi_email",
                    "profile_url": f"https://pypi.org/user/{local_part}/"
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
                "packages_checked_xmlrpc": outcomes[
                    "xmlrpc_search"
                ].packages_checked,
                "packages_checked_direct": outcomes[
                    "direct_keyword"
                ].packages_checked,
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
        await asyncio.sleep(_RATE_LIMIT_SECONDS)

    async def _xmlrpc_search(
        self, client: httpx.AsyncClient, domain: str
    ) -> _SubSourceOutcome:
        """PyPI XML-RPC ``search_packages``-style search.

        The XML-RPC endpoint accepts ``GET`` requests of the shape
        ``/pypi?%3Aaction=search&term=<term>`` and returns an XML
        document with an array of package names.  The endpoint is
        deprecated but still works for unauthenticated read traffic.
        """
        outcome = _SubSourceOutcome(source_id="xmlrpc_search")
        try:
            await self._throttle()
            response = await client.get(
                _PYPI_XMLRPC_SEARCH_URL,
                params={"%3Aaction": "search", "term": domain},
                timeout=_REQUEST_TIMEOUT,
            )
        except httpx.TimeoutException:
            outcome.error = "xmlrpc_timeout"
            return outcome
        except Exception as exc:
            outcome.error = f"xmlrpc_request:{exc}"
            return outcome

        if response.status_code == 429:
            outcome.error = "xmlrpc_rate_limited"
            return outcome
        if response.status_code != 200:
            outcome.error = f"xmlrpc_http_{response.status_code}"
            return outcome

        names = _parse_xmlrpc_search(response.text)
        outcome.packages_checked = len(names)
        outcome.ok = True

        # Fetch each package's JSON to extract emails.  Bound the
        # concurrent fetches to avoid hammering PyPI.
        if names:
            semaphore = asyncio.Semaphore(4)

            async def _bounded(name: str) -> None:
                async with semaphore:
                    pkg_outcome = await self._direct_package_lookup(
                        client, name, domain
                    )
                    # Merge findings into our outcome.
                    for email, evidence in pkg_outcome.emails.items():
                        outcome.emails.setdefault(email, []).extend(evidence)
                        outcome.count += 1

            await asyncio.gather(
                *(_bounded(name) for name in names[:_MAX_SEARCH_RESULTS]),
                return_exceptions=True,
            )

        return outcome

    async def _direct_package_lookup(
        self,
        client: httpx.AsyncClient,
        name: str,
        domain: str,
    ) -> _SubSourceOutcome:
        outcome = _SubSourceOutcome(source_id="direct_keyword")
        try:
            await self._throttle()
            response = await client.get(
                _PYPI_JSON_URL.format(name=name),
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

        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        pkg_name = str(info.get("name") or name)
        outcome.packages_checked = 1
        outcome.ok = True

        # author_email and maintainer_email are free-form strings,
        # sometimes comma-separated lists of multiple authors.
        author_email = str(info.get("author_email") or "")
        maintainer_email = str(info.get("maintainer_email") or "")
        for label, raw in (
            ("author", author_email),
            ("maintainer", maintainer_email),
        ):
            for email in _extract_emails_from_csv(raw):
                self._record_email(outcome, email, domain, pkg_name, label)

        return outcome

    def _record_email(
        self,
        outcome: _SubSourceOutcome,
        email: str | None,
        domain: str,
        package_name: str,
        source_label: str,
    ) -> None:
        if not email or "@" not in email:
            return
        if not _email_domain_matches(email, domain):
            return
        outcome.emails.setdefault(email, []).append(
            {
                "source": source_label,
                "package": package_name,
            }
        )
        outcome.count += 1