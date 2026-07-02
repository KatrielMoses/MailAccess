"""Code + Certificate Transparency email discovery — Phase B2 of 0.10.0.

Four structured-data sources in one module:

1. **GitHub code search** for ``"@<domain>"`` mentions via
   ``GitHubEmailSearcher.search_code_mentions``.
2. **GitHub commit-author discovery** via
   ``GitHubEmailSearcher.search_commit_authors`` — runs after step 1
   so it can scope to the repos already known to mention the domain.
3. **crt.sh** records fetched directly (URL pattern reused from
   ``collect_crtsh`` in ``harvester_collectors``), with email parsing
   via ``extract_emails_from_crtsh_record``.
4. **certspotter** same as crt.sh but with the certspotter URL and
   ``extract_emails_from_certspotter_record``.

Why crt.sh / certspotter are reimplemented at the raw-record layer
(``harvester_collectors`` only returns subdomains):
    Refactoring ``collect_crtsh`` / ``collect_certspotter`` to also
    return raw records would break their ``set[str]`` contract that
    ``domain_harvester`` relies on.  Touching them risked Phase A
    regressions.  Phase B2 therefore fetches the same JSON endpoints
    here with the same URL shape and parsing pattern.

Why the module pulls CT records itself (via :func:`build_client`)
rather than via ``harvester_collectors``: separation of concerns —
this module is the only consumer that needs email-bearing fields.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import settings
from ..core.ca_email_extraction import (
    extract_emails_from_certspotter_record,
    extract_emails_from_crtsh_record,
)
from ..core.email_confidence import compute_confidence_breakdown, label_for_score
from ..core.github_email_search import GitHubEmailSearcher
from ..core.http_client import build_client
from ..core.role_classifier import classify_email
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

# URL shapes reused verbatim from
# ``backend.core.harvester_collectors.collect_crtsh`` and
# ``collect_certspotter``.  Kept as string constants to make the
# reuse obvious and reviewable.
_CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances"
    "?domain={domain}&include_subdomains=true&expand=dns_names"
)
_REQUEST_TIMEOUT = 15.0
# MUST-FIX S6: User-Agent version is derived from APP_VERSION at
# import time (was hardcoded "mailaccess/0.8.3" — lagged the actual
# package version).
from ..config import APP_VERSION as _APP_VERSION  # noqa: E402

_HARVESTER_UA = f"mailaccess/{_APP_VERSION}"
_HARVESTER_HEADERS = {"User-Agent": _HARVESTER_UA}

# Source-weight identifiers (mirror SOURCE_WEIGHTS keys).
_TYPE_AUTHOR = "github_commit_author"
_TYPE_CODE = "github_code_match"
_TYPE_CA = "ca_attested"

# When an email is found via multiple sub-sources, this is the priority
# order for ``source_type`` (used as the primary signal for confidence
# and reported on the finding).  Higher rank wins.
_RANK = {_TYPE_AUTHOR: 3, _TYPE_CA: 2, _TYPE_CODE: 1}


@dataclass
class _SubSourceOutcome:
    source_id: str  # "github_code" | "github_commits" | "crtsh" | "certspotter"
    ok: bool = False
    error: str | None = None
    count: int = 0
    records_checked: int = 0
    emails: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


class CodeAndCertEmailModule(BaseModule):
    name = "code_and_cert_email"
    description = (
        "Email discovery via GitHub code/commit search and Certificate "
        "Transparency (crt.sh, certspotter) log records."
    )
    requires_key = False  # GitHub works better with token but functions without
    default_enabled = False  # domain harvest mode only

    async def run(self, target: str) -> ModuleResult:  # type: ignore[override]
        if not settings.enable_code_and_cert_email:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "code_and_cert_email disabled — "
                    "set ENABLE_CODE_AND_CERT_EMAIL=true to enable"
                ],
            )

        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["code_and_cert_email: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        max_results = max(1, int(getattr(settings, "github_email_max_results", 30)))
        max_repos = max(1, int(getattr(settings, "github_email_max_repos_checked", 10)))
        max_commits_per_repo = max(
            1, int(getattr(settings, "github_email_max_commits_per_repo", 20))
        )

        outcomes: dict[str, _SubSourceOutcome] = {
            "github_code": _SubSourceOutcome(source_id="github_code"),
            "github_commits": _SubSourceOutcome(source_id="github_commits"),
            "crtsh": _SubSourceOutcome(source_id="crtsh"),
            "certspotter": _SubSourceOutcome(source_id="certspotter"),
        }

        # email -> {
        #   "types": set[str] (which _TYPE_* matched this email),
        #   "evidence": list[dict] (per-source snippets),
        # }
        aggregated: dict[str, dict[str, Any]] = {}

        rate_limited = False
        repos_from_code_search: list[str] = []

        try:
            async with build_client(timeout=10.0) as shared_client:
                github = GitHubEmailSearcher(
                    transport=shared_client,
                    min_interval=0.0,
                    # Caller-level throttle handled by orchestrator;
                    # per-instance interval disabled here.
                )

                # --- Step 1: GitHub code mentions ---------------------------
                code_result = await github.search_code_mentions(
                    domain=domain, max_results=max_results
                )
                outcomes["github_code"].error = code_result.error
                outcomes["github_code"].ok = bool(code_result.matches)
                outcomes["github_code"].count = len(code_result.matches)
                outcomes["github_code"].records_checked = len(code_result.matches)
                if code_result.rate_limited:
                    rate_limited = True

                for match in code_result.matches:
                    bucket = aggregated.setdefault(
                        match.email,
                        {
                            "types": set(),
                            "evidence": [],
                        },
                    )
                    bucket["types"].add(_TYPE_CODE)
                    bucket["evidence"].append(
                        {
                            "source": "github_code",
                            "repo": match.repo_full_name,
                            "file_path": match.file_path,
                            "html_url": match.html_url,
                        }
                    )
                    outcomes["github_code"].emails.setdefault(match.email, []).append(
                        bucket["evidence"][-1]
                    )

                repos_from_code_search = code_result.repos

                # --- Step 2: GitHub commit authors (uses step-1 repos) -----
                if repos_from_code_search and not rate_limited:
                    commits_result = await github.search_commit_authors(
                        domain=domain,
                        repos=repos_from_code_search,
                        max_repos=max_repos,
                        max_commits_per_repo=max_commits_per_repo,
                    )
                    outcomes["github_commits"].error = commits_result.error
                    outcomes["github_commits"].ok = bool(commits_result.matches)
                    outcomes["github_commits"].count = len(commits_result.matches)
                    outcomes["github_commits"].records_checked = (
                        commits_result.commits_inspected
                    )
                    if commits_result.rate_limited:
                        rate_limited = True

                    for match in commits_result.matches:
                        bucket = aggregated.setdefault(
                            match.email,
                            {
                                "types": set(),
                                "evidence": [],
                            },
                        )
                        bucket["types"].add(_TYPE_AUTHOR)
                        ev = {
                            "source": "github_commit",
                            "repo": match.repo_full_name,
                            "commit_sha": match.commit_sha,
                            "author_name": match.author_name,
                            "html_url": match.html_url,
                        }
                        bucket["evidence"].append(ev)
                        outcomes["github_commits"].emails.setdefault(
                            match.email, []
                        ).append(ev)
                else:
                    outcomes["github_commits"].error = (
                        outcomes["github_commits"].error or "no_repos_from_code_search"
                    )

                # --- Steps 3 & 4: crt.sh + certspotter (concurrent) --------
                crtsh_task = asyncio.create_task(
                    self._fetch_crtsh_emails(shared_client, domain)
                )
                certspotter_task = asyncio.create_task(
                    self._fetch_certspotter_emails(shared_client, domain)
                )
                crtsh_outcome = await crtsh_task
                certspotter_outcome = await certspotter_task

                outcomes["crtsh"] = crtsh_outcome
                outcomes["certspotter"] = certspotter_outcome

                for outcome in (crtsh_outcome, certspotter_outcome):
                    for email, evidence in outcome.emails.items():
                        bucket = aggregated.setdefault(
                            email, {"types": set(), "evidence": []}
                        )
                        bucket["types"].add(_TYPE_CA)
                        bucket["evidence"].extend(evidence)
        except Exception as exc:
            _LOG.error("code_and_cert_email: catastrophic error: %s", exc)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"code_and_cert_email: {exc}"],
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
            types = data["types"]
            primary = _primary_type(types)
            confidence_info = compute_confidence_breakdown(
                source_types=[primary],
                is_ca_attested=(_TYPE_CA in types),
                is_smtp_verified=False,
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
                    "platform": "code_and_cert_email",
                    "profile_url": f"https://{domain}" if on_domain else "",
                    "username": local_part,
                    "confidence": label_for_score(confidence_info.score).lower(),
                    "metadata": {
                        "email": email,
                        "on_domain": on_domain,
                        "source_type": primary,
                        "all_sources": sorted(types),
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
        ok_count = sum(1 for o in outcomes.values() if o.ok or o.records_checked)
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
                "github_code_mentions_found": outcomes["github_code"].count,
                "github_repos_checked": len(repos_from_code_search),
                "github_commits_checked": outcomes["github_commits"].records_checked,
                "github_commit_authors_found": outcomes["github_commits"].count,
                "crtsh_records_checked": outcomes["crtsh"].records_checked,
                "crtsh_emails_found": outcomes["crtsh"].count,
                "certspotter_records_checked": outcomes["certspotter"].records_checked,
                "certspotter_emails_found": outcomes["certspotter"].count,
                "total_unique_emails": len(aggregated),
                "on_domain_emails": on_domain_count,
                "role_accounts": role_count,
                "personal_emails": personal_count,
                "github_rate_limited": rate_limited,
                "sub_source_outcomes": {
                    sid: {
                        "ok": o.ok,
                        "error": o.error,
                        "count": o.count,
                    }
                    for sid, o in outcomes.items()
                },
            },
        )

    # ----------------------------------------------------------------------
    # CT log fetchers
    # ----------------------------------------------------------------------
    async def _fetch_crtsh_emails(
        self, client: httpx.AsyncClient, domain: str
    ) -> _SubSourceOutcome:
        url = _CRT_SH_URL.format(domain=domain)
        outcome = _SubSourceOutcome(source_id="crtsh")
        return await self._ct_records_to_outcome(
            client, url, domain, source_label="crtsh", outcome=outcome
        )

    async def _fetch_certspotter_emails(
        self, client: httpx.AsyncClient, domain: str
    ) -> _SubSourceOutcome:
        url = _CERTSPOTTER_URL.format(domain=domain)
        outcome = _SubSourceOutcome(source_id="certspotter")
        return await self._ct_records_to_outcome(
            client, url, domain, source_label="certspotter", outcome=outcome
        )

    async def _ct_records_to_outcome(
        self,
        client: httpx.AsyncClient,
        url: str,
        domain: str,
        source_label: str,
        outcome: _SubSourceOutcome,
    ) -> _SubSourceOutcome:
        """Generic JSON-fetch → records → emails pipeline for CT endpoints."""
        try:
            try:
                response = await client.get(
                    url, headers=_HARVESTER_HEADERS, timeout=_REQUEST_TIMEOUT
                )
            except httpx.TimeoutException:
                outcome.error = f"{source_label}_timeout"
                return outcome
            except Exception as exc:
                outcome.error = f"{source_label}_request:{exc}"
                return outcome

            if response.status_code == 429:
                outcome.error = f"{source_label}_rate_limited"
                return outcome
            if response.status_code != 200:
                outcome.error = f"{source_label}_http_{response.status_code}"
                return outcome

            data = response.json()
        except Exception as exc:
            outcome.error = f"{source_label}_invalid_json:{exc}"
            return outcome

        if not isinstance(data, list):
            outcome.ok = True  # empty/error response is still "we tried"
            return outcome

        records = data
        outcome.records_checked = len(records)
        outcome.ok = True

        parse_one = (
            extract_emails_from_crtsh_record
            if source_label == "crtsh"
            else extract_emails_from_certspotter_record
        )

        email_count = 0
        for record in records:
            for email in parse_one(record, target_domain=domain):
                outcome.emails.setdefault(email, []).append(
                    {
                        "source": source_label,
                        "record_id": record.get("id"),
                    }
                )
                email_count += 1

        outcome.count = email_count
        return outcome


def _primary_type(types: set[str]) -> str:
    """Pick the highest-confidence ``source_type`` for findings."""
    if not types:
        return _TYPE_CODE
    return max(types, key=lambda t: _RANK.get(t, 0))
