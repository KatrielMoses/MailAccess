"""Common Crawl email discovery module — Phase A of the 0.10.0 rebuild.

This module harvests email addresses for a target domain by querying
the Common Crawl URL Index and fetching the matching pages (WARC
preferred, direct-GET fallback).  The aggregate is classified by the
shared role classifier and confidence model.

The module is intentionally opt-in: ``default_enabled`` is ``False``
because it only makes sense in *domain harvest mode*, never during a
normal ``email → profile`` investigation.  The Phase C orchestrator
will wire it up via the future domain-harvest entry point.
"""

from __future__ import annotations

import logging
from typing import Any

from ..config import settings
from ..core.cc_index_client import CCRecord, CommonCrawlClient
from ..core.cc_page_fetcher import CCPageFetcher
from ..core.email_confidence import compute_confidence_breakdown, label_for_score
from ..core.email_extraction import extract_emails
from ..core.http_client import build_client
from ..core.role_classifier import classify_email
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_MAX_SOURCE_URLS = 5  # how many source URLs we attach to each finding
_DENSITY_THRESHOLD = 3  # >= 3 distinct CC URLs → high_density source type


class CommonCrawlEmailModule(BaseModule):
    name = "commoncrawl_email"
    description = (
        "Email discovery via Common Crawl index — fetches indexed pages for the "
        "target domain and extracts emails."
    )
    requires_key = False
    default_enabled = False  # Opt-in: domain harvest mode only

    async def run(
        self,
        target: str,
        *,
        max_records: int | None = None,
    ) -> ModuleResult:  # type: ignore[override]
        """Harvest emails for *target*, which is a domain (not an email).

        Parameters
        ----------
        target:
            Target domain (e.g. ``"example.com"``).
        max_records:
            Explicit override for the Common Crawl record limit.
            MUST-FIX M3: when the orchestrator calls this method it
            MUST pass ``max_records`` explicitly; ``None`` falls back
            to ``settings.cc_max_records`` only for standalone/test
            use. This eliminates the previous race where the CLI
            mutated ``settings.cc_max_records`` globally and any
            concurrent reader saw the wrong value.
        """
        # Honour master kill-switch.
        if not settings.enable_commoncrawl_email:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=[
                    "commoncrawl_email disabled — set ENABLE_COMMONCRAWL_EMAIL=true to enable"
                ],
            )

        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["commoncrawl_email: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        # MUST-FIX M3: explicit parameter wins; settings is a fallback.
        effective_max_records = (
            int(max_records)
            if max_records is not None
            else int(getattr(settings, "cc_max_records", 100) or 100)
        )
        max_records_value = max(1, effective_max_records)
        concurrency = max(1, int(getattr(settings, "cc_fetch_concurrency", 10) or 10))
        fetch_timeout = float(getattr(settings, "cc_fetch_timeout_seconds", 8) or 8.0)

        records: list[CCRecord] = []
        fetch_failures = 0
        index_unreachable = False

        try:
            async with build_client(timeout=10.0) as shared_client:
                client = CommonCrawlClient(transport=shared_client)
                fetcher = CCPageFetcher(
                    transport=shared_client,
                    warc_timeout=fetch_timeout,
                    direct_timeout=fetch_timeout,
                    concurrency=concurrency,
                )

                try:
                    records = await client.query_url_index(
                        domain=domain, limit=max_records_value
                    )
                except Exception as exc:
                    _LOG.warning("commoncrawl_email: index query failed: %s", exc)
                    index_unreachable = True

                if not records:
                    # Two flavours of "no records":
                    # - Index returned empty → SUCCESS (some domains
                    #   genuinely have no CC coverage).
                    # - Index call threw → FAILED (network / upstream).
                    status = (
                        ModuleStatus.FAILED if index_unreachable
                        else ModuleStatus.SUCCESS
                    )
                    return ModuleResult(
                        status=status,
                        findings=[],
                        errors=[
                            "commoncrawl_email: index query failed"
                        ] if index_unreachable else [],
                        metadata={
                            "domain": domain,
                            "records_queried": 0,
                            "records_fetched": 0,
                            "fetch_failures": 0,
                            "total_emails_found": 0,
                            "on_domain_emails": 0,
                            "role_accounts": 0,
                            "personal_emails": 0,
                            "cc_coverage": "none",
                        },
                    )

                # Fetch pages concurrently, bounded by fetcher's semaphore.
                # The fetcher already handles WARC→direct fallback; failures
                # come back as None in the same order as records.
                bodies = await fetcher.fetch_many(records)
                fetch_failures = sum(1 for body in bodies if body is None)
        except Exception as exc:
            _LOG.error("commoncrawl_email: catastrophic failure: %s", exc)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"commoncrawl_email: {exc}"],
                metadata={"domain": domain, "cc_coverage": "unreachable"},
            )

        # ------------------------------------------------------------------
        # Per-record extraction & aggregation
        # ------------------------------------------------------------------
        # email -> {"urls": set, "timestamps": list}
        email_hits: dict[str, dict[str, Any]] = {}

        for record, body in zip(records, bodies):
            if body is None:
                continue
            for extracted in extract_emails(body, target_domain=domain):
                bucket = email_hits.setdefault(
                    extracted.email,
                    {
                        "urls": set(),
                        "timestamps": [],
                        "first_on_domain": False,
                    },
                )
                bucket["urls"].add(record.url)
                if record.timestamp:
                    bucket["timestamps"].append(record.timestamp)
                if extracted.on_domain:
                    bucket["first_on_domain"] = True

        # Build FindingItem per unique email.
        findings: list[dict[str, Any]] = []
        on_domain_count = 0
        role_count = 0
        personal_count = 0

        for email, data in sorted(email_hits.items()):
            urls = data["urls"]
            timestamps = data["timestamps"]
            url_count = len(urls)

            source_type = (
                "common_crawl_high_density" if url_count >= _DENSITY_THRESHOLD
                else "common_crawl_single"
            )

            confidence_info = compute_confidence_breakdown(
                source_types=[source_type],
                is_smtp_verified=False,
                is_ca_attested=False,
                oldest_timestamp=min(timestamps) if timestamps else None,
            )

            classification = classify_email(email)
            if data["first_on_domain"]:
                on_domain_count += 1

            # Decompose the local part for downstream tooling.
            local_part = email.split("@", 1)[0]
            on_domain = bool(data["first_on_domain"])

            finding = {
                "platform": "commoncrawl_email",
                "profile_url": (
                    f"https://{domain}" if on_domain else next(iter(urls))
                ),
                "username": local_part,
                "confidence": label_for_score(confidence_info.score).lower(),
                "metadata": {
                    "email": email,
                    "on_domain": on_domain,
                    "source_urls": sorted(urls)[:_MAX_SOURCE_URLS],
                    "url_count": url_count,
                    "is_role": classification.is_role,
                    "role_match_type": classification.match_type,
                    "role_confidence": classification.confidence,
                    "role_matched_prefix": classification.matched_prefix,
                    "source_type": source_type,
                    "confidence_score": round(confidence_info.score, 4),
                    "confidence_breakdown": confidence_info.breakdown,
                    "oldest_timestamp": (
                        min(timestamps) if timestamps else None
                    ),
                    "newest_timestamp": (
                        max(timestamps) if timestamps else None
                    ),
                    "local_part": local_part,
                },
            }
            findings.append(finding)
            if classification.is_role:
                role_count += 1
            else:
                personal_count += 1

        # Derive module status.
        if index_unreachable and not email_hits:
            status = ModuleStatus.FAILED
        elif fetch_failures and (fetch_failures / max(len(records), 1)) > 0.5:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "domain": domain,
                "records_queried": len(records),
                "records_fetched": sum(1 for b in bodies if b is not None)
                if records
                else 0,
                "fetch_failures": fetch_failures,
                "total_emails_found": len(email_hits),
                "on_domain_emails": on_domain_count,
                "role_accounts": role_count,
                "personal_emails": personal_count,
                "cc_coverage": (
                    "none" if not records else ("high" if len(records) >= 50 else "low")
                ),
            },
        )
