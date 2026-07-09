"""Common Crawl email discovery module — Phase A of the 0.10.0 rebuild
+ 0.11.1 Phase 3 Archive Intelligence Expansion.

This module harvests email addresses for a target domain by querying
the Common Crawl URL Index across MULTIPLE collections (Phase 3),
fetching the matching pages (WARC preferred, direct-GET fallback),
then decoding Cloudflare-obfuscation and running both the email
regex and the structured-person extractor on the result.

The aggregate is classified by the shared role classifier and the
shared confidence model.  The ``wayback_archive`` evidence weight is
set in :mod:`backend.core.email_confidence` so Wayback- and
CC-sourced addresses contribute to a single bucket at the
orchestrator level.

The module is intentionally opt-in: ``default_enabled`` is ``False``
because it only makes sense in *domain harvest mode*, never during a
normal ``email → profile`` investigation.  The domain-harvest
orchestrator wires it up via :func:`run_domain_harvest`.
"""

from __future__ import annotations

import logging
from typing import Any

from ..config import settings
from ..core.cc_index_client import CCRecord, CommonCrawlClient
from ..core.cc_page_fetcher import CCFetchResult, CCPageFetcher
from ..core.email_confidence import compute_confidence_breakdown, label_for_score
from ..core.email_extraction import extract_emails
from ..core.http_client import build_client
from ..core.role_classifier import classify_email
from ..core.structured_data_extractor import PersonRecord
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_MAX_SOURCE_URLS = 5  # how many source URLs we attach to each finding
_DENSITY_THRESHOLD = 3  # >= 3 distinct CC URLs → high_density source type


class CommonCrawlEmailModule(BaseModule):
    name = "commoncrawl_email"
    description = (
        "Email discovery via Common Crawl index — fetches indexed pages across "
        "multiple collections for the target domain and extracts emails + person "
        "records."
    )
    requires_key = False
    default_enabled = False  # Opt-in: domain harvest mode only

    async def run(
        self,
        target: str,
        *,
        max_records: int | None = None,
        max_collections: int | None = None,
        aggressive: bool | None = None,
    ) -> ModuleResult:  # type: ignore[override]
        """Harvest emails for *target*, which is a domain (not an email).

        Parameters
        ----------
        target:
            Target domain (e.g. ``"example.com"``).
        max_records:
            Back-compat override — when set, treated as
            ``max_collections * max_records_per_collection`` for the
            ``query_multi_collection`` call.  Phase 3 callers should
            prefer ``max_collections`` / settings directly.
        max_collections:
            Cap on the number of CC collections swept per Phase 3.
            Defaults to ``settings.cc_max_collections`` (6).
        aggressive:
            When True, doubles the cap on collections and triples
            per-collection record count (matches CCIndexClient
            ``aggressive=True`` semantics).
        """
        # Honour master kill-switch.
        if not settings.enable_commoncrawl_email:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["commoncrawl_email disabled — set ENABLE_COMMONCRAWL_EMAIL=true to enable"],
            )

        domain = (target or "").strip().lower()
        if not domain or "." not in domain:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["commoncrawl_email: invalid domain"],
                metadata={"skip_reason": "invalid_domain", "domain": domain},
            )

        effective_aggressive = bool(aggressive) if aggressive is not None else bool(
            getattr(settings, "harvest_aggressive", False)
        )

        # Resolve effective caps.  ``max_records`` is the legacy override
        # path: when set it caps the *total* budget across collections.
        default_max_collections = int(
            getattr(settings, "cc_max_collections", 6) or 6
        )
        default_max_records_per = int(
            getattr(settings, "cc_max_records_per_collection", 250) or 250
        )
        eff_max_collections = (
            int(max_collections) if max_collections is not None else default_max_collections
        )
        if effective_aggressive:
            eff_max_collections = max(eff_max_collections, 24)
        eff_max_records_per = default_max_records_per
        if effective_aggressive:
            eff_max_records_per = max(eff_max_records_per, 500)
        if max_records is not None:
            # Distribute the legacy max_records budget across the
            # available collections.
            try:
                per_budget = int(max_records) // max(1, eff_max_collections)
                eff_max_records_per = min(eff_max_records_per, max(1, per_budget))
            except (TypeError, ValueError):
                pass

        eff_max_collections = max(1, eff_max_collections)
        eff_max_records_per = max(1, eff_max_records_per)

        concurrency = max(1, int(getattr(settings, "cc_fetch_concurrency", 10) or 10))
        fetch_timeout = float(getattr(settings, "cc_fetch_timeout_seconds", 8) or 8.0)

        records: list[CCRecord] = []
        fetch_results: list[CCFetchResult | None] = []
        index_unreachable = False
        collections_swept: list[str] = []

        try:
            # scrapingant: dropped in S5 audit (CC index JSON + WARC fetches are direct).
            async with build_client(timeout=10.0) as shared_client:
                client = CommonCrawlClient(transport=shared_client)
                fetcher = CCPageFetcher(
                    transport=shared_client,
                    warc_timeout=fetch_timeout,
                    direct_timeout=fetch_timeout,
                    concurrency=concurrency,
                )

                try:
                    records = await client.query_multi_collection(
                        domain=domain,
                        max_collections=eff_max_collections,
                        max_records_per_collection=eff_max_records_per,
                        aggressive=effective_aggressive,
                    )
                    collections_swept = sorted(
                        {r.collection for r in records if r.collection}
                    )
                except Exception as exc:
                    _LOG.warning("commoncrawl_email: multi-collection query failed: %s", exc)
                    index_unreachable = True

                if not records:
                    # Two flavours of "no records":
                    # - Index returned empty → SUCCESS (some domains
                    #   genuinely have no CC coverage).
                    # - Index call threw → FAILED (network / upstream).
                    status = ModuleStatus.FAILED if index_unreachable else ModuleStatus.SUCCESS
                    return ModuleResult(
                        status=status,
                        findings=[],
                        errors=["commoncrawl_email: index query failed"]
                        if index_unreachable
                        else [],
                        metadata={
                            "domain": domain,
                            "collections_swept": collections_swept,
                            "records_queried": 0,
                            "records_fetched": 0,
                            "fetch_failures": 0,
                            "total_emails_found": 0,
                            "on_domain_emails": 0,
                            "role_accounts": 0,
                            "personal_emails": 0,
                            "cc_coverage": "none",
                            "aggressive": effective_aggressive,
                        },
                    )

                # Fetch pages concurrently, bounded by fetcher's semaphore.
                # The fetcher already handles WARC→direct fallback + CF
                # decoding + per-record provenance metadata.
                fetch_results = await fetcher.fetch_many_with_metadata(records)
        except Exception as exc:
            _LOG.error("commoncrawl_email: catastrophic failure: %s", exc)
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"commoncrawl_email: {exc}"],
                metadata={"domain": domain, "cc_coverage": "unreachable"},
            )

        fetch_failures = sum(1 for fr in fetch_results if fr is None)

        # ------------------------------------------------------------------
        # Per-record extraction & aggregation
        # ------------------------------------------------------------------
        # email -> {"urls": set, "timestamps": list, "first_on_domain": bool,
        #          "collections": set, "person_records": list}
        email_hits: dict[str, dict[str, Any]] = {}
        people_records: list[PersonRecord] = []

        for record, fetch_result in zip(records, fetch_results):
            if fetch_result is None:
                continue
            body = fetch_result.html
            if not body:
                continue
            for extracted in extract_emails(body, target_domain=domain):
                bucket = email_hits.setdefault(
                    extracted.email,
                    {
                        "urls": set(),
                        "timestamps": [],
                        "collections": set(),
                        "first_on_domain": False,
                    },
                )
                bucket["urls"].add(record.url)
                if record.timestamp:
                    bucket["timestamps"].append(record.timestamp)
                if record.collection:
                    bucket["collections"].add(record.collection)
                if extracted.on_domain:
                    bucket["first_on_domain"] = True

            # Phase 3: structured person extraction on the same HTML.
            # We collect PersonRecords to expose them as findings in
            # their own right (the aggregated-identity pipeline picks
            # them up via the email record when there's a mailto, but
            # even email-less pages can surface people we want to
            # keep).
            try:
                page_people = await fetcher.extract_people_from_html(
                    body, fetch_result.original_url, domain
                )
                people_records.extend(page_people)
            except Exception as exc:  # noqa: BLE001 — defensive
                _LOG.debug(
                    "commoncrawl_email: extract_people failed on %s: %s",
                    fetch_result.original_url,
                    exc,
                )

        # Build FindingItem per unique email.
        findings: list[dict[str, Any]] = []
        on_domain_count = 0
        role_count = 0
        personal_count = 0

        # Build a lookup of person records by email so we can attach
        # structured name/title to the email findings.
        people_by_email = {
            (person.email or "").strip().lower(): person
            for person in people_records
            if getattr(person, "email", None)
        }

        for email, data in sorted(email_hits.items()):
            urls = data["urls"]
            timestamps = data["timestamps"]
            collections = data["collections"]
            url_count = len(urls)

            source_type = (
                "common_crawl_high_density"
                if url_count >= _DENSITY_THRESHOLD
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

            local_part = email.split("@", 1)[0]
            on_domain = bool(data["first_on_domain"])

            # Attach structured name/title when the same email was
            # surfaced by the structured extractor.
            person = people_by_email.get(email.lower())
            person_name = getattr(person, "name", None) if person is not None else None
            person_title = getattr(person, "title", None) if person is not None else None

            finding = {
                "platform": "commoncrawl_email",
                "profile_url": (f"https://{domain}" if on_domain else next(iter(urls))),
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
                    "oldest_timestamp": (min(timestamps) if timestamps else None),
                    "newest_timestamp": (max(timestamps) if timestamps else None),
                    "local_part": local_part,
                    "cc_collections": sorted(collections),
                    "person_name": person_name,
                    "person_title": person_title,
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
                "collections_swept": collections_swept,
                "records_queried": len(records),
                "records_fetched": (
                    sum(1 for fr in fetch_results if fr is not None)
                    if records
                    else 0
                ),
                "fetch_failures": fetch_failures,
                "total_emails_found": len(email_hits),
                "on_domain_emails": on_domain_count,
                "role_accounts": role_count,
                "personal_emails": personal_count,
                "people_records_surfaced": len(people_records),
                "aggressive": effective_aggressive,
                "cc_coverage": (
                    "none"
                    if not records
                    else ("high" if len(records) >= 50 else "low")
                ),
            },
        )
