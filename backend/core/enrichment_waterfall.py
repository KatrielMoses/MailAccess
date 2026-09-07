"""Phase 7A — enrichment waterfall orchestrator.

Turns scattered enrichment connectors into a coherent engine: for each lead
with empty person fields, try connectors in priority order, **stop at the first
confident hit per field**, and fall back to lower-priority connectors only for
the fields still missing. Connector output is never written onto the lead
directly — each hit becomes an *evidence entry* appended to the lead, and the
existing Phase-1E claim resolver (via ``lead_person.resolve_person_fields``,
re-run by the caller) merges it. That is what guarantees enrichment can only
*fill gaps*, never clobber an evidenced native claim (enrichment source weights
sit below the native person-field sources).

Governance is a hard constraint, not a bolt-on: every connector is classified
under Phase 2B and the waterfall runs a connector only when
``is_module_allowed(connector, mode)`` — so in public-business-contact mode only
lawful-public business connectors (Apollo) run, while data-broker connectors
(PDL) are gated to security-investigation. Each connector re-checks the same
gate as defense-in-depth. Per-provider free-tier budgets (``provider_budget``)
cap monthly calls so no BYO key is silently overrun; when a provider's budget is
exhausted the waterfall simply falls through to the next.

Fully guarded and additive: a connector failure leaves the lead exactly as it
was (email-only yield never regresses), and network I/O only happens for leads
that are actually missing fields.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..config import settings
from . import apollo_client, pdl_client
from .enrichment_base import EnrichmentResult
from .product_mode import ProductMode, is_module_allowed, normalize_mode

logger = logging.getLogger(__name__)

# Lead person fields the waterfall may fill. ``seniority`` is intentionally
# absent — it is *derived* from a resolved ``job_title`` by lead_person, never
# enriched directly (evidence-or-null holds).
_ENRICHABLE: tuple[str, ...] = (
    "full_name",
    "first",
    "last",
    "job_title",
    "department",
    "linkedin_url",
    "phone",
    "location",
)

EnrichFn = Callable[..., Awaitable["EnrichmentResult | None"]]


@dataclass(frozen=True)
class Connector:
    """A priority-ordered enrichment source."""

    name: str  # canonical policy-module name (product_mode classification key)
    enrich: EnrichFn
    enabled: Callable[[], bool]


def default_connectors() -> list[Connector]:
    """Built-in connectors in waterfall priority order.

    Apollo (lawful-public business data, larger free tier) is tried before PDL
    (data-broker, security-only, smaller tier). Business-first also aligns with
    governance: in public/org mode only Apollo is permitted anyway.
    """
    return [
        Connector(apollo_client.POLICY_MODULE, apollo_client.enrich, apollo_client._enabled),
        Connector(pdl_client.POLICY_MODULE, pdl_client.enrich, pdl_client._enabled),
    ]


def _min_confidence() -> float:
    try:
        return float(getattr(settings, "enrichment_min_confidence", 0.5))
    except (TypeError, ValueError):
        return 0.5


def _max_lookups() -> int:
    try:
        return int(getattr(settings, "enrichment_max_lookups", 50))
    except (TypeError, ValueError):
        return 50


def _enrichment_enabled() -> bool:
    return bool(getattr(settings, "enable_enrichment_waterfall", True))


def _missing_fields(entry: Any) -> set[str]:
    return {f for f in _ENRICHABLE if not getattr(entry, f, None)}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _append_evidence(entry: Any, result: EnrichmentResult, contributed: dict[str, str]) -> None:
    """Append one enrichment hit as an evidence entry the 1E resolver consumes.

    The metadata carries the person keys under names ``claim_resolver._FIELD_KEYS``
    already recognizes, plus ``source_type`` so the claim is weighted (and, for a
    business connector, allowed to carry phone/location in public mode via
    ``lead_person._BUSINESS_CONTACT_SOURCES``).
    """
    metadata: dict[str, Any] = {
        "source_type": result.source_type,
        "enrichment_confidence": result.confidence,
        "last_seen": _now_iso(),
        **contributed,
    }
    # ``company`` is not a surfaced lead field but helps resolution downstream.
    if result.fields.get("company"):
        metadata["company"] = result.fields["company"]
    if result.source_url:
        metadata["source_url"] = result.source_url
    if not isinstance(getattr(entry, "evidence", None), list):
        entry.evidence = []
    entry.evidence.append({"module": result.provider, "metadata": metadata})
    if isinstance(getattr(entry, "found_by_modules", None), list) and \
            result.provider not in entry.found_by_modules:
        entry.found_by_modules.append(result.provider)


async def enrich_leads(
    emails: list[Any],
    *,
    mode: str | ProductMode,
    connectors: list[Connector] | None = None,
) -> dict[str, Any]:
    """Run the enrichment waterfall over *emails*; return a telemetry summary.

    Mutates each lead in place by appending enrichment evidence; the caller is
    responsible for re-running person attribution so the new evidence resolves
    through 1E. Never raises.
    """
    summary: dict[str, Any] = {
        "attempted": 0,
        "enriched": 0,
        "by_provider": {},
        "skipped_by_mode": [],
    }
    if not _enrichment_enabled():
        return summary
    try:
        m = normalize_mode(mode)
    except Exception:
        return summary

    active = connectors if connectors is not None else default_connectors()
    # Filter connectors up front: mode-allowed AND enabled (BYO key present).
    usable: list[Connector] = []
    for c in active:
        if not is_module_allowed(c.name, m):
            summary["skipped_by_mode"].append(c.name)
            continue
        try:
            if c.enabled():
                usable.append(c)
        except Exception:
            logger.debug("connector %s enabled-check failed", c.name, exc_info=True)
    if not usable:
        return summary

    threshold = _min_confidence()
    budget = _max_lookups()
    looked_up = 0

    for entry in emails:
        if looked_up >= budget:
            break
        # Person enrichment is meaningless for role mailboxes (info@, sales@).
        if getattr(entry, "is_role", False):
            continue
        missing = _missing_fields(entry)
        if not missing:
            continue
        email = getattr(entry, "email", None)
        if not isinstance(email, str) or "@" not in email:
            continue
        looked_up += 1
        summary["attempted"] += 1
        full_name = getattr(entry, "full_name", None)
        domain = email.split("@", 1)[1]
        enriched_this_lead = False

        for connector in usable:
            if not missing:
                break
            try:
                result = await connector.enrich(email, full_name=full_name, domain=domain)
            except Exception:
                logger.debug("connector %s failed for %s", connector.name, email, exc_info=True)
                continue
            if result is None or result.confidence < threshold or not result.has_fields():
                continue
            contributed = {
                k: result.fields[k]
                for k in _ENRICHABLE
                if k in missing and result.fields.get(k)
            }
            if not contributed:
                continue
            _append_evidence(entry, result, contributed)
            missing -= set(contributed)
            enriched_this_lead = True
            summary["by_provider"][connector.name] = (
                summary["by_provider"].get(connector.name, 0) + 1
            )

        if enriched_this_lead:
            summary["enriched"] += 1

    return summary
