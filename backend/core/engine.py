from __future__ import annotations

import asyncio
import logging
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import update

from ..db.database import AsyncSessionLocal
from ..db.models import Finding, Investigation, InvestigationStatus, ModuleRun
from ..modules.base import ModuleResult, ModuleStatus
from .breach_normalizer import collapse_breach_findings
from .credential_risk import assess_credential_risk_from_results
from .defenders_brief import defenders_brief_to_dict, generate_defenders_brief
from .email_credibility import normalize_email_address
from .name_consensus import NameConsensusEngine, extract_name_candidates
from .policy import _BREACH_MODULES as _BREACH_MODULES  # noqa: F401
from .policy import (
    _CONFIDENCE_MULTIPLIER,
    _MODULE_CAP,
    _OPT_IN_FLAG_BY_MODULE,
    module_weight,
)
from .timeline import TimelineBuilder

logger = logging.getLogger(__name__)
_ENRICHMENT_TIMEOUT_SECONDS = 30


def _normalize_module_result(
    module_name: str,
    result: ModuleResult | None,
) -> ModuleResult:
    if result is not None:
        return result
    logger.warning(
        "Module %s returned None instead of ModuleResult — skipping",
        module_name,
    )
    return ModuleResult(
        status=ModuleStatus.FAILED,
        findings=[],
        metadata={},
        errors=["Module returned None — this is a bug in the module"],
    )


def _finding_sort_key(finding) -> tuple[str, str, str]:
    if not isinstance(finding, dict):
        return ("", "", str(finding))
    return (
        str(finding.get("platform", "")),
        str(finding.get("profile_url", "")),
        str(finding.get("source", "")),
    )


def _sort_collected(results: dict[str, ModuleResult]) -> dict[str, ModuleResult]:
    ordered: dict[str, ModuleResult] = {}
    for name in sorted(results):
        result = _normalize_module_result(name, results[name])
        result.findings = sorted(result.findings, key=_finding_sort_key)
        ordered[name] = result
    return ordered


def _compute_exposure_score(
    results: dict[str, ModuleResult],
    name_confidence: str | None = None,
) -> int:
    total = 0.0
    for name in sorted(results):
        result = _normalize_module_result(name, results[name])
        if result.status not in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL):
            continue
        weight = module_weight(name)
        module_score = 0.0
        for finding in result.findings:
            confidence = "high"
            if isinstance(finding, dict):
                meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
                # RC4 (Output-Trust): the risk score must reflect CORROBORATED
                # evidence, not finding VOLUME. An uncorroborated speculative hit
                # (RC1: verification == "unverified") is not evidence — a
                # localpart guess firing at hundreds of sites must not push an
                # identity-less address to "critical". Domain-infrastructure
                # contacts (RC3) are not the subject's exposure either. Neither
                # contributes to the score.
                if meta.get("verification") == "unverified" or meta.get("is_infrastructure"):
                    continue
                confidence = finding.get("confidence", "high")
            module_score += weight * _CONFIDENCE_MULTIPLIER.get(confidence, 1.0)
        cap = _MODULE_CAP.get(name)
        total += min(module_score, cap) if cap is not None else module_score

    name_bonus = {
        "confirmed": 10,
        "probable": 5,
        "possible": 2,
    }.get(str(name_confidence or "").lower(), 0)
    return min(int(total) + name_bonus, 100)


def _build_graph(
    canonical_email: str,
    collected: dict[str, ModuleResult],
    name_consensus: Any = None,
) -> dict | None:
    try:
        from .identity_graph import IdentityGraph

        findings = [
            {"module_name": module_name, "data": finding}
            for module_name, result in collected.items()
            for finding in _normalize_module_result(module_name, result).findings
        ]
        findings = collapse_breach_findings(findings)
        graph = IdentityGraph.build(
            {"email": canonical_email, "findings": findings},
            name_consensus=name_consensus,
        )
        # Store the full to_dict() output so shadow_findings + clusters
        # survive persistence.  The /graph endpoint extracts just
        # nodes/links for D3 rendering.
        return graph.to_dict()
    except Exception:
        return None


async def _build_graph_with_timeout(
    canonical_email: str,
    collected: dict[str, ModuleResult],
    name_consensus: Any = None,
) -> dict | None:
    """Run graph enrichment off-loop and cap the complete enrichment pass.

    IdentityGraph.build performs avatar hashing/fetching plus bio, temporal,
    infrastructure, and shadow-profile clustering.  Some of those libraries
    expose synchronous APIs, so invoking the builder on the event-loop thread
    can freeze both investigation progress and the health endpoint.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                _build_graph,
                canonical_email,
                collected,
                name_consensus,
            ),
            timeout=_ENRICHMENT_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "Graph enrichment timed out after %ss; continuing without graph data",
            _ENRICHMENT_TIMEOUT_SECONDS,
        )
        return None
    except Exception:
        logger.exception("Graph enrichment failed; continuing without graph data")
        return None


def _prepare_results(collected: dict[str, ModuleResult]) -> dict[str, ModuleResult]:
    final = {
        name: ModuleResult(
            status=safe_result.status,
            findings=list(safe_result.findings),
            metadata=deepcopy(safe_result.metadata) if safe_result.metadata else {},
            errors=list(safe_result.errors) if safe_result.errors else [],
        )
        for name, result in collected.items()
        if (safe_result := _normalize_module_result(name, result))
    }
    from .platform_dedup import deduplicate_platform_findings

    deduplicate_platform_findings(final)
    flattened = [
        {"module_name": module_name, "data": finding}
        for module_name, result in final.items()
        for finding in result.findings
    ]
    collapsed = collapse_breach_findings(flattened)
    final = {
        name: ModuleResult(
            status=safe_result.status,
            findings=[],
            metadata=deepcopy(safe_result.metadata) if safe_result.metadata else {},
            errors=list(safe_result.errors) if safe_result.errors else [],
        )
        for name, result in final.items()
        if (safe_result := _normalize_module_result(name, result))
    }
    for finding in collapsed:
        module_name = str(finding.get("module_name") or "").strip()
        if not module_name:
            continue
        final.setdefault(
            module_name,
            ModuleResult(status=ModuleStatus.SUCCESS),
        )
        payload = (
            finding.get("data")
            if isinstance(finding.get("data"), dict)
            else finding
        )
        if isinstance(payload, dict):
            final[module_name].findings.append(payload)
    return _sort_collected(final)


@dataclass
class QueueEvent:
    type: str
    module_name: str
    result: ModuleResult | None = None


class InvestigationEngine:
    def __init__(
        self,
        timeout: int = 30,
        max_concurrency: int = 10,
        budget_seconds: float | None = None,
        min_module_seconds: float = 2.0,
        mode: str | None = None,
    ) -> None:
        self._timeout = timeout
        self._max_concurrency = max_concurrency
        self._budget_seconds = budget_seconds
        self._min_module_seconds = min_module_seconds
        # Phase 2B — per-run product mode; None means fall back to the config
        # default (resolved in investigate()).
        self._mode = mode
        self.status = InvestigationStatus.PENDING

    async def investigate(
        self,
        email: str,
        investigation_id: str,
        module_names: list[str] | None = None,
        enable_modules: list[str] | None = None,
    ) -> asyncio.Queue[QueueEvent | None]:
        normalized = normalize_email_address(email)
        canonical_email = normalized.canonical_email
        queue: asyncio.Queue[QueueEvent | None] = asyncio.Queue()
        semaphore = asyncio.Semaphore(self._max_concurrency)
        collected: dict[str, ModuleResult] = {}
        started_at = datetime.now(timezone.utc)

        async def _run_and_persist() -> None:
            current_email = canonical_email
            try:
                self.status = InvestigationStatus.RUNNING
                await self._set_status(investigation_id, InvestigationStatus.RUNNING)

                from ..config import (
                    reset_run_opt_in_flags,
                    set_run_opt_in_flags,
                )
                from ..config import (
                    settings as config,
                )
                from .investigation_budget import InvestigationBudget
                from .phases import PHASE_DAG
                from .product_mode import normalize_mode

                # Phase 2B — resolve the product mode (per-run override else the
                # config default), mirroring the budget resolution below. A bad
                # mode raises here rather than silently downgrading.
                resolved_mode = normalize_mode(
                    self._mode if self._mode is not None else config.product_mode
                )

                # Phase 1B — resolve the wall-clock budget and (optionally) a
                # pinned fast primary module set. Both fall back to config so the
                # server default applies when the CLI/API don't override them.
                budget_seconds = (
                    self._budget_seconds
                    if self._budget_seconds is not None
                    else config.investigation_budget_seconds
                )
                budget = InvestigationBudget(
                    budget_seconds, min_module_seconds=self._min_module_seconds
                )
                effective_modules = module_names
                if effective_modules is None and config.investigation_fast_modules:
                    effective_modules = list(config.investigation_fast_modules)

                # L1 — publish this run's opt-in flags task-locally instead of
                # mutating the shared `config` singleton across phase awaits, so
                # concurrent investigations cannot cross-contaminate each other's
                # feature flags. Read sites use `config.opt_in_active(...)`.
                opt_in_flags = {
                    _OPT_IN_FLAG_BY_MODULE[name]
                    for name in (enable_modules or [])
                    if name in _OPT_IN_FLAG_BY_MODULE
                }
                opt_in_token = set_run_opt_in_flags(opt_in_flags)

                # RC5 (Output-Trust): decide the investigate entry gates ONCE.
                # If the domain does not resolve, the mailbox cannot exist — do NOT
                # let the localpart enumerator fabricate an identity from soft hits.
                # A role/system address (noreply@, info@) is not a person.
                from .investigation_gate import reset_target_gate, set_target_gate

                domain = current_email.split("@", 1)[1] if "@" in current_email else ""
                try:
                    from .name_consensus import is_role_or_system_email

                    is_role_system = bool(is_role_or_system_email(current_email))
                except Exception:
                    is_role_system = False
                domain_resolves = True
                if domain:
                    try:
                        from .mx_resolver import MxStatus, resolve_mx_typed

                        _mx = await resolve_mx_typed(domain)
                        # No MX AND no A/AAAA → the domain does not resolve. A
                        # transient DNS error stays "resolves" (fail open — we are
                        # only uncertain, not certain it is absent).
                        domain_resolves = _mx.status is not MxStatus.NO_RECORDS
                    except Exception:
                        domain_resolves = True
                gate_token = set_target_gate(
                    domain_resolves=domain_resolves, is_role_system=is_role_system
                )
                if not domain_resolves:
                    collected["domain_resolution"] = ModuleResult(
                        status=ModuleStatus.SUCCESS,
                        findings=[{
                            "platform": "domain_resolution",
                            "signal_type": "domain_status",
                            "confidence": "high",
                            "metadata": {
                                "domain": domain,
                                "resolves": False,
                                "note": (
                                    "domain does not resolve — mailbox cannot exist; "
                                    "personal identity enumeration skipped"
                                ),
                            },
                        }],
                        metadata={"domain": domain, "resolves": False},
                    )
                try:
                    for phase in PHASE_DAG:
                        await phase.run(
                            investigation_id=investigation_id,
                            email=email,
                            canonical_email=current_email,
                            collected=collected,
                            queue=queue,
                            semaphore=semaphore,
                            config=config,
                            budget=budget,
                            explicit_modules=(
                                set(effective_modules)
                                if effective_modules is not None
                                else None
                            ),
                            enable_modules=(
                                set(enable_modules) if enable_modules is not None else None
                            ),
                            mode=resolved_mode.value,
                        )
                        if phase.name == "email_credibility":
                            credibility = collected.get("email_credibility")
                            if credibility:
                                current_email = str(
                                    (credibility.metadata or {}).get("canonical_email")
                                    or current_email
                                )

                    # Compute name consensus before the graph build so
                    # the Phase 6B.2 V2 shadow-profile detector can use
                    # the resolved confirmed_name.
                    name_result = NameConsensusEngine(email).resolve(
                        extract_name_candidates(collected, email)
                    )
                    name_consensus = {
                        "confirmed_name": name_result.confirmed_name,
                        "name_confidence": name_result.name_confidence,
                    }
                    graph_data = await _build_graph_with_timeout(
                        current_email, collected, name_consensus=name_consensus
                    )
                    final = _prepare_results(collected)
                    self.status = InvestigationStatus.COMPLETE
                    await self._persist(
                        investigation_id,
                        final,
                        started_at,
                        current_email,
                        email,
                        graph_data,
                        mode=resolved_mode.value,
                    )
                    # Phase 1C — dual-write the canonical evidence ledger. Runs
                    # after _persist in its own transaction so a ledger failure
                    # can never roll back or otherwise disturb the findings.
                    await self._record_observations(
                        investigation_id, current_email, final, mode=resolved_mode.value
                    )
                    # Phase 2E — persist the reproducible run manifest + audit the
                    # collection. Guarded internally; never breaks the run.
                    try:
                        from .run_manifest import record_run_manifest

                        await record_run_manifest(
                            run_id=investigation_id,
                            pipeline="investigate",
                            mode=resolved_mode.value,
                        )
                    except Exception:
                        logger.exception("run manifest skipped for %s", investigation_id)
                    await self._dispatch_webhooks(investigation_id, email, final)
                finally:
                    reset_run_opt_in_flags(opt_in_token)
                    reset_target_gate(gate_token)
            except Exception:
                logger.exception("Investigation %s failed", investigation_id)
                self.status = InvestigationStatus.FAILED
                try:
                    await self._set_status(
                        investigation_id, InvestigationStatus.FAILED
                    )
                except Exception:
                    logger.exception(
                        "Failed to persist failed status for %s", investigation_id
                    )
            finally:
                await queue.put(None)

        asyncio.create_task(_run_and_persist())
        return queue

    async def _dispatch_webhooks(
        self,
        investigation_id: str,
        email: str,
        final: dict[str, ModuleResult],
    ) -> None:
        try:
            from ..integrations.webhooks import WebhookDispatcher

            name_result = NameConsensusEngine(email).resolve(
                extract_name_candidates(final, email)
            )
            score = _compute_exposure_score(final, name_result.name_confidence)
            credential_risk = assess_credential_risk_from_results(final)
            await WebhookDispatcher().dispatch(
                email,
                score,
                credential_risk.score,
                credential_risk.band,
                final,
            )

            from ..config import settings

            if settings.integration_webhook_url:
                from ..core.service import InvestigationService, enrich_report
                from ..integrations.integration_webhook import (
                    IntegrationWebhookDispatcher,
                )

                async with AsyncSessionLocal() as session:
                    service = InvestigationService(session)
                    data = await service.get_investigation(investigation_id)
                if data:
                    await IntegrationWebhookDispatcher().dispatch(enrich_report(data))
        except Exception:
            logger.exception("Webhook dispatch failed")

    async def _record_observations(
        self,
        investigation_id: str,
        canonical_email: str,
        final: dict[str, ModuleResult],
        mode: str = "security-investigation",
    ) -> None:
        """Phase 1C — write investigate findings into the evidence ledger."""
        try:
            from .observation_ledger import observations_from_results, record_observations

            records = observations_from_results(
                pipeline="investigate",
                activity_id=investigation_id,
                subject=canonical_email,
                subject_type="email",
                results=final,
                mode=mode,
            )
            await record_observations(records)
        except Exception:
            logger.exception(
                "Ledger dual-write skipped for investigation %s", investigation_id
            )

    async def _set_status(
        self, investigation_id: str, status: InvestigationStatus
    ) -> None:
        values: dict[str, Any] = {"status": status}
        if status == InvestigationStatus.RUNNING:
            values.update(started_at=datetime.now(timezone.utc), error=None)
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == investigation_id)
                    .values(**values)
                )

    async def _persist(
        self,
        investigation_id: str,
        collected: dict[str, ModuleResult],
        started_at: datetime,
        canonical_email: str,
        original_email: str,
        graph_data: dict | None = None,
        mode: str = "security-investigation",
    ) -> None:
        now = datetime.now(timezone.utc)
        safe_collected = {
            name: _normalize_module_result(name, result)
            for name, result in collected.items()
        }
        name_result = NameConsensusEngine(original_email).resolve(
            extract_name_candidates(safe_collected, original_email)
        )
        score = _compute_exposure_score(safe_collected, name_result.name_confidence)
        credential_risk = assess_credential_risk_from_results(
            safe_collected, as_of=now
        )
        timeline_rows = [
            {"module_name": module_name, "data": finding}
            for module_name, result in safe_collected.items()
            for finding in result.findings
        ]
        timeline = TimelineBuilder(as_of=now).build_timeline(timeline_rows)
        credibility = {}
        credibility_result = safe_collected.get("email_credibility")
        if credibility_result and isinstance(credibility_result.metadata, dict):
            credibility = credibility_result.metadata
        defenders_brief = defenders_brief_to_dict(
            generate_defenders_brief(
                {"email": original_email},
                timeline_rows,
                credential_risk,
                name_result,
                timeline,
                credibility,
            )
        )

        async with AsyncSessionLocal() as session:
            async with session.begin():
                values: dict = {
                    "status": InvestigationStatus.COMPLETE,
                    "completed_at": now,
                    "canonical_email": canonical_email,
                    "mode": mode,
                    "exposure_score": score,
                    "credential_risk_score": credential_risk.score,
                    "confirmed_name": name_result.confirmed_name,
                    "name_confidence": name_result.name_confidence,
                    "name_reasoning": name_result.name_reasoning,
                    "name_sources": name_result.name_sources,
                    "timeline_json": asdict(timeline),
                    "defenders_brief_json": defenders_brief,
                }
                if graph_data is not None:
                    values["graph_data"] = graph_data
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == investigation_id)
                    .values(**values)
                )
                for module_name, result in safe_collected.items():
                    session.add(
                        ModuleRun(
                            investigation_id=investigation_id,
                            module_name=module_name,
                            status=result.status.value,
                            run_metadata=result.metadata or None,
                            errors=result.errors or None,
                            started_at=started_at,
                            finished_at=now,
                        )
                    )
                    for finding_data in result.findings:
                        session.add(
                            Finding(
                                investigation_id=investigation_id,
                                module_name=module_name,
                                data=finding_data,
                            )
                        )
