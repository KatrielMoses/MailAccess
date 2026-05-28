from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from sqlalchemy import update

from ..db.database import AsyncSessionLocal
from ..db.models import Finding, Investigation, InvestigationStatus, ModuleRun
from .email_credibility import normalize_email_address
from .breach_normalizer import collapse_breach_findings
from .credential_risk import assess_credential_risk_from_results
from .timeline import TimelineBuilder
from ..modules import get_all_modules
from ..modules.base import ModuleResult, ModuleStatus

# Module categories for exposure scoring
_INFOSTEALER_MODULES = frozenset({"hudson_rock"})
_BREACH_MODULES = frozenset({"hibp", "breachdirectory", "breach_deep", "xposedornot"})
_SOCIAL_MODULES = frozenset({
    "gravatar",
    "social_links",
    "google_search",
    "ghunt",
    "whatsmyname",
    "account_discovery",
    "user_scanner",
    "username_pivot",
    "email_discovery",
    "social",
})
_POST_PRIMARY_ONLY = frozenset({"username_pivot", "phone_intel", "email_discovery", "alternate_email"})

_WEIGHT_INFOSTEALER = 20  # critical: active malware compromise
_WEIGHT_BREACH = 15       # high: credential exposure
_MODULE_WEIGHT_OVERRIDES: dict[str, int] = {
    "breach_deep": 18,
}
_WEIGHT_SOCIAL = 5        # medium: identity surface
_WEIGHT_META = 2          # low: infrastructure / info

# Confidence multipliers applied per finding before summing.
# Low-confidence findings (search-result WMN hits, experimental hints) contribute
# fractionally so volume alone can't inflate the score.
_CONFIDENCE_MULTIPLIER: dict[str, float] = {
    "high":   1.0,
    "medium": 0.5,
    "low":    0.2,
    "none":   0.0,
}

# Per-module score caps prevent a single module with many hits (e.g. WMN matching
# a common first-name username across 700 sites) from dominating the total.
# Breach/infostealer modules have higher caps because each hit is genuinely alarming.
_MODULE_CAP: dict[str, int] = {
    "whatsmyname":      20,
    "account_discovery": 15,
    "user_scanner":     15,
    "username_pivot":   10,
    "email_discovery":  10,
    "social":           10,
    "social_links":      5,
    "hudson_rock":      40,
    "breach_deep":      50,
    "hibp":             45,
    "breachdirectory":  40,
    "xposedornot":      45,
}

_MODULE_DEFAULT_TIMEOUTS: dict[str, int] = {
    "breach_deep": 90,
    "github_commits": 45,
}

_MODULE_TIMEOUT_FLOORS: dict[str, int] = {
    "account_discovery": 120,
    "username_pivot": 60,
    "user_scanner": 180,
    "whatsmyname": 200,
}


def _resolve_module_timeout(
    module_name: str,
    default_timeout: int,
    overrides: dict[str, int],
) -> int:
    floor_timeout = _MODULE_TIMEOUT_FLOORS.get(module_name, 0)
    resolved_timeout = max(default_timeout, floor_timeout)
    override_timeout = overrides.get(module_name)
    if override_timeout is None:
        return resolved_timeout
    return max(resolved_timeout, override_timeout)


def _module_weight(module_name: str) -> int:
    if module_name in _MODULE_WEIGHT_OVERRIDES:
        return _MODULE_WEIGHT_OVERRIDES[module_name]
    if module_name in _INFOSTEALER_MODULES:
        return _WEIGHT_INFOSTEALER
    if module_name in _BREACH_MODULES:
        return _WEIGHT_BREACH
    if module_name in _SOCIAL_MODULES:
        return _WEIGHT_SOCIAL
    return _WEIGHT_META


def _finding_sort_key(finding) -> tuple[str, str, str]:
    if not isinstance(finding, dict):
        return ("", "", str(finding))
    platform = str(finding.get("platform", ""))
    profile_url = str(finding.get("profile_url", ""))
    source = str(finding.get("source", ""))
    return (platform, profile_url, source)


def _sort_collected(results: dict[str, ModuleResult]) -> dict[str, ModuleResult]:
    """Return a new dict with module keys sorted and findings within each module sorted.

    Determinism guard: async completion order varies between runs, which made the
    insertion order of `results` (and finding lists inside each module) depend on
    network race conditions. Sorting both gives identical inputs → identical score.
    """
    ordered: dict[str, ModuleResult] = {}
    for name in sorted(results.keys()):
        result = results[name]
        result.findings = sorted(result.findings, key=_finding_sort_key)
        ordered[name] = result
    return ordered


def _compute_exposure_score(results: dict[str, ModuleResult]) -> int:
    """
    Confidence-weighted, per-module-capped exposure score, clamped to [0, 100].

    Each finding contributes: base_weight × confidence_multiplier.
    The sum per module is then capped to prevent high-volume enumeration modules
    (WMN, account_discovery) from drowning out genuine breach/infostealer signals.
    """
    total: float = 0.0
    base_weight = _module_weight  # local alias

    for name in sorted(results.keys()):
        result = results[name]
        if result.status not in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL):
            continue

        weight = base_weight(name)
        module_score: float = 0.0
        for finding in result.findings:
            confidence = "high"
            if isinstance(finding, dict):
                confidence = finding.get("confidence", "high")
            multiplier = _CONFIDENCE_MULTIPLIER.get(confidence, 1.0)
            module_score += weight * multiplier

        cap = _MODULE_CAP.get(name)
        if cap is not None:
            module_score = min(module_score, cap)

        total += module_score

    return min(int(total), 100)


@dataclass
class QueueEvent:
    type: str  # "module_start" | "module_result" | "module_error"
    module_name: str
    result: ModuleResult | None = None


class InvestigationEngine:
    """
    Runs selected OSINT modules concurrently and streams results via asyncio.Queue.

    Usage::

        queue = await engine.investigate(email, investigation_id)
        while True:
            item = await queue.get()
            if item is None:              # sentinel — all modules done, DB persisted
                break
            # item is a QueueEvent

    The engine persists ModuleRun records, Finding records, the final exposure
    score, and the COMPLETE status to the DB before sending the sentinel.
    """

    def __init__(self, timeout: int = 30, max_concurrency: int = 10) -> None:
        self._timeout = timeout
        self._max_concurrency = max_concurrency
        self.status = InvestigationStatus.PENDING

    async def investigate(
        self,
        email: str,
        investigation_id: str,
        module_names: list[str] | None = None,
        enable_modules: list[str] | None = None,
    ) -> asyncio.Queue[QueueEvent | None]:
        """
        Start investigation and return the result queue immediately.

        The background task writes a None sentinel to the queue after all modules
        complete and DB persistence finishes. Pass module_names to run a subset;
        None (default) runs all registered modules.
        """
        normalized = normalize_email_address(email)
        canonical_email = normalized.canonical_email

        if module_names is not None:
            classes = [c for c in get_all_modules() if c.name in module_names]
        else:
            classes = [
                c
                for c in get_all_modules()
                if c.name not in _POST_PRIMARY_ONLY and c.name != "emailrep"
            ]
        classes = [c for c in classes if c.name != "email_credibility"]
        classes = sorted(classes, key=lambda c: (getattr(c, "priority", 100), c.name))

        queue: asyncio.Queue[QueueEvent | None] = asyncio.Queue()
        semaphore = asyncio.Semaphore(self._max_concurrency)
        collected: dict[str, ModuleResult] = {}
        started_at = datetime.now(timezone.utc)
        credibility_result: ModuleResult | None = None

        cred_cls = next((cls for cls in get_all_modules() if cls.name == "email_credibility"), None)
        if cred_cls is not None:
            cred_mod = cred_cls()
            await queue.put(QueueEvent(type="module_start", module_name=cred_mod.name))
            try:
                from ..config import settings

                cred_timeout = _resolve_module_timeout(
                    cred_mod.name,
                    settings.module_timeout_seconds,
                    settings.module_timeout_overrides,
                )
                credibility_result = await asyncio.wait_for(
                    cred_mod.run(email),
                    timeout=cred_timeout,
                )
            except asyncio.TimeoutError:
                credibility_result = ModuleResult(
                    status=ModuleStatus.FAILED,
                    errors=["timed out during email credibility preflight"],
                )
            except Exception as exc:
                credibility_result = ModuleResult(
                    status=ModuleStatus.FAILED,
                    errors=[str(exc)],
                )
            collected[cred_mod.name] = credibility_result
            await queue.put(
                QueueEvent(
                    type=(
                        "module_error"
                        if credibility_result.status == ModuleStatus.FAILED
                        else "module_result"
                    ),
                    module_name=cred_mod.name,
                    result=credibility_result,
                )
            )

            cred_payload = credibility_result.metadata or {}
            canonical_email = str(cred_payload.get("canonical_email") or canonical_email)
            if bool(cred_payload.get("is_disposable")):
                classes = [c for c in classes if c.name in _BREACH_MODULES]

        async def _run_one(cls) -> None:
            mod = cls()
            from ..config import settings
            default_timeout = _MODULE_DEFAULT_TIMEOUTS.get(
                mod.name, settings.module_timeout_seconds
            )
            timeout = _resolve_module_timeout(
                mod.name,
                default_timeout,
                settings.module_timeout_overrides,
            )
            explicit_module = module_names is not None and mod.name in module_names
            async with semaphore:
                await queue.put(QueueEvent(type="module_start", module_name=mod.name))
                try:
                    if mod.name == "breach_deep":
                        coro = mod.run(canonical_email, force=explicit_module)
                    else:
                        coro = mod.run(canonical_email)
                    result = await asyncio.wait_for(coro, timeout=timeout)
                except asyncio.TimeoutError:
                    result = ModuleResult(
                        status=ModuleStatus.FAILED,
                        errors=[f"timed out after {timeout}s"],
                    )
                except Exception as exc:
                    result = ModuleResult(
                        status=ModuleStatus.FAILED,
                        errors=[str(exc)],
                    )
            collected[mod.name] = result
            event_type = (
                "module_error" if result.status == ModuleStatus.FAILED else "module_result"
            )
            await queue.put(QueueEvent(type=event_type, module_name=mod.name, result=result))

        async def _run_and_persist() -> None:
            self.status = InvestigationStatus.RUNNING
            await self._set_status(investigation_id, InvestigationStatus.RUNNING)

            from ..config import settings as _cfg

            _OPT_IN_MAP = {
                "breach_deep": "enable_breach_deep",
                "ghunt": "enable_ghunt",
                "email_discovery": "enable_email_discovery",
            }

            override_flags = {
                _OPT_IN_MAP[name]: True
                for name in (enable_modules or [])
                if name in _OPT_IN_MAP
            }

            from unittest.mock import patch
            import contextlib
            with contextlib.ExitStack() as stack:
                if override_flags:
                    stack.enter_context(patch.multiple(_cfg, **override_flags))
                await asyncio.gather(
                    *[_run_one(cls) for cls in classes],
                    return_exceptions=True,
                )

                _primary_collected = dict(collected)

                if _cfg.enable_username_pivot:
                    from ..modules.username_pivot import UsernamePivotModule

                    _pivot = UsernamePivotModule()
                    _pivot_timeout = _resolve_module_timeout(
                        _pivot.name,
                        _cfg.module_timeout_seconds,
                        _cfg.module_timeout_overrides,
                    )
                    await queue.put(QueueEvent(type="module_start", module_name=_pivot.name))
                    try:
                        _pivot_result = await asyncio.wait_for(
                            _pivot.run(email, collected), timeout=_pivot_timeout
                        )
                    except asyncio.TimeoutError:
                        _pivot_result = ModuleResult(
                            status=ModuleStatus.FAILED,
                            errors=[f"timed out after {_pivot_timeout}s"],
                        )
                    except Exception as _exc:
                        _pivot_result = ModuleResult(
                            status=ModuleStatus.FAILED, errors=[str(_exc)]
                        )
                    collected[_pivot.name] = _pivot_result
                    _pivot_evt = (
                        "module_error"
                        if _pivot_result.status == ModuleStatus.FAILED
                        else "module_result"
                    )
                    await queue.put(
                        QueueEvent(
                            type=_pivot_evt, module_name=_pivot.name, result=_pivot_result
                        )
                    )

                # Permutation discovery phase — runs after primary modules so it can
                # read their findings to extract a real name.
                if _cfg.enable_permutation_discovery:
                    from ..modules.permutation_discovery import PermutationDiscovery
                    _perm = PermutationDiscovery()
                    await queue.put(QueueEvent(type="module_start", module_name=_perm.name))
                    try:
                        _perm_result = await _perm.run(email, collected)
                    except Exception as _exc:
                        _perm_result = ModuleResult(
                            status=ModuleStatus.FAILED, errors=[str(_exc)]
                        )
                    collected[_perm.name] = _perm_result
                    _evt = (
                        "module_error"
                        if _perm_result.status == ModuleStatus.FAILED
                        else "module_result"
                    )
                    await queue.put(
                        QueueEvent(type=_evt, module_name=_perm.name, result=_perm_result)
                    )

                if _cfg.enable_email_discovery:
                    from ..modules.email_discovery import EmailDiscoveryModule

                    _email_discovery = EmailDiscoveryModule()
                    _email_timeout = _resolve_module_timeout(
                        _email_discovery.name,
                        _cfg.module_timeout_seconds,
                        _cfg.module_timeout_overrides,
                    )
                    await queue.put(
                        QueueEvent(
                            type="module_start", module_name=_email_discovery.name
                        )
                    )
                    try:
                        _email_result = await asyncio.wait_for(
                            _email_discovery.run(email, _primary_collected),
                            timeout=_email_timeout,
                        )
                    except asyncio.TimeoutError:
                        _email_result = ModuleResult(
                            status=ModuleStatus.FAILED,
                            errors=[f"timed out after {_email_timeout}s"],
                        )
                    except Exception as _exc:
                        _email_result = ModuleResult(
                            status=ModuleStatus.FAILED, errors=[str(_exc)]
                        )
                    collected[_email_discovery.name] = _email_result
                    _email_evt = (
                        "module_error"
                        if _email_result.status == ModuleStatus.FAILED
                        else "module_result"
                    )
                    await queue.put(
                        QueueEvent(
                            type=_email_evt,
                            module_name=_email_discovery.name,
                            result=_email_result,
                        )
                    )

                from ..modules.alternate_email import AlternateEmailModule
                
                _alt_email = AlternateEmailModule()
                _alt_timeout = _resolve_module_timeout(
                    _alt_email.name,
                    _cfg.module_timeout_seconds,
                    _cfg.module_timeout_overrides,
                )
                await queue.put(QueueEvent(type="module_start", module_name=_alt_email.name))
                try:
                    _alt_result = await asyncio.wait_for(
                        _alt_email.run(email, collected), timeout=_alt_timeout
                    )
                except asyncio.TimeoutError:
                    _alt_result = ModuleResult(
                        status=ModuleStatus.FAILED,
                        errors=[f"timed out after {_alt_timeout}s"],
                    )
                except Exception as _exc:
                    _alt_result = ModuleResult(
                        status=ModuleStatus.FAILED, errors=[str(_exc)]
                    )
                collected[_alt_email.name] = _alt_result
                _alt_evt = (
                    "module_error"
                    if _alt_result.status == ModuleStatus.FAILED
                    else "module_result"
                )
                await queue.put(
                    QueueEvent(
                        type=_alt_evt, module_name=_alt_email.name, result=_alt_result
                    )
                )

                if _cfg.enable_phone_intel:
                    from ..core.phone_extractor import extract_phones
                    from ..modules.phone_intel import PhoneIntelModule

                    _phone = PhoneIntelModule()
                    _phone_timeout = _resolve_module_timeout(
                        _phone.name,
                        _cfg.module_timeout_seconds,
                        _cfg.module_timeout_overrides,
                    )
                    await queue.put(QueueEvent(type="module_start", module_name=_phone.name))
                    try:
                        _phone_result = await asyncio.wait_for(
                            _phone.run(email, collected), timeout=_phone_timeout
                        )
                    except asyncio.TimeoutError:
                        _phone_result = ModuleResult(
                            status=ModuleStatus.FAILED,
                            errors=[f"timed out after {_phone_timeout}s"],
                        )
                    except Exception as _exc:
                        _phone_result = ModuleResult(
                            status=ModuleStatus.FAILED, errors=[str(_exc)]
                        )
                    collected[_phone.name] = _phone_result
                    _phone_evt = (
                        "module_error"
                        if _phone_result.status == ModuleStatus.FAILED
                        else "module_result"
                    )
                    await queue.put(
                        QueueEvent(
                            type=_phone_evt, module_name=_phone.name, result=_phone_result
                        )
                    )

                    # Re-run messaging hints with recovered phones (WhatsApp path)
                    if _cfg.enable_messaging_hints:
                        from ..modules.messaging_hints import MessagingHintsModule

                        _all_findings: list = []
                        for _r in collected.values():
                            if hasattr(_r, "findings"):
                                _all_findings.extend(_r.findings)
                        _phones = extract_phones(_all_findings)
                        if _phones:
                            _msg = MessagingHintsModule()
                            try:
                                _msg_extra = await asyncio.wait_for(
                                    _msg.run(email, phone_hints=_phones, collected=collected),
                                    timeout=_cfg.module_timeout_seconds,
                                )
                                if _msg_extra.findings:
                                    prev = collected.get(_msg.name)
                                    if prev and hasattr(prev, "findings"):
                                        existing_urls = {
                                            f.get("profile_url") for f in prev.findings
                                        }
                                        new_only = [
                                            f for f in _msg_extra.findings
                                            if f.get("profile_url") not in existing_urls
                                        ]
                                        prev.findings = list(prev.findings) + new_only
                                        if prev.metadata and _msg_extra.metadata:
                                            prev.metadata["whatsapp_followup"] = True
                                    else:
                                        collected[_msg.name] = _msg_extra
                            except Exception:
                                pass

                graph_data: dict | None = None
                try:
                    from .identity_graph import IdentityGraph

                    _findings_flat = []
                    for _mod, _res in collected.items():
                        if hasattr(_res, "findings"):
                            for _f in _res.findings:
                                _findings_flat.append({"module_name": _mod, "data": _f})
                    _findings_flat = collapse_breach_findings(_findings_flat)
                    graph_data = IdentityGraph.build(
                        {"email": canonical_email, "findings": _findings_flat}
                    ).to_d3()
                except Exception:
                    graph_data = None

                # Sort collected once, after every module has reported, so the
                # exposure score and persisted finding order are independent of
                # async completion order.
                # NOTE: use a separate variable to avoid shadowing the closed-over
                # `collected` in _run_and_persist — assigning to `collected` here
                # would make Python treat it as a local throughout the function,
                # causing UnboundLocalError on every earlier reference.
                _final: dict[str, ModuleResult] = {
                    name: ModuleResult(
                        status=result.status,
                        findings=list(result.findings),
                        metadata=deepcopy(result.metadata) if result.metadata else {},
                        errors=list(result.errors) if result.errors else [],
                    )
                    for name, result in collected.items()
                }
                _flat_findings: list[dict] = []
                for _mod, _res in _final.items():
                    if hasattr(_res, "findings"):
                        for _f in _res.findings:
                            _flat_findings.append({"module_name": _mod, "data": _f})

                _collapsed = collapse_breach_findings(_flat_findings)
                _final = {
                    name: ModuleResult(
                        status=result.status,
                        findings=[],
                        metadata=deepcopy(result.metadata) if result.metadata else {},
                        errors=list(result.errors) if result.errors else [],
                    )
                    for name, result in _final.items()
                }
                for _finding in _collapsed:
                    _module = str(_finding.get("module_name") or "").strip()
                    if not _module:
                        continue
                    if _module not in _final:
                        _final[_module] = ModuleResult(
                            status=ModuleStatus.SUCCESS,
                            findings=[],
                            metadata={},
                            errors=[],
                        )
                    _payload = _finding.get("data") if isinstance(_finding.get("data"), dict) else _finding
                    if isinstance(_payload, dict):
                        _final[_module].findings.append(_payload)

                _final = _sort_collected(_final)

                # Persist before sentinel so consumers see the final score in the DB.
                self.status = InvestigationStatus.COMPLETE
                try:
                    await self._persist(
                        investigation_id,
                        _final,
                        started_at,
                        canonical_email,
                        graph_data,
                    )

                    # Dispatch webhooks if configured
                    try:
                        from ..integrations.webhooks import WebhookDispatcher
                        score = _compute_exposure_score(_final)
                        credential_risk = assess_credential_risk_from_results(_final)
                        await WebhookDispatcher().dispatch(
                            email,
                            score,
                            credential_risk.score,
                            credential_risk.band,
                            _final,
                        )

                        from ..config import settings
                        if settings.integration_webhook_url:
                            from ..core.service import InvestigationService, enrich_report
                            from ..integrations.integration_webhook import IntegrationWebhookDispatcher
                            
                            async with AsyncSessionLocal() as session:
                                svc = InvestigationService(session)
                                data = await svc.get_investigation(investigation_id)
                            
                            if data:
                                payload = enrich_report(data)
                                await IntegrationWebhookDispatcher().dispatch(payload)
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).error(f"Webhook dispatch failed: {e}")
                except Exception:
                    self.status = InvestigationStatus.FAILED
                    await self._set_status(investigation_id, InvestigationStatus.FAILED)
                finally:
                    await queue.put(None)

        asyncio.create_task(_run_and_persist())
        return queue

    # ------------------------------------------------------------------
    # DB helpers (each opens its own session — runs outside request scope)
    # ------------------------------------------------------------------

    async def _set_status(
        self, investigation_id: str, status: InvestigationStatus
    ) -> None:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == investigation_id)
                    .values(status=status)
                )

    async def _persist(
        self,
        investigation_id: str,
        collected: dict[str, ModuleResult],
        started_at: datetime,
        canonical_email: str,
        graph_data: dict | None = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        score = _compute_exposure_score(collected)
        credential_risk = assess_credential_risk_from_results(collected, as_of=now)
        timeline_rows: list[dict] = []
        for module_name, result in collected.items():
            for finding_data in result.findings:
                timeline_rows.append({"module_name": module_name, "data": finding_data})
        timeline_json = asdict(TimelineBuilder(as_of=now).build_timeline(timeline_rows))

        async with AsyncSessionLocal() as session:
            async with session.begin():
                values: dict = {
                    "status": InvestigationStatus.COMPLETE,
                    "completed_at": now,
                    "canonical_email": canonical_email,
                    "exposure_score": score,
                    "credential_risk_score": credential_risk.score,
                    "timeline_json": timeline_json,
                }
                if graph_data is not None:
                    values["graph_data"] = graph_data
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == investigation_id)
                    .values(**values)
                )
                for module_name, result in collected.items():
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
