from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any

from ..modules.base import BaseModule, ModuleResult, ModuleStatus
from ._phase_runner import run_one_module
from .engine import QueueEvent
from .policy import (
    _BREACH_MODULES,
    _MODULE_DEFAULT_TIMEOUTS,
    _POST_PRIMARY_ONLY,
)

logger = logging.getLogger(__name__)


def _event_start(module_name: str) -> QueueEvent:
    return QueueEvent(type="module_start", module_name=module_name)


def _event_result(module_name: str, result: ModuleResult) -> QueueEvent:
    event_type = "module_error" if result.status == ModuleStatus.FAILED else "module_result"
    return QueueEvent(type=event_type, module_name=module_name, result=result)


def _flat_findings(collected: dict[str, ModuleResult]) -> list[dict]:
    return [finding for result in collected.values() for finding in result.findings]


async def _run_and_record(
    mod: BaseModule,
    *,
    email: str,
    canonical_email: str,
    collected: dict[str, ModuleResult],
    queue: asyncio.Queue,
    semaphore: asyncio.Semaphore,
    config: Any,
    explicit_module: bool = False,
    findings_input: dict[str, ModuleResult] | None = None,
    use_canonical_email: bool = True,
) -> tuple[str, ModuleResult]:
    default_timeout = _MODULE_DEFAULT_TIMEOUTS.get(
        mod.name, config.module_timeout_seconds
    )
    async with semaphore:
        result = await run_one_module(
            mod,
            email,
            default_timeout=default_timeout,
            overrides=config.module_timeout_overrides,
            explicit_module=explicit_module,
            queue=queue,
            canonical_email=canonical_email if use_canonical_email else None,
            collected=findings_input,
        )
    collected[mod.name] = result
    await queue.put(_event_result(mod.name, result))
    return mod.name, result


class InvestigationPhase(ABC):
    name: str = ""
    dependencies: tuple[str, ...] = ()

    @abstractmethod
    async def run(
        self,
        *,
        investigation_id: str,
        email: str,
        canonical_email: str,
        collected: dict[str, ModuleResult],
        queue: asyncio.Queue,
        semaphore: asyncio.Semaphore,
        config: Any,
        explicit_modules: set[str] | None,
        enable_modules: set[str] | None,
    ) -> dict[str, ModuleResult]: ...


class CredibilityPhase(InvestigationPhase):
    name = "email_credibility"

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        from ..modules.email_credibility import EmailCredibilityModule

        await _run_and_record(
            EmailCredibilityModule(),
            **_runner_kwargs(kwargs),
            use_canonical_email=False,
        )
        return kwargs["collected"]


class PrimaryPhase(InvestigationPhase):
    name = "primary"
    dependencies = ("email_credibility",)

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        from ..modules import get_all_modules

        explicit_modules = kwargs["explicit_modules"]
        enable_modules = kwargs["enable_modules"] or set()
        collected = kwargs["collected"]
        classes = list(get_all_modules())
        if explicit_modules is not None:
            classes = [cls for cls in classes if cls.name in explicit_modules]
        classes = [
            cls
            for cls in classes
            if cls.name not in _POST_PRIMARY_ONLY
            and cls.name not in {"emailrep", "email_credibility"}
            and (cls.name != "press_intel" or cls.name in enable_modules)
        ]
        credibility = collected.get("email_credibility")
        if credibility and bool((credibility.metadata or {}).get("is_disposable")):
            classes = [cls for cls in classes if cls.name in _BREACH_MODULES]
        classes.sort(key=lambda cls: (getattr(cls, "priority", 100), cls.name))

        async def run_class(cls: type[BaseModule]) -> tuple[str, ModuleResult]:
            return await _run_and_record(
                cls(),
                **_runner_kwargs(kwargs),
                explicit_module=(
                    explicit_modules is not None and cls.name in explicit_modules
                ),
            )

        await asyncio.gather(
            *(run_class(cls) for cls in classes), return_exceptions=True
        )
        return collected


class PivotPhase(InvestigationPhase):
    name = "username_pivot"
    dependencies = ("primary",)

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        if kwargs["config"].enable_username_pivot:
            from ..modules.username_pivot import UsernamePivotModule

            await _run_and_record(
                UsernamePivotModule(),
                **_runner_kwargs(kwargs),
                findings_input=kwargs["collected"],
            )
        return kwargs["collected"]


class PermutationPhase(InvestigationPhase):
    name = "permutation_discovery"
    dependencies = ("primary",)

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        if kwargs["config"].enable_permutation_discovery:
            from ..modules.permutation_discovery import PermutationDiscovery

            await _run_and_record(
                PermutationDiscovery(),
                **_runner_kwargs(kwargs),
                findings_input=kwargs["collected"],
            )
        return kwargs["collected"]


class EmailDiscoveryPhase(InvestigationPhase):
    name = "email_discovery"
    dependencies = ("primary",)

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        if kwargs["config"].enable_email_discovery:
            from ..modules import get_all_modules
            from ..modules.email_discovery import EmailDiscoveryModule

            explicit = kwargs["explicit_modules"]
            enable = kwargs["enable_modules"] or set()
            primary_names = {
                cls.name
                for cls in get_all_modules()
                if cls.name not in _POST_PRIMARY_ONLY
                and cls.name not in {"emailrep", "email_credibility"}
                and (explicit is None or cls.name in explicit)
                and (cls.name != "press_intel" or cls.name in enable)
            }
            snapshot = {
                name: result
                for name, result in kwargs["collected"].items()
                if name in primary_names
            }
            await _run_and_record(
                EmailDiscoveryModule(),
                **_runner_kwargs(kwargs),
                findings_input=snapshot,
            )
        return kwargs["collected"]


class AlternateEmailPhase(InvestigationPhase):
    name = "alternate_email"
    dependencies = ("primary",)

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        from ..modules.alternate_email import AlternateEmailModule

        await _run_and_record(
            AlternateEmailModule(),
            **_runner_kwargs(kwargs),
            findings_input=kwargs["collected"],
        )
        return kwargs["collected"]


class DomainClusterPhase(InvestigationPhase):
    """Phase 6B.1 — group platform domains by shared infrastructure.

    Runs after all platform modules and after the alternate-email pass so
    the clusterer sees the full set of platform findings.  Emits
    ``infra_cluster`` findings whenever 3+ platforms share the same
    registrar AND /24 IP subnet; the identity graph picks them up
    automatically via the regular finding pipeline.
    """

    name = "domain_cluster"
    dependencies = ("primary", "alternate_email")

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        from ..modules.domain_cluster import DomainClusterModule

        await _run_and_record(
            DomainClusterModule(),
            **_runner_kwargs(kwargs),
            findings_input=kwargs["collected"],
        )
        return kwargs["collected"]


class ProfilePhase(InvestigationPhase):
    name = "profile"
    dependencies = ("primary", "alternate_email")

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        from ..modules.linkedin_serp import LinkedInSerpModule
        from ..modules.marketplace_profile import MarketplaceProfileModule
        from ..modules.twitter_profile import TwitterProfileModule

        modules = (
            TwitterProfileModule(),
            LinkedInSerpModule(),
            MarketplaceProfileModule(),
        )
        await asyncio.gather(
            *(
                _run_and_record(
                    mod,
                    **_runner_kwargs(kwargs),
                    findings_input=kwargs["collected"],
                )
                for mod in modules
            ),
            return_exceptions=True,
        )
        return kwargs["collected"]


class PhonePhase(InvestigationPhase):
    name = "phone_intel"
    dependencies = ("profile",)

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        config = kwargs["config"]
        collected = kwargs["collected"]
        if not config.enable_phone_intel:
            return collected

        from ..modules.phone_intel import PhoneIntelModule

        await _run_and_record(
            PhoneIntelModule(),
            **_runner_kwargs(kwargs),
            findings_input=collected,
        )
        if config.enable_messaging_hints:
            from ..modules.messaging_hints import MessagingHintsModule
            from .phone_extractor import extract_phones

            phones = extract_phones(_flat_findings(collected))
            if phones:
                messaging = MessagingHintsModule()
                try:
                    extra = await asyncio.wait_for(
                        messaging.run(
                            kwargs["canonical_email"],
                            phone_hints=phones,
                            collected=collected,
                        ),
                        timeout=config.module_timeout_seconds,
                    )
                    if extra.findings:
                        previous = collected.get(messaging.name)
                        if previous is not None:
                            existing_urls = {
                                finding.get("profile_url")
                                for finding in previous.findings
                            }
                            previous.findings.extend(
                                finding
                                for finding in extra.findings
                                if finding.get("profile_url") not in existing_urls
                            )
                            previous.metadata["whatsapp_followup"] = True
                        else:
                            collected[messaging.name] = extra
                except Exception:
                    logger.debug("messaging_hints phone follow-up failed", exc_info=True)
        return collected


def _runner_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {
        "email": kwargs["email"],
        "canonical_email": kwargs["canonical_email"],
        "collected": kwargs["collected"],
        "queue": kwargs["queue"],
        "semaphore": kwargs["semaphore"],
        "config": kwargs["config"],
    }


PHASE_DAG: tuple[InvestigationPhase, ...] = (
    CredibilityPhase(),
    PrimaryPhase(),
    PivotPhase(),
    PermutationPhase(),
    EmailDiscoveryPhase(),
    AlternateEmailPhase(),
    DomainClusterPhase(),
    ProfilePhase(),
    PhonePhase(),
)
