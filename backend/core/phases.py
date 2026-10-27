from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any

from ..modules.base import BaseModule, ModuleResult, ModuleStatus
from ._phase_runner import run_one_module
from .engine import QueueEvent
from .investigation_budget import InvestigationBudget
from .policy import (
    _BREACH_MODULES,
    _MODULE_DEFAULT_TIMEOUTS,
    _POST_PRIMARY_ONLY,
    _SPECULATIVE_ENUMERATION,
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
    budget: InvestigationBudget | None = None,
    explicit_module: bool = False,
    findings_input: dict[str, ModuleResult] | None = None,
    use_canonical_email: bool = True,
    mode: str = "security-investigation",
    force: bool = False,
) -> tuple[str, ModuleResult]:
    default_timeout = _MODULE_DEFAULT_TIMEOUTS.get(
        mod.name, config.module_timeout_seconds
    )
    from . import run_stream

    async with semaphore:
        run_stream.module_started(mod.name)
        try:
            result = await run_one_module(
                mod,
                email,
                default_timeout=default_timeout,
                overrides=config.module_timeout_overrides,
                explicit_module=explicit_module,
                queue=queue,
                canonical_email=canonical_email if use_canonical_email else None,
                collected=findings_input,
                budget=budget,
                mode=mode,
                force=force,
            )
        except BaseException as exc:
            # A module that raises still gets its "done" event, so a viewer never
            # waits on a module that is already over.
            run_stream.module_finished(
                mod.name,
                ModuleResult(status=ModuleStatus.FAILED, errors=[str(exc)[:200]]),
                canonical_email,
            )
            raise
    collected[mod.name] = result
    run_stream.module_finished(mod.name, result, canonical_email)
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
        budget: InvestigationBudget | None = None,
        mode: str = "security-investigation",
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
        from .product_mode import is_module_allowed

        explicit_modules = kwargs["explicit_modules"]
        enable_modules = kwargs["enable_modules"] or set()
        collected = kwargs["collected"]
        mode = kwargs.get("mode", "security-investigation")
        classes = list(get_all_modules())
        if explicit_modules is not None:
            classes = [cls for cls in classes if cls.name in explicit_modules]
        classes = [
            cls
            for cls in classes
            if cls.name not in _POST_PRIMARY_ONLY
            and cls.name not in {"emailrep", "email_credibility"}
            and (cls.name != "press_intel" or cls.name in enable_modules)
            # Phase 2C — prune modules not permitted in this product mode so
            # they never instantiate (the run_one_module gate is the backstop).
            and is_module_allowed(cls.name, mode)
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

        # T1 (Output-Trust final): run the EVIDENCE / real-signal modules first,
        # then the SPECULATIVE localpart enumerators with whatever budget remains.
        # Previously all primary modules ran in one concurrent burst, so a heavy
        # localpart sweep (username_platforms) saturated the shared network/budget
        # and starved the sources that actually confirm identity (github/PGP/
        # keybase/gravatar) — they'd time out or be budget-skipped. Reserving the
        # budget for evidence first is the fix; the speculative wave then runs (and
        # is budget-skipped by run_one_module if evidence already used the time).
        evidence_classes = [c for c in classes if c.name not in _SPECULATIVE_ENUMERATION]
        speculative_classes = [c for c in classes if c.name in _SPECULATIVE_ENUMERATION]
        await asyncio.gather(
            *(run_class(cls) for cls in evidence_classes), return_exceptions=True
        )
        if speculative_classes:
            await asyncio.gather(
                *(run_class(cls) for cls in speculative_classes), return_exceptions=True
            )
        return collected


class BreachAggregatorPhase(InvestigationPhase):
    """Phase 5 — breach aggregation.

    Runs strictly after ``PrimaryPhase`` (which runs the HIBP breach
    check) so the four aggregator sources corroborate the existing breach
    evidence.  Findings land in ``collected["breach_aggregator"]`` and flow
    into ``_prepare_results`` / the Defender's Brief like any other module.
    """

    name = "breach_aggregator"
    dependencies = ("primary",)

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        from ..modules.breach_aggregator import BreachAggregatorModule

        await _run_and_record(
            BreachAggregatorModule(),
            **_runner_kwargs(kwargs),
        )
        return kwargs["collected"]


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
        from ..config import opt_in_active

        if opt_in_active("enable_email_discovery", kwargs["config"].enable_email_discovery):
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


class AlternateEmailAnchorPhase(InvestigationPhase):
    """UC7.3a — re-anchor Class-1 discovery on alternate emails found via a Class-1
    signal, merged under one person. Runs after alternate_email; bounded depth 1."""

    name = "alternate_email_anchor"
    dependencies = ("primary", "alternate_email")

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        from ..modules.alternate_email_anchor import AlternateEmailAnchorModule

        await _run_and_record(
            AlternateEmailAnchorModule(),
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

        def _record(mod):
            return _run_and_record(
                mod, **_runner_kwargs(kwargs), findings_input=kwargs["collected"]
            )

        async def _linkedin() -> None:
            # Keyless LinkedIn SERP (free tier). The Pro LinkedIn card comes from Oxylabs
            # (social_discovery).
            await _record(LinkedInSerpModule())

        async def _social() -> None:
            # Instagram/Facebook/LinkedIn discovery via Oxylabs Web Search (Pro, BYOK).
            # Off (no token) means fully off.
            from .oxylabs_client import oxylabs_active

            explicit = kwargs.get("explicit_modules")
            if oxylabs_active() and (explicit is None or "social_discovery" in explicit):
                from ..modules.social_discovery import SocialDiscoveryModule

                await _record(SocialDiscoveryModule())

        await asyncio.gather(
            _record(TwitterProfileModule()),
            _linkedin(),
            _social(),
            _record(MarketplaceProfileModule()),
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
            budget = kwargs.get("budget")
            if phones and (budget is None or budget.can_start_module()):
                messaging = MessagingHintsModule()
                hint_timeout = float(config.module_timeout_seconds)
                if budget is not None:
                    hint_timeout = budget.cap(hint_timeout)
                from . import run_stream

                run_stream.module_started(messaging.name, followup=True)
                try:
                    extra = await asyncio.wait_for(
                        messaging.run(
                            kwargs["canonical_email"],
                            phone_hints=phones,
                            collected=collected,
                        ),
                        timeout=hint_timeout,
                    )
                    run_stream.module_finished(
                        messaging.name, extra, kwargs["canonical_email"]
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
                    run_stream.module_finished(
                        messaging.name,
                        ModuleResult(status=ModuleStatus.FAILED, errors=["follow-up failed"]),
                        kwargs["canonical_email"],
                    )
                    logger.debug("messaging_hints phone follow-up failed", exc_info=True)
        return collected


class IpIntelPhase(InvestigationPhase):
    name = "ip_intel"
    dependencies = ("breach_aggregator", "phone_intel")

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        from ..modules.ip_intel import IpIntelModule, collect_investigate_ips
        from .ipgeo_client import ipgeo_active

        explicit = kwargs.get("explicit_modules")
        if explicit is not None and self.name not in explicit:
            return kwargs["collected"]
        ips = collect_investigate_ips(kwargs["canonical_email"], kwargs["collected"])
        # Off (no key, disabled, or --no-ipgeo) means fully off: no call and no cached data.
        if not ips or not ipgeo_active():
            return kwargs["collected"]
        runner = _runner_kwargs(kwargs)
        # The primary wall budget may be spent by discovery. This final,
        # bounded enrichment phase still gets its normal module timeout.
        runner["budget"] = None
        await _run_and_record(IpIntelModule(), **runner, findings_input=kwargs["collected"])
        return kwargs["collected"]


class WhoisFreaksPhase(InvestigationPhase):
    name = "whoisfreaks_intel"
    dependencies = ("ip_intel",)

    async def run(self, **kwargs: Any) -> dict[str, ModuleResult]:
        from ..modules.whoisfreaks_intel import WhoisFreaksIntelModule
        from .whoisfreaks_client import whoisfreaks_active

        explicit = kwargs.get("explicit_modules")
        if explicit is not None and self.name not in explicit:
            return kwargs["collected"]
        # Off (no key, disabled, or --no-whoisfreaks) means fully off: no call, no cache.
        if not whoisfreaks_active():
            return kwargs["collected"]
        runner = _runner_kwargs(kwargs)
        # Like ip_intel: a bounded final enrichment that keeps its own timeout
        # even when discovery spent the primary budget.
        runner["budget"] = None
        await _run_and_record(
            WhoisFreaksIntelModule(), **runner, findings_input=kwargs["collected"]
        )
        return kwargs["collected"]


def _runner_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {
        "email": kwargs["email"],
        "canonical_email": kwargs["canonical_email"],
        "collected": kwargs["collected"],
        "queue": kwargs["queue"],
        "semaphore": kwargs["semaphore"],
        "config": kwargs["config"],
        "budget": kwargs.get("budget"),
        "mode": kwargs.get("mode", "security-investigation"),
        "force": kwargs.get("force", False),
    }


PHASE_DAG: tuple[InvestigationPhase, ...] = (
    CredibilityPhase(),
    PrimaryPhase(),
    BreachAggregatorPhase(),
    PivotPhase(),
    PermutationPhase(),
    EmailDiscoveryPhase(),
    AlternateEmailPhase(),
    AlternateEmailAnchorPhase(),
    DomainClusterPhase(),
    ProfilePhase(),
    PhonePhase(),
    IpIntelPhase(),
    WhoisFreaksPhase(),
)


def _phase_levels(dag: tuple[InvestigationPhase, ...]) -> list[list[InvestigationPhase]]:
    """Group the DAG into concurrent batches, preserving its order exactly (UC4).

    A batch is a run of *consecutive* phases that share the identical dependency set
    (e.g. username_pivot, permutation_discovery, email_discovery and alternate_email all
    depend only on ``primary``). Such phases cannot depend on one another — a phase is
    never in its own dependency set — so running them together is safe, and because the
    grouping is strictly adjacent, no phase ever moves ahead of one it follows in the
    DAG. A phase with a different dependency set starts a new batch and runs after the
    previous one, so ordering (and every declared dependency) is respected even for a
    reduced DAG whose intermediate phases are absent.
    """
    batches: list[list[InvestigationPhase]] = []
    current_key: frozenset[str] | None = None
    for phase in dag:
        key = frozenset(getattr(phase, "dependencies", ()))
        if batches and key == current_key:
            batches[-1].append(phase)
        else:
            batches.append([phase])
            current_key = key
    return batches


_KEY_SETTINGS: dict[str, tuple[str, ...]] = {
    "hibp": ("hibp_api_key", "haveibeenpwned_api_key"),
    "breachdirectory": ("breachdirectory_api_key",),
    "hunter_io": ("hunter_io_api_key",),
    "shodan": ("shodan_api_key",),
    "intelx_lookup": ("intelx_api_key",),
    "google_dork": ("serpapi_key",),
}
# Domain modules that have nothing to read when the address is on a free provider
# (gmail.com, outlook.com...): there is no company domain behind it.
_COMPANY_DOMAIN_MODULES = frozenset(
    {
        "companies_house", "domain_intel", "netlas_org_surface", "opencorporates",
        "ransomware_intel", "sec_edgar", "whois_lookup", "domain_harvester",
        "github_domain_commits", "github_org_members", "subdomain_intel",
        # Domain-wide email harvest: nothing to read behind a free provider, so
        # they burn ~100s on gmail.com and return 0. (Email-scoped siblings like
        # pgp_keyserver / github_commits still run.)
        "commoncrawl_email", "employee_name_discovery", "pgp_domain_email",
        "npm_email", "code_and_cert_email", "email_search_dork",
        "wayback_domain_harvest", "wordpress_rest", "syndication_feed_sweeper",
    }
)
_NETLAS_MODULES = frozenset({"netlas_email_footprint", "netlas_org_surface"})
_MS_CONSUMER_DOMAINS = frozenset({"outlook.com", "hotmail.com", "live.com", "msn.com"})


def unavailable_reason(
    module: str,
    config: Any,
    email: str,
    explicit: set[str] | None,
    enable: set[str],
) -> str | None:
    """``no_key`` | ``disabled`` when a module cannot run in this run, else None."""
    if explicit is not None and module in explicit:
        return None  # asked for by name: it will at least be attempted
    keys = _KEY_SETTINGS.get(module)
    if keys and not any(getattr(config, k, None) for k in keys):
        return "no_key"
    if module in _NETLAS_MODULES:
        from .netlas_client import netlas_active

        if not netlas_active():
            return "no_key"
    flag = getattr(config, f"enable_{module}", None)
    if flag is False and module not in enable:
        return "disabled"
    domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
    from ..modules.domain_intel import _FREE_PROVIDERS

    if module in _COMPANY_DOMAIN_MODULES and domain in _FREE_PROVIDERS:
        return "disabled"
    if module == "outlook_autodiscover" and domain not in _MS_CONSUMER_DOMAINS:
        return "disabled"
    return None


def plan_modules(
    config: Any,
    explicit_modules: set[str] | None,
    enable_modules: set[str] | None,
    mode: str,
    *,
    only_phases: set[str] | None = None,
    email: str = "",
) -> tuple[list[tuple[str, str]], list[dict[str, str]]]:
    """``(planned, unavailable)`` for ``run_started``.

    ``planned`` is the ``(phase, module)`` pairs that will actually run, which is what
    "checked N of M sources" counts. Modules that cannot run (no key, disabled, nothing
    to read for this address) go to ``unavailable`` as ``{module, reason}``. Modules
    decided only at run time (ip_intel, whoisfreaks_intel) announce themselves with
    their ``module_start``.
    """
    from ..config import opt_in_active
    from ..modules import get_all_modules
    from .capabilities import provider_module_enabled
    from .product_mode import is_module_allowed

    enable = enable_modules or set()
    planned: list[tuple[str, str]] = []
    unavailable: list[dict[str, str]] = []

    def add(phase: str, *names: str) -> None:
        if only_phases is not None and phase not in only_phases:
            return
        for name in names:
            if not provider_module_enabled(name):
                continue  # a provider that is off is omitted: not planned, not "unavailable"
            reason = unavailable_reason(name, config, email, explicit_modules, enable)
            if reason:
                unavailable.append({"module": name, "reason": reason})
            else:
                planned.append((phase, name))

    add("email_credibility", "email_credibility")
    classes = [
        cls
        for cls in get_all_modules()
        if (explicit_modules is None or cls.name in explicit_modules)
        and cls.name not in _POST_PRIMARY_ONLY
        and cls.name not in {"emailrep", "email_credibility"}
        and (cls.name != "press_intel" or cls.name in enable)
        and is_module_allowed(cls.name, mode)
    ]
    classes.sort(key=lambda cls: (getattr(cls, "priority", 100), cls.name))
    add("primary", *[cls.name for cls in classes])
    add("breach_aggregator", "breach_aggregator")
    if config.enable_username_pivot:
        add("username_pivot", "username_pivot")
    if config.enable_permutation_discovery:
        add("permutation_discovery", "permutation_discovery")
    if opt_in_active("enable_email_discovery", config.enable_email_discovery):
        add("email_discovery", "email_discovery")
    add("alternate_email", "alternate_email")
    add("domain_cluster", "domain_cluster")
    add("profile", "twitter_profile", "linkedin_serp", "marketplace_profile")
    if config.enable_phone_intel:
        add("phone_intel", "phone_intel")
    return planned, unavailable
