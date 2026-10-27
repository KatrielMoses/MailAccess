"""Which paid providers this engine can use right now.

A provider "exists" only when its key is set and it is not switched off. When it does
not exist it must not appear anywhere (events, report, graph, exports, credit lines,
module list). Booleans only: never key values, fragments or quota.
"""

from __future__ import annotations

# investigate modules that belong to one provider (hidden everywhere when it is off)
PROVIDER_OF_MODULE = {
    "ip_intel": "ipgeolocation",
    "whoisfreaks_intel": "whoisfreaks",
}


def provider_capabilities() -> dict[str, bool]:
    """``{"ipgeolocation", "whoisfreaks", "netlas", "own_index": bool}`` for
    this engine (key set and not persistently disabled; a per-run opt-out is not
    considered). ``own_index`` (the MailAccess Index) needs BOTH its URL and key."""
    from .ipgeo_client import ipgeo_active
    from .netlas_client import netlas_active
    from .own_index_client import own_index_active
    from .whoisfreaks_client import whoisfreaks_active

    return {
        "ipgeolocation": bool(ipgeo_active(no_ipgeo=False)),
        "whoisfreaks": bool(whoisfreaks_active(no_whoisfreaks=False)),
        "netlas": bool(netlas_active(no_netlas=False)),
        "own_index": bool(own_index_active(no_own_index=False)),
    }


def provider_module_enabled(module: str) -> bool:
    """False for a provider's module when that provider is off for THIS run (no key,
    persistently disabled, or the per-run flag)."""
    provider = PROVIDER_OF_MODULE.get(module)
    if provider is None:
        return True
    from .ipgeo_client import ipgeo_active
    from .whoisfreaks_client import whoisfreaks_active

    return bool(ipgeo_active() if provider == "ipgeolocation" else whoisfreaks_active())


def active_providers() -> dict[str, bool]:
    """What is ACTIVE for the current run: key set, not disabled, and not opted out
    per-run (reads the run's context flags). Recorded in the run manifest."""
    from .ipgeo_client import ipgeo_active
    from .netlas_client import netlas_active
    from .own_index_client import own_index_active
    from .whoisfreaks_client import whoisfreaks_active

    return {
        "ipgeolocation": bool(ipgeo_active()),
        "whoisfreaks": bool(whoisfreaks_active()),
        "netlas": bool(netlas_active()),
        "own_index": bool(own_index_active()),
    }


def providers_for_flags(
    *,
    no_ipgeo: bool = False,
    no_whoisfreaks: bool = False,
    no_netlas: bool = False,
    no_own_index: bool = False,
) -> dict[str, bool]:
    """Active providers for a run given explicit per-run flags (harvest passes them)."""
    from .ipgeo_client import ipgeo_active
    from .netlas_client import netlas_active
    from .own_index_client import own_index_active
    from .whoisfreaks_client import whoisfreaks_active

    return {
        "ipgeolocation": bool(ipgeo_active(no_ipgeo=no_ipgeo)),
        "whoisfreaks": bool(whoisfreaks_active(no_whoisfreaks=no_whoisfreaks)),
        "netlas": bool(netlas_active(no_netlas=no_netlas)),
        "own_index": bool(own_index_active(no_own_index=no_own_index)),
    }


# Providers whose stored facts are filtered at cross-run reads. (Netlas keeps its
# deliberate F8 design: the enrichment store is readable without a key.)
FILTERED_PROVIDERS = ("ipgeolocation", "whoisfreaks")
_MODULE_PROVIDER = {
    "ip_intel": "ipgeolocation",
    "whoisfreaks_intel": "whoisfreaks",
}


async def allowed_providers_for_run(run_id: str, session=None) -> set[str]:
    """Which filtered providers a run's report may show facts from.

    From the run's manifest when it recorded ``providers``. An older run without it
    counts as the providers that actually produced data in its OWN findings: never
    inferred from the keys the engine happens to hold now."""
    from sqlalchemy import select

    from ..db.database import AsyncSessionLocal
    from ..db.models import Finding, ModuleRun
    from .run_manifest import read_run_manifest

    manifest = await read_run_manifest(run_id, session=session, include_providers=True)
    recorded = (manifest or {}).get("providers")
    if isinstance(recorded, dict):
        return {p for p in FILTERED_PROVIDERS if recorded.get(p)}

    async def _derive(s) -> set[str]:
        found = set()
        for model in (Finding, ModuleRun):
            rows = (
                await s.execute(select(model.module_name).where(model.investigation_id == run_id))
            ).scalars().all()
            found |= {_MODULE_PROVIDER[m] for m in rows if m in _MODULE_PROVIDER}
        return found

    if session is not None:
        return await _derive(session)
    async with AsyncSessionLocal() as owned:
        return await _derive(owned)
