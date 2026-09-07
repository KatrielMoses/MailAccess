"""Phase 2E — W3C PROV-DM export of the evidence chain.

Serializes the 1C observation ledger into the PROV-JSON representation of
PROV-DM: each observation is an **entity**, each run (``activity_id`` + pipeline
+ extraction method + module version) is an **activity**, and each source
(``source_type`` + ``source_url``) is an **agent**. Relations: an entity
``wasGeneratedBy`` its activity, ``wasAttributedTo`` its agent, and the activity
``wasAssociatedWith`` that agent. This makes trust and derivation
machine-readable — the precondition for ever sharing evidence in Phase 6.
"""

from __future__ import annotations

from typing import Any

_NS = "mailaccess"


def _get(obs: Any, key: str) -> Any:
    if isinstance(obs, dict):
        return obs.get(key)
    return getattr(obs, key, None)


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def to_prov(observations: list[Any], *, run_manifest: dict | None = None) -> dict:
    """Build a PROV-JSON document from ledger observations (dicts or ORM rows)."""
    entities: dict[str, dict] = {}
    activities: dict[str, dict] = {}
    agents: dict[str, dict] = {}
    was_generated_by: dict[str, dict] = {}
    was_attributed_to: dict[str, dict] = {}
    was_associated_with: dict[str, dict] = {}

    for i, obs in enumerate(observations):
        oid = str(_get(obs, "id") or f"obs{i}")
        activity_id = str(_get(obs, "activity_id") or "unknown")
        extraction_method = str(_get(obs, "extraction_method") or "unknown")
        module_version = str(_get(obs, "module_version") or "")
        source_type = _get(obs, "source_type") or "unknown"
        source_url = _get(obs, "source_url")

        entity_key = f"{_NS}:observation/{oid}"
        activity_key = f"{_NS}:run/{activity_id}/{extraction_method}"
        agent_key = f"{_NS}:source/{source_type}"

        entities[entity_key] = {
            "prov:type": "mailaccess:Observation",
            "mailaccess:subject_type": _get(obs, "subject_type"),
            "mailaccess:subject": _get(obs, "subject"),
            "mailaccess:claim_key": _get(obs, "claim_key"),
            "mailaccess:content_hash": _get(obs, "content_hash"),
            "mailaccess:capture_time": _iso(_get(obs, "capture_time")),
            "mailaccess:mode": _get(obs, "mode"),
            "mailaccess:policy_status": _get(obs, "source_policy_status"),
        }
        activities[activity_key] = {
            "prov:type": "mailaccess:Run",
            "mailaccess:pipeline": _get(obs, "pipeline"),
            "mailaccess:extraction_method": extraction_method,
            "mailaccess:module_version": module_version,
            "mailaccess:mode": _get(obs, "mode"),
        }
        agents[agent_key] = {
            "prov:type": "prov:SoftwareAgent",
            "mailaccess:source_type": source_type,
            "mailaccess:source_url": source_url,
        }
        was_generated_by[f"_:wGB{i}"] = {"prov:entity": entity_key, "prov:activity": activity_key}
        was_attributed_to[f"_:wAT{i}"] = {"prov:entity": entity_key, "prov:agent": agent_key}
        was_associated_with[f"_:wAW{i}"] = {"prov:activity": activity_key, "prov:agent": agent_key}

    doc: dict[str, Any] = {
        "prefix": {
            _NS: "https://mailaccess.local/prov#",
            "prov": "http://www.w3.org/ns/prov#",
        },
        "entity": entities,
        "activity": activities,
        "agent": agents,
        "wasGeneratedBy": was_generated_by,
        "wasAttributedTo": was_attributed_to,
        "wasAssociatedWith": was_associated_with,
    }
    if run_manifest:
        doc["mailaccess:runManifest"] = run_manifest
    return doc


async def prov_for_subject(subject: str, *, run_manifest: dict | None = None) -> dict:
    """Gather a subject's ledger observations and serialize them to PROV-JSON."""
    from sqlalchemy import select

    from ..db.database import AsyncSessionLocal, init_db
    from ..db.models import Observation

    await init_db()
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(select(Observation).where(Observation.subject == subject))
        ).scalars().all()
    return to_prov(rows, run_manifest=run_manifest)
