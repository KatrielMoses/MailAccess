"""Phase 2E — the reproducible run manifest.

Persisted with every result so a run can be reproduced and audited: config
version, module versions, source policy (mode), corpus version and run seed.
Also the source of the export **watermark** and the activity record the W3C PROV
export builds on.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import text

from ..config import APP_VERSION, settings
from ..db.database import AsyncSessionLocal, init_db
from ..db.models import RunManifest
from . import audit_log

logger = logging.getLogger(__name__)

# Config keys whose values define a run's behavior — hashed (never stored raw,
# so secrets never leak) into a stable fingerprint.
_FINGERPRINT_KEYS = (
    "product_mode",
    "eligibility_confidence_threshold_public",
    "eligibility_confidence_threshold_org",
    "eligibility_review_floor",
    "ledger_default_ttl_days",
    "enable_observation_ledger",
    "investigation_budget_seconds",
    "harvest_timing_profile",
)


def config_fingerprint() -> str:
    payload = {key: getattr(settings, key, None) for key in _FINGERPRINT_KEYS}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


async def _corpus_version() -> str | None:
    """The DB schema/corpus version (the current Alembic revision)."""
    try:
        async with AsyncSessionLocal() as session:
            row = (await session.execute(text("SELECT version_num FROM alembic_version"))).first()
            return str(row[0]) if row else None
    except Exception:
        return None


def manifest_dict(
    *, run_id: str, pipeline: str, mode: str, seed: str | None = None
) -> dict:
    """The manifest as a plain dict (no DB) — used for the export watermark."""
    return {
        "run_id": run_id,
        "pipeline": pipeline,
        "mode": mode,
        "app_version": APP_VERSION,
        "config_fingerprint": config_fingerprint(),
        "module_versions": {"app": APP_VERSION},
        "source_policy": mode,
        "seed": seed or run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


async def record_run_manifest(
    *, run_id: str, pipeline: str, mode: str, seed: str | None = None
) -> dict:
    """Persist the run manifest and audit the collection. Guarded — a manifest
    failure never breaks the run that produced the result."""
    data = manifest_dict(run_id=run_id, pipeline=pipeline, mode=mode, seed=seed)
    try:
        await init_db()
        corpus_version = await _corpus_version()
        data["corpus_version"] = corpus_version
        async with AsyncSessionLocal() as session:
            async with session.begin():
                session.add(
                    RunManifest(
                        run_id=run_id,
                        pipeline=pipeline,
                        mode=mode,
                        app_version=APP_VERSION,
                        config_fingerprint=data["config_fingerprint"],
                        module_versions=data["module_versions"],
                        source_policy=mode,
                        corpus_version=corpus_version,
                        seed=data["seed"],
                    )
                )
        await audit_log.append(
            audit_log.ACTION_COLLECTION,
            subject=run_id,
            details={"pipeline": pipeline, "mode": mode, "config": data["config_fingerprint"]},
        )
    except Exception:
        logger.exception("run manifest record failed for %s", run_id)
    return data
