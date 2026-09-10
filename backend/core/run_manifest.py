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


def config_fingerprint(mode: str | None = None) -> str:
    payload = {key: getattr(settings, key, None) for key in _FINGERPRINT_KEYS}
    # RC6 (Output-Trust): the fingerprint must reflect THIS RUN's product mode, not
    # the config default — otherwise two harvests with different --mode produce an
    # identical fingerprint (the tamper-evident record would be wrong).
    if mode is not None:
        payload["product_mode"] = mode
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
        # RC6: fingerprint the RUN's mode so different --mode runs differ.
        "config_fingerprint": config_fingerprint(mode=mode),
        "module_versions": {"app": APP_VERSION},
        "source_policy": mode,
        "seed": seed or run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


async def read_run_manifest(run_id: str, session: object | None = None) -> dict | None:
    """R12 (S1) — the RECORDED manifest for a run, as a watermark dict.

    The export watermark must reflect the run that actually produced the report
    (its original time, app version, corpus version, config fingerprint), not the
    current process/time. Returns None if no manifest was recorded (caller then
    falls back to a freshly generated one). Guarded → None on error.
    """
    from sqlalchemy import desc, select

    async def _query(s: object) -> dict | None:
        row = (
            await s.execute(  # type: ignore[attr-defined]
                select(RunManifest)
                .where(RunManifest.run_id == run_id)
                .order_by(desc(RunManifest.created_at))
                .limit(1)
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        return {
            "run_id": row.run_id,
            "pipeline": row.pipeline,
            "mode": row.mode,
            "app_version": row.app_version,
            "config_fingerprint": row.config_fingerprint,
            "module_versions": row.module_versions or {"app": row.app_version},
            "source_policy": row.source_policy or row.mode,
            "corpus_version": row.corpus_version,
            "seed": row.seed or row.run_id,
            # The run's own record time — NOT wall-clock now.
            "generated_at": row.created_at.isoformat()
            if isinstance(row.created_at, datetime)
            else None,
            "recorded": True,
        }

    try:
        if session is not None:
            return await _query(session)
        await init_db()
        async with AsyncSessionLocal() as owned:
            return await _query(owned)
    except Exception:
        logger.exception("run manifest read failed for %s", run_id)
        return None


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
