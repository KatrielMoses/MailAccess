"""Phase 1C — canonical evidence ledger writer.

Turns the loosely-typed findings both pipelines already produce into immutable,
provenance-complete :class:`~backend.db.models.Observation` rows. This module
only *writes* the ledger (dual-write, alongside the existing outputs); making the
report/export *read* from it is Phase 1D.

Design decisions (exploration latitude in the brief):

* **Content hash** — sha256 of a canonical JSON of the observation's evidentiary
  core ``(subject_type, subject, source_type, source_url, extraction_method,
  claim)``, with volatile/run-specific keys (timestamps, latencies, ids) stripped
  from the claim first. Deterministic, so identical evidence hashes identically
  across re-runs. When raw evidence bytes are supplied and raw storage is on, the
  bytes themselves are hashed instead.
* **Module version** — a module may declare a ``version`` class attribute;
  otherwise the package version (``APP_VERSION``) is used, since modules ship as
  one versioned package.
* **Identity / dedup** — the ledger is append-only, so writes are never deduped:
  a re-observation is a new row (same ``content_hash``, new ``id``). ``claim_key``
  + ``content_hash`` are indexed for later lookup/collation.
* **Source vocabulary** — ``source_type`` is read from the finding's own existing
  fields (the ``SOURCE_WEIGHTS`` vocabulary / module source labels); no parallel
  taxonomy is invented here.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import APP_VERSION, settings
from ..modules.base import ModuleResult

logger = logging.getLogger(__name__)

# Keys stripped from a claim before hashing: run-specific / volatile fields that
# do not change what the evidence *asserts* but do vary run-to-run. Everything
# else (platform, url, username, http status codes, category, …) is substantive
# and kept, so a genuine change in the evidence changes the hash.
_VOLATILE_CLAIM_KEYS = frozenset(
    {
        "timestamp",
        "timestamps",
        "captured_at",
        "capture_time",
        "checked_at",
        "fetched_at",
        "retrieved_at",
        "as_of",
        "first_seen",
        "last_seen",
        "first_seen_timestamp",
        "last_seen_timestamp",
        "created_at",
        "updated_at",
        "run_id",
        "investigation_id",
        "elapsed",
        "elapsed_seconds",
        "duration",
        "duration_seconds",
        "latency",
        "latency_ms",
        "response_time_ms",
        "took_ms",
    }
)

_SOURCE_TYPE_KEYS = ("source_type", "source", "provider")
_SOURCE_URL_KEYS = ("source_url", "profile_url", "url", "html_url", "link", "page_url")
_CLAIM_KEY_KEYS = ("email", "profile_url", "url", "username", "platform", "value", "handle")


def module_version(module_name: str, obj: Any | None = None) -> str:
    """A module's version — its declared ``version`` attr, else the package version."""
    version = getattr(obj, "version", None) if obj is not None else None
    return str(version) if version else APP_VERSION


def _first(data: dict, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_source_type(data: dict) -> str | None:
    direct = _first(data, _SOURCE_TYPE_KEYS)
    if direct:
        return direct
    meta = data.get("metadata")
    if isinstance(meta, dict):
        return _first(meta, _SOURCE_TYPE_KEYS)
    return None


def _extract_source_url(data: dict) -> str | None:
    direct = _first(data, _SOURCE_URL_KEYS)
    if direct:
        return direct
    meta = data.get("metadata")
    if isinstance(meta, dict):
        return _first(meta, _SOURCE_URL_KEYS)
    return None


def _extract_claim_key(data: dict) -> str | None:
    return _first(data, _CLAIM_KEY_KEYS)


def _strip_volatile(value: Any) -> Any:
    """Recursively drop volatile keys and normalize for a stable hash."""
    if isinstance(value, dict):
        return {
            k: _strip_volatile(v)
            for k, v in value.items()
            if k not in _VOLATILE_CLAIM_KEYS
        }
    if isinstance(value, list | tuple):
        return [_strip_volatile(v) for v in value]
    return value


def content_hash(
    *,
    subject_type: str,
    subject: str,
    source_type: str | None,
    source_url: str | None,
    extraction_method: str,
    claim: Any,
    raw_payload: bytes | None = None,
) -> str:
    """Stable sha256 of the evidence. Hashes raw bytes when supplied, else the
    canonical evidentiary core (volatile claim fields stripped)."""
    if raw_payload is not None:
        return hashlib.sha256(raw_payload).hexdigest()
    core = {
        "subject_type": subject_type,
        "subject": subject,
        "source_type": source_type,
        "source_url": source_url,
        "extraction_method": extraction_method,
        "claim": _strip_volatile(claim),
    }
    canonical = json.dumps(
        core, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _policy_status_for_mode(mode: str) -> str:
    # Defensive wrapper — a malformed stored mode must never break a ledger write.
    from .product_mode import policy_status_for_mode

    try:
        return policy_status_for_mode(mode)
    except Exception:
        return "unreviewed"


def _expiry(capture_time: datetime) -> datetime | None:
    ttl = settings.ledger_default_ttl_days
    if ttl and ttl > 0:
        return capture_time + timedelta(days=ttl)
    return None


def build_observation(
    *,
    pipeline: str,
    activity_id: str,
    subject_type: str,
    subject: str,
    extraction_method: str,
    claim: dict,
    captured_at: datetime,
    mode: str = "security-investigation",
    module_obj: Any | None = None,
    raw_payload: bytes | None = None,
    media_type: str | None = None,
) -> dict[str, Any]:
    """Assemble one provenance-complete observation record (as a dict of column
    values, plus optional private ``_raw_*`` keys consumed by the writer).

    ``mode`` is the Phase-2B collection product mode; it is stamped onto every
    observation so a fact's collection mode is always known. ``content_hash``
    deliberately excludes ``mode`` — the same evidence hashes identically
    regardless of the mode it was collected under.
    """
    source_type = _extract_source_type(claim)
    source_url = _extract_source_url(claim)
    record: dict[str, Any] = {
        "pipeline": pipeline,
        "activity_id": activity_id,
        "extraction_method": extraction_method,
        "module_version": module_version(extraction_method, module_obj),
        "subject_type": subject_type,
        "subject": subject,
        "claim": claim,
        "claim_key": _extract_claim_key(claim),
        "source_type": source_type,
        "source_url": source_url,
        "capture_time": captured_at,
        "content_hash": content_hash(
            subject_type=subject_type,
            subject=subject,
            source_type=source_type,
            source_url=source_url,
            extraction_method=extraction_method,
            claim=claim,
            raw_payload=raw_payload,
        ),
        "mode": mode,
        # Phase 2C — the lawful basis of this observation, derived from its
        # collection mode (the dispatch gate ensures only mode-appropriate
        # sources ran). Security stays "unreviewed"; 2D's eligibility reads this.
        "source_policy_status": _policy_status_for_mode(mode),
        "expires_at": _expiry(captured_at),
    }
    if raw_payload is not None:
        record["_raw_payload"] = raw_payload
        record["_media_type"] = media_type
    return record


def observations_from_results(
    *,
    pipeline: str,
    activity_id: str,
    subject: str,
    subject_type: str,
    results: dict[str, ModuleResult],
    captured_at: datetime | None = None,
    mode: str = "security-investigation",
) -> list[dict[str, Any]]:
    """One observation per finding across a ``{module: ModuleResult}`` map.

    Used by the investigate path (the engine's collected results) and available
    to any harvest caller that has the same raw ``module_results`` shape.
    """
    when = captured_at or datetime.now(timezone.utc)
    observations: list[dict[str, Any]] = []
    for module_name, result in results.items():
        findings = getattr(result, "findings", None) or []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            observations.append(
                build_observation(
                    pipeline=pipeline,
                    activity_id=activity_id,
                    subject_type=subject_type,
                    subject=subject,
                    extraction_method=module_name,
                    claim=finding,
                    captured_at=when,
                    mode=mode,
                )
            )
    return observations


def observations_from_harvest(
    domain: str,
    harvest_result: Any,
    *,
    captured_at: datetime | None = None,
    mode: str = "security-investigation",
) -> list[dict[str, Any]]:
    """One observation per (email, evidence-source) pair from a harvest result.

    The subject is the harvested ``domain``; each observation asserts a
    discovered email address and the source that yielded it, so provenance is
    per-source rather than per-aggregated-email.
    """
    when = captured_at or datetime.now(timezone.utc)
    observations: list[dict[str, Any]] = []
    for entry in getattr(harvest_result, "unique_emails", None) or []:
        email = getattr(entry, "email", None)
        if not isinstance(email, str) or not email:
            continue
        evidence_items = getattr(entry, "evidence", None) or []
        if not evidence_items:
            # No per-source evidence retained — still record the aggregated claim
            # so the email is provenance-tracked, attributed to its modules.
            for module_name in getattr(entry, "found_by_modules", None) or ["harvest"]:
                observations.append(
                    build_observation(
                        pipeline="harvest",
                        activity_id=domain,
                        subject_type="domain",
                        subject=domain,
                        extraction_method=str(module_name),
                        claim={
                            "email": email,
                            "confidence": getattr(entry, "confidence_label", None),
                            "on_domain": getattr(entry, "on_domain", None),
                        },
                        captured_at=when,
                        mode=mode,
                    )
                )
            continue
        for item in evidence_items:
            if not isinstance(item, dict):
                continue
            module_name = str(item.get("module") or "harvest")
            meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            claim = {"email": email, **meta}
            observations.append(
                build_observation(
                    pipeline="harvest",
                    activity_id=domain,
                    subject_type="domain",
                    subject=domain,
                    extraction_method=module_name,
                    claim=claim,
                    captured_at=when,
                    mode=mode,
                )
            )
    return observations


async def record_observations(records: list[dict[str, Any]]) -> int:
    """Persist observation records into the ledger (its own transaction).

    Fully guarded by callers; returns the number written (0 on any failure or
    when the ledger is disabled). Never raises — the ledger must never be able to
    break the pipeline that feeds it.
    """
    if not records or not settings.enable_observation_ledger:
        return 0
    try:
        from ..db.database import AsyncSessionLocal
        from ..db.models import Observation, ObservationRawPayload

        store_raw = settings.ledger_store_raw_payloads
        async with AsyncSessionLocal() as session:
            async with session.begin():
                for record in records:
                    raw_payload = record.pop("_raw_payload", None)
                    media_type = record.pop("_media_type", None)
                    observation = Observation(**record)
                    session.add(observation)
                    if store_raw and raw_payload is not None:
                        await session.flush()
                        session.add(
                            ObservationRawPayload(
                                observation_id=observation.id,
                                content_hash=observation.content_hash,
                                media_type=media_type,
                                payload=raw_payload,
                                expires_at=observation.expires_at,
                            )
                        )
        return len(records)
    except Exception:
        logger.exception("Observation ledger write failed (%d records dropped)", len(records))
        return 0
