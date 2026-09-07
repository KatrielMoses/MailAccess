"""Phase 4A — ground-truth & feature capture for self-calibrating scoring.

Turns every deliverability score into a future training example. The moment the
hand-tuned scorer produces a score, the exact feature vector that produced it is
snapshotted **immutably** (:class:`~backend.db.models.ScoreFeatureSnapshot`).
When an objective outcome later becomes known — an SMTP/provider verdict, a
corpus re-verification, or a filled human truth label — it is attached as a NEW
linked row (:class:`~backend.db.models.ScoreOutcomeLabel`); the snapshot is never
mutated. Together they are the substrate the Phase-4B trainer learns from.

Design decisions (exploration latitude in the brief):

* **Feature set** — exactly the ``features`` dict the 3C ``compute_deliverability_score``
  already emits (MX / SPF / DMARC / provider / disposable / role / corpus history
  + the raw logit). No parallel feature taxonomy is invented; the capture stays
  in lock-step with the live scorer's inputs.
* **Join key** — the snapshot ``id`` is the primary link (an outcome known in the
  same pass attaches by id). For an outcome that arrives in a *later* run, the
  denormalized ``(subject, content_hash)`` natural key resolves the matching
  snapshot: ``content_hash`` is a deterministic fingerprint of the feature vector
  (volatile keys stripped), so identical evidence matches identically across runs.
* **Governance** — capture obeys the same policy/retention as the 1C ledger: every
  snapshot carries its collection ``mode``, the derived ``source_policy_status``,
  and an ``expires_at`` from ``ledger_default_ttl_days``. No raw PII beyond the
  ``subject`` email the ledger/corpus already retain.

Fully guarded: a capture failure can never break a harvest. Nothing here trains
or serves a model — that is 4B/4D.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import settings

logger = logging.getLogger(__name__)

# Feature keys that vary run-to-run without changing what the features *assert*.
# Stripped before hashing so the same evidence fingerprints identically. The raw
# logit is derived from the substantive features, so it is excluded too (it would
# otherwise make the hash redundant with, and more brittle than, the features).
_VOLATILE_FEATURE_KEYS = frozenset({"logit"})

# Outcome status vocabulary → 0/1 training label. Mirrors the 3C history signal
# semantics so labels are consistent with what the scorer already treats as
# positive/negative evidence. Unknown/missing → None (captured, but unlabelled).
_POSITIVE_OUTCOMES = frozenset({"verified", "deliverable", "valid"})
_NEGATIVE_OUTCOMES = frozenset({"not_found", "bounced", "invalid", "no_mx", "undeliverable"})


def outcome_to_label(outcome: str | None) -> float | None:
    """Map an objective outcome status to a 0/1 Brier/training label, or None."""
    status = str(outcome or "").strip().lower()
    if status in _POSITIVE_OUTCOMES:
        return 1.0
    if status in _NEGATIVE_OUTCOMES:
        return 0.0
    return None


def _strip_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: _strip_volatile(v)
            for k, v in value.items()
            if k not in _VOLATILE_FEATURE_KEYS
        }
    if isinstance(value, list | tuple):
        return [_strip_volatile(v) for v in value]
    return value


def feature_content_hash(features: dict[str, Any], model_version: str) -> str:
    """Deterministic sha256 of a feature vector (volatile keys stripped).

    Stable across re-runs, so an outcome arriving later can be matched to the
    exact evidence that produced the score."""
    core = {"model_version": model_version, "features": _strip_volatile(features)}
    canonical = json.dumps(
        core, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _expiry(now: datetime) -> datetime | None:
    ttl = settings.ledger_default_ttl_days
    if ttl and ttl > 0:
        return now + timedelta(days=ttl)
    return None


def _policy_status_for_mode(mode: str) -> str:
    from .product_mode import policy_status_for_mode

    try:
        return policy_status_for_mode(mode)
    except Exception:
        return "unreviewed"


def build_snapshot_record(
    *,
    subject: str,
    subject_domain: str | None,
    activity_id: str,
    features: dict[str, Any],
    hand_score: float,
    model_version: str,
    pipeline: str = "harvest",
    mode: str = "security-investigation",
    captured_at: datetime | None = None,
) -> dict[str, Any]:
    """Assemble one immutable feature-snapshot row (as a dict of column values)."""
    now = captured_at or datetime.now(timezone.utc)
    return {
        "pipeline": pipeline,
        "activity_id": activity_id,
        "subject": subject,
        "subject_domain": subject_domain,
        "model_version": model_version,
        "features": features,
        "hand_score": float(hand_score),
        "content_hash": feature_content_hash(features, model_version),
        "mode": mode,
        "source_policy_status": _policy_status_for_mode(mode),
        "expires_at": _expiry(now),
        "created_at": now,
    }


async def capture_score(
    *,
    subject: str,
    subject_domain: str | None,
    activity_id: str,
    features: dict[str, Any],
    hand_score: float,
    model_version: str,
    pipeline: str = "harvest",
    mode: str = "security-investigation",
    known_outcome: str | None = None,
) -> str | None:
    """Persist a feature snapshot (and, when supplied, its objective outcome).

    Returns the new snapshot id, or ``None`` when capture is disabled or fails.
    Never raises — the capture must never be able to break the pipeline that
    feeds it. When ``known_outcome`` is given it is attached in the same
    transaction as a linked outcome row (a corpus re-verification available at
    scoring time is a free label)."""
    if not getattr(settings, "enable_scoring_capture", True):
        return None
    try:
        from ..db.database import AsyncSessionLocal
        from ..db.models import ScoreFeatureSnapshot, ScoreOutcomeLabel

        record = build_snapshot_record(
            subject=subject,
            subject_domain=subject_domain,
            activity_id=activity_id,
            features=features,
            hand_score=hand_score,
            model_version=model_version,
            pipeline=pipeline,
            mode=mode,
        )
        async with AsyncSessionLocal() as session:
            async with session.begin():
                snapshot = ScoreFeatureSnapshot(**record)
                session.add(snapshot)
                await session.flush()  # populate snapshot.id
                snapshot_id = snapshot.id
                label = outcome_to_label(known_outcome)
                if known_outcome is not None:
                    session.add(
                        ScoreOutcomeLabel(
                            snapshot_id=snapshot_id,
                            subject=subject,
                            content_hash=record["content_hash"],
                            outcome=str(known_outcome),
                            label=label,
                            label_source="corpus",
                            evidence={"captured_with_score": True},
                        )
                    )
        return snapshot_id
    except Exception:
        logger.debug("scoring capture skipped", exc_info=True)
        return None


async def capture_batch(records: list[dict[str, Any]]) -> int:
    """Persist many feature snapshots (+ optional known outcomes) in one txn.

    Each item is the kwargs of :func:`capture_score` (``subject``,
    ``subject_domain``, ``activity_id``, ``features``, ``hand_score``,
    ``model_version``, and optionally ``pipeline`` / ``mode`` / ``known_outcome``).
    Used by the harvest deliverability pass, which scores every lead in a loop —
    one transaction beats one-per-email. Returns the number of snapshots written
    (0 on any failure or when disabled). Never raises."""
    if not records or not getattr(settings, "enable_scoring_capture", True):
        return 0
    try:
        from ..db.database import AsyncSessionLocal
        from ..db.models import ScoreFeatureSnapshot, ScoreOutcomeLabel

        written = 0
        async with AsyncSessionLocal() as session:
            async with session.begin():
                for item in records:
                    known_outcome = item.get("known_outcome")
                    row = build_snapshot_record(
                        subject=item["subject"],
                        subject_domain=item.get("subject_domain"),
                        activity_id=item["activity_id"],
                        features=item["features"],
                        hand_score=item["hand_score"],
                        model_version=item["model_version"],
                        pipeline=item.get("pipeline", "harvest"),
                        mode=item.get("mode", "security-investigation"),
                    )
                    snapshot = ScoreFeatureSnapshot(**row)
                    session.add(snapshot)
                    if known_outcome is not None:
                        await session.flush()
                        session.add(
                            ScoreOutcomeLabel(
                                snapshot_id=snapshot.id,
                                subject=item["subject"],
                                content_hash=row["content_hash"],
                                outcome=str(known_outcome),
                                label=outcome_to_label(known_outcome),
                                label_source="corpus",
                                evidence={"captured_with_score": True},
                            )
                        )
                    written += 1
        return written
    except Exception:
        logger.debug("scoring capture batch skipped", exc_info=True)
        return 0


async def attach_outcome(
    *,
    subject: str,
    outcome: str,
    label_source: str,
    content_hash: str | None = None,
    snapshot_id: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> str | None:
    """Attach an objective outcome to a captured snapshot as a NEW linked row.

    The snapshot is resolved by ``snapshot_id`` when known, else by the most
    recent snapshot matching ``(subject, content_hash)`` — or ``subject`` alone
    when no hash is supplied. Never mutates the snapshot; returns the new label
    row id, or ``None`` if capture is disabled, no snapshot matches, or it fails.
    """
    if not getattr(settings, "enable_scoring_capture", True):
        return None
    try:
        from sqlalchemy import desc, select

        from ..db.database import AsyncSessionLocal
        from ..db.models import ScoreFeatureSnapshot, ScoreOutcomeLabel

        norm_subject = str(subject).strip()
        async with AsyncSessionLocal() as session:
            async with session.begin():
                resolved_id = snapshot_id
                resolved_hash = content_hash
                if resolved_id is None:
                    conditions = [ScoreFeatureSnapshot.subject == norm_subject]
                    if content_hash:
                        conditions.append(ScoreFeatureSnapshot.content_hash == content_hash)
                    snap = (
                        await session.execute(
                            select(ScoreFeatureSnapshot)
                            .where(*conditions)
                            .order_by(desc(ScoreFeatureSnapshot.created_at))
                            .limit(1)
                        )
                    ).scalars().first()
                    if snap is None:
                        return None
                    resolved_id = snap.id
                    resolved_hash = resolved_hash or snap.content_hash
                row = ScoreOutcomeLabel(
                    snapshot_id=resolved_id,
                    subject=norm_subject,
                    content_hash=resolved_hash,
                    outcome=str(outcome),
                    label=outcome_to_label(outcome),
                    label_source=str(label_source),
                    evidence=evidence,
                )
                session.add(row)
                await session.flush()
                return row.id
    except Exception:
        logger.debug("scoring outcome attach skipped", exc_info=True)
        return None


async def load_training_examples(
    *,
    model_version: str | None = None,
    labelled_only: bool = True,
    limit: int = 100_000,
) -> list[dict[str, Any]]:
    """Join snapshots to their outcome labels for the Phase-4B trainer.

    Returns one example per (snapshot, outcome) with a non-null label — the
    positive/negative training rows — as plain dicts::

        {subject, subject_domain, features, hand_score, model_version,
         label, outcome, label_source}

    When ``labelled_only`` is False, snapshots with no label are also returned
    (label=None) for coverage/telemetry. Guarded → [] on failure."""
    try:
        from sqlalchemy import select

        from ..db.database import AsyncSessionLocal
        from ..db.models import ScoreFeatureSnapshot, ScoreOutcomeLabel

        out: list[dict[str, Any]] = []
        async with AsyncSessionLocal() as session:
            stmt = select(ScoreFeatureSnapshot)
            if model_version:
                stmt = stmt.where(ScoreFeatureSnapshot.model_version == model_version)
            stmt = stmt.limit(max(1, int(limit)))
            snapshots = (await session.execute(stmt)).scalars().all()
            snap_ids = [s.id for s in snapshots]
            labels_by_snap: dict[str, list[ScoreOutcomeLabel]] = {}
            if snap_ids:
                label_rows = (
                    await session.execute(
                        select(ScoreOutcomeLabel).where(
                            ScoreOutcomeLabel.snapshot_id.in_(snap_ids)
                        )
                    )
                ).scalars().all()
                for lr in label_rows:
                    labels_by_snap.setdefault(lr.snapshot_id, []).append(lr)

        for snap in snapshots:
            labels = labels_by_snap.get(snap.id, [])
            # A snapshot can accrue multiple outcomes over time; the most recent
            # labelled one is the training target.
            labelled = [lo for lo in labels if lo.label is not None]
            if labelled:
                latest = max(labelled, key=lambda lo: lo.created_at)
                out.append(
                    {
                        "subject": snap.subject,
                        "subject_domain": snap.subject_domain,
                        "features": snap.features,
                        "hand_score": snap.hand_score,
                        "model_version": snap.model_version,
                        "label": float(latest.label),
                        "outcome": latest.outcome,
                        "label_source": latest.label_source,
                    }
                )
            elif not labelled_only:
                out.append(
                    {
                        "subject": snap.subject,
                        "subject_domain": snap.subject_domain,
                        "features": snap.features,
                        "hand_score": snap.hand_score,
                        "model_version": snap.model_version,
                        "label": None,
                        "outcome": None,
                        "label_source": None,
                    }
                )
        return out
    except Exception:
        logger.debug("load_training_examples failed", exc_info=True)
        return []
