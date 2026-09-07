"""Phase 6E — opt-in corpus contribution pipeline (built now, inert until opt-in).

The "gets better every week" mechanic (Doc-2 A3): a user can batch their
public-source-derived, 6B-safe findings and submit them upstream. Like 6D this
is fully built and testable now but **inert** — a contribution is impossible
unless the operator (a) turns the master switch on, (b) explicitly opts in, and
(c) has a concrete sync adapter configured. The hard invariant, enforced by the
6B gate and asserted by the policy suite: **no contact-level data enters a
contribution without explicit human review.**

What is real now:

* **Batching** of only :mod:`safe_artifact`-distributable artifacts (aggregate
  patterns / fingerprints / summaries; contact-level only with per-batch review).
* **License gating** — a batch declares a license from an allowlist of
  contributable bases; anything else is refused.
* **ID hashing** — the contributor identity is stored only as a salted hash,
  never in clear text.
* **Rate limiting** — a per-batch cap and a per-window cap.
* **Audit** — every contribution attempt is written to the 2E tamper-evident
  audit chain, whether or not it is (inertly) blocked from publishing.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..config import settings
from .corpus_distribution import (
    DistributionInactive,
    InertSyncAdapter,
    SyncAdapter,
    content_hash,
    shard_for,
)
from .safe_artifact import Artifact, partition_distributable

logger = logging.getLogger(__name__)

ACTION_CONTRIBUTION = "corpus.contribution"

# Licenses under which a finding may be contributed. A contribution declares one;
# anything outside this allowlist is refused (license-gated).
LICENSE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "public-source-derived",  # derived from lawfully-public business sources
        "user-owned",  # the contributor's own data
        "cc0",
        "public-domain",
        "opt-in-public",
    }
)


def hash_contributor_id(raw: str | None, *, salt: str = "mailaccess-corpus-v1") -> str:
    """Salted SHA-256 of a contributor identity — never stored in clear text."""
    material = f"{salt}:{str(raw or '').strip().lower()}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def within_rate_limit(
    recent_submission_times: list[datetime],
    *,
    now: datetime | None = None,
    max_per_window: int,
    window_seconds: float,
) -> bool:
    """Whether another contribution is allowed given recent submissions. Pure."""
    reference = now or datetime.now(timezone.utc)
    cutoff = reference.timestamp() - float(window_seconds)
    in_window = [t for t in recent_submission_times if t.timestamp() >= cutoff]
    return len(in_window) < int(max_per_window)


@dataclass(frozen=True)
class ContributionEntry:
    kind: str
    key: str
    shard: int
    content_hash: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ContributionBatch:
    batch_id: str
    contributor_hash: str
    created_at: str
    license: str
    entries: list[ContributionEntry]

    @property
    def count(self) -> int:
        return len(self.entries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "contributor_hash": self.contributor_hash,
            "created_at": self.created_at,
            "license": self.license,
            "count": self.count,
            "entries": [
                {"kind": e.kind, "key": e.key, "content_hash": e.content_hash, "shard": e.shard}
                for e in self.entries
            ],
        }


class ContributionRefused(RuntimeError):
    """Raised when a contribution cannot be built (bad license, etc.)."""


def build_contribution_batch(
    artifacts: list[Artifact],
    *,
    contributor_id: str,
    license: str = "public-source-derived",
    reviewed_keys: frozenset[str] | set[str] = frozenset(),
    max_per_batch: int | None = None,
    num_shards: int | None = None,
    created_at: datetime | None = None,
) -> tuple[ContributionBatch, list[tuple[Artifact, str]]]:
    """Batch only the 6B-safe artifacts for contribution. Pure (no I/O).

    Returns ``(batch, rejected)``. The invariant: a contact-level artifact is
    included **only** when its ``key`` is in ``reviewed_keys`` — the 6B gate
    guarantees this, so a raw contact can never enter a batch un-reviewed.
    """
    if str(license).strip().lower() not in LICENSE_ALLOWLIST:
        raise ContributionRefused(
            f"license {license!r} is not contributable; allowed: {sorted(LICENSE_ALLOWLIST)}"
        )
    cap = int(
        max_per_batch
        if max_per_batch is not None
        else settings.corpus_contribution_max_per_batch
    )
    shards = int(num_shards if num_shards is not None else settings.corpus_distribution_shards)

    partition = partition_distributable(artifacts, reviewed_keys=reviewed_keys)
    kept = partition.distributable[: max(0, cap)]
    rejected = list(partition.rejected)
    for extra in partition.distributable[max(0, cap):]:
        rejected.append((extra, "rate-limited: exceeds max_per_batch"))

    entries: list[ContributionEntry] = []
    for artifact in kept:
        kind = artifact.kind.value if hasattr(artifact.kind, "value") else str(artifact.kind)
        entries.append(
            ContributionEntry(
                kind=kind,
                key=artifact.key,
                shard=shard_for(artifact.key, shards),
                content_hash=content_hash(kind, artifact.key, artifact.payload),
                payload=dict(artifact.payload),
            )
        )
    entries.sort(key=lambda e: (e.shard, e.content_hash))

    contributor_hash = hash_contributor_id(contributor_id)
    created = (created_at or datetime.now(timezone.utc)).isoformat()
    batch_id = hashlib.sha256(
        (contributor_hash + created + "".join(e.content_hash for e in entries)).encode("utf-8")
    ).hexdigest()[:32]

    batch = ContributionBatch(
        batch_id=batch_id,
        contributor_hash=contributor_hash,
        created_at=created,
        license=str(license).strip().lower(),
        entries=entries,
    )
    return batch, rejected


def is_contribution_active(adapter: SyncAdapter | None = None) -> bool:
    """True only when the master switch is on AND a concrete adapter is set."""
    if not getattr(settings, "enable_corpus_contribution", False):
        return False
    return adapter is not None and not isinstance(adapter, InertSyncAdapter)


async def submit_contribution(
    batch: ContributionBatch,
    *,
    opt_in: bool,
    adapter: SyncAdapter | None = None,
    recent_submission_times: list[datetime] | None = None,
) -> None:
    """Submit a batch upstream — refused unless explicitly opted in and active.

    Always writes a contribution event to the 2E audit chain (even when the
    attempt is inertly blocked, so the attempt is recorded), then refuses to
    publish unless: opt-in is explicit, the master switch is on, a concrete
    adapter is configured, and the per-window rate limit allows it.
    """
    active = bool(opt_in) and is_contribution_active(adapter)
    # Audit the attempt first (guarded) — a contribution event is always recorded.
    try:
        from . import audit_log

        await audit_log.append(
            ACTION_CONTRIBUTION,
            subject=batch.batch_id,
            details={
                "count": batch.count,
                "license": batch.license,
                "contributor_hash": batch.contributor_hash,
                "opt_in": bool(opt_in),
                "active": active,
            },
        )
    except Exception:
        logger.debug("contribution audit append unavailable", exc_info=True)

    if not opt_in:
        raise DistributionInactive("contribution requires explicit opt-in (opt_in=False)")
    if not getattr(settings, "enable_corpus_contribution", False):
        raise DistributionInactive(
            "corpus contribution master switch is off (enable_corpus_contribution=False)"
        )
    if adapter is None or isinstance(adapter, InertSyncAdapter):
        raise DistributionInactive(
            "no concrete sync adapter is configured — contribution is inert"
        )
    if recent_submission_times is not None and not within_rate_limit(
        recent_submission_times,
        max_per_window=int(settings.corpus_contribution_max_per_window),
        window_seconds=float(settings.corpus_contribution_window_seconds),
    ):
        raise DistributionInactive("contribution rate limit exceeded for the current window")

    from .corpus_distribution import CorpusDelta

    # Reaching here means the operator has explicitly activated contribution with
    # a real transport. Package the batch as a single-parent manifest+delta so the
    # adapter's publish contract is identical to 6D distribution.
    manifest = _batch_as_manifest(batch)
    delta = CorpusDelta(
        parent_hash=None,
        current_hash=manifest.manifest_hash,
        added=list(manifest.entries),
        changed=[],
        removed=[],
    )
    await adapter.publish(manifest, delta)


def _batch_as_manifest(batch: ContributionBatch) -> Any:
    from .corpus_distribution import ArtifactEntry, build_manifest
    from .safe_artifact import ArtifactKind

    artifacts = [
        Artifact(kind=ArtifactKind(e.kind), key=e.key, payload=e.payload) for e in batch.entries
    ]
    manifest, _rejected = build_manifest(artifacts)
    # Entries are already 6B-safe by construction of the batch.
    assert all(isinstance(e, ArtifactEntry) for e in manifest.entries)
    return manifest
