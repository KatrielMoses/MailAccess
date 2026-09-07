"""Phase 6D — federated corpus distribution machinery (built now, inert until activated).

This is the transport-agnostic core for shipping the shared corpus as signed,
delta-based, domain-hash-sharded updates (Doc-2 A2, Doc-1 #15). Everything here
is built and testable now, but **nothing publishes**: the concrete network
transport is left unimplemented behind a :class:`SyncAdapter` interface, the
master switch defaults off, and :meth:`CorpusDistributor.publish` refuses unless
explicitly activated. Only 6B-safe artifacts are ever eligible.

What is real now:

* **Artifact format** — a canonical, content-hashed entry per artifact.
* **Signing / verification** — a detached signature over the canonical manifest
  via a pluggable :class:`Signer` (HMAC-SHA256 today, pure-stdlib so it runs in
  the keyless gate env; an Ed25519 signer drops in behind the same interface).
* **Domain-hash sharding** — each artifact lands in one of ``num_shards`` buckets
  by ``sha256(key)`` so a consumer can sync only the shards it cares about.
* **Delta computation** — added / changed / removed vs a parent manifest, so an
  update ships only what changed and is rollback-safe (each manifest names its
  parent; rollback = revert to the parent manifest).
* **Eligibility gate** — only :mod:`safe_artifact`-distributable artifacts are
  included; contact-level artifacts require explicit per-batch review.

What is deliberately NOT real: a concrete sync adapter (R2 / Oracle / GitHub
Releases / Hetzner origin) — that waits on the infra decision. The default
adapter is inert and records that nothing left.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..config import settings
from .safe_artifact import Artifact, partition_distributable

logger = logging.getLogger(__name__)

DISTRIBUTION_FORMAT_VERSION = 1


class DistributionInactive(RuntimeError):
    """Raised if a publish is attempted while the machinery is inert."""


# ---------------------------------------------------------------------------
# Canonical hashing + signing.
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def content_hash(kind: str, key: str, payload: dict[str, Any]) -> str:
    """Deterministic content hash of one artifact (format-versioned)."""
    canonical = _canonical(
        {"v": DISTRIBUTION_FORMAT_VERSION, "kind": str(kind), "key": key, "payload": payload}
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def shard_for(key: str, num_shards: int) -> int:
    """Stable domain-hash shard for a key in ``[0, num_shards)``."""
    n = max(1, int(num_shards))
    digest = hashlib.sha256(str(key).encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % n


class Signer(ABC):
    """Pluggable detached-signature signer (HMAC today, Ed25519 later)."""

    key_id: str

    @abstractmethod
    def sign(self, data: bytes) -> str: ...

    @abstractmethod
    def verify(self, data: bytes, signature: str) -> bool: ...


class HmacSigner(Signer):
    """HMAC-SHA256 detached signatures — pure stdlib, symmetric key."""

    def __init__(self, secret: bytes | str, key_id: str = "hmac-sha256") -> None:
        self._secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        self.key_id = key_id

    def sign(self, data: bytes) -> str:
        return hmac.new(self._secret, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature: str) -> bool:
        expected = self.sign(data)
        return hmac.compare_digest(expected, str(signature or ""))


def _default_signing_secret() -> str:
    """The configured signing secret, else a locally-generated persistent key.

    Never a network secret; used only to prove a bundle was produced locally and
    was not tampered with in transit. Kept out of the repo.
    """
    configured = getattr(settings, "corpus_signing_key", None)
    if configured:
        return str(configured)
    from pathlib import Path

    key_path = Path.home() / ".mailaccess" / "corpus" / "signing.key"
    try:
        if key_path.exists():
            return key_path.read_text(encoding="utf-8").strip()
        import secrets

        generated = secrets.token_hex(32)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(generated, encoding="utf-8")
        return generated
    except Exception:
        # A local key-file failure must not break bundle building in tests/CI;
        # fall back to a process-stable ephemeral secret.
        logger.debug("corpus signing key file unavailable; using ephemeral", exc_info=True)
        return "ephemeral-corpus-signing-secret"


def default_signer() -> Signer:
    return HmacSigner(_default_signing_secret())


# ---------------------------------------------------------------------------
# Manifest + delta.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArtifactEntry:
    kind: str
    key: str
    shard: int
    content_hash: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CorpusManifest:
    """A signed, sharded set of distributable artifacts."""

    format_version: int
    created_at: str
    parent_hash: str | None
    num_shards: int
    entries: list[ArtifactEntry]
    manifest_hash: str
    signature: str
    key_id: str

    def shard_ids(self) -> set[int]:
        return {e.shard for e in self.entries}

    def entries_for_shard(self, shard: int) -> list[ArtifactEntry]:
        return [e for e in self.entries if e.shard == shard]

    def content_hashes(self) -> set[str]:
        return {e.content_hash for e in self.entries}

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "created_at": self.created_at,
            "parent_hash": self.parent_hash,
            "num_shards": self.num_shards,
            "entries": [e.to_dict() for e in self.entries],
            "manifest_hash": self.manifest_hash,
            "signature": self.signature,
            "key_id": self.key_id,
        }


def _manifest_signing_bytes(
    *, created_at: str, parent_hash: str | None, num_shards: int, entries: list[ArtifactEntry]
) -> bytes:
    body = {
        "format_version": DISTRIBUTION_FORMAT_VERSION,
        "created_at": created_at,
        "parent_hash": parent_hash,
        "num_shards": num_shards,
        # Order-independent: entries identified by their content hashes.
        "entries": sorted(e.content_hash for e in entries),
    }
    return _canonical(body).encode("utf-8")


def build_manifest(
    artifacts: list[Artifact],
    *,
    parent_hash: str | None = None,
    reviewed_keys: frozenset[str] | set[str] = frozenset(),
    signer: Signer | None = None,
    num_shards: int | None = None,
    created_at: datetime | None = None,
) -> tuple[CorpusManifest, list[tuple[Artifact, str]]]:
    """Build a signed, sharded manifest of the **distributable** artifacts.

    Returns ``(manifest, rejected)`` where ``rejected`` lists every artifact that
    was excluded and why (unsafe, contact-level-without-review, PII-in-payload).
    Building a manifest does **not** publish anything.
    """
    signer = signer or default_signer()
    shards = int(num_shards if num_shards is not None else settings.corpus_distribution_shards)
    partition = partition_distributable(artifacts, reviewed_keys=reviewed_keys)

    entries: list[ArtifactEntry] = []
    for artifact in partition.distributable:
        entries.append(
            ArtifactEntry(
                kind=artifact.kind.value if hasattr(artifact.kind, "value") else str(artifact.kind),
                key=artifact.key,
                shard=shard_for(artifact.key, shards),
                content_hash=content_hash(
                    artifact.kind.value if hasattr(artifact.kind, "value") else str(artifact.kind),
                    artifact.key,
                    artifact.payload,
                ),
                payload=dict(artifact.payload),
            )
        )
    entries.sort(key=lambda e: (e.shard, e.content_hash))

    created = (created_at or datetime.now(timezone.utc)).isoformat()
    signing_bytes = _manifest_signing_bytes(
        created_at=created, parent_hash=parent_hash, num_shards=shards, entries=entries
    )
    manifest_hash = hashlib.sha256(signing_bytes).hexdigest()
    signature = signer.sign(signing_bytes)

    manifest = CorpusManifest(
        format_version=DISTRIBUTION_FORMAT_VERSION,
        created_at=created,
        parent_hash=parent_hash,
        num_shards=shards,
        entries=entries,
        manifest_hash=manifest_hash,
        signature=signature,
        key_id=signer.key_id,
    )
    return manifest, partition.rejected


def verify_manifest(manifest: CorpusManifest, signer: Signer | None = None) -> bool:
    """Verify a manifest's hash and signature (supply-chain integrity check)."""
    signer = signer or default_signer()
    signing_bytes = _manifest_signing_bytes(
        created_at=manifest.created_at,
        parent_hash=manifest.parent_hash,
        num_shards=manifest.num_shards,
        entries=manifest.entries,
    )
    if hashlib.sha256(signing_bytes).hexdigest() != manifest.manifest_hash:
        return False
    return signer.verify(signing_bytes, manifest.signature)


@dataclass(frozen=True)
class CorpusDelta:
    """The change set between a parent manifest and a current one."""

    parent_hash: str | None
    current_hash: str
    added: list[ArtifactEntry]
    changed: list[ArtifactEntry]
    removed: list[ArtifactEntry]

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.changed or self.removed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_hash": self.parent_hash,
            "current_hash": self.current_hash,
            "added": [e.to_dict() for e in self.added],
            "changed": [e.to_dict() for e in self.changed],
            "removed": [e.to_dict() for e in self.removed],
        }


def compute_delta(
    previous: CorpusManifest | None, current: CorpusManifest
) -> CorpusDelta:
    """Delta of ``current`` vs ``previous``, keyed by (kind, key).

    An entry present in both with a different content hash is ``changed``; new
    keys are ``added``; keys only in ``previous`` are ``removed``. Rollback-safe:
    a consumer applies added+changed and drops removed, and can revert by
    re-applying the parent manifest.
    """
    prev_by_key: dict[tuple[str, str], ArtifactEntry] = (
        {(e.kind, e.key): e for e in previous.entries} if previous else {}
    )
    curr_by_key = {(e.kind, e.key): e for e in current.entries}

    added, changed = [], []
    for key, entry in curr_by_key.items():
        if key not in prev_by_key:
            added.append(entry)
        elif prev_by_key[key].content_hash != entry.content_hash:
            changed.append(entry)
    removed = [e for key, e in prev_by_key.items() if key not in curr_by_key]

    return CorpusDelta(
        parent_hash=previous.manifest_hash if previous else None,
        current_hash=current.manifest_hash,
        added=sorted(added, key=lambda e: (e.shard, e.content_hash)),
        changed=sorted(changed, key=lambda e: (e.shard, e.content_hash)),
        removed=sorted(removed, key=lambda e: (e.shard, e.content_hash)),
    )


# ---------------------------------------------------------------------------
# Sync adapter interface — concrete transport intentionally unimplemented.
# ---------------------------------------------------------------------------


class SyncAdapter(ABC):
    """The pluggable transport seam. A concrete adapter (R2 / Oracle / GitHub
    Releases / Hetzner origin) is the LAST thing built, pending the infra call."""

    name: str = "abstract"

    @abstractmethod
    async def publish(self, manifest: CorpusManifest, delta: CorpusDelta) -> None: ...

    @abstractmethod
    async def fetch_latest(self) -> CorpusManifest | None: ...


class InertSyncAdapter(SyncAdapter):
    """The default adapter: publishes nowhere and records that nothing left.

    This is what keeps the machinery private-by-default — with no concrete
    adapter configured, a publish is structurally impossible, not merely
    disabled by a flag.
    """

    name = "inert"

    def __init__(self) -> None:
        self.publish_attempts = 0

    async def publish(self, manifest: CorpusManifest, delta: CorpusDelta) -> None:
        self.publish_attempts += 1
        raise DistributionInactive(
            "no concrete sync adapter is configured — corpus distribution is inert "
            "(private-by-default; a transport is wired only after the infra decision)"
        )

    async def fetch_latest(self) -> CorpusManifest | None:
        return None


class CorpusDistributor:
    """Orchestrates build → verify → delta → (refused) publish. Inert by default."""

    def __init__(
        self, *, signer: Signer | None = None, adapter: SyncAdapter | None = None
    ) -> None:
        self.signer = signer or default_signer()
        self.adapter = adapter or InertSyncAdapter()

    def is_publishing_active(self) -> bool:
        """True only when the master switch is on AND a non-inert adapter is set."""
        return bool(
            getattr(settings, "enable_corpus_distribution", False)
        ) and not isinstance(self.adapter, InertSyncAdapter)

    async def publish(self, manifest: CorpusManifest, delta: CorpusDelta) -> None:
        """Publish a signed delta — refused unless explicitly activated.

        Refuses (``DistributionInactive``) when the master switch is off or no
        concrete adapter is configured. This is the enforcement point for
        publish-never-without-explicit-approval.
        """
        if not getattr(settings, "enable_corpus_distribution", False):
            raise DistributionInactive(
                "corpus distribution master switch is off (enable_corpus_distribution=False)"
            )
        if not verify_manifest(manifest, self.signer):
            raise DistributionInactive("manifest failed signature/hash verification")
        await self.adapter.publish(manifest, delta)


async def collect_shareable_artifacts() -> list[Artifact]:
    """Gather 6B-safe, aggregate artifacts from the local corpus (guarded → []).

    Emits only shareable classes — per-provider/industry pattern priors (6C),
    per-domain confirmed patterns, and per-domain freshness summaries — never a
    contact. This is what a (future, activated) distribution would ship; building
    the list publishes nothing.
    """
    from .safe_artifact import ArtifactKind

    artifacts: list[Artifact] = []
    try:
        from .pattern_priors import build_priors_from_corpus

        priors = await build_priors_from_corpus()
        artifacts.extend(priors.to_safe_artifacts())
    except Exception:
        logger.debug("prior artifact collection unavailable", exc_info=True)

    try:
        from sqlalchemy import select

        from ..db.database import AsyncSessionLocal
        from ..db.models import CrawlSnapshot, Domain

        async with AsyncSessionLocal() as session:
            domains = (await session.execute(select(Domain))).scalars().all()
            for dom in domains:
                artifacts.append(
                    Artifact(
                        kind=ArtifactKind.FRESHNESS_SUMMARY,
                        key=dom.domain,
                        payload={
                            "domain": dom.domain,
                            "total_emails": dom.total_emails,
                            "high_confidence_count": dom.high_confidence_count,
                            "catchall_detected": dom.catchall_detected,
                            "last_harvested_at": dom.last_harvested_at.isoformat()
                            if dom.last_harvested_at
                            else None,
                        },
                    )
                )
                snap = (
                    await session.execute(
                        select(CrawlSnapshot)
                        .where(CrawlSnapshot.domain == dom.domain)
                        .where(CrawlSnapshot.confirmed_pattern.isnot(None))
                        .order_by(CrawlSnapshot.harvested_at.desc())
                        .limit(1)
                    )
                ).scalar_one_or_none()
                if snap is not None and snap.confirmed_pattern:
                    artifacts.append(
                        Artifact(
                            kind=ArtifactKind.DOMAIN_PATTERN,
                            key=dom.domain,
                            payload={"domain": dom.domain, "pattern": snap.confirmed_pattern},
                        )
                    )
    except Exception:
        logger.debug("domain artifact collection unavailable", exc_info=True)

    return artifacts


async def build_corpus_manifest(
    *, parent_hash: str | None = None, signer: Signer | None = None
) -> tuple[CorpusManifest, list[tuple[Artifact, str]]]:
    """Build a signed manifest from the local corpus's shareable artifacts.

    Publishes nothing — it produces a verifiable, sharded, signed manifest that
    an (activated) distributor could later ship. Guarded via
    :func:`collect_shareable_artifacts`.
    """
    return build_manifest(
        await collect_shareable_artifacts(), parent_hash=parent_hash, signer=signer
    )


def rollback_target(
    current: CorpusManifest, history: list[CorpusManifest]
) -> CorpusManifest | None:
    """The parent manifest to roll back to (by ``parent_hash``), if present."""
    if not current.parent_hash:
        return None
    for manifest in history:
        if manifest.manifest_hash == current.parent_hash:
            return manifest
    return None
