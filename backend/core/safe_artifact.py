"""Phase 6B — private-by-default safe-artifact classification.

This is the hard governance line for the entire shared-corpus flywheel: it
defines, **exhaustively and fail-closed**, what may *ever* leave the local store.
Every artifact the corpus can produce is classified into exactly one share
class, and the distribution (6D) and contribution (6E) machinery consult *only*
this module to decide eligibility. Nothing else is allowed to make that call.

Three share classes:

* ``SHAREABLE`` — aggregate, non-contact artifacts that carry no personal data:
  domain-level email patterns, per-provider/industry pattern *distributions*
  (6C priors), source fingerprints, and freshness summaries. These are the only
  classes that are auto-safe (Doc-1 #14: a shared corpus of raw personal emails
  is a GDPR/takedown liability — only patterns and summaries are shareable).
* ``REVIEW_REQUIRED`` — **contact-level** artifacts (a specific email/person, a
  verification outcome, a raw crawl snapshot, a ledger observation, or
  user-owned/contributed data). These are *never auto-safe*: they may be
  distributed only after explicit per-batch human review, and never otherwise.
* ``NEVER`` — internal governance and raw evidence (suppression, takedowns, the
  audit chain, raw payload bytes, run manifests). These never leave, ever.

**Fail closed.** An *unclassified* artifact kind is treated as ``NEVER``. The
classification is kept exhaustive (``ALL_ARTIFACT_KINDS`` + the policy test
suite), so the fail-closed default is a safety net, not the norm.

**Defense in depth.** Independent of the kind label, the payload is scanned for
contact-level PII (an email address, a phone, a person field). A ``SHAREABLE``
artifact whose payload actually contains contact PII is *downgraded* to
``REVIEW_REQUIRED`` — a mislabeled aggregate can never leak a contact.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ArtifactKind(str, Enum):
    """Every kind of artifact the corpus can produce. Exhaustive by contract."""

    # --- Aggregate, non-contact (the only auto-shareable classes) ---
    DOMAIN_PATTERN = "domain_pattern"  # per-domain confirmed email pattern, e.g. {first}
    PROVIDER_PATTERN_PRIOR = "provider_pattern_prior"  # 6C aggregate distribution
    INDUSTRY_PATTERN_PRIOR = "industry_pattern_prior"  # 6C aggregate distribution
    SOURCE_FINGERPRINT = "source_fingerprint"  # which sources yield on a domain
    FRESHNESS_SUMMARY = "freshness_summary"  # domain counts / last-seen / staleness

    # --- Contact-level: NEVER auto-safe; explicit human review required ---
    CONTACT_RECORD = "contact_record"  # a specific email address / lead row
    PERSON_RECORD = "person_record"  # name/title/linkedin for a person
    VERIFICATION_OUTCOME = "verification_outcome"  # per-email verify verdict
    CRAWL_SNAPSHOT = "crawl_snapshot"  # raw serialized harvest (contains emails)
    OBSERVATION = "observation"  # 1C ledger row (subject is often an email)
    USER_OWNED = "user_owned"  # user-owned / explicitly-contributed data

    # --- Never shareable: internal governance + raw evidence ---
    SUPPRESSION_ENTRY = "suppression_entry"
    TAKEDOWN_ENTRY = "takedown_entry"
    AUDIT_LOG_ENTRY = "audit_log_entry"
    RAW_PAYLOAD = "raw_payload"
    RUN_MANIFEST = "run_manifest"


class ShareClass(str, Enum):
    """The share verdict for an artifact kind."""

    SHAREABLE = "shareable"  # aggregate, non-contact → auto-safe
    REVIEW_REQUIRED = "review-required"  # contact-level → explicit human review
    NEVER = "never"  # never leaves, under any circumstance


ALL_ARTIFACT_KINDS: frozenset[ArtifactKind] = frozenset(ArtifactKind)

_SHAREABLE: frozenset[ArtifactKind] = frozenset(
    {
        ArtifactKind.DOMAIN_PATTERN,
        ArtifactKind.PROVIDER_PATTERN_PRIOR,
        ArtifactKind.INDUSTRY_PATTERN_PRIOR,
        ArtifactKind.SOURCE_FINGERPRINT,
        ArtifactKind.FRESHNESS_SUMMARY,
    }
)

# Contact-level artifacts — never auto-safe; distribution requires review, and
# even then only through the reviewed path.
_CONTACT_LEVEL: frozenset[ArtifactKind] = frozenset(
    {
        ArtifactKind.CONTACT_RECORD,
        ArtifactKind.PERSON_RECORD,
        ArtifactKind.VERIFICATION_OUTCOME,
        ArtifactKind.CRAWL_SNAPSHOT,
        ArtifactKind.OBSERVATION,
        ArtifactKind.USER_OWNED,
    }
)

_NEVER: frozenset[ArtifactKind] = frozenset(
    {
        ArtifactKind.SUPPRESSION_ENTRY,
        ArtifactKind.TAKEDOWN_ENTRY,
        ArtifactKind.AUDIT_LOG_ENTRY,
        ArtifactKind.RAW_PAYLOAD,
        ArtifactKind.RUN_MANIFEST,
    }
)

# Invariant checked at import: the three buckets partition the universe exactly.
assert _SHAREABLE | _CONTACT_LEVEL | _NEVER == ALL_ARTIFACT_KINDS
assert not (_SHAREABLE & _CONTACT_LEVEL)
assert not (_SHAREABLE & _NEVER)
assert not (_CONTACT_LEVEL & _NEVER)


def _coerce_kind(kind: str | ArtifactKind) -> ArtifactKind | None:
    if isinstance(kind, ArtifactKind):
        return kind
    try:
        return ArtifactKind(str(kind).strip())
    except ValueError:
        return None


def share_class(kind: str | ArtifactKind) -> ShareClass:
    """The share class of an artifact kind. **Unknown kind → NEVER (fail closed).**"""
    resolved = _coerce_kind(kind)
    if resolved is None:
        return ShareClass.NEVER
    if resolved in _SHAREABLE:
        return ShareClass.SHAREABLE
    if resolved in _CONTACT_LEVEL:
        return ShareClass.REVIEW_REQUIRED
    return ShareClass.NEVER


def is_contact_level(kind: str | ArtifactKind) -> bool:
    """Whether a kind is contact-level (never auto-safe). Unknown → True (safe side)."""
    resolved = _coerce_kind(kind)
    if resolved is None:
        # An unknown kind is treated as the most sensitive thing it could be.
        return True
    return resolved in _CONTACT_LEVEL


# ---------------------------------------------------------------------------
# Defense in depth — content PII scan, independent of the kind label.
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?:\+?\d[\s\-().]?){7,}\d")
# Keys that, if present with a truthy value, indicate a contact-level payload.
_PII_KEYS = frozenset(
    {
        "email",
        "emails",
        "contact",
        "contacts",
        "person",
        "full_name",
        "first_name",
        "last_name",
        "phone",
        "linkedin_url",
        "address",
        "canonical_email",
    }
)


def _scan_for_pii(value: Any, *, _depth: int = 0) -> bool:
    """Recursively scan a payload for contact-level PII. Bounded depth."""
    if _depth > 12:
        return False
    if isinstance(value, str):
        return bool(_EMAIL_RE.search(value)) or bool(_PHONE_RE.search(value))
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).strip().lower() in _PII_KEYS and item:
                # A PII-named key that isn't just an empty/None placeholder.
                if not (isinstance(item, list | dict) and not item):
                    return True
            if _scan_for_pii(item, _depth=_depth + 1):
                return True
        return False
    if isinstance(value, list | tuple | set):
        return any(_scan_for_pii(item, _depth=_depth + 1) for item in value)
    return False


def payload_contains_pii(payload: Any) -> bool:
    """Public wrapper: does this payload contain contact-level PII?"""
    return _scan_for_pii(payload)


@dataclass(frozen=True)
class Artifact:
    """A unit of corpus content that 6D/6E may consider for distribution."""

    kind: ArtifactKind
    key: str  # shard/lookup key (e.g. the domain, provider, or industry)
    payload: dict[str, Any]
    # Set only for genuinely user-owned/opt-in-contributed data.
    contributed: bool = False


@dataclass(frozen=True)
class Decision:
    """Explainable classification of one artifact."""

    share_class: ShareClass
    contact_level: bool
    distributable: bool  # given the ``reviewed`` flag passed to :func:`classify`
    reason: str


def classify(
    kind: str | ArtifactKind,
    payload: Any = None,
    *,
    reviewed: bool = False,
) -> Decision:
    """Classify an artifact for distribution eligibility.

    ``reviewed`` records that a human has explicitly reviewed and approved this
    contact-level artifact for a specific batch. It only ever *upgrades* a
    ``REVIEW_REQUIRED`` verdict to distributable — it can never make a ``NEVER``
    artifact distributable, and it is meaningless for an already-``SHAREABLE`` one.
    """
    cls = share_class(kind)
    contact = is_contact_level(kind)

    # Defense in depth: a payload that actually contains contact PII can never be
    # auto-shareable, whatever its declared kind. Downgrade to review-required.
    if cls is ShareClass.SHAREABLE and payload is not None and payload_contains_pii(payload):
        return Decision(
            share_class=ShareClass.REVIEW_REQUIRED,
            contact_level=True,
            distributable=bool(reviewed),
            reason=(
                "declared shareable but payload contains contact PII — downgraded "
                "to review-required (defense in depth)"
            ),
        )

    if cls is ShareClass.NEVER:
        return Decision(cls, contact, False, "never distributable (internal/raw or unclassified)")
    if cls is ShareClass.SHAREABLE:
        return Decision(cls, False, True, "aggregate, non-contact — auto-shareable")
    # REVIEW_REQUIRED (contact-level).
    return Decision(
        cls,
        True,
        bool(reviewed),
        "contact-level — distributable only after explicit human review"
        if not reviewed
        else "contact-level — explicitly reviewed for this batch",
    )


def is_distributable(
    kind: str | ArtifactKind,
    payload: Any = None,
    *,
    reviewed: bool = False,
) -> bool:
    """Whether an artifact may be distributed. The single gate 6D/6E consult."""
    return classify(kind, payload, reviewed=reviewed).distributable


@dataclass(frozen=True)
class Partition:
    """The result of splitting artifacts into distributable / rejected."""

    distributable: list[Artifact]
    rejected: list[tuple[Artifact, str]]  # (artifact, reason)


def partition_distributable(
    artifacts: list[Artifact], *, reviewed_keys: frozenset[str] | set[str] = frozenset()
) -> Partition:
    """Split artifacts into those that may leave and those that may not.

    The single eligibility gate both 6D (distribution) and 6E (contribution)
    consult. A contact-level artifact is distributable only when its ``key`` is
    in ``reviewed_keys`` (an explicit per-batch human review); an unsafe/unknown
    one is never distributable. The payload PII scan applies throughout.
    """
    reviewed = {str(k) for k in reviewed_keys}
    keep: list[Artifact] = []
    drop: list[tuple[Artifact, str]] = []
    for artifact in artifacts:
        decision = classify(
            artifact.kind, artifact.payload, reviewed=artifact.key in reviewed
        )
        if decision.distributable:
            keep.append(artifact)
        else:
            drop.append((artifact, decision.reason))
    return Partition(distributable=keep, rejected=drop)


# Introspection view: {kind: share_class} over the exhaustive universe. Handy for
# tests and for surfacing the policy in docs/exports (mirrors MODULE_MODE_POLICY).
ARTIFACT_CLASS_POLICY: dict[str, ShareClass] = {
    k.value: share_class(k) for k in sorted(ALL_ARTIFACT_KINDS, key=lambda x: x.value)
}
