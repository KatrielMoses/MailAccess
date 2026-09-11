"""0.16.0 Phase 3 — govern a :class:`PatternEmail` into a lead candidate.

Phase 2 produced ONE graded, *unverified* email from the offline corpus pattern
index (:mod:`company_pattern_index`). Phase 3 is the governance layer: it takes
that :class:`PatternEmail` and treats it exactly like any other unverified
candidate — deliverability-graded, eligibility-verdicted, suppression-checked,
provenance-recorded — reusing the existing machinery rather than building new
grading. A pattern guess is never over-trusted and never bypasses governance.

The three non-negotiables this module enforces, end to end:

* **Never falsely Valid.** A pattern email has no per-mailbox proof, so it grades
  at most ``Risky`` (MX ok, unverified) — never ``Valid``. Only Phase 6's oracle
  can lift it. See :func:`grade_pattern_email`.
* **Never auto-eligible.** However well-supported (a corpus pattern can carry a
  research score ~0.9), an *unverified* candidate is verdicted ``review`` /
  ``research-only`` — never ``eligible`` on its own. The verification gate in
  :func:`eligibility.evaluate` enforces this; :func:`pattern_email_to_candidate`
  feeds it ``verification="unverified"``.
* **Suppression wins.** The email (and its implied domain / company) is checked
  against the read-time suppression store before it is surfaced; a suppressed
  subject can never resurface via a pattern guess.

Every emitted candidate carries full provenance (``source_type=
company_pattern_index``, pattern id, support, confidence, applied confidence,
mx, role, provenance string) and produces a W3C-PROV-ready observation whose
lineage marks it a *learned-pattern inference*, not an observed address.

Phase 4 (not here) wires :func:`pattern_email_to_candidate` into harvest /
``person_email_pivot`` / ``/api/leads``; this module only makes the object
correct and governed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from .catchall_buster import ExistenceSignal, confirm_mailbox, confirm_mailboxes
from .company_pattern_index import CONFIDENCE_BASIS, SOURCE_TYPE, PatternEmail, confidence_label
from .company_pattern_index import get_index as _get_company_pattern_index
from .deliverability_grade import GRADE_VALID, DeliverabilityGrade, grade_email
from .deliverability_score import compute_deliverability_score
from .eligibility import Eligibility, EligibilityVerdict, evaluate
from .email_confidence import ConfidenceLabel, compute_confidence_breakdown
from .observation_ledger import build_observation
from .pattern_resolver import CanonicalResolver
from .pattern_resolver import person_key as _index_first_last
from .product_mode import ProductMode, normalize_mode, policy_status_for_mode
from .role_classifier import is_role_email
from .suppression import SuppressionIndex, load_index_sync

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .domain_harvest_orchestrator import HarvestedEmail

_LOG = logging.getLogger(__name__)

#: The verification status stamped on every pattern candidate. A pattern email is
#: an inference, never a confirmed address — this is what makes the eligibility
#: verification gate cap it at REVIEW.
VERIFICATION_UNVERIFIED = "unverified"

#: The verification status stamped on a Phase-6 oracle-confirmed pattern candidate.
#: It is a member of ``eligibility._CONFIRMED_VERIFICATIONS``, so the REVIEW cap
#: lifts and the candidate can auto-clear to ELIGIBLE (in a lead-gen mode).
VERIFICATION_PROVIDER_VERIFIED = "provider_verified"

#: The one ``mx`` tag with a live per-mailbox existence oracle (Phase 1 research:
#: M365 ``GetCredentialType`` discriminates; Google gxlu is dead). Only these
#: candidates are ever sent to the oracle.
_ORACLE_MX = "m365"

#: The extraction-method / pipeline label used on the ledger observation, so the
#: PROV lineage names the run a company-pattern inference.
PIPELINE = "pattern_inference"

#: Map the index's coarse ``mx`` tag to the deliverability model's provider name.
#: ``m365`` / ``google`` are reputable managed providers; ``other`` carries no
#: provider signal (``None`` → the model's "provider unknown" feature).
_MX_TO_PROVIDER: dict[str, str] = {"m365": "m365", "google": "google"}


def _provider_for(pe: PatternEmail) -> str | None:
    return _MX_TO_PROVIDER.get((pe.mx or "").strip().lower())


# --------------------------------------------------------------------------- #
# 0.16.0 fix-pass Root A — shared per-harvest run-state for the ONE governed
# name->email path. A single instance is threaded through BOTH the reactive
# worker and the batch module so the two generators behave as one governed
# generator, not two independent ones.
# --------------------------------------------------------------------------- #


@dataclass
class PatternRunState:
    """Shared, mutable state for one harvest's governed pattern generation.

    The 0.15.0/0.16.0 contract is "ONE governed name->email path and ONE canonical
    finalization". On the live harvest that path is exercised from several
    asynchronous producers — the reactive per-name worker, the batch module, and the
    M365 oracle callbacks — so this object is the shared ground they stand on. Its
    authority over evidence and decisions is the run-scoped
    :class:`~backend.core.pattern_resolver.CanonicalResolver` (Brief A): both
    generation paths and every oracle callback submit evidence to it, and final
    aggregation consumes its projection, so module-result dicts and signal-pool rows
    stop being competing authorities.

    * ``resolver`` — the canonical resolver: retained per-mailbox oracle decisions
      (a terminal ``not_found`` retracts the mailbox even if a racing producer
      already emitted it), single-flight verification (one probe/one budget draw per
      mailbox however many producers request it), the normalized evidence-kind
      contract, and domain-scoped person association / deterministic canonical
      selection. ``tombstones`` (emails that must never be re-emitted as an
      inference) live on the resolver and are surfaced here for the existing callers.
    * ``emitted_inference_by_person`` — retained for back-compat telemetry; the
      resolver's person store is now the authority for person-level reconciliation.
    * ``oracle_budget_remaining`` — the M365 existence-oracle verification budget
      for the WHOLE run, decremented as candidates are actually sent to the oracle
      (shared run-state, not a per-invocation cap that every reactive call would
      reset to the full budget).
    """

    resolver: CanonicalResolver = field(default_factory=CanonicalResolver)
    emitted_inference_by_person: dict[tuple[str, str], str] = field(default_factory=dict)
    oracle_budget_remaining: int | None = None

    @property
    def tombstones(self) -> set[str]:
        """The resolver's tombstone set — the one source of truth for dropped mailboxes."""
        return self.resolver.tombstones

    def tombstone(self, email: str) -> None:
        self.resolver.tombstone(email)

    def is_tombstoned(self, email: str) -> bool:
        return self.resolver.is_tombstoned(email)

    def seed_oracle_budget(self, default: int) -> None:
        """Seed the shared oracle budget once (the first consumer wins)."""
        if self.oracle_budget_remaining is None:
            self.oracle_budget_remaining = max(0, int(default))

    def reserve_oracle(self, n: int) -> int:
        """Reserve up to ``n`` oracle verifications from the shared budget.

        Synchronous (no ``await`` between read and decrement), so it is race-free
        under asyncio's cooperative scheduling even with concurrent reactive
        workers. Returns the number granted; an unseeded budget is unbounded.
        """
        if self.oracle_budget_remaining is None:
            return max(0, n)
        grant = max(0, min(int(n), self.oracle_budget_remaining))
        self.oracle_budget_remaining -= grant
        return grant


def grade_pattern_email(
    pe: PatternEmail, *, mailbox_confirmed: bool = False
) -> DeliverabilityGrade:
    """Grade a :class:`PatternEmail` through the terminal deliverability grader.

    Feeds the pattern source into :func:`deliverability_grade.grade_email`
    correctly and offline:

    * **MX** is taken as present — the index only records a domain once its mail
      provider was classified (the ``mx`` tag *is* that evidence), so the domain
      publishes MX; the tag also selects the provider signal.
    * **No SMTP, no provider verifier** — a pattern guess has none of the
      affirmative signals that can reach ``Valid``. ``catchall`` is unknown
      offline (``None``), so it is neither asserted nor cleared.
    * **Role** is classified from the generated localpart (a name-derived guess
      is essentially never a role mailbox), affecting only the reasons, not the
      terminal grade.

    Without ``mailbox_confirmed`` the result is ``Risky`` (MX ok, unconfirmed) —
    or ``Unknown`` if the infrastructure signal is too weak — but **never**
    ``Valid``. ``mailbox_confirmed=True`` is Phase 6's per-mailbox existence
    signal (the M365 oracle confirmed *this* mailbox exists); it is the ONE thing
    that lifts the grade to ``Valid``. The asserts below encode both halves of
    that invariant so a future grader change can never silently let an unverified
    guess present as Valid, nor silently fail to promote a confirmed mailbox.
    """
    provider = _provider_for(pe)
    is_role = is_role_email(pe.email)
    # Non-SMTP probability from the signals we actually have offline: MX present
    # + provider reputability. This drives the graceful-degradation band that
    # lands the grade at Risky (rather than Unknown for a missing score).
    score = compute_deliverability_score(
        mx_present=True,
        provider=provider,
        is_role=is_role,
    )
    grade = grade_email(
        score=score,
        mx_present=True,
        is_role=is_role,
        provider_name=provider,
        # Every per-mailbox confirmation signal is omitted EXCEPT the Phase-6
        # oracle's ``mailbox_confirmed`` — an unverified inference cannot be Valid;
        # only an oracle-confirmed mailbox can.
        catchall=None,
        smtp_status=None,
        smtp_exists=None,
        provider_status=None,
        mailbox_confirmed=mailbox_confirmed,
        history_recent_verified=False,
    )
    if mailbox_confirmed:
        # A confirmed mailbox MUST reach Valid — the Phase-6 upgrade depends on it.
        assert grade.grade == GRADE_VALID, (
            "invariant violated: an oracle-confirmed pattern mailbox must grade "
            f"Valid (got {grade.grade!r})"
        )
    else:
        # Belt-and-braces: without confirmation a pattern guess can never be Valid.
        assert grade.grade != GRADE_VALID, (
            "invariant violated: an unverified pattern-index email must never "
            f"grade Valid (got {grade.grade!r})"
        )
    return grade


def pattern_observation(
    pe: PatternEmail,
    *,
    mode: str | ProductMode = ProductMode.SECURITY_INVESTIGATION,
    captured_at: datetime | None = None,
) -> dict[str, Any]:
    """Build the ledger observation for a pattern email (full provenance).

    The claim carries ``source_type=company_pattern_index`` (so the PROV agent is
    ``source/company_pattern_index`` and the activity's extraction method names
    the inference), ``is_inference=True`` and ``verification="unverified"`` (so
    the lineage plainly marks a learned-pattern inference, not an observed
    address), plus the full pattern metadata for audit.
    """
    domain = pe.email.split("@", 1)[1] if "@" in pe.email else ""
    claim: dict[str, Any] = {
        "email": pe.email,
        "source_type": SOURCE_TYPE,
        "is_inference": True,
        "verification": pe.verification,
        "pattern_id": pe.pattern_id,
        "support_n": pe.support_n,
        # Brief C R9 — the TRUE denominator behind the confidence, propagated into
        # the ledger claim alongside the numerator + basis so the calculation is
        # reproducible from the provenance (``None`` on a legacy record).
        "considered_n": pe.considered_n,
        "confidence": pe.confidence,
        "applied_confidence": pe.applied_confidence,
        "confidence_basis": pe.confidence_basis,
        "mx": pe.mx,
        "role_used": pe.role_used,
        "provenance": pe.provenance,
    }
    return build_observation(
        pipeline=PIPELINE,
        activity_id=domain or pe.email,
        subject_type="email",
        subject=pe.email,
        extraction_method=SOURCE_TYPE,
        claim=claim,
        captured_at=captured_at or datetime.now(timezone.utc),
        mode=normalize_mode(mode).value,
    )


@dataclass
class PatternCandidate:
    """A fully-governed lead candidate derived from a :class:`PatternEmail`.

    Carries the address, its (capped) confidence label, the deliverability grade,
    the eligibility verdict, suppression state, full provenance, and the ledger
    observation — everything a downstream consumer (Phase 4: harvest / pivot /
    leads) needs to treat it as a governed, unverified candidate.
    """

    email: str
    verification: str
    # Confidence — the canonical-scorer label (already honesty-capped below the
    # CONFIRMED band) and its numeric score, surfaced independently of eligibility.
    confidence_score: float
    confidence_label: str
    confidence_breakdown: dict[str, Any]
    # Deliverability grade (≤ Risky) + its full reasons/evidence.
    deliverability_grade: str
    deliverability: dict[str, Any]
    # Eligibility verdict — orthogonal to confidence; never ``eligible`` on its own.
    eligibility: str
    eligibility_reason: str
    # Suppression state (checked at read-time before surfacing).
    suppressed: bool
    # Full provenance metadata.
    provenance: str
    source_type: str
    pattern_id: str
    support_n: int
    confidence: float
    applied_confidence: float
    mx: str
    role_used: str | None
    # The W3C-PROV-ready ledger observation (lineage tagged as inference).
    observation: dict[str, Any] = field(default_factory=dict)
    # Brief C R9 — the TRUE denominator behind ``confidence`` (``None`` on a legacy
    # record) and the confidence basis/version, carried alongside ``support_n`` /
    # ``applied_confidence`` so the calculation survives every projection (candidate
    # → oracle reconstruction → observation → harvested evidence → export).
    considered_n: int | None = None
    confidence_basis: str = CONFIDENCE_BASIS

    def as_harvested_email(self) -> HarvestedEmail:
        """Project into the harvest pipeline's candidate type (Phase 4 seam).

        Sets ``verification="unverified"`` and the confidence + deliverability
        fields so that, wherever the export path recomputes eligibility, the
        verification gate still caps this address at REVIEW. Provenance rides in
        ``evidence`` so it survives into the ledger/export.
        """
        from .domain_harvest_orchestrator import HarvestedEmail

        return HarvestedEmail(
            email=self.email,
            on_domain=True,
            is_role=False,
            role_match_type=None,
            confidence_score=self.confidence_score,
            confidence_label=self.confidence_label,
            found_by_modules=[self.source_type],
            source_count=1,
            evidence=[
                {
                    "module": self.source_type,
                    "metadata": {
                        "source_type": self.source_type,
                        "provenance": self.provenance,
                        "pattern_id": self.pattern_id,
                        "support_n": self.support_n,
                        "considered_n": self.considered_n,
                        "confidence": self.confidence,
                        "applied_confidence": self.applied_confidence,
                        "confidence_basis": self.confidence_basis,
                        "mx": self.mx,
                        "role_used": self.role_used,
                        "verification": self.verification,
                        "is_inference": True,
                    },
                }
            ],
            confidence_breakdown=self.confidence_breakdown,
            deliverability_score=self.deliverability.get("score"),
            deliverability_grade=self.deliverability_grade,
            deliverability=self.deliverability,
            verification=self.verification,
        )


def pattern_email_to_candidate(
    pe: PatternEmail,
    *,
    mode: str | ProductMode = ProductMode.SECURITY_INVESTIGATION,
    company: str | None = None,
    suppression_index: SuppressionIndex | None = None,
    captured_at: datetime | None = None,
) -> PatternCandidate:
    """Turn ONE :class:`PatternEmail` into a governed :class:`PatternCandidate`.

    Deterministic for a given ``(pe, mode, company, suppression_index)`` — the
    grade, verdict and provenance are pure functions of the inputs (the ledger
    observation's capture time is the only nondeterministic field and is not part
    of the verdict).

    Governance, in order:

    1. Confidence via the ONE canonical scorer, honesty-capped below CONFIRMED
       (:func:`company_pattern_index.confidence_label`).
    2. Deliverability grade ≤ Risky (:func:`grade_pattern_email`).
    3. Suppression check at the same read-time seam every export uses — the
       email (escalating to its domain) and, if given, the company name.
    4. Eligibility verdict (:func:`eligibility.evaluate`) gating on mode +
       lawful basis + grade + **verification** — never ``eligible`` on its own.
    5. A provenance-complete ledger observation, lineage-tagged as inference.
    """
    m = normalize_mode(mode)
    label = confidence_label(pe)
    grade = grade_pattern_email(pe)

    index = suppression_index if suppression_index is not None else load_index_sync()
    suppressed = index.hit(email=pe.email, company=company) is not None

    verdict: EligibilityVerdict = evaluate(
        mode=m,
        policy_status=policy_status_for_mode(m),
        suppressed=suppressed,
        confidence=label.score,
        deliverability_grade=grade.grade,
        verification=pe.verification,
    )

    return PatternCandidate(
        email=pe.email,
        verification=pe.verification,
        confidence_score=label.score,
        confidence_label=label.label,
        confidence_breakdown=dict(label.breakdown),
        deliverability_grade=grade.grade,
        deliverability=grade.as_dict(),
        eligibility=verdict.verdict.value,
        eligibility_reason=verdict.reason,
        suppressed=suppressed,
        provenance=pe.provenance,
        source_type=SOURCE_TYPE,
        pattern_id=pe.pattern_id,
        support_n=pe.support_n,
        confidence=pe.confidence,
        applied_confidence=pe.applied_confidence,
        considered_n=pe.considered_n,
        confidence_basis=pe.confidence_basis,
        mx=pe.mx,
        role_used=pe.role_used,
        observation=pattern_observation(pe, mode=m, captured_at=captured_at),
    )


# --------------------------------------------------------------------------- #
# Brief B — every input name gets ONE explicit, accounted generation decision, so
# an error can never masquerade as an ordinary miss or observed coverage, and
# ungoverned fallback spray is reserved for explicitly-permitted outcomes.
# --------------------------------------------------------------------------- #

DECISION_EMITTED = "emitted"                    # a governed candidate was produced
DECISION_LOW_NAME_EVIDENCE = "low_name_evidence"  # name confidence below the gate
DECISION_OBSERVED_COVERAGE = "observed_coverage"  # a real observed address wins
DECISION_SUPPRESSED = "suppressed"              # subject objected — never resurface
DECISION_ORACLE_REJECTED = "oracle_rejected"    # a prior oracle not_found tombstone
DECISION_UNPLACEABLE = "unplaceable"            # indexed, but the name can't be placed
DECISION_UNINDEXED = "unindexed"                # domain not in the corpus index
DECISION_INDEX_UNAVAILABLE = "index_unavailable"  # index disabled / not shipped
DECISION_APPLY_ERROR = "apply_error"            # index.apply raised
DECISION_GOVERNANCE_ERROR = "governance_error"  # governance/grading raised

#: The outcomes for which the legacy ungoverned permutation spray is a permitted
#: fallback: a plain corpus MISS (unindexed / unplaceable) or the index simply not
#: being available. A governance failure, an ``apply`` error, or a malformed indexed
#: record is NOT here — Brief B forbids silently switching such a failure to an
#: ungoverned spray path. A low-name-evidence or suppressed/observed/rejected
#: outcome is also not here (it must emit nothing at all).
_FALLBACK_DECISIONS = frozenset(
    {DECISION_UNINDEXED, DECISION_UNPLACEABLE, DECISION_INDEX_UNAVAILABLE}
)


@dataclass
class NameEvidence:
    """Structured name-evidence input to the governed generator (Brief B item 3).

    Carries the confidence and provenance of the *independently-observed* person a
    generated address would be attributed to, so the one name-evidence gate can be
    applied identically on every generation path before an address is produced.
    ``confidence`` is the discovering source's name confidence (``None`` means "not
    supplied" — see the explicit missing-confidence policy in
    :func:`govern_name_to_candidate`, which never manufactures a passing value).
    """

    name: str
    confidence: float | None = None
    title: str | None = None
    provenance: str | None = None


@dataclass
class GovernOutcome:
    """The accounted result of ONE governed name→email decision (Brief B item 4)."""

    decision: str
    candidate: PatternCandidate | None = None

    @property
    def emitted(self) -> bool:
        return self.decision == DECISION_EMITTED

    @property
    def fallback_allowed(self) -> bool:
        """Whether the caller may fall through to the ungoverned permutation spray.

        True only for a plain corpus miss / unavailable index — never for a
        governance/apply error or a deliberate no-emit (low evidence, suppressed,
        observed, oracle-rejected).
        """
        return self.decision in _FALLBACK_DECISIONS


#: Back-compat sentinel: truthy object whose identity older call sites compared
#: against. New code branches on :attr:`GovernOutcome.fallback_allowed` /
#: :attr:`GovernOutcome.decision`; this remains only so a stale ``is SPRAY`` import
#: does not break at import time.
SPRAY: Any = object()


def _name_evidence_passes(name_evidence: NameEvidence, *, settings: Any) -> bool:
    """Apply the configured name-confidence gate (Brief B item 3).

    A name whose discovering-source confidence is below
    ``settings.pattern_medium_confidence_threshold`` is too weak to attribute a
    generated address to — no path may produce one for it. The gate is applied
    HERE, in the shared generator, so it is authoritative and identical for the
    reactive worker and the batch module; the subscriber's pre-schedule filter is
    only an optimization.

    Missing confidence (``None``) follows an EXPLICIT, conservative policy: it does
    **not** pass. A missing value is never silently promoted to a passing one — a
    producer that cannot vouch for the name's confidence does not clear the gate.
    """
    threshold = float(
        getattr(settings, "pattern_medium_confidence_threshold", 0.50) or 0.50
    )
    conf = name_evidence.confidence
    if conf is None:
        return False
    try:
        return float(conf) >= threshold
    except (TypeError, ValueError):
        return False


def govern_name_to_candidate(
    name_evidence: NameEvidence,
    domain: str,
    *,
    mode: str | ProductMode = ProductMode.SECURITY_INVESTIGATION,
    suppression_index: SuppressionIndex | None = None,
    run_state: PatternRunState | None = None,
    observed_localparts: set[str] | None = None,
    observed_name_keys: set[tuple[str, str]] | None = None,
    index: Any | None = None,
) -> GovernOutcome:
    """The ONE governed name→email generator (Root A / Brief B) — shared by the
    reactive worker and the batch module, so both call sites produce identical
    governed candidates, honour the same shared run-state, apply the same
    name-evidence gate, and return the same accounted decision.

    Returns a :class:`GovernOutcome` whose ``decision`` is exactly one accounted
    outcome (see the ``DECISION_*`` constants) and whose ``candidate`` is set only
    for :data:`DECISION_EMITTED`. The caller reads ``fallback_allowed`` to decide
    whether the ungoverned permutation spray may run — it may ONLY for a plain
    corpus miss / unavailable index, never for a governance/apply error or a
    deliberate no-emit (low evidence, suppressed, observed, oracle-rejected).

    Brief B — the name-evidence gate is applied FIRST, before corpus application and
    before any fallback, so a low-evidence name produces no address on any domain
    (indexed or not) and never sprays.

    Pure except for the shared ``run_state`` it updates (tombstones a
    superseded/suppressed mailbox; records the per-person emission for finalize-time
    reconciliation). No network I/O — the oracle upgrade/drop is a separate step
    (:func:`verify_pattern_candidate` / :func:`verify_pattern_candidates`) that each
    path runs with the same ``run_state``.
    """
    from ..config import settings

    name = name_evidence.name
    title = name_evidence.title

    # Brief B item 3 — the authoritative name-evidence gate, before corpus
    # application AND before any fallback. A weak name generates nothing anywhere.
    if not _name_evidence_passes(name_evidence, settings=settings):
        return GovernOutcome(DECISION_LOW_NAME_EVIDENCE)

    idx = index if index is not None else _get_company_pattern_index()
    if not getattr(settings, "enable_company_pattern_index", True) or not idx.available:
        # The index is not shipped/enabled — spray is the legitimate non-corpus path.
        return GovernOutcome(DECISION_INDEX_UNAVAILABLE)
    try:
        pe = idx.apply(name, domain, title=title, seniority=None)
    except Exception:
        # A malformed indexed record / apply failure is an ERROR, not a miss: it
        # must NOT silently switch to the ungoverned spray path (Brief B item 4).
        _LOG.warning("company_pattern_index.apply failed for %r", name, exc_info=True)
        return GovernOutcome(DECISION_APPLY_ERROR)
    if pe is None:
        # A plain corpus miss: an unindexed domain, or an indexed domain whose
        # pattern the name cannot satisfy (a mononym on a distinct-name pattern).
        # Both are legitimate fallbacks to the spray.
        if idx.is_indexed(domain):
            return GovernOutcome(DECISION_UNPLACEABLE)
        return GovernOutcome(DECISION_UNINDEXED)

    # Tombstone precedence — a mailbox already dropped (oracle not_found, suppressed,
    # or superseded by a real observed address) must never be regenerated.
    if run_state is not None and run_state.is_tombstoned(pe.email):
        return GovernOutcome(DECISION_ORACLE_REJECTED)

    # Observed beats inferred — a real observed address for this person (or this
    # exact localpart) wins; the inference must never duplicate or override it.
    pe_local = pe.email.partition("@")[0]
    name_key = _index_first_last(name)
    if (observed_localparts and pe_local in observed_localparts) or (
        observed_name_keys and name_key is not None and name_key in observed_name_keys
    ):
        return GovernOutcome(DECISION_OBSERVED_COVERAGE)

    try:
        candidate = pattern_email_to_candidate(
            pe, mode=mode, company=None, suppression_index=suppression_index
        )
    except Exception:
        # A governance/grading failure is an ERROR — never a silent spray fallback.
        _LOG.warning(
            "pattern_email_to_candidate failed for %r; recording governance error",
            name,
            exc_info=True,
        )
        return GovernOutcome(DECISION_GOVERNANCE_ERROR)

    # Suppression wins outright — a suppressed subject can never resurface via a
    # pattern guess. Tombstone so no later reactive call regenerates it.
    if candidate.suppressed:
        if run_state is not None:
            run_state.tombstone(candidate.email)
        return GovernOutcome(DECISION_SUPPRESSED)

    if run_state is not None and name_key is not None:
        run_state.emitted_inference_by_person[name_key] = candidate.email
        # Brief A item 2 — register this inference with the run's canonical person
        # store (domain-scoped) so two competing inferences for the SAME person
        # (e.g. a title-driven reactive guess vs. a title-less batch guess) resolve
        # to ONE deterministic canonical selection at finalize, independent of which
        # producer emitted first.
        run_state.resolver.register_person_mailbox(
            candidate.email, person_key=name_key, kind="inferred", title=title, corpus=True
        )
    return GovernOutcome(DECISION_EMITTED, candidate=candidate)


# Verdicts that may NOT be emitted as a ready-to-send lead on their own. A pattern
# candidate is expected to land here (never ELIGIBLE by itself).
_NON_SENDABLE_VERDICTS = frozenset(
    {Eligibility.REVIEW.value, Eligibility.RESEARCH_ONLY.value, Eligibility.SUPPRESSED.value}
)


def is_ready_to_send(candidate: PatternCandidate) -> bool:
    """Whether the candidate is a ready-to-send lead on its own (it never is)."""
    return candidate.eligibility not in _NON_SENDABLE_VERDICTS


# --------------------------------------------------------------------------- #
# 0.16.0 Phase 6 — M365 oracle verification (Risky/unverified → Valid/confirmed).
#
# A corpus-pattern email is a *likely* guess. On a Microsoft 365 domain the
# existing, governance-gated ``GetCredentialType`` oracle can tell us whether the
# specific mailbox actually exists — turning that likely guess into a verified,
# sendable lead, and catching the ~15% of people who deviate from the domain's
# dominant pattern (their generated address does NOT exist → dropped). Google and
# self-hosted have no working oracle (Phase 1), so their candidates are never
# probed and stay unverified. This step does network I/O and is therefore kept
# separate from the pure, deterministic :func:`pattern_email_to_candidate`.
# --------------------------------------------------------------------------- #


def _pattern_email_from_candidate(
    candidate: PatternCandidate,
    *,
    verification: str,
    provenance: str,
) -> PatternEmail:
    """Reconstruct the source :class:`PatternEmail` from a candidate (lossless).

    Every ``PatternEmail`` field is stored on :class:`PatternCandidate`, so this
    lets the confirmed-upgrade path re-run the exact governance chain (grade,
    eligibility, observation) with the oracle result folded in.
    """
    return PatternEmail(
        email=candidate.email,
        pattern_id=candidate.pattern_id,
        support_n=candidate.support_n,
        confidence=candidate.confidence,
        applied_confidence=candidate.applied_confidence,
        # Brief C R9 — the oracle upgrade must not lose the denominator.
        considered_n=candidate.considered_n,
        confidence_basis=candidate.confidence_basis,
        mx=candidate.mx,
        role_used=candidate.role_used,
        provenance=provenance,
        verification=verification,
    )


def _uncapped_confidence_label(applied_confidence: float) -> ConfidenceLabel:
    """The natural (un-honesty-capped) confidence label for a confirmed mailbox.

    :func:`company_pattern_index.confidence_label` caps an *unverified* inference
    below the CONFIRMED band. Once the oracle confirms the mailbox exists that
    rationale is gone, so the label may honestly present at its natural band. The
    numeric score is unchanged — only the cap is lifted.
    """
    return compute_confidence_breakdown(
        [SOURCE_TYPE],
        source_confidence={SOURCE_TYPE: applied_confidence},
    )


def _upgrade_confirmed(
    candidate: PatternCandidate,
    *,
    mode: ProductMode,
    captured_at: datetime | None = None,
) -> PatternCandidate:
    """Upgrade an oracle-confirmed candidate: provider_verified / Valid / re-verdict.

    The mailbox is proven to exist, so: verification → ``provider_verified`` (a
    confirmed status the eligibility gate accepts), grade → Valid (per-mailbox
    proof), the honesty cap on the confidence label lifts, and eligibility is
    re-evaluated (it can now reach ELIGIBLE in a lead-gen mode). Provenance and
    the ledger observation record the oracle confirmation.
    """
    m = normalize_mode(mode)
    provenance = f"{candidate.provenance} + M365 oracle confirmed"
    pe = _pattern_email_from_candidate(
        candidate, verification=VERIFICATION_PROVIDER_VERIFIED, provenance=provenance
    )
    grade = grade_pattern_email(pe, mailbox_confirmed=True)  # → Valid
    label = _uncapped_confidence_label(candidate.applied_confidence)
    verdict = evaluate(
        mode=m,
        policy_status=policy_status_for_mode(m),
        suppressed=candidate.suppressed,
        confidence=label.score,
        deliverability_grade=grade.grade,
        verification=VERIFICATION_PROVIDER_VERIFIED,
    )
    return replace(
        candidate,
        verification=VERIFICATION_PROVIDER_VERIFIED,
        confidence_score=label.score,
        confidence_label=label.label,
        confidence_breakdown=dict(label.breakdown),
        deliverability_grade=grade.grade,
        deliverability=grade.as_dict(),
        eligibility=verdict.verdict.value,
        eligibility_reason=verdict.reason,
        provenance=provenance,
        observation=pattern_observation(pe, mode=m, captured_at=captured_at),
    )


def _map_existence_signal(
    candidate: PatternCandidate,
    signal: ExistenceSignal,
    *,
    mode: ProductMode,
) -> PatternCandidate | None:
    """Map one :class:`ExistenceSignal` onto the candidate. Pure, no I/O.

    * ``confirmed`` → upgraded (provider_verified / Valid / re-verdicted).
    * ``not_found`` → ``None`` (drop — the generated address does not exist; a
      known-nonexistent address must never be surfaced). This is the precision
      win: the oracle removes the pattern deviants.
    * ``inconclusive`` / ``blocked_by_mode`` / ``no_oracle`` → unchanged (honest
      degradation — a throttle or a mode that forbids active probing simply means
      "not verified", never a false upgrade).
    """
    status = (signal.status or "").strip().lower()
    if status == "confirmed":
        return _upgrade_confirmed(candidate, mode=mode)
    if status == "not_found":
        return None
    return candidate


async def verify_pattern_candidate(
    candidate: PatternCandidate,
    *,
    mode: str | ProductMode,
    verifier: Any | None = None,
    run_state: PatternRunState | None = None,
) -> PatternCandidate | None:
    """Oracle-verify ONE candidate (network I/O). See module note above.

    Fires the oracle only for ``mx == "m365"`` — no oracle exists for
    google/other (Phase 1), so probing them would waste a call. Goes through the
    governance-gated :func:`catchall_buster.confirm_mailbox` seam (mode gate +
    guards), never the verifier directly. ``verifier`` is injectable for tests.

    Root E — flag/budget parity with the batch path: this single helper now ALSO
    honours ``settings.enable_pattern_oracle_verify`` and the mode gate up front
    (previously it ignored the feature flag), and draws from the shared
    ``run_state`` oracle budget so the reactive per-name path can't reset the cap on
    every call. Root A — a ``not_found`` drop tombstones the mailbox so no later
    reactive call regenerates it.

    Returns the upgraded candidate (confirmed), ``None`` (not_found → dropped),
    or the unchanged candidate (inconclusive / blocked / no-oracle / non-m365 /
    flag-off / over budget).
    """
    from ..config import settings

    m = normalize_mode(mode)
    if (candidate.mx or "").strip().lower() != _ORACLE_MX:
        return candidate
    if not getattr(settings, "enable_pattern_oracle_verify", True):
        return candidate
    from .catchall_buster import is_bust_allowed

    if not is_bust_allowed(m):
        return candidate

    # Brief A item 3 — route through the resolver's single-flight so concurrent
    # duplicate workers share ONE verification (and one budget draw), a mailbox with
    # a retained terminal decision is reused without re-probing, and a terminal
    # negative retracts the mailbox before any joined waiter observes it. Without a
    # run-state (standalone/test call) fall back to a direct, budget-free probe.
    if run_state is None:
        signal = await confirm_mailbox(
            candidate.email, provider=_ORACLE_MX, mode=m, verifier=verifier
        )
        return _map_existence_signal(candidate, signal, mode=m)

    run_state.seed_oracle_budget(
        int(getattr(settings, "pattern_oracle_max_verifications_per_run", 50))
    )

    async def _runner() -> Any:
        # Budget is reserved only when THIS producer is the one that actually probes
        # (the single-flight guarantees runner fires at most once per mailbox). A
        # zero grant means the shared run budget is exhausted — surface an
        # inconclusive signal so the candidate stays unverified, never dropped.
        if run_state.reserve_oracle(1) < 1:
            return SimpleNamespace(
                email=candidate.email, status="inconclusive", exists=None
            )
        return await confirm_mailbox(
            candidate.email, provider=_ORACLE_MX, mode=m, verifier=verifier
        )

    signal = await run_state.resolver.verify_once(candidate.email, runner=_runner)
    return _map_existence_signal(candidate, signal, mode=m)


async def verify_pattern_candidates(
    candidates: list[PatternCandidate],
    *,
    mode: str | ProductMode,
    verifier: Any | None = None,
    max_verifications: int | None = None,
    run_state: PatternRunState | None = None,
) -> list[PatternCandidate | None]:
    """Batched oracle verification for a harvest run (one ``verify_batch`` call).

    Returns a list positionally aligned with ``candidates``: the upgraded
    candidate (confirmed), ``None`` (not_found → drop), or the unchanged
    candidate (everything else, incl. non-m365 and over-budget).

    Self-limiting and budgeted:

    * If ``settings.enable_pattern_oracle_verify`` is off, or the mode forbids
      active probing (public-business-contact), NO candidate is probed — all pass
      through unchanged and no oracle client is constructed.
    * Only ``mx == "m365"`` candidates are eligible; the rest pass through.
    * The oracle budget is drawn from ``run_state`` (shared across the whole run —
      Root E) when supplied, else from ``max_verifications`` / the setting for a
      single call. Candidates beyond the budget stay unverified (never dropped).
      Batching amortises latency and rate-limit pressure; the M365 verifier groups
      the batch by domain/tenant so a mixed-domain batch is cross-tenant-safe.
    * Root A — a ``not_found`` drop tombstones the mailbox in ``run_state`` so no
      later reactive call regenerates it.
    """
    from ..config import settings

    results: list[PatternCandidate | None] = list(candidates)
    if not candidates:
        return results

    m = normalize_mode(mode)
    if not getattr(settings, "enable_pattern_oracle_verify", True):
        return results
    # Mirror the seam's own gate up front so we neither construct a client nor
    # consume budget when active probing is not permitted in this mode.
    from .catchall_buster import is_bust_allowed

    if not is_bust_allowed(m):
        return results

    default_budget = (
        int(getattr(settings, "pattern_oracle_max_verifications_per_run", 50))
        if max_verifications is None
        else int(max_verifications)
    )
    state = run_state if run_state is not None else PatternRunState()
    state.seed_oracle_budget(default_budget)
    eligible = [i for i, c in enumerate(candidates) if (c.mx or "").strip().lower() == _ORACLE_MX]

    async def runner(emails: list[str]) -> list[Any]:
        grant = state.reserve_oracle(len(emails))
        if not grant:
            return []
        return await confirm_mailboxes(
            emails[:grant], provider=_ORACLE_MX, mode=m, verifier=verifier
        )

    signals = await state.resolver.verify_many(
        [candidates[i].email for i in eligible], runner=runner
    )
    for i, signal in zip(eligible, signals):
        results[i] = _map_existence_signal(candidates[i], signal, mode=m)
    return results
