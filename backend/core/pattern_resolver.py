"""0.16.0 re-audit Brief A — the ONE run-scoped canonical resolver.

The 0.16.0 governed name->email path is exercised from several asynchronous
producers (the reactive per-name worker, the batch module, the M365 oracle
callbacks) and consumed by final aggregation, the signal-pool candidate views,
persistence, cache reconstruction and exports. Before this module those producers
and consumers each carried their own partial authority:

* :func:`pattern_candidate.verify_pattern_candidate` recorded oracle negatives only
  as *future-generation* tombstones — never retracting an inference already
  emitted by a racing producer.
* ``harvest_runner._record_module_result`` *replaced* batch results while
  ``_accumulate_pattern_findings`` *appended* reactive ones, so arrival order and
  the accumulating-vs-overwriting seam decided which survived.
* ``domain_harvest_orchestrator._aggregate`` derived verification from separately
  supplied finding fields, and ``_reconcile_pattern_inferences_by_person`` treated
  a *missing* verification field as evidence of observation.

This resolver replaces those competing authorities with a single retained
projection for one harvest run. Every generation path, every oracle callback and
final aggregation submit evidence to it and consume its projection, so the final
result is a pure function of the retained evidence and oracle outcomes —
independent of reactive/batch arrival order, oracle completion order, budget
exhaustion, duplicate generation, or whether a producer used current or legacy
metadata.

The resolver never does network I/O itself; the oracle probe is injected as a
``runner`` coroutine (:meth:`CanonicalResolver.verify_once`) so the transport and
budget policy stay in :mod:`pattern_candidate`, while the *single-flight* and
*retention* semantics live here.
"""

from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from .email_confidence import is_inference_source

# --------------------------------------------------------------------------- #
# Evidence kinds — normalized ONCE, at ingestion (Brief A item 1).
# --------------------------------------------------------------------------- #

#: A genuine per-mailbox / identity observation (a real sighting or an affirmative
#: verification). Anchors a person and always beats an inference for the mailbox.
EVIDENCE_OBSERVED = "observed"
#: A generated / learned-pattern guess (permutation spray or company-pattern
#: index). Never anchors a person and caps the lead at REVIEW unless an oracle
#: confirms the specific mailbox.
EVIDENCE_INFERRED = "inferred"
#: Neither an affirmative observation nor a flagged inference — a source we can
#: neither confirm nor restrict. Unknown evidence can never *lift* an inference
#: restriction, and its absence of a verification field is not proof of observation.
EVIDENCE_UNKNOWN = "unknown"

#: Verification statuses (from the new ``verification`` field OR the legacy
#: ``verification_status`` / SMTP / provider status fields) that establish an
#: affirmative per-mailbox confirmation. Mirrors ``eligibility._CONFIRMED_VERIFICATIONS``
#: — the shared contract, kept literal here to avoid an import cycle.
_CONFIRMED_VERIFICATIONS = frozenset(
    {"verified", "confirmed", "smtp_verified", "provider_verified", "valid"}
)

#: The confirmed verification a Phase-6 M365 oracle stamps on a corpus candidate.
VERIFICATION_PROVIDER_VERIFIED = "provider_verified"
#: The canonical unverified status for a pure inference.
VERIFICATION_UNVERIFIED = "unverified"

#: Sentinel returned by :meth:`CanonicalResolver.mailbox_verification` when the
#: mailbox has a retained terminal *negative* oracle decision and must be dropped
#: from every current projection (never merely capped).
DROP = "__drop__"


def normalize_email(email: str | None) -> str:
    """Lowercase/strip an address for use as a mailbox key (local@domain)."""
    return (email or "").strip().lower()


def person_key(name: str | None) -> tuple[str, str] | None:
    """Preserve middle tokens when associating evidence; template keys cannot do this."""
    from .company_pattern_index import _index_norm

    tokens = [_index_norm(t) for t in (name or "").split()]
    if not tokens or any(not t for t in tokens):
        return None
    return (" ".join(tokens[:-1]) or tokens[0], tokens[-1])


def _split(email: str) -> tuple[str, str]:
    local, _, domain = normalize_email(email).partition("@")
    return local, domain


def _confirmed_status(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() in _CONFIRMED_VERIFICATIONS


def classify_evidence_kind(meta: dict[str, Any] | None) -> str:
    """Normalize a finding/signal metadata dict to ONE evidence kind.

    The single ingestion-time contract (Brief A item 1). It consumes every marker
    a producer might carry — the scalar ``source_type``; ``source_types`` /
    ``all_sources`` collections; the ``is_inference`` / ``generated`` flags; the
    legacy ``verification_status``; SMTP / provider status fields; and the new
    ``verification`` field — and collapses them to ``observed`` / ``inferred`` /
    ``unknown`` under three rules:

    * an affirmative confirmation (any of the fields above naming a confirmed
      status) is ``observed``, even when the source began life as an inference
      (e.g. an SMTP-verified permutation) — a real probe is a real observation;
    * otherwise a flagged inference (``is_inference`` / ``generated``), an
      inference-family source-type (``permutation_*`` / ``company_pattern_index``),
      or an explicit ``unverified`` verification/``verification_status`` is
      ``inferred`` — a *missing* verification field is **not** what makes it
      inferred, and its absence never upgrades it to observed;
    * everything else — a plain sighting with no verification claim and no
      inference marker (e.g. a Common-Crawl email) — is ``observed`` (a genuine
      observation), while a truly empty/unclassifiable metadata is ``unknown``.
    """
    if not isinstance(meta, dict):
        return EVIDENCE_UNKNOWN

    # 1. Affirmative confirmation wins outright — a probe/attestation is observed.
    if (
        _confirmed_status(meta.get("verification_status"))
        or _confirmed_status(meta.get("smtp_verification_status"))
        or _confirmed_status(meta.get("provider_verification_status"))
        or _confirmed_status(meta.get("verification"))
        or meta.get("source_type") in ("ca_attested", "pgp_uid")
    ):
        return EVIDENCE_OBSERVED

    # 2. An explicit inference marker — flag, inference-family source, or an
    #    explicit unverified status (new field OR legacy verification_status).
    sources: set[str] = set()
    for key in ("source_type", "source_types", "all_sources"):
        val = meta.get(key)
        if isinstance(val, list | tuple | set):
            sources.update(str(s) for s in val)
    st = meta.get("source_type")
    if isinstance(st, str):
        sources.add(st)
    inference_flag = bool(meta.get("is_inference")) or bool(meta.get("generated"))
    inference_source = any(is_inference_source(s) for s in sources)
    explicit_unverified = (
        str(meta.get("verification") or "").strip().lower() == VERIFICATION_UNVERIFIED
        or str(meta.get("verification_status") or "").strip().lower() == VERIFICATION_UNVERIFIED
    )
    if inference_flag or inference_source or explicit_unverified:
        return EVIDENCE_INFERRED

    # 3. A concrete source-type that is neither a confirmation nor an inference
    #    family is a genuine observation; an empty/opaque metadata is unknown.
    if isinstance(st, str) and st.strip():
        return EVIDENCE_OBSERVED
    if sources and not inference_source:
        return EVIDENCE_OBSERVED
    return EVIDENCE_UNKNOWN


# --------------------------------------------------------------------------- #
# Retained mailbox decisions + person association.
# --------------------------------------------------------------------------- #


@dataclass
class _MailboxDecision:
    """Retained oracle state for ONE mailbox (Brief A item 3).

    ``decision`` is the terminal projection: ``none`` (undecided), ``confirmed``,
    ``not_found``, or ``conflict`` (an unresolved positive/negative disagreement —
    kept, but never automatically eligible). ``signal`` is the object returned to a
    reuse/join caller so a resolved mailbox is never re-probed.
    """

    email: str
    decision: str = "none"
    signal: Any | None = None

    @property
    def terminal(self) -> bool:
        return self.decision in ("confirmed", "not_found", "conflict")


@dataclass
class _PersonMailbox:
    email: str
    kind: str  # observed | confirmed | inferred
    has_title: bool = False
    title: str = ""
    corpus: bool = False


class CanonicalResolver:
    """The single run-scoped authority over mailbox evidence and person choice.

    All state is per-harvest and mutated only from the harvest's own event loop, so
    the synchronous sections are race-free under asyncio's cooperative scheduling;
    :meth:`verify_once` is the sole coroutine and is single-flight per mailbox.
    """

    def __init__(self) -> None:
        # Mailboxes that must NEVER be (re)emitted as an inference — a terminal
        # oracle ``not_found``, a suppressed subject, a superseded guess.
        self.tombstones: set[str] = set()
        # Retained per-mailbox oracle decisions.
        self._mailbox: dict[str, _MailboxDecision] = {}
        # In-flight single-flight verification futures, keyed by mailbox.
        self._pending: dict[str, asyncio.Future] = {}
        # Person (domain, first, last) -> {mailbox -> _PersonMailbox}.
        self._person: dict[tuple[str, str, str], dict[str, _PersonMailbox]] = {}
        self._mailbox_people: dict[str, set[tuple[str, str, str]]] = {}
        self._retained_findings: dict[str, dict[str, dict[str, Any]]] = {}
        self._retained_results: dict[str, Any] = {}

    def retain_result(self, module: str, result: Any) -> None:
        """Retain evidence before module replacement can discard an observation."""
        if result is None:
            return
        bucket = self._retained_findings.setdefault(module, {})
        for finding in result.findings or []:
            if not isinstance(finding, dict):
                continue
            key = json.dumps(finding, sort_keys=True, default=str, ensure_ascii=False)
            if key not in bucket:
                bucket[key] = copy.deepcopy(finding)
                meta = finding.get("metadata") or {}
                if not isinstance(meta, dict):
                    continue
                email = meta.get("email")
                statuses = {
                    str(meta.get(name) or "").strip().lower()
                    for name in (
                        "verification",
                        "verification_status",
                        "smtp_verification_status",
                        "provider_verification_status",
                    )
                }
                if email and "not_found" in statuses:
                    self.record_signal(email, SimpleNamespace(email=email, status="not_found"))
                elif email and "provider_verified" in statuses:
                    self.record_signal(email, SimpleNamespace(email=email, status="confirmed"))
        retained = copy.copy(result)
        retained.findings = list(bucket.values())
        self._retained_results[module] = retained

    def retained_results(self, results: dict[str, Any]) -> dict[str, Any]:
        """Ingest new results and return the accumulated evidence projection."""
        for module, result in results.items():
            self.retain_result(module, result)
        return dict(self._retained_results)

    # -- tombstones -------------------------------------------------------- #

    def tombstone(self, email: str) -> None:
        e = normalize_email(email)
        if e:
            self.tombstones.add(e)

    def is_tombstoned(self, email: str) -> bool:
        return normalize_email(email) in self.tombstones

    # -- retained oracle decisions ---------------------------------------- #

    def record_signal(self, email: str, signal: Any) -> None:
        """Fold ONE oracle result into the retained mailbox decision.

        Confirmation is sticky and an unverified/inconclusive result can never
        overwrite it; a terminal negative retracts the mailbox (tombstone + drop);
        a positive and a negative for the same mailbox produce an unresolved
        ``conflict`` that is retained but never automatically eligible — resolving
        it requires an explicit re-verification, never last-arrival-wins.
        """
        key = normalize_email(email)
        if not key:
            return
        status = str(getattr(signal, "status", "") or "").strip().lower()
        rec = self._mailbox.setdefault(key, _MailboxDecision(email=key))
        if status == "confirmed":
            if rec.decision == "not_found":
                rec.decision = "conflict"
                self.tombstones.discard(key)
                rec.signal = SimpleNamespace(email=key, status="inconclusive", exists=None)
            elif rec.decision != "conflict":
                rec.decision = "confirmed"
                rec.signal = signal
        elif status == "not_found":
            if rec.decision == "confirmed":
                rec.decision = "conflict"
                rec.signal = SimpleNamespace(email=key, status="inconclusive", exists=None)
            elif rec.decision != "conflict":
                rec.decision = "not_found"
                rec.signal = signal
                self.tombstone(key)
        else:
            # Inconclusive / throttled / blocked — non-terminal. Never overwrite a
            # terminal decision; only fill an empty slot so a reuse caller has a
            # signal object to map to "unchanged".
            if rec.decision == "none" and rec.signal is None:
                rec.signal = signal

    def decision_for(self, email: str) -> str:
        rec = self._mailbox.get(normalize_email(email))
        return rec.decision if rec is not None else "none"

    def signal_for(self, email: str) -> Any | None:
        """The retained oracle signal object for a mailbox (for reuse projection)."""
        rec = self._mailbox.get(normalize_email(email))
        return rec.signal if rec is not None else None

    def is_rejected(self, email: str) -> bool:
        """Whether a retained terminal negative means this mailbox must be dropped."""
        return self.decision_for(email) == "not_found"

    def is_visible(self, email: str, *, inferred: bool) -> bool:
        key = normalize_email(email)
        if self.is_rejected(key) or (inferred and self.is_tombstoned(key)):
            return False
        if inferred:
            for domain, first, last in self._mailbox_people.get(key, ()):
                _, retired = self.canonical_person_email((first, last), domain)
                if key in retired:
                    return False
        return True

    def mailbox_verification(self, email: str) -> str | None:
        """The verification the retained oracle decision projects, or ``None``.

        * ``confirmed`` -> ``provider_verified`` (lifts the honesty cap / eligibility);
        * ``not_found`` -> :data:`DROP` (exclude from every current projection);
        * ``conflict``  -> ``unverified`` (kept, but never automatically eligible);
        * otherwise ``None`` (no oracle claim — evidence-derived verification stands).
        """
        decision = self.decision_for(email)
        if decision == "confirmed":
            return VERIFICATION_PROVIDER_VERIFIED
        if decision == "not_found":
            return DROP
        if decision == "conflict":
            return VERIFICATION_UNVERIFIED
        return None

    async def verify_once(self, email: str, *, runner: Any) -> Any:
        """Single-flight oracle verification for ONE mailbox (Brief A item 3).

        Guarantees at most one real verification per mailbox across the whole run,
        no matter how many producers request it concurrently:

        * a mailbox with a retained *terminal* decision reuses it — ``runner`` is
          not called, so no oracle request and no budget draw;
        * a mailbox with an in-flight verification joins the existing operation and
          shares its outcome (a budget-exhausted or duplicate producer therefore
          reuses the pending/resolved state rather than issuing a second probe);
        * only the first producer runs ``runner`` (which reserves budget and does
          the transport), and its result is retained before any waiter observes it,
          so a callback can never append a candidate after its own rejection.

        ``runner`` is an ``async`` callable returning the oracle signal object
        (with a ``.status``); it is invoked at most once per mailbox.
        """
        key = normalize_email(email)
        rec = self._mailbox.get(key)
        if rec is not None and rec.terminal:
            return rec.signal
        pending = self._pending.get(key)
        if pending is not None:
            return await asyncio.shield(pending)
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        fut.add_done_callback(lambda f: None if f.cancelled() else f.exception())
        self._pending[key] = fut
        try:
            signal = await runner()
        except BaseException as exc:  # noqa: BLE001 - propagate to joined waiters
            self._pending.pop(key, None)
            if not fut.done():
                fut.set_exception(exc)
            raise
        # Retain BEFORE resolving waiters so no joiner can observe a decision the
        # store has not yet recorded (the retract-before-append guarantee).
        self.record_signal(key, signal)
        self._pending.pop(key, None)
        if not fut.done():
            fut.set_result(self.signal_for(key) or signal)
        return self.signal_for(key) or signal

    async def verify_many(self, emails: list[str], *, runner: Any) -> list[Any]:
        """Claim new mailboxes before I/O; join single and batch owners alike.

        The runner reserves the shared budget for unique owned addresses only.
        Waiters are shielded so cancelling one consumer cannot cancel its peers.
        """
        owned: dict[str, asyncio.Future] = {}
        waits: dict[str, asyncio.Future] = {}
        for email in emails:
            key = normalize_email(email)
            if self.decision_for(key) != "none":
                continue
            pending = self._pending.get(key)
            if pending is None:
                pending = asyncio.get_running_loop().create_future()
                pending.add_done_callback(lambda f: None if f.cancelled() else f.exception())
                self._pending[key] = pending
                owned[key] = pending
            waits[key] = pending
        if owned:
            try:
                signals = await runner(list(owned))
                by_email = {normalize_email(s.email): s for s in signals}
                for key, future in owned.items():
                    signal = by_email.get(key) or SimpleNamespace(
                        email=key, status="inconclusive", exists=None
                    )
                    self.record_signal(key, signal)
                    self._pending.pop(key, None)
                    future.set_result(self.signal_for(key) or signal)
            except BaseException as exc:
                for key, future in owned.items():
                    self._pending.pop(key, None)
                    if not future.done():
                        future.set_exception(exc)
                raise
        for future in waits.values():
            await asyncio.shield(future)
        return [
            self.signal_for(e)
            or SimpleNamespace(email=normalize_email(e), status="inconclusive", exists=None)
            for e in emails
        ]

    # -- person association ------------------------------------------------ #

    def register_person_mailbox(
        self,
        email: str,
        *,
        person_key: tuple[str, str] | None,
        kind: str,
        title: str | None = None,
        corpus: bool = False,
    ) -> None:
        """Associate a mailbox with a person, domain-scoped (Brief A item 2).

        ``person_key`` is the ``(first, last)`` name key; the domain is taken from
        the address so two unrelated people whose first/last tokens collide across
        different employers are never merged.
        """
        if person_key is None:
            return
        e = normalize_email(email)
        _, domain = _split(e)
        if not e or not domain:
            return
        key = (domain, person_key[0], person_key[1])
        self._mailbox_people.setdefault(e, set()).add(key)
        bucket = self._person.setdefault(key, {})
        existing = bucket.get(e)
        has_title = bool(title and str(title).strip())
        if existing is None:
            bucket[e] = _PersonMailbox(
                email=e, kind=kind, has_title=has_title, title=str(title or ""), corpus=corpus
            )
        else:
            # Upgrade the retained kind (observed > confirmed > inferred) and keep
            # any title evidence — order-independent.
            existing.kind = _stronger_kind(existing.kind, kind)
            existing.corpus = existing.corpus or corpus
            if has_title and not existing.has_title:
                existing.has_title = True
                existing.title = str(title or "")

    def canonical_person_email(
        self, person_key: tuple[str, str] | None, domain: str
    ) -> tuple[str | None, list[str]]:
        """Deterministically select ONE mailbox for a person; return the retired rest.

        Selection order (order-independent — arrival is never a tie-breaker):
        observed ahead of oracle-confirmed generated, ahead of a title-backed
        inference, ahead of a plain inference; ties broken by the lexicographically
        smallest address. Returns ``(chosen, superseded_inferences)`` where the
        superseded list contains only *inferred* mailboxes to retire (a real
        observation is never retired). ``chosen`` is ``None`` when the person has no
        associated mailbox.
        """
        if person_key is None:
            return None, []
        key = (normalize_email(domain).split("@")[-1], person_key[0], person_key[1])
        bucket = self._person.get(key)
        if not bucket:
            return None, []
        if not any(m.corpus or m.kind != "inferred" for m in bucket.values()):
            return None, []  # Legacy unindexed spray keeps its existing contract.
        ranked = sorted(
            (m for m in bucket.values() if not self.is_tombstoned(m.email)),
            key=lambda m: _selection_key(
                _PersonMailbox(
                    m.email,
                    "confirmed"
                    if m.kind != "observed" and self.decision_for(m.email) == "confirmed"
                    else "inferred"
                    if m.kind != "observed" and self.decision_for(m.email) == "conflict"
                    else m.kind,
                    m.has_title,
                    m.title,
                    m.corpus,
                )
            ),
        )
        if not ranked:
            return None, []
        chosen = ranked[0].email
        superseded = [m.email for m in ranked[1:] if m.kind != "observed" and m.email != chosen]
        return chosen, superseded


def _stronger_kind(a: str, b: str) -> str:
    order = {"observed": 0, "confirmed": 1, "inferred": 2}
    return a if order.get(a, 3) <= order.get(b, 3) else b


def _selection_key(m: _PersonMailbox) -> tuple[int, int, int, str]:
    kind_rank = {"observed": 0, "confirmed": 1, "inferred": 2}.get(m.kind, 3)
    title_rank = 0 if m.has_title else 1
    return (kind_rank, 0 if m.corpus else 1, title_rank, m.email)
