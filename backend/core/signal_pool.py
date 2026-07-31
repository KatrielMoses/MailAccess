"""AsyncSignalPool — central pub/sub memory space for the harvest loop.

The pool is the orchestration spine of the Phase-7 workstream: every raw
finding (name, slug, email, social URL, schema.org metadata, avatar
pHash, target-domain match) is published as a :class:`Signal` and gets
folded into a :class:`CandidatePerson` cluster.  The pool is consumed by
the export layer (CLI / API / identity graph) instead of returning
``ModuleResult``-shaped dicts from each phase.

Async-safety model
------------------

* One ``asyncio.Lock`` guards the cluster index.  We hold the lock only
  long enough to insert/merge a single signal — never across I/O.
* One drain :class:`asyncio.Task` per pool, lazily started on first
  publish, processes the queue under that lock.
* Publishers use :meth:`asyncio.Queue.put_nowait`.  When the queue is
  full we drop and count — we **never** block the harvest event loop
  from a producer coroutine.
* :meth:`AsyncSignalPool.close` flushes the queue before terminating
  the drain task so no signals are lost on shutdown.

Scoring model
-------------

Base score starts at :attr:`AsyncSignalPool.base_score` (0.1 by default).
Three documented confidence boosters apply at most once per cluster,
identically to the Phase-2 ``IdentityGraph`` model —

================  ============  ============================
flag              multiplier    meaning
================  ============  ============================
target_domain     x2.0          social URL host == target
worksfor          x2.5          schema.org/Person.worksFor
                                  matches the target org
avatar_phash      x1.5          at least two pages share a
                                  perceptual hash
================  ============  ============================

The boosters are flags, not counters — pushing ten ``target_domain``
signals into a cluster still applies the multiplier exactly once.
This is the same policy as the Phase-2 :class:`IdentityGraph`
multiplicative stack and the Phase-2 boost doc warns about it.

Stacking math
-------------

The composite score is the base score multiplied by the present
boosters' multipliers.  All three boosters firing gives::

    0.1 * 2.0 * 2.5 * 1.5 = 0.75

Two-booster combinations land in the 0.30–0.50 range, so the only
two-booster combination that clears the default ``0.5`` export
threshold is ``(target_domain × worksfor) = 0.5`` exactly.  This
threshold/gate combination is intentional — it requires either the
Schema.org ``worksFor`` brand assertion combined with a target-domain
hit, or all three boosters — both of which are strong identity
signals on their own.  Callers that want different gating can
instantiate a pool with a lower ``export_threshold``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .work_scheduler import WorkItem, WorkScheduler

from .signal_normalize import canonical_key

logger = logging.getLogger(__name__)


# Public ------------------------------------------------------------------------


#: Recognised signal kinds.  Modules should pick from this set when
#: publishing; unknown kinds fall back to ``"other"`` after logging.
VALID_SIGNAL_KINDS: frozenset[str] = frozenset(
    {
        "name",
        "slug",
        "email",
        "social_url",
        "schema",
        "avatar_phash",
        "target_domain",
        "other",
    }
)

#: Allowed boost flags.  Boosters apply at most once per cluster;
#: duplicate flags in subsequent signals are idempotent.  Unknown
#: flags raise :class:`ValueError` on :class:`Signal` construction so
#: we never silently lose a booster.
VALID_BOOST_FLAGS: frozenset[str] = frozenset(
    {
        "target_domain_match",
        "worksfor_match",
        "avatar_phash_match",
    }
)

#: Multiplier applied per booster when present.  Order-independent —
#: the cluster stores the *set* of flags and recomputes from this map.
BOOST_MULTIPLIERS: Mapping[str, float] = {
    "target_domain_match": 2.0,
    "worksfor_match": 2.5,
    "avatar_phash_match": 1.5,
}

HIGH_TIER_THRESHOLD: float = 3.0
MEDIUM_TIER_THRESHOLD: float = 1.5
LOW_TIER_THRESHOLD: float = 0.5

_DEFAULT_QUEUE_MAXSIZE: int = 4096


def export_tier_for_score(score: float) -> str | None:
    """Translate a finalized composite score into an export tier."""
    if score >= HIGH_TIER_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_TIER_THRESHOLD:
        return "MEDIUM"
    if score >= LOW_TIER_THRESHOLD:
        return "LOW"
    return None


@dataclass(slots=True)
class Signal:
    """One raw finding published into the pool.

    Fields
    ------

    source:      The module that produced the signal (e.g. ``"maigret"``,
                 ``"username_pivot"``, ``"avatar_hasher"``).
    kind:        The kind of finding (see :data:`VALID_SIGNAL_KINDS`).
                 Unknown kinds log a warning and fall back to ``"other"``.
    value:       The signal payload — display name, slug, email, URL,
                 schema.org JSON string, perceptual-hash string, etc.
    metadata:    Optional dict carried alongside the signal so consumers
                 can introspect ``schema.org`` payloads, ``platform``,
                 ``profile_url``, etc.
    ts:          Ingest timestamp (epoch seconds).  Defaults to the
                 publish time — callers may overwrite for back-dating.
    flags:       A :class:`frozenset` of booster identifiers from
                 :data:`VALID_BOOST_FLAGS`.  Each flag can appear at
                 most once; passing an unknown flag raises
                 :class:`ValueError`.
    """

    source: str
    kind: str
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    flags: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("Signal.source must be a non-empty module name")
        if not self.kind:
            self.kind = "other"
        if self.kind not in VALID_SIGNAL_KINDS:
            logger.warning(
                "Signal kind %r is not in VALID_SIGNAL_KINDS; falling back to 'other'",
                self.kind,
            )
            self.kind = "other"
        if not self.value:
            raise ValueError("Signal.value must be a non-empty string")
        for flag in self.flags:
            if flag not in VALID_BOOST_FLAGS:
                raise ValueError(
                    f"unknown boost flag {flag!r}; expected one of {sorted(VALID_BOOST_FLAGS)}"
                )


@dataclass(slots=True)
class CandidatePerson:
    """One deduplicated identity cluster.

    Equality is based on the canonical key only — two clusters with
    the same ``canonical_key`` are the same person.  Comparison on
    `(canonical_key,)` is sufficient for storage in a dict.
    """

    canonical_key: tuple[str | None, str | None]
    signals: list[Signal] = field(default_factory=list)
    score: float = 0.0
    boost_flags: set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0

    def recompute_score(self, base_score: float = 0.1) -> float:
        """Recompute the multiplicative composite score.

        Idempotent — the result depends only on ``base_score`` and
        :attr:`boost_flags`, not on how many times each flag was
        pushed.  Returns the new score and updates :attr:`score` in
        place.
        """
        score = base_score
        for flag, multiplier in BOOST_MULTIPLIERS.items():
            if flag in self.boost_flags:
                score *= multiplier
        self.score = score
        return score

    def merged_signals(self) -> dict[str, int]:
        """Count signals per source module — useful for export metadata."""
        return dict(Counter(sig.source for sig in self.signals))

    @property
    def has_name(self) -> bool:
        """True if the canonical key carries a usable display name."""
        return bool(self.canonical_key[0])

    @property
    def has_slug(self) -> bool:
        """True if the canonical key carries a usable slug/email local-part."""
        return bool(self.canonical_key[1])

    @property
    def export_tier(self) -> str | None:
        """HIGH/MEDIUM/LOW tier for the finalized composite score."""
        return export_tier_for_score(self.score)


@dataclass(slots=True)
class PoolStats:
    """Snapshot returned from :meth:`AsyncSignalPool.stats`."""

    clusters: int
    signals: int
    exports: int
    dropped: int


class AsyncSignalPool:
    """Central pub/sub memory space for the harvest event loop.

    Lifecycle::

        pool = AsyncSignalPool()
        await pool.publish(signal)         # fire-and-forget, non-blocking
        await pool.publish_many([...])
        await pool.close()                  # flushes pending signals
        ready = await pool.export_ready()   # >= threshold, sorted

    All async-safe: multiple producers can call :meth:`publish` from
    any number of coroutines.  The internal drain task is single-flight;
    cluster mutations happen under a single ``asyncio.Lock``.
    """

    def __init__(
        self,
        base_score: float = 0.1,
        export_threshold: float = 0.5,
        queue_maxsize: int = _DEFAULT_QUEUE_MAXSIZE,
    ) -> None:
        if base_score < 0:
            raise ValueError("base_score must be non-negative")
        self._base_score = base_score
        self._export_threshold = export_threshold

        self._lock = asyncio.Lock()
        self._queue: asyncio.Queue[Signal | None] = asyncio.Queue(maxsize=queue_maxsize)
        # sentinel pushed onto the queue at close-time to terminate the
        # drain loop after the last real signal has been processed.
        self._close_sentinel: Signal | None = None
        self._drain_task: asyncio.Task[None] | None = None
        self._drain_started = asyncio.Event()

        self._clusters: dict[tuple[str | None, str | None], CandidatePerson] = {}
        self._total_signals = 0
        self._dropped = 0
        self._export_count = 0
        self._closed = False
        self._emails_by_domain: dict[str, dict[str, dict[str, Any]]] = {}
        self._names_by_domain: dict[str, dict[str, dict[str, Any]]] = {}
        self._confirmed_patterns: list[str] = []
        self._name_subscribers: list[
            Callable[[str, str, dict[str, Any]], Awaitable[list[WorkItem]] | list[WorkItem]]
        ] = []
        self._email_subscribers: list[
            Callable[[str, str, dict[str, Any]], Awaitable[list[WorkItem]] | list[WorkItem]]
        ] = []
        self._display_subscribers: list[Callable[[Signal], Any]] = []
        self._scheduler: WorkScheduler | None = None
        self._dispatch_tasks: set[asyncio.Task[Any]] = set()

    # Properties --------------------------------------------------------

    @property
    def base_score(self) -> float:
        return self._base_score

    @property
    def export_threshold(self) -> float:
        return self._export_threshold

    def register_name_subscriber(
        self,
        callback: Callable[[str, str, dict[str, Any]], Awaitable[list[WorkItem]] | list[WorkItem]],
    ) -> None:
        """Register a subscriber to be invoked when a name signal is emitted."""
        self._name_subscribers.append(callback)

    def register_email_subscriber(
        self,
        callback: Callable[[str, str, dict[str, Any]], Awaitable[list[WorkItem]] | list[WorkItem]],
    ) -> None:
        """Register a subscriber to be invoked when an email signal is emitted."""
        self._email_subscribers.append(callback)

    def register_display_subscriber(
        self, callback: Callable[[Signal], Any]
    ) -> None:
        """Register a best-effort observer for every newly absorbed signal."""
        self._display_subscribers.append(callback)

    def set_scheduler(self, scheduler: WorkScheduler) -> None:
        """Set the scheduler to which subscribers can submit WorkItems."""
        self._scheduler = scheduler

    # Producer API ------------------------------------------------------

    async def publish(self, signal: Signal) -> None:
        """Push one signal onto the ingestion queue.

        Never blocks the event loop — on a full queue we increment the
        dropped counter and return so the caller can keep producing.
        The lazy drain task is started on first call.
        """
        if self._closed:
            logger.warning(
                "AsyncSignalPool.publish called after close(); dropping signal from %s (kind=%s)",
                signal.source,
                signal.kind,
            )
            self._dropped += 1
            return
        self._ensure_drain_task()
        try:
            self._queue.put_nowait(signal)
        except asyncio.QueueFull:
            self._dropped += 1
            logger.warning(
                "AsyncSignalPool queue is full (maxsize=%d); dropped signal from %s",
                self._queue.maxsize,
                signal.source,
            )

    async def publish_many(self, signals: Iterable[Signal]) -> None:
        """Convenience wrapper for batched publishes.

        Each signal is published individually so the dropped-counter
        semantics are consistent with :meth:`publish`.  Empty input
        is a no-op.
        """
        for signal in signals:
            await self.publish(signal)

    def emit_email(
        self,
        email: str,
        source: str,
        confidence: float = 0.5,
        **metadata: Any,
    ) -> None:
        """Synchronously index an email signal and enqueue it for clustering."""
        cleaned = (email or "").strip().lower()
        if not cleaned or "@" not in cleaned:
            return
        domain = cleaned.rsplit("@", 1)[-1]
        bucket = self._emails_by_domain.setdefault(domain, {})
        existing = bucket.setdefault(
            cleaned,
            {"email": cleaned, "sources": set(), "confidence": 0.0, "metadata": {}},
        )
        existing["sources"].add(source)
        existing["confidence"] = max(float(existing["confidence"]), float(confidence))
        existing["metadata"].update(metadata)
        signal = Signal(
            source=source,
            kind="email",
            value=cleaned,
            metadata={
                "slug_or_email": cleaned,
                "email": cleaned,
                "confidence": confidence,
                **metadata,
            },
        )
        self._publish_background(signal)

    def emit_name(
        self,
        name: str,
        source: str,
        confidence: float = 0.5,
        *,
        domain: str | None = None,
        **metadata: Any,
    ) -> None:
        """Synchronously index a name signal and enqueue it for clustering."""
        cleaned = " ".join((name or "").split())
        if not cleaned:
            return
        domain_key = (domain or metadata.get("domain") or "").strip().lower()
        if domain_key:
            bucket = self._names_by_domain.setdefault(domain_key, {})
            existing = bucket.setdefault(
                cleaned.lower(),
                {"name": cleaned, "sources": set(), "confidence": 0.0, "metadata": {}},
            )
            existing["sources"].add(source)
            existing["confidence"] = max(float(existing["confidence"]), float(confidence))
            existing["metadata"].update(metadata)
        signal = Signal(
            source=source,
            kind="name",
            value=cleaned,
            metadata={"name": cleaned, "confidence": confidence, **metadata},
        )
        self._publish_background(signal)

    def emit_confirmed_pattern(self, pattern: str) -> None:
        """Record a confirmed email template, preserving first-seen priority."""
        cleaned = (pattern or "").strip()
        if cleaned and cleaned not in self._confirmed_patterns:
            self._confirmed_patterns.append(cleaned)

    def emit_hunter_pattern(self, pattern_template: str | None) -> None:
        """Record the Hunter ``data.pattern``-derived template (P1).

        Hunter reports a single most-common template per domain —
        e.g. ``"{first}.{last}"`` → ``"{first}.{last}@{domain}"`` —
        which is a *prior*, not an SMTP verification.  It is kept
        in a dedicated slot so :mod:`pattern_and_verify` can
        distinguish it from the SMTP-confirmed pattern and apply
        the asymmetric +0.30 / -0.12 boost correctly.

        A ``None`` or empty value CLEARS the slot — the operator
        can undo a prior Hunter pattern without restarting the
        process.
        """
        cleaned = (pattern_template or "").strip()
        self._hunter_pattern_template = cleaned or None

    def get_hunter_pattern(self) -> str | None:
        """Return the Hunter-derived pattern template (or ``None``)."""
        return getattr(self, "_hunter_pattern_template", None)

    def get_confirmed_patterns(self) -> list[str]:
        """Return confirmed templates in first-seen priority order."""
        return list(self._confirmed_patterns)

    def get_names_for_domain(self, domain: str) -> list[dict[str, Any]]:
        """Return indexed name signals for a domain."""
        domain_key = (domain or "").strip().lower()
        names = self._names_by_domain.get(domain_key, {})
        out: list[dict[str, Any]] = []
        for payload in names.values():
            out.append(
                {
                    "name": payload["name"],
                    "sources": sorted(payload["sources"]),
                    "confidence": payload["confidence"],
                    "metadata": dict(payload["metadata"]),
                }
            )
        return out

    def get_emails(self, domain: str | None = None) -> list[dict[str, Any]]:
        """Return indexed email signals, optionally scoped to one domain."""
        domains = (
            [(domain or "").strip().lower()]
            if domain
            else sorted(self._emails_by_domain)
        )
        out: list[dict[str, Any]] = []
        for domain_key in domains:
            for payload in self._emails_by_domain.get(domain_key, {}).values():
                out.append(
                    {
                        "email": payload["email"],
                        "sources": sorted(payload["sources"]),
                        "confidence": payload["confidence"],
                        "metadata": dict(payload["metadata"]),
                    }
                )
        return out

    def _publish_background(self, signal: Signal) -> None:
        """Best-effort bridge from sync emit helpers to async publish().

        FIX 6: when there is no running event loop the signal cannot be
        enqueued. Rather than dropping it silently, log at DEBUG and
        count it in :meth:`stats` so the loss is observable.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._dropped += 1
            logger.debug(
                "AsyncSignalPool._publish_background: no running event loop; "
                "dropped signal from %s (kind=%s)",
                signal.source,
                signal.kind,
            )
            return
        loop.create_task(self.publish(signal))

    # Drain -------------------------------------------------------------

    async def drain(self) -> None:
        """Process every queued signal under the cluster lock.

        Pulls items with a small :class:`asyncio.wait_for` so we don't
        busy-loop.  Coalesces a burst of items into one critical
        section by draining every item already queued when we wake up,
        but never holds the lock across a queue-wait — that would
        starve publishers.
        """
        while True:
            # Wait up to ~50ms for a new item so we can exit cheaply
            # if close() is called concurrently.
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=0.05)
            except asyncio.TimeoutError:
                if self._close_sentinel is not None:
                    # close() wants the drain task to exit; honour it.
                    return
                continue
            if item is None or item is self._close_sentinel:
                # Flush anything still in the queue before exiting so
                # close() really empties the buffer.
                self._close_sentinel = item
                while True:
                    try:
                        pending = self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    if pending is None or pending is self._close_sentinel:
                        continue
                    await self._absorb(pending)
                return
            await self._absorb(item)

    async def _absorb(self, signal: Signal) -> None:
        """Merge *signal* into the cluster index under the lock."""
        # Display subscribers observe every accepted signal, including
        # subdomains that intentionally have no person/email cluster key.
        for callback in tuple(self._display_subscribers):
            try:
                outcome = callback(signal)
                if asyncio.isfuture(outcome) or asyncio.iscoroutine(outcome):
                    self._track_dispatch(outcome)
            except Exception:
                logger.exception("Display subscriber %s raised", callback)

        key = canonical_key(signal.metadata.get("name"), signal.metadata.get("slug_or_email"))
        if key == (None, None):
            # Signal carried no identity payload we could key on; skip
            # rather than synthesize a fresh cluster from nothing.
            logger.debug(
                "AsyncSignalPool skipping signal with no key (source=%s kind=%s)",
                signal.source,
                signal.kind,
            )
            return
        async with self._lock:
            cluster = self._clusters.get(key)
            if cluster is None:
                cluster = CandidatePerson(
                    canonical_key=key,
                    first_seen=signal.ts,
                )
                self._clusters[key] = cluster
            cluster.signals.append(signal)
            cluster.last_seen = max(cluster.last_seen, signal.ts)
            # Boosters are flags — first occurrence wins.
            new_flags = set(signal.flags)
            added = new_flags - cluster.boost_flags
            if added:
                cluster.boost_flags |= added
            # Always recompute — covers the first-signal case where the
            # cluster has no boosters yet but should still pick up the
            # base score.
            cluster.recompute_score(base_score=self._base_score)
            self._total_signals += 1

        if signal.kind == "name" and self._name_subscribers:
            self._track_dispatch(self._dispatch_name(signal))

        if signal.kind == "email" and self._email_subscribers:
            self._track_dispatch(self._dispatch_email(signal))


    def _track_dispatch(self, awaitable: Awaitable[Any]) -> None:
        """Track subscriber work so :meth:`close` can await its completion."""
        task = asyncio.create_task(awaitable)
        self._dispatch_tasks.add(task)
        task.add_done_callback(self._dispatch_tasks.discard)

    async def _dispatch_name(self, signal: Signal) -> None:
        name = signal.metadata.get("name", signal.value)
        source = signal.source
        metadata = signal.metadata

        for cb in self._name_subscribers:
            try:
                result = cb(name, source, metadata)
                if asyncio.isfuture(result) or asyncio.iscoroutine(result):
                    items = await result
                else:
                    items = result or []
                if self._scheduler:
                    for item in items:
                        await self._scheduler.submit(item)
            except Exception:
                logger.exception("Name subscriber %s raised", cb)

    async def _dispatch_email(self, signal: Signal) -> None:
        email = signal.metadata.get("email", signal.value)
        source = signal.source
        metadata = signal.metadata

        for cb in self._email_subscribers:
            try:
                result = cb(email, source, metadata)
                if asyncio.isfuture(result) or asyncio.iscoroutine(result):
                    items = await result
                else:
                    items = result or []
                if self._scheduler:
                    for item in items:
                        await self._scheduler.submit(item)
            except Exception:
                logger.exception("Email subscriber %s raised", cb)

    # Lifecycle ---------------------------------------------------------

    async def close(self) -> None:
        """Flush pending signals and stop the drain task.

        Idempotent — calling ``close()`` twice is safe.  After
        :meth:`close` returns, :meth:`publish` records drops instead
        of enqueueing.
        """
        if self._closed:
            return
        self._closed = True
        self._ensure_drain_task()
        # Push the sentinel so the drain loop wakes up and runs to
        # completion.  If the queue is full, drain a slot first.
        while True:
            try:
                self._queue.put_nowait(self._close_sentinel)
                break
            except asyncio.QueueFull:
                # Give the drain task a chance to consume one item
                # before we try again, so we don't busy-spin here.
                await asyncio.sleep(0.01)
        if self._drain_task is not None:
            try:
                await self._drain_task
            except asyncio.CancelledError:
                logger.debug("AsyncSignalPool drain task cancelled during close")
            finally:
                self._drain_task = None
        # The drain task schedules subscriber callbacks separately.  Await
        # those callbacks before returning so name-keyed pivots are submitted
        # to the scheduler before the harvest aggregates and closes resources.
        while self._dispatch_tasks:
            await asyncio.gather(*tuple(self._dispatch_tasks), return_exceptions=True)
        self._export_count = sum(
            1 for cluster in self._clusters.values() if cluster.score >= self._export_threshold
        )

    def _ensure_drain_task(self) -> None:
        """Start the drain task lazily — exactly one per pool."""
        if self._drain_task is not None and not self._drain_task.done():
            return
        self._drain_task = asyncio.create_task(
            self.drain(),
            name="AsyncSignalPool.drain",
        )

    # Consumer API ------------------------------------------------------

    async def all_candidates(self) -> list[CandidatePerson]:
        """Return a snapshot of every cluster, copy-stable for callers."""
        async with self._lock:
            return list(self._clusters.values())

    async def export_ready(self) -> list[CandidatePerson]:
        """Return only clusters at or above :attr:`export_threshold`.

        Sorted by score descending then ``first_seen`` ascending so
        earlier-sighted candidates win tie-breaks.
        """
        async with self._lock:
            qualifying = [
                cluster
                for cluster in self._clusters.values()
                if cluster.score >= self._export_threshold
            ]
        qualifying.sort(key=lambda c: (-c.score, c.first_seen))
        return qualifying

    def stats(self) -> PoolStats:
        """Return a low-cost stats snapshot — non-async and lock-free.

        Counters are eventually consistent under concurrent publish /
        drain activity; that is appropriate for telemetry only.
        """
        return PoolStats(
            clusters=len(self._clusters),
            signals=self._total_signals,
            exports=self._export_count,
            dropped=self._dropped,
        )
