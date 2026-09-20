"""0.17.0 Phase 1 — per-key concurrency-1 FIFO queue for Pro engine calls.

The paid tier's honest framing is "unlimited searches, concurrency=1 per key
with a FIFO queue": a second concurrent request for the *same* key waits for the
first to finish (it does not error), and a small global semaphore caps total
concurrent engine calls so a burst of distinct keys can never overwhelm the
homelab box.

``/v1/enrich`` wraps its engine call in :meth:`ProQueryQueue.acquire`, which takes
the per-key lock first, then a global slot, then yields; both are released on
exit. ``asyncio.Lock`` is FIFO-fair, so queued same-key requests are served in
arrival order.

KNOWN LIMITATION (documented, not solved here): these are in-process asyncio
primitives. They serialize correctly within a single uvicorn worker but NOT
across multiple workers/processes — two workers each admit one concurrent call
per key. True cross-process serialization (e.g. a Redis lock) is a Phase-7 scale
item; for the Phase-1 single-worker deployment this is sufficient and honest.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

# Small global ceiling on total concurrent engine calls (protect the box).
_DEFAULT_GLOBAL_CONCURRENCY = 4
# C2 — a coroutine may wait at most this long to acquire its per-key lock AND a
# global slot before the request fails open. Bounds the tail so a stalled key can
# never make an independent request hang indefinitely; generous enough that ordinary
# same-key FIFO queueing is not killed. (Kept short in tests.)
_DEFAULT_ACQUIRE_TIMEOUT = 30.0


class ProQueueUnavailable(RuntimeError):
    """The bounded queue wait was exceeded — the per-key lock or a global slot could
    not be acquired within the acquire timeout. The route turns this into an
    ``unavailable`` envelope (never an indefinite hang)."""


class ProQueryQueue:
    """Per-key concurrency-1 gate + a global concurrency ceiling, with a BOUNDED
    acquire wait (C2).

    Locks are created lazily per key-hash and retained for the process lifetime
    (the set of live keys is small and bounded by paying customers, so unbounded
    growth is not a practical concern in Phase 1).
    """

    def __init__(
        self,
        *,
        global_concurrency: int = _DEFAULT_GLOBAL_CONCURRENCY,
        acquire_timeout: float = _DEFAULT_ACQUIRE_TIMEOUT,
    ) -> None:
        self._global = asyncio.Semaphore(max(1, global_concurrency))
        self._locks: dict[str, asyncio.Lock] = {}
        self._acquire_timeout = float(acquire_timeout)

    def _lock_for(self, key_hash: str) -> asyncio.Lock:
        # Single-threaded event loop: dict get/set between no awaits is atomic, so
        # no extra guard lock is needed to avoid two coroutines racing a create.
        lock = self._locks.get(key_hash)
        if lock is None:
            lock = self._locks[key_hash] = asyncio.Lock()
        return lock

    @asynccontextmanager
    async def acquire(self, key_hash: str):
        """Serialize per key, then bound globally, for the wrapped engine call.

        Order matters: the per-key lock is taken FIRST so same-key requests queue
        FIFO regardless of global-slot contention; the global slot is taken only
        once this request owns its key, so a saturated global semaphore can never
        deadlock distinct keys behind one another's per-key locks.

        C2 — both acquisitions are bounded by ``acquire_timeout``: exceeding it
        raises :class:`ProQueueUnavailable` rather than blocking forever, so four
        stalled keys can't starve a fifth. Acquisition and release are paired with
        ``acquired`` flags so a cancelled / timed-out request releases whatever it
        took (per-key lock and/or global slot) and never leaks a permit.
        """
        lock = self._lock_for(key_hash)
        lock_held = False
        slot_held = False
        try:
            try:
                await asyncio.wait_for(lock.acquire(), timeout=self._acquire_timeout)
                lock_held = True
                await asyncio.wait_for(self._global.acquire(), timeout=self._acquire_timeout)
                slot_held = True
            except asyncio.TimeoutError as exc:
                raise ProQueueUnavailable("pro queue wait exceeded") from exc
            yield
        finally:
            if slot_held:
                self._global.release()
            if lock_held:
                lock.release()


# Process-wide singleton used by the route.
_queue = ProQueryQueue()


def get_queue() -> ProQueryQueue:
    return _queue


def reset_queue_for_tests(
    *,
    global_concurrency: int = _DEFAULT_GLOBAL_CONCURRENCY,
    acquire_timeout: float = _DEFAULT_ACQUIRE_TIMEOUT,
) -> None:
    global _queue
    _queue = ProQueryQueue(
        global_concurrency=global_concurrency, acquire_timeout=acquire_timeout
    )
