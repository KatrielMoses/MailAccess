"""Circuit breaker for the JEV provider — a dead key never taxes a run.

States:

* CLOSED — calls go through. A *hard* failure (auth rejected, credits / quota
  exhausted) opens the breaker at once; *soft* failures (timeout, transport,
  rate limit, 5xx, other HTTP errors) open it after
  ``JEV_BREAKER_FAILURE_THRESHOLD`` consecutive occurrences.
* OPEN — every ``judge()`` DEFERs instantly (``circuit_open``, no network) until
  ``JEV_BREAKER_COOLDOWN_SECONDS`` have passed.
* HALF-OPEN — after the cooldown exactly one probe call is let through; others
  keep deferring. Success closes the breaker; any failure re-opens it for a
  fresh cooldown.

Any HTTP 200 counts as success here — a malformed or low-confidence answer is a
quality problem, not an availability one. State is process-wide and resets when
the provider identity (base URL + key fingerprint) changes, so replacing a dead
key takes effect without waiting out the cooldown.
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass

from .contract import DeferReason

HARD_FAILURES = frozenset({DeferReason.AUTH_FAILED, DeferReason.CREDITS_EXHAUSTED})
SOFT_FAILURES = frozenset({
    DeferReason.TIMEOUT,
    DeferReason.TRANSPORT,
    DeferReason.RATE_LIMITED,
    DeferReason.SERVER_ERROR,
    DeferReason.HTTP_STATUS,
    DeferReason.INTERNAL,
})

CLOSED, OPEN, HALF_OPEN = "closed", "open", "half_open"


@dataclass
class _State:
    identity: str = ""
    state: str = CLOSED
    consecutive_soft: int = 0
    opened_at: float = 0.0
    probe_in_flight: bool = False
    last_trip_reason: str | None = None
    trips: int = 0


_LOCK = threading.Lock()
_S = _State()
# Test seam: monotonic clock.
_clock = time.monotonic


def identity(base_url: str, api_key: str) -> str:
    return hashlib.sha256(f"{base_url}\x1f{api_key}".encode()).hexdigest()[:16]


def _sync(ident: str) -> None:
    global _S
    if _S.identity != ident:
        _S = _State(identity=ident)


def blocked(ident: str, cooldown: float) -> bool:
    """Cheap pre-check: should this call DEFER as circuit_open right now?"""
    with _LOCK:
        _sync(ident)
        if _S.state == CLOSED:
            return False
        if _S.state == OPEN:
            return _clock() - _S.opened_at < cooldown
        return _S.probe_in_flight  # HALF_OPEN


def acquire(ident: str, cooldown: float) -> bool:
    """Claim permission to hit the network (called right before the request).

    In OPEN-past-cooldown this transitions to HALF_OPEN and claims the single
    probe; a concurrent caller loses the race and DEFERs.
    """
    with _LOCK:
        _sync(ident)
        if _S.state == CLOSED:
            return True
        if _S.state == OPEN:
            if _clock() - _S.opened_at < cooldown:
                return False
            _S.state = HALF_OPEN
        if _S.probe_in_flight:
            return False
        _S.probe_in_flight = True
        return True


def record(ident: str, outcome: DeferReason | None, threshold: int) -> None:
    """Report a network attempt. ``outcome`` is None for any HTTP-200 response."""
    with _LOCK:
        if _S.identity != ident:
            return  # identity changed mid-flight; the stale result is irrelevant
        probing = _S.state == HALF_OPEN
        _S.probe_in_flight = False
        if outcome is None or not (outcome in HARD_FAILURES or outcome in SOFT_FAILURES):
            _S.state = CLOSED
            _S.consecutive_soft = 0
            return
        if outcome in SOFT_FAILURES:
            _S.consecutive_soft += 1
        if probing or outcome in HARD_FAILURES or _S.consecutive_soft >= max(1, threshold):
            _S.state = OPEN
            _S.opened_at = _clock()
            _S.consecutive_soft = 0
            _S.last_trip_reason = outcome.value
            _S.trips += 1


def release_probe(ident: str) -> None:
    """Give back a claimed probe that never reached the network."""
    with _LOCK:
        if _S.identity == ident:
            _S.probe_in_flight = False


def snapshot() -> dict[str, object]:
    with _LOCK:
        return {
            "state": _S.state,
            "consecutive_soft_failures": _S.consecutive_soft,
            "trips": _S.trips,
            "last_trip_reason": _S.last_trip_reason,
        }


def reset() -> None:
    global _S
    with _LOCK:
        _S = _State()
