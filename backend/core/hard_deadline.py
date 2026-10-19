"""Hard wall-clock limits for long runs (the harvest ``--timeout``).

``asyncio.wait_for`` is a soft limit: when it expires it cancels the inner task
and then WAITS for that task to finish unwinding. A coroutine that swallows
``CancelledError`` (or one stuck behind an un-cancellable await) therefore keeps
the caller waiting forever. ``asyncio.run`` has the same problem at teardown: it
waits for every leftover task and, on Python 3.10, joins every default-executor
thread with no timeout, so one blocking call running in ``asyncio.to_thread``
keeps the process alive long after the work it belonged to was given up.

The helpers here never wait for stragglers past a short grace:

* :func:`wait_hard` awaits with a deadline, cancels on expiry, and abandons a
  task that does not unwind within the grace.
* :func:`run_hard` is ``asyncio.run`` without the unbounded teardown waits.
* :class:`StallWatchdog` is a daemon thread that fires a callback when the
  event loop itself is blocked past the deadline (synchronous code on the loop).
* :func:`exit_if_stragglers` ends the process after the final output is flushed
  when abandoned non-daemon threads would otherwise keep the interpreter alive.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)

# How long a cancelled task gets to unwind before it is abandoned.
CANCEL_GRACE_SECONDS = 2.0


def _consume(task: asyncio.Future) -> None:
    """Retrieve a finished task's exception so asyncio does not log it later."""
    if task.done() and not task.cancelled():
        with contextlib.suppress(BaseException):
            task.exception()


async def wait_hard(
    aw: Awaitable[Any],
    timeout: float,
    *,
    grace: float = CANCEL_GRACE_SECONDS,
) -> tuple[bool, Any]:
    """Await ``aw`` for at most ``timeout`` seconds.

    Returns ``(True, result)`` when it finished in time (its exception, if any,
    is re-raised). On expiry the task is cancelled and given ``grace`` seconds
    to unwind; after that it is abandoned and ``(False, None)`` is returned.
    The caller never waits longer than ``timeout + grace``.
    """
    task = asyncio.ensure_future(aw)
    try:
        done, _ = await asyncio.wait({task}, timeout=max(0.0, float(timeout)))
    except asyncio.CancelledError:
        # The caller itself was cancelled: do not leave the child running, but
        # do not wait for it either.
        task.cancel()
        task.add_done_callback(_consume)
        raise
    if task in done:
        return True, task.result()
    task.cancel()
    if grace > 0:
        await asyncio.wait({task}, timeout=grace)
    if task.done():
        _consume(task)
    else:
        task.add_done_callback(_consume)
        logger.warning("abandoned a task that ignored cancellation: %r", task)
    return False, None


def _cancel_leftovers(loop: asyncio.AbstractEventLoop, grace: float) -> list[asyncio.Task]:
    pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
    for task in pending:
        task.cancel()
    if pending and grace > 0:
        loop.run_until_complete(asyncio.wait(pending, timeout=grace))
    stragglers = []
    for task in pending:
        if task.done():
            _consume(task)
        else:
            stragglers.append(task)
    return stragglers


def run_hard(main: Awaitable[Any], *, grace: float = CANCEL_GRACE_SECONDS) -> Any:
    """``asyncio.run`` with bounded teardown.

    Leftover tasks are cancelled and given ``grace`` seconds; tasks that ignore
    cancellation are abandoned. The default executor is shut down without
    waiting (queued work is cancelled; threads already running are left behind
    and see :func:`exit_if_stragglers`).
    """
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(main)
    finally:
        try:
            stragglers = _cancel_leftovers(loop, grace)
            if stragglers:
                logger.warning("abandoned %d task(s) at shutdown", len(stragglers))
            with contextlib.suppress(Exception):
                loop.run_until_complete(
                    asyncio.wait({loop.create_task(loop.shutdown_asyncgens())}, timeout=grace)
                )
            executor = getattr(loop, "_default_executor", None)
            if executor is not None:
                executor.shutdown(wait=False, cancel_futures=True)
        finally:
            asyncio.set_event_loop(None)
            with contextlib.suppress(Exception):
                loop.close()


class StallWatchdog:
    """Daemon thread that calls ``on_fire`` once, ``seconds`` from now, unless stopped.

    It is the backstop for synchronous code that blocks the event loop (no
    asyncio deadline can fire while the loop is blocked). It cannot preempt a
    single C call that holds the GIL; see :func:`arm_last_resort` for that.
    """

    def __init__(self, seconds: float, on_fire: Callable[[], None]) -> None:
        self._seconds = max(0.0, float(seconds))
        self._on_fire = on_fire
        self._stopped = threading.Event()
        self.fired = False
        self._thread = threading.Thread(
            target=self._run, name="mailaccess-stall-watchdog", daemon=True
        )

    def start(self) -> StallWatchdog:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stopped.set()

    def _run(self) -> None:
        if self._stopped.wait(self._seconds):
            return
        self.fired = True
        try:
            self._on_fire()
        except Exception:  # noqa: BLE001 - the watchdog must never raise
            logger.exception("stall watchdog callback failed")


def arm_last_resort(seconds: float) -> bool:
    """Arm faulthandler to dump stacks and ``_exit(1)`` after ``seconds``.

    faulthandler's timer runs in C without the GIL, so it still fires when one
    long C call (for example a pathological regex) holds the interpreter. It is
    the very last line of defence; :func:`disarm_last_resort` cancels it.
    """
    try:
        import faulthandler

        faulthandler.dump_traceback_later(max(1.0, float(seconds)), exit=True, file=sys.stderr)
        return True
    except Exception:  # noqa: BLE001 - e.g. stderr without a file descriptor
        return False


def disarm_last_resort() -> None:
    with contextlib.suppress(Exception):
        import faulthandler

        faulthandler.cancel_dump_traceback_later()


def straggler_threads() -> list[threading.Thread]:
    """Alive non-daemon threads other than the main thread."""
    main = threading.main_thread()
    return [
        t for t in threading.enumerate()
        if t is not main and t.is_alive() and not t.daemon
    ]


def _flush() -> None:
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.flush()
    with contextlib.suppress(Exception):
        logging.shutdown()


def hard_exit(code: int) -> None:
    """Flush output and end the process now, skipping thread joins."""
    _flush()
    os._exit(int(code))


def exit_if_stragglers(code: int, *, grace: float = 3.0) -> None:
    """End the process with ``code`` if abandoned threads would keep it alive.

    Waits up to ``grace`` seconds for non-daemon threads to finish on their own.
    Returns normally when none are left, so the regular exit path runs.
    """
    deadline = time.monotonic() + max(0.0, grace)
    for thread in straggler_threads():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        thread.join(remaining)
    left = straggler_threads()
    if not left:
        return
    names = ", ".join(sorted({t.name for t in left}))[:200]
    with contextlib.suppress(Exception):
        print(
            f"Abandoning {len(left)} background thread(s) still running "
            f"after the harvest ({names}).",
            file=sys.stderr,
        )
    hard_exit(code)
