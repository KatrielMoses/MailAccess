"""The run event log: one emitter per run.

Every event a run produces goes through :class:`RunEventEmitter`, which

* assigns a per-run, gap-free ``seq`` (from 1) and a UTC millisecond timestamp,
* keeps the events in memory so any number of live viewers can replay then follow,
* writes them to the ``run_events`` table in batches (flushed at least every
  250 ms, in ``seq`` order) so the database never slows the run,
* feeds the legacy per-module queue used by ``/ws/investigate`` (``legacy_items``).

Events are small. A platform hit is one ``finding`` event, never a whole module
result. Payloads are scrubbed of any configured provider key before they are stored
or streamed, so keys cannot appear in an event, a trace or an export.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import time
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

FLUSH_INTERVAL = 0.25
PROGRESS_MIN_INTERVAL = 0.25  # at most 4 module_progress events per second per module
REGISTRY_LINGER_SECONDS = 300.0

_current: contextvars.ContextVar[RunEventEmitter | None] = contextvars.ContextVar(
    "run_event_emitter", default=None
)
_registry: dict[str, RunEventEmitter] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _secret_values() -> list[str]:
    """Configured provider keys/tokens (never emitted)."""
    try:
        from ..config import settings
    except Exception:
        return []
    out = []
    for name in getattr(settings.__class__, "model_fields", {}):
        if any(t in name for t in ("api_key", "token", "secret", "password", "webhook_url", "proxy_url", "serpapi_key")):
            value = getattr(settings, name, None)
            if isinstance(value, str) and len(value) >= 8:
                out.append(value)
    return sorted(set(out), key=len, reverse=True)


class RunEventEmitter:
    def __init__(
        self,
        investigation_id: str,
        *,
        persist: bool = True,
        sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.persist = persist
        self._sinks: list[Callable[[dict[str, Any]], None]] = [sink] if sink else []
        self.events: list[dict[str, Any]] = []
        self.legacy_items: list[Any] = []
        self.done = False
        self.phase = ""
        self.module_times: dict[str, dict[str, datetime]] = {}
        self.finding_ids: dict[int, int] = {}  # id(finding dict) -> run-local finding id
        self.finding_state: dict[int, tuple[str, str]] = {}  # finding_id -> (label, reason)
        self.findings_by_id: dict[int, dict[str, Any]] = {}
        self.announced_nodes: set[str] = set()
        self.announced_edges: set[tuple[str, str, str]] = set()
        self.modules_done: set[str] = set()
        self.modules_started: set[str] = set()
        self.modules_checked: set[str] = set()
        self.planned_total = 0
        self.finding_count = 0
        self._next_finding_id = 1
        self._seq = 0
        self._pending: list[dict[str, Any]] = []
        self._wake = asyncio.Event()
        self._legacy_wake = asyncio.Event()
        self._last_progress: dict[str, float] = {}
        self._secrets = _secret_values()
        self._flusher: asyncio.Task | None = None
        self._flush_lock = asyncio.Lock()

    # ------------------------------------------------------------------ emit
    def _scrub(self, payload: dict[str, Any]) -> dict[str, Any]:
        """JSON-safe copy of ``payload`` with any configured provider key removed."""
        text = json.dumps(payload, default=str)
        for secret in self._secrets:
            if secret in text:
                text = text.replace(secret, "[redacted]")
        return json.loads(text)

    def add_sink(self, sink: Callable[[dict[str, Any]], None]) -> None:
        self._sinks.append(sink)

    def emit(self, type_: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        self._seq += 1
        event = {
            "seq": self._seq,
            "ts": _now_iso(),
            "type": type_,
            "payload": self._scrub(payload or {}),
        }
        self.events.append(event)
        if self.persist:
            self._pending.append(event)
            self._ensure_flusher()
        for sink in self._sinks:
            try:
                sink(event)
            except Exception:  # a viewer/export problem must never break the run
                logger.debug("run event sink failed", exc_info=True)
        self._notify()
        return event

    def _notify(self) -> None:
        old, self._wake = self._wake, asyncio.Event()
        old.set()

    def legacy(self, item: Any) -> None:
        """Record a legacy queue item (QueueEvent or None sentinel) for /ws viewers."""
        self.legacy_items.append(item)
        old, self._legacy_wake = self._legacy_wake, asyncio.Event()
        old.set()

    # ------------------------------------------------------------ persistence
    def _ensure_flusher(self) -> None:
        if self._flusher is None or self._flusher.done():
            try:
                self._flusher = asyncio.get_running_loop().create_task(self._flush_loop())
            except RuntimeError:  # no running loop (sync test); flushed on close
                self._flusher = None

    async def _flush_loop(self) -> None:
        while self._pending and not self.done:
            await asyncio.sleep(FLUSH_INTERVAL)
            await self.flush()

    async def flush(self) -> None:
        if not self.persist:
            return
        async with self._flush_lock:
            batch, self._pending = self._pending, []
            if not batch:
                return
            from sqlalchemy import insert

            from ..db.database import AsyncSessionLocal
            from ..db.models import RunEvent

            rows = [
                {
                    "investigation_id": self.investigation_id,
                    "seq": e["seq"],
                    "ts": e["ts"],
                    "type": e["type"],
                    "payload": e["payload"],
                }
                for e in batch
            ]
            try:
                async with AsyncSessionLocal() as session:
                    async with session.begin():
                        await session.execute(insert(RunEvent), rows)
            except Exception:
                # The in-memory log still serves live viewers; a failed save must
                # never stall or re-queue forever.
                logger.exception("run_events flush failed for %s", self.investigation_id)

    async def close(self) -> None:
        """Mark the run finished, flush everything, wake every viewer."""
        self.done = True
        if self._flusher is not None:
            self._flusher.cancel()
            try:
                await self._flusher
            except (asyncio.CancelledError, Exception):
                pass
        await self.flush()
        self._notify()
        old, self._legacy_wake = self._legacy_wake, asyncio.Event()
        old.set()
        try:
            asyncio.get_running_loop().call_later(REGISTRY_LINGER_SECONDS, unregister, self)
        except RuntimeError:
            pass

    # ----------------------------------------------------------------- viewers
    async def follow(
        self, since: int = 0, heartbeat: float | None = None
    ) -> AsyncIterator[dict[str, Any] | None]:
        """Yield every event with ``seq > since`` (replay), then live ones, until
        the run is done. Any number of viewers get an identical sequence. With
        ``heartbeat`` set, yields ``None`` whenever that many seconds pass quietly."""
        index = max(0, int(since))
        while True:
            while index < len(self.events):
                yield self.events[index]
                index += 1
            if self.done:
                return
            wake = self._wake
            try:
                await asyncio.wait_for(wake.wait(), heartbeat)
            except asyncio.TimeoutError:
                yield None

    async def follow_legacy(self) -> AsyncIterator[Any]:
        index = 0
        while True:
            while index < len(self.legacy_items):
                yield self.legacy_items[index]
                index += 1
            if self.done and index >= len(self.legacy_items):
                return
            wake = self._legacy_wake
            if index < len(self.legacy_items) or self.done:
                continue
            await wake.wait()

    # ------------------------------------------------------------- finding ids
    def finding_id_for(self, finding: dict[str, Any]) -> tuple[int, bool]:
        """(run-local finding id, is_new)."""
        existing = finding.get("finding_id")
        if isinstance(existing, int) and existing in self.findings_by_id:
            self.finding_ids[id(finding)] = existing
            return existing, False
        known = self.finding_ids.get(id(finding))
        if known is not None and self.findings_by_id.get(known) is finding:
            return known, False
        fid = self._next_finding_id
        self._next_finding_id += 1
        self.finding_ids[id(finding)] = fid
        self.findings_by_id[fid] = finding
        finding["finding_id"] = fid
        return fid, True

    # ------------------------------------------------------------ module timing
    def module_started(self, module: str) -> None:
        self.module_times[module] = {"started_at": datetime.now(timezone.utc)}

    def module_finished(self, module: str) -> int:
        times = self.module_times.setdefault(module, {"started_at": datetime.now(timezone.utc)})
        times["finished_at"] = datetime.now(timezone.utc)
        return int((times["finished_at"] - times["started_at"]).total_seconds() * 1000)

    def progress(
        self,
        module: str,
        checked: int,
        total: int,
        found: int | None = None,
        label: str | None = None,
        *,
        force: bool = False,
    ) -> None:
        total = max(int(total), 0)
        checked = max(0, min(int(checked), total))
        now = time.monotonic()
        # ``force`` lets the final tick through even inside the min-interval window, so
        # the last "750 / 750 checked" is always emitted.
        if not force and now - self._last_progress.get(module, -1.0) < PROGRESS_MIN_INTERVAL:
            return
        self._last_progress[module] = now
        payload: dict[str, Any] = {"module": module, "checked": checked, "total": total}
        if found is not None:
            payload["found"] = int(found)
            # A ready-to-display line for the live view ("612 / 750 checked · 14 found").
            payload["label"] = label or f"{checked} / {total} checked · {found} found"
        elif label is not None:
            payload["label"] = label
        self.emit("module_progress", payload)


class FanoutQueue(asyncio.Queue):
    """The engine's module queue. Same API as before (Maltego drains it), but every
    item is also recorded on the emitter so any number of /ws viewers can read it."""

    def __init__(self, emitter: RunEventEmitter) -> None:
        super().__init__()
        self._emitter = emitter

    async def put(self, item: Any) -> None:
        self._emitter.legacy(item)
        await super().put(item)


# ---------------------------------------------------------------- registry/context
def create(investigation_id: str) -> RunEventEmitter:
    emitter = RunEventEmitter(investigation_id)
    _registry[investigation_id] = emitter
    return emitter


def get(investigation_id: str) -> RunEventEmitter | None:
    return _registry.get(investigation_id)


def unregister(emitter: RunEventEmitter) -> None:
    if _registry.get(emitter.investigation_id) is emitter:
        _registry.pop(emitter.investigation_id, None)


def set_current(emitter: RunEventEmitter | None) -> contextvars.Token:
    return _current.set(emitter)


def reset_current(token: contextvars.Token) -> None:
    _current.reset(token)


def current() -> RunEventEmitter | None:
    return _current.get()


def module_progress(
    module: str,
    checked: int,
    total: int,
    found: int | None = None,
    label: str | None = None,
    *,
    force: bool = False,
) -> None:
    """No-op unless a run is being recorded (modules call this freely)."""
    emitter = _current.get()
    if emitter is not None:
        emitter.progress(module, checked, total, found, label, force=force)
