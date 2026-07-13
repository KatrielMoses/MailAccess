from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

PRIORITY_GUARANTEED = 0
PRIORITY_ROUTER_EXPANSION = 5
PRIORITY_HIGH_SIGNAL = 10
PRIORITY_UNIVERSAL = 20
PRIORITY_ARCHIVE = 30
PRIORITY_SEARCH = 40
PRIORITY_REGISTRY = 50
PRIORITY_OPPORTUNISTIC = 100

TRACK_GUARANTEED = 1
TRACK_OPPORTUNISTIC = 2


def _normalize_url(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path.rstrip("/")
    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            path.lower(),
            parts.query,
            "",
        )
    )


def _stable_payload(payload: dict[str, Any]) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    except TypeError:
        return repr(sorted(payload.items(), key=lambda item: str(item[0])))


@dataclass
class WorkItem:
    kind: str
    url: str | None = None
    module_name: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    priority: int = PRIORITY_OPPORTUNISTIC
    track: int = TRACK_OPPORTUNISTIC
    source: str = ""

    def fingerprint(self) -> str:
        if self.kind == "fetch_page" and self.url:
            return f"fetch_page:{_normalize_url(self.url)}"
        if self.kind == "run_module":
            return f"run_module:{self.module_name}:{_stable_payload(self.payload)}"
        if self.kind == "verify_pattern":
            return f"verify:{self.payload['pattern']}:{self.payload['domain']}"
        return (
            f"{self.kind}:{self.url or ''}:"
            f"{self.module_name or ''}:{_stable_payload(self.payload)}"
        )


@dataclass
class WorkResult:
    item: WorkItem
    success: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    new_items: list[WorkItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


class WorkScheduler:
    def __init__(self) -> None:
        self._queue: asyncio.PriorityQueue[tuple[int, int, WorkItem]] = asyncio.PriorityQueue()
        self._seen: set[str] = set()
        self._lock = asyncio.Lock()
        self._counter = 0
        self._closed = False
        self._submitted_count = 0
        self._deduped_count = 0

    async def submit(self, item: WorkItem, priority: int | None = None) -> bool:
        if self._closed:
            return False

        fp = item.fingerprint()
        async with self._lock:
            if self._closed:
                return False
            if fp in self._seen:
                self._deduped_count += 1
                return False

            self._seen.add(fp)
            self._counter += 1
            p = priority if priority is not None else item.priority
            await self._queue.put((p, self._counter, item))
            self._submitted_count += 1
            return True

    async def pull(self, timeout: float = 1.0) -> WorkItem | None:
        try:
            _priority, _counter, item = await asyncio.wait_for(
                self._queue.get(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return None
        return item

    async def pull_matching(
        self,
        predicate: Callable[[WorkItem], bool],
        timeout: float = 1.0,
    ) -> WorkItem | None:
        deadline = asyncio.get_event_loop().time() + timeout
        skipped: list[tuple[int, int, WorkItem]] = []
        try:
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    return None
                try:
                    priority, counter, item = await asyncio.wait_for(
                        self._queue.get(),
                        timeout=remaining,
                    )
                except asyncio.TimeoutError:
                    return None
                if predicate(item):
                    return item
                skipped.append((priority, counter, item))
                if self._queue.empty():
                    return None
        finally:
            for entry in skipped:
                await self._queue.put(entry)

    async def requeue(self, item: WorkItem, priority: int | None = None) -> bool:
        if self._closed:
            return False
        async with self._lock:
            if self._closed:
                return False
            self._counter += 1
            p = priority if priority is not None else item.priority
            await self._queue.put((p, self._counter, item))
            return True

    def close(self) -> None:
        self._closed = True

    @property
    def stats(self) -> dict[str, int]:
        return {
            "submitted": self._submitted_count,
            "deduped": self._deduped_count,
            "queue_size": self._queue.qsize(),
            "seen_fingerprints": len(self._seen),
        }

    def is_empty(self) -> bool:
        return self._queue.empty()
