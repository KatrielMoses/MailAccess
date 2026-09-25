"""Per-task JEV metrics: calls, DEFER rate (by reason), cache-hit rate, latency.

In-memory by default. When ``JEV_METRICS_DIR`` is set (the eval harness sets it
per target run) and JEV is enabled, a snapshot is rewritten to
``<dir>/jev-metrics-<pid>.json`` after each call so a CLI run and the server it
spawns each leave their own file for the harness to merge. These counters are
what each later JEV phase's ROI is judged on.
"""

from __future__ import annotations

import json
import logging
import os
import statistics
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)
_MAX_SAMPLES = 2000


@dataclass
class TaskMetrics:
    calls: int = 0
    verdicts: int = 0
    defers: int = 0
    cache_hits: int = 0
    model_calls: int = 0
    defer_reasons: dict[str, int] = field(default_factory=dict)
    latencies_ms: list[float] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        lat = sorted(self.latencies_ms)
        return {
            "calls": self.calls,
            "verdicts": self.verdicts,
            "defers": self.defers,
            "defer_rate": round(self.defers / self.calls, 4) if self.calls else None,
            "defer_reasons": dict(sorted(self.defer_reasons.items())),
            "cache_hits": self.cache_hits,
            "cache_hit_rate": round(self.cache_hits / self.calls, 4) if self.calls else None,
            "model_calls": self.model_calls,
            "latency_ms": {
                "n": len(lat),
                "mean": round(statistics.fmean(lat), 2) if lat else None,
                "p50": round(lat[len(lat) // 2], 2) if lat else None,
                "p95": round(lat[min(len(lat) - 1, int(len(lat) * 0.95))], 2) if lat else None,
                "max": round(lat[-1], 2) if lat else None,
            },
        }


_LOCK = threading.Lock()
_TASKS: dict[str, TaskMetrics] = {}


def record(
    task: str,
    *,
    latency_ms: float,
    defer_reason: str | None = None,
    cache_hit: bool = False,
    model_called: bool = False,
) -> None:
    with _LOCK:
        m = _TASKS.setdefault(task, TaskMetrics())
        m.calls += 1
        if defer_reason is None:
            m.verdicts += 1
        else:
            m.defers += 1
            m.defer_reasons[defer_reason] = m.defer_reasons.get(defer_reason, 0) + 1
        if cache_hit:
            m.cache_hits += 1
        if model_called:
            m.model_calls += 1
        if len(m.latencies_ms) < _MAX_SAMPLES:
            m.latencies_ms.append(latency_ms)


def snapshot() -> dict[str, dict[str, Any]]:
    with _LOCK:
        return {name: m.snapshot() for name, m in sorted(_TASKS.items())}


def reset() -> None:
    with _LOCK:
        _TASKS.clear()


def persist(directory: str) -> None:
    """Rewrite this process's snapshot file. Never raises."""
    if not directory:
        return
    try:
        root = Path(directory).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        payload = {"pid": os.getpid(), "tasks": snapshot()}
        fd, tmp = tempfile.mkstemp(dir=root, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        os.replace(tmp, root / f"jev-metrics-{os.getpid()}.json")
    except OSError as exc:
        _LOG.debug("JEV metrics persist failed: %s", type(exc).__name__)


def merge_snapshots(snapshots: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Merge persisted per-process snapshots into one per-task view (eval side).

    Latency is merged as a call-weighted mean plus the worst max; percentiles
    cannot be recombined exactly from summaries, so they are dropped here.
    """
    merged: dict[str, dict[str, Any]] = {}
    for snap in snapshots:
        for name, t in (snap.get("tasks") or {}).items():
            acc = merged.setdefault(name, {
                "calls": 0, "verdicts": 0, "defers": 0, "cache_hits": 0, "model_calls": 0,
                "defer_reasons": {}, "_lat_sum": 0.0, "_lat_n": 0, "latency_max_ms": None,
            })
            for k in ("calls", "verdicts", "defers", "cache_hits", "model_calls"):
                acc[k] += int(t.get(k) or 0)
            for reason, n in (t.get("defer_reasons") or {}).items():
                acc["defer_reasons"][reason] = acc["defer_reasons"].get(reason, 0) + int(n)
            lat = t.get("latency_ms") or {}
            if lat.get("n") and lat.get("mean") is not None:
                acc["_lat_sum"] += float(lat["mean"]) * int(lat["n"])
                acc["_lat_n"] += int(lat["n"])
            if lat.get("max") is not None:
                acc["latency_max_ms"] = max(acc["latency_max_ms"] or 0.0, float(lat["max"]))
    for acc in merged.values():
        calls = acc["calls"]
        acc["defer_rate"] = round(acc["defers"] / calls, 4) if calls else None
        acc["cache_hit_rate"] = round(acc["cache_hits"] / calls, 4) if calls else None
        n = acc.pop("_lat_n")
        total = acc.pop("_lat_sum")
        acc["latency_mean_ms"] = round(total / n, 2) if n else None
    return dict(sorted(merged.items()))
