"""Phase 4C — novelty & source accounting.

Measures what each source actually *earns* and auto-demotes the ones that don't
(Doc-1 #13). Needs no labels — it runs on harvest telemetry + the confirmations
the pipeline already produces — so it delivers value immediately and cuts the
noise/runtime the audit flagged.

Per source (harvest module), per run and aggregated over a window:

* **marginal unique contribution** — emails ONLY this source found (its novelty);
* **incremental confirmed contribution** — confirmed (Valid-graded) emails only
  this source found (novelty that actually pays);
* **latency** — the module's wall-clock time (from the harvest summary);
* **failure / block rate** — non-success module runs;
* **FP rate** — of the addresses it contributed that carry a grade, the fraction
  graded Invalid (a proxy for confirmations available in-band).

Demotion is **explainable and reversible**, reusing the existing
``platform_health`` / ``demotion_log`` patterns rather than inventing a parallel
one: a demotion is a logged event (with the snapshot that triggered it and the
env var that reverses it), a reinstatement is a logged ``upgrade``, and a
force-keep env override always wins. A demoted source is simply skipped at
scheduling time (runtime saved); nothing is removed (module removal is Phase 7).
Like the calibrated scorer, a source is only demoted once it has *earned* it —
so at baseline scale the demoted set is empty and live behavior is unchanged.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import demotion_log

logger = logging.getLogger(__name__)

_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")

# Grades that count as a per-mailbox confirmation vs a false-positive contribution.
_CONFIRMED_GRADES = frozenset({"Valid"})
_INVALID_GRADES = frozenset({"Invalid"})
_SUCCESS_STATUSES = frozenset({"success", "complete"})

# Demotion policy (exploration latitude): a source seen in at least this many runs
# over the window that added ZERO marginal-unique AND ZERO incremental-confirmed
# leads has stopped earning its runtime.
DEFAULT_MIN_RUNS = 5
DEFAULT_WINDOW_DAYS = 30


def _base_dir() -> Path:
    home = os.environ.get("HOME")
    base = Path(home) if home else Path.home()
    return base / ".mailaccess"


def accounting_log_path() -> Path:
    return _base_dir() / "source_accounting.jsonl"


def demotion_log_path() -> Path:
    return _base_dir() / "source_demotions.log"


def force_keep_env_key(source: str) -> str:
    """Env var that force-keeps a demoted source (the reversibility hint)."""
    stripped = _NON_ALNUM_RE.sub("", source or "").upper() or "UNKNOWN"
    return f"MAILACCESS_FORCE_SOURCE_{stripped}"


# ---------------------------------------------------------------------------
# Per-run accounting
# ---------------------------------------------------------------------------
def account_run(
    emails: list[dict[str, Any]],
    *,
    module_timings: dict[str, float] | None = None,
    module_status: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Compute per-source contribution accounting for one harvest.

    ``emails`` are plain dicts (keeps this decoupled from HarvestedEmail, like the
    ledger builders): each needs ``found_by_modules`` and, when known,
    ``deliverability_grade``. Returns ``{per_source: {...}, totals: {...}}``.
    """
    module_timings = module_timings or {}
    module_status = module_status or {}
    per_source: dict[str, dict[str, Any]] = {}

    def _src(name: str) -> dict[str, Any]:
        return per_source.setdefault(
            name,
            {
                "contributed": 0,
                "marginal_unique": 0,
                "confirmed": 0,
                "marginal_confirmed": 0,
                "invalid_contributed": 0,
                "gradable_contributed": 0,
            },
        )

    for em in emails:
        finders = [str(m) for m in (em.get("found_by_modules") or []) if str(m).strip()]
        if not finders:
            continue
        unique = len(set(finders)) == 1
        grade = str(em.get("deliverability_grade") or "")
        is_confirmed = grade in _CONFIRMED_GRADES
        is_invalid = grade in _INVALID_GRADES
        has_grade = bool(grade)
        for name in set(finders):
            s = _src(name)
            s["contributed"] += 1
            if unique:
                s["marginal_unique"] += 1
            if is_confirmed:
                s["confirmed"] += 1
                if unique:
                    s["marginal_confirmed"] += 1
            if has_grade:
                s["gradable_contributed"] += 1
                if is_invalid:
                    s["invalid_contributed"] += 1

    # Attach telemetry (latency / status) even for sources that found nothing.
    for name in set(module_timings) | set(module_status) | set(per_source):
        s = _src(name)
        latency = module_timings.get(name)
        s["latency_seconds"] = float(latency) if isinstance(latency, int | float) else None
        status = module_status.get(name)
        s["status"] = str(status) if status else None
        s["success"] = str(status).lower() in _SUCCESS_STATUSES if status else None
        grad = s["gradable_contributed"]
        s["fp_rate"] = round(s["invalid_contributed"] / grad, 4) if grad else None

    totals = {
        "sources": len(per_source),
        "emails": len(emails),
        "confirmed": sum(1 for em in emails
                         if str(em.get("deliverability_grade") or "") in _CONFIRMED_GRADES),
    }
    return {"per_source": per_source, "totals": totals}


def record_run_accounting(
    domain: str, accounting: dict[str, Any], *, path: Path | None = None
) -> Path | None:
    """Append one per-run accounting record (append-only JSONL). Guarded."""
    target = path or accounting_log_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "domain": str(domain),
            "per_source": accounting.get("per_source", {}),
            "totals": accounting.get("totals", {}),
        }
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return target
    except OSError as exc:
        logger.warning("source_accounting: record failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Aggregation over a window
# ---------------------------------------------------------------------------
def aggregate(
    *, window_days: int = DEFAULT_WINDOW_DAYS, path: Path | None = None
) -> dict[str, dict[str, Any]]:
    """Aggregate per-source contribution over the rolling window (from the JSONL)."""
    target = path or accounting_log_path()
    if not target.exists():
        return {}
    from datetime import timedelta

    cutoff = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()
    agg: dict[str, dict[str, Any]] = {}
    try:
        with open(target, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(rec.get("ts") or "") < cutoff:
                    continue
                for name, s in (rec.get("per_source") or {}).items():
                    a = agg.setdefault(
                        name,
                        {
                            "runs": 0, "contributed": 0, "marginal_unique": 0,
                            "confirmed": 0, "marginal_confirmed": 0,
                            "invalid_contributed": 0, "gradable_contributed": 0,
                            "failures": 0, "latency_sum": 0.0, "latency_n": 0,
                        },
                    )
                    a["runs"] += 1
                    for k in ("contributed", "marginal_unique", "confirmed",
                              "marginal_confirmed", "invalid_contributed",
                              "gradable_contributed"):
                        a[k] += int(s.get(k) or 0)
                    if s.get("success") is False:
                        a["failures"] += 1
                    lat = s.get("latency_seconds")
                    if isinstance(lat, int | float):
                        a["latency_sum"] += float(lat)
                        a["latency_n"] += 1
    except OSError:
        return agg
    for a in agg.values():
        a["avg_latency_seconds"] = (
            round(a["latency_sum"] / a["latency_n"], 3) if a["latency_n"] else None
        )
        a["failure_rate"] = round(a["failures"] / a["runs"], 3) if a["runs"] else None
        a["fp_rate"] = (
            round(a["invalid_contributed"] / a["gradable_contributed"], 4)
            if a["gradable_contributed"] else None
        )
    return agg


# ---------------------------------------------------------------------------
# Demotion decision engine (explainable, reversible)
# ---------------------------------------------------------------------------
def compute_demotion_candidates(
    *,
    window_days: int = DEFAULT_WINDOW_DAYS,
    min_runs: int = DEFAULT_MIN_RUNS,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    """Sources that no longer earn their runtime (reproducible from the JSONL).

    A candidate has ``runs >= min_runs`` over the window and added ZERO
    marginal-unique AND ZERO incremental-confirmed leads — every address it found,
    another (cheaper-or-not) source also found. Deterministic given the log."""
    agg = aggregate(window_days=window_days, path=path)
    candidates: list[dict[str, Any]] = []
    for name, a in sorted(agg.items()):
        if a["runs"] < min_runs:
            continue
        if a["marginal_unique"] == 0 and a["marginal_confirmed"] == 0:
            candidates.append(
                {
                    "source": name,
                    "reason": (
                        f"0 marginal-unique and 0 incremental-confirmed leads over "
                        f"{a['runs']} runs (window {window_days}d)"
                    ),
                    "stats": {
                        "runs": a["runs"],
                        "contributed": a["contributed"],
                        "marginal_unique": a["marginal_unique"],
                        "marginal_confirmed": a["marginal_confirmed"],
                        "failure_rate": a["failure_rate"],
                        "avg_latency_seconds": a["avg_latency_seconds"],
                    },
                }
            )
    return candidates


def demote(
    source: str, *, stats: dict[str, Any] | None = None, reason: str = "",
    log_path: Path | None = None,
) -> Path:
    """Record a reversible demotion for ``source`` (logged with its trigger stats)."""
    return demotion_log.log_event(
        source,
        "demote",
        stats or {},
        reason or "auto-demoted: no marginal-unique or incremental-confirmed leads",
        reversible_via=force_keep_env_key(source),
        path=log_path or demotion_log_path(),
    )


def reinstate(
    source: str, *, reason: str = "", log_path: Path | None = None
) -> Path:
    """Reverse a demotion (logged as an ``upgrade`` event) — instant reinstatement."""
    return demotion_log.log_event(
        source,
        "upgrade",
        {},
        reason or "reinstated",
        reversible_via=force_keep_env_key(source),
        path=log_path or demotion_log_path(),
    )


def _force_kept(source: str) -> bool:
    val = os.environ.get(force_keep_env_key(source), "").strip().lower()
    return val in {"1", "true", "yes", "on"}


def demoted_source_names(*, log_path: Path | None = None) -> set[str]:
    """Currently-demoted sources: replay the log (last action wins), then drop any
    source force-kept by its env override. Reversible and env-overridable."""
    events = demotion_log.read_recent_events(path=log_path or demotion_log_path())
    state: dict[str, str] = {}
    for ev in events:
        name = str(ev.get("platform") or "")
        action = str(ev.get("action") or "")
        if not name or action not in {"demote", "upgrade"}:
            continue
        state[name] = action  # last action for this source wins
    demoted = {name for name, action in state.items() if action == "demote"}
    return {name for name in demoted if not _force_kept(name)}


def is_source_demoted(source: str, *, log_path: Path | None = None) -> bool:
    return source in demoted_source_names(log_path=log_path)


def filter_active_sources(
    names: list[str] | set[str] | tuple[str, ...], *, log_path: Path | None = None
) -> list[str]:
    """Drop demoted sources from a candidate list (order preserved)."""
    demoted = demoted_source_names(log_path=log_path)
    return [n for n in names if n not in demoted]
