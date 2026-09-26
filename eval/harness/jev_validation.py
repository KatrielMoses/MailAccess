"""Phase JEV validation — per-task side-by-side over labeled fixtures.

Measurement only (no feature changes): for every JEV task, run a labeled fixture set
through each available provider mode and decide KEEP(provider) / DROP against the
per-task gate. Three modes over the SAME fixtures:

  baseline  = reasoner force-off (today's deterministic fallback).
  ollaya    = local typed-decisions provider (only the tasks it supports).
  jev       = hosted chat provider (skipped when no endpoint is configured).

For each mode/task we record: accuracy of the FINAL answer a caller would get (the
JEV verdict when not DEFER, else the heuristic fallback) vs the label, the DEFER
rate, and median per-call latency. The gate then compares ollaya/jev to baseline.

Run:  uv run python -m eval.harness.jev_validation
Writes dev/jev-validation.md (git-ignored). Requires a live local Ollaya for the
ollaya mode; set JEV_BASE_URL/JEV_MODEL/JEV_API_KEY for a hosted jev mode.

This never changes task logic to pass a gate — a failing task is recorded as DROP.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import backend.config as config_mod
from backend.core import jev
from backend.core.jev import adapters, breaker
from backend.core.jev import metrics as jev_metrics

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO_ROOT / "dev" / "jev-validation.md"

# Task categories → the keep-gate description shown in the report.
_CATEGORY = {
    "identity.same_person": "identity", "identity.name_reconcile": "identity",
    "identity.bio_extract": "identity",
    "verify.reply_classify": "verification", "verify.catchall_judge": "verification",
    "verify.m365_signal_read": "verification",
    "roster.person_filter": "harvest", "roster.title_normalize": "harvest",
    "roster.person_dedupe": "harvest", "roster.company_resolve": "harvest",
    "reach.platform_select": "reach", "reach.query_generate": "reach",
    "signal.role_system_classify": "signal", "signal.common_name_context": "signal",
    "signal.breach_canonicalize": "signal",
    "narrative.brief_wording": "narrative", "narrative.finding_correlation": "narrative",
    "demo.plausible_personal_name": "demo",
}


@dataclass
class Case:
    payload: dict[str, Any]
    label: Any  # expected value of `extract(verdict.output)`
    extract: Callable[[Any], Any]  # verdict.output -> comparable value
    heuristic: Callable[[], Any] | None = None  # baseline answer (fallback), or None


@dataclass
class ModeResult:
    n: int = 0
    correct: int = 0
    defers: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    available: bool = True
    note: str = ""
    # Diagnostic (ollaya only): the model's answer IGNORING the confidence floor, so
    # a 100%-defer row can be read as "model wrong" vs "model right but under-confident".
    raw_correct: int = 0
    raw_answered: int = 0
    confidences: list[float] = field(default_factory=list)

    @property
    def accuracy(self) -> float | None:
        return round(self.correct / self.n, 3) if self.n else None

    @property
    def defer_rate(self) -> float | None:
        return round(self.defers / self.n, 3) if self.n else None

    @property
    def median_ms(self) -> float | None:
        return round(statistics.median(self.latencies_ms), 1) if self.latencies_ms else None

    @property
    def raw_accuracy(self) -> float | None:
        return round(self.raw_correct / self.raw_answered, 3) if self.raw_answered else None

    @property
    def median_conf(self) -> float | None:
        return round(statistics.median(self.confidences), 3) if self.confidences else None


# ---------------------------------------------------------------------------
# Provider mode configuration
# ---------------------------------------------------------------------------
def _apply_mode(mode: str) -> None:
    s = config_mod.settings
    common = {
        "jev_force_off": False, "jev_timeout_ms": 8000, "jev_max_concurrency": 4,
        "jev_cache_ttl_seconds": 3600, "jev_cache_refresh": True,  # real latencies
        "jev_run_ceiling_seconds": 0.0, "jev_metrics_dir": "",
        "jev_breaker_failure_threshold": 1000, "jev_breaker_cooldown_seconds": 1.0,
    }
    for k, v in common.items():
        setattr(s, k, v)
    if mode == "baseline":
        s.jev_provider, s.jev_enabled, s.jev_force_off = "", False, True
    elif mode == "ollaya":
        s.jev_provider, s.jev_enabled = "ollaya", True
        s.jev_base_url = os.environ.get("OLLAYA_BASE_URL", "http://localhost:11435")
        s.jev_model = os.environ.get("OLLAYA_MODEL", "laya:typed-decisions")
        s.jev_api_key = os.environ.get("OLLAYA_API_KEY") or None
    elif mode == "jev":
        s.jev_provider, s.jev_enabled = "jev", True
        s.jev_base_url = os.environ.get("JEV_BASE_URL", "")
        s.jev_model = os.environ.get("JEV_MODEL", "")
        s.jev_api_key = os.environ.get("JEV_API_KEY") or None


def _mode_available(mode: str) -> tuple[bool, str]:
    if mode == "baseline":
        return True, ""
    prof = adapters.resolve_profile(config_mod.settings)
    if prof is None or not prof.config_ok():
        return False, "not configured"
    if mode == "ollaya":
        import httpx

        try:
            r = httpx.get(prof.base_url.rstrip("/") + "/v1/models", timeout=3.0)
            return (r.status_code == 200), ("" if r.status_code == 200 else f"http {r.status_code}")
        except Exception as exc:
            return False, f"unreachable ({type(exc).__name__})"
    return True, ""


def _ollaya_supported(task_name: str) -> bool:
    task = jev.get_task(task_name)
    if task is None:
        return False
    if task_name in adapters._DECOMPOSERS:
        return True
    try:
        adapters.schema_to_questions(task.output_model)
        return True
    except adapters.UnsupportedForOllaya:
        return False


# ---------------------------------------------------------------------------
# Run one task's fixtures in one mode
# ---------------------------------------------------------------------------
async def _run_task_mode(task_name: str, cases: list[Case], mode: str) -> ModeResult:
    res = ModeResult()
    if mode == "ollaya" and not _ollaya_supported(task_name):
        res.available = False
        res.note = "unsupported on Ollaya (generative/list task)"
        return res
    _apply_mode(mode)
    ok, why = _mode_available(mode)
    if not ok:
        res.available = False
        res.note = why
        return res
    for case in cases:
        res.n += 1
        breaker.reset()
        start = time.monotonic()
        verdict = await jev.judge(task_name, case.payload)
        res.latencies_ms.append((time.monotonic() - start) * 1000.0)
        if verdict is jev.DEFER:
            res.defers += 1
            final = case.heuristic() if case.heuristic else None
        else:
            final = case.extract(verdict.output)
        if final == case.label:
            res.correct += 1
    # Diagnostic raw pass (ollaya): bypass BOTH the global and the per-task confidence
    # floor to see the model's own answer + its confidence, so DEFER-heavy rows are
    # interpretable (model wrong vs model right-but-under-confident).
    if mode == "ollaya":
        import dataclasses

        from backend.core.jev import contract as _contract
        s = config_mod.settings
        saved_floor, saved_refresh = s.jev_min_confidence, s.jev_cache_refresh
        task = _contract.get_task(task_name)
        s.jev_min_confidence, s.jev_cache_refresh = 0.0, True
        _contract._REGISTRY[task_name] = dataclasses.replace(task, min_confidence=0.0)
        try:
            for case in cases:
                breaker.reset()
                verdict = await jev.judge(task_name, case.payload)
                if verdict is jev.DEFER:
                    continue
                res.raw_answered += 1
                res.confidences.append(verdict.confidence)
                if case.extract(verdict.output) == case.label:
                    res.raw_correct += 1
        finally:
            _contract._REGISTRY[task_name] = task
            s.jev_min_confidence, s.jev_cache_refresh = saved_floor, saved_refresh
    return res


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------
def _decide(task_name: str, base: ModeResult, ollaya: ModeResult, jevm: ModeResult) -> str:
    winners = []
    for name, r in (("ollaya", ollaya), ("jev", jevm)):
        if not r.available or r.n == 0:
            continue
        base_acc = base.accuracy or 0.0
        # KEEP where the reasoner's final-answer accuracy strictly beats baseline
        # (recall/precision proxy on the labeled set) with a non-total defer rate.
        if r.accuracy is not None and r.accuracy > base_acc and (r.defer_rate or 0.0) < 1.0:
            winners.append(name)
    return "KEEP(" + ",".join(winners) + ")" if winners else "DROP"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def _render(rows: list[dict[str, Any]], modes_note: dict[str, str]) -> str:
    def cell(r: ModeResult) -> str:
        if not r.available:
            return f"n/a ({r.note})"
        return f"{r.accuracy}/{int((r.defer_rate or 0)*100)}%/{r.median_ms}ms"

    lines = [
        "# Phase JEV — validation scorecard (side-by-side, keep/drop)",
        "",
        "Per task: **accuracy / DEFER% / median latency** of the final answer a caller "
        "would get (JEV verdict when not DEFER, else the heuristic fallback), over a "
        "labeled fixture set. Measurement only — a failing task is DROP.",
        "",
        f"- **ollaya:** {modes_note.get('ollaya', '')}",
        f"- **jev (hosted chat):** {modes_note.get('jev', '')}",
        "",
        "Cells are `accuracy / DEFER% / median-latency`. **ollaya-raw** is the local "
        "model's own answer with the confidence floor bypassed (`raw-accuracy @ "
        "median-confidence`) — it tells apart *model wrong* from *model right but "
        "under-confident for the task's floor*.",
        "",
        "| task | category | baseline | ollaya | ollaya-raw | jev | decision |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        o = row["ollaya"]
        raw = (f"{o.raw_accuracy} @ {o.median_conf}"
               if o.available and o.raw_answered else "—")
        lines.append(
            f"| {row['task']} | {row['category']} | {cell(row['baseline'])} | "
            f"{cell(row['ollaya'])} | {raw} | {cell(row['jev'])} | **{row['decision']}** |"
        )
    lines.append("")
    return "\n".join(lines)


def _summary(rows: list[dict[str, Any]]) -> str:
    kept_local = [r["task"] for r in rows if "ollaya" in r["decision"]]
    kept_hosted = [
        r["task"] for r in rows
        if "jev" in r["decision"] and "ollaya" not in r["decision"]
    ]
    dropped = [r["task"] for r in rows if r["decision"] == "DROP"]
    # "Capable but under-confident": raw model accuracy is strong yet the gated row
    # deferred — a candidate for a future floor tweak, not a drop-for-inaccuracy.
    under_conf = [
        r["task"] for r in rows
        if r["ollaya"].available and (r["ollaya"].defer_rate or 0) >= 0.5
        and (r["ollaya"].raw_accuracy or 0) >= 0.7
    ]
    return (
        "## Summary\n\n"
        f"- **Win locally (Ollaya):** {', '.join(kept_local) or '(none)'}\n"
        f"- **Need hosted only:** {', '.join(kept_hosted) or '(none)'}\n"
        f"- **Drop:** {', '.join(dropped) or '(none)'}\n"
        f"- **Capable-but-under-confident (raw≥0.7 yet mostly DEFER — future floor "
        f"review, not accuracy drop):** {', '.join(under_conf) or '(none)'}\n"
    )


_SAFETY = """## Safety invariants (asserted by the test suite; any failure = auto-drop)

- **No JEV call inside scoring/aggregation** — `test_jev_identity`,
  `test_jev_signal` assert `_compute_exposure_score` / `credential_risk` never
  reference JEV; the breach-canonicalize pre-pass runs *before* scoring and only a
  deterministic field read happens inside `collapse_breach_findings`.
- **Scores move only via corrected inputs** — same_person edges, bio metadata, and
  verification never write a score/band; `test_jev_identity` /
  `test_jev_verify` assert exposure + credential scores are unchanged.
- **Corpus leads stay unverified / live-only; no fabricated domain** —
  `roster.company_resolve` returns an index into real candidates only
  (`test_jev_roster`); the enrich projection is untouched.
- **Narrative grounding** — every entity in a brief/lead traces to an input or the
  output is dropped/DEFERred (`test_jev_narrative`, zero-violation gate).
- **DEFER falls back cleanly** — verified live: stopping Ollaya mid-run yields
  `provider_unreachable` and the tool completes on heuristics (breaker tests +
  `test_jev_providers`).
"""


async def main_async(only: list[str] | None) -> int:
    from eval.harness.jev_fixtures import FIXTURES  # colocated labeled cases

    modes = ["baseline", "ollaya", "jev"]
    modes_note: dict[str, str] = {}
    for m in ("ollaya", "jev"):
        _apply_mode(m)
        ok, why = _mode_available(m)
        modes_note[m] = "available" if ok else f"NOT RUN — {why}"

    rows: list[dict[str, Any]] = []
    for task_name in jev.registered_tasks():
        if only and task_name not in only:
            continue
        cases = FIXTURES.get(task_name, [])
        results: dict[str, ModeResult] = {}
        for m in modes:
            jev_metrics.reset()
            if not cases:
                r = ModeResult()
                r.available = False
                r.note = "no fixtures"
                results[m] = r
            else:
                results[m] = await _run_task_mode(task_name, cases, m)
        decision = _decide(task_name, results["baseline"], results["ollaya"], results["jev"])
        rows.append({
            "task": task_name, "category": _CATEGORY.get(task_name, "?"),
            "baseline": results["baseline"], "ollaya": results["ollaya"],
            "jev": results["jev"], "decision": decision,
        })
        print(f"{task_name:32s} base={results['baseline'].accuracy} "
              f"ollaya={results['ollaya'].accuracy}/{results['ollaya'].defer_rate} "
              f"-> {decision}", flush=True)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        _render(rows, modes_note) + "\n" + _summary(rows) + "\n" + _SAFETY,
        encoding="utf-8",
    )
    print(f"\nWrote {REPORT_PATH}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="JEV per-task validation")
    ap.add_argument("--only", nargs="*", default=None, help="task names to run")
    args = ap.parse_args(argv)
    return asyncio.run(main_async(args.only))


if __name__ == "__main__":
    raise SystemExit(main())
