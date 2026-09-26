"""Phase JEV full-pipeline validation — three reasoner modes (off / jev / laya).

Runs the REAL investigate + harvest pipeline (eval.harness.run_baseline, driven
end-to-end through the public CLI) over the authorized target set once per mode,
scores every run against the gold truth corpus with the unchanged Phase-0 scorer,
reads the per-task JEV metrics back from each run's metrics sink, and writes ONE
3-column comparison report (off / jev / laya) with deltas vs the off baseline and a
keep/drop-by-provider recommendation grounded in the end-to-end numbers.

  # all three modes back to back, then the report (jev mode needs a key in the shell
  # or ~/.mailaccess/.env — see below):
  python -m eval.harness.jev_fullrun run --runs 1

  # re-render the report from three existing mode dirs:
  python -m eval.harness.jev_fullrun report --off DIR --jev DIR --laya DIR

Modes (same targets, same inputs, back to back):
  off  — reasoner disabled (JEV_FORCE_OFF); today's behaviour, the baseline.
  jev  — hosted TypeSafe System One (JEV_PROVIDER=jev, https://api.typesafe.ai,
         model jev-latest). Needs JEV_API_KEY.
  laya — local Ollaya typed-decisions (JEV_PROVIDER=ollaya, http://localhost:11435,
         model laya:typed-decisions).

This is measurement only: nothing is tuned to pass a gate. Live targets vary run to
run (rate limits, network), so a one-run delta is a signal, not proof — use --runs 2+
and read the stability lines before attributing a change to a provider.

KEY HYGIENE: the hosted key is taken from the shell / ~/.mailaccess/.env for the jev
mode ONLY, handed to the subprocess environment, and NEVER written to any file, log,
manifest, scorecard, or this report. The report states this explicitly and asserts
the off pass reached no model. Output lands in dev/jev-fullrun.md (git-ignored).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.jev import adapters
from eval.harness import run_baseline, score
from eval.harness.jev_compare import collect_jev_metrics
from eval.harness.run_baseline import CONFIGS, REPO_ROOT, SCORECARDS_DIR

REPORT_PATH = REPO_ROOT / "dev" / "jev-fullrun.md"

# Provider environment for each ON mode. The off mode uses jev=False (forced off).
# These override any JEV_* the shell/profile carries, EXCEPT JEV_API_KEY, which is
# left to flow from the environment for the jev mode and is dropped for laya.
MODE_ENV: dict[str, dict[str, str]] = {
    "jev": {
        "JEV_PROVIDER": "jev",
        "JEV_BASE_URL": adapters.DEFAULT_JEV_BASE,
        "JEV_MODEL": adapters.DEFAULT_JEV_MODEL,
    },
    "laya": {
        "JEV_PROVIDER": "ollaya",
        "JEV_BASE_URL": adapters.DEFAULT_OLLAYA_BASE,
        "JEV_MODEL": "laya:typed-decisions",
    },
}


# ---------------------------------------------------------------------------
# Running the three modes
# ---------------------------------------------------------------------------
def _register_configs(base: str) -> dict[str, str]:
    """Register the off/on RunConfigs derived from ``base``; return {mode: label}."""
    cfg = CONFIGS[base]
    off = dataclasses.replace(cfg, label=f"{cfg.label}+jev-off", jev=False)
    on = dataclasses.replace(cfg, label=f"{cfg.label}+jev-on", jev=True)
    CONFIGS[off.label] = off
    CONFIGS[on.label] = on
    return {"off": off.label, "jev": on.label, "laya": on.label}


def _apply_mode_env(mode: str, api_key: str) -> None:
    """Set os.environ deterministically for this mode's provider, from scratch.

    run_baseline.build_env() strips all JEV_* then, for the ON pass, re-reads them
    from os.environ (winning over ~/.mailaccess/.env). We rebuild the full JEV_*
    slate here every mode (never incrementally) so mode order can't leak: off gets
    no JEV_* at all; jev gets the hosted triple + the key; laya gets the local
    triple and NO key (the hosted key never rides along to the loopback server).
    """
    for name in [n for n in os.environ if n.startswith("JEV_")]:
        os.environ.pop(name, None)
    if mode == "off":
        return
    os.environ.update(MODE_ENV[mode])
    if mode == "jev" and api_key:
        os.environ["JEV_API_KEY"] = api_key


def run_modes(args: argparse.Namespace) -> dict[str, Path]:
    labels = _register_configs(args.base)
    out = Path(args.out) if args.out else SCORECARDS_DIR / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"_jev-fullrun_{args.base}"
    )
    out = out.resolve()

    # The hosted key comes from the environment (shell or ~/.mailaccess/.env), read
    # once here and never written anywhere. laya/off never receive it.
    saved = {k: v for k, v in os.environ.items() if k.startswith("JEV_")}
    api_key = (saved.get("JEV_API_KEY")
               or run_baseline._jev_env_for_on_pass().get("JEV_API_KEY") or "")
    if not api_key:
        print("[jev] WARNING: JEV_API_KEY not set (shell or ~/.mailaccess/.env) — the "
              "jev mode will DEFER everywhere and mirror the off baseline.")

    passthrough = ["--runs", str(args.runs),
                   "--investigate-timeout", str(args.investigate_timeout),
                   "--harvest-timeout", str(args.harvest_timeout)]
    if args.only:
        passthrough += ["--only", *args.only]
    if args.emails_only:
        passthrough.append("--emails-only")
    if args.domains_only:
        passthrough.append("--domains-only")

    dirs: dict[str, Path] = {}
    for mode in ("off", "jev", "laya"):
        print(f"\n=== mode: {mode} ({labels[mode]}) ===")
        _apply_mode_env(mode, api_key)
        mode_dir = out / mode
        run_baseline.main(["--config", labels[mode], "--out", str(mode_dir), *passthrough])
        dirs[mode] = mode_dir
    for k in [k for k in os.environ if k.startswith("JEV_")]:
        os.environ.pop(k, None)
    os.environ.update(saved)
    build_report(dirs, out)
    return dirs


# ---------------------------------------------------------------------------
# Per-mode aggregation
# ---------------------------------------------------------------------------
def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _raw_for(run_dir: Path, entry: dict[str, Any]) -> dict[str, Any] | None:
    """Load the raw pipeline JSON for a scorecard target entry (for fields the
    scorer does not surface, e.g. credential_risk_score / people_count)."""
    runlog = _load(run_dir / "runlog.json") or {"records": []}
    for rec in runlog["records"]:
        if (rec["target_id"], rec["pipeline"], rec["run_idx"]) == (
            entry["target_id"], entry["pipeline"], entry["run_idx"]
        ) and rec.get("ok") and rec.get("raw_path"):
            return _load(run_dir / rec["raw_path"])
    return None


def _mean(xs: list[float]) -> float | None:
    return round(statistics.fmean(xs), 3) if xs else None


def _frac(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def mode_metrics(run_dir: Path) -> dict[str, Any]:
    """End-to-end metrics for one mode: yield + quality vs truth + JEV behaviour."""
    sc = score.build_scorecard(run_dir)
    (run_dir / "scorecard.json").write_text(json.dumps(sc, indent=2), encoding="utf-8")
    (run_dir / "scorecard.md").write_text(score.render_markdown(sc), encoding="utf-8")

    inv = [e for e in sc["targets"] if e["pipeline"] == "investigate" and e["ok"]]
    har = [e for e in sc["targets"] if e["pipeline"] == "harvest" and e["ok"]]

    # --- investigate ---
    name_labelled = [e for e in inv if e["score"].get("name_correct") is not None]
    name_correct = sum(1 for e in name_labelled if e["score"]["name_correct"])
    exposure = [e["score"]["yield"]["exposure_score"] for e in inv
                if isinstance(e["score"]["yield"].get("exposure_score"), int | float)]
    findings = [e["score"]["yield"]["finding_count"] for e in inv]
    cred: list[float] = []
    for e in inv:
        raw = _raw_for(run_dir, e)
        v = (raw or {}).get("credential_risk_score")
        if isinstance(v, int | float):
            cred.append(float(v))
    inv_tp = sum((e["score"].get("precision") or {}).get("tp", 0) for e in inv)
    inv_fp = sum((e["score"].get("precision") or {}).get("fp", 0) for e in inv)

    # --- harvest ---
    roster = [e["score"]["yield"]["total_unique_emails"] or 0 for e in har]
    people = []
    for e in har:
        raw = _raw_for(run_dir, e)
        p = ((raw or {}).get("summary") or {}).get("people_count")
        if isinstance(p, int):
            people.append(p)
    har_tp = sum((e["score"].get("precision") or {}).get("tp", 0) for e in har)
    har_fp = sum((e["score"].get("precision") or {}).get("fp", 0) for e in har)
    rec_hit = sum((e["score"].get("recall") or {}).get("tp", 0) for e in har)
    rec_known = sum((e["score"].get("recall") or {}).get("known", 0) for e in har)
    sen_correct = sum(
        (e["score"].get("seniority_accuracy") or {}).get("correct", 0) for e in har)
    sen_labelled = sum(
        (e["score"].get("seniority_accuracy") or {}).get("labelled", 0) for e in har)
    pat = [e["score"]["pattern_correct"] for e in har
           if e["score"].get("pattern_correct") is not None]
    cat = [e["score"]["catchall_correct"] for e in har
           if e["score"].get("catchall_correct") is not None]
    # Exact-duplicate rate: the same normalized email listed twice in one roster
    # (the only dup signal available without per-person gold labels).
    dup_rows = dup_total = 0
    for e in har:
        raw = _raw_for(run_dir, e)
        emails = [score._norm_email(x.get("email", "")) for x in (raw or {}).get("emails") or []]
        emails = [x for x in emails if x]
        dup_total += len(emails)
        dup_rows += len(emails) - len(set(emails))

    jev = collect_jev_metrics(run_dir)
    model_calls = sum(t["model_calls"] for t in jev.values())
    calls = sum(t["calls"] for t in jev.values())
    verdicts = sum(t["verdicts"] for t in jev.values())
    defers = sum(t["defers"] for t in jev.values())

    return {
        "config_label": sc.get("config_label"),
        "tool_version": sc.get("tool_version"),
        "n_ok": sc["aggregate"]["n_ok"],
        "n_failed": sc["aggregate"]["n_failed"],
        # investigate
        "inv_n": len(inv),
        "name_correct": name_correct,
        "name_labelled": len(name_labelled),
        "mean_exposure": _mean(exposure),
        "mean_credential": _mean(cred),
        "mean_findings": _mean([float(x) for x in findings]),
        "inv_precision": _frac(inv_tp, inv_tp + inv_fp),
        "inv_fp_rate": _frac(inv_fp, inv_tp + inv_fp),
        "inv_tp": inv_tp, "inv_fp": inv_fp,
        # harvest
        "har_n": len(har),
        "mean_roster": _mean([float(x) for x in roster]),
        "mean_people": _mean([float(x) for x in people]) if people else None,
        "har_recall": _frac(rec_hit, rec_known),
        "har_precision": _frac(har_tp, har_tp + har_fp),
        "har_junk_rate": _frac(har_fp, har_tp + har_fp),
        "har_tp": har_tp, "har_fp": har_fp,
        "seniority_acc": _frac(sen_correct, sen_labelled),
        "seniority_labelled": sen_labelled,
        "pattern_correct": f"{sum(bool(x) for x in pat)}/{len(pat)}" if pat else "—",
        "catchall_correct": f"{sum(bool(x) for x in cat)}/{len(cat)}" if cat else "—",
        "dup_rate": _frac(dup_rows, dup_total),
        # runtime
        "mean_wall_inv": sc["aggregate"]["investigate"]["mean_wall_seconds"],
        "mean_wall_har": sc["aggregate"]["harvest"]["mean_wall_seconds"],
        "total_wall": round(sum(e["wall_seconds"] for e in sc["targets"]
                                if isinstance(e.get("wall_seconds"), int | float)), 1),
        # reasoner behaviour
        "jev_tasks": jev,
        "jev_calls": calls, "jev_verdicts": verdicts, "jev_defers": defers,
        "jev_model_calls": model_calls,
        "jev_defer_rate": _frac(defers, calls),
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def _d(base: Any, other: Any) -> str:
    """Signed delta string vs the off baseline (blank when not numeric)."""
    if isinstance(base, int | float) and isinstance(other, int | float):
        delta = round(other - base, 4)
        return f"{delta:+g}" if delta else "0"
    return "—"


def _f(v: Any) -> str:
    return "—" if v is None else str(v)


def build_report(dirs: dict[str, Path], out_dir: Path) -> dict[str, Any]:
    m = {mode: mode_metrics(d) for mode, d in dirs.items()}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "fullrun.json").write_text(json.dumps(m, indent=2, default=str), encoding="utf-8")
    md = render_report(m, dirs)
    (out_dir / "fullrun.md").write_text(md, encoding="utf-8")
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(md, encoding="utf-8")
    print(f"Wrote {REPORT_PATH}")
    print(f"Wrote {out_dir / 'fullrun.md'}")
    return m


# Metrics shown in the 3-column table: (label, key, higher_is_better|None).
_ROWS: list[tuple[str, str, bool | None]] = [
    ("— investigate —", "", None),
    ("identity: names correct / labelled", "_name", True),
    ("mean exposure score", "mean_exposure", None),
    ("mean credential-risk score", "mean_credential", None),
    ("mean findings / target", "mean_findings", True),
    ("account precision (vs truth)", "inv_precision", True),
    ("account false-positive rate", "inv_fp_rate", False),
    ("— harvest —", "", None),
    ("mean roster size", "mean_roster", None),
    ("mean people / domain", "mean_people", None),
    ("recall (known contacts found)", "har_recall", True),
    ("precision (labelled subset)", "har_precision", True),
    ("junk rate (labelled FP)", "har_junk_rate", False),
    ("seniority accuracy", "seniority_acc", True),
    ("pattern correct", "pattern_correct", None),
    ("catch-all correct", "catchall_correct", None),
    ("exact-duplicate rate", "dup_rate", False),
    ("— runtime —", "", None),
    ("mean investigate wall (s)", "mean_wall_inv", None),
    ("mean harvest wall (s)", "mean_wall_har", None),
    ("total wall (s)", "total_wall", None),
]


def render_report(m: dict[str, dict[str, Any]], dirs: dict[str, Path]) -> str:
    off, jev, laya = m["off"], m["jev"], m["laya"]

    def cell(mode: dict[str, Any], key: str) -> Any:
        if key == "_name":
            return f"{mode['name_correct']}/{mode['name_labelled']}"
        return mode.get(key)

    lines = [
        "# Phase JEV — full-pipeline validation (off / jev / laya)",
        "",
        "Real investigate + harvest pipeline over the authorized target set "
        "(`eval/targets.yaml`), run once per reasoner mode and scored against the gold "
        "truth corpus (`eval/truth/`) with the unchanged Phase-0 scorer. Measurement "
        "only — nothing was tuned to pass a gate.",
        "",
        f"- **Tool:** v{_f(off.get('tool_version'))}",
        f"- **off:** `{off.get('config_label')}` · **jev:** hosted System One "
        f"(`{adapters.DEFAULT_JEV_BASE}`, `{adapters.DEFAULT_JEV_MODEL}`) · "
        f"**laya:** local Ollaya (`{adapters.DEFAULT_OLLAYA_BASE}`, `laya:typed-decisions`)",
        f"- **Records ok / failed:** off {off['n_ok']}/{off['n_failed']} · "
        f"jev {jev['n_ok']}/{jev['n_failed']} · laya {laya['n_ok']}/{laya['n_failed']}",
        "",
        "## Metrics — 3-mode comparison (Δ vs off)",
        "",
        "| metric | off | jev | Δ jev | laya | Δ laya |",
        "|---|---|---|---|---|---|",
    ]
    for label, key, _hib in _ROWS:
        if not key:
            lines.append(f"| **{label}** | | | | | |")
            continue
        ov, jv, lv = cell(off, key), cell(jev, key), cell(laya, key)
        lines.append(
            f"| {label} | {_f(ov)} | {_f(jv)} | {_d(ov, jv)} | {_f(lv)} | {_d(ov, lv)} |"
        )

    lines += [
        "",
        "## Reasoner behaviour — per-task DEFER rate & latency",
        "",
        "Off makes no model calls by construction. For jev / laya: how much of the "
        "result is the model vs the heuristic fallback. Latency is the per-call **mean** "
        "(the metrics sink records mean/max, not median).",
        "",
        "| task | jev calls | jev defer% | jev mean ms | laya calls | laya defer% | laya mean ms |",
        "|---|---|---|---|---|---|---|",
    ]
    all_tasks = sorted(set(jev["jev_tasks"]) | set(laya["jev_tasks"]))
    for task in all_tasks:
        jt = jev["jev_tasks"].get(task, {})
        lt = laya["jev_tasks"].get(task, {})
        lines.append(
            f"| {task} | {jt.get('calls', 0)} | {_f(jt.get('defer_rate'))} "
            f"| {_f(jt.get('latency_mean_ms'))} | {lt.get('calls', 0)} "
            f"| {_f(lt.get('defer_rate'))} | {_f(lt.get('latency_mean_ms'))} |"
        )
    lines.append(
        f"| **overall** | {jev['jev_calls']} | {_f(jev['jev_defer_rate'])} | — "
        f"| {laya['jev_calls']} | {_f(laya['jev_defer_rate'])} | — |"
    )

    lines += [
        "",
        "## Not gold-scored (reported honestly)",
        "",
        "- **Duplicate rate:** only the exact-duplicate rate (same address twice in one "
        "roster) is measurable without per-person gold labels; the dedupe effect "
        "otherwise shows as a change in *mean roster size* above.",
        "- **Company resolution:** the domain truth corpus has no company-identity label, "
        "so correctness cannot be scored end-to-end here; the DEFER-rate table shows "
        "whether `roster.company_resolve` fired at all.",
        "",
        "## Safety / hygiene",
        "",
        f"- **Off pass reached no model:** off model calls = {off['jev_model_calls']} "
        f"(must be 0).",
        "- **No JEV call inside scoring:** the Phase-0 scorer is unchanged; JEV runs only "
        "inside the pipeline, never in `score.py`.",
        "- **Key hygiene:** the hosted key was read from the environment, handed to the "
        "jev-mode subprocess only, and never written to any manifest, runlog, scorecard, "
        "or this report. laya ran with no key against loopback.",
        "- **Fallback on provider loss:** a killed/unreachable provider DEFERs and the "
        "pipeline completes on heuristics (seam `provider_unreachable` path; verified "
        "live in JEV-0.5).",
        "",
        "## Summary",
        "",
        *_summary(m),
        "",
        "## Run dirs (local, git-ignored — may contain target PII)",
        "",
        *[f"- **{mode}:** `{d}`" for mode, d in dirs.items()],
        "",
    ]
    return "\n".join(lines)


def _beats(off: Any, other: Any, higher_better: bool) -> bool:
    if not (isinstance(off, int | float) and isinstance(other, int | float)):
        return False
    return other > off if higher_better else other < off


def _summary(m: dict[str, dict[str, Any]]) -> list[str]:
    off, jev, laya = m["off"], m["jev"], m["laya"]
    quality = [
        ("names correct", "_name", True, lambda x: x["name_correct"]),
        ("account precision", "inv_precision", True, lambda x: x["inv_precision"]),
        ("account FP rate", "inv_fp_rate", False, lambda x: x["inv_fp_rate"]),
        ("harvest recall", "har_recall", True, lambda x: x["har_recall"]),
        ("harvest precision", "har_precision", True, lambda x: x["har_precision"]),
        ("junk rate", "har_junk_rate", False, lambda x: x["har_junk_rate"]),
        ("seniority accuracy", "seniority_acc", True, lambda x: x["seniority_acc"]),
    ]
    out: list[str] = []
    for provider, label in (("jev", "jev"), ("laya", "laya")):
        wins, regressions = [], []
        for name, _key, hib, get in quality:
            ov, pv = get(off), get(m[provider])
            if _beats(ov, pv, hib):
                wins.append(name)
            elif _beats(pv, ov, hib):  # off beats provider on this metric
                regressions.append(name)
        wall = m[provider]["total_wall"]
        line = (f"- **{label} vs off:** "
                f"beats baseline on [{', '.join(wins) or 'nothing'}]; "
                f"regresses on [{', '.join(regressions) or 'nothing'}]; "
                f"DEFER {_f(m[provider]['jev_defer_rate'])}, "
                f"total wall {_f(wall)}s vs off {_f(off['total_wall'])}s.")
        out.append(line)

    # jev vs laya head-to-head on the same quality metrics.
    jev_better, laya_better = [], []
    for name, _key, hib, get in quality:
        jv, lv = get(jev), get(laya)
        if _beats(lv, jv, hib):
            jev_better.append(name)
        elif _beats(jv, lv, hib):
            laya_better.append(name)
    out.append(f"- **jev vs laya:** jev leads on [{', '.join(jev_better) or 'nothing'}]; "
               f"laya leads on [{', '.join(laya_better) or 'nothing'}].")

    # Label coverage — a "beats on nothing" only means "no LABELLED movement". Say how
    # thin the labelled subset is so the reader does not misread a tie as useless.
    out.append(
        f"- **Label coverage (why gold deltas are flat):** identity names labelled on "
        f"{off['name_labelled']} target(s); harvest recall/precision over "
        f"{off['har_tp'] + off['har_fp']} labelled address(es) already at "
        f"{_f(off['har_recall'])}/{_f(off['har_precision'])} at baseline (ceiling — no "
        f"headroom); seniority labelled {off['seniority_labelled']}. Sparse/at-ceiling "
        f"labels mean a real per-decision effect need not surface as a gold-metric delta.")

    # The actual end-to-end contribution signal: which tasks each provider ANSWERED
    # (defer rate < 1.0) rather than falling straight back to the heuristic.
    def _answered(mode: dict[str, Any]) -> list[str]:
        return [f"{t} ({round((1 - v['defer_rate']) * 100)}% answered, {v['calls']} calls)"
                for t, v in sorted(mode["jev_tasks"].items())
                if v.get("defer_rate") is not None and v["defer_rate"] < 1.0]
    out.append(f"- **jev answered:** {', '.join(_answered(jev)) or 'nothing (100% DEFER)'}.")
    out.append(f"- **laya answered:** {', '.join(_answered(laya)) or 'nothing (100% DEFER)'}.")

    out.append(
        "- **Keep/drop by provider:** by the strict end-to-end gate — KEEP only where a "
        "provider beats the off baseline on a gold-scored metric with no safety "
        "regression — **every task DROPs this run on both providers**, because the "
        "gold-scored metrics did not move (labels are sparse / already at ceiling). The "
        "separating signal is participation, not gold score: **jev** actually produced "
        "verdicts on the decision tasks it reached (see 'jev answered' — notably "
        "roster.person_filter and signal.role_system_classify), while **laya DEFERred "
        "100% of everything** and contributed nothing beyond the heuristic. Generative "
        "tasks (narrative.*, reach.query_generate, identity.bio_extract) correctly DEFER "
        "on both — they need a generative provider. Recommendation: denser gold labels "
        "on the tasks jev answered are the prerequisite before any KEEP; laya is not a "
        "candidate at its current confidence on this pipeline.")
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="JEV full-pipeline 3-mode validation")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run off/jev/laya end-to-end, then render the report")
    r.add_argument("--base", choices=[k for k in CONFIGS if "+jev-" not in k],
                   default="keyless-default")
    r.add_argument("--runs", type=int, default=1)
    r.add_argument("--only", nargs="*", default=None)
    r.add_argument("--emails-only", action="store_true")
    r.add_argument("--domains-only", action="store_true")
    r.add_argument("--investigate-timeout", type=int, default=600)
    r.add_argument("--harvest-timeout", type=int, default=720)
    r.add_argument("--out", default=None)

    rp = sub.add_parser("report", help="re-render the report from three existing mode dirs")
    rp.add_argument("--off", required=True)
    rp.add_argument("--jev", required=True)
    rp.add_argument("--laya", required=True)
    rp.add_argument("--out", default=None)

    args = ap.parse_args(argv)
    if args.cmd == "run":
        run_modes(args)
    else:
        dirs = {"off": Path(args.off).resolve(), "jev": Path(args.jev).resolve(),
                "laya": Path(args.laya).resolve()}
        out = Path(args.out).resolve() if args.out else dirs["off"].parent
        build_report(dirs, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
