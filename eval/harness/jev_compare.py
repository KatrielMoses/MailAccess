"""Phase JEV side-by-side eval — the same target set, JEV off vs JEV on.

Every JEV phase (JEV-1…6) is accepted or dropped on this comparison. It runs the
existing baseline harness twice on the local build — once with JEV forced OFF
(== current behavior) and once with JEV forced ON — scores both against the gold
truth corpus with the unchanged Phase-0 scorer, and writes one comparison
scorecard: per-task JEV call/defer/cache/latency metrics, per-target output and
quality deltas, and any score drift to review.

  # both passes + comparison. The ON pass takes JEV_* from this shell, falling back
  # to ~/.mailaccess/.env (where `mailaccess keys set JEV_API_KEY …` stores it);
  # the OFF pass strips every JEV_* var and sets the JEV_FORCE_OFF override.
  python -m eval.harness.jev_compare run --base keyless-default --runs 1

  # re-compare two existing run dirs
  python -m eval.harness.jev_compare compare --off <run_dir> --on <run_dir>

Live targets vary run to run (rate limits, network), so a delta on one run is not
proof: use ``--runs 2+`` and read the stability section of each scorecard before
attributing a change to JEV. Outputs land under eval/scorecards/ (gitignored —
they contain target PII). A key value is only ever handed to the ON-pass subprocess
environment — never recorded in a manifest, runlog or scorecard.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.jev.metrics import merge_snapshots
from eval.harness import run_baseline, score
from eval.harness.run_baseline import CONFIGS, JEV_METRICS_SUBDIR, SCORECARDS_DIR

# Keys whose values change run to run without meaning the output changed.
_VOLATILE_SUFFIXES = ("_at", "_time", "_ms", "_seconds", "timestamp", "_date")
_VOLATILE_KEYS = frozenset({"time", "date", "latency", "elapsed", "duration"})


# ---------------------------------------------------------------------------
# Running both passes
# ---------------------------------------------------------------------------
def _register_pair(base: str, refresh_cache: bool) -> tuple[str, str]:
    cfg = CONFIGS[base]
    off = dataclasses.replace(cfg, label=f"{cfg.label}+jev-off", jev=False)
    on = dataclasses.replace(
        cfg, label=f"{cfg.label}+jev-on", jev=True, jev_cache_refresh=refresh_cache
    )
    CONFIGS[off.label] = off
    CONFIGS[on.label] = on
    return off.label, on.label


def run_pair(args: argparse.Namespace) -> Path:
    off_label, on_label = _register_pair(args.base, args.refresh_cache)
    out = Path(args.out) if args.out else SCORECARDS_DIR / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"_jev-compare_{args.base}"
    )
    out = out.resolve()
    on_env = run_baseline._jev_env_for_on_pass()
    missing = [n for n in ("JEV_API_KEY", "JEV_BASE_URL", "JEV_MODEL") if not on_env.get(n)]
    if missing:
        print(f"[jev] WARNING: {', '.join(missing)} not set (shell or ~/.mailaccess/.env) "
              f"— the ON pass will DEFER everywhere and match the OFF pass.")

    passthrough: list[str] = ["--runs", str(args.runs),
                              "--investigate-timeout", str(args.investigate_timeout),
                              "--harvest-timeout", str(args.harvest_timeout)]
    if args.only:
        passthrough += ["--only", *args.only]
    if args.emails_only:
        passthrough.append("--emails-only")
    if args.domains_only:
        passthrough.append("--domains-only")

    for label, sub in ((off_label, "off"), (on_label, "on")):
        print(f"\n=== {label} ===")
        run_baseline.main(["--config", label, "--out", str(out / sub), *passthrough])
    compare(out / "off", out / "on", out)
    return out


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------
def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _scorecard(run_dir: Path) -> dict[str, Any]:
    sc = score.build_scorecard(run_dir)
    (run_dir / "scorecard.json").write_text(json.dumps(sc, indent=2), encoding="utf-8")
    (run_dir / "scorecard.md").write_text(score.render_markdown(sc), encoding="utf-8")
    return sc


def collect_jev_metrics(run_dir: Path) -> dict[str, dict[str, Any]]:
    snaps = [
        s for p in sorted((run_dir / "home").glob(f"*/{JEV_METRICS_SUBDIR}/jev-metrics-*.json"))
        if (s := _load(p)) is not None
    ]
    return merge_snapshots(snaps)


def _strip_volatile(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: _strip_volatile(v) for k, v in obj.items()
            if k.lower() not in _VOLATILE_KEYS and not k.lower().endswith(_VOLATILE_SUFFIXES)
        }
    if isinstance(obj, list):
        return [_strip_volatile(v) for v in obj]
    return obj


def _finding_keys(raw: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for f in raw.get("findings") or []:
        data = json.dumps(_strip_volatile(f.get("data")), sort_keys=True, default=str)
        keys.add(f"{f.get('module_name')}:{hashlib.sha1(data.encode()).hexdigest()[:12]}")
    return keys


def _email_keys(raw: dict[str, Any]) -> set[str]:
    return {score._norm_email(e.get("email", "")) for e in raw.get("emails") or []} - {""}


def _value(block: Any) -> float | None:
    return block.get("value") if isinstance(block, dict) else None


def _pair_records(off_dir: Path, on_dir: Path) -> list[dict[str, Any]]:
    off_log = _load(off_dir / "runlog.json") or {"records": []}
    on_log = _load(on_dir / "runlog.json") or {"records": []}
    truth = score.load_truth()
    on_by_key = {(r["target_id"], r["pipeline"], r["run_idx"]): r for r in on_log["records"]}
    pairs: list[dict[str, Any]] = []
    for off_rec in off_log["records"]:
        key = (off_rec["target_id"], off_rec["pipeline"], off_rec["run_idx"])
        on_rec = on_by_key.get(key)
        entry: dict[str, Any] = {
            "target_id": key[0], "pipeline": key[1], "run_idx": key[2],
            "ok_off": off_rec.get("ok"), "ok_on": bool(on_rec and on_rec.get("ok")),
            "wall_off": off_rec.get("wall_seconds"),
            "wall_on": on_rec.get("wall_seconds") if on_rec else None,
            "jev": collect_jev_metrics_for(on_dir, key),
        }
        raw_off = _load(off_dir / off_rec["raw_path"]) if off_rec.get("ok") else None
        raw_on = _load(on_dir / on_rec["raw_path"]) if on_rec and on_rec.get("ok") else None
        if raw_off is None or raw_on is None:
            entry["comparable"] = False
            pairs.append(entry)
            continue
        entry["comparable"] = True
        t = truth.get(key[0])
        if key[1] == "harvest":
            s_off, s_on = score.score_harvest(raw_off, t), score.score_harvest(raw_on, t)
            k_off, k_on = _email_keys(raw_off), _email_keys(raw_on)
            numbers = {}
        else:
            s_off, s_on = score.score_investigate(raw_off, t), score.score_investigate(raw_on, t)
            k_off, k_on = _finding_keys(raw_off), _finding_keys(raw_on)
            numbers = {
                n: (raw_off.get(n), raw_on.get(n))
                for n in ("exposure_score", "credential_risk_score", "risk_level")
            }
        entry.update({
            "has_truth": t is not None,
            "outputs_identical": k_off == k_on,
            "added": len(k_on - k_off),
            "removed": len(k_off - k_on),
            "precision": (_value(s_off.get("precision")), _value(s_on.get("precision"))),
            "recall": (_value(s_off.get("recall")), _value(s_on.get("recall"))),
            "name_correct": (s_off.get("name_correct"), s_on.get("name_correct")),
            "score_drift": {n: v for n, v in numbers.items() if v[0] != v[1]},
        })
        pairs.append(entry)
    return pairs


def collect_jev_metrics_for(run_dir: Path, key: tuple[str, str, int]) -> dict[str, Any]:
    home = run_dir / "home" / f"{key[0]}.run{key[2]}" / JEV_METRICS_SUBDIR
    snaps = [s for p in sorted(home.glob("jev-metrics-*.json")) if (s := _load(p)) is not None]
    merged = merge_snapshots(snaps)
    return {
        "calls": sum(t["calls"] for t in merged.values()),
        "verdicts": sum(t["verdicts"] for t in merged.values()),
    }


def _mean_pair(pairs: list[dict[str, Any]], field: str) -> dict[str, float | None]:
    offs = [p[field][0] for p in pairs if p.get("comparable") and p[field][0] is not None]
    ons = [p[field][1] for p in pairs if p.get("comparable") and p[field][1] is not None]
    mean_off = round(statistics.fmean(offs), 4) if offs else None
    mean_on = round(statistics.fmean(ons), 4) if ons else None
    delta = round(mean_on - mean_off, 4) if mean_off is not None and mean_on is not None else None
    return {"off": mean_off, "on": mean_on, "delta": delta, "n_off": len(offs), "n_on": len(ons)}


def compare(off_dir: Path, on_dir: Path, out_dir: Path) -> dict[str, Any]:
    _scorecard(off_dir)
    sc_on = _scorecard(on_dir)
    pairs = _pair_records(off_dir, on_dir)
    jev_on = collect_jev_metrics(on_dir)
    jev_off = collect_jev_metrics(off_dir)
    comparable = [p for p in pairs if p.get("comparable")]
    walls = [(p["wall_off"], p["wall_on"]) for p in comparable
             if p["wall_off"] is not None and p["wall_on"] is not None]
    comparison = {
        "schema_version": 1,
        "off_run": str(off_dir),
        "on_run": str(on_dir),
        "tool_version": sc_on.get("tool_version"),
        "jev_model": ((_load(on_dir / "manifest.json") or {}).get("extra") or {}).get("jev_model"),
        # Guard: the OFF pass must never have reached a model.
        "off_pass_model_calls": sum(t["model_calls"] for t in jev_off.values()),
        "jev_tasks": jev_on,
        "summary": {
            "n_pairs": len(pairs),
            "n_comparable": len(comparable),
            "n_outputs_identical": sum(1 for p in comparable if p["outputs_identical"]),
            "n_score_drift": sum(1 for p in comparable if p["score_drift"]),
            "precision": _mean_pair(comparable, "precision"),
            "recall": _mean_pair(comparable, "recall"),
            "name_correct": {
                "off": sum(1 for p in comparable if p["name_correct"][0] is True),
                "on": sum(1 for p in comparable if p["name_correct"][1] is True),
            },
            "mean_wall_seconds": {
                "off": round(statistics.fmean(w[0] for w in walls), 3) if walls else None,
                "on": round(statistics.fmean(w[1] for w in walls), 3) if walls else None,
            },
        },
        "pairs": pairs,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "comparison.json").write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    (out_dir / "comparison.md").write_text(render_markdown(comparison), encoding="utf-8")
    print(f"Wrote {out_dir / 'comparison.json'}")
    print(f"Wrote {out_dir / 'comparison.md'}")
    return comparison


def _fmt(v: Any) -> str:
    return "—" if v is None else str(v)


def render_markdown(c: dict[str, Any]) -> str:
    s = c["summary"]
    lines = [
        "# JEV side-by-side scorecard — OFF vs ON",
        "",
        f"- **Tool:** v{_fmt(c['tool_version'])}  ·  **JEV model:** `{_fmt(c['jev_model'])}`",
        f"- **OFF run:** `{c['off_run']}`",
        f"- **ON run:** `{c['on_run']}`",
        f"- **OFF-pass model calls (must be 0):** {c['off_pass_model_calls']}",
        f"- **Pairs:** {s['n_pairs']}  ·  comparable {s['n_comparable']}  ·  outputs identical "
        f"{s['n_outputs_identical']}  ·  score drift {s['n_score_drift']}",
        "",
        "## Quality delta (vs gold truth)",
        "",
        "| metric | OFF | ON | Δ |",
        "|---|---|---|---|",
    ]
    for name in ("precision", "recall"):
        m = s[name]
        lines.append(f"| mean {name} | {_fmt(m['off'])} | {_fmt(m['on'])} | {_fmt(m['delta'])} |")
    nc = s["name_correct"]
    lines.append(f"| names correct | {nc['off']} | {nc['on']} | {nc['on'] - nc['off']} |")
    w = s["mean_wall_seconds"]
    lines.append(f"| mean wall (s) | {_fmt(w['off'])} | {_fmt(w['on'])} | — |")
    lines += ["", "## JEV tasks (ON pass)", ""]
    if not c["jev_tasks"]:
        lines.append("_No JEV calls were made (no task is wired into a decision yet, or JEV "
                     "was not configured for the ON pass)._")
    else:
        lines += ["| task | calls | verdicts | defer rate | defer reasons | cache-hit rate "
                  "| model calls | mean ms | max ms |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for name, t in c["jev_tasks"].items():
            reasons = ", ".join(f"{k}={v}" for k, v in t["defer_reasons"].items()) or "—"
            lines.append(
                f"| {name} | {t['calls']} | {t['verdicts']} | {_fmt(t['defer_rate'])} "
                f"| {reasons} | {_fmt(t['cache_hit_rate'])} | {t['model_calls']} "
                f"| {_fmt(t['latency_mean_ms'])} | {_fmt(t['latency_max_ms'])} |"
            )
    lines += ["", "## Per target", "",
              "| target | pipeline | run | identical | +/− | precision | recall | wall off/on "
              "| JEV calls | score drift |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for p in c["pairs"]:
        head = f"| {p['target_id']} | {p['pipeline']} | {p['run_idx']} "
        if not p.get("comparable"):
            lines.append(head + f"| n/a (ok off={p['ok_off']} on={p['ok_on']}) "
                         "| — | — | — | — | — | — |")
            continue
        drift = "; ".join(f"{k}: {a}→{b}" for k, (a, b) in p["score_drift"].items()) or "—"
        lines.append(
            head + f"| {'yes' if p['outputs_identical'] else 'NO'} | +{p['added']}/−{p['removed']} "
            f"| {_fmt(p['precision'][0])}→{_fmt(p['precision'][1])} "
            f"| {_fmt(p['recall'][0])}→{_fmt(p['recall'][1])} "
            f"| {_fmt(p['wall_off'])}/{_fmt(p['wall_on'])} | {p['jev']['calls']} | {drift} |"
        )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="JEV off-vs-on side-by-side eval")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the target set JEV-off then JEV-on, then compare")
    r.add_argument("--base", choices=[k for k in CONFIGS if "+jev-" not in k],
                   default="keyless-default")
    r.add_argument("--runs", type=int, default=1)
    r.add_argument("--only", nargs="*", default=None)
    r.add_argument("--emails-only", action="store_true")
    r.add_argument("--domains-only", action="store_true")
    r.add_argument("--investigate-timeout", type=int, default=600)
    r.add_argument("--harvest-timeout", type=int, default=720)
    r.add_argument("--refresh-cache", action="store_true",
                   help="ON pass skips JEV cache reads (re-asks the model)")
    r.add_argument("--out", default=None)

    c = sub.add_parser("compare", help="compare two existing run dirs")
    c.add_argument("--off", required=True)
    c.add_argument("--on", required=True)
    c.add_argument("--out", default=None, help="default: the ON run's parent dir")

    args = ap.parse_args(argv)
    if args.cmd == "run":
        run_pair(args)
    else:
        off, on = Path(args.off).resolve(), Path(args.on).resolve()
        compare(off, on, Path(args.out).resolve() if args.out else on.parent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
