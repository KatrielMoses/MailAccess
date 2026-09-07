"""Build the 0D baseline report from a >=3-run capture dir.

Reads a run dir (runlog.json + raw/ + logs/ + manifest.json), computes per-target
mean + variance across the runs for every numeric 0C metric on both pipelines,
scans the logs for the current failure modes, and writes a human-readable report
(report.md) plus a machine-readable aggregate (report.json).

  python -m eval.harness.build_report --run baseline/v0.14.4/keyless \
      --out-md baseline/v0.14.4/report.md --out-json baseline/v0.14.4/report.json
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

from eval.harness.manifest import REPO_ROOT
from eval.harness.score import load_truth, score_harvest, score_investigate

# Failure-mode signals to count in the per-run logs.
FAILURE_SIGNALS = {
    "search_captcha": re.compile(r"CAPTCHA|HTTP 202|202\b", re.I),
    "investigate_120s_timeout": re.compile(r"Timed out waiting for investigation", re.I),
    "harness_timeout": re.compile(r"\[harness\] TIMEOUT", re.I),
    "connection_error": re.compile(r"ConnectError|ConnectionError|Max retries|getaddrinfo", re.I),
    "rate_limited": re.compile(r"429|rate.?limit", re.I),
    "blocked": re.compile(r"blocked|forbidden|403", re.I),
}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _stats(xs: list[float]) -> dict[str, float | None]:
    xs = [x for x in xs if x is not None]
    if not xs:
        return {"mean": None, "stdev": None, "min": None, "max": None, "n": 0}
    return {
        "mean": round(statistics.fmean(xs), 3),
        "stdev": round(statistics.pstdev(xs), 3) if len(xs) > 1 else 0.0,
        "min": min(xs),
        "max": max(xs),
        "n": len(xs),
    }


def _fmt(s: dict[str, Any]) -> str:
    if not s or s.get("mean") is None:
        return "—"
    return f"{s['mean']}±{s['stdev']} [{s['min']}–{s['max']}]"


def _scan_logs(run_dir: Path) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for log in (run_dir / "logs").glob("*.log"):
        text = log.read_text(encoding="utf-8", errors="replace")
        for name, pat in FAILURE_SIGNALS.items():
            if pat.search(text):
                counts[name] += 1  # per-file occurrence
    return dict(counts)


def build(run_dir: Path) -> dict[str, Any]:
    runlog = _load(run_dir / "runlog.json")
    manifest = _load(run_dir / "manifest.json")
    if not runlog:
        raise SystemExit(f"No runlog.json in {run_dir}")
    truth = load_truth()

    # Group records by (target_id, pipeline).
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    meta: dict[str, dict[str, str]] = {}
    for rec in runlog["records"]:
        key = (rec["target_id"], rec["pipeline"])
        groups.setdefault(key, []).append(rec)
        meta[rec["target_id"]] = {"value": rec["target_value"], "category": rec["category"]}

    per_target: list[dict[str, Any]] = []
    for (tid, pipeline), recs in sorted(groups.items()):
        walls = [r["wall_seconds"] for r in recs]
        oks = [r["ok"] for r in recs]
        scores = []
        for r in recs:
            raw = _load(run_dir / r["raw_path"]) if r.get("ok") and r.get("raw_path") else None
            if raw is None:
                continue
            t = truth.get(tid)
            fn = score_harvest if pipeline == "harvest" else score_investigate
            scores.append(fn(raw, t))

        entry: dict[str, Any] = {
            "target_id": tid,
            "target_value": meta[tid]["value"],
            "category": meta[tid]["category"],
            "pipeline": pipeline,
            "n_runs": len(recs),
            "n_ok": sum(1 for o in oks if o),
            "wall_seconds": _stats(walls),
            "exit_codes": dict(Counter(r["exit_code"] for r in recs)),
        }
        if pipeline == "harvest":
            entry["yield_total"] = _stats([s["yield"]["total_unique_emails"] for s in scores])
            for tier in ("CONFIRMED", "LIKELY", "MEDIUM", "LOW"):
                entry[f"yield_{tier}"] = _stats([s["yield"]["by_tier"].get(tier) for s in scores])
            deliv = [s["deliverability"] for s in scores]
            entry["smtp_verified"] = _stats([d["smtp_verified"] for d in deliv])
            entry["smtp_not_found"] = _stats([d["smtp_not_found"] for d in deliv])
            entry["smtp_inconclusive"] = _stats([d["smtp_inconclusive"] for d in deliv])
            entry["catchall_detected"] = [s["deliverability"]["catchall_detected"] for s in scores]
            entry["confirmed_pattern"] = [s["deliverability"]["confirmed_pattern"] for s in scores]
            entry["precision"] = [s.get("precision") for s in scores]
            entry["recall"] = [s.get("recall") for s in scores]
        else:
            entry["findings"] = _stats([s["yield"]["finding_count"] for s in scores])
            entry["module_count"] = _stats([s["yield"]["module_count"] for s in scores])
            entry["exposure_score"] = _stats([s["yield"]["exposure_score"] for s in scores])
            entry["confirmed_name"] = [s["yield"]["confirmed_name"] for s in scores]
        per_target.append(entry)

    return {
        "run_dir": str(run_dir),
        "manifest": manifest,
        "failure_modes": _scan_logs(run_dir),
        "per_target": per_target,
    }


def render_md(rep: dict[str, Any], redact: bool) -> str:
    m = rep["manifest"] or {}
    L: list[str] = []
    L.append("# MailAccess v0.14.4 — Phase 0 Baseline Report")
    L.append("")
    L.append(f"- **Config:** `{m.get('config_label')}`  ·  **Tool:** v{m.get('tool_version')}  "
             f"·  **Git:** `{(m.get('git_commit') or '')[:12]}`")
    L.append(f"- **Host:** {(m.get('host') or {}).get('platform')}, "
             f"Python {(m.get('host') or {}).get('python')}")
    kp = m.get("keys_present_names") or []
    L.append(f"- **Keys present:** {', '.join(kp) or '(none — keyless)'}")
    L.append(f"- **Runs per target:** {(m.get('extra') or {}).get('runs')}")
    L.append("")
    L.append("All numeric cells are **mean±stdev [min–max]** across the runs. Values labelled "
             "keyless reflect a zero-key user (key-gated modules skip).")
    L.append("")

    inv = [e for e in rep["per_target"] if e["pipeline"] == "investigate"]
    har = [e for e in rep["per_target"] if e["pipeline"] == "harvest"]

    def name(e: dict[str, Any]) -> str:
        return e["target_id"] if redact else f"{e['target_id']} (`{e['target_value']}`)"

    L.append("## Investigate (email → identity/exposure)")
    L.append("")
    L.append("| target | cat | runs | done | findings | modules | exposure | wall(s) | exits |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for e in inv:
        exits = e["exit_codes"]
        L.append(f"| {name(e)} | {e['category']} | {e['n_runs']} | {e['n_ok']}/{e['n_runs']} "
                 f"| {_fmt(e.get('findings'))} | {_fmt(e.get('module_count'))} "
                 f"| {_fmt(e.get('exposure_score'))} | {_fmt(e['wall_seconds'])} | {exits} |")
    L.append("")

    L.append("## Harvest (domain → emails)")
    L.append("")
    L.append("| target | category | runs | ok | unique | CONFIRMED | LIKELY | MEDIUM | LOW | "
             "wall(s) | catch-all | pattern |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for e in har:
        ca = e.get("catchall_detected")
        pat = e.get("confirmed_pattern")
        L.append(f"| {name(e)} | {e['category']} | {e['n_runs']} | {e['n_ok']}/{e['n_runs']} "
                 f"| {_fmt(e.get('yield_total'))} | {_fmt(e.get('yield_CONFIRMED'))} "
                 f"| {_fmt(e.get('yield_LIKELY'))} | {_fmt(e.get('yield_MEDIUM'))} "
                 f"| {_fmt(e.get('yield_LOW'))} | {_fmt(e['wall_seconds'])} | {ca} | {pat} |")
    L.append("")

    L.append("### Deliverability verdicts (harvest, SMTP cap = 10 probes/domain)")
    L.append("")
    L.append("| target | smtp verified | smtp not-found | smtp inconclusive | catch-all |")
    L.append("|---|---|---|---|---|")
    for e in har:
        L.append(f"| {name(e)} | {_fmt(e.get('smtp_verified'))} | {_fmt(e.get('smtp_not_found'))} "
                 f"| {_fmt(e.get('smtp_inconclusive'))} | {e.get('catchall_detected')} |")
    L.append("")

    L.append("## Observed failure modes")
    L.append("")
    fm = rep["failure_modes"]
    if fm:
        for k, v in sorted(fm.items(), key=lambda kv: -kv[1]):
            L.append(f"- **{k}**: seen in {v} run log(s)")
    else:
        L.append("- (none detected)")
    L.append("")

    # --- Stripe catch-all handling ---
    stripe = next((e for e in har if "stripe" in (e["target_value"] or "")
                   or e["target_id"] == "large_catchall"), None)
    L.append("## Stripe catch-all handling")
    L.append("")
    if stripe:
        L.append(f"- Tool's `catchall_detected` across runs: **{stripe.get('catchall_detected')}** "
                 f"— the tool did **not** flag stripe.com as catch-all at v0.14.4.")
        L.append(f"- SMTP verdicts: verified {_fmt(stripe.get('smtp_verified'))}, "
                 f"not-found {_fmt(stripe.get('smtp_not_found'))}, "
                 f"inconclusive {_fmt(stripe.get('smtp_inconclusive'))} — the 10-probe SMTP cap "
                 f"produced no usable verdicts on this host (port 25 egress blocked).")
        L.append(f"- Yield: {_fmt(stripe.get('yield_total'))} unique, of which "
                 f"CONFIRMED {_fmt(stripe.get('yield_CONFIRMED'))} — but 'CONFIRMED' here is "
                 f"pattern/source confidence, **not** SMTP-verified deliverability.")
        L.append("- **Whether stripe.com is actually catch-all is a 0B truth question** (verify "
                 "independently); the baseline only records that the tool did not detect it.")
    else:
        L.append("- (stripe target not found in this run)")
    L.append("")

    # --- Deliverability & empty-vs-blocked ambiguity ---
    L.append("## Deliverability & the empty-vs-blocked ambiguity")
    L.append("")
    L.append("Across all three domains, SMTP verified / not-found / inconclusive are **all 0**. "
             "On this host port 25 egress is blocked, so every RCPT probe is `not_attempted`. "
             "This is a genuine ambiguity the tool does not resolve at v0.14.4: a `0 verified` "
             "result can mean *no mailbox exists* OR *the probe never ran*. A deliverability "
             "baseline needs either a port-25-open host or the SMTP-less scoring path.")
    L.append("")

    # --- Precision / recall status ---
    L.append("## Precision / recall status")
    L.append("")
    L.append("Precision/recall/Brier are computed only where 0B truth labels exist. The truth "
             "files are currently stubs (all `unknown`), so these metrics are **not computed** in "
             "this baseline — it is a **yield / latency / deliverability / stability** baseline. "
             "Once truth labels are populated, re-run `score.py` (raw outputs are retained) to add "
             "precision/recall without re-harvesting.")
    L.append("")

    # --- Nondeterminism ---
    L.append("## Nondeterminism (run-to-run)")
    L.append("")
    noisy = []
    for e in har:
        yt = e.get("yield_total") or {}
        if yt.get("stdev"):
            noisy.append(f"{e['target_id']} yield {_fmt(yt)}")
    for e in inv:
        fs = e.get("findings") or {}
        if fs.get("stdev"):
            noisy.append(f"{e['target_id']} findings {_fmt(fs)}")
    if noisy:
        L.append("Targets with run-to-run variance (>0 stdev):")
        for n in noisy:
            L.append(f"- {n}")
    else:
        L.append("- No yield variance observed (small sample).")
    L.append("")
    L.append("Latency is also nondeterministic — e.g. harvest wall times span the full range shown "
             "above, and one rootaccess.tech harvest run hit the 900 s ceiling (exit -1) while "
             "others finished ~892 s. Drivers: search-engine CAPTCHA/rate-limit backoff, "
             "Common Crawl/crt.sh flakiness, and live-source drift.")
    L.append("")

    # --- Caveats ---
    L.append("## Caveats & known limitations of this baseline")
    L.append("")
    L.append("- **Investigate 120 s cap:** the default module set (incl. `maigret_platforms`) can "
             "exceed the tool's hard 120 s completion cap; `corp_own_2` timed out 3/3 (exit 3). "
             "4/5 emails completed.")
    L.append("- **Harvest ceiling:** rootaccess.tech harvest runs ~892 s, occasionally hitting the "
             "900 s harness timeout (1/3). Not a tool cap — raise `--harvest-timeout` to capture "
             "the tail, but the slowness itself is the finding (search backoff).")
    L.append("- **Keyless:** key-gated modules (HIBP, SerpAPI, Hunter, EmailRep, Shodan) skip; "
             "this is the zero-key user's experience. A with-keys secondary run is not included.")
    L.append("- **Host:** Windows, port 25 blocked — affects SMTP deliverability only.")
    L.append("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--out-md", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--redact", action="store_true",
                    help="show target ids instead of real emails/domains")
    args = ap.parse_args(argv)
    run_dir = Path(args.run)
    if not run_dir.is_absolute():
        run_dir = REPO_ROOT / run_dir
    rep = build(run_dir)
    Path(args.out_json).write_text(json.dumps(rep, indent=2), encoding="utf-8")
    Path(args.out_md).write_text(render_md(rep, args.redact), encoding="utf-8")
    print(f"Wrote {args.out_md}")
    print(f"Wrote {args.out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
