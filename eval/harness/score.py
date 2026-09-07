"""Phase 0 scorecard — score a baseline run against the 0B truth labels.

Reads a run dir produced by ``run_baseline.py`` (runlog.json + raw/ exports)
plus the hand-verified truth labels in ``eval/truth/``, and emits a FIXED,
machine-readable scorecard (JSON) + a human-readable summary (Markdown).

The scorecard SHAPE is the contract every later phase reports against, so its
top-level keys are stable. Truth-dependent metrics (precision/recall/Brier/
per-source FP) degrade to ``null`` with a ``reason`` when a target has no truth
labels — which is the expected state for third-party targets at baseline.

Confidence -> probability mappings (documented, adjustable):

  harvest tier   -> P(deliverable/correct)
    CONFIRMED     -> 0.95
    LIKELY        -> 0.80
    MEDIUM        -> 0.60
    LOW           -> 0.30

  investigate    -> P(finding is the true person)
    uses per-finding/name confidence in [0,1] when present; else skipped.

Brier score = mean((p - outcome)^2) over LABELLED items only. Lower is better.
"""
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any

import yaml

from eval.harness.manifest import REPO_ROOT

TRUTH_DIR = REPO_ROOT / "eval" / "truth"

HARVEST_TIER_PROB = {"CONFIRMED": 0.95, "LIKELY": 0.80, "MEDIUM": 0.60, "LOW": 0.30}
# Legacy summary count keys -> canonical tier name.
SUMMARY_TIER_KEYS = {
    "high_confidence": "CONFIRMED",
    "likely_confidence": "LIKELY",
    "medium_confidence": "MEDIUM",
    "low_confidence": "LOW",
}
# Substrings that flag a module as policy/safety-relevant for the snapshot.
SENSITIVE_MODULE_HINTS = (
    "breach",
    "reset",
    "probe",
    "smtp",
    "m365",
    "yahoo",
    "ghunt",
    "deep",
    "credential",
)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def load_truth() -> dict[str, dict[str, Any]]:
    """Map target_id -> truth dict for every *.yaml in eval/truth/ (excl. schema)."""
    truth: dict[str, dict[str, Any]] = {}
    if not TRUTH_DIR.exists():
        return truth
    for p in TRUTH_DIR.glob("*.yaml"):
        if p.name.startswith("_") or p.name == "README.md":
            continue
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        tid = data.get("target_id")
        if tid:
            truth[tid] = data
    return truth


def _norm_email(s: str) -> str:
    return (s or "").strip().lower()


def _norm_text(s: str) -> str:
    """Case/space-insensitive compare key for name/title matching."""
    return " ".join(str(s or "").split()).casefold()


def _deliverability_outcome(contact: dict[str, Any]) -> float | None:
    """Map a truth contact's deliverability label to a 0/1 Brier outcome.

    Prefers an explicit ``deliverability_outcome`` (true/false), else the
    ``currently_deliverable`` flag. ``unknown``/missing → None (unscored)."""
    for field_name in ("deliverability_outcome", "currently_deliverable"):
        val = contact.get(field_name)
        if isinstance(val, bool):
            return 1.0 if val else 0.0
        if isinstance(val, str) and val.strip().lower() in {"true", "false"}:
            return 1.0 if val.strip().lower() == "true" else 0.0
    return None


# ---------------------------------------------------------------------------
# Harvest scoring
# ---------------------------------------------------------------------------
def score_harvest(raw: dict[str, Any], truth: dict[str, Any] | None) -> dict[str, Any]:
    summary = raw.get("summary") or {}
    emails = raw.get("emails") or []

    yield_by_tier = {tier: summary.get(k, 0) for k, tier in SUMMARY_TIER_KEYS.items()}
    result: dict[str, Any] = {
        "yield": {
            "total_unique_emails": summary.get("total_unique_emails", len(emails)),
            "by_tier": yield_by_tier,
            "role_accounts": summary.get("role_accounts"),
            "people_count": summary.get("people_count"),
        },
        "deliverability": {
            "smtp_verification_used": summary.get("smtp_verification_used"),
            "smtp_verified": summary.get("smtp_verified_emails"),
            "smtp_not_found": summary.get("smtp_not_found_emails"),
            "smtp_inconclusive": summary.get("smtp_inconclusive_emails"),
            "smtp_not_attempted": summary.get("smtp_not_attempted_emails"),
            "catchall_detected": summary.get("catchall_detected"),
            "confirmed_pattern": summary.get("confirmed_pattern"),
        },
        "latency": {
            "duration_seconds": raw.get("duration_seconds"),
            "module_timings": summary.get("module_timings") or {},
            "module_skip_reasons": summary.get("module_skip_reasons") or {},
        },
        "precision": None,
        "recall": None,
        "pattern_correct": None,
        "catchall_correct": None,
        "brier": None,
        "per_source_fp": None,
        # Phase 3 metrics (null until person/seniority/deliverability labels land,
        # matching the existing no_truth degradation). See eval/truth/README.md.
        "person_field_precision": None,  # 3A — populated person fields vs truth
        "seniority_accuracy": None,      # 3B — title→band classifier vs labels
        "brier_deliverability": None,    # 3C — deliverability score calibration
        "truth_status": "no_truth",
    }

    if not truth:
        return result

    result["truth_status"] = "labelled"
    labelled = {_norm_email(c.get("email", "")): c for c in (truth.get("known_contacts") or [])}
    # Also allow explicit false-positive labels.
    fp_labels = {_norm_email(e) for e in (truth.get("false_positive_emails") or [])}

    found_emails = {_norm_email(e.get("email", "")): e for e in emails}

    # Recall: fraction of known-good contacts the harvest surfaced.
    if labelled:
        hit = sum(1 for k in labelled if k in found_emails)
        result["recall"] = {
            "tp": hit, "known": len(labelled), "value": round(hit / len(labelled), 4),
        }

    # Precision over the LABELLED subset of harvested emails.
    tp = fp = 0
    per_source: dict[str, dict[str, int]] = {}
    brier_terms: list[float] = []
    for key, em in found_emails.items():
        is_tp = key in labelled
        is_fp = key in fp_labels
        if not (is_tp or is_fp):
            continue  # unlabelled -> excluded from precision (truth non-exhaustive)
        tp += int(is_tp)
        fp += int(is_fp)
        outcome = 1.0 if is_tp else 0.0
        p = HARVEST_TIER_PROB.get(str(em.get("confidence_label", "")).upper())
        if p is not None:
            brier_terms.append((p - outcome) ** 2)
        for mod in em.get("found_by_modules") or []:
            d = per_source.setdefault(mod, {"labelled": 0, "fp": 0})
            d["labelled"] += 1
            d["fp"] += int(is_fp)
    if tp + fp > 0:
        result["precision"] = {"tp": tp, "fp": fp, "value": round(tp / (tp + fp), 4)}
        result["per_source_fp"] = {
            m: {
                "labelled": v["labelled"], "fp": v["fp"],
                "fp_rate": round(v["fp"] / v["labelled"], 4),
            }
            for m, v in sorted(per_source.items())
        }
    if brier_terms:
        result["brier"] = {"n": len(brier_terms), "value": round(statistics.fmean(brier_terms), 4)}

    # --- Phase 3A — person-field precision over the labelled contact subset ---
    # Of the person fields the tool populated for a known contact, what fraction
    # match the hand-verified label (name/title). Only labelled contacts the tool
    # also surfaced, and only fields with a truth value, are scored.
    pf_correct = pf_total = 0
    for key, contact in labelled.items():
        em = found_emails.get(key)
        if not em:
            continue
        person = em.get("person") or {}
        for tool_field, truth_field in (("full_name", "name"), ("job_title", "title")):
            truth_val = str(contact.get(truth_field) or "").strip()
            tool_val = str(person.get(tool_field) or "").strip()
            if truth_val and tool_val:  # scored only when both present
                pf_total += 1
                pf_correct += int(_norm_text(tool_val) == _norm_text(truth_val))
    if pf_total:
        result["person_field_precision"] = {
            "correct": pf_correct, "populated": pf_total,
            "value": round(pf_correct / pf_total, 4),
        }

    # --- Phase 3B — seniority classifier accuracy vs labelled titles ---
    # Runs the production classifier on each labelled title and compares to the
    # hand-labelled seniority band. Measures the classifier directly (independent
    # of harvest yield). ``unknown`` truth bands are skipped.
    sen_correct = sen_total = 0
    try:
        from backend.core.seniority_classifier import classify_title

        for contact in labelled.values():
            title = str(contact.get("title") or "").strip()
            truth_band = str(contact.get("seniority") or "").strip().lower()
            if not title or not truth_band or truth_band == "unknown":
                continue
            sen_total += 1
            sen_correct += int(classify_title(title).band == truth_band)
    except Exception:
        sen_total = 0
    if sen_total:
        result["seniority_accuracy"] = {
            "correct": sen_correct, "labelled": sen_total,
            "value": round(sen_correct / sen_total, 4),
        }

    # --- Phase 3C — deliverability score calibration (Brier) ---
    # For each labelled contact with a known deliverability outcome the tool also
    # scored: (score - outcome)^2, meaned. Outcome from ``currently_deliverable``
    # (or an explicit ``deliverability_outcome``) truth field.
    deliv_terms: list[float] = []
    for key, contact in labelled.items():
        em = found_emails.get(key)
        if not em:
            continue
        outcome = _deliverability_outcome(contact)
        score = em.get("deliverability_score")
        if outcome is not None and isinstance(score, int | float):
            deliv_terms.append((float(score) - outcome) ** 2)
    if deliv_terms:
        result["brier_deliverability"] = {
            "n": len(deliv_terms), "value": round(statistics.fmean(deliv_terms), 4),
        }

    # Pattern correctness.
    truth_pattern = truth.get("email_pattern")
    if truth_pattern and truth_pattern != "unknown":
        result["pattern_correct"] = (summary.get("confirmed_pattern") == truth_pattern)

    # Catch-all correctness.
    truth_catchall = truth.get("catch_all")
    if isinstance(truth_catchall, bool):
        result["catchall_correct"] = (bool(summary.get("catchall_detected")) == truth_catchall)

    return result


# ---------------------------------------------------------------------------
# Investigate scoring
# ---------------------------------------------------------------------------
def score_investigate(raw: dict[str, Any], truth: dict[str, Any] | None) -> dict[str, Any]:
    findings = raw.get("findings") or []
    module_runs = raw.get("module_runs") or []
    result: dict[str, Any] = {
        "yield": {
            "finding_count": len(findings),
            "module_count": len(module_runs),
            "exposure_score": raw.get("exposure_score"),
            "exposure_score_pct": raw.get("exposure_score_pct"),
            "risk_level": raw.get("risk_level"),
            "confirmed_name": raw.get("confirmed_name"),
            "name_confidence": raw.get("name_confidence"),
        },
        "latency": {
            # investigate per-module timing is unreliable (batch timestamps); see docs.
            "per_module_timing_reliable": False,
        },
        "precision": None,
        "recall": None,
        "brier": None,
        "per_source_fp": None,
        "name_correct": None,
        "truth_status": "no_truth",
    }
    if not truth:
        return result

    result["truth_status"] = "labelled"
    # Name correctness.
    ident = truth.get("identity") or {}
    truth_name = ident.get("real_name")
    if truth_name and truth_name != "unknown":
        got = (raw.get("confirmed_name") or "").strip().lower()
        result["name_correct"] = (got == str(truth_name).strip().lower())

    # Account TP/FP from truth labels keyed by "module:identifier".
    acct_labels = {a.get("key"): a.get("verdict") for a in (truth.get("accounts") or [])}
    if acct_labels:
        tp = sum(1 for v in acct_labels.values() if v == "true_positive")
        fp = sum(1 for v in acct_labels.values() if v == "false_positive")
        if tp + fp > 0:
            result["precision"] = {"tp": tp, "fp": fp, "value": round(tp / (tp + fp), 4)}
    return result


# ---------------------------------------------------------------------------
# Policy / safety snapshot
# ---------------------------------------------------------------------------
def policy_snapshot(runlog: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    """Record which probing/breach/reset/SMTP behaviors fired (the 'before' picture)."""
    fired: dict[str, int] = {}
    skipped: dict[str, int] = {}
    probing_flags: dict[str, int] = {}
    for rec in runlog.get("records", []):
        raw = _load_json(run_dir / rec["raw_path"]) if rec.get("raw_path") else None
        if not raw:
            continue
        if rec["pipeline"] == "harvest":
            summary = raw.get("summary") or {}
            timings = summary.get("module_timings") or {}
            skips = summary.get("module_skip_reasons") or {}
            names_ran, names_skipped = list(timings), list(skips)
            # Harvest exposes verification/probing intent as summary flags.
            for flag in ("smtp_verification_used", "m365_email_verification",
                         "yahoo_email_verification", "smtp_email_verification"):
                if summary.get(flag):
                    probing_flags[flag] = probing_flags.get(flag, 0) + 1
        else:
            names_ran = [m.get("module_name") for m in (raw.get("module_runs") or [])
                         if m.get("status") in ("complete", "success")]
            names_skipped = [m.get("module_name") for m in (raw.get("module_runs") or [])
                             if m.get("status") in ("skipped",)]
        for n in names_ran:
            if n and any(h in str(n).lower() for h in SENSITIVE_MODULE_HINTS):
                fired[n] = fired.get(n, 0) + 1
        for n in names_skipped:
            if n and any(h in str(n).lower() for h in SENSITIVE_MODULE_HINTS):
                skipped[n] = skipped.get(n, 0) + 1
    return {
        "sensitive_modules_fired": fired,
        "sensitive_modules_skipped": skipped,
        "harvest_probing_flags": probing_flags,
    }


# ---------------------------------------------------------------------------
# Stability (0D)
# ---------------------------------------------------------------------------
def stability(per_target: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Variance across repeated runs of the same target."""
    out: dict[str, Any] = {}
    for tid, runs in per_target.items():
        if len(runs) < 2:
            continue
        pipeline = runs[0]["pipeline"]
        # Only runs that produced a scored result carry a "yield"; failed/timed-out
        # runs carry an "error" instead and are excluded from the yield series.
        ok_runs = [r for r in runs if "yield" in r["score"]]
        key = "total_unique_emails" if pipeline == "harvest" else "finding_count"
        series = [r["score"]["yield"][key] or 0 for r in ok_runs]
        walls = [r["record"]["wall_seconds"] for r in runs]
        if not series:
            out[tid] = {
                "pipeline": pipeline, "n_runs": len(runs), "n_ok": 0,
                "yield_series": [], "note": "all runs failed/timed out",
                "wall_mean": round(statistics.fmean(walls), 3),
                "wall_stdev": round(statistics.pstdev(walls), 3),
            }
            continue
        out[tid] = {
            "pipeline": pipeline,
            "n_runs": len(runs),
            "n_ok": len(ok_runs),
            "yield_series": series,
            "yield_min": min(series),
            "yield_max": max(series),
            "yield_mean": round(statistics.fmean(series), 3),
            "yield_stdev": round(statistics.pstdev(series), 3) if len(series) > 1 else 0.0,
            "yield_cv": round(statistics.pstdev(series) / statistics.fmean(series), 4)
            if statistics.fmean(series) else None,
            "wall_mean": round(statistics.fmean(walls), 3),
            "wall_stdev": round(statistics.pstdev(walls), 3),
        }
    return out


# ---------------------------------------------------------------------------
# Aggregate + main
# ---------------------------------------------------------------------------
def build_scorecard(run_dir: Path) -> dict[str, Any]:
    runlog = _load_json(run_dir / "runlog.json")
    manifest = _load_json(run_dir / "manifest.json")
    if runlog is None:
        raise SystemExit(f"No runlog.json in {run_dir}")
    truth = load_truth()

    per_target_runs: dict[str, list[dict[str, Any]]] = {}
    targets_out: list[dict[str, Any]] = []
    for rec in runlog["records"]:
        raw = _load_json(run_dir / rec["raw_path"]) if rec.get("raw_path") else None
        t = truth.get(rec["target_id"])
        if not rec.get("ok") or raw is None:
            score = {"error": "no_output_or_failed", "exit_code": rec.get("exit_code"),
                     "timed_out": rec.get("timed_out")}
        elif rec["pipeline"] == "harvest":
            score = score_harvest(raw, t)
        else:
            score = score_investigate(raw, t)
        entry = {
            "target_id": rec["target_id"],
            "target_value": rec["target_value"],
            "category": rec["category"],
            "pipeline": rec["pipeline"],
            "run_idx": rec["run_idx"],
            "ok": rec["ok"],
            "wall_seconds": rec["wall_seconds"],
            "has_truth": t is not None,
            "score": score,
        }
        targets_out.append(entry)
        per_target_runs.setdefault(rec["target_id"], []).append(
            {"pipeline": rec["pipeline"], "record": rec, "score": score}
        )

    scorecard = {
        "schema_version": 1,
        "run_id": runlog.get("run_id"),
        "config_label": runlog.get("config_label"),
        "config_hash": runlog.get("config_hash"),
        "tool_version": (manifest or {}).get("tool_version"),
        "keys_present_names": (manifest or {}).get("keys_present_names"),
        "targets": targets_out,
        "stability": stability(per_target_runs),
        "policy_snapshot": policy_snapshot(runlog, run_dir),
        "aggregate": _aggregate(targets_out),
    }
    return scorecard


def _aggregate(entries: list[dict[str, Any]]) -> dict[str, Any]:
    inv = [e for e in entries if e["pipeline"] == "investigate" and e["ok"]]
    har = [e for e in entries if e["pipeline"] == "harvest" and e["ok"]]

    def _mean(xs: list[float]) -> float | None:
        return round(statistics.fmean(xs), 3) if xs else None

    return {
        "n_targets": len({e["target_id"] for e in entries}),
        "n_records": len(entries),
        "n_ok": sum(1 for e in entries if e["ok"]),
        "n_failed": sum(1 for e in entries if not e["ok"]),
        "investigate": {
            "n": len(inv),
            "mean_findings": _mean([e["score"]["yield"]["finding_count"] for e in inv]),
            "mean_wall_seconds": _mean([e["wall_seconds"] for e in inv]),
        },
        "harvest": {
            "n": len(har),
            "mean_unique_emails": _mean(
                [e["score"]["yield"]["total_unique_emails"] or 0 for e in har]
            ),
            "mean_wall_seconds": _mean([e["wall_seconds"] for e in har]),
            "catchall_domains": [e["target_id"] for e in har
                                 if e["score"]["deliverability"]["catchall_detected"]],
        },
    }


def render_markdown(sc: dict[str, Any]) -> str:
    lines: list[str] = []
    a = sc["aggregate"]
    inv, har = a["investigate"], a["harvest"]
    lines.append(f"# Phase 0 Scorecard — `{sc['config_label']}`")
    lines.append("")
    lines.append(f"- **Run:** `{sc['run_id']}`  ·  **Tool:** v{sc['tool_version']}  "
                 f"·  **Config hash:** `{sc['config_hash']}`")
    keys = ", ".join(sc["keys_present_names"] or []) or "(none — keyless)"
    lines.append(f"- **Keys present:** {keys}")
    lines.append(f"- **Records:** {a['n_records']}  ·  ok {a['n_ok']}  ·  failed {a['n_failed']}")
    lines.append("")
    lines.append("## Aggregate")
    lines.append("")
    lines.append(f"- Investigate: n={inv['n']}, mean findings={inv['mean_findings']}, "
                 f"mean wall={inv['mean_wall_seconds']}s")
    lines.append(f"- Harvest: n={har['n']}, mean unique emails={har['mean_unique_emails']}, "
                 f"mean wall={har['mean_wall_seconds']}s")
    lines.append(f"- Catch-all domains detected: {', '.join(har['catchall_domains']) or '(none)'}")
    lines.append("")
    lines.append("## Per-target")
    lines.append("")
    lines.append("| target | pipeline | run | ok | wall(s) | yield | truth | precision | recall |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for e in sc["targets"]:
        s = e["score"]
        tid, pipe, ridx, wall = e["target_id"], e["pipeline"], e["run_idx"], e["wall_seconds"]
        if not e["ok"]:
            lines.append(f"| {tid} | {pipe} | {ridx} | ❌ | {wall} | — | — | — | — |")
            continue
        if pipe == "harvest":
            y = s["yield"]["total_unique_emails"]
        else:
            y = s["yield"]["finding_count"]
        prec = (s.get("precision") or {}).get("value", "—") if s.get("precision") else "—"
        rec = (s.get("recall") or {}).get("value", "—") if s.get("recall") else "—"
        truth = "yes" if e["has_truth"] else "no"
        lines.append(f"| {tid} | {pipe} | {ridx} | ✅ | {wall} | {y} | {truth} | {prec} | {rec} |")
    lines.append("")
    if sc["stability"]:
        lines.append("## Run-to-run stability (0D)")
        lines.append("")
        lines.append("| target | runs | yield series | mean | stdev | CV |")
        lines.append("|---|---|---|---|---|---|")
        for tid, st in sc["stability"].items():
            lines.append(f"| {tid} | {st['n_runs']} | {st.get('yield_series')} "
                         f"| {st.get('yield_mean', '—')} | {st.get('yield_stdev', '—')} "
                         f"| {st.get('yield_cv', '—')} |")
        lines.append("")
    ps = sc["policy_snapshot"]
    lines.append("## Policy / safety snapshot (before-picture)")
    lines.append("")
    lines.append(f"- Sensitive modules FIRED: {ps['sensitive_modules_fired'] or '(none)'}")
    lines.append(f"- Sensitive modules SKIPPED: {ps['sensitive_modules_skipped'] or '(none)'}")
    lines.append(f"- Harvest probing flags: {ps.get('harvest_probing_flags') or '(none)'}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score a Phase 0 baseline run")
    ap.add_argument("--run", required=True, help="run dir under eval/scorecards/")
    args = ap.parse_args(argv)
    run_dir = Path(args.run)
    if not run_dir.is_absolute():
        run_dir = REPO_ROOT / run_dir
    sc = build_scorecard(run_dir)
    (run_dir / "scorecard.json").write_text(json.dumps(sc, indent=2), encoding="utf-8")
    (run_dir / "scorecard.md").write_text(render_markdown(sc), encoding="utf-8")
    print(f"Wrote {run_dir / 'scorecard.json'}")
    print(f"Wrote {run_dir / 'scorecard.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
