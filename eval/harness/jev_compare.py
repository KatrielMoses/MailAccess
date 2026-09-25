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


# ---------------------------------------------------------------------------
# Per-task gate vs gold truth (JEV-1+). A task is KEPT only if its JEV score beats
# the heuristic score on labelled data; a tie — including "no labels" — drops it.
# ---------------------------------------------------------------------------
_NAME_NOTE = "JEV-assisted (identity.name_reconcile)"


def _investigate_raws(off_dir: Path, on_dir: Path) -> list[tuple[str, Any, Any]]:
    off_log = _load(off_dir / "runlog.json") or {"records": []}
    on_log = _load(on_dir / "runlog.json") or {"records": []}
    on_by_key = {(r["target_id"], r["pipeline"], r["run_idx"]): r for r in on_log["records"]}
    out = []
    for rec in off_log["records"]:
        if rec["pipeline"] != "investigate" or not rec.get("ok"):
            continue
        on_rec = on_by_key.get((rec["target_id"], "investigate", rec["run_idx"]))
        if not on_rec or not on_rec.get("ok"):
            continue
        raw_off, raw_on = _load(off_dir / rec["raw_path"]), _load(on_dir / on_rec["raw_path"])
        if raw_off is not None and raw_on is not None:
            out.append((rec["target_id"], raw_off, raw_on))
    return out


def _gate(heuristic: float, jev_score: float, n: int, extra_ok: bool = True) -> str:
    if n == 0:
        return "drop (no labels)"
    return "keep" if jev_score > heuristic and extra_ok else "drop"


def _gate_names(raws: list[tuple[str, Any, Any]], truth: dict[str, Any]) -> dict[str, Any]:
    n = off = on = assisted = 0
    for tid, raw_off, raw_on in raws:
        if _NAME_NOTE in str(raw_on.get("name_reasoning") or ""):
            assisted += 1
        real = ((truth.get(tid) or {}).get("identity") or {}).get("real_name")
        if not real or real == "unknown":
            continue
        n += 1
        want = str(real).strip().lower()
        off += (str(raw_off.get("confirmed_name") or "").strip().lower() == want)
        on += (str(raw_on.get("confirmed_name") or "").strip().lower() == want)
    return {"labelled": n, "heuristic_correct": off, "jev_correct": on,
            "jev_assisted_runs": assisted, "decision": _gate(off, on, n)}


def _account_verdicts(t: dict[str, Any]) -> dict[str, set[str]]:
    by_platform: dict[str, set[str]] = {}
    for acct in t.get("accounts") or []:
        key = str(acct.get("key") or "")
        if ":" in key:
            by_platform.setdefault(key.split(":", 1)[0].lower(), set()).add(
                str(acct.get("verdict") or "unknown"))
    return by_platform


def _pair_truth(a: str, b: str, verdicts: dict[str, set[str]]) -> bool | None:
    va, vb = verdicts.get(a.lower(), set()), verdicts.get(b.lower(), set())
    if "false_positive" in va or "false_positive" in vb:
        return False  # one side is not the subject → merging them is wrong
    if "true_positive" in va and "true_positive" in vb:
        return True
    return None


def _gate_same_person(raws: list[tuple[str, Any, Any]], truth: dict[str, Any]) -> dict[str, Any]:
    n = heur = jev_ok = wrong_yes = new_wrong = reviewed = 0
    for tid, _raw_off, raw_on in raws:
        verdicts = _account_verdicts(truth.get(tid) or {})
        for r in ((raw_on.get("graph_data") or {}).get("jev_review") or []):
            reviewed += 1
            label = _pair_truth(str(r.get("a")), str(r.get("b")), verdicts)
            if label is None:
                continue
            n += 1
            heuristic_merge = bool(r.get("heuristic_merge"))
            decision = {"yes": True, "no": False}.get(r.get("jev"), heuristic_merge)
            heur += heuristic_merge == label
            jev_ok += decision == label
            if r.get("jev") == "yes" and label is False:
                wrong_yes += 1
                new_wrong += not heuristic_merge
    return {"labelled_pairs": n, "reviewed_pairs": reviewed, "heuristic_correct": heur,
            "jev_correct": jev_ok, "wrong_yes": wrong_yes, "new_wrong_merges": new_wrong,
            "decision": _gate(heur, jev_ok, n, extra_ok=new_wrong == 0)}


def _gate_bio(raws: list[tuple[str, Any, Any]], truth: dict[str, Any]) -> dict[str, Any]:
    n = correct = wrong = populated = 0
    for tid, _raw_off, raw_on in raws:
        ident = (truth.get(tid) or {}).get("identity") or {}
        for f in raw_on.get("findings") or []:
            data = f.get("data") if isinstance(f.get("data"), dict) else f
            meta = data.get("metadata") if isinstance(data, dict) else None
            bio = meta.get("bio_structured") if isinstance(meta, dict) else None
            if not isinstance(bio, dict):
                continue
            populated += 1
            for field in ("employer", "role_title", "location"):
                got, want = bio.get(field), ident.get(field)
                if not got or not want or want == "unknown":
                    continue
                n += 1
                g, w = str(got).lower(), str(want).lower()
                if g in w or w in g:
                    correct += 1
                else:
                    wrong += 1
    # The heuristic extracts none of these fields, so its score is 0.
    return {"labelled_fields": n, "populated_profiles": populated, "correct": correct,
            "wrong": wrong, "heuristic_score": 0, "jev_score": correct - wrong,
            "decision": _gate(0, correct - wrong, n)}


def _harvest_raws(off_dir: Path, on_dir: Path) -> list[tuple[str, Any, Any]]:
    off_log = _load(off_dir / "runlog.json") or {"records": []}
    on_log = _load(on_dir / "runlog.json") or {"records": []}
    on_by_key = {(r["target_id"], r["pipeline"], r["run_idx"]): r for r in on_log["records"]}
    out = []
    for rec in off_log["records"]:
        if rec["pipeline"] != "harvest" or not rec.get("ok"):
            continue
        on_rec = on_by_key.get((rec["target_id"], "harvest", rec["run_idx"]))
        if not on_rec or not on_rec.get("ok"):
            continue
        raw_off, raw_on = _load(off_dir / rec["raw_path"]), _load(on_dir / on_rec["raw_path"])
        if raw_off is not None and raw_on is not None:
            out.append((rec["target_id"], raw_off, raw_on))
    return out


_VALID_GRADES = {"valid"}


def _grade_stats(raw: Any, truth: dict[str, Any]) -> dict[str, int]:
    """Count correct classifications and false 'valid' against a domain's truth."""
    deliverable = {
        score._norm_email(c.get("email", "")): _deliverable(c)
        for c in (truth.get("known_contacts") or [])
    }
    fp = {score._norm_email(e) for e in (truth.get("false_positive_emails") or [])}
    correct = labelled = false_valid = valid_total = 0
    for em in raw.get("emails") or []:
        key = score._norm_email(em.get("email", ""))
        grade = str(em.get("deliverability_grade") or "").strip().lower()
        is_valid = grade in _VALID_GRADES
        valid_total += is_valid
        # A false 'valid': graded Valid but labelled a false positive or a
        # known non-deliverable address. This is the precision guard's numerator.
        if is_valid and (key in fp or deliverable.get(key) is False):
            false_valid += 1
        want = None
        if key in fp:
            want = False
        elif key in deliverable and deliverable[key] is not None:
            want = deliverable[key]
        if want is None:
            continue
        labelled += 1
        correct += is_valid == want
    return {"correct": correct, "labelled": labelled, "false_valid": false_valid,
            "valid_total": valid_total}


def _deliverable(contact: dict[str, Any]) -> bool | None:
    val = score._deliverability_outcome(contact)
    return None if val is None else bool(val)


def _gate_verification(off_dir: Path, on_dir: Path, truth: dict[str, Any]) -> dict[str, Any]:
    """Grade verification precision/recall across harvest runs (JEV-2 tasks share it).

    The primary guard: JEV must not increase false 'valid'. Kept only when correct
    classification rises AND false-valid does not.
    """
    off = {"correct": 0, "labelled": 0, "false_valid": 0, "valid_total": 0}
    on = dict(off)
    for tid, raw_off, raw_on in _harvest_raws(off_dir, on_dir):
        t = truth.get(tid)
        if not t:
            continue
        for acc, src in ((off, raw_off), (on, raw_on)):
            stats = _grade_stats(src, t)
            for k in acc:
                acc[k] += stats[k]
    precision_held = on["false_valid"] <= off["false_valid"]
    decision = _gate(off["correct"], on["correct"], on["labelled"], extra_ok=precision_held)
    return {
        "labelled": on["labelled"],
        "heuristic_correct": off["correct"], "jev_correct": on["correct"],
        "heuristic_false_valid": off["false_valid"], "jev_false_valid": on["false_valid"],
        "precision_held": precision_held, "decision": decision,
    }


def _seniority_of(contact: dict[str, Any]) -> str | None:
    val = str(contact.get("seniority") or "").strip().lower()
    return val or None


def _roster_stats(raw: Any, truth: dict[str, Any]) -> dict[str, int]:
    labelled = {
        score._norm_email(c.get("email", "")): c for c in (truth.get("known_contacts") or [])
    }
    emails = raw.get("emails") or []
    found = {score._norm_email(e.get("email", "")): e for e in emails}
    recall = sum(1 for k in labelled if k in found)
    seniority_correct = seniority_labelled = 0
    for key, contact in labelled.items():
        want = _seniority_of(contact)
        got = _seniority_of(found.get(key) or {})
        if want and want != "unknown":
            seniority_labelled += 1
            seniority_correct += got == want
    return {"roster_size": len(emails), "recall": recall,
            "seniority_correct": seniority_correct, "seniority_labelled": seniority_labelled}


def _gate_roster(off_dir: Path, on_dir: Path, truth: dict[str, Any]) -> dict[str, Any]:
    """Score roster cleanliness across harvest runs (the JEV-3 roster.* tasks).

    Primary guard: RECALL HELD — no labeled real contact is dropped
    (``jev_recall >= heuristic_recall``). Kept only when the roster gets cleaner
    (fewer rows) or seniority accuracy rises, AND recall holds.
    """
    off = {"roster_size": 0, "recall": 0, "seniority_correct": 0, "seniority_labelled": 0}
    on = dict(off)
    for tid, raw_off, raw_on in _harvest_raws(off_dir, on_dir):
        t = truth.get(tid)
        if not t:
            continue
        for acc, src in ((off, raw_off), (on, raw_on)):
            stats = _roster_stats(src, t)
            for k in acc:
                acc[k] += stats[k]
    recall_held = on["recall"] >= off["recall"]
    cleaner = on["roster_size"] < off["roster_size"]
    seniority_up = on["seniority_correct"] > off["seniority_correct"]
    if on["recall"] == 0 and off["recall"] == 0 and on["seniority_labelled"] == 0:
        decision = "drop (no labels)"
    elif recall_held and (cleaner or seniority_up):
        decision = "keep"
    else:
        decision = "drop"
    return {
        "labelled_contacts": on["recall"] if on["recall"] else off["recall"],
        "heuristic_recall": off["recall"], "jev_recall": on["recall"],
        "heuristic_roster_size": off["roster_size"], "jev_roster_size": on["roster_size"],
        "heuristic_seniority_correct": off["seniority_correct"],
        "jev_seniority_correct": on["seniority_correct"],
        "seniority_labelled": on["seniority_labelled"],
        "recall_held": recall_held, "decision": decision,
    }


def _module_meta(raw: Any, module_name: str) -> dict[str, Any] | None:
    for m in raw.get("module_runs") or []:
        if m.get("module_name") == module_name and isinstance(m.get("run_metadata"), dict):
            return m["run_metadata"]
    return None


def _gate_reach(off_dir: Path, on_dir: Path) -> dict[str, Any]:
    """Score reach/selection: username hit-rate at EQUAL probe count (JEV-4 Task 1).

    The equal-cost guard is primary: JEV must not change the probe count. Kept only
    when wave-1 probe count is unchanged AND confirmed platforms rise. Open-web query
    yield is reported informationally (harvest email yield).
    """
    off = {"wave1_probes": 0, "confirmed": 0}
    on = dict(off)
    for _tid, raw_off, raw_on in _investigate_raws(off_dir, on_dir):
        for acc, src in ((off, raw_off), (on, raw_on)):
            meta = _module_meta(src, "username_platforms")
            if meta:
                acc["wave1_probes"] += int(meta.get("wave1_probes") or 0)
                acc["confirmed"] += int(meta.get("platforms_confirmed") or 0)
    off_yield = on_yield = 0
    for _tid, raw_off, raw_on in _harvest_raws(off_dir, on_dir):
        off_yield += len(raw_off.get("emails") or [])
        on_yield += len(raw_on.get("emails") or [])
    equal_cost = on["wave1_probes"] == off["wave1_probes"]
    hit_up = on["confirmed"] > off["confirmed"]
    if off["wave1_probes"] == 0 and on["wave1_probes"] == 0:
        decision = "drop (no probes)"
    elif equal_cost and hit_up:
        decision = "keep"
    else:
        decision = "drop"
    return {
        "heuristic_probes": off["wave1_probes"], "jev_probes": on["wave1_probes"],
        "heuristic_confirmed": off["confirmed"], "jev_confirmed": on["confirmed"],
        "heuristic_email_yield": off_yield, "jev_email_yield": on_yield,
        "equal_cost": equal_cost, "decision": decision,
    }


def task_gate(off_dir: Path, on_dir: Path) -> dict[str, Any]:
    truth = score.load_truth()
    raws = _investigate_raws(off_dir, on_dir)
    verification = _gate_verification(off_dir, on_dir, truth)
    roster = _gate_roster(off_dir, on_dir, truth)
    reach = _gate_reach(off_dir, on_dir)
    return {
        "identity.name_reconcile": _gate_names(raws, truth),
        "identity.same_person": _gate_same_person(raws, truth),
        "identity.bio_extract": _gate_bio(raws, truth),
        # The three JEV-2 verify.* tasks all feed the deliverability grade; scored
        # jointly on precision (no new false 'valid') + correct classification.
        "verify.*": verification,
        # The four JEV-3 roster.* tasks clean the harvest roster; scored jointly on
        # recall held (no labeled contact dropped) + cleanliness / seniority.
        "roster.*": roster,
        # The two JEV-4 reach.* tasks pick within the same budget; scored on username
        # hit-rate at EQUAL probe count (the equal-cost guard is primary).
        "reach.*": reach,
    }


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
        "task_gate": task_gate(off_dir, on_dir),
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
    lines += ["", "## Task gate (keep only if JEV beats the heuristic; ties drop)", "",
              "| task | labelled | heuristic | JEV | detail | decision |",
              "|---|---|---|---|---|---|"]
    for name, g in c.get("task_gate", {}).items():
        if name == "identity.bio_extract":
            row = (g["labelled_fields"], g["heuristic_score"], g["jev_score"],
                   f"correct {g['correct']}, wrong {g['wrong']}, "
                   f"profiles populated {g['populated_profiles']}")
        elif name == "identity.same_person":
            row = (g["labelled_pairs"], g["heuristic_correct"], g["jev_correct"],
                   f"reviewed {g['reviewed_pairs']}, wrong yes {g['wrong_yes']}, "
                   f"new wrong merges {g['new_wrong_merges']}")
        elif name == "verify.*":
            row = (g["labelled"], g["heuristic_correct"], g["jev_correct"],
                   f"false-valid {g['heuristic_false_valid']}→{g['jev_false_valid']}, "
                   f"precision held {g['precision_held']}")
        elif name == "roster.*":
            row = (g["labelled_contacts"], g["heuristic_recall"], g["jev_recall"],
                   f"roster size {g['heuristic_roster_size']}→{g['jev_roster_size']}, "
                   f"seniority {g['heuristic_seniority_correct']}→{g['jev_seniority_correct']}, "
                   f"recall held {g['recall_held']}")
        elif name == "reach.*":
            row = (g["heuristic_probes"], g["heuristic_confirmed"], g["jev_confirmed"],
                   f"probes {g['heuristic_probes']}→{g['jev_probes']} (equal {g['equal_cost']}), "
                   f"email yield {g['heuristic_email_yield']}→{g['jev_email_yield']}")
        else:
            row = (g["labelled"], g["heuristic_correct"], g["jev_correct"],
                   f"JEV-assisted runs {g['jev_assisted_runs']}")
        lines.append(f"| {name} | {row[0]} | {row[1]} | {row[2]} | {row[3]} | "
                     f"**{g['decision']}** |")
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
