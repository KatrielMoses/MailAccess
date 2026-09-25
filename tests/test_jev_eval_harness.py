"""Phase JEV-0 — side-by-side eval harness: env isolation + comparison scorecard.

No subprocesses and no network: build_env is exercised directly and the
comparison runs over synthetic off/on run directories.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from eval.harness import jev_compare, score
from eval.harness.run_baseline import CONFIGS, JEV_METRICS_SUBDIR


@pytest.fixture(autouse=True)
def _jev_shell_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("JEV_API_KEY", "shell-key-not-real")
    monkeypatch.setenv("JEV_BASE_URL", "https://jev.invalid/v1")
    monkeypatch.setenv("JEV_MODEL", "jev-test")
    monkeypatch.setenv("JEV_FORCE_OFF", "false")  # a stray export must not leak
    # The harness's "real" home (where `keys set` stores keys) — empty by default.
    monkeypatch.setenv("HOME", str(tmp_path / "realhome"))


@pytest.mark.parametrize("label", ["keyless-default", "with-keys", "security-enabled"])
def test_legacy_configs_force_jev_off(tmp_path: Path, label: str) -> None:
    env = CONFIGS[label].build_env(tmp_path / "run")
    assert {k: v for k, v in env.items() if k.startswith("JEV_")} == {"JEV_FORCE_OFF": "true"}


def test_jev_off_pass_matches_no_key_install(tmp_path: Path) -> None:
    off = dataclasses.replace(CONFIGS["with-keys"], jev=False)
    env = off.build_env(tmp_path)
    assert env["JEV_FORCE_OFF"] == "true"
    assert "JEV_API_KEY" not in env
    assert env["JEV_METRICS_DIR"] == str(tmp_path / JEV_METRICS_SUBDIR)


def test_jev_on_forwards_shell_config_through_keyless(tmp_path: Path) -> None:
    on = dataclasses.replace(CONFIGS["keyless-default"], jev=True, jev_cache_refresh=True)
    env = on.build_env(tmp_path / "run")
    assert env["JEV_API_KEY"] == "shell-key-not-real"
    assert env["JEV_MODEL"] == "jev-test"
    assert env["JEV_CACHE_REFRESH"] == "true"
    assert "JEV_FORCE_OFF" not in env


def test_jev_on_falls_back_to_profile_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JEV_API_KEY")
    profile = tmp_path / "realhome" / ".mailaccess" / ".env"
    profile.parent.mkdir(parents=True)
    profile.write_text("JEV_API_KEY=profile-key-not-real\nHIBP_API_KEY=unrelated\n")
    on = dataclasses.replace(CONFIGS["keyless-default"], jev=True)
    env = on.build_env(tmp_path / "run")
    assert env["JEV_API_KEY"] == "profile-key-not-real"
    assert "HIBP_API_KEY" not in env  # only JEV_* is taken from the profile


# ---------------------------------------------------------------------------
# Comparison over synthetic run dirs
# ---------------------------------------------------------------------------
def _write_run(run_dir: Path, label: str, findings: list[dict[str, Any]],
               emails: list[str], jev_tasks: dict[str, Any] | None) -> None:
    (run_dir / "raw").mkdir(parents=True)
    inv = {"exposure_score": 42, "credential_risk_score": 7, "risk_level": "medium",
           "findings": findings, "module_runs": []}
    har = {"emails": [{"email": e} for e in emails], "summary": {}}
    (run_dir / "raw" / "e1.run1.investigate.json").write_text(json.dumps(inv))
    (run_dir / "raw" / "d1.run1.harvest.json").write_text(json.dumps(har))
    records = [
        {"target_id": "e1", "target_value": "a@example.com", "category": "free",
         "pipeline": "investigate", "run_idx": 1, "ok": True, "wall_seconds": 10.0,
         "raw_path": "raw/e1.run1.investigate.json", "exit_code": 0},
        {"target_id": "d1", "target_value": "example.com", "category": "corporate_small",
         "pipeline": "harvest", "run_idx": 1, "ok": True, "wall_seconds": 20.0,
         "raw_path": "raw/d1.run1.harvest.json", "exit_code": 0},
    ]
    (run_dir / "runlog.json").write_text(json.dumps(
        {"run_id": run_dir.name, "config_label": label, "config_hash": "x", "records": records}
    ))
    (run_dir / "manifest.json").write_text(json.dumps(
        {"tool_version": "test", "extra": {"jev_model": "jev-test" if jev_tasks else None}}
    ))
    if jev_tasks is not None:
        mdir = run_dir / "home" / "e1.run1" / JEV_METRICS_SUBDIR
        mdir.mkdir(parents=True)
        (mdir / "jev-metrics-123.json").write_text(json.dumps({"pid": 123, "tasks": jev_tasks}))


def test_compare_writes_scorecard_with_task_metrics_and_deltas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(score, "load_truth", lambda: {})
    finding = {"id": 1, "module_name": "gravatar_lookup", "created_at": "t1",
               "data": {"url": "https://g/x", "fetched_at": "now"}}
    moved = {**finding, "id": 9, "created_at": "t2", "data": {**finding["data"],
                                                              "fetched_at": "later"}}
    extra = {"id": 2, "module_name": "hibp", "data": {"breach": "Example"}}
    task = {"calls": 4, "verdicts": 3, "defers": 1, "cache_hits": 1, "model_calls": 3,
            "defer_reasons": {"low_confidence": 1},
            "latency_ms": {"n": 4, "mean": 100.0, "max": 250.0}}

    _write_run(tmp_path / "off", "keyless-default+jev-off", [finding], ["a@x.com"], None)
    _write_run(tmp_path / "on", "keyless-default+jev-on", [moved, extra],
               ["a@x.com", "b@x.com"], {"demo.plausible_personal_name": task})

    c = jev_compare.compare(tmp_path / "off", tmp_path / "on", tmp_path)

    assert c["off_pass_model_calls"] == 0
    assert c["jev_model"] == "jev-test"
    t = c["jev_tasks"]["demo.plausible_personal_name"]
    assert (t["calls"], t["defer_rate"], t["cache_hit_rate"]) == (4, 0.25, 0.25)
    assert t["latency_mean_ms"] == 100.0 and t["latency_max_ms"] == 250.0

    pairs = {p["pipeline"]: p for p in c["pairs"]}
    # Volatile timestamps never count as an output change; the new hibp row does.
    assert (pairs["investigate"]["added"], pairs["investigate"]["removed"]) == (1, 0)
    assert pairs["investigate"]["score_drift"] == {}
    assert pairs["investigate"]["jev"]["calls"] == 4
    assert (pairs["harvest"]["added"], pairs["harvest"]["removed"]) == (1, 0)
    assert c["summary"]["n_comparable"] == 2
    assert (tmp_path / "comparison.md").read_text().startswith("# JEV side-by-side")
    assert (tmp_path / "off" / "scorecard.json").exists()
    assert (tmp_path / "on" / "scorecard.json").exists()


def test_compare_flags_score_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(score, "load_truth", lambda: {})
    _write_run(tmp_path / "off", "off", [], [], None)
    _write_run(tmp_path / "on", "on", [], [], {})
    raw_path = tmp_path / "on" / "raw" / "e1.run1.investigate.json"
    raw = json.loads(raw_path.read_text())
    raw["exposure_score"] = 55
    raw_path.write_text(json.dumps(raw))

    c = jev_compare.compare(tmp_path / "off", tmp_path / "on", tmp_path)
    inv = next(p for p in c["pairs"] if p["pipeline"] == "investigate")
    assert inv["score_drift"] == {"exposure_score": (42, 55)}
    assert c["summary"]["n_score_drift"] == 1


# ---------------------------------------------------------------------------
# JEV-1 per-task gate vs gold truth
# ---------------------------------------------------------------------------
def _write_investigate(run_dir: Path, raw: dict[str, Any]) -> None:
    (run_dir / "raw").mkdir(parents=True)
    (run_dir / "raw" / "e1.run1.investigate.json").write_text(json.dumps(raw))
    (run_dir / "runlog.json").write_text(json.dumps({"run_id": run_dir.name, "records": [
        {"target_id": "e1", "target_value": "a@example.com", "category": "free",
         "pipeline": "investigate", "run_idx": 1, "ok": True, "wall_seconds": 1.0,
         "raw_path": "raw/e1.run1.investigate.json", "exit_code": 0}]}))
    (run_dir / "manifest.json").write_text(json.dumps({"tool_version": "t", "extra": {}}))


_TRUTH = {"e1": {
    "identity": {"real_name": "Robert Smith", "employer": "Northwind Labs",
                 "role_title": "unknown", "location": "Leeds"},
    "accounts": [
        {"key": "github:nightowl", "verdict": "true_positive"},
        {"key": "gitlab:nightowl", "verdict": "false_positive"},
        {"key": "reddit:jq", "verdict": "true_positive"},
        {"key": "mastodon:jq", "verdict": "true_positive"},
    ],
}}


def test_task_gate_keeps_winners_and_drops_ties(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(score, "load_truth", lambda: _TRUTH)
    off = {"confirmed_name": "Bob Smith", "findings": [], "module_runs": []}
    on = {
        "confirmed_name": "Robert Smith",
        "name_reasoning": "… Candidate grouping was JEV-assisted (identity.name_reconcile).",
        "module_runs": [],
        "findings": [{"module_name": "github_commits", "data": {"platform": "github_user",
            "metadata": {"bio_structured": {"employer": "Northwind Labs",
                                            "location": "Paris", "jev_assisted": True}}}}],
        "graph_data": {"jev_review": [
            {"a": "github", "b": "gitlab", "heuristic_merge": True, "jev": "no"},
            {"a": "reddit", "b": "mastodon", "heuristic_merge": True, "jev": "unclear"},
            {"a": "x", "b": "y", "heuristic_merge": True, "jev": "yes"},  # unlabelled
        ]},
    }
    _write_investigate(tmp_path / "off", off)
    _write_investigate(tmp_path / "on", on)

    gate = jev_compare.task_gate(tmp_path / "off", tmp_path / "on")

    names = gate["identity.name_reconcile"]
    assert (names["heuristic_correct"], names["jev_correct"], names["decision"]) == (0, 1, "keep")
    assert names["jev_assisted_runs"] == 1

    sp = gate["identity.same_person"]
    # github/gitlab: heuristic merged a TP with an FP (wrong); JEV said no (right).
    # reddit/mastodon: unclear → heuristic merge stands (right for both).
    assert (sp["labelled_pairs"], sp["heuristic_correct"], sp["jev_correct"]) == (2, 1, 2)
    assert sp["new_wrong_merges"] == 0 and sp["decision"] == "keep"

    bio = gate["identity.bio_extract"]
    assert (bio["correct"], bio["wrong"], bio["jev_score"]) == (1, 1, 0)
    assert bio["decision"] == "drop"  # a tie with the heuristic's 0 is dropped


def test_task_gate_without_labels_drops(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(score, "load_truth", lambda: {})
    for sub in ("off", "on"):
        _write_investigate(tmp_path / sub, {"findings": [], "module_runs": []})
    gate = jev_compare.task_gate(tmp_path / "off", tmp_path / "on")
    assert {g["decision"] for g in gate.values()} == {"drop (no labels)"}
    c = jev_compare.compare(tmp_path / "off", tmp_path / "on", tmp_path)
    assert "## Task gate" in (tmp_path / "comparison.md").read_text()
    assert c["task_gate"] == gate


# ---------------------------------------------------------------------------
# JEV-2 verification gate (harvest deliverability precision)
# ---------------------------------------------------------------------------
def _write_harvest(run_dir: Path, emails: list[dict[str, Any]]) -> None:
    (run_dir / "raw").mkdir(parents=True)
    (run_dir / "raw" / "d1.run1.harvest.json").write_text(
        json.dumps({"emails": emails, "summary": {}}))
    (run_dir / "runlog.json").write_text(json.dumps({"run_id": run_dir.name, "records": [
        {"target_id": "d1", "target_value": "x.com", "category": "corporate_small",
         "pipeline": "harvest", "run_idx": 1, "ok": True, "wall_seconds": 1.0,
         "raw_path": "raw/d1.run1.harvest.json", "exit_code": 0}]}))
    (run_dir / "manifest.json").write_text(json.dumps({"tool_version": "t", "extra": {}}))


_HARVEST_TRUTH = {"d1": {"kind": "domain", "known_contacts": [
    {"email": "real@x.com", "currently_deliverable": "true"},
], "false_positive_emails": ["ghost@x.com"]}}


def test_verification_gate_keeps_when_precision_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(score, "load_truth", lambda: _HARVEST_TRUTH)
    # OFF: real address only Risky (missed), ghost wrongly Valid (a false valid).
    _write_harvest(tmp_path / "off", [
        {"email": "real@x.com", "deliverability_grade": "Risky"},
        {"email": "ghost@x.com", "deliverability_grade": "Valid"}])
    # ON: real correctly Valid, ghost demoted to Invalid → more correct, fewer false-valid.
    _write_harvest(tmp_path / "on", [
        {"email": "real@x.com", "deliverability_grade": "Valid"},
        {"email": "ghost@x.com", "deliverability_grade": "Invalid"}])

    g = jev_compare.task_gate(tmp_path / "off", tmp_path / "on")["verify.*"]
    assert (g["heuristic_correct"], g["jev_correct"]) == (0, 2)
    assert (g["heuristic_false_valid"], g["jev_false_valid"]) == (1, 0)
    assert g["precision_held"] is True and g["decision"] == "keep"


def test_verification_gate_drops_on_new_false_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(score, "load_truth", lambda: _HARVEST_TRUTH)
    _write_harvest(tmp_path / "off", [
        {"email": "real@x.com", "deliverability_grade": "Risky"},
        {"email": "ghost@x.com", "deliverability_grade": "Invalid"}])
    # ON gets real right (+1 correct) but also flips ghost to Valid (a NEW false valid).
    _write_harvest(tmp_path / "on", [
        {"email": "real@x.com", "deliverability_grade": "Valid"},
        {"email": "ghost@x.com", "deliverability_grade": "Valid"}])

    g = jev_compare.task_gate(tmp_path / "off", tmp_path / "on")["verify.*"]
    # A new false 'valid' appeared (0 → 1): the precision guard fails, so drop even
    # though the real address was newly graded correctly.
    assert (g["heuristic_false_valid"], g["jev_false_valid"]) == (0, 1)
    assert g["precision_held"] is False and g["decision"] == "drop"


# ---------------------------------------------------------------------------
# JEV-3 roster gate (recall guard is primary)
# ---------------------------------------------------------------------------
_ROSTER_TRUTH = {"d1": {"kind": "domain", "known_contacts": [
    {"email": "real@x.com", "seniority": "vp"},
    {"email": "two@x.com", "seniority": "unknown"},
]}}


def test_roster_gate_keeps_when_cleaner_and_recall_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(score, "load_truth", lambda: _ROSTER_TRUTH)
    # OFF: both labeled contacts present + a junk row; real@ has wrong seniority.
    _write_harvest(tmp_path / "off", [
        {"email": "real@x.com", "seniority": "ic"},
        {"email": "two@x.com"},
        {"email": "junkrow@x.com"}])
    # ON: junk row dropped (cleaner), real@ seniority fixed, both labeled kept (recall held).
    _write_harvest(tmp_path / "on", [
        {"email": "real@x.com", "seniority": "vp"},
        {"email": "two@x.com"}])
    g = jev_compare.task_gate(tmp_path / "off", tmp_path / "on")["roster.*"]
    assert (g["heuristic_recall"], g["jev_recall"]) == (2, 2)
    assert (g["heuristic_roster_size"], g["jev_roster_size"]) == (3, 2)
    assert g["recall_held"] is True and g["decision"] == "keep"


def test_roster_gate_drops_when_recall_regresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(score, "load_truth", lambda: _ROSTER_TRUTH)
    _write_harvest(tmp_path / "off", [
        {"email": "real@x.com", "seniority": "vp"},
        {"email": "two@x.com"}, {"email": "junk@x.com"}])
    # ON drops a junk row but ALSO loses a labeled real contact → recall regressed.
    _write_harvest(tmp_path / "on", [{"email": "real@x.com", "seniority": "vp"}])
    g = jev_compare.task_gate(tmp_path / "off", tmp_path / "on")["roster.*"]
    assert g["jev_recall"] < g["heuristic_recall"]
    assert g["recall_held"] is False and g["decision"] == "drop"
