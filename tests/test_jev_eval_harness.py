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
def _jev_shell_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JEV_API_KEY", "shell-key-not-real")
    monkeypatch.setenv("JEV_BASE_URL", "https://jev.invalid/v1")
    monkeypatch.setenv("JEV_MODEL", "jev-test")
    monkeypatch.setenv("JEV_ENABLED", "true")  # a stray export must not leak


def test_legacy_keyless_config_strips_all_jev_env(tmp_path: Path) -> None:
    env = CONFIGS["keyless-default"].build_env(tmp_path)
    assert not [k for k in env if k.startswith("JEV_")]


def test_jev_off_forces_disabled_and_drops_the_key(tmp_path: Path) -> None:
    off = dataclasses.replace(CONFIGS["with-keys"], jev=False)
    env = off.build_env(tmp_path)
    assert env["JEV_ENABLED"] == "false"
    assert "JEV_API_KEY" not in env
    assert env["JEV_METRICS_DIR"] == str(tmp_path / JEV_METRICS_SUBDIR)


def test_jev_on_forwards_shell_config_through_keyless(tmp_path: Path) -> None:
    on = dataclasses.replace(CONFIGS["keyless-default"], jev=True, jev_cache_refresh=True)
    env = on.build_env(tmp_path)
    assert env["JEV_ENABLED"] == "true"
    assert env["JEV_API_KEY"] == "shell-key-not-real"
    assert env["JEV_MODEL"] == "jev-test"
    assert env["JEV_CACHE_REFRESH"] == "true"


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
