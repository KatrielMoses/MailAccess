"""Phase 0 baseline harness — drive both MailAccess pipelines over the target set.

Runs unattended. For each target it invokes the tool through its **public CLI**
(not internal APIs) so the scorecard contract stays stable across the coming
re-architecture. Two run configs are supported:

  * ``keyless-default`` (PRIMARY): the tool is run in an ISOLATED environment
    with every API key stripped and no dotenv picked up, so the numbers reflect
    exactly what a zero-key user gets. This is the headline baseline.
  * ``with-keys`` (SECONDARY, clearly labelled): the tool runs from the repo
    root so it reads the repo ``./.env`` keys itself. The harness never reads or
    stores key values.

Both configs redirect the tool's HOME to a per-run scratch dir, so results,
caches, and the investigate SQLite DB are captured per-run and never touch the
user's real ``~/.mailaccess``.

Output per run goes to ``eval/scorecards/<run_id>/`` (gitignored):
  manifest.json, runlog.json, raw/<target>.run<N>.<pipeline>.json, logs/...

Usage:
  python -m eval.harness.run_baseline --config keyless-default --runs 1
  python -m eval.harness.run_baseline --only corp_own_1 --emails-only
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from eval.harness.manifest import _KEY_NAMES, REPO_ROOT, _dotenv_key_names, build_manifest

SCORECARDS_DIR = REPO_ROOT / "eval" / "scorecards"
TARGETS_FILE = REPO_ROOT / "eval" / "targets.yaml"


# ---------------------------------------------------------------------------
# Run configuration (environment isolation)
# ---------------------------------------------------------------------------
@dataclass
class RunConfig:
    label: str
    strip_keys: bool  # keyless => strip all key + dotenv-defined names
    use_repo_cwd: bool  # with-keys => cwd=repo so ./.env is read by the tool
    # security-enabled (Config B): extra env toggles turning the de-vendored
    # native modules ON, plus a product mode passed via --mode. Left empty for
    # the parity configs so their CLI invocation stays byte-identical to the
    # v0.14.4 baseline (the regression proof must not change the command line).
    extra_env: dict[str, str] = field(default_factory=dict)
    mode: str | None = None

    def build_env(self, home_dir: Path) -> dict[str, str]:
        env = dict(os.environ)
        # Redirect HOME so ~/.mailaccess resolves into the per-run scratch dir.
        env["HOME"] = str(home_dir)
        env["USERPROFILE"] = str(home_dir)
        if home_dir.drive:
            env["HOMEDRIVE"] = str(home_dir.drive) + os.sep
        env["HOMEPATH"] = str(home_dir)
        # Ensure the package is importable regardless of cwd.
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        # Deterministic, non-interactive.
        env["PYTHONIOENCODING"] = "utf-8"
        env["NO_COLOR"] = "1"
        if self.strip_keys:
            # Remove every known key name AND every name defined in either dotenv,
            # so the tool falls back to code defaults (true zero-key posture).
            names_to_strip = set(_KEY_NAMES)
            names_to_strip |= _dotenv_key_names(REPO_ROOT / ".env")
            names_to_strip |= _dotenv_key_names(Path.home() / ".mailaccess" / ".env")
            for name in names_to_strip:
                env.pop(name, None)
        # Config B: apply native-module enable toggles AFTER stripping so they
        # survive the keyless purge (they are behavior flags, not API keys).
        for name, value in self.extra_env.items():
            env[name] = value
        return env

    def build_cwd(self, isolated_cwd: Path) -> Path:
        # with-keys: run from repo root so the tool reads ./.env.
        # keyless: run from an isolated cwd so ./.env is NOT found.
        return REPO_ROOT if self.use_repo_cwd else isolated_cwd


CONFIGS: dict[str, RunConfig] = {
    "keyless-default": RunConfig("keyless-default", strip_keys=True, use_repo_cwd=False),
    "with-keys": RunConfig("with-keys", strip_keys=False, use_repo_cwd=True),
    # Config B — keyless isolation (no API keys) but with the de-vendored native
    # engines explicitly enabled and the full-capability product mode selected,
    # so the run exercises account_discovery + username_platforms (+ google
    # account intel, on by default) that the public/default gate keeps dormant.
    "security-enabled": RunConfig(
        "security-enabled",
        strip_keys=True,
        use_repo_cwd=False,
        extra_env={
            "ENABLE_ACCOUNT_DISCOVERY": "true",
            "ENABLE_USERNAME_PLATFORMS": "true",
            "ENABLE_GOOGLE_ACCOUNT_INTEL": "true",
        },
        mode="security-investigation",
    ),
}


# ---------------------------------------------------------------------------
# Target loading
# ---------------------------------------------------------------------------
@dataclass
class Target:
    id: str
    value: str
    category: str
    note: str = ""


@dataclass
class TargetSet:
    emails: list[Target] = field(default_factory=list)
    domains: list[Target] = field(default_factory=list)


def load_targets(path: Path = TARGETS_FILE) -> TargetSet:
    if not path.exists():
        raise SystemExit(
            f"Target file not found: {path}\n"
            f"Copy eval/targets.example.yaml -> eval/targets.yaml and fill in the "
            f"authorized targets (the real file is gitignored)."
        )
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    ts = TargetSet()
    for row in data.get("emails", []):
        ts.emails.append(
            Target(row["id"], row["value"], row.get("category", ""), row.get("note", ""))
        )
    for row in data.get("domains", []):
        ts.domains.append(
            Target(row["id"], row["value"], row.get("category", ""), row.get("note", ""))
        )
    return ts


# ---------------------------------------------------------------------------
# Pipeline invocations
# ---------------------------------------------------------------------------
def _run_cli(
    args: list[str], cfg: RunConfig, home_dir: Path, isolated_cwd: Path,
    timeout: int, log_path: Path,
) -> dict[str, Any]:
    """Run a mailaccess CLI subprocess; return timing/exit/log metadata."""
    env = cfg.build_env(home_dir)
    cwd = cfg.build_cwd(isolated_cwd)
    cmd = [sys.executable, "-m", "cli.main", "--no-banner", *args]
    start = time.perf_counter()
    timed_out = False
    try:
        proc = subprocess.run(
            cmd, env=env, cwd=str(cwd), capture_output=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        rc = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = -1
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + f"\n[harness] TIMEOUT after {timeout}s"
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
    wall = time.perf_counter() - start
    log_path.write_text(
        f"$ {' '.join(cmd)}\ncwd={cwd}\n\n=== STDOUT ===\n{stdout}\n\n=== STDERR ===\n{stderr}\n",
        encoding="utf-8",
    )
    return {
        "cmd": cmd,
        "exit_code": rc,
        "wall_seconds": round(wall, 3),
        "timed_out": timed_out,
        "stderr_tail": "\n".join(stderr.splitlines()[-8:]),
    }


def _port_in_use(host: str = "127.0.0.1", port: int = 8000) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def run_investigate(
    target: Target, cfg: RunConfig, run_dir: Path, run_idx: int, timeout: int
) -> dict[str, Any]:
    home_dir = _fresh_home(run_dir, target.id, run_idx)
    isolated_cwd = home_dir / "cwd"
    isolated_cwd.mkdir(parents=True, exist_ok=True)
    # Contamination guard: the CLI auto-spawns `serve` on 127.0.0.1:8000 and the
    # spawn port is not overridable. If a foreign server is already on :8000, an
    # investigate would latch onto IT (possibly with real keys) instead of the
    # harness's isolated, keyless server. Abort rather than contaminate.
    if _port_in_use():
        raw_path = run_dir / "raw" / f"{target.id}.run{run_idx}.investigate.json"
        return {
            "target_id": target.id, "target_value": target.value, "category": target.category,
            "pipeline": "investigate", "run_idx": run_idx, "ok": False,
            "raw_path": _rel(raw_path, run_dir), "log_path": None,
            "exit_code": None, "wall_seconds": 0.0, "timed_out": False,
            "stderr_tail": "[harness] ABORTED: 127.0.0.1:8000 already in use — stop any "
                           "running `mailaccess serve` so the harness can spawn an isolated "
                           "server (else the keyless baseline would be contaminated).",
            "extracted": None,
        }
    raw_path = run_dir / "raw" / f"{target.id}.run{run_idx}.investigate.json"
    log_path = run_dir / "logs" / f"{target.id}.run{run_idx}.investigate.log"
    mode_args = ["--mode", cfg.mode] if cfg.mode else []
    meta = _run_cli(
        ["investigate", target.value, "--format", "json",
         "--output", str(raw_path), "--timeout", "30", *mode_args],
        cfg,
        home_dir,
        isolated_cwd,
        timeout,
        log_path,
    )
    raw = _load_json(raw_path)
    return {
        "target_id": target.id,
        "target_value": target.value,
        "category": target.category,
        "pipeline": "investigate",
        "run_idx": run_idx,
        "ok": meta["exit_code"] == 0 and raw is not None,
        "raw_path": _rel(raw_path, run_dir),
        "log_path": _rel(log_path, run_dir),
        **{k: meta[k] for k in ("exit_code", "wall_seconds", "timed_out", "stderr_tail")},
        "extracted": _extract_investigate(raw) if raw else None,
    }


def run_harvest(
    target: Target, cfg: RunConfig, run_dir: Path, run_idx: int, timeout: int
) -> dict[str, Any]:
    home_dir = _fresh_home(run_dir, target.id, run_idx)
    isolated_cwd = home_dir / "cwd"
    isolated_cwd.mkdir(parents=True, exist_ok=True)
    raw_path = run_dir / "raw" / f"{target.id}.run{run_idx}.harvest.json"
    log_path = run_dir / "logs" / f"{target.id}.run{run_idx}.harvest.log"
    mode_args = ["--mode", cfg.mode] if cfg.mode else []
    meta = _run_cli(
        ["harvest-emails", "-d", target.value, "--export", str(raw_path),
         "--timeout", str(timeout - 30), *mode_args],
        cfg,
        home_dir,
        isolated_cwd,
        timeout,
        log_path,
    )
    raw = _load_json(raw_path)
    return {
        "target_id": target.id,
        "target_value": target.value,
        "category": target.category,
        "pipeline": "harvest",
        "run_idx": run_idx,
        "ok": meta["exit_code"] == 0 and raw is not None,
        "raw_path": _rel(raw_path, run_dir),
        "log_path": _rel(log_path, run_dir),
        **{k: meta[k] for k in ("exit_code", "wall_seconds", "timed_out", "stderr_tail")},
        "extracted": _extract_harvest(raw) if raw else None,
    }


# ---------------------------------------------------------------------------
# Lightweight extraction (full detail stays in raw/; scoring reads raw/ too)
# ---------------------------------------------------------------------------
def _extract_investigate(raw: dict[str, Any]) -> dict[str, Any]:
    findings = raw.get("findings") or []
    module_runs = raw.get("module_runs") or []
    return {
        "exposure_score": raw.get("exposure_score"),
        "exposure_score_pct": raw.get("exposure_score_pct"),
        "risk_level": raw.get("risk_level"),
        "credential_risk_score": raw.get("credential_risk_score"),
        "confirmed_name": raw.get("confirmed_name"),
        "name_confidence": raw.get("name_confidence"),
        "finding_count": len(findings),
        "module_count": len(module_runs),
        "module_status_counts": _count_by(module_runs, "status"),
    }


def _extract_harvest(raw: dict[str, Any]) -> dict[str, Any]:
    summary = raw.get("summary") or {}
    emails = raw.get("emails") or []
    return {
        "duration_seconds": raw.get("duration_seconds"),
        "total_unique_emails": summary.get("total_unique_emails", len(emails)),
        "confirmed_count": summary.get("high_confidence"),  # legacy key == CONFIRMED tier
        "likely_count": summary.get("likely_confidence"),
        "medium_count": summary.get("medium_confidence"),
        "low_count": summary.get("low_confidence"),
        "role_accounts": summary.get("role_accounts"),
        "smtp_verified_emails": summary.get("smtp_verified_emails"),
        "smtp_not_found_emails": summary.get("smtp_not_found_emails"),
        "smtp_inconclusive_emails": summary.get("smtp_inconclusive_emails"),
        "smtp_verification_used": summary.get("smtp_verification_used"),
        "catchall_detected": summary.get("catchall_detected"),
        "confirmed_pattern": summary.get("confirmed_pattern"),
        "people_count": summary.get("people_count"),
        "module_timings": summary.get("module_timings"),
        "module_skip_reasons": summary.get("module_skip_reasons"),
    }


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        v = str(it.get(key))
        out[v] = out.get(v, 0) + 1
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _fresh_home(run_dir: Path, target_id: str, run_idx: int) -> Path:
    home = run_dir / "home" / f"{target_id}.run{run_idx}"
    if home.exists():
        shutil.rmtree(home, ignore_errors=True)
    (home / ".mailaccess").mkdir(parents=True, exist_ok=True)
    return home


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _rel(p: Path, base: Path) -> str:
    try:
        return str(p.relative_to(base))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="MailAccess Phase 0 baseline harness")
    ap.add_argument("--config", choices=list(CONFIGS), default="keyless-default")
    ap.add_argument("--runs", type=int, default=1, help="repeat count for stability (0D)")
    ap.add_argument("--only", nargs="*", default=None, help="target ids to include")
    ap.add_argument("--emails-only", action="store_true")
    ap.add_argument("--domains-only", action="store_true")
    # Must exceed the CLI's budget-derived wait ceiling
    # (investigation_budget_seconds + margin ~= 510s at the 420s default) so a
    # healthy long run (e.g. lavellenetworks ~257s) is never killed by the
    # subprocess timeout before it completes. Phase 1B raised this from 240.
    ap.add_argument("--investigate-timeout", type=int, default=600)
    ap.add_argument("--harvest-timeout", type=int, default=720)
    ap.add_argument("--out", default=None, help="override run dir (default under eval/scorecards)")
    args = ap.parse_args(argv)

    cfg = CONFIGS[args.config]
    ts = load_targets()

    emails = ts.emails if not args.domains_only else []
    domains = ts.domains if not args.emails_only else []
    if args.only:
        keep = set(args.only)
        emails = [t for t in emails if t.id in keep]
        domains = [t for t in domains if t.id in keep]

    existing_out = args.out and (Path(args.out) / "runlog.json").exists()
    # Resolve to an ABSOLUTE path: raw/log paths are passed to the tool subprocess,
    # which runs in an isolated cwd — a relative path would resolve against THAT
    # cwd and the captures would land in the wrong place.
    run_dir = (Path(args.out) if args.out else SCORECARDS_DIR / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"_{cfg.label}"
    )).resolve()
    for sub in ("raw", "logs", "home"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)

    # Resume: reuse an existing runlog in the same --out dir so a long capture that
    # crossed a session boundary or died can be re-invoked and continue. Any
    # (target, pipeline, run_idx) already recorded is skipped (including timeouts,
    # so failures aren't retried forever — delete a record to force a re-run).
    records: list[dict[str, Any]] = []
    run_id = run_dir.name
    if existing_out:
        prior = _load_json(run_dir / "runlog.json") or {}
        records = prior.get("records", [])
        run_id = prior.get("run_id", run_id)
        print(f"[resume] loaded {len(records)} prior record(s) from {run_dir / 'runlog.json'}")
    done_keys = {(r["target_id"], r["pipeline"], r["run_idx"]) for r in records}

    manifest = build_manifest(
        config_label=cfg.label,
        keys_stripped=cfg.strip_keys,
        extra={
            "run_id": run_id,
            "runs": args.runs,
            # Config B specifics live in the subprocess env, so record them here
            # explicitly (the harness-process resolved_config cannot see them).
            "cli_mode": cfg.mode,
            "module_enable_env": cfg.extra_env,
        },
    )
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    total = (len(emails) + len(domains)) * args.runs
    done = 0
    for run_idx in range(1, args.runs + 1):
        for t in emails:
            done += 1
            if (t.id, "investigate", run_idx) in done_keys:
                print(f"[{done}/{total}] investigate {t.id} run {run_idx} — SKIP", flush=True)
                continue
            print(f"[{done}/{total}] investigate {t.id} ({t.value}) run {run_idx} …", flush=True)
            rec = run_investigate(t, cfg, run_dir, run_idx, args.investigate_timeout)
            records.append(rec)
            _dump_runlog(run_dir, manifest, records)  # incremental, resumable
            print(f"    -> ok={rec['ok']} exit={rec['exit_code']} "
                  f"{rec['wall_seconds']}s", flush=True)
        for t in domains:
            done += 1
            if (t.id, "harvest", run_idx) in done_keys:
                print(f"[{done}/{total}] harvest {t.id} run {run_idx} — SKIP (done)", flush=True)
                continue
            print(f"[{done}/{total}] harvest {t.id} ({t.value}) run {run_idx} …", flush=True)
            rec = run_harvest(t, cfg, run_dir, run_idx, args.harvest_timeout)
            records.append(rec)
            _dump_runlog(run_dir, manifest, records)
            print(f"    -> ok={rec['ok']} exit={rec['exit_code']} "
                  f"{rec['wall_seconds']}s", flush=True)

    _dump_runlog(run_dir, manifest, records)
    print(f"\nRun complete. Runlog: {run_dir / 'runlog.json'}")
    print(f"Score it with:  python -m eval.harness.score --run {run_dir}")
    return 0


def _dump_runlog(run_dir: Path, manifest: dict[str, Any], records: list[dict[str, Any]]) -> None:
    (run_dir / "runlog.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": manifest["extra"]["run_id"],
                "config_label": manifest["config_label"],
                "config_hash": manifest["config_hash"],
                "records": records,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
