"""Baseline-diff gate for CI — fail a PR only on NEW test/lint failures.

The suite has ~thousands of tests with a stable set of pre-existing failures,
and ruff reports hundreds of pre-existing findings. A hard "must be green" gate
would be useless here. Instead we snapshot the *current* failing set as a
committed baseline and, on every PR, fail only when a failure appears that is
NOT already in that baseline. This is what lets a reviewer tell a real new
regression from old noise (Phase 0 brief, 0A).

  python -m eval.harness.gate snapshot   # regenerate the baselines (maintainers)
  python -m eval.harness.gate check      # CI gate: nonzero exit on new failures

Baselines (committed):
  eval/baseline/known-test-failures.txt   # one pytest nodeid per line
  eval/baseline/known-ruff.txt            # one "<relpath>\t<code>" per line
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from eval.harness.manifest import REPO_ROOT

BASELINE_DIR = REPO_ROOT / "eval" / "baseline"
TEST_BASELINE = BASELINE_DIR / "known-test-failures.txt"
RUFF_BASELINE = BASELINE_DIR / "known-ruff.txt"
HUNG_BASELINE = BASELINE_DIR / "known-hung-files.txt"
# Substrings of nodeids known to flake run-to-run (network/async nondeterminism).
# A current failure matching any line here is never counted as a NEW regression.
FLAKY_ALLOWLIST = BASELINE_DIR / "known-flaky.txt"


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------
def collect_pytest_failures() -> tuple[set[str], list[str]]:
    """Return (set of failing/erroring nodeids, list of hung files).

    Uses per-file isolation (each test file in its own timed subprocess, network
    blocked) so the run TERMINATES deterministically despite the suite's live/
    async tests. The committed baseline is captured the same way, so the gate
    compares like-for-like. Hung files are treated as env-only noise, not tracked
    per-nodeid (their tests are unknowable once killed) — a NEW hung file is
    surfaced separately below.
    """
    from eval.harness.pytest_baseline import collect_failures

    r = collect_failures(timeout_per_file=90, workers=4)
    return r.failures, r.hung_files


def collect_ruff_findings() -> set[str]:
    """Return a set of '<relpath>\\t<code>' pairs (line-number-independent)."""
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "check", ".", "--output-format", "json"],
        cwd=str(REPO_ROOT), capture_output=True, text=True,
    )
    findings: set[str] = set()
    try:
        items = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return findings
    for it in items:
        fname = it.get("filename", "")
        try:
            rel = str(Path(fname).resolve().relative_to(REPO_ROOT)).replace("\\", "/")
        except ValueError:
            rel = fname
        code = it.get("code") or "?"
        findings.add(f"{rel}\t{code}")
    return findings


# ---------------------------------------------------------------------------
# Baseline IO
# ---------------------------------------------------------------------------
def _read_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {ln.rstrip("\n") for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()}


def _write_lines(path: Path, items: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(items)) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_snapshot(_args: argparse.Namespace) -> int:
    print("Collecting pytest failures (per-file isolation)…", flush=True)
    failures, hung = collect_pytest_failures()
    _write_lines(TEST_BASELINE, failures)
    _write_lines(HUNG_BASELINE, set(hung))
    print(f"  wrote {len(failures)} failing nodeids -> {TEST_BASELINE}")
    print(f"  wrote {len(hung)} hung files -> {HUNG_BASELINE}")
    print("Collecting ruff findings…", flush=True)
    ruff = collect_ruff_findings()
    _write_lines(RUFF_BASELINE, ruff)
    print(f"  wrote {len(ruff)} (file,code) findings -> {RUFF_BASELINE}")
    return 0


def cmd_check(_args: argparse.Namespace) -> int:
    base_tests = _read_lines(TEST_BASELINE)
    base_ruff = _read_lines(RUFF_BASELINE)
    base_hung = _read_lines(HUNG_BASELINE)

    print("Running pytest (per-file isolation)…", flush=True)
    cur_tests, cur_hung = collect_pytest_failures()
    print("Running ruff…", flush=True)
    cur_ruff = collect_ruff_findings()

    flaky = _read_lines(FLAKY_ALLOWLIST)

    def _is_flaky(nodeid: str) -> bool:
        return any(pat and not pat.startswith("#") and pat in nodeid for pat in flaky)

    new_tests = sorted(n for n in (cur_tests - base_tests) if not _is_flaky(n))
    flaky_new = sorted(n for n in (cur_tests - base_tests) if _is_flaky(n))
    fixed_tests = sorted(base_tests - cur_tests)
    new_ruff = sorted(cur_ruff - base_ruff)
    new_hung = sorted(set(cur_hung) - base_hung)

    print(f"\npytest: {len(cur_tests)} failing (baseline {len(base_tests)}); "
          f"{len(new_tests)} NEW, {len(fixed_tests)} fixed")
    print(f"ruff:   {len(cur_ruff)} findings (baseline {len(base_ruff)}); {len(new_ruff)} NEW")
    print(f"hung:   {len(cur_hung)} files (baseline {len(base_hung)}); {len(new_hung)} NEW")

    failed = False
    if new_tests:
        failed = True
        print("\n❌ NEW test failures (regressions vs baseline):")
        for n in new_tests:
            print(f"   {n}")
    if new_ruff:
        failed = True
        print("\n❌ NEW ruff findings (regressions vs baseline):")
        for n in new_ruff:
            print(f"   {n.replace(chr(9), '  ')}")
    if new_hung:
        failed = True
        print("\n❌ NEW hung test file(s) (a file now hangs that didn't before):")
        for n in new_hung:
            print(f"   {n}")
    if flaky_new:
        print(f"\nℹ️  {len(flaky_new)} new failure(s) ignored as known-flaky "
              f"(matched eval/baseline/known-flaky.txt).")
    if fixed_tests:
        print(f"\nℹ️  {len(fixed_tests)} previously-failing test(s) now pass — "
              f"consider refreshing the baseline with `gate snapshot`.")

    if failed:
        print("\nGATE FAILED: new failures introduced.")
        return 1
    print("\n✅ GATE PASSED: no new test, lint, or hang failures vs baseline.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Baseline-diff CI gate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    snap = sub.add_parser("snapshot", help="regenerate committed baselines")
    snap.set_defaults(func=cmd_snapshot)
    sub.add_parser("check", help="fail on new failures vs baseline").set_defaults(func=cmd_check)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
