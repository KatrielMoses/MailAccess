"""Terminating pytest collection via per-file isolation.

A single full-suite ``pytest`` run hangs on this codebase: some async tests make
outbound connections on Windows' Proactor (IOCP) loop, which a synchronous
socket block can't intercept, and there is no per-test timeout. To get a
COMPLETE, deterministic failing set we run **each test file in its own
subprocess** with a wall-clock timeout. A file that hangs is killed and recorded
as ``hung`` (an env/network artifact) instead of blocking the whole catalogue.

Each subprocess also loads ``-p eval.harness.no_network`` (fast-fail live tests)
and gets an isolated HOME so file/DB state can't collide across parallel workers.

Public API:
  collect_failures(timeout_per_file=90, workers=4) -> CollectResult
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from eval.harness.manifest import REPO_ROOT

TESTS_DIR = REPO_ROOT / "tests"
LINE_RE = re.compile(r"^(FAILED|ERROR)\s+(\S+?)(?:\s+-\s+(.*))?$")
SUMMARY_RE = re.compile(r"(\d+) (passed|failed|error|errors|skipped|deselected|xfailed|xpassed)")


@dataclass
class FileResult:
    file: str
    status: str  # ok | failures | hung | crashed
    duration: float
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    failing_nodeids: list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)


@dataclass
class CollectResult:
    failures: set[str] = field(default_factory=set)
    hung_files: list[str] = field(default_factory=list)
    per_file: list[FileResult] = field(default_factory=list)


def _iter_test_files() -> list[Path]:
    files: list[Path] = []
    for pat in ("test_*.py", "*_test.py"):
        files.extend(TESTS_DIR.rglob(pat))
    # Stable, de-duplicated order.
    return sorted({f for f in files}, key=lambda p: str(p).lower())


def _run_one(path: Path, timeout: int) -> FileResult:
    rel = str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    home = Path(tempfile.mkdtemp(prefix="matest_"))
    (home / ".mailaccess").mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    # Isolate the temp dir per file too, so pytest's ``tmp_path`` never falls back
    # to the machine's shared temp dir. On some Windows hosts that shared dir
    # (``%LOCALAPPDATA%\\Temp\\pytest-of-<user>``) can become ACL-locked, which
    # otherwise fails every ``tmp_path``-using test at fixture setup and silently
    # contaminates the baseline. A per-file temp dir keeps the gate robust and
    # baseline/check like-for-like regardless of the host's temp ACLs.
    _tmp = home / "tmp"
    _tmp.mkdir(parents=True, exist_ok=True)
    env["TEMP"] = str(_tmp)
    env["TMP"] = str(_tmp)
    env["TMPDIR"] = str(_tmp)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    # Wide terminal so pytest's -rfE summary lines aren't truncated (we parse the
    # exception reason for classification).
    env["COLUMNS"] = "250"
    cmd = [
        sys.executable, "-m", "pytest", str(path),
        "-q", "-p", "no:cacheprovider", "-p", "eval.harness.no_network",
        "--tb=no", "-rfE", "-o", "addopts=", "--timeout=45", "--timeout-method=thread",
    ]
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, capture_output=True,
                              text=True, timeout=timeout)
        out = proc.stdout + "\n" + proc.stderr
        dur = time.perf_counter() - start
        res = FileResult(file=rel, status="ok", duration=round(dur, 2))
        for line in out.splitlines():
            m = LINE_RE.match(line.strip())
            if m:
                nodeid = m.group(2)
                res.failing_nodeids.append(nodeid)
                res.reasons[nodeid] = (m.group(3) or "").strip()
        for m in SUMMARY_RE.finditer(out):
            n, kind = int(m.group(1)), m.group(2)
            if kind == "passed":
                res.passed = n
            elif kind == "failed":
                res.failed = n
            elif kind.startswith("error"):
                res.errors = n
            elif kind == "skipped":
                res.skipped = n
        if res.failing_nodeids:
            res.status = "failures"
        elif proc.returncode not in (0, 1, 5):  # 5 = no tests collected
            res.status = "crashed"
        return res
    except subprocess.TimeoutExpired:
        dur = time.perf_counter() - start
        return FileResult(file=rel, status="hung", duration=round(dur, 2))
    finally:
        import shutil

        shutil.rmtree(home, ignore_errors=True)


def collect_failures(timeout_per_file: int = 90, workers: int = 4,
                     progress: bool = False) -> CollectResult:
    files = _iter_test_files()
    result = CollectResult()
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_run_one, f, timeout_per_file): f for f in files}
        for fut in as_completed(futs):
            fr = fut.result()
            result.per_file.append(fr)
            done += 1
            if fr.status == "hung":
                result.hung_files.append(fr.file)
            for nid in fr.failing_nodeids:
                result.failures.add(nid)
            if progress:
                print(f"[{done}/{len(files)}] {fr.status:8s} {fr.file} "
                      f"({fr.duration}s, {len(fr.failing_nodeids)} fail)", flush=True)
    result.per_file.sort(key=lambda r: r.file)
    return result


if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout-per-file", type=int, default=90)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", default=None, help="write JSON summary here")
    args = ap.parse_args()

    r = collect_failures(args.timeout_per_file, args.workers, progress=True)
    summary = {
        "total_failing": len(r.failures),
        "hung_files": r.hung_files,
        "n_files": len(r.per_file),
        "per_file": [vars(fr) for fr in r.per_file],
        "failures": sorted(r.failures),
    }
    print(f"\nTOTAL failing nodeids: {len(r.failures)}  ·  hung files: {len(r.hung_files)}")
    if args.out:
        Path(args.out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"wrote {args.out}")
