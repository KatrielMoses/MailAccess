"""Phase 5B — data-acquisition resilience metrics harness.

Measures hard-block counts (rate-limit / blocked / CAPTCHA / HTTP-202 walls) a
harvest incurs, comparing the **resilient** posture (5B defaults: CC-first +
fingerprint rotation, plus the always-on unified throttle and search failover)
against a **legacy** posture (CC-first off, rotation off) — the Phase-0D
failure-mode baseline behaviour. Keyless and isolated, mirroring
:mod:`eval.harness.corpus_parity`.

The done-when for 5B's block-reduction bullet is: the resilient run shows
measurably fewer hard-blocks than the legacy baseline. Run::

    uv run python -m eval.harness.resilience_metrics --timeout 180 \
        lavellenetworks.com rootaccess.tech stripe.com
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from eval.harness.run_baseline import CONFIGS

# Hard-block signal patterns (case-insensitive) counted in the run output.
_BLOCK_PATTERNS = [
    re.compile(r"HTTP\s*202", re.I),
    re.compile(r"captcha", re.I),
    re.compile(r"\bblocked\b", re.I),
    re.compile(r"block page", re.I),
    re.compile(r"HTTP\s*429", re.I),
    re.compile(r"rate.?limit", re.I),
    re.compile(r"anomaly", re.I),
    re.compile(r"unusual traffic", re.I),
]


def _count_blocks(text: str) -> int:
    return sum(len(p.findall(text)) for p in _BLOCK_PATTERNS)


def _run(domain: str, home: Path, cwd: Path, export: Path, timeout: int,
         env_overrides: dict[str, str]) -> dict[str, Any]:
    cfg = CONFIGS["keyless-default"]
    env = cfg.build_env(home)
    env.update(env_overrides)
    run_cwd = cfg.build_cwd(cwd)
    cmd = [
        sys.executable, "-m", "cli.main", "--no-banner", "harvest-emails",
        "-d", domain, "--export", str(export), "--no-verify", "--timeout", str(timeout),
    ]
    start = time.perf_counter()
    proc = subprocess.run(
        cmd, env=env, cwd=str(run_cwd), capture_output=True, text=True,
        timeout=timeout + 300, errors="replace",
    )
    wall = time.perf_counter() - start
    output = (proc.stdout or "") + (proc.stderr or "")
    emails = 0
    if export.exists():
        try:
            emails = len(json.loads(export.read_text(encoding="utf-8")).get("emails", []) or [])
        except (OSError, json.JSONDecodeError):
            emails = 0
    return {"exit": proc.returncode, "wall": round(wall, 1),
            "blocks": _count_blocks(output), "emails": emails}


def check_domain(domain: str, timeout: int) -> dict[str, Any]:
    scratch = Path(tempfile.mkdtemp(prefix="resilience-"))
    (scratch / "cwd").mkdir(parents=True)

    legacy_home = scratch / "legacy"
    legacy_home.mkdir()
    legacy = _run(
        domain, legacy_home, scratch / "cwd", scratch / "legacy.json", timeout,
        {"CC_FIRST": "false", "HARVEST_FINGERPRINT_ROTATION": "false"},
    )

    resilient_home = scratch / "resilient"
    resilient_home.mkdir()
    resilient = _run(
        domain, resilient_home, scratch / "cwd", scratch / "resilient.json", timeout,
        {"CC_FIRST": "true", "HARVEST_FINGERPRINT_ROTATION": "true"},
    )

    improved = resilient["blocks"] <= legacy["blocks"]
    return {
        "domain": domain,
        "legacy_blocks": legacy["blocks"],
        "resilient_blocks": resilient["blocks"],
        "block_delta": legacy["blocks"] - resilient["blocks"],
        "improved": improved,
        "legacy_emails": legacy["emails"],
        "resilient_emails": resilient["emails"],
        "legacy_wall": legacy["wall"],
        "resilient_wall": resilient["wall"],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 5B resilience metrics harness")
    ap.add_argument("domains", nargs="+")
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args(argv)

    results = []
    total_legacy = total_resilient = 0
    for domain in args.domains:
        print(f"[resilience] {domain} — legacy vs resilient …", flush=True)
        r = check_domain(domain, args.timeout)
        results.append(r)
        total_legacy += r["legacy_blocks"]
        total_resilient += r["resilient_blocks"]
        print(f"  blocks: legacy={r['legacy_blocks']} resilient={r['resilient_blocks']} "
              f"(Δ{r['block_delta']:+d})  emails: {r['legacy_emails']}→{r['resilient_emails']}",
              flush=True)

    print("\n=== SUMMARY ===")
    print(json.dumps(results, indent=2))
    print(f"\nTOTAL hard-blocks: legacy={total_legacy} resilient={total_resilient} "
          f"(Δ{total_legacy - total_resilient:+d})")
    ok = total_resilient <= total_legacy
    print("RESILIENCE IMPROVED (fewer/equal hard-blocks)" if ok
          else "RESILIENCE REGRESSED (more hard-blocks)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
