"""Build the committed failure baseline + catalogue from a per-file run JSON.

Consumes the JSON emitted by ``pytest_baseline.py --out`` and writes:
  * eval/baseline/known-test-failures.txt   (failing nodeids)
  * eval/baseline/known-hung-files.txt       (files that hung)
  * eval/docs/failure-catalogue.md           (classified, human-readable)

Classification is heuristic (env-only / pre-existing-known / real) and marked as
a first pass — the `real` bucket is what a human should review.

  python -m eval.harness.build_catalogue <perfile.json>
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import date
from pathlib import Path

from eval.harness.classify_failures import classify_reason
from eval.harness.gate import HUNG_BASELINE, TEST_BASELINE, _write_lines
from eval.harness.manifest import REPO_ROOT

CATALOGUE = REPO_ROOT / "eval" / "docs" / "failure-catalogue.md"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("perfile_json")
    args = ap.parse_args(argv)

    data = json.loads(Path(args.perfile_json).read_text(encoding="utf-8"))
    per_file = data["per_file"]
    failures = set(data["failures"])
    hung = data.get("hung_files", [])

    # Gather (nodeid -> reason) from every file result.
    reasons: dict[str, str] = {}
    for fr in per_file:
        reasons.update(fr.get("reasons") or {})

    # Classify.
    buckets: Counter[str] = Counter()
    rows: list[tuple[str, str, str]] = []  # (bucket, nodeid, reason)
    for nid in sorted(failures):
        reason = reasons.get(nid, "")
        bucket = classify_reason(reason)
        buckets[bucket] += 1
        rows.append((bucket, nid, reason))

    # Write baselines.
    _write_lines(TEST_BASELINE, failures)
    _write_lines(HUNG_BASELINE, set(hung))

    # Per-file rollup.
    n_files = len(per_file)
    n_ok = sum(1 for f in per_file if f["status"] == "ok")
    n_failfiles = sum(1 for f in per_file if f["status"] == "failures")
    total_pass = sum(f.get("passed", 0) for f in per_file)

    # Markdown.
    md: list[str] = []
    md.append("# Phase 0 — Pre-existing Test Failure Catalogue")
    md.append("")
    md.append(f"_Captured {date.today().isoformat()} · v0.14.4 · hermetic per-file run "
              f"(network blocked, 45s/test, 90s/file)._")
    md.append("")
    md.append("This is the **known baseline** the CI gate diffs against. A PR fails only "
              "on failures **not** listed here (`eval/harness/gate.py`). Buckets are a "
              "heuristic first pass; the `real` bucket is the human-review set.")
    md.append("")
    md.append("## Totals")
    md.append("")
    md.append(f"- Test files run: **{n_files}** ({n_ok} clean, {n_failfiles} with failures)")
    md.append(f"- Passing tests (approx, summed per file): **{total_pass}**")
    md.append(f"- Failing/erroring nodeids catalogued: **{len(failures)}**")
    md.append(f"- Files that hung (killed, env/network): **{len(hung)}**")
    md.append("")
    md.append("### By classification")
    md.append("")
    md.append("| bucket | count | meaning |")
    md.append("|---|---|---|")
    env_n = buckets.get("env-only", 0)
    pre_n = buckets.get("pre-existing-known", 0)
    real_n = buckets.get("real", 0)
    md.append(f"| env-only | {env_n} | network/DNS/timeout or missing optional dep |")
    md.append(f"| pre-existing-known | {pre_n} | known-broken imports/collection |")
    md.append(f"| real | {real_n} | assertion/type/value failures in tool logic — REVIEW |")
    md.append(f"| unclassified | {buckets.get('unclassified', 0)} | no clear signal — review |")
    md.append("")
    if hung:
        md.append("## Hung files (env-only)")
        md.append("")
        md.append("These files did not terminate under a blocked network and were killed. "
                  "Treated as env/network noise; a NEW hung file fails the gate.")
        md.append("")
        for h in sorted(hung):
            md.append(f"- `{h}`")
        md.append("")
    md.append("## `real` + `unclassified` — human-review candidates")
    md.append("")
    md.append("| bucket | nodeid | reason (truncated) |")
    md.append("|---|---|---|")
    for bucket, nid, reason in rows:
        if bucket in ("real", "unclassified"):
            safe = reason[:100].replace("|", "\\|")
            md.append(f"| {bucket} | `{nid}` | {safe} |")
    md.append("")
    md.append("<details><summary>Full env-only + pre-existing list</summary>")
    md.append("")
    md.append("| bucket | nodeid |")
    md.append("|---|---|")
    for bucket, nid, _reason in rows:
        if bucket in ("env-only", "pre-existing-known"):
            md.append(f"| {bucket} | `{nid}` |")
    md.append("")
    md.append("</details>")
    md.append("")

    CATALOGUE.write_text("\n".join(md), encoding="utf-8")
    print(f"Wrote {TEST_BASELINE}  ({len(failures)} nodeids)")
    print(f"Wrote {HUNG_BASELINE}  ({len(hung)} files)")
    print(f"Wrote {CATALOGUE}")
    print(f"Buckets: {dict(buckets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
